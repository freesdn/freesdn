# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Committed selection and per-action revocation at production entry points.

The DB transport and effects are synthetic here. Separate migrated PostgreSQL
qualification covers real commit/rollback and independently running processes.
"""

import asyncio
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

import app.db.session as db_module
from app.services.automation import (
    ActionType,
    AutomationEngine,
    AutomationService,
    RuleStatus,
    automation_engine,
)
from tests.services.test_automation_hydration import _record


@pytest.fixture
def authority(monkeypatch):
    row = _record(
        author=uuid4(),
        rule_id=uuid4(),
        org=uuid4(),
        actions=[
            {"action_type": "delay", "params": {"number": n}, "continue_on_error": True}
            for n in [1, 2, 3]
        ],
    )
    f = SimpleNamespace(row=row, rows=[row], queries=[], effects=[], reads=0, unavailable=False)

    class Session:
        async def __aenter__(self):
            if f.unavailable:
                raise RuntimeError("PRIVATE-DEFINITION-CANARY")
            return self

        async def __aexit__(self, *_args):
            return False

        async def execute(self, statement):
            f.queries.append(statement)
            f.reads += 1
            result = MagicMock()
            result.scalars.return_value.all.return_value = deepcopy(f.rows)
            result.scalar_one_or_none.return_value = deepcopy(f.rows[0]) if f.rows else None
            return result

        def add(self, _record):
            pass

        async def commit(self):
            pass

    monkeypatch.setattr(db_module, "AsyncSessionLocal", Session)
    f.session = Session
    f.runtime = type(automation_engine)()
    f.runtime._check_throttle = AsyncMock(return_value=True)

    async def handler(params):
        f.effects.append(params["number"])
        return {"success": True}

    f.runtime.register_action_handler(ActionType.DELAY, handler)
    f.snapshot = AutomationService._rule_from_record(deepcopy(row))
    return f


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ["new", "edited", "deleted", "disabled", "rollback_cache", "unchanged"]
)
async def test_event_execution_uses_committed_selection(authority, kind):
    f = authority
    if kind != "new":
        await f.runtime.register_rule(deepcopy(f.snapshot))
    if kind == "edited":
        f.row.name = "New committed name"
    elif kind in ["deleted", "disabled"]:
        # The real query filters inactive rows; the transport returns no match.
        f.rows = []
    elif kind == "rollback_cache":
        f.runtime._rules[f.row.id].name = "Uncommitted cache name"
    selected = []

    async def execute(rule, _data):
        selected.append(rule.name)
        return SimpleNamespace(id=uuid4())

    f.runtime._execute_rule = AsyncMock(side_effect=execute)
    await f.runtime.process_event("device.up", {}, event_org_id=str(f.row.organization_id))
    assert selected == ([] if kind in ["deleted", "disabled"] else [f.row.name])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ["name", "author", "actions", "disable", "delete", "unavailable", "stats", "cache_only"]
)
async def test_current_definition_is_rechecked_between_actions(authority, kind, caplog):
    f = authority
    await f.runtime.register_rule(deepcopy(f.snapshot))

    async def handler(params):
        f.effects.append(params["number"])
        if params["number"] == 1:
            if kind == "name":
                f.row.name = "Changed"
            elif kind == "author":
                f.row.created_by = uuid4()
            elif kind == "actions":
                f.row.actions = []
            elif kind == "disable":
                f.row.status = RuleStatus.DISABLED.value
            elif kind == "delete":
                f.rows = []
            elif kind == "unavailable":
                f.unavailable = True
            elif kind == "stats":
                f.row.trigger_count += 1
            else:
                f.runtime._rules[f.row.id].name = "Uncommitted cache"
        return {"success": True}

    f.runtime.register_action_handler(ActionType.DELAY, handler)
    result = await f.runtime.trigger_rule(f.row.id)
    allowed = kind in ["stats", "cache_only"]
    assert f.effects == ([1, 2, 3] if allowed else [1])
    assert result.success == allowed
    if not allowed:
        assert len(result.actions_executed) == 2
        assert "refused" in result.error
    assert "PRIVATE-DEFINITION-CANARY" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["disable", "author", "delete", "unavailable"])
async def test_authority_check_happens_after_pre_action_delay(authority, monkeypatch, kind):
    f = authority
    f.row.actions[0]["delay_seconds"] = 3
    await f.runtime.register_rule(AutomationService._rule_from_record(deepcopy(f.row)))
    original_sleep = asyncio.sleep

    async def sleep(delay, *args, **kwargs):
        if delay != 3:
            return await original_sleep(delay, *args, **kwargs)
        if kind == "disable":
            f.row.status = "disabled"
        elif kind == "author":
            f.row.created_by = uuid4()
        elif kind == "delete":
            f.rows = []
        else:
            f.unavailable = True

    monkeypatch.setattr(asyncio, "sleep", sleep)
    result = await f.runtime.trigger_rule(f.row.id)
    assert f.effects == [] and not result.success
    assert len(result.actions_executed) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("trigger_config", ["PRIVATE-DEFINITION-CANARY"]),
        ("conditions", ["PRIVATE-DEFINITION-CANARY"]),
        ("actions", [{"action_type": "PRIVATE-DEFINITION-CANARY"}]),
        ("actions", [{"action_type": "delay", "params": ["PRIVATE-DEFINITION-CANARY"]}]),
        ("actions", [{"action_type": "delay", "delay_seconds": "PRIVATE-DEFINITION-CANARY"}]),
        ("actions", [{"action_type": "delay", "continue_on_error": "PRIVATE-DEFINITION-CANARY"}]),
        ("priority", "PRIVATE-DEFINITION-CANARY"),
        ("cooldown_seconds", -1),
        ("max_triggers_per_hour", 0),
    ],
)
async def test_invalid_persisted_definitions_refuse_cached_execution(
    authority, caplog, field, value
):
    f = authority
    await f.runtime.register_rule(deepcopy(f.snapshot))
    setattr(f.row, field, value)
    results = await f.runtime.process_event(
        "device.up", {}, event_org_id=str(f.row.organization_id)
    )
    assert results == [] and f.effects == []
    assert "PRIVATE-DEFINITION-CANARY" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "organization_id", [None, "invalid", "", "00000000-0000-0000-0000-000000000000"]
)
async def test_unscoped_events_do_not_execute_cached_rule(authority, organization_id):
    f = authority
    await f.runtime.register_rule(deepcopy(f.snapshot))
    result = await f.runtime.process_event("device.up", {}, event_org_id=organization_id)
    assert result == [] and f.effects == []


@pytest.mark.asyncio
async def test_production_queries_bind_tenant_and_live_organization(authority):
    f = authority
    await f.runtime.process_event("device.up", {}, event_org_id=str(f.row.organization_id))
    assert f.effects == [1, 2, 3]
    selects = [
        statement.compile() for statement in f.queries if getattr(statement, "is_select", False)
    ]
    assert len(selects) == 4
    for statement in selects:
        sql = str(statement)
        assert "core.organizations.is_active IS true" in sql
        assert "core.organizations.deleted_at IS NULL" in sql
        assert f.row.organization_id in statement.params.values()
    assert "active" in selects[0].params.values()
    assert "event" in selects[0].params.values()
    assert all(f.row.id in statement.params.values() for statement in selects[1:])


@pytest.mark.asyncio
async def test_manual_service_uses_database_ownership_and_forwards_scope(authority):
    f = authority
    await f.runtime.register_rule(deepcopy(f.snapshot))
    f.runtime._rules[f.row.id].organization_id = uuid4()
    f.runtime.trigger_rule = AsyncMock(return_value=SimpleNamespace(success=True))
    async with f.session() as db:
        result = await AutomationService(db, f.runtime).trigger_rule(
            f.row.id, {"owned": True}, organization_id=f.row.organization_id
        )
    assert result.success
    f.runtime.trigger_rule.assert_awaited_once_with(
        f.row.id, {"owned": True}, organization_id=f.row.organization_id
    )
    statement = f.queries[0].compile()
    assert (
        f.row.organization_id in statement.params.values() and f.row.id in statement.params.values()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["active", "disabled", "paused"])
async def test_explicit_manual_run_retains_status_compatibility(authority, status):
    f = authority
    f.row.status = status
    await f.runtime.register_rule(AutomationService._rule_from_record(deepcopy(f.row)))
    result = await f.runtime.trigger_rule(f.row.id)
    assert result.success and f.effects == [1, 2, 3]


def test_both_production_construction_sites_require_persistence():
    service = AutomationService(MagicMock())
    assert type(service.engine) is type(automation_engine)
    assert type(automation_engine) is not AutomationEngine


@pytest.mark.asyncio
async def test_cancelled_action_stops_chain_and_releases_context(authority):
    f = authority
    await f.runtime.register_rule(deepcopy(f.snapshot))

    async def cancel(params):
        f.effects.append(params["number"])
        raise asyncio.CancelledError()

    f.runtime.register_action_handler(ActionType.DELAY, cancel)
    with pytest.raises(asyncio.CancelledError):
        await f.runtime.trigger_rule(f.row.id)
    assert f.effects == [1]
    # A direct action call outside a rule must not inherit cancelled authority.
    result = await f.runtime._execute_action(f.snapshot.actions[1], {})
    assert not result.success and f.effects == [1]
