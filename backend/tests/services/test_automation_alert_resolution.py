# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Alert resolution must report refusal and preserve system actor attribution."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.models.alert_rules import AlertStatus
from app.services.automation import (
    Action,
    ActionType,
    AutomationEngine,
    AutomationRule,
    RuleStatus,
    TriggerType,
)


@pytest.fixture
def resolution(monkeypatch):
    org = uuid4()
    alert_id = uuid4()
    db = MagicMock()
    db.get = AsyncMock(return_value=SimpleNamespace(id=alert_id, organization_id=org))
    db.commit = AsyncMock()
    db.__aenter__ = AsyncMock(return_value=db)
    db.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock(return_value=db)
    monkeypatch.setattr("app.db.async_session_factory", factory)
    service = MagicMock()
    service.resolve_alert = AsyncMock(return_value=db.get.return_value)
    monkeypatch.setattr(
        "app.services.alert_rules.AlertRuleService", MagicMock(return_value=service)
    )
    return AutomationEngine(), org, alert_id, db, factory, service


@pytest.mark.parametrize(
    "failure", ["missing_id", "missing_org", "absent", "foreign", "unresolved"]
)
async def test_refused_alert_resolution_is_a_failed_action(resolution, failure):
    engine, org, alert_id, db, factory, service = resolution
    params = {"alert_id": str(alert_id)}
    context = {"organization_id": str(org)}
    if failure == "missing_id":
        params = {}
    elif failure == "missing_org":
        context = {}
        params["organization_id"] = str(org)  # Cannot supply trusted context.
    elif failure == "absent":
        db.get.return_value = None
    elif failure == "foreign":
        db.get.return_value.organization_id = uuid4()
        params["organization_id"] = str(db.get.return_value.organization_id)
    else:
        service.resolve_alert.return_value = None
    result = await engine._execute_action(
        Action(action_type=ActionType.ALERT_RESOLVE, params=params), context
    )
    assert result.success is False
    assert result.error
    assert result.output["resolved"] is False
    db.commit.assert_not_awaited()
    if failure != "unresolved":
        service.resolve_alert.assert_not_awaited()
    if failure in {"missing_id", "missing_org"}:
        factory.assert_not_called()


async def test_resolution_uses_nullable_system_actor_not_a_fictitious_user(resolution):
    engine, org, alert_id, db, _, service = resolution
    result = await engine._execute_action(
        Action(action_type=ActionType.ALERT_RESOLVE, params={"alert_id": str(alert_id)}),
        {"organization_id": str(org)},
    )
    assert result.success and result.output == {"success": True, "resolved": True}
    assert service.resolve_alert.await_args.kwargs["user_id"] is None
    db.commit.assert_awaited_once()


async def test_commit_failure_is_not_success(resolution):
    engine, org, alert_id, db, _, _ = resolution
    db.commit.side_effect = RuntimeError("owned commit failure")
    result = await engine._execute_action(
        Action(action_type=ActionType.ALERT_RESOLVE, params={"alert_id": str(alert_id)}),
        {"organization_id": str(org)},
    )
    assert result.success is False and result.error == "owned commit failure"


@pytest.mark.parametrize("continue_on_error", [False, True])
async def test_failed_resolution_controls_chain_and_persisted_history(
    monkeypatch, continue_on_error
):
    engine = AutomationEngine()
    next_action = AsyncMock(return_value={"success": True})
    engine.register_action_handler(ActionType.NOTIFY_IN_APP, next_action)
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.commit = AsyncMock()
    session.execute = AsyncMock()
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", MagicMock(return_value=session))
    rule = AutomationRule(
        id=uuid4(),
        name="Owned resolution chain",
        description=None,
        organization_id=uuid4(),
        trigger_type=TriggerType.EVENT,
        trigger_config={"event_pattern": "owned.event"},
        conditions=None,
        status=RuleStatus.ACTIVE,
        actions=[
            Action(
                action_type=ActionType.ALERT_RESOLVE, params={}, continue_on_error=continue_on_error
            ),
            Action(action_type=ActionType.NOTIFY_IN_APP, params={}),
        ],
    )
    execution = await engine._execute_rule(rule, {})
    assert execution.success is False
    assert execution.actions_executed[0].success is False
    assert len(execution.actions_executed) == (2 if continue_on_error else 1)
    assert next_action.await_count == int(continue_on_error)
    session.commit.assert_awaited_once()
    record = session.add.call_args.args[0]
    assert record.success is False and record.actions_executed[0]["success"] is False


@pytest.mark.parametrize("human_actor", [False, True])
async def test_service_event_preserves_system_or_human_attribution(monkeypatch, human_actor):
    from app.services.alert_rules import AlertRuleService

    actor = uuid4() if human_actor else None
    alert = SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        rule_id=None,
        status=AlertStatus.FIRING,
        extra_metadata={},
        severity="warning",
        title="Owned alert",
    )
    db = SimpleNamespace(flush=AsyncMock(), refresh=AsyncMock())
    service = AlertRuleService(db)
    service.get_alert = AsyncMock(return_value=alert)
    bus = SimpleNamespace(publish=AsyncMock())
    monkeypatch.setattr("app.services.alert_rules.get_event_bus", lambda: bus)
    result = await service.resolve_alert(alert.id, user_id=actor, note="owned resolution")
    assert result is alert and alert.resolved_by == actor and alert.status == AlertStatus.RESOLVED
    event = bus.publish.await_args.args[0]
    assert event.payload["resolved_by"] == (str(actor) if actor else None)
    db.flush.assert_awaited_once()
