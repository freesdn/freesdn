# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression: startup hydration must not lose an automation rule's AUTHOR.

The bug (external pre-release review, F-04). There were TWO hand-written
``AutomationRuleRecord -> AutomationRule`` conversions, and they had drifted:

  * ``AutomationService.get_rule``            passed ``created_by=rec.created_by``
  * ``AutomationService._load_rules_from_db`` did NOT

``main.py`` hydrates the engine at boot through ``_load_rules_from_db``, so after
every restart every rule came back authorless. ``_execute_rule`` then put
``actor_id=None`` into the action context, ``_handle_fabric_operation`` re-checked
the author's permission with ``fabric_permission_checker(None, ...)``, and that
call fails closed by design -- so the rule reported "rule author no longer holds
the required permission" and did nothing. The same ``None`` also went to
``resolve_actor_site_grants``. The failure was intermittent-looking because
browsing the rule in the UI calls ``get_rule``, which re-registers the GOOD copy
and incidentally repairs that one in-memory object.

The fix is a single ``_rule_from_record`` used by both entry points. These tests
pin the behaviour, not the edit: one walks a hydrated rule all the way into the
Fabric operation context, and one compares the two entry points field-for-field
so ANY future drift (not just ``created_by``) is caught.
"""

from __future__ import annotations

import dataclasses
import inspect
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services.automation import (
    ActionType,
    AutomationEngine,
    AutomationService,
    RuleStatus,
    TriggerType,
)


def _record(*, author, rule_id, org, actions=None):
    """A stand-in for a persisted AutomationRuleRecord row."""
    return SimpleNamespace(
        id=rule_id,
        name="nightly-vlan-push",
        description=None,
        organization_id=org,
        trigger_type=TriggerType.EVENT.value,
        trigger_config={"event_pattern": "device.*"},
        conditions=None,
        actions=actions
        if actions is not None
        else [{"action_type": "notify.in_app", "params": {}}],
        status=RuleStatus.ACTIVE.value,
        priority=3,
        cooldown_seconds=0,
        max_triggers_per_hour=100,
        created_at=datetime.now(UTC),
        updated_at=None,
        last_triggered=None,
        trigger_count=7,
        created_by=author,
    )


def _db_returning(rec):
    """A DB double whose execute() serves ``rec`` to both query shapes the
    service uses: ``.scalars().all()`` (hydration) and ``.scalar_one_or_none()``
    (single get)."""
    scalars = MagicMock()
    scalars.all.return_value = [rec]
    result = MagicMock()
    result.scalars.return_value = scalars
    result.scalar_one_or_none.return_value = rec
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    return db


class TestHydrationKeepsTheAuthor:
    async def test_startup_hydration_preserves_the_rule_author(self):
        """The direct regression. Mutation caught: dropping ``created_by`` from
        ``_rule_from_record`` (i.e. restoring the old hydration copy)."""
        author, rule_id, org = uuid4(), uuid4(), uuid4()
        engine = AutomationEngine()
        svc = AutomationService(db=_db_returning(_record(author=author, rule_id=rule_id, org=org)))
        svc.engine = engine

        await svc._load_rules_from_db()  # exactly what main.py calls at boot

        assert engine._rules[rule_id].created_by == author

    async def test_both_record_conversions_agree_field_for_field(self):
        """Reach, not just logic: compare the two ENTRY POINTS on the same row
        across every dataclass field, so a future field added to one conversion
        and forgotten in the other fails here even though nobody thought of it.

        Mutation caught: any per-field divergence between ``get_rule`` and
        ``_load_rules_from_db`` -- the exact class of bug F-04 was."""
        author, rule_id, org = uuid4(), uuid4(), uuid4()
        rec = _record(author=author, rule_id=rule_id, org=org)

        hydrated_engine = AutomationEngine()
        hydrated_svc = AutomationService(db=_db_returning(rec))
        hydrated_svc.engine = hydrated_engine
        await hydrated_svc._load_rules_from_db()
        hydrated = hydrated_engine._rules[rule_id]

        fetched_svc = AutomationService(db=_db_returning(rec))
        fetched_svc.engine = AutomationEngine()
        fetched = await fetched_svc.get_rule(rule_id)

        names = [f.name for f in dataclasses.fields(hydrated)]
        assert "created_by" in names  # the field that drifted must be in scope
        differing = {
            n: (getattr(hydrated, n), getattr(fetched, n))
            for n in names
            if repr(getattr(hydrated, n)) != repr(getattr(fetched, n))
        }
        assert differing == {}, f"hydration and get_rule disagree on {sorted(differing)}"

    async def test_hydrated_rule_reaches_fabric_with_its_author(self, monkeypatch):
        """End-to-end, DB row -> boot hydration -> event fire -> the real
        ``_handle_fabric_operation`` -> the OperationContext handed to the
        executor. Asserts the AUTHOR arrives at BOTH authority gates: the
        permission re-check and the site-grant resolution.

        Mutation caught: dropping ``created_by`` in the conversion, renaming the
        ``actor_id`` context key in ``_execute_rule``, or the handler reading the
        actor from params instead of ``__context__``. All of those leave the
        assertions below holding ``None``."""
        import app.core.fabric.registry as registry_mod
        import app.core.fabric.runtime as runtime_mod
        import app.core.site_access as site_access_mod
        import app.db as db_mod
        import app.db.session as session_mod
        from app.core.fabric import executor as executor_mod
        from app.core.fabric.operations import OperationTier

        author, rule_id, org = uuid4(), uuid4(), uuid4()
        rec = _record(
            author=author,
            rule_id=rule_id,
            org=org,
            actions=[
                {
                    "action_type": ActionType.FABRIC_OPERATION.value,
                    "params": {"operation_id": "network.vlan.write", "operation_params": {}},
                }
            ],
        )

        engine = AutomationEngine()
        engine._register_builtin_handlers()
        svc = AutomationService(db=_db_returning(rec))
        svc.engine = engine
        await svc._load_rules_from_db()

        # --- stub only the collaborators that would need a live DB ---
        class _NullSession:
            async def __aenter__(self):
                return MagicMock()

            async def __aexit__(self, *_a):
                return False

        monkeypatch.setattr(db_mod, "async_session_factory", _NullSession)
        monkeypatch.setattr(session_mod, "AsyncSessionLocal", _NullSession)

        op = SimpleNamespace(
            id="network.vlan.write",
            permission="network:write",
            tier=OperationTier.NATIVE,
            write=True,
        )
        monkeypatch.setattr(
            registry_mod.fabric_registry, "get_operation", lambda _id: op, raising=False
        )

        gate: dict[str, object] = {}

        async def _checker(actor_id, permission, org_id):
            gate["actor_id"] = actor_id
            gate["permission"] = permission
            return True  # the author DOES hold it — so the run proceeds

        monkeypatch.setattr(runtime_mod, "fabric_permission_checker", _checker)

        grants: dict[str, object] = {}

        async def _grants(_db, actor_id):
            grants["actor_id"] = actor_id
            return None

        monkeypatch.setattr(site_access_mod, "resolve_actor_site_grants", _grants)

        seen: dict[str, object] = {}

        async def _execute(_op, ctx):
            seen["actor_id"] = ctx.actor_id
            seen["organization_id"] = ctx.organization_id
            return SimpleNamespace(to_dict=lambda: {"success": True, "staged_change_id": "s1"})

        monkeypatch.setattr(executor_mod.operation_executor, "execute", _execute)

        execution = await engine._execute_rule(engine._rules[rule_id], {"device_id": "d1"})

        # The permission re-check saw the AUTHOR, not None (None fails closed).
        assert gate["actor_id"] == author
        assert gate["permission"] == "network:write"
        # ...so did the site-grant resolution...
        assert grants["actor_id"] == author
        # ...and so did the operation the executor actually ran.
        assert seen["actor_id"] == author
        assert seen["organization_id"] == org
        assert execution.success is True
        assert execution.actions_executed[0].success is True

    async def test_permission_checker_denies_a_none_author(self):
        """Why the dropped author was fatal rather than cosmetic: the REAL
        Fabric checker fails closed on ``None`` before touching the DB.

        Mutation caught: relaxing that fail-closed guard (which is the WRONG fix
        for F-04 -- it would let an authorless rule execute unchecked)."""
        from app.core.fabric.runtime import fabric_permission_checker

        assert await fabric_permission_checker(None, "network:write", uuid4()) is False


def test_neither_entry_point_hand_rolls_a_conversion_again():
    """Source-level ratchet, because the runtime parity test above can only
    compare conversions that BOTH exist and are BOTH exercised. This one catches
    the shape of the bug directly: a record -> rule conversion written inline in
    either loader instead of going through ``_rule_from_record``.

    Mutation caught: pasting an ``AutomationRule(...)`` literal back into
    ``_load_rules_from_db`` or ``get_rule`` -- even one that is field-complete
    today and drifts later, which is exactly how F-04 happened."""
    for fn in (AutomationService._load_rules_from_db, AutomationService.get_rule):
        src = inspect.getsource(fn)
        assert "AutomationRule(" not in src, (
            f"{fn.__name__} hand-rolls a record->rule conversion again; "
            "call AutomationService._rule_from_record instead"
        )
        assert "_rule_from_record" in src, f"{fn.__name__} no longer uses the shared conversion"


@pytest.mark.parametrize("entry_point", ["hydrate", "get_rule"])
async def test_no_entry_point_resurrects_a_rule_without_its_author(entry_point):
    """Belt and braces across both callers, parameterised so adding a third
    conversion that skips ``_rule_from_record`` is a visible omission here."""
    author, rule_id, org = uuid4(), uuid4(), uuid4()
    svc = AutomationService(db=_db_returning(_record(author=author, rule_id=rule_id, org=org)))
    svc.engine = AutomationEngine()

    if entry_point == "hydrate":
        await svc._load_rules_from_db()
        rule = svc.engine._rules[rule_id]
    else:
        rule = await svc.get_rule(rule_id)

    assert rule is not None
    assert rule.created_by == author
