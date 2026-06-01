# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression: automation must be HONEST about what it can actually do.

A capability audit found three problems:
  1. ``created_by`` was never set on a rule, so the ``fabric.operation`` action
     read ``actor_id=None`` and ``fabric_permission_checker`` failed closed —
     EVERY fabric.operation rule always denied.
  2. SCHEDULE / WEBHOOK / THRESHOLD trigger types were offered by the API and
     accepted at creation, but only EVENT (event bus) and MANUAL (explicit
     /trigger) have a live driver — the others silently never fire.
  3. device.* / network.* / script.run / api.call / llm.* action types were
     offered/accepted but have no handler, so they always fail at execution.

These lock: the implemented-type sets reflect the LIVE registry, and create_rule
threads the author through so fabric rules can re-check permission at fire time.
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.api.v1.endpoints import automation as automation_ep
from app.services.automation import (
    IMPLEMENTED_TRIGGER_TYPES,
    ActionType,
    AutomationEngine,
    AutomationService,
    TriggerType,
)


def test_implemented_trigger_types_excludes_phantoms():
    assert frozenset({TriggerType.EVENT, TriggerType.MANUAL}) == IMPLEMENTED_TRIGGER_TYPES
    for phantom in (TriggerType.SCHEDULE, TriggerType.WEBHOOK, TriggerType.THRESHOLD):
        assert phantom not in IMPLEMENTED_TRIGGER_TYPES


def test_implemented_action_types_match_the_live_registry():
    engine = AutomationEngine()
    engine._register_builtin_handlers()
    supported = engine.implemented_action_types()

    # Have a real handler → offered. (llm.* ARE registered via automation_llm —
    # contrary to the audit's assumption — so they are correctly implemented.)
    for ok in (
        ActionType.NOTIFY_EMAIL,
        ActionType.NOTIFY_IN_APP,
        ActionType.ALERT_CREATE,
        ActionType.CAMERA_SNAPSHOT,
        ActionType.FABRIC_OPERATION,
        ActionType.LLM_CLASSIFY,
    ):
        assert ok in supported, ok

    # No handler (genuinely phantom) → NOT offered.
    for phantom in (
        ActionType.DEVICE_REBOOT,
        ActionType.DEVICE_CONFIG,
        ActionType.NETWORK_BLOCK_CLIENT,
        ActionType.NETWORK_QUARANTINE,
        ActionType.SCRIPT_RUN,
        ActionType.API_CALL,
    ):
        assert phantom not in supported, phantom


@pytest.mark.asyncio
async def test_create_rule_threads_created_by():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    engine = MagicMock()
    engine.register_rule = AsyncMock()

    svc = AutomationService(db=db, engine=engine)
    author = uuid4()
    rule = await svc.create_rule(
        name="r1",
        organization_id=uuid4(),
        trigger_type=TriggerType.EVENT,
        trigger_config={},
        actions=[{"action_type": "notify.in_app", "params": {}}],
        created_by=author,
    )

    # In-memory rule carries the author (used as actor_id at fire time)...
    assert rule.created_by == author
    # ...and so does the persisted record.
    record = db.add.call_args.args[0]
    assert record.created_by == author


def test_endpoints_gate_on_the_implemented_sets():
    """The create endpoint validates, and the listings filter, against the
    implemented sets — so phantom types can be neither created nor offered."""
    create_src = inspect.getsource(automation_ep.create_automation_rule)
    assert "IMPLEMENTED_TRIGGER_TYPES" in create_src
    assert "implemented_action_types" in create_src
    assert "created_by=current_user.id" in create_src

    for listing in (
        automation_ep.get_action_types,
        automation_ep.get_trigger_types,
        automation_ep.get_trigger_types_meta,
        automation_ep.get_action_types_meta,
    ):
        src = inspect.getsource(listing)
        assert "IMPLEMENTED_TRIGGER_TYPES" in src or "implemented_action_types" in src, (
            listing.__name__
        )
