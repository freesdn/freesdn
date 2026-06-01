# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Cross-tenant isolation for the automation engine (security review #2).

An event must fire ONLY rules belonging to the event's own organization. A
system event with no organization_id fires NOTHING (fail-closed). Without this,
an Org-B rule would trigger on an Org-A event (matched by event_type alone) and
leak Org-A's payload through its notify/log/webhook actions — the
camera.status / ai.budget cross-tenant class.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.services.automation import (
    AutomationEngine,
    AutomationRule,
    RuleStatus,
    TriggerType,
)


def _event_rule(org_id, pattern: str = "test.event") -> AutomationRule:
    return AutomationRule(
        id=uuid4(),
        name="rule",
        description=None,
        organization_id=org_id,
        trigger_type=TriggerType.EVENT,
        trigger_config={"event_pattern": pattern},
        conditions=None,
        actions=[],
        status=RuleStatus.ACTIVE,
    )


@pytest.mark.asyncio
async def test_event_fires_only_same_org_rules() -> None:
    engine = AutomationEngine()
    org_a, org_b = uuid4(), uuid4()
    await engine.register_rule(_event_rule(org_a))
    await engine.register_rule(_event_rule(org_b))

    fired: list = []

    async def _fake_execute(rule, trigger_data):  # noqa: ANN001
        fired.append(rule.organization_id)
        return SimpleNamespace(id=uuid4())

    # Isolate the org-filter: bypass actions + the Redis throttle/idempotency.
    engine._execute_rule = _fake_execute  # type: ignore[assignment]
    engine._check_throttle = AsyncMock(return_value=True)  # type: ignore[assignment]

    # Org-A event -> only Org-A's rule.
    fired.clear()
    await engine.process_event("test.event", {}, event_org_id=str(org_a))
    assert fired == [org_a]

    # Org-B event -> only Org-B's rule.
    fired.clear()
    await engine.process_event("test.event", {}, event_org_id=str(org_b))
    assert fired == [org_b]


@pytest.mark.asyncio
async def test_system_event_with_no_org_fires_nothing() -> None:
    """Fail-closed: a no-org (system-scoped) event must not fire any org rule."""
    engine = AutomationEngine()
    org_a = uuid4()
    await engine.register_rule(_event_rule(org_a))

    fired: list = []

    async def _fake_execute(rule, trigger_data):  # noqa: ANN001
        fired.append(rule.organization_id)
        return SimpleNamespace(id=uuid4())

    engine._execute_rule = _fake_execute  # type: ignore[assignment]
    engine._check_throttle = AsyncMock(return_value=True)  # type: ignore[assignment]

    await engine.process_event("test.event", {}, event_org_id=None)
    assert fired == []


@pytest.mark.asyncio
async def test_event_for_unknown_org_fires_nothing() -> None:
    engine = AutomationEngine()
    await engine.register_rule(_event_rule(uuid4()))

    fired: list = []

    async def _fake_execute(rule, trigger_data):  # noqa: ANN001
        fired.append(rule.organization_id)
        return SimpleNamespace(id=uuid4())

    engine._execute_rule = _fake_execute  # type: ignore[assignment]
    engine._check_throttle = AsyncMock(return_value=True)  # type: ignore[assignment]

    await engine.process_event("test.event", {}, event_org_id=str(uuid4()))
    assert fired == []
