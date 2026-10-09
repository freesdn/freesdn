# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Uncertain shared coordination must not authorize unattended side effects."""

import asyncio
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services.automation import AutomationEngine, AutomationRule, RuleStatus, TriggerType


async def configured(*, cooldown=0):
    engine = AutomationEngine()
    rule = AutomationRule(
        id=uuid4(),
        name="Owned coordination check",
        description=None,
        organization_id=uuid4(),
        trigger_type=TriggerType.EVENT,
        trigger_config={"event_pattern": "owned.event"},
        conditions=None,
        actions=[],
        cooldown_seconds=cooldown,
        max_triggers_per_hour=2,
    )
    await engine.register_rule(rule)
    client = MagicMock()
    client.set = AsyncMock(return_value=True)
    client.eval = AsyncMock(return_value=1)
    engine._redis = client
    # Do not invoke a device, notification, database write or action handler.
    engine._execute_rule = AsyncMock(return_value=object())
    return engine, rule, client


async def deliver(engine, rule, event_id="same-event"):
    return await engine.process_event(
        "owned.event",
        {"payload": "must-not-be-in-diagnostic"},
        event_id=event_id,
        event_org_id=str(rule.organization_id),
    )


@pytest.mark.parametrize("reply", [1, "OK", b"OK", {}, [True]])
async def test_malformed_event_claim_never_authorizes_actions(reply):
    engine, rule, client = await configured()
    client.set.return_value = reply
    assert await deliver(engine, rule) == []
    engine._execute_rule.assert_not_awaited()
    client.eval.assert_not_awaited()
    assert rule.trigger_count == 0 and rule.last_triggered is None


async def test_lost_event_claim_reply_is_not_retried_or_undone(caplog):
    engine, rule, client = await configured()
    client.set.side_effect = [TimeoutError("SECRET_CLIENT_URL"), None]
    assert await deliver(engine, rule) == []
    assert engine.coordination_blocks(rule.organization_id)[0]["reason"] == (
        "event claim unavailable or uncertain"
    )
    assert await deliver(engine, rule) == []
    engine._execute_rule.assert_not_awaited()
    client.delete.assert_not_called()
    assert "SECRET_CLIENT_URL" not in caplog.text
    assert "must-not-be-in-diagnostic" not in caplog.text
    assert engine.coordination_blocks(rule.organization_id) == []


@pytest.mark.parametrize("cooldown", [0, 60])
async def test_unavailable_client_never_falls_back_to_worker_memory(cooldown):
    engine, rule, _ = await configured(cooldown=cooldown)
    engine._get_redis = MagicMock(side_effect=ConnectionError("offline"))
    assert await deliver(engine, rule, event_id=None) == []
    engine._execute_rule.assert_not_awaited()
    assert rule.trigger_count == 0 and rule.last_triggered is None


@pytest.mark.parametrize("reply", [1, "OK", {}, [True]])
async def test_malformed_cooldown_never_reaches_rate_limit_or_actions(reply):
    engine, rule, client = await configured(cooldown=60)
    client.set.return_value = reply
    assert await deliver(engine, rule, event_id=None) == []
    client.eval.assert_not_awaited()
    engine._execute_rule.assert_not_awaited()


@pytest.mark.parametrize("gate", ["event", "cooldown", "rate"])
async def test_outage_refuses_and_later_positive_coordination_recovers(gate):
    engine, rule, client = await configured(cooldown=60 if gate == "cooldown" else 0)
    failing = client.eval if gate == "rate" else client.set
    failing.side_effect = ConnectionError("private client connection details")
    event_id = "event" if gate == "event" else None
    assert await deliver(engine, rule, event_id) == []
    assert rule.trigger_count == 0
    first = engine.coordination_blocks(rule.organization_id)
    assert first and await deliver(engine, rule, event_id) == []
    assert engine.coordination_blocks(rule.organization_id) == first
    assert engine.coordination_blocks(uuid4()) == []
    assert engine.coordination_blocks(None) == []
    failing.side_effect = None
    assert len(await deliver(engine, rule, event_id)) == 1
    assert rule.trigger_count == 1 and rule.last_triggered is not None
    assert engine.coordination_blocks(rule.organization_id) == []


@pytest.mark.parametrize("reply", [True, "1", "0", b"1", 2, -1, None, [1]])
async def test_rate_limiter_requires_exact_integer_allow_response(reply):
    engine, rule, client = await configured()
    client.eval.return_value = reply
    assert await deliver(engine, rule, event_id=None) == []
    engine._execute_rule.assert_not_awaited()
    assert rule.trigger_count == 0 and rule.last_triggered is None


@pytest.mark.parametrize("reply", [None, False])
async def test_duplicate_event_is_not_executed(reply):
    engine, rule, client = await configured()
    client.set.return_value = reply
    assert await deliver(engine, rule) == []
    client.eval.assert_not_awaited()
    engine._execute_rule.assert_not_awaited()


async def test_rate_refusal_retains_prior_event_claim_and_cooldown():
    engine, rule, client = await configured(cooldown=60)
    client.eval.side_effect = TimeoutError("lost rate reply")
    assert await deliver(engine, rule) == []
    assert client.set.await_count == 2
    client.delete.assert_not_called()
    assert rule.trigger_count == 0 and rule.last_triggered is None


@pytest.mark.parametrize("action", ["pause", "unregister"])
async def test_inactive_or_removed_rules_do_not_leave_refusal_diagnostics(action):
    engine, rule, client = await configured()
    client.set.side_effect = ConnectionError("offline")
    await deliver(engine, rule)
    assert engine.coordination_blocks(rule.organization_id)
    if action == "pause":
        assert await engine.update_rule_status(rule.id, RuleStatus.PAUSED)
    else:
        assert await engine.unregister_rule(rule.id)
    assert engine.coordination_blocks(rule.organization_id) == []
    assert rule.id not in engine._coordination_blocks


async def test_cancelled_claim_does_not_execute_or_swallow_cancellation():
    engine, rule, client = await configured()
    client.set.side_effect = asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await deliver(engine, rule)
    engine._execute_rule.assert_not_awaited()
    client.delete.assert_not_called()


async def test_healthy_rate_limit_denial_is_not_a_coordination_failure():
    engine, rule, client = await configured()
    client.eval.return_value = 0
    assert await deliver(engine, rule, event_id=None) == []
    engine._execute_rule.assert_not_awaited()
    assert engine.coordination_blocks(rule.organization_id) == []
