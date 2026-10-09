# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unattended Fabric chains need an affirmative shared coordination result."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.core.fabric.negotiator import Connection, Negotiator


def configured(cooldown=0):
    conn = Connection(
        id=str(uuid4()),
        organization_id=uuid4(),
        name="Owned claim",
        source_event="owned.event",
        steps=[],
        cooldown_seconds=cooldown,
    )
    engine = Negotiator(session_factory=lambda: None)
    engine.add_connection(conn)
    client = MagicMock()
    client.set = AsyncMock(return_value=True)
    engine._redis = client
    engine._run = AsyncMock(return_value={"connection_id": conn.id, "success": True})
    event = SimpleNamespace(
        id=str(uuid4()),
        organization_id=str(conn.organization_id),
        event_type="owned.event",
        payload={"private": "not-for-diagnostics"},
    )
    return engine, conn, client, event


@pytest.mark.parametrize("gate", ["claim", "cooldown"])
@pytest.mark.parametrize("reply", [1, "OK", b"OK", [True], {"ok": True}])
async def test_malformed_shared_reply_never_executes(gate, reply):
    engine, _, client, event = configured(cooldown=60 if gate == "cooldown" else 0)
    client.set.side_effect = [True, reply] if gate == "cooldown" else [reply]
    assert await engine.handle_event(event) == []
    engine._run.assert_not_awaited()
    client.delete.assert_not_called()


@pytest.mark.parametrize("gate", ["claim", "cooldown"])
@pytest.mark.parametrize("reply", [None, False])
async def test_healthy_duplicate_or_cooldown_is_refused(gate, reply):
    engine, _, client, event = configured(cooldown=60 if gate == "cooldown" else 0)
    client.set.side_effect = [True, reply] if gate == "cooldown" else [reply]
    assert await engine.handle_event(event) == []
    engine._run.assert_not_awaited()


@pytest.mark.parametrize("gate", ["claim", "cooldown"])
@pytest.mark.parametrize("failure", ["no_client", "factory_error", "lost_reply"])
async def test_outage_never_uses_worker_local_fallback(gate, failure, caplog):
    engine, _, client, event = configured(cooldown=60 if gate == "cooldown" else 0)
    secret = "PRIVATE_COORDINATION_CLIENT_URL"
    if failure == "lost_reply":
        client.set.side_effect = (
            [True, TimeoutError(secret)] if gate == "cooldown" else TimeoutError(secret)
        )
    else:
        outcomes = [None] if failure == "no_client" else [ConnectionError(secret)]
        if gate == "cooldown":
            outcomes.insert(0, client)
        engine._get_redis = AsyncMock(side_effect=outcomes)
    assert await engine.handle_event(event) == []
    engine._run.assert_not_awaited()
    client.delete.assert_not_called()
    assert secret not in caplog.text and "not-for-diagnostics" not in caplog.text


@pytest.mark.parametrize("event_id", [None, ""])
async def test_missing_event_identity_cannot_run_unattended(event_id):
    engine, _, client, event = configured()
    event.id = event_id
    assert await engine.handle_event(event) == []
    engine._run.assert_not_awaited()
    client.set.assert_not_awaited()


async def test_client_initialization_failure_is_retried_on_a_later_event(monkeypatch, caplog):
    engine = Negotiator()
    client = MagicMock()
    factory = MagicMock(side_effect=[ConnectionError("PRIVATE_FACTORY_URL"), client])
    monkeypatch.setattr("app.core.redis_client.get_async_redis", factory)
    assert await engine._get_redis() is None
    assert await engine._get_redis() is client
    assert factory.call_count == 2
    assert "PRIVATE_FACTORY_URL" not in caplog.text


@pytest.mark.parametrize("gate", ["claim", "cooldown"])
async def test_lost_reply_retains_claim_and_later_event_recovers(gate):
    engine, _, client, event = configured(cooldown=60 if gate == "cooldown" else 0)
    client.set.side_effect = (
        [True, TimeoutError("uncertain"), None, True, True]
        if gate == "cooldown"
        else [TimeoutError("uncertain"), None, True]
    )
    assert await engine.handle_event(event) == []
    assert await engine.handle_event(event) == []
    engine._run.assert_not_awaited()
    event.id = str(uuid4())
    assert len(await engine.handle_event(event)) == 1
    engine._run.assert_awaited_once()
    client.delete.assert_not_called()


@pytest.mark.parametrize("gate", ["claim", "cooldown"])
async def test_cancelled_coordination_never_runs_and_propagates(gate):
    engine, _, client, event = configured(cooldown=60 if gate == "cooldown" else 0)
    client.set.side_effect = (
        [True, asyncio.CancelledError()] if gate == "cooldown" else asyncio.CancelledError()
    )
    with pytest.raises(asyncio.CancelledError):
        await engine.handle_event(event)
    engine._run.assert_not_awaited()
    client.delete.assert_not_called()


@pytest.mark.parametrize("cooldown", [0, 60])
async def test_shared_positive_results_allow_one_run(cooldown):
    engine, _, client, event = configured(cooldown=cooldown)
    assert len(await engine.handle_event(event)) == 1
    engine._run.assert_awaited_once()
    assert client.set.await_count == (2 if cooldown else 1)


async def test_failed_coordination_on_one_connection_does_not_drop_healthy_peer():
    engine, conn, client, event = configured()
    other = Connection(
        id=str(uuid4()),
        organization_id=conn.organization_id,
        name="Healthy peer",
        source_event=conn.source_event,
        steps=[],
    )
    engine.add_connection(other)
    client.set.side_effect = [TimeoutError("outage"), True]
    assert len(await engine.handle_event(event)) == 1
    assert engine._run.await_args.args[0] is other


async def test_explicit_run_once_does_not_require_an_event_claim():
    engine, conn, client, _ = configured()
    client.set.side_effect = ConnectionError("offline")
    assert (await engine.run_once(conn, {}))["success"]
    engine._run.assert_awaited_once()
    client.set.assert_not_awaited()
