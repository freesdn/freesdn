# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for ``app.services.websocket_pubsub.WSCrossInstanceBus``.

This is the cross-pod fan-out layer for targeted ``send_to_user`` /
``send_personal`` messages. The bus is meant to be transparent — if
Redis is unavailable it must degrade to single-pod behaviour without
raising.

We don't run real Redis. Instead we patch ``redis.asyncio.from_url`` to
return a fake client whose pubsub() returns a fake pubsub whose
get_message() yields scripted messages. This keeps the tests fast and
deterministic, and lets us assert the dedupe + envelope semantics
directly.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.websocket_pubsub import (
    WSCrossInstanceBus,
    reset_ws_pubsub_for_tests,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakePubSub:
    """Records subscriptions and lets the test queue scripted messages.

    The bus's listener calls ``get_message(timeout=1.0)`` in a loop. We
    return queued items first, then ``None`` forever (so the listener
    parks until cancelled).
    """

    def __init__(self) -> None:
        self.psubscribed: list[str] = []
        self._queue: list[dict[str, Any]] = []
        self.closed = False

    async def psubscribe(self, pattern: str) -> None:
        self.psubscribed.append(pattern)

    async def get_message(self, ignore_subscribe_messages: bool = False,
                          timeout: float = 1.0) -> dict[str, Any] | None:
        if self._queue:
            return self._queue.pop(0)
        # Park so the listener loops back without burning CPU.
        await asyncio.sleep(0.01)
        return None

    async def unsubscribe(self) -> None:
        pass

    async def close(self) -> None:
        self.closed = True

    def queue_pmessage(self, channel: str, data: dict[str, Any]) -> None:
        self._queue.append({
            "type": "pmessage",
            "pattern": "freesdn:ws:user:*",
            "channel": channel,
            "data": json.dumps(data),
        })


class _FakeRedis:
    """Tiny redis client double — pubsub + publish + aclose."""

    def __init__(self) -> None:
        self.pubsub_obj = _FakePubSub()
        self.published: list[tuple[str, str]] = []
        self.closed = False

    def pubsub(self) -> _FakePubSub:
        return self.pubsub_obj

    async def publish(self, channel: str, data: str) -> None:
        self.published.append((channel, data))

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Each test gets a fresh module singleton."""
    reset_ws_pubsub_for_tests()
    yield
    reset_ws_pubsub_for_tests()


@pytest.fixture
def fake_redis():
    """Patch redis.asyncio.from_url to return our fake client."""
    fake = _FakeRedis()
    with patch("app.services.websocket_pubsub.redis.from_url", return_value=fake):
        yield fake


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestConnectDisconnect:
    @pytest.mark.asyncio
    async def test_no_redis_url_is_noop(self) -> None:
        """No REDIS_URL → connect() returns cleanly without touching Redis."""
        bus = WSCrossInstanceBus(redis_url=None)
        handler = AsyncMock()
        await bus.connect(on_targeted=handler)
        assert bus.connected is False
        await bus.disconnect()  # also a no-op, must not raise

    @pytest.mark.asyncio
    async def test_connect_subscribes_to_user_pattern(self, fake_redis) -> None:
        bus = WSCrossInstanceBus(redis_url="redis://localhost:6379/0")
        handler = AsyncMock()
        await bus.connect(on_targeted=handler)
        try:
            assert bus.connected is True
            assert fake_redis.pubsub_obj.psubscribed == ["freesdn:ws:user:*"]
        finally:
            await bus.disconnect()

    @pytest.mark.asyncio
    async def test_disconnect_cancels_listener(self, fake_redis) -> None:
        bus = WSCrossInstanceBus(redis_url="redis://localhost:6379/0")
        await bus.connect(on_targeted=AsyncMock())
        listener = bus._listener_task
        await bus.disconnect()
        assert listener is None or listener.done()
        assert fake_redis.closed is True


class TestPublishToUser:
    @pytest.mark.asyncio
    async def test_publishes_envelope_with_pod_id(self, fake_redis) -> None:
        bus = WSCrossInstanceBus(redis_url="redis://localhost:6379/0")
        await bus.connect(on_targeted=AsyncMock())
        try:
            await bus.publish_to_user("user-42", {"type": "alert", "msg": "hi"})
            assert len(fake_redis.published) == 1
            channel, raw = fake_redis.published[0]
            assert channel == "freesdn:ws:user:user-42"

            envelope = json.loads(raw)
            assert envelope["source_pod_id"] == bus.pod_id
            assert envelope["user_id"] == "user-42"
            assert envelope["payload"] == {"type": "alert", "msg": "hi"}
        finally:
            await bus.disconnect()

    @pytest.mark.asyncio
    async def test_publish_when_disconnected_is_noop(self) -> None:
        """If Redis isn't connected, publish_to_user must not raise."""
        bus = WSCrossInstanceBus(redis_url=None)
        await bus.connect(on_targeted=AsyncMock())
        await bus.publish_to_user("u1", {"a": 1})  # no-op, no exception


class TestSelfDedup:
    @pytest.mark.asyncio
    async def test_self_published_messages_are_dropped(self, fake_redis) -> None:
        """The Redis listener sees our own publishes echoed back —
        these must NOT call the handler again, otherwise we'd
        double-deliver locally."""
        bus = WSCrossInstanceBus(redis_url="redis://localhost:6379/0")
        handler = AsyncMock()
        await bus.connect(on_targeted=handler)
        try:
            # Queue a message tagged with OUR pod_id.
            fake_redis.pubsub_obj.queue_pmessage(
                "freesdn:ws:user:u1",
                {
                    "source_pod_id": bus.pod_id,
                    "user_id": "u1",
                    "payload": {"x": 1},
                },
            )
            await _wait(lambda: True, timeout=0.2)  # let listener tick
            handler.assert_not_called()
        finally:
            await bus.disconnect()


class TestRemoteDelivery:
    @pytest.mark.asyncio
    async def test_remote_messages_invoke_handler(self, fake_redis) -> None:
        delivered: list[tuple[str, dict[str, Any]]] = []

        async def handler(user_id: str, payload: dict[str, Any]) -> None:
            delivered.append((user_id, payload))

        bus = WSCrossInstanceBus(redis_url="redis://localhost:6379/0")
        await bus.connect(on_targeted=handler)
        try:
            fake_redis.pubsub_obj.queue_pmessage(
                "freesdn:ws:user:u1",
                {
                    "source_pod_id": "some-other-pod-uuid",
                    "user_id": "u1",
                    "payload": {"type": "task_update", "id": "t9"},
                },
            )
            await _wait(lambda: len(delivered) >= 1, timeout=1.0)
            assert delivered == [("u1", {"type": "task_update", "id": "t9"})]
        finally:
            await bus.disconnect()


class TestMalformedHandling:
    @pytest.mark.asyncio
    async def test_non_json_dropped_silently(self, fake_redis) -> None:
        handler = AsyncMock()
        bus = WSCrossInstanceBus(redis_url="redis://localhost:6379/0")
        await bus.connect(on_targeted=handler)
        try:
            fake_redis.pubsub_obj._queue.append({
                "type": "pmessage",
                "pattern": "freesdn:ws:user:*",
                "channel": "freesdn:ws:user:u1",
                "data": "not-valid-json{{{",
            })
            await _wait(lambda: True, timeout=0.2)
            handler.assert_not_called()
        finally:
            await bus.disconnect()

    @pytest.mark.asyncio
    async def test_envelope_missing_user_id_dropped(self, fake_redis) -> None:
        handler = AsyncMock()
        bus = WSCrossInstanceBus(redis_url="redis://localhost:6379/0")
        await bus.connect(on_targeted=handler)
        try:
            fake_redis.pubsub_obj.queue_pmessage(
                "freesdn:ws:user:u1",
                {"source_pod_id": "other", "payload": {"x": 1}},  # no user_id
            )
            await _wait(lambda: True, timeout=0.2)
            handler.assert_not_called()
        finally:
            await bus.disconnect()

    @pytest.mark.asyncio
    async def test_handler_exception_does_not_kill_listener(
        self, fake_redis,
    ) -> None:
        """A handler that raises must not stop subsequent deliveries."""
        seen: list[str] = []

        async def handler(uid: str, payload: dict[str, Any]) -> None:
            seen.append(uid)
            if len(seen) == 1:
                raise RuntimeError("boom")

        bus = WSCrossInstanceBus(redis_url="redis://localhost:6379/0")
        await bus.connect(on_targeted=handler)
        try:
            for n in range(3):
                fake_redis.pubsub_obj.queue_pmessage(
                    "freesdn:ws:user:u1",
                    {"source_pod_id": "other", "user_id": f"u{n}",
                     "payload": {"n": n}},
                )
            await _wait(lambda: len(seen) >= 3, timeout=1.0)
            assert seen == ["u0", "u1", "u2"]
        finally:
            await bus.disconnect()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _wait(predicate, *, timeout: float, interval: float = 0.02) -> None:
    async def _poll():
        while not predicate():
            await asyncio.sleep(interval)
    try:
        await asyncio.wait_for(_poll(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
