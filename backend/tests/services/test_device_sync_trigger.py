# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression tests for ``trigger_device_registry_sync``.

Every caller is an ``async def`` FastAPI handler (``create_nvr``,
``create_gateway``, ``create_pbx`` and their update twins), yet the function
did a blocking Redis ``SET NX`` plus a blocking Celery broker publish -- and
its docstring claimed "Safe to call from any async or sync context". On a slow
broker or a Valkey failover that froze the worker's whole event loop mid
request, and a Redis error propagated out of a handler that had ALREADY
committed the row, so the operator saw a 500 for a device that exists.
"""

import asyncio
import time
from typing import Any

import pytest

import app.core.redis_client as redis_client
import app.services.device_sync as device_sync


class _FakeRedis:
    def __init__(self, delay: float = 0.0, raise_on_set: bool = False) -> None:
        self.delay = delay
        self.raise_on_set = raise_on_set
        self.set_calls = 0
        self.closed = False

    def set(self, key: str, value: str, **kwargs: Any) -> bool:
        self.set_calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.raise_on_set:
            raise ConnectionError("valkey unreachable")
        return True

    def close(self) -> None:
        self.closed = True


class _FakeCelery:
    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.sent: list[tuple[str, Any]] = []

    def send_task(self, name: str, **kwargs: Any) -> None:
        if self.delay:
            time.sleep(self.delay)
        self.sent.append((name, kwargs))


@pytest.fixture
def fake_broker(monkeypatch: pytest.MonkeyPatch) -> tuple[_FakeRedis, _FakeCelery]:
    """Slow, in-memory stand-ins for Redis and the Celery broker."""
    import app.core.celery_app as celery_module

    fake_redis = _FakeRedis(delay=0.6)
    fake_celery = _FakeCelery(delay=0.6)
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda *_a, **_k: fake_redis)
    monkeypatch.setattr(celery_module, "celery_app", fake_celery)
    return fake_redis, fake_celery


async def _wait_for(predicate: Any, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return False


async def test_trigger_does_not_block_the_event_loop(
    fake_broker: tuple[_FakeRedis, _FakeCelery],
) -> None:
    """The handler must return before the broker round trip finishes.

    Mutation this catches: reverting to the inline body, which held the loop
    for the Redis SET plus the broker publish (1.2s with these stand-ins).
    """
    fake_redis, fake_celery = fake_broker

    started = time.monotonic()
    device_sync.trigger_device_registry_sync("cameras")
    elapsed = time.monotonic() - started

    assert elapsed < 0.1, f"trigger held the event loop for {elapsed:.3f}s"

    # ...and the dispatch still happens. Without this, a "fix" that dropped the
    # work entirely would pass the timing assertion.
    assert await _wait_for(lambda: bool(fake_celery.sent)), "sync task never dispatched"
    assert fake_celery.sent[0][0] == "sync.sync_module_incremental"
    assert fake_celery.sent[0][1]["args"] == ["cameras"]
    assert fake_redis.set_calls == 1


async def test_broker_failure_does_not_escape_into_the_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Redis outage must not 500 a create whose row is already committed.

    Mutation this catches: re-raising from the worker, or running inline again
    -- either turns "Valkey is down" into "your NVR was not created", which is
    false.
    """
    fake_redis = _FakeRedis(raise_on_set=True)
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda *_a, **_k: fake_redis)

    device_sync.trigger_device_registry_sync("cameras")  # must not raise

    assert await _wait_for(lambda: fake_redis.set_calls == 1)
    assert await _wait_for(lambda: fake_redis.closed), "client leaked on the failure path"


def test_sync_caller_dispatches_inline_and_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Off an event loop (Celery, scripts) nothing is deferred or swallowed.

    Mutation this catches: always threading, which would make a Celery caller
    unable to observe or retry a broker failure.
    """
    import app.core.celery_app as celery_module

    fake_redis = _FakeRedis()
    fake_celery = _FakeCelery()
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda *_a, **_k: fake_redis)
    monkeypatch.setattr(celery_module, "celery_app", fake_celery)

    device_sync.trigger_device_registry_sync("voip")

    # Already done by the time the call returns -- no waiting.
    assert fake_redis.set_calls == 1
    assert fake_celery.sent[0][1]["args"] == ["voip"]
    assert fake_redis.closed

    failing = _FakeRedis(raise_on_set=True)
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda *_a, **_k: failing)
    with pytest.raises(ConnectionError):
        device_sync.trigger_device_registry_sync("voip")
    assert failing.closed, "client leaked on the failure path"


def test_debounce_skips_the_broker_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    """A losing SET NX must not publish a duplicate task.

    Mutation this catches: moving the ``send_task`` call out of the ``if``,
    which would defeat the debounce that exists so a 50-NVR bulk import does
    not queue 50 syncs.
    """
    import app.core.celery_app as celery_module

    class _Losing(_FakeRedis):
        def set(self, key: str, value: str, **kwargs: Any) -> bool:
            self.set_calls += 1
            return False  # key already present -> another worker queued it

    losing = _Losing()
    fake_celery = _FakeCelery()
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda *_a, **_k: losing)
    monkeypatch.setattr(celery_module, "celery_app", fake_celery)

    device_sync.trigger_device_registry_sync("firewall")

    assert losing.set_calls == 1
    assert fake_celery.sent == []
    assert losing.closed
