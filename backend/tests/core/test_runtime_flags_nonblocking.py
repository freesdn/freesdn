# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression tests for the adapter read-only gate's Redis read.

``is_adapter_read_only()`` is a plain ``def`` called from
``AdapterStagingService.apply_change`` and from every vendor client's per-write
gate -- all coroutines on the API event loop. It used to do the Redis GET
inline through ``get_sync_redis()``, which:

* held the worker's event loop for the whole socket round trip (once per
  5-second cache TTL, so a degraded-but-reachable Valkey froze *every* request
  on that worker in a sawtooth, health probes included), and
* built a brand-new ``redis.Redis`` -- and therefore a new connection pool --
  on every refresh, making each one a fresh DNS lookup + TCP connect + AUTH
  rather than a pooled GET, with no ``socket_connect_timeout`` set (redis-py
  then inherits the 5s ``socket_timeout``).

The safety semantics must NOT change: the gate still fails safe, and the first
read in a process still consults Redis before answering.
"""

import asyncio
import time
from collections.abc import Iterator
from typing import Any

import pytest

import app.core.redis_client as redis_client
import app.core.runtime_flags as rf


class _FakeRedis:
    """A sync Redis stand-in whose GET/SET take a controllable amount of time."""

    def __init__(self, value: str | None = "true", delay: float = 0.0) -> None:
        self.value = value
        self.delay = delay
        self.get_calls = 0
        self.set_calls = 0

    def get(self, key: str) -> str | None:
        self.get_calls += 1
        if self.delay:
            time.sleep(self.delay)
        return self.value

    def set(self, key: str, value: str, **kwargs: Any) -> bool:
        self.set_calls += 1
        if self.delay:
            time.sleep(self.delay)
        self.value = value
        return True


@pytest.fixture
def clean_flag_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset the module's process-wide cache and client around each test.

    Teardown is NOT just monkeypatch's restore. The refresh runs on a daemon
    thread that writes ``_cache``/``_cache_primed`` directly, and it can land
    AFTER monkeypatch has put the originals back -- which leaves a bogus
    override in the module and breaks whatever unrelated test runs next
    (``test_proxmox_safety`` and ``test_voip_security`` both patch
    ``settings.ADAPTER_READ_ONLY`` and read this flag). Wait the thread out,
    then reset by hand.
    """
    monkeypatch.setattr(rf, "_client", None)
    monkeypatch.setattr(rf, "_cache", (None, 0.0))
    monkeypatch.setattr(rf, "_cache_primed", False)
    monkeypatch.setattr(rf, "_refresh_in_flight", False)
    yield
    deadline = time.monotonic() + 5.0
    while rf._refresh_in_flight and time.monotonic() < deadline:
        time.sleep(0.01)
    rf._cache = (None, 0.0)
    rf._cache_primed = False
    rf._client = None


def _install(monkeypatch: pytest.MonkeyPatch, fake: _FakeRedis) -> dict[str, Any]:
    """Point the flag module at *fake* and capture the client kwargs."""
    captured: dict[str, Any] = {}

    def _factory(**kwargs: Any) -> _FakeRedis:
        captured.update(kwargs)
        captured["build_count"] = captured.get("build_count", 0) + 1
        return fake

    monkeypatch.setattr(redis_client, "get_sync_redis", _factory)
    return captured


async def _prime_off_loop() -> bool:
    """Do the first (blocking) read on a worker thread, as a cold worker would."""
    return await asyncio.to_thread(rf.is_adapter_read_only)


# ---------------------------------------------------------------------------
# The event loop must survive a slow Valkey
# ---------------------------------------------------------------------------


async def test_warm_refresh_does_not_block_the_event_loop(
    monkeypatch: pytest.MonkeyPatch, clean_flag_state: None
) -> None:
    """A stale cache must not make the gate wait on the socket.

    Mutation this catches: reverting ``is_adapter_read_only`` to refresh inline
    (``_refresh_cache()`` on every expiry), which is what stalled the worker.
    """
    fake = _FakeRedis(value="true", delay=0.75)
    _install(monkeypatch, fake)

    assert await _prime_off_loop() is True
    assert fake.get_calls == 1

    # Expire the cache, keeping the primed value.
    monkeypatch.setattr(rf, "_cache", (True, 0.0))

    started = time.monotonic()
    result = rf.is_adapter_read_only()
    elapsed = time.monotonic() - started

    assert result is True
    assert elapsed < 0.1, f"gate held the event loop for {elapsed:.3f}s"

    # ...and the refresh really did happen, off the loop. Without this a
    # "fix" that simply stopped refreshing would pass the timing assertion.
    for _ in range(100):
        if fake.get_calls >= 2:
            break
        await asyncio.sleep(0.02)
    assert fake.get_calls >= 2, "background refresh never ran"


async def test_concurrent_gate_checks_start_only_one_refresh(
    monkeypatch: pytest.MonkeyPatch, clean_flag_state: None
) -> None:
    """A burst of writes must not spawn a refresh thread per call.

    Mutation this catches: dropping the ``_refresh_in_flight`` guard, which
    would start one thread (and one Redis round trip) per gate check while the
    first is still in flight.
    """
    fake = _FakeRedis(value="false", delay=0.3)
    _install(monkeypatch, fake)

    await _prime_off_loop()
    monkeypatch.setattr(rf, "_cache", (False, 0.0))

    for _ in range(20):
        rf.is_adapter_read_only()

    for _ in range(100):
        if not rf._refresh_in_flight:
            break
        await asyncio.sleep(0.02)

    # 1 prime + 1 coalesced refresh.
    assert fake.get_calls == 2, f"expected one coalesced refresh, saw {fake.get_calls - 1}"


# ---------------------------------------------------------------------------
# ...without weakening the gate
# ---------------------------------------------------------------------------


async def test_cold_read_consults_redis_even_on_the_event_loop(
    monkeypatch: pytest.MonkeyPatch, clean_flag_state: None
) -> None:
    """The first read must not be answered from the env default.

    The shipped compose sets ADAPTER_READ_ONLY=false (read-WRITE). If a freshly
    started worker served that while a background refresh was still in flight,
    the very first write after a restart would bypass an operator freeze set
    from the Settings UI.

    Mutation this catches: extending the background-refresh path to the
    unprimed cache.
    """
    fake = _FakeRedis(value="true", delay=0.0)
    _install(monkeypatch, fake)

    assert rf.is_adapter_read_only() is True
    assert fake.get_calls == 1, "cold read answered without consulting Redis"


async def test_stale_value_is_served_not_the_env_default(
    monkeypatch: pytest.MonkeyPatch, clean_flag_state: None
) -> None:
    """While refreshing, the last KNOWN override wins over the env default.

    Mutation this catches: returning ``_env_default()`` during the refresh
    window, which on the shipped read-write default would unfreeze a
    deliberately frozen appliance for the duration of every refresh.
    """
    fake = _FakeRedis(value="true", delay=0.5)
    _install(monkeypatch, fake)
    monkeypatch.setattr(rf, "_env_default", lambda: False)

    await _prime_off_loop()
    monkeypatch.setattr(rf, "_cache", (True, 0.0))

    assert rf.is_adapter_read_only() is True


def test_sync_caller_still_reads_inline(
    monkeypatch: pytest.MonkeyPatch, clean_flag_state: None
) -> None:
    """Celery and scripts have no loop to protect, so nothing is deferred.

    Mutation this catches: always deferring to a thread, which would make a
    Celery task's gate check race its own refresh and read a stale value.
    """
    fake = _FakeRedis(value="true", delay=0.0)
    _install(monkeypatch, fake)

    assert rf.is_adapter_read_only() is True
    monkeypatch.setattr(rf, "_cache", (True, 0.0))
    fake.value = "false"

    assert rf.is_adapter_read_only() is False, "sync caller got a stale value"
    assert fake.get_calls == 2


# ---------------------------------------------------------------------------
# Client construction
# ---------------------------------------------------------------------------


def test_client_is_built_once_and_reused(
    monkeypatch: pytest.MonkeyPatch, clean_flag_state: None
) -> None:
    """Refreshes must reuse one pooled client.

    Mutation this catches: going back to calling ``get_sync_redis()`` inside
    ``_read_redis_override``, which rebuilt the client (and its pool) per read
    -- a DNS lookup, TCP connect and AUTH every 5 seconds per worker.
    """
    fake = _FakeRedis(value="true")
    captured = _install(monkeypatch, fake)

    rf.is_adapter_read_only()
    monkeypatch.setattr(rf, "_cache", (True, 0.0))
    rf.is_adapter_read_only()

    assert fake.get_calls == 2
    assert captured["build_count"] == 1


def test_client_timeouts_are_bounded(
    monkeypatch: pytest.MonkeyPatch, clean_flag_state: None
) -> None:
    """Both timeouts must be set and short.

    redis-py falls back ``socket_connect_timeout = socket_connect_timeout or
    socket_timeout``; ``get_sync_redis`` supplies only ``socket_timeout=5``, so
    an unresponsive half-open connection could hold a caller for ~5s.

    Mutation this catches: dropping either kwarg, or raising them back toward
    the 5s default.
    """
    fake = _FakeRedis(value="true")
    captured = _install(monkeypatch, fake)

    rf.is_adapter_read_only()

    assert captured["socket_timeout"] <= 2
    assert captured["socket_connect_timeout"] <= 2
    assert captured["decode_responses"] is True
