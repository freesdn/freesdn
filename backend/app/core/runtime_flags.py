# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Runtime-toggleable platform flags (no restart required).

The single operator-facing write-safety switch — ``ADAPTER_READ_ONLY`` — must be
flippable LIVE from the Settings UI, not only via the deploy-time env var. The
runtime override is stored in Redis (shared across all gunicorn + celery
workers) and cached briefly in-process so the per-write read-only GATE stays
effectively synchronous and cheap.

State resolution (most → least specific):
  1. Redis key ``freesdn:config:adapter_read_only`` ("true"/"false"), if set.
  2. The deploy-time env default ``settings.ADAPTER_READ_ONLY``.

Fail-safe: any error reading Redis falls back to the env default; if even that
cannot be read, return True (refuse writes) — the gate never fails OPEN.

NOTE: the env default is the DURABLE default (a monitor-only deployment sets
ADAPTER_READ_ONLY=true in .env). The Redis override is a live operator toggle;
if Redis loses the key the gate falls back to the env default.

WHERE THIS RUNS. ``is_adapter_read_only()`` is a plain ``def`` invoked from
``AdapterStagingService.apply_change`` and from every vendor client's per-write
gate — all coroutines on the API event loop. A blocking Redis GET there holds
the *whole worker* for the round trip, so two things below are load-bearing and
not micro-optimisation:

  * one pooled client for the process, because ``get_sync_redis()`` builds a
    fresh ``redis.Redis`` (and pool) per call — every cache refresh was a new
    DNS lookup + TCP connect + AUTH, not a pooled GET; and
  * the refresh runs on a worker thread once the cache has been primed, so a
    degraded-but-reachable Valkey (Sentinel failover, paused container, packet
    loss) can no longer freeze every request on the worker for the socket
    timeout, once per TTL, health probes included.

The very first read per process still blocks. That is deliberate: serving the
env default before Redis has ever been consulted would let a write through that
the operator had disabled from the UI. It is bounded by the timeouts below and
happens once per worker.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from redis import Redis

_REDIS_KEY = "freesdn:config:adapter_read_only"
_CACHE_TTL_S = (
    5.0  # bounds Redis reads to ~once/5s per worker; toggle propagates within this window
)

# Bound the blocking window explicitly. redis-py falls back
# ``socket_connect_timeout = socket_connect_timeout or socket_timeout``, and
# get_sync_redis() only passes socket_timeout=5 — so a half-open connection
# could hold a caller for ~5s. This gate is a cheap boolean; if Valkey cannot
# answer in a second, the fail-safe env default is the right answer.
_SOCKET_TIMEOUT_S = 1.0

# (override, monotonic_expiry). override is bool | None (None ⇒ "use env default").
_cache: tuple[bool | None, float] = (None, 0.0)
# False until Redis has been consulted at least once in this process. Until
# then a caller must wait for a real answer rather than be served a guess.
_cache_primed = False

_state_lock = threading.Lock()
_refresh_in_flight = False

# One client per process, so a refresh is a pooled GET rather than a fresh
# connect + AUTH. Sentinel-backed clients re-resolve the master per connection,
# so caching the object stays failover-correct.
_client: Redis | None = None


def _get_client() -> Redis:
    """Return the process-wide sync client, creating it on first use."""
    global _client
    client = _client
    if client is None:
        from app.core.redis_client import get_sync_redis

        client = get_sync_redis(
            decode_responses=True,
            socket_timeout=_SOCKET_TIMEOUT_S,
            socket_connect_timeout=_SOCKET_TIMEOUT_S,
        )
        _client = client
    return client


def _env_default() -> bool:
    """The deploy-time default; fail-safe True if config is unreadable."""
    try:
        from app.core.config import settings

        return bool(getattr(settings, "ADAPTER_READ_ONLY", True))
    except Exception:
        return True


def _read_redis_override() -> bool | None:
    """Return the runtime override (True/False), or None if unset/unreachable."""
    try:
        val: Any = _get_client().get(_REDIS_KEY)
        if val is None:
            return None
        return str(val).strip().lower() == "true"
    except Exception:
        return None  # Redis down → caller falls back to the env default


def _refresh_cache() -> None:
    """Read Redis and replace the cached override. Blocks; never raises."""
    global _cache, _cache_primed
    override = _read_redis_override()
    _cache = (override, time.monotonic() + _CACHE_TTL_S)
    _cache_primed = True


def _refresh_in_background() -> None:
    """Kick off at most one off-loop refresh, then return immediately."""
    global _refresh_in_flight
    with _state_lock:
        if _refresh_in_flight:
            return
        _refresh_in_flight = True

    def _worker() -> None:
        global _refresh_in_flight
        try:
            _refresh_cache()
        finally:
            with _state_lock:
                _refresh_in_flight = False

    # A daemon thread rather than loop.run_in_executor: this module is also
    # imported by Celery workers, and the refresh must not depend on an event
    # loop existing or outliving it.
    threading.Thread(target=_worker, name="adapter-read-only-refresh", daemon=True).start()


def _on_event_loop() -> bool:
    """True when the caller is running inside an asyncio event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def is_adapter_read_only() -> bool:
    """Effective read-only state for the adapter write gates.

    Cheap and non-blocking on the hot path: an in-process cache (TTL 5s) bounds
    Redis reads, and once primed the refresh is handed to a worker thread so a
    slow Valkey stalls this gate rather than the caller's event loop. A stale
    value is served for the duration of that refresh — the toggle already lags
    up to the TTL, so this widens an existing window rather than opening a new
    one.
    """
    override, expiry = _cache
    if time.monotonic() < expiry:
        return override if override is not None else _env_default()

    if _cache_primed and _on_event_loop():
        _refresh_in_background()
        return override if override is not None else _env_default()

    _refresh_cache()
    override = _cache[0]
    return override if override is not None else _env_default()


def set_adapter_read_only(read_only: bool) -> None:
    """Persist the runtime override to Redis + refresh this worker's cache.

    No TTL: the operator's choice persists until changed. Raises if Redis is
    unreachable (the caller surfaces a 503 — the change could not be shared).

    Still blocking: this is one deliberate operator action whose result the
    caller has to report, not a per-write gate, and it is bounded by
    ``_SOCKET_TIMEOUT_S``.
    """
    global _cache, _cache_primed
    _get_client().set(_REDIS_KEY, "true" if read_only else "false")
    _cache = (bool(read_only), time.monotonic() + _CACHE_TTL_S)
    _cache_primed = True
