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
"""

from __future__ import annotations

import time

_REDIS_KEY = "freesdn:config:adapter_read_only"
_CACHE_TTL_S = (
    5.0  # bounds Redis reads to ~once/5s per worker; toggle propagates within this window
)

# (override, monotonic_expiry). override is bool | None (None ⇒ "use env default").
_cache: tuple[bool | None, float] = (None, 0.0)


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
        from app.core.redis_client import get_sync_redis

        val = get_sync_redis(decode_responses=True).get(_REDIS_KEY)
        if val is None:
            return None
        return str(val).strip().lower() == "true"
    except Exception:
        return None  # Redis down → caller falls back to the env default


def is_adapter_read_only() -> bool:
    """Effective read-only state for the adapter write gates.

    Cheap + effectively synchronous: an in-process cache (TTL 5s) bounds Redis
    reads, so the per-write gate stays fast while a Settings-UI toggle still
    propagates across all workers within a few seconds.
    """
    global _cache
    now = time.monotonic()
    override, expiry = _cache
    if now >= expiry:
        override = _read_redis_override()
        _cache = (override, now + _CACHE_TTL_S)
    return override if override is not None else _env_default()


def set_adapter_read_only(read_only: bool) -> None:
    """Persist the runtime override to Redis + refresh this worker's cache.

    No TTL: the operator's choice persists until changed. Raises if Redis is
    unreachable (the caller surfaces a 503 — the change could not be shared).
    """
    from app.core.redis_client import get_sync_redis

    get_sync_redis(decode_responses=True).set(_REDIS_KEY, "true" if read_only else "false")
    global _cache
    _cache = (bool(read_only), time.monotonic() + _CACHE_TTL_S)
