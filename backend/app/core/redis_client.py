# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Central Redis/Valkey client factory — Sentinel-aware for high availability.

Every Redis consumer in the codebase should create clients through this module
instead of calling ``redis.from_url(settings.REDIS_URL)`` directly. That single
indirection is what makes the platform survive a Redis/Valkey master failure:

  * When ``settings.REDIS_SENTINELS`` is set, clients are created via Sentinel
    and ``master_for()`` re-resolves the *current* master on every connection,
    so when Sentinel promotes a replica the app follows it automatically.
  * Otherwise we connect directly to ``REDIS_HOST`` (single-node — dev/lite/pro).

The backing server may be Redis or Valkey; both speak RESP and ship the same
Sentinel, so this code is identical for either.

Async and sync variants are provided because the codebase uses both
(``redis.asyncio`` in the API/WS paths, sync ``redis`` in Celery tasks).
"""

from __future__ import annotations

from typing import Any

import redis as _sync_redis
import redis.asyncio as _async_redis

from app.core.config import settings


def sentinel_addrs() -> list[tuple[str, int]]:
    """Parse ``REDIS_SENTINELS`` ("host:port,host:port") into (host, port) tuples."""
    raw = (settings.REDIS_SENTINELS or "").strip()
    addrs: list[tuple[str, int]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        host, _, port = part.partition(":")
        addrs.append((host.strip(), int(port) if port.strip() else 26379))
    return addrs


def ha_enabled() -> bool:
    """True when Sentinel-based HA is configured."""
    return bool(sentinel_addrs())


def _direct_url(db: int) -> str:
    pw = settings.REDIS_PASSWORD or ""
    auth = f":{pw}@" if pw else ""
    return f"redis://{auth}{settings.REDIS_HOST}:{settings.REDIS_PORT}/{db}"


def _sentinel_kwargs() -> dict[str, Any]:
    # Sentinels themselves require AUTH in our deployment (auth-pass).
    return {"password": settings.REDIS_PASSWORD} if settings.REDIS_PASSWORD else {}


# Default command timeout on the MASTER connection. Critical for failover: a
# frozen/partitioned master (TCP open but unresponsive) otherwise blocks every
# command until the OS TCP timeout (minutes), so the app can't re-resolve to the
# promoted master. 5s makes a hung command fail fast → redis-py re-queries
# Sentinel for the new master on the next call.
# EXCEPTION: pub/sub listeners pass socket_timeout=None, because socket_timeout
# would interrupt the long-lived blocking listen() read.
_SENTINEL_QUERY_TIMEOUT = 5  # connecting to / querying the sentinels themselves


def get_async_redis(
    db: int = 0, *, decode_responses: bool = False, socket_timeout: float | None = 5, **kwargs: Any
) -> _async_redis.Redis:
    """Return an async Redis/Valkey client (Sentinel-aware when HA is configured)."""
    addrs = sentinel_addrs()
    if addrs:
        sentinel = _async_redis.sentinel.Sentinel(
            addrs,
            sentinel_kwargs=_sentinel_kwargs(),
            password=settings.REDIS_PASSWORD or None,
            socket_timeout=_SENTINEL_QUERY_TIMEOUT,
        )
        return sentinel.master_for(
            settings.REDIS_MASTER_NAME,
            db=db,
            decode_responses=decode_responses,
            password=settings.REDIS_PASSWORD or None,
            socket_timeout=socket_timeout,
            **kwargs,
        )
    return _async_redis.from_url(
        _direct_url(db), decode_responses=decode_responses, socket_timeout=socket_timeout, **kwargs
    )


def get_sync_redis(
    db: int = 0, *, decode_responses: bool = False, socket_timeout: float | None = 5, **kwargs: Any
) -> _sync_redis.Redis:
    """Return a sync Redis/Valkey client (Sentinel-aware when HA is configured)."""
    addrs = sentinel_addrs()
    if addrs:
        sentinel = _sync_redis.sentinel.Sentinel(
            addrs,
            sentinel_kwargs=_sentinel_kwargs(),
            password=settings.REDIS_PASSWORD or None,
            socket_timeout=_SENTINEL_QUERY_TIMEOUT,
        )
        return sentinel.master_for(
            settings.REDIS_MASTER_NAME,
            db=db,
            decode_responses=decode_responses,
            password=settings.REDIS_PASSWORD or None,
            socket_timeout=socket_timeout,
            **kwargs,
        )
    return _sync_redis.from_url(
        _direct_url(db), decode_responses=decode_responses, socket_timeout=socket_timeout, **kwargs
    )
