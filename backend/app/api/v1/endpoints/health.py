# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Health Check Endpoints
====================================

Comprehensive health checks for application, database, and Redis.
"""

import asyncio
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import require_permissions
from app.core.startup import SUBSYSTEM_STATUS
from app.db import get_session

router = APIRouter()


class HealthStatus(StrEnum):
    """Health check status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ComponentHealth(BaseModel):
    """Health status of a single component."""

    status: HealthStatus
    latency_ms: float | None = None
    details: dict[str, Any] | None = None
    error: str | None = None


class PlatformInfo(BaseModel):
    """Platform/runtime metadata."""

    python_version: str
    fastapi_version: str
    sqlalchemy_version: str
    pydantic_version: str
    cryptography_version: str


class HealthResponse(BaseModel):
    """Full health check response."""

    status: HealthStatus
    app: str
    version: str
    environment: str
    timestamp: datetime
    uptime_seconds: float | None = None
    components: dict[str, ComponentHealth] = {}
    platform: PlatformInfo | None = None


def _get_platform_info() -> PlatformInfo:
    """Collect runtime version metadata."""
    import sys

    import cryptography
    import fastapi
    import pydantic
    import sqlalchemy

    return PlatformInfo(
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        fastapi_version=fastapi.__version__,
        sqlalchemy_version=sqlalchemy.__version__,
        pydantic_version=pydantic.VERSION,
        cryptography_version=cryptography.__version__,
    )


# Track application start time
_start_time = time.time()


async def check_database(session: AsyncSession) -> ComponentHealth:
    """Check database connectivity and latency."""
    start = time.time()
    try:
        # Execute a simple query
        result = await session.execute(text("SELECT 1"))
        result.scalar()
        latency = (time.time() - start) * 1000

        return ComponentHealth(
            status=HealthStatus.HEALTHY,
            latency_ms=round(latency, 2),
            details={"type": "postgresql"},
        )
    except Exception as e:
        return ComponentHealth(
            status=HealthStatus.UNHEALTHY,
            error=str(e),
        )


async def check_redis() -> ComponentHealth:
    """Check Redis connectivity and latency."""
    start = time.time()
    try:
        from app.core.redis_client import get_async_redis

        if not settings.REDIS_URL:
            return ComponentHealth(
                status=HealthStatus.HEALTHY,
                details={"enabled": False, "message": "Redis not configured"},
            )

        # Sentinel-aware (HA): resolves + pings the current master.
        client = get_async_redis()
        await client.ping()
        latency = (time.time() - start) * 1000

        # Get some Redis info
        info = await client.info("server")
        await client.close()

        return ComponentHealth(
            status=HealthStatus.HEALTHY,
            latency_ms=round(latency, 2),
            details={
                "version": info.get("redis_version"),
                "uptime_days": info.get("uptime_in_days"),
            },
        )
    except Exception as e:
        return ComponentHealth(
            status=HealthStatus.UNHEALTHY,
            error=str(e),
        )


async def _count_celery_workers(celery_app: Any) -> int | None:
    """Best-effort count of live Celery workers via ``inspect()``.

    Returns the number of responding workers, or ``None`` if the broadcast
    could not be completed (no reply within the timeout, broker error, etc.).
    ``inspect()`` is a synchronous, blocking broadcast, so it is offloaded to a
    thread and bounded by an overall timeout to avoid stalling the event loop.
    This is purely informational — callers must treat ``None`` as "count
    unavailable", never as "no workers".
    """
    try:
        from app.core.celery_app import celery_app as _app

        app = celery_app or _app

        def _ping() -> int | None:
            # Short per-broadcast timeout; ping() returns {hostname: {"ok": "pong"}}
            replies = app.control.inspect(timeout=1.0).ping()
            return len(replies) if replies else None

        return await asyncio.wait_for(asyncio.to_thread(_ping), timeout=2.0)
    except Exception:
        return None


async def check_celery() -> ComponentHealth:
    """Check Celery worker liveness via a TTL-based heartbeat key in Redis.

    We avoid ``celery.control.inspect().ping()`` because with a solo pool
    (concurrency=1) the worker thread is blocked executing tasks and cannot
    respond to broadcast pings, causing false-negative "degraded" signals.

    We also avoid scanning ``_kombu.binding.*`` keys because those persist
    after startup and prove queue declaration, not live worker health.

    Instead, we use a **real heartbeat**: the Celery beat scheduler dispatches
    a lightweight ``worker.heartbeat`` task every 30 seconds, which writes
    the Redis key ``freesdn:worker:heartbeat`` with a 90-second TTL.  If the
    key exists and the timestamp is recent, the worker is alive.  If the key
    is missing (expired), the worker has not completed a task in >90 seconds
    and is likely down.

    The Redis check uses GET (O(1)), not KEYS/SCAN (O(N)).
    """
    start = time.monotonic()
    try:
        from app.core.celery_app import celery_app
        from app.core.redis_client import get_async_redis

        # Worker heartbeat is written to the broker DB (1). Sentinel-aware so the
        # check follows a failover instead of pinging a dead master.
        r = get_async_redis(db=1, decode_responses=True)
        try:
            # O(1) GET — checks the TTL heartbeat key written by the worker
            heartbeat = await r.get("freesdn:worker:heartbeat")
            latency = (time.monotonic() - start) * 1000

            if heartbeat:
                details: dict[str, Any] = {
                    "last_heartbeat": heartbeat,
                    "mechanism": "ttl_heartbeat",
                }
                # Best-effort live worker count. ``inspect()`` is a blocking
                # broadcast call, so it runs in a thread with a short timeout
                # and is fully exception-safe — failure simply omits the
                # ``workers`` detail rather than regressing the (already
                # determined) HEALTHY liveness verdict above.
                worker_count = await _count_celery_workers(celery_app)
                if worker_count is not None:
                    details["workers"] = worker_count

                return ComponentHealth(
                    status=HealthStatus.HEALTHY,
                    latency_ms=round(latency, 1),
                    details=details,
                )

            # Heartbeat key missing — worker may have just started or is down.
            # Fall back: check if queue binding keys exist (proves worker
            # connected to broker at least once since Redis started).
            cursor, bindings = await r.scan(cursor=0, match="_kombu.binding.*", count=5)
            latency = (time.monotonic() - start) * 1000

            if bindings:
                # Queues exist but no recent heartbeat — worker may be starting
                return ComponentHealth(
                    status=HealthStatus.DEGRADED,
                    latency_ms=round(latency, 1),
                    details={
                        "message": "Queues registered but no recent worker heartbeat",
                        "queues_found": len(bindings),
                    },
                )

            return ComponentHealth(
                status=HealthStatus.DEGRADED,
                latency_ms=round(latency, 1),
                details={"message": "No worker heartbeat or queue bindings found"},
            )
        finally:
            await r.aclose()
    except Exception:
        latency = (time.monotonic() - start) * 1000
        return ComponentHealth(
            status=HealthStatus.DEGRADED,
            latency_ms=round(latency, 1),
            error="Celery broker check failed",
            details={"message": "Could not query broker for worker state"},
        )


def aggregate_status(components: dict[str, ComponentHealth]) -> HealthStatus:
    """Determine overall status from component statuses."""
    statuses = [c.status for c in components.values()]

    if any(s == HealthStatus.UNHEALTHY for s in statuses):
        return HealthStatus.UNHEALTHY
    if any(s == HealthStatus.DEGRADED for s in statuses):
        return HealthStatus.DEGRADED
    return HealthStatus.HEALTHY


class ComponentStatusOnly(BaseModel):
    """Per-component status with no latency/error detail (public view)."""

    status: HealthStatus


class PublicHealthResponse(BaseModel):
    """Minimal, unauthenticated health payload.

    Deliberately status-only: per-component ``{status}`` but NO
    latencies, dependency/package versions, app version, or
    environment — those are reconnaissance signals (version targeting,
    infra fingerprinting) and live behind the authenticated
    /health/detail endpoint. Component shape stays an
    object so existing dashboard consumers reading
    ``components.{x}.status`` keep working.
    """

    status: HealthStatus
    timestamp: datetime
    components: dict[str, ComponentStatusOnly] = {}


async def _collect_components(session: AsyncSession) -> dict[str, ComponentHealth]:
    """Run all component checks concurrently and assemble the map."""
    db_check, redis_check, celery_check = await asyncio.gather(
        check_database(session),
        check_redis(),
        check_celery(),
        return_exceptions=True,
    )
    components: dict[str, ComponentHealth] = {}
    components["database"] = (
        ComponentHealth(status=HealthStatus.UNHEALTHY)
        if isinstance(db_check, Exception)
        else db_check
    )
    components["redis"] = (
        ComponentHealth(status=HealthStatus.UNHEALTHY)
        if isinstance(redis_check, Exception)
        else redis_check
    )
    components["celery"] = (
        ComponentHealth(status=HealthStatus.DEGRADED)
        if isinstance(celery_check, Exception)
        else celery_check
    )
    for name, st in SUBSYSTEM_STATUS.items():
        if st != "healthy":
            components[name] = ComponentHealth(
                status=HealthStatus.DEGRADED,
                details={"reason": "failed during startup"},
            )
    return components


@router.get("/", response_model=PublicHealthResponse)
async def health_check(
    session: AsyncSession = Depends(get_session),
) -> Any:
    """
    Public health check endpoint — status only.

    Returns overall + per-component status (healthy/degraded/unhealthy)
    with NO versions, latencies, or infra metadata. Use the
    authenticated /health/detail for the full picture.
    """
    components = await _collect_components(session)
    return PublicHealthResponse(
        status=aggregate_status(components),
        timestamp=datetime.now(UTC),
        components={name: ComponentStatusOnly(status=c.status) for name, c in components.items()},
    )


@router.get("/detail", response_model=HealthResponse)
async def health_detail(
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("settings:read")),
) -> Any:
    """
    Full health detail — authenticated (settings:read).

    Includes component latencies, dependency/package versions, app
    version, environment, and uptime. Gated because this is
    infrastructure-grade metadata, not something anonymous callers
    should be able to fingerprint.
    """
    components = await _collect_components(session)
    return HealthResponse(
        status=aggregate_status(components),
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(UTC),
        uptime_seconds=round(time.time() - _start_time, 2),
        components=components,
        platform=_get_platform_info(),
    )


async def _probe_db_engine(eng: Any, timeout: float = 6.0) -> None:
    """Fail-fast connectivity probe on a FRESH connection — acquisition INCLUDED
    in the timeout.

    Readiness must NOT use the pooled request session for its gate: a FROZEN DB
    (disk-full / failover-in-progress / network partition — i.e. hangs rather than
    cleanly refusing) makes the pool checkout + ``pool_pre_ping`` SELECT 1 block
    for the full OS TCP timeout (minutes). With ``Depends(get_session)`` that hang
    happens BEFORE the endpoint body, so the per-check ``wait_for`` never fires —
    every readiness request then ties up a gunicorn worker until the pool is
    exhausted and the whole instance stops serving even ``/live``. Wrapping a
    fresh ``engine.connect()`` in ``wait_for`` bounds connect AND query, so a
    frozen DB yields a clean 503 in ``timeout`` seconds. (Battle-tested: before
    this, /ready hung 35s+ under a paused Postgres.)
    """

    async def _run() -> None:
        async with eng.connect() as conn:
            await conn.execute(text("SELECT 1"))

    await asyncio.wait_for(_run(), timeout=timeout)


@router.get("/ready")
async def readiness_check() -> Any:
    """
    Kubernetes / load-balancer readiness probe.

    HARD-gates (503) on what makes THIS instance unable to serve: the per-instance
    primary DB connection and critical subsystems (event_bus, modules). Redis and
    LogDB are PROBED and REPORTED in the payload but do NOT gate by default —
    they are SHARED dependencies, so hard-gating readiness on them would make a
    transient Redis blip (or the ~9s Sentinel failover window) pull EVERY instance
    out of the LB at once → a cascading full outage. Set READINESS_STRICT_DEPS=true
    to also 503 on Redis/LogDB.

    Uses fresh, time-boxed connections (NOT the pooled request session) so a
    frozen DB fails fast at 503 instead of hanging — see _probe_db_engine.
    """
    from app.db.session import readiness_engine, readiness_logdb_engine

    checks: dict[str, str] = {}
    hard_failures: list[str] = []

    # Primary DB — hard gate (per-instance; a stuck instance must be pulled).
    # readiness_engine = NullPool + asyncpg connect/command timeouts → fails fast
    # on a frozen DB (the main pool would hang; see _probe_db_engine).
    try:
        await _probe_db_engine(readiness_engine)
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unreachable"
        hard_failures.append("database")

    # Redis/Valkey — probe + report (shared; Sentinel HA recovers a master loss).
    try:
        rc = await asyncio.wait_for(check_redis(), timeout=3)
        checks["redis"] = rc.status.value
    except Exception:
        checks["redis"] = "unreachable"

    # LogDB — probe + report (shared, single-node time-series DB).
    if readiness_logdb_engine is None:
        checks["logdb"] = "disabled"
    else:
        try:
            await _probe_db_engine(readiness_logdb_engine)
            checks["logdb"] = "ok"
        except Exception:
            checks["logdb"] = "unreachable"

    # Critical subsystems — hard gate (existing behavior).
    critical = ["modules", "event_bus"]
    degraded = [s for s in critical if SUBSYSTEM_STATUS.get(s) == "degraded"]

    # Optional strict gating on the shared deps (off by default — see docstring).
    if settings.READINESS_STRICT_DEPS:
        hard_failures += [
            d for d in ("redis", "logdb") if checks.get(d) in ("unreachable", "unhealthy")
        ]

    if hard_failures or degraded:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "failed": hard_failures,
                "degraded_subsystems": degraded,
                "checks": checks,
            },
        )

    return {"status": "ready", "checks": checks}


@router.get("/live")
async def liveness_check() -> Any:
    """
    Kubernetes liveness probe endpoint.

    Indicates the application is running.
    Always returns 200 unless the process is dead.
    """
    return {"status": "alive", "timestamp": datetime.now(UTC).isoformat()}
