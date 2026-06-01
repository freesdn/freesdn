# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - System Information Endpoints
==========================================

System info, version details, and platform metadata.
"""

import contextlib
import os
import platform
import time
from datetime import UTC, datetime
from typing import Any
from typing import Any as _Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import is_unscoped_superuser, require_permissions
from app.core.redis_client import get_async_redis
from app.db import get_session

router = APIRouter()


# ── Adapter write-safety (read-only ↔ read-write), runtime-toggleable ──────────
class AdapterReadOnlyState(BaseModel):
    """Platform write-safety mode. read_only=true ⇒ device writes are refused
    (monitor-only); false ⇒ read-write (manage). One switch, two states."""

    read_only: bool


@router.get("/settings/adapter-read-only", response_model=AdapterReadOnlyState)
async def get_adapter_read_only_state(
    _user: _Any = Depends(require_permissions("settings:read")),
) -> _Any:
    """Current effective write-safety state (runtime override, else env default)."""
    from app.core.runtime_flags import is_adapter_read_only

    return AdapterReadOnlyState(read_only=is_adapter_read_only())


@router.put("/settings/adapter-read-only", response_model=AdapterReadOnlyState)
async def set_adapter_read_only_state(
    body: AdapterReadOnlyState,
    # Write-level gate: this mutates a platform-wide safety setting. ``settings:read``
    # (granted to org_admin) must not gate a write — require ``settings:write`` so the
    # decorator matches the operation; the is_unscoped_superuser check below remains.
    current_user: _Any = Depends(require_permissions("settings:write")),
) -> _Any:
    """Flip the platform write-safety mode LIVE (no restart) — super-admin only.

    Persisted as a runtime override in Redis (the env var stays the durable
    default). Propagates to every worker's gate within a few seconds.
    """
    if not is_unscoped_superuser(current_user):
        raise HTTPException(
            status_code=403,
            detail="Only a super administrator can change the write-safety mode",
        )
    from app.core.runtime_flags import is_adapter_read_only, set_adapter_read_only

    try:
        set_adapter_read_only(body.read_only)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail=f"Could not persist the setting (Redis unavailable): {e}",
        ) from e
    return AdapterReadOnlyState(read_only=is_adapter_read_only())


_start_time = time.time()


class DatabaseInfo(BaseModel):
    type: str
    version: str
    host: str
    database: str
    pool_size: int
    status: str


class RedisInfo(BaseModel):
    host: str
    port: int
    database: int
    status: str
    version: str | None = None


class ComponentVersion(BaseModel):
    name: str
    version: str
    status: str = "current"
    latest_version: str | None = None
    update_available: bool = False


class SystemInfoResponse(BaseModel):
    app_name: str
    app_version: str
    app_license: str
    environment: str
    server_time: str
    uptime_seconds: float | None = None
    python_version: str
    python_implementation: str
    os_name: str
    os_version: str
    os_platform: str
    architecture: str
    database: DatabaseInfo
    redis: RedisInfo
    components: list[ComponentVersion]


@router.get("/info", response_model=SystemInfoResponse)
async def get_system_info(
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("settings:read")),
) -> Any:
    """Return system information for the dashboard.

    Gated behind ``settings:read`` — this exposes DB/Redis host names,
    DB name, OS/platform, and component versions, which is admin-grade
    infrastructure metadata, not something every active user should see.
    """
    # Database info
    db_version = "unknown"
    db_status = "unhealthy"
    try:
        result = await session.execute(text("SELECT version()"))
        row = result.scalar()
        if row:
            db_version = row.split(",")[0] if "," in row else row
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"

    db_url = str(settings.DATABASE_URL)
    db_host = ""
    db_name = ""
    try:
        # Parse host and dbname from URL like postgresql+asyncpg://user:pass@host:port/dbname
        parts = db_url.split("@")[-1] if "@" in db_url else ""
        db_host = parts.split("/")[0] if "/" in parts else parts
        db_name = parts.split("/")[1].split("?")[0] if "/" in parts else ""
    except (IndexError, ValueError):
        pass

    database = DatabaseInfo(
        type="postgresql",
        version=db_version,
        host=db_host,
        database=db_name,
        pool_size=settings.DB_POOL_SIZE if hasattr(settings, "DB_POOL_SIZE") else 10,
        status=db_status,
    )

    # Redis info
    redis_info = RedisInfo(host="", port=6379, database=0, status="not configured")
    if settings.REDIS_URL:
        try:
            client = get_async_redis()
            info = await client.info("server")
            await client.close()
            redis_url = str(settings.REDIS_URL)
            r_host = (
                redis_url.split("@")[-1].split("/")[0]
                if "@" in redis_url
                else redis_url.split("//")[-1].split("/")[0]
            )
            r_port = int(r_host.split(":")[1]) if ":" in r_host else 6379
            r_host = r_host.split(":")[0]
            r_db = 0
            with contextlib.suppress(ValueError, IndexError):
                r_db = int(redis_url.rstrip("/").split("/")[-1])
            redis_info = RedisInfo(
                host=r_host,
                port=r_port,
                database=r_db,
                status="healthy",
                version=info.get("redis_version"),
            )
        except Exception:
            redis_info = RedisInfo(host="", port=6379, database=0, status="unhealthy")

    # Components
    components = [
        ComponentVersion(name="FastAPI", version=_get_package_version("fastapi")),
        ComponentVersion(name="SQLAlchemy", version=_get_package_version("sqlalchemy")),
        ComponentVersion(name="Celery", version=_get_package_version("celery")),
        ComponentVersion(name="Pydantic", version=_get_package_version("pydantic")),
    ]

    return SystemInfoResponse(
        app_name=settings.APP_NAME,
        app_version=settings.APP_VERSION,
        app_license=settings.APP_LICENSE,
        environment=settings.ENVIRONMENT,
        server_time=datetime.now(UTC).isoformat(),
        uptime_seconds=round(time.time() - _start_time, 2),
        python_version=platform.python_version(),
        python_implementation=platform.python_implementation(),
        os_name=os.name,
        os_version=platform.version(),
        os_platform=platform.platform(),
        architecture=platform.machine(),
        database=database,
        redis=redis_info,
        components=components,
    )


def _get_package_version(package: str) -> str:
    try:
        from importlib.metadata import version

        return version(package)
    except Exception:
        return "unknown"
