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
from typing import Any, Literal
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
class AdapterReadOnlyUpdate(BaseModel):
    """Requested state of the Settings read-only switch."""

    read_only: bool


class AdapterReadOnlyState(BaseModel):
    """Platform write-safety mode, with both of its sources.

    ``read_only`` is what is in force: true means device writes are refused
    (monitor-only). It is true when EITHER source says so:

    * ``env_read_only``: ``ADAPTER_READ_ONLY`` in the server environment. Only a
      change to the environment (and a restart) can turn it off.
    * ``setting_read_only``: the Settings switch, stored in the database.
      ``null`` when it could not be read, in which case writes are refused.

    ``enforced_by`` names the source in force: ``environment``, ``setting``,
    ``environment_and_setting``, ``unverified`` (the switch could not be read,
    so writes are refused to be safe) or ``none`` (read-write).
    """

    read_only: bool
    env_read_only: bool = False
    setting_read_only: bool | None = None
    enforced_by: Literal[
        "environment", "setting", "environment_and_setting", "unverified", "none"
    ] = "none"
    # False when the switch can only be turned on from here (the environment
    # enforces read-only mode).
    can_disable: bool = True
    setting_updated_at: datetime | None = None
    # PUT only: false when the change is saved but other processes learn of it
    # from the database (within about 30 seconds) rather than immediately.
    propagated: bool | None = None


async def _setting_updated_at(session: AsyncSession) -> datetime | None:
    from app.models.platform_settings import ADAPTER_READ_ONLY_KEY, PlatformSetting

    try:
        row = await session.get(PlatformSetting, ADAPTER_READ_ONLY_KEY)
    except Exception:  # noqa: BLE001 - informational only
        return None
    return row.updated_at if row is not None else None


def _state_from(
    status_: Any, *, updated_at: datetime | None, propagated: bool | None = None
) -> Any:
    return AdapterReadOnlyState(
        read_only=status_.read_only,
        env_read_only=status_.env_read_only,
        setting_read_only=status_.setting_read_only,
        enforced_by=status_.enforced_by,
        can_disable=not status_.env_read_only,
        setting_updated_at=updated_at,
        propagated=propagated,
    )


@router.get("/settings/adapter-read-only", response_model=AdapterReadOnlyState)
async def get_adapter_read_only_state(
    _user: _Any = Depends(require_permissions("settings:read")),
    session: AsyncSession = Depends(get_session),
) -> _Any:
    """Current write-safety mode, with the environment and the Settings switch."""
    from app.core.runtime_flags import read_only_status

    status_ = await read_only_status()
    return _state_from(status_, updated_at=await _setting_updated_at(session))


@router.put("/settings/adapter-read-only", response_model=AdapterReadOnlyState)
async def set_adapter_read_only_state(
    body: AdapterReadOnlyUpdate,
    # Write-level gate: this mutates a platform-wide safety setting. ``settings:read``
    # (granted to org_admin) must not gate a write — require ``settings:write`` so the
    # decorator matches the operation; the is_unscoped_superuser check below remains.
    current_user: _Any = Depends(require_permissions("settings:write")),
    session: AsyncSession = Depends(get_session),
) -> _Any:
    """Turn the Settings read-only switch on or off, live (no restart). Super admin only.

    Saved in the database, then pushed to every process through Valkey. Refused
    with 409 when asked to turn read-only off while ``ADAPTER_READ_ONLY`` is set
    in the server environment: the Settings switch cannot override it.
    """
    if not is_unscoped_superuser(current_user):
        raise HTTPException(
            status_code=403,
            detail="Only a super administrator can change the write-safety mode",
        )
    from app.core.runtime_flags import (
        EnvironmentEnforcesReadOnly,
        read_only_status,
        store_adapter_read_only,
    )

    previous = await read_only_status()
    try:
        result = await store_adapter_read_only(
            session, body.read_only, actor_id=getattr(current_user, "id", None)
        )
    except EnvironmentEnforcesReadOnly as exc:
        raise HTTPException(
            status_code=409,
            detail=(
                "Read-only mode is set by ADAPTER_READ_ONLY=true in the server environment, "
                "so the Settings switch cannot turn it off. Set ADAPTER_READ_ONLY=false in "
                "the environment (.env) and restart FreeSDN to allow device writes."
            ),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail="Could not save the setting: the database is unavailable. Nothing was changed.",
        ) from exc
    try:
        from app.services.audit import AuditService

        await AuditService(session).log(
            action="settings.adapter_read_only",
            resource_type="settings",
            resource_name="adapter_read_only",
            actor_id=getattr(current_user, "id", None),
            previous_state={"setting_read_only": previous.setting_read_only},
            new_state={
                "setting_read_only": body.read_only,
                "read_only": result.status.read_only,
                "enforced_by": result.status.enforced_by,
            },
            tags=["write-safety"],
        )
        await session.commit()
    except Exception:  # noqa: BLE001 - the switch is saved; the record is best-effort
        import logging

        logging.getLogger(__name__).warning(
            "write-safety change saved but its audit record failed", exc_info=True
        )
        with contextlib.suppress(Exception):
            await session.rollback()
    return _state_from(
        result.status,
        updated_at=await _setting_updated_at(session),
        propagated=result.propagated,
    )


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
