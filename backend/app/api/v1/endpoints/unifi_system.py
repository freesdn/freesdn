# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi system / sysinfo / alerts endpoints.

URL layout::

    GET   /api/v1/unifi/{controller_id}/system/info
    GET   /api/v1/unifi/{controller_id}/system/sites/{site}/sysinfo
    GET   /api/v1/unifi/{controller_id}/system/sites/{site}/alerts
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.adapters.unifi import UniFiAdapter
from app.api.v1.deps import CurrentUser, require_permissions
from app.api.v1.endpoints.unifi_deps import get_adapter_for_controller

router = APIRouter(prefix="/unifi", tags=["UniFi"])


class UniFiControllerInfo(BaseModel):
    version: str | None = None
    hostname: str | None = None
    build: str | None = None
    ubnt_device_type: str | None = None
    is_unifi_os: bool | None = None
    timezone: str | None = None

    model_config = {"extra": "allow"}


class UniFiSysinfoResponse(BaseModel):
    site: str
    sysinfo: dict[str, Any]


class UniFiAlertsResponse(BaseModel):
    site: str
    alerts: list[dict[str, Any]]
    count: int


@router.get(
    "/{controller_id}/system/info",
    response_model=UniFiControllerInfo,
    summary="Controller-level info (version, hostname, mode)",
)
async def get_controller_info(
    controller_id: UUID,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiControllerInfo:
    try:
        info = await adapter.get_controller_info()
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiControllerInfo(**info)


@router.get(
    "/{controller_id}/system/sites/{site}/sysinfo",
    response_model=UniFiSysinfoResponse,
    summary="Site-scoped sysinfo block",
)
async def get_sysinfo(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiSysinfoResponse:
    try:
        info = await adapter.get_sysinfo(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiSysinfoResponse(site=site, sysinfo=info)


@router.get(
    "/{controller_id}/system/sites/{site}/alerts",
    response_model=UniFiAlertsResponse,
    summary="List recent active alarms at a site",
)
async def list_alerts(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 50,
) -> UniFiAlertsResponse:
    try:
        alerts = await adapter.list_alerts(site, limit=limit)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiAlertsResponse(site=site, alerts=alerts, count=len(alerts))
