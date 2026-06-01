# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi WLAN (SSID) endpoints.

URL layout::

    GET   /api/v1/unifi/{controller_id}/sites/{site}/wlans
    GET   /api/v1/unifi/{controller_id}/sites/{site}/wlans/{wlan_id}
    POST  /api/v1/unifi/{controller_id}/sites/{site}/wlans/{wlan_id}/password
    POST  /api/v1/unifi/{controller_id}/sites/{site}/wlans/{wlan_id}/enable

Read paths strip the PSK and any RADIUS shared secret. Writes
require ``site_admin`` and explicit ``force=true``.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field

from app.adapters.unifi import UniFiAdapter
from app.api.v1.deps import CurrentUser, require_min_role, require_permissions
from app.api.v1.endpoints.unifi_deps import get_adapter_for_controller

router = APIRouter(prefix="/unifi", tags=["UniFi"])


class UniFiWlansResponse(BaseModel):
    site: str
    wlans: list[dict[str, Any]]
    count: int


class UniFiWlanResponse(BaseModel):
    site: str
    wlan_id: str
    wlan: dict[str, Any] | None


class UniFiWlanWriteResponse(BaseModel):
    success: bool = True
    action: str
    site: str
    wlan_id: str
    detail: dict[str, Any] | None = None


class _WlanPasswordBody(BaseModel):
    new_psk: str = Field(..., min_length=8, max_length=63)
    force: bool = False


class _WlanEnableBody(BaseModel):
    enabled: bool
    force: bool = False


@router.get(
    "/{controller_id}/sites/{site}/wlans",
    response_model=UniFiWlansResponse,
    summary="List wireless networks (SSIDs) at a site",
)
async def list_wlans(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiWlansResponse:
    try:
        wlans = await adapter.list_wlans(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiWlansResponse(site=site, wlans=wlans, count=len(wlans))


@router.get(
    "/{controller_id}/sites/{site}/wlans/{wlan_id}",
    response_model=UniFiWlanResponse,
    summary="Get one WLAN by Mongo ObjectID (PSK redacted)",
)
async def get_wlan(
    controller_id: UUID,
    site: str,
    wlan_id: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiWlanResponse:
    try:
        wlan = await adapter.get_wlan(site, wlan_id)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    # surface a clean 404 rather than 200 + ``wlan: null``.
    if wlan is None:
        raise HTTPException(
            404,
            detail=f"wlan {wlan_id} not found at site {site}",
        )
    return UniFiWlanResponse(site=site, wlan_id=wlan_id, wlan=wlan)


@router.post(
    "/{controller_id}/sites/{site}/wlans/{wlan_id}/password",
    response_model=UniFiWlanWriteResponse,
    summary="Rotate the WPA-PSK on a WLAN (dual-gated)",
)
async def update_wlan_password(
    controller_id: UUID,
    site: str,
    wlan_id: str,
    body: Annotated[_WlanPasswordBody, Body()],
    user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiWlanWriteResponse:
    try:
        detail = await adapter.update_wlan_password(
            site,
            wlan_id,
            body.new_psk,
            force=body.force,
        )
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    # Strip the PSK from the audit trail (it never reaches the
    # response — the adapter only logs the wlan_id, not the secret).
    return UniFiWlanWriteResponse(
        action="update_wlan_password",
        site=site,
        wlan_id=wlan_id,
        detail=detail,
    )


@router.post(
    "/{controller_id}/sites/{site}/wlans/{wlan_id}/enable",
    response_model=UniFiWlanWriteResponse,
    summary="Toggle a WLAN on or off (dual-gated)",
)
async def enable_wlan(
    controller_id: UUID,
    site: str,
    wlan_id: str,
    body: Annotated[_WlanEnableBody, Body()],
    user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiWlanWriteResponse:
    try:
        detail = await adapter.enable_wlan(
            site,
            wlan_id,
            body.enabled,
            force=body.force,
        )
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiWlanWriteResponse(
        action="enable_wlan",
        site=site,
        wlan_id=wlan_id,
        detail=detail,
    )
