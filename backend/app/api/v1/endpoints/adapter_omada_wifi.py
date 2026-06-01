# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway WiFi advanced endpoints
=========================================================

URL layout::

    GET   /api/v1/gateway-wifi/{controller_id}/sites/{site_id}/wlan-groups/{wlan_id}
    GET   /api/v1/gateway-wifi/{controller_id}/sites/{site_id}/wlan-groups/{wlan_id}/ssids/{ssid_id}
    GET   /api/v1/gateway-wifi/{controller_id}/sites/{site_id}/surveillance-vlan
    GET   /api/v1/gateway-wifi/{controller_id}/sites/{site_id}/portals/{portal_id}/walled-garden
    GET   /api/v1/gateway-wifi/{controller_id}/sites/{site_id}/portals/{portal_id}/voucher-templates
    POST  /api/v1/gateway-wifi/{controller_id}/sites/{site_id}/changes/{feature}
    GET   /api/v1/gateway-wifi/{controller_id}/sites/{site_id}/changes
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_base import validate_omada_id
from app.services.adapter_omada_wifi import GatewayWifiService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-wifi", tags=["gateway-wifi"])


@router.get("/{controller_id}/sites/{site_id}/wlan-groups/{wlan_id}")
async def get_wlan_group_advanced(
    controller_id: UUID,
    site_id: UUID,
    wlan_id: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    wlan_id = validate_omada_id(wlan_id, label="wlan_id")
    svc = GatewayWifiService(session)
    return await svc.get_wlan_group_advanced(controller_id, user.organization_id, site_id, wlan_id)


@router.get("/{controller_id}/sites/{site_id}/wlan-groups/{wlan_id}/ssids/{ssid_id}")
async def get_ssid_advanced(
    controller_id: UUID,
    site_id: UUID,
    wlan_id: str,
    ssid_id: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    wlan_id = validate_omada_id(wlan_id, label="wlan_id")
    ssid_id = validate_omada_id(ssid_id, label="ssid_id")
    svc = GatewayWifiService(session)
    return await svc.get_ssid_advanced(
        controller_id, user.organization_id, site_id, wlan_id, ssid_id
    )


@router.get("/{controller_id}/sites/{site_id}/surveillance-vlan")
async def get_surveillance_vlan(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayWifiService(session)
    return await svc.get_surveillance_vlan(controller_id, user.organization_id, site_id)


@router.get("/{controller_id}/sites/{site_id}/portals/{portal_id}/walled-garden")
async def list_walled_garden(
    controller_id: UUID,
    site_id: UUID,
    portal_id: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    portal_id = validate_omada_id(portal_id, label="portal_id")
    svc = GatewayWifiService(session)
    return await svc.list_walled_garden(controller_id, user.organization_id, site_id, portal_id)


@router.get("/{controller_id}/sites/{site_id}/portals/{portal_id}/voucher-templates")
async def list_voucher_templates(
    controller_id: UUID,
    site_id: UUID,
    portal_id: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    portal_id = validate_omada_id(portal_id, label="portal_id")
    svc = GatewayWifiService(session)
    return await svc.list_voucher_templates(controller_id, user.organization_id, site_id, portal_id)


@router.get("/{controller_id}/sites/{site_id}/configs/{config_name}")
async def get_wifi_config(
    controller_id: UUID,
    site_id: UUID,
    config_name: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """``config_name`` ∈ {wids_wips, mesh_detail, regulatory, dfs, channel_pilot}."""
    svc = GatewayWifiService(session)
    return await svc.get_wifi_config(controller_id, user.organization_id, site_id, config_name)


@router.get("/{controller_id}/sites/{site_id}/wids-wips/events")
async def list_wids_wips_events(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> Any:
    svc = GatewayWifiService(session)
    return await svc.list_wids_wips_events(
        controller_id, user.organization_id, site_id, limit=limit
    )


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_wifi_change(
    controller_id: UUID,
    site_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("wifi."):
        raise HTTPException(
            400,
            detail="wifi endpoint only accepts wifi.* features",
        )
    svc = GatewayWifiService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=site_id,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/sites/{site_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_wifi_changes(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        site_id=site_id,
        feature_prefix="wifi.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
