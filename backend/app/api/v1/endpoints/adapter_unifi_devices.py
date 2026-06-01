# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway UniFi Devices endpoint (stage + read).

URL layout::

    GET   /api/v1/gateway-unifi-devices/{controller_id}/sites/{site}/devices
    POST  /api/v1/gateway-unifi-devices/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-unifi-devices/{controller_id}/changes
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_staging import AdapterStagingService
from app.services.adapter_unifi_devices import GatewayUniFiDevicesService

router = APIRouter(
    prefix="/gateway-unifi-devices",
    tags=["gateway-unifi-devices"],
)


@router.get("/{controller_id}/sites/{site}/devices")
async def list_devices(
    controller_id: UUID,
    site: str,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayUniFiDevicesService(session)
    return await svc.list_devices(
        controller_id=controller_id,
        organization_id=user.organization_id,
        site=site,
        is_superuser=user.is_superuser,
    )


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_unifi_devices_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("unifi.devices."):
        raise HTTPException(
            400,
            detail=("UniFi Devices endpoint only accepts unifi.devices.* features"),
        )
    # Stage-time authz must MIRROR apply-time. unifi.devices.upgrade FLASHES firmware
    # and applies at the admin-only ``firmware:upgrade`` tier (adapter_omada_vpn.
    # _required_apply_permission). Gating STAGE at only ``network:write`` let a
    # site_admin (has network:* but explicitly NOT firmware:upgrade) plant a firmware
    # operation in the queue they could not create if stage matched apply — so require
    # firmware:upgrade to stage it too.
    if feature == "unifi.devices.upgrade" and not user.has_permission("firmware:upgrade"):
        raise HTTPException(
            403,
            detail="unifi.devices.upgrade requires the firmware:upgrade permission to stage.",
        )
    # Defense-in-depth — same MAC validation as the clients endpoint.
    if body.target_id is not None:
        from app.adapters.unifi.validators import validate_mac

        try:
            validate_mac(body.target_id)
        except Exception as exc:
            raise HTTPException(
                400,
                detail=(f"unifi.devices.* target_id must be a MAC address: {exc}"),
            ) from exc
    svc = GatewayUniFiDevicesService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_unifi_devices(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="unifi.devices.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
