# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway-firmware endpoints
=====================================

Read firmware state live from the controller; stage every upgrade or
schedule change. Reads always work; writes never touch the live device
unless ``OMADA_READ_ONLY=false`` AND the apply call carries ``force=true``.

URL layout::

    GET   /api/v1/gateway-firmware/{controller_id}/sites/{site_id}/devices/{device_mac}
    GET   /api/v1/gateway-firmware/{controller_id}/sites/{site_id}/available
    GET   /api/v1/gateway-firmware/{controller_id}/sites/{site_id}/schedules
    GET   /api/v1/gateway-firmware/{controller_id}/sites/{site_id}/history
    POST  /api/v1/gateway-firmware/{controller_id}/sites/{site_id}/changes/{feature}
          (body: PendingChangeRequest; ``feature`` ∈ firmware.upgrade
           / firmware.upgrade.batch / firmware.schedule)
    GET   /api/v1/gateway-firmware/{controller_id}/sites/{site_id}/changes
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_omada_firmware import GatewayFirmwareService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-firmware", tags=["gateway-firmware"])


# ── Reads ────────────────────────────────────────────────────────────────


@router.get(
    "/{controller_id}/sites/{site_id}/devices/{device_mac}",
    summary="Live firmware info for a single device (current + available)",
)
async def get_device_firmware(
    controller_id: UUID,
    site_id: UUID,
    device_mac: str,
    user: Annotated[CurrentUser, Depends(require_permissions("firmware:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayFirmwareService(session)
    return await svc.get_device_firmware_info(
        controller_id, user.organization_id, site_id, device_mac
    )


@router.get(
    "/{controller_id}/sites/{site_id}/available",
    summary="List firmware images available for adopted devices",
)
async def get_available_firmware(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firmware:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    model: Annotated[
        str | None,
        Query(description="Filter to a specific hardware model (e.g. EAP670)."),
    ] = None,
) -> Any:
    svc = GatewayFirmwareService(session)
    return await svc.get_available_firmware(controller_id, user.organization_id, site_id, model)


@router.get(
    "/{controller_id}/sites/{site_id}/schedules",
    summary="List configured firmware auto-upgrade schedules",
)
async def list_schedules(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firmware:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayFirmwareService(session)
    return await svc.list_firmware_upgrade_schedules(controller_id, user.organization_id, site_id)


@router.get(
    "/{controller_id}/sites/{site_id}/history",
    summary="Recent firmware upgrade attempts (success/fail/in-progress)",
)
async def get_history(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firmware:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> Any:
    svc = GatewayFirmwareService(session)
    return await svc.get_upgrade_history(controller_id, user.organization_id, site_id, limit=limit)


# ── Writes (staged) ──────────────────────────────────────────────────────


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Stage a firmware change. Does NOT touch the controller.",
)
async def stage_firmware_change(
    controller_id: UUID,
    site_id: UUID,
    feature: str,  # firmware.upgrade | firmware.upgrade.batch | firmware.schedule
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firmware:upgrade"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("firmware."):
        from fastapi import HTTPException

        raise HTTPException(400, detail="firmware endpoint only accepts firmware.* features")
    svc = GatewayFirmwareService(session)
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
    summary="List pending firmware changes",
)
async def list_pending_changes(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firmware:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[
        str,
        Query(alias="status", description="pending|applied|discarded|failed"),
    ] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="firmware.",
        status_filter=status_filter,
        limit=limit,
    )
    changes = [c for c in changes if c.site_id == site_id]
    return [PendingChangeResponse.from_model(c) for c in changes]
