# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox HA endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-ha/{controller_id}/groups
    GET   /api/v1/gateway-proxmox-ha/{controller_id}/resources
    GET   /api/v1/gateway-proxmox-ha/{controller_id}/status
    POST  /api/v1/gateway-proxmox-ha/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-ha/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint.

Stage endpoint locks ``feature`` to ``proxmox.ha.*``.
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
from app.services.adapter_proxmox_ha import GatewayProxmoxHaService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-ha",
    tags=["gateway-proxmox-ha"],
)


@router.get("/{controller_id}/groups")
async def list_groups(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxHaService(session)
    return await svc.list_groups(controller_id, user.organization_id)


@router.get("/{controller_id}/resources")
async def list_resources(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxHaService(session)
    return await svc.list_resources(controller_id, user.organization_id)


@router.get("/{controller_id}/status")
async def get_status(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxHaService(session)
    return await svc.get_status(controller_id, user.organization_id)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_ha_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.ha."):
        raise HTTPException(
            400,
            detail=("Proxmox HA endpoint only accepts proxmox.ha.* features"),
        )
    svc = GatewayProxmoxHaService(session)
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
async def list_pending_proxmox_ha(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="proxmox.ha.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
