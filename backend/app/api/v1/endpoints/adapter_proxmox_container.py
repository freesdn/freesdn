# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Container endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-container/{controller_id}/nodes/{node}/containers
    GET   /api/v1/gateway-proxmox-container/{controller_id}/nodes/{node}/containers/{vmid}/status
    GET   /api/v1/gateway-proxmox-container/{controller_id}/nodes/{node}/containers/{vmid}/config
    GET   /api/v1/gateway-proxmox-container/{controller_id}/nodes/{node}/containers/{vmid}/pending-config
    GET   /api/v1/gateway-proxmox-container/{controller_id}/nodes/{node}/containers/{vmid}/rrd
    POST  /api/v1/gateway-proxmox-container/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-container/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint, which routes
``proxmox.container.*`` features through this service's
``build_applier``.

Stage endpoint locks ``feature`` to ``proxmox.container.*`` so a
caller with ``hypervisor:write`` cannot smuggle a non-container
feature through this URL.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.validation import validate_id
from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_proxmox_container import (
    GatewayProxmoxContainerService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-container",
    tags=["gateway-proxmox-container"],
)


@router.get("/{controller_id}/nodes/{node}/containers")
async def list_containers(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxContainerService(session)
    return await svc.list_containers(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/containers/{vmid}/status")
async def get_container_status(
    controller_id: UUID,
    node: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxContainerService(session)
    return await svc.get_container_status(controller_id, user.organization_id, node, vmid)


@router.get("/{controller_id}/nodes/{node}/containers/{vmid}/config")
async def get_container_config(
    controller_id: UUID,
    node: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxContainerService(session)
    return await svc.get_container_config(controller_id, user.organization_id, node, vmid)


@router.get("/{controller_id}/nodes/{node}/containers/{vmid}/pending-config")
async def get_container_pending_config(
    controller_id: UUID,
    node: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxContainerService(session)
    return await svc.get_container_pending_config(controller_id, user.organization_id, node, vmid)


@router.get("/{controller_id}/nodes/{node}/containers/{vmid}/rrd")
async def get_container_rrd(
    controller_id: UUID,
    node: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    timeframe: Annotated[str, Query()] = "hour",
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxContainerService(session)
    return await svc.get_container_rrd(controller_id, user.organization_id, node, vmid, timeframe)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_container_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.container."):
        raise HTTPException(
            400,
            detail=("Proxmox container endpoint only accepts proxmox.container.* features"),
        )
    svc = GatewayProxmoxContainerService(session)
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
async def list_pending_proxmox_container(
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
        feature_prefix="proxmox.container.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
