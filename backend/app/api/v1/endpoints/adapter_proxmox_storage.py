# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Storage endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-storage/{controller_id}/nodes/{node}/storage
    GET   /api/v1/gateway-proxmox-storage/{controller_id}/nodes/{node}/storage/{storage}/content
    GET   /api/v1/gateway-proxmox-storage/{controller_id}/nodes/{node}/storage/{storage}/prune-backups
    POST  /api/v1/gateway-proxmox-storage/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-storage/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint, which dispatches
``proxmox.storage.*`` features through this service's ``build_applier``.

Stage endpoint locks ``feature`` to ``proxmox.storage.*`` so a caller
with ``hypervisor:write`` can't smuggle a non-storage feature through
this URL.
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
from app.services.adapter_proxmox_storage import (
    GatewayProxmoxStorageService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-storage",
    tags=["gateway-proxmox-storage"],
)


@router.get("/{controller_id}/nodes/{node}/storage")
async def list_node_storage(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxStorageService(session)
    return await svc.list_storage(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/storage/{storage}/content")
async def list_storage_content(
    controller_id: UUID,
    node: str,
    storage: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    content: Annotated[
        str | None,
        Query(
            description=(
                "Optional content-type filter: ``iso`` | ``vztmpl`` | "
                "``backup`` | ``rootdir`` | ``images``"
            ),
        ),
    ] = None,
    vmid: Annotated[int | None, Query(ge=1, description="Filter by VMID")] = None,
) -> Any:
    svc = GatewayProxmoxStorageService(session)
    return await svc.list_storage_content(
        controller_id,
        user.organization_id,
        node,
        storage,
        content_type=content,
        vmid=vmid,
    )


@router.get("/{controller_id}/nodes/{node}/storage/{storage}/prune-backups")
async def list_prune_backups(
    controller_id: UUID,
    node: str,
    storage: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    vmid: Annotated[int | None, Query(ge=1, description="Filter by VMID")] = None,
) -> Any:
    svc = GatewayProxmoxStorageService(session)
    return await svc.list_prune_backups(
        controller_id,
        user.organization_id,
        node,
        storage,
        vmid=vmid,
    )


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_storage_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.storage."):
        raise HTTPException(
            400,
            detail=("Proxmox storage endpoint only accepts proxmox.storage.* features"),
        )
    svc = GatewayProxmoxStorageService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,  # Proxmox is controller-scoped (cluster-level)
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_proxmox_storage(
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
        feature_prefix="proxmox.storage.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
