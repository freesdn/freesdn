# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Ceph endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-ceph/{controller_id}/status
    GET   /api/v1/gateway-proxmox-ceph/{controller_id}/mon
    GET   /api/v1/gateway-proxmox-ceph/{controller_id}/osd
    GET   /api/v1/gateway-proxmox-ceph/{controller_id}/pools
    GET   /api/v1/gateway-proxmox-ceph/{controller_id}/fs
    GET   /api/v1/gateway-proxmox-ceph/{controller_id}/mds
    GET   /api/v1/gateway-proxmox-ceph/{controller_id}/crush-rules
    POST  /api/v1/gateway-proxmox-ceph/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-ceph/{controller_id}/changes

READS ONLY for now — no Ceph writes are exposed. Each endpoint takes
a ``node`` query param because Proxmox routes Ceph queries through
one of the cluster nodes (any quorate node works).
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
from app.services.adapter_proxmox_ceph import GatewayProxmoxCephService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-ceph",
    tags=["gateway-proxmox-ceph"],
)


def _node_dep(node: str) -> str:
    """Validate the ``node`` query parameter once per request."""
    return validate_id(node, label="node")


@router.get("/{controller_id}/status")
async def get_status(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    node = _node_dep(node)
    svc = GatewayProxmoxCephService(session)
    return await svc.get_status(controller_id, user.organization_id, node)


@router.get("/{controller_id}/mon")
async def list_mons(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    node = _node_dep(node)
    svc = GatewayProxmoxCephService(session)
    return await svc.list_mons(controller_id, user.organization_id, node)


@router.get("/{controller_id}/osd")
async def list_osds(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    node = _node_dep(node)
    svc = GatewayProxmoxCephService(session)
    return await svc.list_osds(controller_id, user.organization_id, node)


@router.get("/{controller_id}/pools")
async def list_pools(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    node = _node_dep(node)
    svc = GatewayProxmoxCephService(session)
    return await svc.list_pools(controller_id, user.organization_id, node)


@router.get("/{controller_id}/fs")
async def list_fs(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    node = _node_dep(node)
    svc = GatewayProxmoxCephService(session)
    return await svc.list_fs(controller_id, user.organization_id, node)


@router.get("/{controller_id}/mds")
async def list_mds(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    node = _node_dep(node)
    svc = GatewayProxmoxCephService(session)
    return await svc.list_mds(controller_id, user.organization_id, node)


@router.get("/{controller_id}/crush-rules")
async def list_crush_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    node = _node_dep(node)
    svc = GatewayProxmoxCephService(session)
    return await svc.list_crush_rules(controller_id, user.organization_id, node)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_ceph_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.ceph."):
        raise HTTPException(
            400,
            detail=("Proxmox Ceph endpoint only accepts proxmox.ceph.* features"),
        )
    svc = GatewayProxmoxCephService(session)
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
async def list_pending_proxmox_ceph(
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
        feature_prefix="proxmox.ceph.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
