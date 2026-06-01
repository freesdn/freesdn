# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Cluster endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/status
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/log
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/resources
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/options
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/replication
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/config-nodes
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/tasks
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/tasks/{upid}/status
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/tasks/{upid}/log
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/firewall-options
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/subscription
    POST  /api/v1/gateway-proxmox-cluster/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-cluster/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint.

Stage endpoint locks ``feature`` to ``proxmox.cluster.*`` so a caller
with ``hypervisor:write`` can't smuggle a non-cluster feature through
this URL.
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
from app.services.adapter_proxmox_cluster import (
    GatewayProxmoxClusterService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-cluster",
    tags=["gateway-proxmox-cluster"],
)


@router.get("/{controller_id}/status")
async def get_status(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_status(controller_id, user.organization_id)


@router.get("/{controller_id}/log")
async def get_log(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    max_entries: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_log(controller_id, user.organization_id, max_entries)


@router.get("/{controller_id}/resources")
async def get_resources(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    resource_type: Annotated[
        str | None,
        Query(
            description=("Optional filter: vm | storage | node | sdn | pool | etc."),
            max_length=32,
        ),
    ] = None,
) -> Any:
    if resource_type is not None:
        # Constrain to a vendor-shaped opaque ID — Proxmox accepts a
        # short alphabetic vocabulary; validate_id is a strict superset
        # that still rejects path-traversal payloads.
        resource_type = validate_id(resource_type, label="resource_type")
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_resources(controller_id, user.organization_id, resource_type)


@router.get("/{controller_id}/options")
async def get_options(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_options(controller_id, user.organization_id)


@router.get("/{controller_id}/replication")
async def get_replication(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_replication(controller_id, user.organization_id)


@router.get("/{controller_id}/config-nodes")
async def get_config_nodes(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_config_nodes(controller_id, user.organization_id)


@router.get("/{controller_id}/tasks")
async def get_tasks(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_tasks(controller_id, user.organization_id, node, limit)


@router.get("/{controller_id}/tasks/{upid}/status")
async def get_task_status(
    controller_id: UUID,
    upid: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    upid = validate_id(upid, label="upid")
    node = validate_id(node, label="node")
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_task_status(controller_id, user.organization_id, node, upid)


@router.get("/{controller_id}/tasks/{upid}/log")
async def get_task_log(
    controller_id: UUID,
    upid: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
    start: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> Any:
    upid = validate_id(upid, label="upid")
    node = validate_id(node, label="node")
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_task_log(controller_id, user.organization_id, node, upid, start, limit)


@router.get("/{controller_id}/firewall-options")
async def get_firewall_options(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_firewall_options(controller_id, user.organization_id)


@router.get("/{controller_id}/subscription")
async def get_subscription(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxClusterService(session)
    return await svc.get_subscription(controller_id, user.organization_id, node)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_cluster_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.cluster."):
        raise HTTPException(
            400,
            detail=("Proxmox cluster endpoint only accepts proxmox.cluster.* features"),
        )
    svc = GatewayProxmoxClusterService(session)
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
async def list_pending_proxmox_cluster(
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
        feature_prefix="proxmox.cluster.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
