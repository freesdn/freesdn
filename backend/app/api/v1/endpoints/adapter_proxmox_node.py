# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Node endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/status
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/network
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/disks
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/disks/{disk}/smart
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/dns
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/services
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/sensors
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/rrd
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/certificates
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/apt-updates
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/apt-versions
    GET   /api/v1/gateway-proxmox-node/{controller_id}/nodes/{node}/firewall-rules
    POST  /api/v1/gateway-proxmox-node/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-node/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint, which dispatches
``proxmox.node.*`` features through this service's ``build_applier``.

Stage endpoint locks ``feature`` to ``proxmox.node.*`` so a caller
with ``hypervisor:write`` can't smuggle a non-node feature through
this URL.

Three features here are extra-sensitive (see the service docstring):

* ``proxmox.node.shutdown`` — CATASTROPHIC, takes the node offline
* ``proxmox.node.reboot``   — CATASTROPHIC, cycles the node
* ``proxmox.node.certificate_upload`` — HIGH-RISK, replaces TLS cert
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
from app.services.adapter_proxmox_node import (
    GatewayProxmoxNodeService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-node",
    tags=["gateway-proxmox-node"],
)


# ── Reads ────────────────────────────────────────────────────────────


@router.get("/{controller_id}/nodes/{node}/status")
async def get_node_status(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_status(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/network")
async def get_node_network(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_network(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/disks")
async def get_node_disks(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_disks(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/disks/{disk}/smart")
async def get_node_disk_smart(
    controller_id: UUID,
    node: str,
    disk: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_disk_smart(controller_id, user.organization_id, node, disk)


@router.get("/{controller_id}/nodes/{node}/dns")
async def get_node_dns(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_dns(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/services")
async def get_node_services(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_services(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/sensors")
async def get_node_sensors(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_sensors(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/rrd")
async def get_node_rrd(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    timeframe: Annotated[
        str,
        Query(
            description=("RRD timeframe: ``hour`` | ``day`` | ``week`` | ``month`` | ``year``"),
        ),
    ] = "hour",
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_rrd(controller_id, user.organization_id, node, timeframe=timeframe)


@router.get("/{controller_id}/nodes/{node}/certificates")
async def get_node_certificates(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_certificates(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/apt-updates")
async def get_node_apt_updates(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_apt_updates(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/apt-versions")
async def get_node_apt_versions(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_apt_versions(controller_id, user.organization_id, node)


@router.get("/{controller_id}/nodes/{node}/firewall-rules")
async def get_node_firewall_rules(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxNodeService(session)
    return await svc.get_firewall_rules(controller_id, user.organization_id, node)


# ── Stage / list pending ─────────────────────────────────────────────


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_node_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.node."):
        raise HTTPException(
            400,
            detail=("Proxmox node endpoint only accepts proxmox.node.* features"),
        )
    svc = GatewayProxmoxNodeService(session)
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
async def list_pending_proxmox_node(
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
        feature_prefix="proxmox.node.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
