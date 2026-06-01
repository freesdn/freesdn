# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Firewall endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-firewall/{controller_id}/cluster-rules
    GET   /api/v1/gateway-proxmox-firewall/{controller_id}/guests/{vm_type}/{vmid}/rules
    GET   /api/v1/gateway-proxmox-firewall/{controller_id}/guests/{vm_type}/{vmid}/options
    POST  /api/v1/gateway-proxmox-firewall/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-firewall/{controller_id}/changes

``vm_type`` MUST be ``qemu`` or ``lxc``. Node-level firewall reads are
exposed by the agent-2 node service — this domain owns cluster-scope
and guest-scope only.

Stage endpoint locks ``feature`` to ``proxmox.firewall.*``.
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
from app.services.adapter_proxmox_firewall import (
    GatewayProxmoxFirewallService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-firewall",
    tags=["gateway-proxmox-firewall"],
)


def _validate_vm_type(vm_type: str) -> str:
    if vm_type not in ("qemu", "lxc"):
        raise HTTPException(400, detail="vm_type must be 'qemu' or 'lxc'")
    return vm_type


@router.get("/{controller_id}/cluster-rules")
async def list_cluster_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxFirewallService(session)
    return await svc.list_cluster_rules(controller_id, user.organization_id)


@router.get("/{controller_id}/guests/{vm_type}/{vmid}/rules")
async def list_guest_rules(
    controller_id: UUID,
    vm_type: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    vm_type = _validate_vm_type(vm_type)
    node = validate_id(node, label="node")
    svc = GatewayProxmoxFirewallService(session)
    return await svc.list_guest_rules(
        controller_id,
        user.organization_id,
        vm_type,
        vmid,
        node,
    )


@router.get("/{controller_id}/guests/{vm_type}/{vmid}/options")
async def get_guest_options(
    controller_id: UUID,
    vm_type: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    node: Annotated[str, Query(description="node name", max_length=64)],
) -> Any:
    vm_type = _validate_vm_type(vm_type)
    node = validate_id(node, label="node")
    svc = GatewayProxmoxFirewallService(session)
    return await svc.get_guest_options(
        controller_id,
        user.organization_id,
        vm_type,
        vmid,
        node,
    )


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_firewall_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.firewall."):
        raise HTTPException(
            400,
            detail=("Proxmox firewall endpoint only accepts proxmox.firewall.* features"),
        )
    svc = GatewayProxmoxFirewallService(session)
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
async def list_pending_proxmox_firewall(
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
        feature_prefix="proxmox.firewall.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
