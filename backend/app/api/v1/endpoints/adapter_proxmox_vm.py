# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox VM endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-vm/{controller_id}/nodes/{node}/vms
    GET   /api/v1/gateway-proxmox-vm/{controller_id}/all-vms
    GET   /api/v1/gateway-proxmox-vm/{controller_id}/nodes/{node}/vms/{vmid}/status
    GET   /api/v1/gateway-proxmox-vm/{controller_id}/nodes/{node}/vms/{vmid}/config
    GET   /api/v1/gateway-proxmox-vm/{controller_id}/nodes/{node}/vms/{vmid}/pending-config
    GET   /api/v1/gateway-proxmox-vm/{controller_id}/nodes/{node}/vms/{vmid}/rrd
    GET   /api/v1/gateway-proxmox-vm/{controller_id}/next-vmid
    POST  /api/v1/gateway-proxmox-vm/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-vm/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint, which routes
``proxmox.vm.*`` features through this service's ``build_applier``.

Stage endpoint locks ``feature`` to ``proxmox.vm.*`` so a caller with
``hypervisor:write`` cannot smuggle a non-VM feature through this
URL.

Path-param validation: ``node`` and other URL segments are validated
against the shared regex in ``app.adapters.validation`` to defend
against traversal payloads in the Proxmox API path.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.validation import validate_id
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db.session import get_session
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_proxmox_vm import GatewayProxmoxVmService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-vm",
    tags=["gateway-proxmox-vm"],
)


async def _assert_controller_site_grant(
    svc: GatewayProxmoxVmService,
    controller_id: UUID,
    user: CurrentUser,
) -> None:
    """Enforce the caller's per-user site grant for a Proxmox controller.

    Proxmox controllers have no FreeSDN sub-sites of their own, but the
    ``core.controllers`` row still carries a ``site_id``.
    A site-limited operator (granted Site A) must not read or stage VM
    operations against a controller that lives in sibling Site B of the
    same org. We resolve the controller org-scoped (raises 404 if not
    owned by the org), then assert the grant. No-op for super_admin /
    org_admin / grant-less users.
    """
    ctrl = await svc._get_controller(controller_id, user.organization_id)
    assert_can_access_site(user, ctrl.site_id, detail="controller not found")


@router.get("/{controller_id}/nodes/{node}/vms")
async def list_vms_on_node(
    controller_id: UUID,
    node: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxVmService(session)
    await _assert_controller_site_grant(svc, controller_id, user)
    return await svc.list_vms_on_node(controller_id, user.organization_id, node)


@router.get("/{controller_id}/all-vms")
async def list_all_vms(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxVmService(session)
    await _assert_controller_site_grant(svc, controller_id, user)
    return await svc.list_all_vms(controller_id, user.organization_id)


@router.get("/{controller_id}/nodes/{node}/vms/{vmid}/status")
async def get_vm_status(
    controller_id: UUID,
    node: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxVmService(session)
    await _assert_controller_site_grant(svc, controller_id, user)
    return await svc.get_vm_status(controller_id, user.organization_id, node, vmid)


@router.get("/{controller_id}/nodes/{node}/vms/{vmid}/config")
async def get_vm_config(
    controller_id: UUID,
    node: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxVmService(session)
    await _assert_controller_site_grant(svc, controller_id, user)
    return await svc.get_vm_config(controller_id, user.organization_id, node, vmid)


@router.get("/{controller_id}/nodes/{node}/vms/{vmid}/pending-config")
async def get_vm_pending_config(
    controller_id: UUID,
    node: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxVmService(session)
    await _assert_controller_site_grant(svc, controller_id, user)
    return await svc.get_vm_pending_config(controller_id, user.organization_id, node, vmid)


@router.get("/{controller_id}/nodes/{node}/vms/{vmid}/rrd")
async def get_vm_rrd(
    controller_id: UUID,
    node: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    timeframe: Annotated[str, Query()] = "hour",
) -> Any:
    node = validate_id(node, label="node")
    svc = GatewayProxmoxVmService(session)
    await _assert_controller_site_grant(svc, controller_id, user)
    return await svc.get_vm_rrd(controller_id, user.organization_id, node, vmid, timeframe)


@router.get("/{controller_id}/next-vmid")
async def get_next_vmid(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxVmService(session)
    await _assert_controller_site_grant(svc, controller_id, user)
    return await svc.get_next_vmid(controller_id, user.organization_id)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_vm_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.vm."):
        raise HTTPException(
            400,
            detail=("Proxmox VM endpoint only accepts proxmox.vm.* features"),
        )
    svc = GatewayProxmoxVmService(session)
    await _assert_controller_site_grant(svc, controller_id, user)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        # Proxmox is cluster-scoped (no FreeSDN sub-sites for the
        # Proxmox controller itself).
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
async def list_pending_proxmox_vm(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    svc = GatewayProxmoxVmService(session)
    await _assert_controller_site_grant(svc, controller_id, user)
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="proxmox.vm.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
