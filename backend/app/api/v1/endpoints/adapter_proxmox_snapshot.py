# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Snapshot endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-snapshot/{controller_id}/nodes/{node}/{vm_type}/{vmid}/snapshots
    POST  /api/v1/gateway-proxmox-snapshot/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-snapshot/{controller_id}/changes

``vm_type`` MUST be ``qemu`` or ``lxc``. The path-param check rejects
anything else with a 400 before the adapter sees it.

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint.

Stage endpoint locks ``feature`` to ``proxmox.snapshot.*`` so a
caller with ``hypervisor:write`` cannot smuggle a non-snapshot
feature through this URL. Snapshot rollback is the most catastrophic
of these (irreversible, discards all guest state since the snapshot
was taken) — the staging row IS the audit trail.
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
from app.services.adapter_proxmox_snapshot import (
    GatewayProxmoxSnapshotService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-snapshot",
    tags=["gateway-proxmox-snapshot"],
)


def _validate_vm_type(vm_type: str) -> str:
    if vm_type not in ("qemu", "lxc"):
        raise HTTPException(400, detail="vm_type must be 'qemu' or 'lxc'")
    return vm_type


@router.get("/{controller_id}/nodes/{node}/{vm_type}/{vmid}/snapshots")
async def list_snapshots(
    controller_id: UUID,
    node: str,
    vm_type: str,
    vmid: int,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    node = validate_id(node, label="node")
    vm_type = _validate_vm_type(vm_type)
    svc = GatewayProxmoxSnapshotService(session)
    return await svc.list_snapshots(controller_id, user.organization_id, node, vmid, vm_type)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_snapshot_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.snapshot."):
        raise HTTPException(
            400,
            detail=("Proxmox snapshot endpoint only accepts proxmox.snapshot.* features"),
        )
    svc = GatewayProxmoxSnapshotService(session)
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
async def list_pending_proxmox_snapshot(
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
        feature_prefix="proxmox.snapshot.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
