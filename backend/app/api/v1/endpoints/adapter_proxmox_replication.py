# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Replication endpoint.

URL layout::

    GET   /api/v1/gateway-proxmox-replication/{controller_id}/jobs
    GET   /api/v1/gateway-proxmox-replication/{controller_id}/jobs/{replication_id}/log
    POST  /api/v1/gateway-proxmox-replication/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-proxmox-replication/{controller_id}/changes

READS ONLY for now — the Proxmox adapter doesn't yet expose
replication-job writes. The stage / list-pending endpoints exist so
the URL shape stays parallel with the other gateway-proxmox-* domains;
when adapter writes land, drop them in ``_APPLY`` and the staging
endpoint becomes meaningful.
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
from app.services.adapter_proxmox_replication import (
    GatewayProxmoxReplicationService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-proxmox-replication",
    tags=["gateway-proxmox-replication"],
)


@router.get("/{controller_id}/jobs")
async def list_jobs(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProxmoxReplicationService(session)
    return await svc.list_jobs(controller_id, user.organization_id)


@router.get("/{controller_id}/jobs/{replication_id}/log")
async def get_job_log(
    controller_id: UUID,
    replication_id: str,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    replication_id = validate_id(replication_id, label="replication_id")
    svc = GatewayProxmoxReplicationService(session)
    return await svc.get_job_log(controller_id, user.organization_id, replication_id)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_proxmox_replication_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("hypervisor:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("proxmox.replication."):
        raise HTTPException(
            400,
            detail=("Proxmox replication endpoint only accepts proxmox.replication.* features"),
        )
    # Per current adapter surface there are no replication writes;
    # this endpoint accepts the stage call so future operations can
    # be queued, but the apply path will 400 until ``_APPLY`` is
    # populated. Operators will see a clear error at apply time
    # instead of getting a silent no-op.
    svc = GatewayProxmoxReplicationService(session)
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
async def list_pending_proxmox_replication(
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
        feature_prefix="proxmox.replication.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
