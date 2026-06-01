# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX SIP trunks (staged writes) endpoint.

    GET   /api/v1/gateway-freepbx-trunks/{pbx_id}/trunks
    GET   /api/v1/gateway-freepbx-trunks/{pbx_id}/trunks/{trunk_id}
    POST  /api/v1/gateway-freepbx-trunks/{pbx_id}/changes/{feature}   (pbx.trunk.*)
    GET   /api/v1/gateway-freepbx-trunks/{pbx_id}/changes

Reads live; writes stage. Apply rides the shared /gateway-vpn apply
endpoint under the ADAPTER_READ_ONLY + force dual-gate. See
``adapter_freepbx_extensions`` for the full pattern rationale.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.validation import validate_id
from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_freepbx_trunks import FreePBXTrunksService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-freepbx-trunks", tags=["gateway-freepbx-trunks"])

_FEATURE_PREFIX = "pbx.trunk."


@router.get("/{pbx_id}/trunks")
async def list_trunks(
    pbx_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    with_details: Annotated[bool, Query()] = False,
) -> Any:
    svc = FreePBXTrunksService(session)
    return await svc.list_trunks(pbx_id, user.organization_id, with_details=with_details)


@router.get("/{pbx_id}/trunks/{trunk_id}")
async def get_trunk(
    pbx_id: UUID,
    trunk_id: str,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    trunk_id = validate_id(trunk_id, label="trunk_id")
    svc = FreePBXTrunksService(session)
    return await svc.get_trunk(pbx_id, user.organization_id, trunk_id)


@router.post(
    "/{pbx_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_trunk_change(
    pbx_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith(_FEATURE_PREFIX):
        raise HTTPException(400, detail="This endpoint only accepts pbx.trunk.* features")
    svc = FreePBXTrunksService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=pbx_id,
        organization_id=user.organization_id,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get("/{pbx_id}/changes", response_model=list[PendingChangeResponse])
async def list_pending_trunk_changes(
    pbx_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=pbx_id,
        feature_prefix=_FEATURE_PREFIX,
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
