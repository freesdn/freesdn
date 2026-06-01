# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX inbound routes / DIDs (staged writes) endpoint.

    GET   /api/v1/gateway-freepbx-inbound-routes/{pbx_id}/inbound-routes
    POST  /api/v1/gateway-freepbx-inbound-routes/{pbx_id}/changes/{feature}  (pbx.inbound_route.*)
    GET   /api/v1/gateway-freepbx-inbound-routes/{pbx_id}/changes

Reads live; writes stage. Apply rides the shared /gateway-vpn apply
endpoint under the ADAPTER_READ_ONLY + force dual-gate.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_freepbx_inbound_routes import FreePBXInboundRoutesService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-freepbx-inbound-routes", tags=["gateway-freepbx-inbound-routes"]
)

_FEATURE_PREFIX = "pbx.inbound_route."


@router.get("/{pbx_id}/inbound-routes")
async def list_inbound_routes(
    pbx_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = FreePBXInboundRoutesService(session)
    return await svc.list_inbound_routes(pbx_id, user.organization_id)


@router.post(
    "/{pbx_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_inbound_route_change(
    pbx_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith(_FEATURE_PREFIX):
        raise HTTPException(400, detail="This endpoint only accepts pbx.inbound_route.* features")
    svc = FreePBXInboundRoutesService(session)
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
async def list_pending_inbound_route_changes(
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
