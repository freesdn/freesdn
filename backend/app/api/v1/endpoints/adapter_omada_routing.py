# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Advanced routing endpoints: VRRP, IPv6 static, BGP."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_omada_routing import GatewayRoutingService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-routing", tags=["gateway-routing"])


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_routing(
    controller_id: UUID,
    site_id: UUID,
    feature: str,
    operation: Annotated[str, Query()],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("routing."):
        raise HTTPException(
            400,
            detail="routing endpoint only accepts routing.* features",
        )
    svc = GatewayRoutingService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=site_id,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/sites/{site_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_routing(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        site_id=site_id,
        feature_prefix="routing.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]


# NOTE: this dynamic catch-all MUST be declared last — declared before the
# literal "/changes" route it would shadow it (what="changes"), 400-ing the
# Pending tab. Order is load-bearing.
@router.get("/{controller_id}/sites/{site_id}/{what}")
async def get_routing(
    controller_id: UUID,
    site_id: UUID,
    what: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    family: Annotated[str, Query(description="ipv4 | ipv6 (for routing_table)")] = "ipv4",
) -> Any:
    svc = GatewayRoutingService(session)
    return await svc.get_routing_data(
        controller_id, user.organization_id, site_id, what, family=family
    )
