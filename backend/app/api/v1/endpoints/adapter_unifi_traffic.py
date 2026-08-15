# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi Traffic endpoint (traffic rules / routes / QoS)."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_staging import AdapterStagingService
from app.services.adapter_unifi_traffic import GatewayUniFiTrafficService

router = APIRouter(prefix="/gateway-unifi-traffic", tags=["gateway-unifi-traffic"])

_READ = Annotated[CurrentUser, Depends(require_permissions("controller:read"))]
_WRITE = Annotated[CurrentUser, Depends(require_permissions("network:write"))]
_Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/{controller_id}/sites/{site}/rules")
async def list_rules(controller_id: UUID, site: str, user: _READ, session: _Session) -> Any:
    return await GatewayUniFiTrafficService(session).list_rules(
        controller_id=controller_id,
        organization_id=user.organization_id,
        site=site,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/sites/{site}/routes")
async def list_routes(controller_id: UUID, site: str, user: _READ, session: _Session) -> Any:
    return await GatewayUniFiTrafficService(session).list_routes(
        controller_id=controller_id,
        organization_id=user.organization_id,
        site=site,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/sites/{site}/qos")
async def list_qos(controller_id: UUID, site: str, user: _READ, session: _Session) -> Any:
    return await GatewayUniFiTrafficService(session).list_qos(
        controller_id=controller_id,
        organization_id=user.organization_id,
        site=site,
        is_superuser=user.is_superuser,
    )


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_traffic_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: _WRITE,
    session: _Session,
) -> Any:
    if not feature.startswith("unifi.traffic."):
        raise HTTPException(400, detail="This endpoint only accepts unifi.traffic.* features")
    change = await GatewayUniFiTrafficService(session).stage_change(
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


@router.get("/{controller_id}/changes", response_model=list[PendingChangeResponse])
async def list_pending_traffic(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: _Session,
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    changes = await AdapterStagingService(session).list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="unifi.traffic.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
