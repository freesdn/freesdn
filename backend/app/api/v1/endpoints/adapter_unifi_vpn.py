# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi VPN endpoint (VPN networks)."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_staging import AdapterStagingService
from app.services.adapter_unifi_vpn import GatewayUniFiVpnService

router = APIRouter(prefix="/gateway-unifi-vpn", tags=["gateway-unifi-vpn"])

_READ = Annotated[CurrentUser, Depends(require_permissions("controller:read"))]
_WRITE = Annotated[CurrentUser, Depends(require_permissions("network:write"))]
_Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/{controller_id}/sites/{site}/networks")
async def list_vpn_networks(controller_id: UUID, site: str, user: _READ, session: _Session) -> Any:
    return await GatewayUniFiVpnService(session).list_vpn_networks(
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
async def stage_vpn_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: _WRITE,
    session: _Session,
) -> Any:
    if not feature.startswith("unifi.vpn."):
        raise HTTPException(400, detail="This endpoint only accepts unifi.vpn.* features")
    change = await GatewayUniFiVpnService(session).stage_change(
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
async def list_pending_vpn(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: _Session,
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    changes = await AdapterStagingService(session).list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="unifi.vpn.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
