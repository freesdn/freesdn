# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Gateway hotspot deeper endpoints."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_base import validate_omada_id
from app.services.adapter_omada_hotspot import GatewayHotspotService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-hotspot", tags=["gateway-hotspot"])


@router.get("/{controller_id}/sites/{site_id}/operators")
async def list_operators(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayHotspotService(session)
    return await svc.list_operators(controller_id, user.organization_id, site_id)


@router.get("/{controller_id}/sites/{site_id}/sms-gateway")
async def get_sms_gateway(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayHotspotService(session)
    return await svc.get_sms_gateway(controller_id, user.organization_id, site_id)


@router.get("/{controller_id}/sites/{site_id}/portals/{portal_id}/form-fields")
async def get_form_fields(
    controller_id: UUID,
    site_id: UUID,
    portal_id: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    portal_id = validate_omada_id(portal_id, label="portal_id")
    svc = GatewayHotspotService(session)
    return await svc.get_form_auth_fields(controller_id, user.organization_id, site_id, portal_id)


@router.get("/{controller_id}/sites/{site_id}/free-auth-policies")
async def list_free_auth(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayHotspotService(session)
    return await svc.list_free_auth_policies(controller_id, user.organization_id, site_id)


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_hotspot(
    controller_id: UUID,
    site_id: UUID,
    feature: str,
    operation: Annotated[str, Query()],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("hotspot."):
        raise HTTPException(
            400,
            detail="hotspot endpoint only accepts hotspot.* features",
        )
    svc = GatewayHotspotService(session)
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
async def list_pending_hotspot(
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
        feature_prefix="hotspot.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
