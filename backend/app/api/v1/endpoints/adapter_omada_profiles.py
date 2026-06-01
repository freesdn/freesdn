# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway profile/group endpoints
=========================================================

URL layout::

    GET     /api/v1/gateway-profiles/{controller_id}/sites/{site_id}/{profile_type}
    GET     /api/v1/gateway-profiles/{controller_id}/sites/{site_id}/{profile_type}/{profile_id}
    POST    /api/v1/gateway-profiles/{controller_id}/sites/{site_id}/changes/{feature}
    GET     /api/v1/gateway-profiles/{controller_id}/sites/{site_id}/changes

profile_type ∈ {mac_groups, domain_groups, oui_profiles, time_ranges,
rate_limit_profiles, ppsk_profiles, radius_profiles, ldap_profiles}

feature follows the dotted convention: ``profile.mac_group``,
``profile.radius``, etc.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_omada_profiles import GatewayProfilesService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-profiles", tags=["gateway-profiles"])


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_profile_change(
    controller_id: UUID,
    site_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("profile."):
        from fastapi import HTTPException

        raise HTTPException(400, detail="profiles endpoint only accepts profile.* features")
    svc = GatewayProfilesService(session)
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
async def list_pending_profile_changes(
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
        feature_prefix="profile.",
        status_filter=status_filter,
        limit=limit,
    )
    changes = [c for c in changes if c.site_id == site_id]
    return [PendingChangeResponse.from_model(c) for c in changes]


# NOTE: these dynamic catch-alls MUST be declared last — declared before the
# literal "/changes" route, "/{profile_type}" would shadow it
# (profile_type="changes"), 400-ing the Pending Changes tab. Order matters.
@router.get("/{controller_id}/sites/{site_id}/{profile_type}")
async def list_profiles(
    controller_id: UUID,
    site_id: UUID,
    profile_type: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProfilesService(session)
    return await svc.list_profiles(controller_id, user.organization_id, site_id, profile_type)


@router.get("/{controller_id}/sites/{site_id}/{profile_type}/{profile_id}")
async def get_profile(
    controller_id: UUID,
    site_id: UUID,
    profile_type: str,
    profile_id: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayProfilesService(session)
    return await svc.get_profile(
        controller_id, user.organization_id, site_id, profile_type, profile_id
    )
