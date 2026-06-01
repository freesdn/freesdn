# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Distribution API
==========================================

Endpoints for triggering, monitoring, and rolling back
VLAN distributions across gateway devices.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.modules.gateway.schemas import (
    DistributionListResponse,
    DistributionResponse,
    DistributionTriggerRequest,
)
from app.modules.gateway.services.canonical_service import CanonicalService, VLANNotFoundError
from app.modules.gateway.services.distribution_service import (
    DistributionError,
    DistributionLockError,
    DistributionService,
)
from app.modules.gateway.services.role_map_service import RoleMapService

router = APIRouter(prefix="/distribution", tags=["Gateway Distribution"])


def _org_id(user) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _svc(session: Annotated[AsyncSession, Depends(get_session)]) -> DistributionService:
    return DistributionService(session)


def _canon(session: Annotated[AsyncSession, Depends(get_session)]) -> CanonicalService:
    return CanonicalService(session)


def _roles(session: Annotated[AsyncSession, Depends(get_session)]) -> RoleMapService:
    return RoleMapService(session)


# ── GET  /gateway/distribution ──────────────────────────────────────────


@router.get("", response_model=DistributionListResponse)
async def list_distributions(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[DistributionService, Depends(_svc)],
    site_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List distribution records, optionally filtered."""
    org_id = _org_id(current_user)
    if site_id:
        assert_can_access_site(current_user, site_id)
    # Per-user site grant is enforced inside
    # ``list_distributions`` via the request-scoped ``current_user_var``
    # (site_scope_filter folded into the SQL), so a site-limited caller never
    # receives sibling-site rows and ``total`` is correct for pagination.
    items, total = await svc.list_distributions(
        org_id,
        site_id=site_id,
        status=None,
        limit=limit,
        offset=offset,
    )
    return DistributionListResponse(
        items=[DistributionResponse.model_validate(r) for r in items],
        total=total,
        limit=limit,
        offset=offset,
    )


# ── GET  /gateway/distribution/{record_id} ──────────────────────────────


@router.get("/{record_id}", response_model=DistributionResponse)
async def get_distribution(
    record_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[DistributionService, Depends(_svc)],
):
    """Get a single distribution record with step details."""
    org_id = _org_id(current_user)
    record = await svc.get_distribution(record_id, org_id=org_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Distribution not found")
    assert_can_access_site(current_user, record.site_id, detail="Distribution not found")
    return DistributionResponse.model_validate(record)


# ── POST  /gateway/distribution/trigger ─────────────────────────────────


@router.post("/trigger", response_model=DistributionResponse, status_code=status.HTTP_201_CREATED)
async def trigger_distribution(
    body: DistributionTriggerRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.distribute"))],
    svc: Annotated[DistributionService, Depends(_svc)],
    canon: Annotated[CanonicalService, Depends(_canon)],
    roles: Annotated[RoleMapService, Depends(_roles)],
):
    """Trigger a new VLAN distribution for a site."""
    org_id = _org_id(current_user)
    assert_can_access_site(current_user, body.site_id)
    try:
        vlan = await canon.get_vlan(body.vlan_id, org_id=org_id)
    except VLANNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN not found")
    role_map = await roles.get_role_map(body.site_id, org_id=org_id)
    if role_map is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No role map for this site")
    try:
        record = await svc.distribute_vlan(
            vlan=vlan,
            role_map=role_map,
            triggered_by=current_user.id,
        )
        return DistributionResponse.model_validate(record)
    except DistributionLockError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
    except DistributionError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))


# ── POST  /gateway/distribution/{record_id}/retry ───────────────────────


@router.post("/{record_id}/retry", response_model=DistributionResponse)
async def retry_distribution(
    record_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.distribute"))],
    svc: Annotated[DistributionService, Depends(_svc)],
    canon: Annotated[CanonicalService, Depends(_canon)],
    roles: Annotated[RoleMapService, Depends(_roles)],
):
    """Retry a failed distribution from the last failed step."""
    org_id = _org_id(current_user)
    record = await svc.get_distribution(record_id, org_id=org_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Distribution not found")
    assert_can_access_site(current_user, record.site_id, detail="Distribution not found")
    try:
        vlan = await canon.get_vlan(record.resource_id, org_id=org_id)
    except VLANNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN no longer exists")
    role_map = await roles.get_role_map(record.site_id, org_id=org_id)
    if role_map is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No role map for this site")
    try:
        new_record = await svc.distribute_vlan(
            vlan=vlan,
            role_map=role_map,
            triggered_by=current_user.id,
        )
        return DistributionResponse.model_validate(new_record)
    except (DistributionLockError, DistributionError) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))


# ── POST  /gateway/distribution/{record_id}/rollback ────────────────────


@router.post("/{record_id}/rollback", response_model=DistributionResponse)
async def rollback_distribution(
    record_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.distribute"))],
    svc: Annotated[DistributionService, Depends(_svc)],
    canon: Annotated[CanonicalService, Depends(_canon)],
    roles: Annotated[RoleMapService, Depends(_roles)],
):
    """Rollback (retract) a completed distribution."""
    org_id = _org_id(current_user)
    record = await svc.get_distribution(record_id, org_id=org_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Distribution not found")
    assert_can_access_site(current_user, record.site_id, detail="Distribution not found")
    try:
        vlan = await canon.get_vlan(record.resource_id, org_id=org_id)
    except VLANNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN no longer exists")
    role_map = await roles.get_role_map(record.site_id, org_id=org_id)
    if role_map is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No role map for this site")
    try:
        result = await svc.retract_vlan(
            vlan=vlan,
            role_map=role_map,
            triggered_by=current_user.id,
        )
        return DistributionResponse.model_validate(result)
    except (DistributionLockError, DistributionError) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
