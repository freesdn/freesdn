# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Role Map API
=====================================

Endpoints for managing Site Role Maps (brain / limb topology).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.modules.gateway.schemas import (
    SiteRoleMapResponse,
    SiteRoleMapUpdate,
)
from app.modules.gateway.services.role_map_service import RoleMapService

router = APIRouter(prefix="/topology", tags=["Gateway Topology"])


def _org_id(user) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _svc(session: Annotated[AsyncSession, Depends(get_session)]) -> RoleMapService:
    return RoleMapService(session)


# ── GET  /gateway/topology/{site_id} ────────────────────────────────────


@router.get("/{site_id}", response_model=SiteRoleMapResponse)
async def get_role_map(
    site_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[RoleMapService, Depends(_svc)],
):
    """Return the current site role map (brain + limbs)."""
    org_id = _org_id(current_user)
    # Per-user site-grant: an explicit {site_id} path is org-only
    # without this — a site-limited caller could read a sibling site's role map.
    assert_can_access_site(current_user, site_id, detail="No role map for this site")
    role_map = await svc.get_role_map(site_id, org_id=org_id)
    if role_map is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No role map for this site")
    return role_map


# ── PUT  /gateway/topology/{site_id} ────────────────────────────────────


@router.put("/{site_id}", response_model=SiteRoleMapResponse)
async def upsert_role_map(
    site_id: UUID,
    body: SiteRoleMapUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_topology"))],
    svc: Annotated[RoleMapService, Depends(_svc)],
):
    """Create or replace the site role map."""
    org_id = _org_id(current_user)
    # Per-user site-grant: block sibling-site writes.
    assert_can_access_site(current_user, site_id, detail="Site not found")
    assignments = [a.model_dump() for a in body.assignments]
    role_map = await svc.upsert_role_map(
        org_id=org_id,
        site_id=site_id,
        assignments=assignments,
        authority_map=body.authority_map if hasattr(body, "authority_map") else None,
    )
    return role_map


# ── DELETE  /gateway/topology/{site_id} ─────────────────────────────────


@router.delete("/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_role_map(
    site_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_topology"))],
    svc: Annotated[RoleMapService, Depends(_svc)],
):
    """Delete the site role map and all assignments."""
    org_id = _org_id(current_user)
    # Per-user site-grant: block sibling-site deletes.
    assert_can_access_site(current_user, site_id, detail="Role map not found")
    existing = await svc.get_role_map(site_id, org_id=org_id)
    if existing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Role map not found")
    await svc.remove_role_map(site_id, org_id=org_id)


# ── POST  /gateway/topology/{site_id}/validate ──────────────────────────


@router.post("/{site_id}/validate")
async def validate_role_map(
    site_id: UUID,
    body: SiteRoleMapUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_topology"))],
    svc: Annotated[RoleMapService, Depends(_svc)],
):
    """Dry-run validation — returns errors / warnings without persisting."""
    # Per-user site-grant: explicit {site_id} path stays org-only
    # otherwise; guard before doing any site-addressed work.
    assert_can_access_site(current_user, site_id, detail="Site not found")
    assignments = [a.model_dump() for a in body.assignments]
    is_valid, errors, warnings = svc.validate_dry_run(assignments)
    return {"is_valid": is_valid, "errors": errors, "warnings": warnings}
