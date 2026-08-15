# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — VLAN Template API
==========================================

CRUD endpoints for org-level VLAN templates and an endpoint
to apply a template to a site (creating a CanonicalVLAN).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.modules.gateway.schemas import (
    VLANTemplateCreate,
    VLANTemplateListResponse,
    VLANTemplateResponse,
    VLANTemplateUpdate,
)
from app.modules.gateway.services.template_service import (
    TemplateConflictError,
    TemplateNotFoundError,
    TemplateService,
)

router = APIRouter(prefix="/templates", tags=["Gateway VLAN Templates"])


def _org_id(user) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _svc(session: Annotated[AsyncSession, Depends(get_session)]) -> TemplateService:
    return TemplateService(session)


# ── List ─────────────────────────────────────────────────────────────────


@router.get("", response_model=VLANTemplateListResponse)
async def list_templates(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[TemplateService, Depends(_svc)],
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List VLAN templates for the current organization."""
    org_id = _org_id(current_user)
    items, total = await svc.list_templates(org_id, limit=limit, offset=offset)
    return VLANTemplateListResponse(
        items=[VLANTemplateResponse.model_validate(t) for t in items],
        total=total,
        limit=limit,
        offset=offset,
    )


# ── Get ──────────────────────────────────────────────────────────────────


@router.get("/{template_id}", response_model=VLANTemplateResponse)
async def get_template(
    template_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[TemplateService, Depends(_svc)],
):
    """Get a single VLAN template by ID."""
    org_id = _org_id(current_user)
    try:
        tmpl = await svc.get_template(template_id, org_id=org_id)
    except TemplateNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    return VLANTemplateResponse.model_validate(tmpl)


# ── Create ───────────────────────────────────────────────────────────────


@router.post("", response_model=VLANTemplateResponse, status_code=status.HTTP_201_CREATED)
async def create_template(
    body: VLANTemplateCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_vlans"))],
    svc: Annotated[TemplateService, Depends(_svc)],
):
    """Create a new VLAN template for the organization."""
    org_id = _org_id(current_user)
    try:
        tmpl = await svc.create_template(
            org_id,
            created_by=current_user.id,
            **body.model_dump(exclude_unset=True),
        )
        return VLANTemplateResponse.model_validate(tmpl)
    except TemplateConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))


# ── Update ───────────────────────────────────────────────────────────────


@router.patch("/{template_id}", response_model=VLANTemplateResponse)
async def update_template(
    template_id: UUID,
    body: VLANTemplateUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_vlans"))],
    svc: Annotated[TemplateService, Depends(_svc)],
):
    """Update a VLAN template."""
    org_id = _org_id(current_user)
    try:
        tmpl = await svc.update_template(
            template_id,
            org_id,
            updated_by=current_user.id,
            **body.model_dump(exclude_unset=True),
        )
        return VLANTemplateResponse.model_validate(tmpl)
    except TemplateNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    except TemplateConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))


# ── Delete ───────────────────────────────────────────────────────────────


@router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_template(
    template_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_vlans"))],
    svc: Annotated[TemplateService, Depends(_svc)],
):
    """Soft-delete a VLAN template."""
    org_id = _org_id(current_user)
    try:
        await svc.delete_template(template_id, org_id)
    except TemplateNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")


# ── Apply Template to Site ───────────────────────────────────────────────


@router.post(
    "/{template_id}/apply/{site_id}",
    status_code=status.HTTP_201_CREATED,
)
async def apply_template_to_site(
    template_id: UUID,
    site_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_vlans"))],
    svc: Annotated[TemplateService, Depends(_svc)],
):
    """Apply a VLAN template to a site, creating a CanonicalVLAN."""
    org_id = _org_id(current_user)
    assert_can_access_site(current_user, site_id)
    try:
        vlan = await svc.apply_template(
            template_id,
            org_id,
            site_id,
            created_by=current_user.id,
        )
        return {
            "id": str(vlan.id),
            "vlan_id": vlan.vlan_id,
            "name": vlan.name,
            "site_id": str(vlan.site_id),
            "message": f"Created canonical VLAN {vlan.vlan_id} from template",
        }
    except TemplateNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    except TemplateConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
