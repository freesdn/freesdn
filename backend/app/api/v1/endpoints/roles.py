# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Roles Endpoints
==============================

RBAC role definitions. Two kinds of role are served here:

  * **System roles** — derived from the built-in role hierarchy
    (``app.core.dependencies``). Code-defined, present in every org, and
    immutable (cannot be edited or deleted).
  * **Custom roles** — org-scoped, DB-backed rows in ``core.custom_roles``
    managed via ``CustomRoleService``. Created/edited/deleted by org admins.

The list endpoint merges both. Write endpoints (create/update/delete) operate
only on custom roles within the caller's organization.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    DEFAULT_ROLE_PERMISSIONS,
    ROLE_HIERARCHY,
    CurrentUser,
    is_unscoped_org_admin,
    require_any_permission,
)
from app.db import get_session
from app.models.custom_roles import CustomRole
from app.services.custom_roles import CustomRoleService

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RoleResponse(BaseModel):
    """Single role returned by the API."""

    id: str
    organization_id: str | None = None
    name: str
    slug: str
    description: str
    permissions: list[str]
    level: int
    is_system: bool
    is_default: bool
    user_count: int


class RoleListResponse(BaseModel):
    items: list[RoleResponse]
    total: int


class RoleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str | None = Field(None, max_length=100)
    description: str | None = Field(None, max_length=2000)
    permissions: list[str] = Field(default_factory=list)
    level: int = Field(50, ge=1, le=100)
    is_default: bool = False


class RoleUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    slug: str | None = Field(None, max_length=100)
    description: str | None = Field(None, max_length=2000)
    permissions: list[str] | None = None
    level: int | None = Field(None, ge=1, le=100)
    is_default: bool | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ROLE_DESCRIPTIONS: dict[str, str] = {
    "super_admin": "Full platform access across all organizations and system settings.",
    "admin": "Organization-wide administration including user and role management.",
    "org_admin": "Manage sites, controllers, devices and users within the organization.",
    "site_admin": "Manage controllers and devices within assigned sites.",
    "operator": "Day-to-day device monitoring and limited device actions.",
    "viewer": "Read-only access to sites, controllers, devices and audit logs.",
    "guest": "Minimal read-only access to sites and devices.",
}

_ROLE_DISPLAY_NAMES: dict[str, str] = {
    "super_admin": "Super Admin",
    "admin": "Admin",
    "org_admin": "Organization Admin",
    "site_admin": "Site Admin",
    "operator": "Operator",
    "viewer": "Viewer",
    "guest": "Guest",
}


def _deterministic_uuid(slug: str) -> str:
    """Produce a stable, deterministic UUID-shaped id from the role slug."""
    h = hashlib.md5(f"freesdn-role-{slug}".encode()).hexdigest()  # noqa: S324
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _build_role(slug: str) -> RoleResponse:
    return RoleResponse(
        id=_deterministic_uuid(slug),
        organization_id=None,
        name=_ROLE_DISPLAY_NAMES.get(slug, slug.replace("_", " ").title()),
        slug=slug,
        description=_ROLE_DESCRIPTIONS.get(slug, ""),
        permissions=DEFAULT_ROLE_PERMISSIONS.get(slug, []),
        level=ROLE_HIERARCHY.get(slug, 0),
        is_system=True,
        is_default=(slug == "viewer"),
        user_count=0,  # populated at query time when DB is available
    )


# Pre-build the system-role list once at import time (immutable)
_SYSTEM_ROLES = {slug: _build_role(slug) for slug in ROLE_HIERARCHY}


def _custom_to_response(role: CustomRole) -> RoleResponse:
    return RoleResponse(
        id=str(role.id),
        organization_id=str(role.organization_id),
        name=role.name,
        slug=role.slug,
        description=role.description or "",
        permissions=list(role.permissions or []),
        level=role.level,
        is_system=False,
        is_default=role.is_default,
        user_count=0,
    )


def _require_role_admin(current_user: CurrentUser, write_perm: str) -> None:
    """Authorize a custom-role write (create / update / delete).

    R17 (sibling of): the route dependency admits ``role:read`` so
    THIS gate carries the real write authority — and it must honor the API-key
    scope ceiling. An UNSCOPED org-admin keeps role-management authority (the
    catalog grants it by role, not via a fine-grained ``role:create``), but a
    SCOPED key must explicitly carry the specific write permission; a scoped
    read-only role key (scopes=['role:read']) can no longer escalate to writing
    roles via its raw org-admin role.
    """
    if not (is_unscoped_org_admin(current_user) or current_user.has_permission(write_perm)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization admin access required to manage custom roles",
        )


def _require_org(current_user: CurrentUser) -> UUID:
    """Resolve the caller's organization, 400 if they have none."""
    org_id = current_user.organization_id
    if org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Caller is not associated with an organization",
        )
    return org_id


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=RoleListResponse)
async def list_roles(
    current_user: Annotated[CurrentUser, Depends(require_any_permission("role:read", "user:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    include_system: bool = Query(True, description="Include built-in system roles"),
    search: str | None = Query(
        None, max_length=128, description="Filter by name (case-insensitive)"
    ),
) -> Any:
    """List all available roles (system + org-scoped custom)."""
    roles: list[RoleResponse] = []

    if include_system:
        roles.extend(_SYSTEM_ROLES.values())

    # Custom roles, scoped to the caller's organization.
    if current_user.organization_id is not None:
        custom_roles = await CustomRoleService(session).list_for_org(current_user.organization_id)
        roles.extend(_custom_to_response(r) for r in custom_roles)

    if search:
        q = search.lower()
        roles = [
            r
            for r in roles
            if q in r.name.lower() or q in r.slug.lower() or q in r.description.lower()
        ]

    # Attempt to populate user_count for system roles from DB.
    # SECURITY: scope the SELECT to the caller's org unless super_admin, else
    # an org_admin would see cross-tenant aggregate user counts.
    try:
        from sqlalchemy import func, select

        from app.core.tenancy import tenant_filter
        from app.models import User

        stmt = (
            select(User.role, func.count(User.id))
            .where(User.is_active.is_(True))
            .where(tenant_filter(User, current_user))
            .group_by(User.role)
        )
        result = await session.execute(stmt)
        counts: dict[str, int] = dict(result.all())  # type: ignore[arg-type]
        roles = [r.model_copy(update={"user_count": counts.get(r.slug, 0)}) for r in roles]
    except Exception:
        pass  # If DB is unavailable, return 0 counts

    return RoleListResponse(items=roles, total=len(roles))


@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: str,
    current_user: Annotated[CurrentUser, Depends(require_any_permission("role:read", "user:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a single role by ID or slug (system or org-scoped custom)."""
    # System roles first (by deterministic id or slug)
    for role in _SYSTEM_ROLES.values():
        if role.id == role_id or role.slug == role_id:
            return role

    # Custom role by UUID, org-scoped
    if current_user.organization_id is not None:
        try:
            role_uuid = UUID(role_id)
        except (ValueError, TypeError):
            role_uuid = None
        if role_uuid is not None:
            custom = await CustomRoleService(session).get_for_org(
                role_uuid, current_user.organization_id
            )
            if custom is not None:
                return _custom_to_response(custom)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Role '{role_id}' not found",
    )


@router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    payload: RoleCreate,
    current_user: Annotated[
        CurrentUser, Depends(require_any_permission("role:create", "role:read"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create an org-scoped custom role (org_admin / super_admin).

    The dependency admits anyone holding ``role:read`` (which includes
    org_admin) so the real write-authority gate below — ``_is_org_admin`` —
    can issue a precise 403. Admin/super_admin pass via ``role:*``.
    """
    _require_role_admin(current_user, "role:create")
    org_id = _require_org(current_user)

    role = await CustomRoleService(session).create(
        organization_id=org_id,
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        permissions=payload.permissions,
        level=payload.level,
        is_default=payload.is_default,
        created_by=current_user.id,
    )
    return _custom_to_response(role)


@router.patch("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    payload: RoleUpdate,
    current_user: Annotated[
        CurrentUser, Depends(require_any_permission("role:update", "role:read"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update an org-scoped custom role. System roles cannot be modified."""
    _require_role_admin(current_user, "role:update")

    # Block edits to system roles (matched by deterministic id or slug).
    for role in _SYSTEM_ROLES.values():
        if role.id == role_id or role.slug == role_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="System roles cannot be modified",
            )

    org_id = _require_org(current_user)
    try:
        role_uuid = UUID(role_id)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role '{role_id}' not found",
        )

    updated = await CustomRoleService(session).update(
        role_id=role_uuid,
        organization_id=org_id,
        updated_by=current_user.id,
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        permissions=payload.permissions,
        level=payload.level,
        is_default=payload.is_default,
    )
    return _custom_to_response(updated)


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: str,
    current_user: Annotated[
        CurrentUser, Depends(require_any_permission("role:delete", "role:read"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete an org-scoped custom role. System roles cannot be deleted."""
    _require_role_admin(current_user, "role:delete")

    # Block deletion of system roles.
    for role in _SYSTEM_ROLES.values():
        if role.id == role_id or role.slug == role_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="System roles cannot be deleted",
            )

    org_id = _require_org(current_user)
    try:
        role_uuid = UUID(role_id)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role '{role_id}' not found",
        )

    await CustomRoleService(session).delete(role_id=role_uuid, organization_id=org_id)
