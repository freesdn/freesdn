# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Organization Endpoints
====================================

Organization management endpoints including dashboard, user site access.
"""

from datetime import UTC
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import is_unscoped_org_admin, is_unscoped_superuser
from app.core.site_access import site_scope_filter
from app.db import get_session
from app.models import Controller, Device, Organization, Site, User, UserSiteAccess
from app.schemas import (
    OrganizationCreate,
    OrganizationDashboard,
    OrganizationResponse,
    OrganizationUpdate,
    OrganizationWithStats,
    PaginatedResponse,
    SiteResponse,
    SiteWithStats,
    UserSiteAccessBulk,
    UserSiteAccessCreate,
    UserSiteAccessResponse,
)

router = APIRouter()


def require_super_admin(current_user: User) -> User:
    """Require an UNSCOPED super admin (platform write).

    this gates org create/delete — platform-global tenant mutations.
    A deliberately-narrowed (scoped) super_admin API key must never create or
    delete tenants, so a scoped credential is rejected even though its role is
    super_admin (mirrors the security.py block/unblock write gate).
    """
    if not is_unscoped_superuser(current_user):  # rejects all scoped keys
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin privileges required",
        )
    return current_user


@router.get("/", response_model=PaginatedResponse)
async def list_organizations(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=200),
) -> Any:
    """
    List organizations with pagination.

    - Super admins see all organizations
    - Other users see only their organization
    """
    query = select(Organization).where(Organization.deleted_at.is_(None))

    # Non-super admins only see their organization. a SCOPED super_admin
    # key (without 'audit:read') is treated as org-scoped here too — it must not
    # enumerate every tenant beyond its declared scope.
    if not is_unscoped_superuser(current_user):
        if current_user.organization_id:
            query = query.where(Organization.id == current_user.organization_id)
        else:
            return PaginatedResponse.create(items=[], total=0, page=page, per_page=per_page)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await session.scalar(count_query) or 0

    # Get paginated results
    offset = (page - 1) * per_page
    result = await session.execute(query.order_by(Organization.name).offset(offset).limit(per_page))
    orgs = result.scalars().all()

    # Per-org stats for the page (site_count / user_count) — the list table
    # surfaces these, and the FE reads them top-level. Grouped to avoid an
    # N+1 of per-row scalar counts.
    from app.models import Site

    org_ids = [o.id for o in orgs]
    site_counts: dict[Any, int] = {}
    user_counts: dict[Any, int] = {}
    if org_ids:
        site_rows = await session.execute(
            select(Site.organization_id, func.count())
            .where(
                Site.organization_id.in_(org_ids),
                Site.deleted_at.is_(None),
                # (R14): a site-limited member viewing their own org
                # must see only granted sites in the rollup count (no-op for
                # super/org-admin).
                site_scope_filter(current_user, Site.id),
            )
            .group_by(Site.organization_id)
        )
        site_counts = dict(site_rows.all())
        user_rows = await session.execute(
            select(User.organization_id, func.count())
            .where(User.organization_id.in_(org_ids), User.deleted_at.is_(None))
            .group_by(User.organization_id)
        )
        user_counts = dict(user_rows.all())

    return PaginatedResponse.create(
        items=[
            OrganizationWithStats(
                **OrganizationResponse.model_validate(o).model_dump(),
                site_count=site_counts.get(o.id, 0),
                user_count=user_counts.get(o.id, 0),
            )
            for o in orgs
        ],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.post("/", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_data: OrganizationCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Create a new organization (super admin only)."""
    require_super_admin(current_user)

    # Check slug uniqueness among LIVE orgs only — the unique index is partial
    # (deleted_at IS NULL), so a slug freed by a soft-deleted org is reusable.
    result = await session.execute(
        select(Organization).where(
            Organization.slug == org_data.slug, Organization.deleted_at.is_(None)
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization slug already exists",
        )

    org = Organization(
        name=org_data.name,
        slug=org_data.slug,
        description=org_data.description,
        contact_email=org_data.contact_email,
        contact_phone=org_data.contact_phone,
        settings=org_data.settings,
        created_by=current_user.id,
    )

    session.add(org)
    # Defense-in-depth on the SELECT-then-INSERT race: two concurrent
    # super_admin POSTs with the same slug would both pass the
    # uniqueness check above; only one wins the DB unique constraint.
    # Previously the loser bubbled IntegrityError → 500.
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization slug already exists",
        ) from exc
    await session.refresh(org)

    return org


@router.get("/{org_id}", response_model=OrganizationWithStats)
async def get_organization(
    org_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get organization by ID with statistics."""
    # Check access. a SCOPED super_admin key (without 'audit:read') is
    # treated as org-scoped — it may only read its own organization, not an
    # arbitrary tenant by id.
    if not is_unscoped_superuser(current_user) and current_user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    result = await session.execute(
        select(Organization).where(
            Organization.id == org_id,
            Organization.deleted_at.is_(None),
        )
    )
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # Get statistics
    from app.models import Site

    # (R14): fold the per-user site grant into the site-derived
    # counts so a site-limited org member only sees granted sites (same class as
    # the /dashboard fix). site_scope_filter is a no-op for super/org-admin and
    # fail-closed for a grant-less site-limited caller. user_count is org-level.
    site_count = (
        await session.scalar(
            select(func.count()).where(
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
                site_scope_filter(current_user, Site.id),
            )
        )
        or 0
    )

    user_count = (
        await session.scalar(
            select(func.count()).where(
                User.organization_id == org_id,
                User.deleted_at.is_(None),
            )
        )
        or 0
    )

    return OrganizationWithStats(
        **OrganizationResponse.model_validate(org).model_dump(),
        site_count=site_count,
        user_count=user_count,
        device_count=await session.scalar(
            select(func.count())
            .select_from(Device)
            .join(Site, Device.site_id == Site.id)
            .where(
                Site.organization_id == org_id,
                Device.deleted_at.is_(None),
                Site.deleted_at.is_(None),
                site_scope_filter(current_user, Site.id),
            )
        )
        or 0,
    )


@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: UUID,
    org_data: OrganizationUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Update organization."""
    # Check access — super_admin OR (org_admin AND org matches).
    # Original line relied on Python operator precedence
    # (``and`` binds tighter than ``or``) which gave the right
    # answer but was hard to read. Parens make the intent explicit.
    # a SCOPED super_admin key is not treated as platform-super here —
    # it must fall to the own-org check (no cross-tenant org-settings mutation).
    is_super = is_unscoped_superuser(current_user)
    # CONV-002: use the SCOPE-AWARE helper, not raw role== — a deliberately
    # narrowed scoped key owned by an org_admin must NOT update org settings via
    # its owner's role (is_unscoped_org_admin returns False for any scoped key).
    is_own_org_admin = (
        is_unscoped_org_admin(current_user) and current_user.organization_id == org_id
    )
    if not (is_super or is_own_org_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    result = await session.execute(
        select(Organization).where(
            Organization.id == org_id,
            Organization.deleted_at.is_(None),
        )
    )
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # Update fields — block sensitive/system fields
    _BLOCKED_ORG_FIELDS = {
        "id",
        "slug",
        "created_at",
        "deleted_at",
        "created_by",
    }
    update_data = org_data.model_dump(exclude_unset=True)

    # SECURITY: strip setup_completed from settings to prevent re-opening wizard
    if "settings" in update_data and isinstance(update_data.get("settings"), dict):
        update_data["settings"].pop("setup_completed", None)
        update_data["settings"].pop("setup_completed_at", None)
        # SECURITY: `tier` is the subscription tier that drives
        # every resource/seat quota (_check_quota reads settings["tier"]). It is
        # a privileged/billing field — only super_admin may change it. For any
        # other caller, drop the incoming value AND re-inject the org's current
        # tier, so a settings PATCH can neither escalate it (tier=unlimited to
        # defeat quotas) nor accidentally drop it (wholesale settings replace).
        if not is_super:
            update_data["settings"].pop("tier", None)
            existing_tier = (org.settings or {}).get("tier")
            if existing_tier is not None:
                update_data["settings"]["tier"] = existing_tier

    for field, value in update_data.items():
        if field in _BLOCKED_ORG_FIELDS:
            continue
        setattr(org, field, value)

    org.updated_by = current_user.id
    await session.flush()
    await session.refresh(org)

    return org


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Soft delete organization (super admin only)."""
    require_super_admin(current_user)

    result = await session.execute(
        select(Organization).where(
            Organization.id == org_id,
            Organization.deleted_at.is_(None),
        )
    )
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # Soft delete
    from datetime import datetime

    org.deleted_at = datetime.now(UTC)
    org.updated_by = current_user.id
    await session.commit()


# ===========================================
# Organization Dashboard
# ===========================================


@router.get("/{org_id}/dashboard", response_model=OrganizationDashboard)
async def get_organization_dashboard(
    org_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """
    Rich organisation dashboard with aggregated statistics and recent sites.

    Returns counts for sites, users, controllers, devices (total + online)
    plus the 5 most recently updated sites with their own stats.
    """
    # Access check. a SCOPED super_admin key (without 'audit:read') is
    # treated as org-scoped — it may only read its own org dashboard.
    if not is_unscoped_superuser(current_user) and current_user.organization_id != org_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Access denied")

    # Load org
    org = (
        await session.execute(
            select(Organization).where(
                Organization.id == org_id,
                Organization.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")

    # Aggregate counts ── single round-trip via scalar subqueries.
    # (R14): a site-limited org member must not see org-wide
    # rollups across sibling sites. AND the per-user site grant into every
    # site-derived counter (site_scope_filter is a no-op for super/org-admin
    # and fail-closed for a site-limited caller with no grants). user_count is
    # org-level (no site dimension), so it stays org-scoped.
    _site_grant = site_scope_filter(current_user, Site.id)
    site_count = (
        await session.scalar(
            select(func.count()).where(
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
                _site_grant,
            )
        )
        or 0
    )

    user_count = (
        await session.scalar(
            select(func.count()).where(User.organization_id == org_id, User.deleted_at.is_(None))
        )
        or 0
    )

    controller_count = (
        await session.scalar(
            select(func.count())
            .select_from(Controller)
            .join(Site, Controller.site_id == Site.id)
            .where(
                Site.organization_id == org_id,
                Controller.deleted_at.is_(None),
                Site.deleted_at.is_(None),
                site_scope_filter(current_user, Site.id),
            )
        )
        or 0
    )

    device_count = (
        await session.scalar(
            select(func.count())
            .select_from(Device)
            .join(Site, Device.site_id == Site.id)
            .where(
                Site.organization_id == org_id,
                Device.deleted_at.is_(None),
                Site.deleted_at.is_(None),
                site_scope_filter(current_user, Site.id),
            )
        )
        or 0
    )

    online_device_count = (
        await session.scalar(
            select(func.count())
            .select_from(Device)
            .join(Site, Device.site_id == Site.id)
            .where(
                Site.organization_id == org_id,
                Device.deleted_at.is_(None),
                Site.deleted_at.is_(None),
                Device.status == "online",
                site_scope_filter(current_user, Site.id),
            )
        )
        or 0
    )

    # Recent 5 sites with per-site stats
    ctrl_sub = (
        select(func.count())
        .where(Controller.site_id == Site.id, Controller.deleted_at.is_(None))
        .correlate(Site)
        .scalar_subquery()
        .label("controller_count")
    )
    dev_sub = (
        select(func.count())
        .where(Device.site_id == Site.id, Device.deleted_at.is_(None))
        .correlate(Site)
        .scalar_subquery()
        .label("device_count")
    )
    online_sub = (
        select(func.count())
        .where(Device.site_id == Site.id, Device.deleted_at.is_(None), Device.status == "online")
        .correlate(Site)
        .scalar_subquery()
        .label("online_device_count")
    )
    recent_rows = (
        await session.execute(
            select(Site, ctrl_sub, dev_sub, online_sub)
            .where(
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
                site_scope_filter(current_user, Site.id),
            )
            .order_by(Site.updated_at.desc().nullslast())
            .limit(5)
        )
    ).all()

    recent_sites = [
        SiteWithStats(
            **SiteResponse.model_validate(s).model_dump(),
            controller_count=c or 0,
            device_count=d or 0,
            online_device_count=o or 0,
        )
        for s, c, d, o in recent_rows
    ]

    return OrganizationDashboard(
        **OrganizationResponse.model_validate(org).model_dump(),
        site_count=site_count,
        user_count=user_count,
        controller_count=controller_count,
        device_count=device_count,
        online_device_count=online_device_count,
        recent_sites=recent_sites,
    )


# ===========================================
# User ↔ Site Access Management
# ===========================================


@router.get(
    "/{org_id}/site-access",
    response_model=list[UserSiteAccessResponse],
)
async def list_site_access(
    org_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    user_id: UUID | None = None,
    site_id: UUID | None = None,
) -> Any:
    """List site-access grants for an organisation, optionally filtered."""
    # a SCOPED super_admin key is org-confined here — it must not
    # read/mutate an arbitrary tenant's user<->site authorization matrix.
    if not is_unscoped_superuser(current_user) and current_user.organization_id != org_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Access denied")
    # the user↔site grant matrix is an internal authorization
    # map (helps target privileged users / sensitive sites) — restrict reads to
    # admins, matching the mutating sibling routes.
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    query = (
        select(UserSiteAccess)
        .join(User, UserSiteAccess.user_id == User.id)
        .where(User.organization_id == org_id, User.deleted_at.is_(None))
    )
    if user_id:
        query = query.where(UserSiteAccess.user_id == user_id)
    if site_id:
        query = query.where(UserSiteAccess.site_id == site_id)

    # Defensive hard ceiling: this endpoint returns a bare list
    # with no pagination, bounded only by tenant size. Cap the materialized set
    # so a very large org can't blow up memory / the response; order for a
    # stable result. (Full pagination would change the FE contract.)
    query = query.order_by(UserSiteAccess.created_at).limit(2000)

    rows = (await session.execute(query)).scalars().all()
    return [UserSiteAccessResponse.model_validate(r) for r in rows]


@router.post(
    "/{org_id}/site-access",
    response_model=UserSiteAccessResponse,
    status_code=status.HTTP_201_CREATED,
)
async def grant_site_access(
    org_id: UUID,
    payload: UserSiteAccessCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Grant a user access to a specific site."""
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    # An org_admin may only manage access within their OWN org — the
    # role check alone let them target any org_id in the path.
    if not is_unscoped_superuser(current_user) and current_user.organization_id != org_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Cannot manage another organization")

    # Verify user belongs to org
    target_user = (
        await session.execute(
            select(User).where(User.id == payload.user_id, User.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if not target_user or target_user.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found in this organization")

    # Verify site belongs to org
    target_site = (
        await session.execute(
            select(Site).where(Site.id == payload.site_id, Site.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if not target_site or target_site.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Site not found in this organization")

    # Check duplicate
    existing = (
        await session.execute(
            select(UserSiteAccess).where(
                UserSiteAccess.user_id == payload.user_id,
                UserSiteAccess.site_id == payload.site_id,
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Access already granted")

    grant = UserSiteAccess(
        user_id=payload.user_id,
        site_id=payload.site_id,
        access_level=payload.access_level,
        created_by=current_user.id,
    )
    session.add(grant)
    # Defense-in-depth on the SELECT-then-INSERT race above: two concurrent
    # grants for the same (user_id, site_id) both pass the duplicate check, but
    # only one wins the unique index (ix_user_site_access_user_site). The loser
    # previously bubbled IntegrityError → 500; map it to 409 like the duplicate
    # check (mirrors create_organization / create_user / create_site).
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Access already granted") from exc
    await session.refresh(grant)
    return grant


@router.put(
    "/{org_id}/site-access/bulk",
    response_model=list[UserSiteAccessResponse],
)
async def bulk_set_site_access(
    org_id: UUID,
    payload: UserSiteAccessBulk,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Replace all site-access grants for a user with the given site list."""
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    if not is_unscoped_superuser(current_user) and current_user.organization_id != org_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Cannot manage another organization")

    # Verify user in org
    target_user = (
        await session.execute(
            select(User).where(User.id == payload.user_id, User.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if not target_user or target_user.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found in this organization")

    # Verify all sites belong to org
    if payload.site_ids:
        valid_count = await session.scalar(
            select(func.count()).where(
                Site.id.in_(payload.site_ids),
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
            )
        )
        if valid_count != len(payload.site_ids):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail="One or more sites not found in this organization",
            )

    # Delete existing grants for this user (scoped to org's sites)
    existing = (
        (
            await session.execute(
                select(UserSiteAccess)
                .join(Site, UserSiteAccess.site_id == Site.id)
                .where(
                    UserSiteAccess.user_id == payload.user_id,
                    Site.organization_id == org_id,
                )
            )
        )
        .scalars()
        .all()
    )
    for row in existing:
        await session.delete(row)

    # Create new grants
    grants = []
    for sid in payload.site_ids:
        g = UserSiteAccess(
            user_id=payload.user_id,
            site_id=sid,
            access_level=payload.access_level,
            created_by=current_user.id,
        )
        session.add(g)
        grants.append(g)

    await session.flush()
    for g in grants:
        await session.refresh(g)

    return [UserSiteAccessResponse.model_validate(g) for g in grants]


@router.delete("/{org_id}/site-access/{access_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_site_access(
    org_id: UUID,
    access_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Revoke a specific site-access grant."""
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    if not is_unscoped_superuser(current_user) and current_user.organization_id != org_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Cannot manage another organization")

    grant = (
        await session.execute(select(UserSiteAccess).where(UserSiteAccess.id == access_id))
    ).scalar_one_or_none()
    if not grant:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Access grant not found")

    # Verify it belongs to this org
    target_user = (
        await session.execute(
            select(User).where(User.id == grant.user_id, User.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if not target_user or target_user.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Access grant not found")

    await session.delete(grant)
    await session.flush()
