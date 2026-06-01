# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Site Endpoints
============================

Enterprise site management with N+1-free aggregated statistics,
organisation-scoped access control and full CRUD.
"""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import (
    is_unscoped_org_admin,
    is_unscoped_superuser,
    require_permissions,
)
from app.core.security_utils import escape_like
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models import Controller, Organization, Site, User, UserRole
from app.models.devices import Device
from app.schemas import (
    PaginatedResponse,
    SiteCreate,
    SiteResponse,
    SiteUpdate,
    SiteWithStats,
)

router = APIRouter()


# ── helpers ──────────────────────────────────────────────────


async def _check_site_access(
    session: AsyncSession,
    current_user: User,
    site: Site | None,
    require_admin: bool = False,
) -> Site:
    """Validate existence + org membership + optional admin role."""
    if site is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Site not found")

    if is_unscoped_superuser(current_user):  # scope-aware
        return site

    if site.organization_id != current_user.organization_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Access denied")

    # SECURITY: enforce per-user site containment.
    # A site-limited user — any non-admin holding >=1 UserSiteAccess grant — may
    # only act on the sites they're granted. Previously this guard never
    # consulted the grants, so a site_admin scoped to Site A could still
    # update/delete Site B in the same org. org_admin/super_admin are never
    # site-limited; a user with zero grants keeps role-based access (compat).
    if current_user.role != UserRole.ORG_ADMIN:
        from app.models.core import UserSiteAccess

        grants = (
            (
                await session.execute(
                    select(UserSiteAccess.site_id).where(UserSiteAccess.user_id == current_user.id)
                )
            )
            .scalars()
            .all()
        )
        if grants and site.id not in set(grants):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Access denied")

    if require_admin and (
        getattr(current_user, "is_scoped", False)
        or current_user.role
        not in (
            UserRole.ORG_ADMIN,
            UserRole.SITE_ADMIN,
        )
    ):
        # Scope ceiling: a scoped API key cannot satisfy the admin role requirement
        # via its owner's role (scope-ceiling class).
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    return site


# ── list (N+1-free) ─────────────────────────────────────────


@router.get("/", response_model=PaginatedResponse)
async def list_sites(
    session: Annotated[AsyncSession, Depends(get_session)],
    # CONV2-004: enforce the scope ceiling on reads — a scoped API key without
    # site:read must not list sites (site:read is held by every role incl. guest,
    # so no normal principal regresses).
    current_user: Annotated[User, Depends(require_permissions("site:read"))],
    organization_id: UUID | None = None,
    search: str | None = Query(None, max_length=200),
    is_active: bool | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> Any:
    """
    List sites with aggregated device / controller counts in **one** query.

    - Super-admins may filter by organisation; other users are scoped automatically.
    - Optional full-text search across name, city, country, description.
    """

    # Sub-queries for aggregated counts (avoids N+1)
    ctrl_count = (
        select(func.count())
        .where(Controller.site_id == Site.id, Controller.deleted_at.is_(None))
        .correlate(Site)
        .scalar_subquery()
        .label("controller_count")
    )
    dev_count = (
        select(func.count())
        .where(Device.site_id == Site.id, Device.deleted_at.is_(None))
        .correlate(Site)
        .scalar_subquery()
        .label("device_count")
    )
    online_count = (
        select(func.count())
        .where(
            Device.site_id == Site.id,
            Device.deleted_at.is_(None),
            Device.status == "online",
        )
        .correlate(Site)
        .scalar_subquery()
        .label("online_device_count")
    )

    # Canonical tenant scoping (org filter + per-user site grant in one call;
    # a site-limited user lists ONLY granted sites — the count
    # below derives from this query, so it's covered too).
    query = select(Site, ctrl_count, dev_count, online_count).where(
        Site.deleted_at.is_(None), tenant_filter(Site, current_user)
    )

    # Optional super-admin narrowing by a specific org (query feature, not
    # isolation): tenant_filter already constrains non-super principals to
    # their own org, so this only takes effect for an unscoped super_admin.
    if organization_id is not None:
        query = query.where(Site.organization_id == organization_id)

    if is_active is not None:
        query = query.where(Site.is_active == is_active)

    if search:
        escaped = escape_like(search)
        pattern = f"%{escaped}%"
        query = query.where(
            Site.name.ilike(pattern, escape="\\")
            | Site.city.ilike(pattern, escape="\\")
            | Site.country.ilike(pattern, escape="\\")
            | Site.description.ilike(pattern, escape="\\")
        )

    # Total count
    total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0

    # Paginated result
    offset = (page - 1) * per_page
    rows = (await session.execute(query.order_by(Site.name).offset(offset).limit(per_page))).all()

    items = [
        SiteWithStats(
            **SiteResponse.model_validate(site).model_dump(),
            controller_count=c_count or 0,
            device_count=d_count or 0,
            online_device_count=o_count or 0,
        )
        for site, c_count, d_count, o_count in rows
    ]

    return PaginatedResponse.create(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


# ── create ───────────────────────────────────────────────────


@router.post("/", response_model=SiteResponse, status_code=status.HTTP_201_CREATED)
async def create_site(
    site_data: SiteCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Create a new site (ORG_ADMIN+ required)."""

    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    # Infer organization_id from the caller when not supplied. The
    # frontend's Create Site dialog doesn't ask the operator for
    # their own org UUID — that's a server-side concern. Without
    # this fallback the dialog 422s on every submit.
    if site_data.organization_id is None:
        if current_user.organization_id is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=("no organization_id supplied and user is not attached to one"),
            )
        site_data.organization_id = current_user.organization_id

    # Verify organisation exists + caller belongs to it
    org = (
        await session.execute(
            select(Organization).where(
                Organization.id == site_data.organization_id,
                Organization.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()

    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")

    if not is_unscoped_superuser(current_user):  # scope-aware
        if current_user.organization_id != site_data.organization_id:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="Cannot create sites in other organizations",
            )

    # Slug uniqueness within org
    existing = (
        await session.execute(
            select(Site.id).where(
                Site.organization_id == site_data.organization_id,
                Site.slug == site_data.slug,
                Site.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()

    if existing:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="Site slug already exists in this organization"
        )

    # Atomic tier-quota check (SELECT FOR UPDATE on org row, close TOCTOU).
    from app.services.organization import OrganizationService

    org_svc = OrganizationService(session)
    await org_svc._check_quota(site_data.organization_id, "sites")

    site = Site(
        organization_id=site_data.organization_id,
        name=site_data.name,
        slug=site_data.slug,
        description=site_data.description,
        address=site_data.address,
        city=site_data.city,
        country=site_data.country,
        timezone=site_data.timezone,
        time_format=site_data.time_format,
        date_format=site_data.date_format,
        settings=site_data.settings,
        subnets=[s.model_dump() for s in site_data.subnets],
        gateway_ip=site_data.gateway_ip,
        created_by=current_user.id,
    )
    session.add(site)
    # Defense-in-depth on the SELECT-then-INSERT race: two concurrent
    # admin POSTs with the same (org, slug) both pass the uniqueness
    # check above; only one wins the DB unique constraint. Previously
    # the loser bubbled IntegrityError → 500.
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Site slug already exists in this organization",
        ) from exc
    await session.refresh(site)

    return site


# ── detail (with stats) ─────────────────────────────────────


@router.get("/{site_id}", response_model=SiteWithStats)
async def get_site(
    site_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    # CONV2-004: scope-ceiling on read (see list_sites).
    current_user: Annotated[User, Depends(require_permissions("site:read"))],
) -> Any:
    """Get a single site with aggregated statistics."""

    site = (
        await session.execute(select(Site).where(Site.id == site_id, Site.deleted_at.is_(None)))
    ).scalar_one_or_none()

    site = await _check_site_access(session, current_user, site)

    # Aggregated counts — separate scalar subqueries to avoid cross-join inflation
    ctrl_count = (
        await session.execute(
            select(func.count())
            .select_from(Controller)
            .where(
                Controller.site_id == site_id,
                Controller.deleted_at.is_(None),
            )
        )
    ).scalar_one()

    dev_count = (
        await session.execute(
            select(func.count())
            .select_from(Device)
            .where(
                Device.site_id == site_id,
                Device.deleted_at.is_(None),
            )
        )
    ).scalar_one()

    online_count = (
        await session.execute(
            select(func.count())
            .select_from(Device)
            .where(
                Device.site_id == site_id,
                Device.deleted_at.is_(None),
                Device.status == "online",
            )
        )
    ).scalar_one()

    return SiteWithStats(
        **SiteResponse.model_validate(site).model_dump(),
        controller_count=ctrl_count,
        device_count=dev_count,
        online_device_count=online_count,
    )


# ── update ───────────────────────────────────────────────────


@router.patch("/{site_id}", response_model=SiteResponse)
async def update_site(
    site_id: UUID,
    site_data: SiteUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Partial update a site (admin required)."""

    site = (
        await session.execute(select(Site).where(Site.id == site_id, Site.deleted_at.is_(None)))
    ).scalar_one_or_none()

    site = await _check_site_access(session, current_user, site, require_admin=True)

    update_data = site_data.model_dump(exclude_unset=True)
    # Defense in depth: explicit allowlist mirrors SiteUpdate so
    # a future schema change that exposes ``organization_id``/``slug``
    # can't silently move a site across tenants via this setattr loop.
    _ALLOWED_SITE_FIELDS = {
        "name",
        "description",
        "address",
        "city",
        "country",
        "timezone",
        "time_format",
        "date_format",
        "settings",
        "is_active",
        "subnets",
        "gateway_ip",
    }
    for field, value in update_data.items():
        if field not in _ALLOWED_SITE_FIELDS:
            continue
        setattr(site, field, value)

    site.updated_by = current_user.id
    await session.flush()
    await session.refresh(site)

    return site


# ── delete (soft) ────────────────────────────────────────────


@router.delete("/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site(
    site_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Soft-delete a site (admin required)."""

    site = (
        await session.execute(select(Site).where(Site.id == site_id, Site.deleted_at.is_(None)))
    ).scalar_one_or_none()

    site = await _check_site_access(session, current_user, site, require_admin=True)

    site.deleted_at = datetime.now(UTC)
    site.updated_by = current_user.id
    await session.flush()
