# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Enterprise Config Management API
================================================

Endpoints for the enterprise config management layer:
  /config/templates       — Config template CRUD
  /config/site-groups     — Site group CRUD
  /config/device-groups   — Device group CRUD
  /config/devices/{id}    — Device config (3-state), overrides, lifecycle
  /config/health          — Health scores
  /config/reconcile       — Trigger reconciliation
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import get_db
from app.core.dependencies import (
    CurrentUser,
    get_current_active_user,
    is_unscoped_superuser,
    require_permissions,
)
from app.core.redaction import _key_is_sensitive
from app.core.site_access import (
    assert_can_access_site,
    site_scope_filter,
)
from app.core.tenancy import tenant_filter
from app.models.core import Site
from app.models.devices import Device
from app.models.enterprise import (
    ConfigTemplate,
    DeviceConfig,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceHealth,
    DeviceLifecycleLog,
    DeviceTag,
    HealthDailySnapshot,
    HealthStatus,
    LifecycleState,
    LifecycleTrigger,
    SiteGroup,
)
from app.schemas.enterprise import (
    BulkOperationCreate,
    BulkOperationResponse,
    ConfigTemplateCreate,
    ConfigTemplateResponse,
    ConfigTemplateUpdate,
    DeviceConfigOverridesUpdate,
    DeviceConfigResponse,
    DeviceConfigSettingsUpdate,
    DeviceGroupCreate,
    DeviceGroupResponse,
    DeviceGroupUpdate,
    DeviceHealthDetail,
    DeviceHealthListResponse,
    DeviceHealthResponse,
    DeviceLifecycleResponse,
    DeviceTagsResponse,
    DeviceTagsUpdate,
    HealthDailySnapshotResponse,
    InfraComponentHealth,
    InfrastructureHealthResponse,
    LifecycleLogEntry,
    LifecycleTransitionRequest,
    ModuleHealthSummary,
    OrgHealthSummary,
    ReconcileRequest,
    ReconcileResultResponse,
    ResolvedConfigResponse,
    SiteGroupCreate,
    SiteGroupResponse,
    SiteGroupUpdate,
    SiteHealthSummary,
    SiteRanking,
    TopHealthIssue,
    TopIssuesResponse,
    WANDeviceHealth,
)
from app.services.enterprise import (
    LifecycleService,
    TemplateResolver,
)

logger = logging.getLogger("freesdn.api.enterprise")

router = APIRouter()


def _org_id(user: Any) -> Any:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


async def _verify_device_org(
    db: AsyncSession,
    device_id: UUID,
    organization_id: UUID,
    user: Any = None,
) -> Device:
    """Verify a device belongs to the user's organization via its site, and return it.

    SITE-GRANT: when ``user`` is supplied, also enforce the
    per-user site grant on the resolved device's ``site_id`` — a site-limited
    operator may only touch devices in granted sites, never a sibling site's
    device in the same org. Chokepoint for device tags / config (3-state) /
    lifecycle / device-health / reconcile-device-scope endpoints.
    """
    result = await db.execute(
        select(Device)
        .join(Site, Device.site_id == Site.id)
        .where(
            Device.id == device_id,
            Site.organization_id == organization_id,
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if user is not None:
        assert_can_access_site(user, device.site_id, detail="Device not found")
    return device


async def _verify_site_group_org(
    db: AsyncSession,
    group_id: UUID,
    organization_id: UUID,
) -> None:
    """Verify a SiteGroup belongs to the caller's organization."""
    res = await db.execute(
        select(SiteGroup.id).where(
            SiteGroup.id == group_id,
            SiteGroup.organization_id == organization_id,
        )
    )
    if res.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Site group not found")


async def _verify_site_org(
    db: AsyncSession,
    site_id: UUID,
    organization_id: UUID,
    user: Any = None,
) -> None:
    """Verify a Site belongs to the caller's organization.

    SITE-GRANT: when ``user`` is supplied, also enforce the
    per-user site grant so a site-limited operator can't anchor a device-group
    (or reference any site) at a sibling site they were not granted.
    """
    res = await db.execute(
        select(Site.id).where(
            Site.id == site_id,
            Site.organization_id == organization_id,
            Site.deleted_at.is_(None),
        )
    )
    if res.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Site not found")
    if user is not None:
        assert_can_access_site(user, site_id, detail="Site not found")


async def _walk_site_group_ancestors(
    db: AsyncSession,
    start_id: UUID,
    organization_id: UUID,
    *,
    max_depth: int = 64,
) -> set[UUID]:
    """Walk parent chain from ``start_id``, returning the set of ancestor IDs.

    Bounded by ``max_depth`` so a pre-existing cycle in the DB (shouldn't
    happen with this check in place, but defense-in-depth) can't pin the
    request. Always returns the chain inside the caller's org only —
    cross-org parents are silently ignored (they'll fail the
    ``_verify_site_group_org`` check at the entry point).
    """
    ancestors: set[UUID] = set()
    current: UUID | None = start_id
    for _ in range(max_depth):
        if current is None or current in ancestors:
            break
        ancestors.add(current)
        row = await db.execute(
            select(SiteGroup.parent_id).where(
                SiteGroup.id == current,
                SiteGroup.organization_id == organization_id,
            )
        )
        current = row.scalar_one_or_none()
    return ancestors


async def _verify_template_scope(
    db: AsyncSession,
    scope: str,
    scope_id: UUID | None,
    organization_id: UUID,
    user: Any = None,
) -> None:
    """Verify a template's scope_id belongs to the caller's organization.

    SECURITY: without this check, a ``config:write``
    user could author a template with ``scope=site|site_group|
    device_group`` pointing at an arbitrary UUID — non-existent rows
    become orphans, and same-org-cross-site references let one site
    admin influence sibling sites they don't own. ``scope=organization``
    ignores scope_id by definition.

    SITE-GRANT: a template silently widens config push to its
    scope target, so a site-limited operator must not author templates that
    can affect sites they were not granted. For ``site`` / ``device_group``
    scope we assert the grant on the referenced site. ``organization`` and
    ``site_group`` scope can fan out to ungranted sibling sites, so a genuinely
    site-limited operator is refused those scopes entirely (no-op for
    super/org admins and grant-less users via ``is_site_limited``).
    """
    is_site_limited = bool(getattr(user, "is_site_limited", False)) if user is not None else False

    if scope == "organization":
        if scope_id is not None:
            # organization-scope templates apply to the whole org;
            # nothing to anchor to.
            raise HTTPException(
                status_code=422,
                detail="scope_id must be omitted for scope=organization",
            )
        if is_site_limited:
            raise HTTPException(
                status_code=403,
                detail="Site-limited operators cannot author organization-scoped templates",
            )
        return

    if scope_id is None:
        raise HTTPException(
            status_code=422,
            detail=f"scope_id is required for scope={scope}",
        )

    if scope == "site":
        check = await db.execute(
            select(Site.id).where(
                Site.id == scope_id,
                Site.organization_id == organization_id,
                Site.deleted_at.is_(None),
            )
        )
        if check.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Site not found")
        assert_can_access_site(user, scope_id, detail="Site not found")
    elif scope == "site_group":
        check = await db.execute(
            select(SiteGroup.id).where(
                SiteGroup.id == scope_id,
                SiteGroup.organization_id == organization_id,
            )
        )
        if check.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Site group not found")
        if is_site_limited:
            # A site group can span sites outside the grant — refuse.
            raise HTTPException(
                status_code=403,
                detail="Site-limited operators cannot author site-group-scoped templates",
            )
    elif scope == "device_group":
        check = await db.execute(
            select(DeviceGroup.site_id)
            .join(Site, DeviceGroup.site_id == Site.id)
            .where(
                DeviceGroup.id == scope_id,
                Site.organization_id == organization_id,
            )
        )
        dg_site_id = check.scalar_one_or_none()
        if dg_site_id is None:
            raise HTTPException(status_code=404, detail="Device group not found")
        assert_can_access_site(user, dg_site_id, detail="Device group not found")


# Templates can carry RADIUS secrets, WiFi PSKs, SNMP communities, API tokens —
# `config:read` is enough to read a template, so secret VALUES must be redacted
# before serialising back to the client. Key detection is delegated to the
# central camelCase-aware matcher (`_key_is_sensitive`,) so vendor
# keys like preSharedKey / securityKey / bindPassword are covered too. We keep
# the local "***REDACTED***" sentinel (not the central "***") because the
# edit-and-save round-trip in `_unredact_config` restores the real value from it.


def _redact_template_config(config: Any) -> Any:
    """Walk a template's ``config`` dict and replace sensitive values
    with ``"***REDACTED***"``. Bounded recursion (depth 12) so a
    malicious deeply-nested template can't pin a worker.
    """
    return _redact_walk(config, depth=0)


def _redact_walk(value: Any, *, depth: int) -> Any:
    if depth > 12:
        return value
    if isinstance(value, dict):
        return {
            k: (
                "***REDACTED***"
                # use the central camelCase-aware matcher so vendor
                # keys like preSharedKey / securityKey / bindPassword / wpaPsk are
                # masked. The prior bespoke lower-cased set-membership match only
                # caught underscored forms and leaked camelCase secrets to a
                # `config:read` viewer.
                if _key_is_sensitive(k)
                else _redact_walk(v, depth=depth + 1)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_walk(v, depth=depth + 1) for v in value]
    return value


def _unredact_config(incoming: Any, existing: Any, *, depth: int = 0) -> Any:
    """Replace ``"***REDACTED***"`` sentinels in an *incoming* template config
    with the real value from the *existing* stored config.

    The client only ever sees the redacted representation (see
    :func:`_redact_walk`), so an edit-and-save round-trips the sentinel back.
    Without this, the literal placeholder overwrites the real secret in the
    DB. A sentinel with no matching stored value is dropped rather
    than persisted. Bounded recursion mirrors :func:`_redact_walk`.
    """
    if depth > 12:
        return incoming
    if isinstance(incoming, dict):
        existing_d = existing if isinstance(existing, dict) else {}
        out: dict[str, Any] = {}
        for k, v in incoming.items():
            # mirror the central matcher used in _redact_walk so the
            # round-trip restores the real secret for camelCase keys too.
            if v == "***REDACTED***" and _key_is_sensitive(k):
                if k in existing_d:
                    out[k] = existing_d[k]  # keep the real stored secret
                # else: drop the bare sentinel — never persist the placeholder
            else:
                out[k] = _unredact_config(v, existing_d.get(k), depth=depth + 1)
        return out
    if isinstance(incoming, list):
        existing_l = existing if isinstance(existing, list) else []
        return [
            _unredact_config(v, existing_l[i] if i < len(existing_l) else None, depth=depth + 1)
            for i, v in enumerate(incoming)
        ]
    return incoming


def _contains_redaction_sentinel(value: Any, *, depth: int = 0) -> bool:
    """True if ``value`` still contains a ``"***REDACTED***"`` placeholder
    anywhere — used to reject a create that would persist the literal mask."""
    if depth > 12:
        return False
    if isinstance(value, str):
        return value == "***REDACTED***"
    if isinstance(value, dict):
        return any(_contains_redaction_sentinel(v, depth=depth + 1) for v in value.values())
    if isinstance(value, list):
        return any(_contains_redaction_sentinel(v, depth=depth + 1) for v in value)
    return False


def _template_response(t: ConfigTemplate) -> dict[str, Any]:
    """Serialise a ConfigTemplate with secret redaction applied."""
    return {
        "id": t.id,
        "organization_id": t.organization_id,
        "name": t.name,
        "description": t.description,
        "scope": t.scope,
        "scope_id": t.scope_id,
        "device_type": t.device_type,
        "config": _redact_template_config(t.config or {}),
        "priority": t.priority,
        "is_active": t.is_active,
        "created_at": t.created_at,
        "updated_at": t.updated_at,
    }


# ==========================================================================
# Site Groups
# ==========================================================================


@router.get("/site-groups", response_model=list[SiteGroupResponse])
async def list_site_groups(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """List all site groups for the user's organization."""
    _org_id(user)
    result = await db.execute(
        select(SiteGroup).where(tenant_filter(SiteGroup, user)).order_by(SiteGroup.name)
    )
    return result.scalars().all()


@router.post(
    "/site-groups",
    response_model=SiteGroupResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_site_group(
    payload: SiteGroupCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Create a new site group."""
    org_id = _org_id(user)

    # SECURITY: parent_id was previously passed directly
    # into the INSERT — a foreign UUID either pointed at another tenant's
    # group (IDOR-adjacent) or didn't exist at all and surfaced as a raw
    # FK-violation 500 to the client. Verify ownership BEFORE insert.
    if payload.parent_id is not None:
        await _verify_site_group_org(db, payload.parent_id, org_id)

    sg = SiteGroup(
        organization_id=org_id,
        name=payload.name,
        description=payload.description,
        parent_id=payload.parent_id,
    )
    db.add(sg)
    await db.commit()
    await db.refresh(sg)
    await _emit_site_group_event(
        "enterprise.site_group.created",
        sg,
        user_id=getattr(user, "id", None),
    )
    return sg


@router.get("/site-groups/{group_id}", response_model=SiteGroupResponse)
async def get_site_group(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Get a site group by ID."""
    org_id = _org_id(user)
    result = await db.execute(
        select(SiteGroup).where(
            SiteGroup.id == group_id,
            SiteGroup.organization_id == org_id,
        )
    )
    sg = result.scalar_one_or_none()
    if not sg:
        raise HTTPException(status_code=404, detail="Site group not found")
    return sg


@router.patch("/site-groups/{group_id}", response_model=SiteGroupResponse)
async def update_site_group(
    group_id: UUID,
    payload: SiteGroupUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Update a site group."""
    org_id = _org_id(user)
    result = await db.execute(
        select(SiteGroup).where(
            SiteGroup.id == group_id,
            SiteGroup.organization_id == org_id,
        )
    )
    sg = result.scalar_one_or_none()
    if not sg:
        raise HTTPException(status_code=404, detail="Site group not found")

    update_data = payload.model_dump(exclude_unset=True)

    # SECURITY: cycle / self-parent / foreign-org parent guards. The
    # previous version blindly took payload.parent_id, which could be
    # any UUID — a foreign-org UUID crashed with 500 (FK violation),
    # a self-reference created an unreachable orphan, and circular
    # chains broke ``_get_site_group_chain`` for downstream code.
    if "parent_id" in update_data and update_data["parent_id"] is not None:
        new_parent = update_data["parent_id"]
        if new_parent == group_id:
            raise HTTPException(
                status_code=422,
                detail="A site group cannot be its own parent",
            )
        await _verify_site_group_org(db, new_parent, org_id)
        # Walk the new parent's ancestor chain — if group_id appears,
        # making this change would create a cycle.
        ancestors = await _walk_site_group_ancestors(db, new_parent, org_id)
        if group_id in ancestors:
            raise HTTPException(
                status_code=422,
                detail="Parent change would create a site-group cycle",
            )

    for field, value in update_data.items():
        setattr(sg, field, value)

    await db.commit()
    await db.refresh(sg)
    await _emit_site_group_event(
        "enterprise.site_group.updated",
        sg,
        user_id=getattr(user, "id", None),
    )
    return sg


@router.delete("/site-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site_group(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> None:
    """Delete a site group. Sites in the group are unlinked (not deleted)."""
    org_id = _org_id(user)
    result = await db.execute(
        select(SiteGroup).where(
            SiteGroup.id == group_id,
            SiteGroup.organization_id == org_id,
        )
    )
    sg = result.scalar_one_or_none()
    if not sg:
        raise HTTPException(status_code=404, detail="Site group not found")

    # Unlink sites from this group
    sites_result = await db.execute(
        select(Site).where(Site.site_group_id == group_id, Site.deleted_at.is_(None))
    )
    for site in sites_result.scalars().all():
        site.site_group_id = None

    sg_id_for_event = sg.id
    sg_name_for_event = sg.name
    await db.delete(sg)
    await db.commit()
    # Emit after delete commit so subscribers can react safely.
    try:
        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        await bus.publish(
            Event(
                event_type="enterprise.site_group.deleted",
                category=EventCategory.SYSTEM,
                priority=EventPriority.NORMAL,
                payload={
                    "site_group_id": str(sg_id_for_event),
                    "name": sg_name_for_event,
                    "user_id": str(user.id) if hasattr(user, "id") else None,
                },
                organization_id=str(org_id),
            )
        )
    except Exception:
        logger.debug("Failed to emit site_group.deleted event", exc_info=True)


async def _emit_site_group_event(
    event_type: str,
    sg: SiteGroup,
    *,
    user_id: Any,
) -> None:
    """Best-effort event-bus publish for site-group CRUD."""
    try:
        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        await bus.publish(
            Event(
                event_type=event_type,
                category=EventCategory.SYSTEM,
                priority=EventPriority.NORMAL,
                payload={
                    "site_group_id": str(sg.id),
                    "name": sg.name,
                    "parent_id": str(sg.parent_id) if sg.parent_id else None,
                    "user_id": str(user_id) if user_id else None,
                },
                organization_id=str(sg.organization_id),
            )
        )
    except Exception:
        logger.debug("Failed to emit %s event", event_type, exc_info=True)


# ==========================================================================
# Device Groups
# ==========================================================================


@router.get("/device-groups", response_model=list[DeviceGroupResponse])
async def list_device_groups(
    site_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """List device groups, optionally filtered by site."""
    _org_id(user)
    # SITE-GRANT: device groups are site-bound; a site-limited
    # operator must only list groups for granted sites. tenant_filter folds
    # the org filter AND the per-user site grant into one predicate.
    conditions = [
        tenant_filter(DeviceGroup, user),
    ]
    if site_id:
        assert_can_access_site(user, site_id, detail="Site not found")
        conditions.append(DeviceGroup.site_id == site_id)

    result = await db.execute(
        select(DeviceGroup).where(and_(*conditions)).order_by(DeviceGroup.name)
    )
    return result.scalars().all()


@router.post(
    "/device-groups",
    response_model=DeviceGroupResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_device_group(
    payload: DeviceGroupCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Create a new device group."""
    org_id = _org_id(user)

    # SECURITY: without this check, a foreign or
    # non-existent site_id either anchored a confused-deputy device-group
    # against another tenant's site (template resolver follows the
    # site → site_group chain — see TemplateResolver._get_templates)
    # or surfaced as a raw 500 FK violation. Verify before insert.
    await _verify_site_org(db, payload.site_id, org_id, user)

    dg = DeviceGroup(
        organization_id=org_id,
        site_id=payload.site_id,
        name=payload.name,
        description=payload.description,
        match_rules=payload.match_rules,
    )
    db.add(dg)
    await db.commit()
    await db.refresh(dg)
    await _emit_device_group_event(
        "enterprise.device_group.created",
        dg,
        user_id=getattr(user, "id", None),
    )
    return dg


@router.get("/device-groups/{group_id}", response_model=DeviceGroupResponse)
async def get_device_group(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Get a single device group by ID."""
    org_id = _org_id(user)
    result = await db.execute(
        select(DeviceGroup).where(
            DeviceGroup.id == group_id,
            DeviceGroup.organization_id == org_id,
        )
    )
    dg = result.scalar_one_or_none()
    if not dg:
        raise HTTPException(status_code=404, detail="Device group not found")
    # SITE-GRANT: device groups are site-bound.
    assert_can_access_site(user, dg.site_id, detail="Device group not found")
    return dg


@router.patch("/device-groups/{group_id}", response_model=DeviceGroupResponse)
async def update_device_group(
    group_id: UUID,
    payload: DeviceGroupUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Update a device group."""
    org_id = _org_id(user)
    result = await db.execute(
        select(DeviceGroup).where(
            DeviceGroup.id == group_id,
            DeviceGroup.organization_id == org_id,
        )
    )
    dg = result.scalar_one_or_none()
    if not dg:
        raise HTTPException(status_code=404, detail="Device group not found")
    # SITE-GRANT: a site-limited operator may only mutate groups
    # in granted sites.
    assert_can_access_site(user, dg.site_id, detail="Device group not found")

    update_data = payload.model_dump(exclude_unset=True)
    # site_id is now an honored field. Verify the target site
    # belongs to the caller's org so a group can't be moved to a foreign site.
    if update_data.get("site_id") is not None:
        owns_site = await db.execute(
            select(Site.id).where(
                Site.id == update_data["site_id"],
                Site.organization_id == org_id,
                Site.deleted_at == None,  # noqa: E711
            )
        )
        if owns_site.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Site not found")
        # ...and the destination site must also be a granted site.
        assert_can_access_site(user, update_data["site_id"], detail="Site not found")

    for field, value in update_data.items():
        setattr(dg, field, value)

    await db.commit()
    await db.refresh(dg)
    await _emit_device_group_event(
        "enterprise.device_group.updated",
        dg,
        user_id=getattr(user, "id", None),
    )
    return dg


@router.delete("/device-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_group(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> None:
    """Delete a device group."""
    org_id = _org_id(user)
    result = await db.execute(
        select(DeviceGroup).where(
            DeviceGroup.id == group_id,
            DeviceGroup.organization_id == org_id,
        )
    )
    dg = result.scalar_one_or_none()
    if not dg:
        raise HTTPException(status_code=404, detail="Device group not found")
    # SITE-GRANT: a site-limited operator may only delete groups
    # in granted sites.
    assert_can_access_site(user, dg.site_id, detail="Device group not found")

    dg_id_for_event = dg.id
    dg_name_for_event = dg.name
    dg_site_id_for_event = dg.site_id
    await db.delete(dg)
    await db.commit()
    try:
        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        await bus.publish(
            Event(
                event_type="enterprise.device_group.deleted",
                category=EventCategory.SYSTEM,
                priority=EventPriority.NORMAL,
                payload={
                    "device_group_id": str(dg_id_for_event),
                    "name": dg_name_for_event,
                    "site_id": str(dg_site_id_for_event),
                    "user_id": str(user.id) if hasattr(user, "id") else None,
                },
                organization_id=str(org_id),
            )
        )
    except Exception:
        logger.debug("Failed to emit device_group.deleted event", exc_info=True)


async def _emit_device_group_event(
    event_type: str,
    dg: DeviceGroup,
    *,
    user_id: Any,
) -> None:
    """Best-effort event-bus publish for device-group CRUD."""
    try:
        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        await bus.publish(
            Event(
                event_type=event_type,
                category=EventCategory.SYSTEM,
                priority=EventPriority.NORMAL,
                payload={
                    "device_group_id": str(dg.id),
                    "name": dg.name,
                    "site_id": str(dg.site_id),
                    "user_id": str(user_id) if user_id else None,
                },
                organization_id=str(dg.organization_id),
            )
        )
    except Exception:
        logger.debug("Failed to emit %s event", event_type, exc_info=True)


# ==========================================================================
# Device Group Membership
# ==========================================================================


@router.post(
    "/device-groups/{group_id}/devices/{device_id}",
    status_code=status.HTTP_201_CREATED,
)
async def add_device_to_group(
    group_id: UUID,
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Add a device to a group."""
    org_id = _org_id(user)
    # Verify group belongs to user's org
    grp_result = await db.execute(
        select(DeviceGroup).where(
            DeviceGroup.id == group_id,
            DeviceGroup.organization_id == org_id,
        )
    )
    grp = grp_result.scalar_one_or_none()
    if not grp:
        raise HTTPException(status_code=404, detail="Device group not found")
    # SITE-GRANT: group + device must both be in granted sites.
    assert_can_access_site(user, grp.site_id, detail="Device group not found")
    # Verify device belongs to user's org (and granted site)
    await _verify_device_org(db, device_id, org_id, user)
    membership = DeviceGroupMembership(device_id=device_id, group_id=group_id)
    db.add(membership)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Device already in group")
    return {"status": "added"}


@router.delete(
    "/device-groups/{group_id}/devices/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_device_from_group(
    group_id: UUID,
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> None:
    """Remove a device from a group."""
    org_id = _org_id(user)
    # Verify group belongs to user's org
    grp_result = await db.execute(
        select(DeviceGroup).where(
            DeviceGroup.id == group_id,
            DeviceGroup.organization_id == org_id,
        )
    )
    grp = grp_result.scalar_one_or_none()
    if not grp:
        raise HTTPException(status_code=404, detail="Device group not found")
    # SITE-GRANT: a site-limited operator may only mutate group
    # membership for groups in granted sites.
    assert_can_access_site(user, grp.site_id, detail="Device group not found")
    await db.execute(
        delete(DeviceGroupMembership).where(
            DeviceGroupMembership.device_id == device_id,
            DeviceGroupMembership.group_id == group_id,
        )
    )
    await db.commit()


# ==========================================================================
# Device Tags
# ==========================================================================


@router.get("/devices/{device_id}/tags", response_model=DeviceTagsResponse)
async def get_device_tags(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get all tags for a device."""
    org_id = _org_id(user)
    await _verify_device_org(db, device_id, org_id, user)
    result = await db.execute(select(DeviceTag.tag).where(DeviceTag.device_id == device_id))
    tags = list(result.scalars().all())
    return DeviceTagsResponse(device_id=device_id, tags=tags)


@router.put("/devices/{device_id}/tags", response_model=DeviceTagsResponse)
async def set_device_tags(
    device_id: UUID,
    payload: DeviceTagsUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:write")),
) -> Any:
    """Replace all tags for a device."""
    org_id = _org_id(user)
    await _verify_device_org(db, device_id, org_id, user)
    # Delete existing tags
    await db.execute(delete(DeviceTag).where(DeviceTag.device_id == device_id))
    # Insert new tags
    for tag in set(payload.tags):
        db.add(DeviceTag(device_id=device_id, tag=tag.strip().lower()))

    await db.commit()
    return DeviceTagsResponse(device_id=device_id, tags=payload.tags)


# ==========================================================================
# Config Templates
# ==========================================================================

_VALID_TEMPLATE_SCOPES = {"organization", "site_group", "site", "device_group"}


@router.get("/templates", response_model=list[ConfigTemplateResponse])
async def list_config_templates(
    scope: str | None = Query(None),
    scope_id: UUID | None = Query(None),
    device_type: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """List config templates, with optional filters.

    SECURITY: ``scope`` was previously a free-form
    string — ``?scope=garbage`` silently returned ``[]`` so callers
    couldn't tell whether they had no matches or a typo. Now validated
    against the enum.
    """
    if scope is not None and scope not in _VALID_TEMPLATE_SCOPES:
        raise HTTPException(
            status_code=422,
            detail=(f"scope must be one of: {sorted(_VALID_TEMPLATE_SCOPES)}"),
        )

    org_id = _org_id(user)
    conditions = [
        ConfigTemplate.organization_id == org_id,
        ConfigTemplate.deleted_at == None,  # noqa: E711
    ]
    if scope:
        conditions.append(ConfigTemplate.scope == scope)
    if scope_id:
        conditions.append(ConfigTemplate.scope_id == scope_id)
    if device_type:
        conditions.append(
            (ConfigTemplate.device_type == device_type) | (ConfigTemplate.device_type == None)  # noqa: E711
        )

    result = await db.execute(
        select(ConfigTemplate)
        .where(and_(*conditions))
        .order_by(ConfigTemplate.scope, ConfigTemplate.priority)
        .limit(limit)
        .offset(offset)
    )
    return [_template_response(t) for t in result.scalars().all()]


@router.post(
    "/templates",
    response_model=ConfigTemplateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_config_template(
    payload: ConfigTemplateCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Create a new config template."""
    org_id = _org_id(user)

    # SECURITY: a template with ``scope=site|site_group|
    # device_group`` previously accepted ANY scope_id including non-
    # existent or another tenant's UUIDs. The template lived in the
    # caller's org but pointed at a foreign target — orphan rows at
    # best, brute-force probe path at worst. Verify scope_id ownership
    # before persisting.
    await _verify_template_scope(db, payload.scope, payload.scope_id, org_id, user)

    # refuse to persist the redaction placeholder. The client
    # cannot see real secrets, so a config still carrying "***REDACTED***"
    # (e.g. a naive clone of a list row) would silently store a broken secret.
    # Cloning must go through the server-side duplicate endpoint instead.
    if _contains_redaction_sentinel(payload.config):
        raise HTTPException(
            status_code=422,
            detail=(
                "config contains the redaction placeholder '***REDACTED***'; "
                "supply real secret values, or use POST /templates/{id}/duplicate to clone"
            ),
        )

    template = ConfigTemplate(
        organization_id=org_id,
        name=payload.name,
        description=payload.description,
        scope=payload.scope,
        scope_id=payload.scope_id,
        device_type=payload.device_type,
        config=payload.config,
        priority=payload.priority,
    )
    db.add(template)
    await db.commit()
    await db.refresh(template)

    # Audit + event emission so drift detection / automation rules /
    # compliance pipelines can react. Template CRUD was previously
    # invisible to all of them.
    await _emit_template_event(
        "enterprise.template.created",
        template,
        user_id=getattr(user, "id", None),
    )
    return _template_response(template)


@router.post(
    "/templates/{template_id}/duplicate",
    response_model=ConfigTemplateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def duplicate_config_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Clone a config template server-side from the *unredacted* stored row.

    The client only ever receives a redacted config, so a client-side clone
    would copy "***REDACTED***" over real secrets. Duplicating on
    the server preserves the real secret values.
    """
    org_id = _org_id(user)
    result = await db.execute(
        select(ConfigTemplate).where(
            ConfigTemplate.id == template_id,
            ConfigTemplate.organization_id == org_id,
            ConfigTemplate.deleted_at == None,  # noqa: E711
        )
    )
    src = result.scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Template not found")

    template = ConfigTemplate(
        organization_id=org_id,
        name=f"{src.name} (copy)",
        description=src.description,
        scope=src.scope,
        scope_id=src.scope_id,
        device_type=src.device_type,
        config=src.config,  # real, unredacted stored config
        priority=src.priority,
    )
    db.add(template)
    await db.commit()
    await db.refresh(template)
    await _emit_template_event(
        "enterprise.template.created",
        template,
        user_id=getattr(user, "id", None),
    )
    return _template_response(template)


@router.get("/templates/{template_id}", response_model=ConfigTemplateResponse)
async def get_config_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Get a config template by ID."""
    org_id = _org_id(user)
    result = await db.execute(
        select(ConfigTemplate).where(
            ConfigTemplate.id == template_id,
            ConfigTemplate.organization_id == org_id,
            ConfigTemplate.deleted_at == None,  # noqa: E711
        )
    )
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return _template_response(template)


@router.patch("/templates/{template_id}", response_model=ConfigTemplateResponse)
async def update_config_template(
    template_id: UUID,
    payload: ConfigTemplateUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Update a config template."""
    org_id = _org_id(user)
    result = await db.execute(
        select(ConfigTemplate).where(
            ConfigTemplate.id == template_id,
            ConfigTemplate.organization_id == org_id,
            ConfigTemplate.deleted_at == None,  # noqa: E711
        )
    )
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    update_data = payload.model_dump(exclude_unset=True)
    # If a future schema migration adds scope_id to the update payload,
    # re-run the ownership check. Today ``ConfigTemplateUpdate`` omits
    # scope_id but this is defence-in-depth.
    if "scope_id" in update_data or "scope" in update_data:
        new_scope = update_data.get("scope", template.scope)
        new_scope_id = update_data.get("scope_id", template.scope_id)
        await _verify_template_scope(db, new_scope, new_scope_id, org_id, user)

    # the client only ever sees the redacted config, so an
    # edit-and-save would persist "***REDACTED***" over the real secret.
    # Restore stored secrets wherever the incoming config echoed the sentinel.
    if "config" in update_data:
        update_data["config"] = _unredact_config(update_data["config"], template.config or {})

    for field, value in update_data.items():
        setattr(template, field, value)

    await db.commit()
    await db.refresh(template)
    await _emit_template_event(
        "enterprise.template.updated",
        template,
        user_id=getattr(user, "id", None),
    )
    return _template_response(template)


@router.delete("/templates/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_config_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> None:
    """Soft-delete a config template."""
    org_id = _org_id(user)
    result = await db.execute(
        select(ConfigTemplate).where(
            ConfigTemplate.id == template_id,
            ConfigTemplate.organization_id == org_id,
            ConfigTemplate.deleted_at == None,  # noqa: E711
        )
    )
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    template.deleted_at = datetime.now(UTC)
    await db.commit()
    await _emit_template_event(
        "enterprise.template.deleted",
        template,
        user_id=getattr(user, "id", None),
    )


async def _emit_template_event(
    event_type: str,
    template: ConfigTemplate,
    *,
    user_id: Any,
) -> None:
    """Best-effort event-bus publish for template CRUD.

    Drift detection, automation rules, and audit pipelines all key off
    these events. We swallow failures so a bus hiccup never breaks the
    CRUD path that already committed to DB.
    """
    try:
        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        await bus.publish(
            Event(
                event_type=event_type,
                category=EventCategory.SYSTEM,
                priority=EventPriority.NORMAL,
                payload={
                    "template_id": str(template.id),
                    "name": template.name,
                    "scope": template.scope,
                    "scope_id": str(template.scope_id) if template.scope_id else None,
                    "device_type": template.device_type,
                    "user_id": str(user_id) if user_id else None,
                },
                organization_id=str(template.organization_id),
            )
        )
    except Exception:
        logger.debug("Failed to emit %s event", event_type, exc_info=True)


# ==========================================================================
# Device Config (Three-State)
# ==========================================================================

_DC_SECRET_FIELDS = (
    "desired_config",
    "pushed_config",
    "running_config",
    "device_overrides",
    "drift_details",
)


def _redacted_dc(db: AsyncSession, dc: DeviceConfig) -> DeviceConfig:
    """Detach + redact the secret-bearing config blobs on a DeviceConfig before
    returning it. The blobs carry RADIUS secrets, WiFi
    PSKs, SNMP communities, tokens; drift_details additionally embeds the raw
    desired/running VALUES under the secret key. ``get_db`` auto-commits, so the
    row is detached FIRST — the redacted copy is never persisted over the real
    stored secrets. Used by the read handler AND the two write-response handlers
    so the three paths can't drift on redaction."""
    from app.core.redaction import redact_secrets

    db.expunge(dc)
    for _field in _DC_SECRET_FIELDS:
        _val = getattr(dc, _field, None)
        if _val:
            setattr(dc, _field, redact_secrets(_val))
    return dc


@router.get("/devices/{device_id}/config", response_model=DeviceConfigResponse)
async def get_device_config(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Get the three-state config for a device."""
    org_id = _org_id(user)
    await _verify_device_org(db, device_id, org_id, user)
    result = await db.execute(select(DeviceConfig).where(DeviceConfig.device_id == device_id))
    dc = result.scalar_one_or_none()
    if not dc:
        raise HTTPException(
            status_code=404, detail="Device config not found — device may not be provisioned yet"
        )
    # redact secret-bearing config before returning to a
    # config:read caller (see _redacted_dc).
    return _redacted_dc(db, dc)


@router.put("/devices/{device_id}/config/overrides", response_model=DeviceConfigResponse)
async def update_device_overrides(
    device_id: UUID,
    payload: DeviceConfigOverridesUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Set per-device config overrides (most specific level in template hierarchy)."""
    org_id = _org_id(user)
    await _verify_device_org(db, device_id, org_id, user)
    result = await db.execute(select(DeviceConfig).where(DeviceConfig.device_id == device_id))
    dc = result.scalar_one_or_none()
    if not dc:
        # Create a new DeviceConfig row
        dc = DeviceConfig(
            device_id=device_id,
            organization_id=org_id,
        )
        db.add(dc)

    dc.device_overrides = payload.device_overrides
    dc.desired_updated_at = datetime.now(UTC)
    dc.desired_updated_by = user.id
    dc.config_version += 1

    await db.commit()
    await db.refresh(dc)
    # redact the secret-bearing blobs in the write-response too (the read
    # sibling already does; this path returned them un-redacted).
    return _redacted_dc(db, dc)


@router.patch("/devices/{device_id}/config/settings", response_model=DeviceConfigResponse)
async def update_device_config_settings(
    device_id: UUID,
    payload: DeviceConfigSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Update device config settings (auto_remediate, drift acknowledgment)."""
    org_id = _org_id(user)
    await _verify_device_org(db, device_id, org_id, user)
    result = await db.execute(select(DeviceConfig).where(DeviceConfig.device_id == device_id))
    dc = result.scalar_one_or_none()
    if not dc:
        raise HTTPException(status_code=404, detail="Device config not found")

    if payload.auto_remediate is not None:
        dc.auto_remediate = payload.auto_remediate
    if payload.drift_acknowledged is not None:
        dc.drift_acknowledged = payload.drift_acknowledged

    await db.commit()
    await db.refresh(dc)
    # redact secret-bearing blobs in the write-response (parity with the read).
    return _redacted_dc(db, dc)


@router.get("/devices/{device_id}/config/resolved", response_model=ResolvedConfigResponse)
async def get_resolved_config(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """
    Preview the fully resolved desired_config from template hierarchy.

    Does NOT push anything — purely a preview of what the device
    should be running based on current templates + overrides.
    """
    org_id = _org_id(user)
    result = await db.execute(
        select(Device)
        .options(selectinload(Device.site))
        .join(Site, Device.site_id == Site.id)
        .where(
            Device.id == device_id,
            Site.organization_id == org_id,
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # SITE-GRANT: a site-limited operator may only preview the
    # resolved config of devices in granted sites.
    assert_can_access_site(user, device.site_id, detail="Device not found")

    resolver = TemplateResolver(db)
    resolved = await resolver.resolve(device)

    # redact secret-bearing values in the resolved (template-merged)
    # config before returning to a config:read caller.
    from app.core.redaction import redact_secrets

    return ResolvedConfigResponse(
        device_id=device_id,
        resolved_config=redact_secrets(resolved),
        template_chain=resolver.template_chain,
    )


# ==========================================================================
# Device Lifecycle
# ==========================================================================


@router.get("/devices/{device_id}/lifecycle", response_model=DeviceLifecycleResponse)
async def get_device_lifecycle(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get current lifecycle state for a device."""
    org_id = _org_id(user)
    device = await _verify_device_org(db, device_id, org_id, user)

    return DeviceLifecycleResponse(
        device_id=device.id,
        lifecycle_state=device.lifecycle_state,
        lifecycle_changed_at=device.lifecycle_changed_at,
        lifecycle_error=device.lifecycle_error,
    )


@router.post("/devices/{device_id}/lifecycle", response_model=DeviceLifecycleResponse)
async def transition_device_lifecycle(
    device_id: UUID,
    payload: LifecycleTransitionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:write")),
) -> Any:
    """
    Transition a device to a new lifecycle state.

    Validates the transition against the FSM rules.
    """
    org_id = _org_id(user)
    result = await db.execute(
        select(Device)
        .options(selectinload(Device.site))
        .join(Site, Device.site_id == Site.id)
        .where(
            Device.id == device_id,
            Site.organization_id == org_id,
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # SITE-GRANT: a site-limited operator may only transition the
    # lifecycle of devices in granted sites.
    assert_can_access_site(user, device.site_id, detail="Device not found")

    prior_state = device.lifecycle_state
    lifecycle = LifecycleService(db)
    try:
        device = await lifecycle.transition(
            device,
            to_state=LifecycleState(payload.to_state),
            trigger=LifecycleTrigger(payload.trigger),
            triggered_by=user.id,
            details=payload.details,
            error_message=payload.error_message,
        )
    except ValueError as exc:
        # Surface the allowed-set so the caller learns what's legal
        # instead of just being told "Invalid lifecycle state
        # transition" with no hint.
        from app.models.enterprise import LIFECYCLE_TRANSITIONS

        allowed = LIFECYCLE_TRANSITIONS.get(
            LifecycleState(prior_state) if prior_state else None,
            set(),
        )
        allowed_names = sorted(s.value if hasattr(s, "value") else str(s) for s in allowed)
        logger.error(
            "Lifecycle transition failed for device %s (from %s to %s): %s",
            device.id,
            prior_state,
            payload.to_state,
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid lifecycle state transition from '{prior_state}' "
                f"to '{payload.to_state}'. Allowed: {allowed_names}"
            ),
        )

    await db.commit()
    await db.refresh(device)

    # Emit a lifecycle-changed event so automation, notification, and
    # WebSocket fan-out can react (the previous version was silent —
    # other operators on the page couldn't see each other's transitions
    # without a manual refresh, and "auto-push config when adopted"
    # automation rules had no trigger to hook).
    await _emit_lifecycle_event(
        device=device,
        from_state=prior_state,
        to_state=payload.to_state,
        trigger=payload.trigger,
        user_id=user.id,
    )

    return DeviceLifecycleResponse(
        device_id=device.id,
        lifecycle_state=device.lifecycle_state,
        lifecycle_changed_at=device.lifecycle_changed_at,
        lifecycle_error=device.lifecycle_error,
    )


async def _emit_lifecycle_event(
    *,
    device: Any,
    from_state: Any,
    to_state: str,
    trigger: str,
    user_id: Any,
) -> None:
    """Best-effort publish for device lifecycle transitions.

    Terminal transitions (``decommissioned`` / ``error``) get HIGH
    priority so downstream notification routing can fan out faster.
    """
    try:
        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        priority = (
            EventPriority.HIGH if to_state in ("decommissioned", "error") else EventPriority.NORMAL
        )
        await bus.publish(
            Event(
                event_type=f"device.lifecycle.{to_state}",
                category=EventCategory.DEVICE,
                priority=priority,
                payload={
                    "device_id": str(device.id),
                    "device_name": getattr(device, "name", None),
                    "device_type": getattr(device, "device_type", None),
                    "site_id": str(device.site_id) if getattr(device, "site_id", None) else None,
                    "from_state": str(from_state) if from_state else None,
                    "to_state": to_state,
                    "trigger": trigger,
                    "user_id": str(user_id) if user_id else None,
                },
                organization_id=(
                    str(device.site.organization_id)
                    if hasattr(device, "site") and device.site
                    else None
                ),
            )
        )
    except Exception:
        logger.debug("Failed to emit device.lifecycle event", exc_info=True)


@router.get("/devices/{device_id}/lifecycle/history", response_model=list[LifecycleLogEntry])
async def get_lifecycle_history(
    device_id: UUID,
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get lifecycle transition history for a device."""
    org_id = _org_id(user)
    await _verify_device_org(db, device_id, org_id, user)
    result = await db.execute(
        select(DeviceLifecycleLog)
        .where(DeviceLifecycleLog.device_id == device_id)
        .order_by(DeviceLifecycleLog.created_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


# ==========================================================================
# Device Health
# ==========================================================================


@router.get("/devices/{device_id}/health", response_model=DeviceHealthResponse)
async def get_device_health(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get health score for a device."""
    org_id = _org_id(user)
    await _verify_device_org(db, device_id, org_id, user)
    result = await db.execute(select(DeviceHealth).where(DeviceHealth.device_id == device_id))
    health = result.scalar_one_or_none()
    if not health:
        raise HTTPException(status_code=404, detail="Health data not yet computed for this device")
    return health


@router.get("/health/site/{site_id}", response_model=SiteHealthSummary)
async def get_site_health(
    site_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get aggregated health summary for a site."""
    org_id = _org_id(user)
    # Get site info
    site_result = await db.execute(
        select(Site).where(
            Site.id == site_id,
            Site.organization_id == org_id,
            Site.deleted_at.is_(None),
        )
    )
    site = site_result.scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    # SITE-GRANT: a site-limited operator may only read the health
    # summary for sites they were granted.
    assert_can_access_site(user, site_id, detail="Site not found")

    # Aggregate health scores
    result = await db.execute(
        select(
            func.count(DeviceHealth.device_id).label("device_count"),
            func.avg(DeviceHealth.health_score).label("avg_score"),
            func.count()
            .filter(DeviceHealth.health_status == HealthStatus.HEALTHY)
            .label("healthy"),
            func.count()
            .filter(DeviceHealth.health_status == HealthStatus.WARNING)
            .label("warning"),
            func.count()
            .filter(DeviceHealth.health_status == HealthStatus.DEGRADED)
            .label("degraded"),
            func.count()
            .filter(DeviceHealth.health_status == HealthStatus.CRITICAL)
            .label("critical"),
        ).where(DeviceHealth.site_id == site_id)
    )
    row = result.one()

    avg_score = float(row.avg_score or 100)
    return SiteHealthSummary(
        site_id=site_id,
        site_name=site.name,
        device_count=row.device_count,
        avg_health_score=round(avg_score, 1),
        health_status=DeviceHealth.compute_status(round(avg_score)).value,
        healthy=row.healthy,
        warning=row.warning,
        degraded=row.degraded,
        critical=row.critical,
    )


@router.get("/health/organization", response_model=OrgHealthSummary)
async def get_org_health(
    site_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get aggregated health summary for the organization (or a single site)."""
    org_id = _org_id(user)

    # If the caller scopes the rollup to a specific site, first verify
    # the site belongs to their org. Without this guard a foreign site_id
    # would silently return an empty "healthy 100" rollup — not a tenant
    # leak (org filter still applies) but misleading enough that ops
    # might miss real outages on the wrong site spelling.
    if site_id is not None:
        site_check = await db.execute(
            select(Site.id).where(
                Site.id == site_id,
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
            )
        )
        if site_check.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Site not found")
        # SITE-GRANT: a site-limited operator may only scope the
        # org-health rollup to a site they were granted.
        assert_can_access_site(user, site_id, detail="Site not found")

    # Single query: join DeviceHealth → Site, group by site.
    # SITE-GRANT: constrain the rollup to the caller's granted
    # sites (no-op for unrestricted admins). The org-wide health rollup must
    # not include sibling sites a site-limited operator can't see.
    base_q = (
        select(
            DeviceHealth.site_id,
            Site.name.label("site_name"),
            func.count(DeviceHealth.device_id).label("device_count"),
            func.avg(DeviceHealth.health_score).label("avg_score"),
            func.avg(DeviceHealth.reachability_score).label("avg_reachability"),
            func.count()
            .filter(DeviceHealth.health_status == HealthStatus.HEALTHY)
            .label("healthy"),
            func.count()
            .filter(DeviceHealth.health_status == HealthStatus.WARNING)
            .label("warning"),
            func.count()
            .filter(DeviceHealth.health_status == HealthStatus.DEGRADED)
            .label("degraded"),
            func.count()
            .filter(DeviceHealth.health_status == HealthStatus.CRITICAL)
            .label("critical"),
        )
        .outerjoin(Site, DeviceHealth.site_id == Site.id)
        .where(tenant_filter(DeviceHealth, user))
    )
    if site_id is not None:
        base_q = base_q.where(DeviceHealth.site_id == site_id)

    result = await db.execute(base_q.group_by(DeviceHealth.site_id, Site.name).order_by(Site.name))
    rows = result.all()

    site_summaries: list[SiteHealthSummary] = []
    total_devices = 0
    total_score_sum = 0.0

    for row in rows:
        avg = float(row.avg_score or 100)
        uptime = round(float(row.avg_reachability), 1) if row.avg_reachability is not None else None
        site_summaries.append(
            SiteHealthSummary(
                site_id=row.site_id,
                site_name=row.site_name or "Unassigned",
                device_count=row.device_count,
                avg_health_score=round(avg, 1),
                health_status=DeviceHealth.compute_status(round(avg)).value,
                healthy=row.healthy,
                warning=row.warning,
                degraded=row.degraded,
                critical=row.critical,
                uptime_percent=uptime,
            )
        )
        total_devices += row.device_count
        total_score_sum += avg * row.device_count

    # Count sites
    site_count_q = select(func.count(Site.id)).where(
        Site.organization_id == org_id,
        Site.deleted_at == None,  # noqa: E711
        site_scope_filter(user, Site.id),
    )
    if site_id is not None:
        site_count_q = site_count_q.where(Site.id == site_id)
    total_sites = (await db.execute(site_count_q)).scalar() or 0

    org_avg = total_score_sum / total_devices if total_devices > 0 else 100.0

    return OrgHealthSummary(
        organization_id=org_id,
        site_count=total_sites,
        device_count=total_devices,
        avg_health_score=round(org_avg, 1),
        health_status=DeviceHealth.compute_status(round(org_avg)).value,
        sites=site_summaries,
    )


# ==========================================================================
# Health Dashboard (expanded)
# ==========================================================================


@router.get("/health/devices", response_model=DeviceHealthListResponse)
async def list_device_health(
    site_id: UUID | None = Query(None),
    health_status: str | None = Query(None),
    device_type: str | None = Query(None),
    sort_by: str = Query("health_score"),
    sort_dir: str = Query("asc"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """List device health records with device metadata, filterable and sortable."""
    _org_id(user)

    # Base query: join DeviceHealth + Device + Site (outerjoin since site_id is nullable)
    base = (
        select(
            DeviceHealth,
            Device.name.label("device_name"),
            Device.device_type.label("d_type"),
            Device.ip_address.label("ip_address"),
            Site.name.label("site_name"),
        )
        .join(Device, DeviceHealth.device_id == Device.id)
        .outerjoin(Site, DeviceHealth.site_id == Site.id)
        # SITE-GRANT: tenant_filter folds the org filter AND the
        # per-user site grant — constrain the device-health list to the
        # caller's granted sites (no-op for unrestricted admins).
        .where(tenant_filter(DeviceHealth, user))
    )

    if site_id is not None:
        assert_can_access_site(user, site_id, detail="Site not found")
        base = base.where(DeviceHealth.site_id == site_id)
    if health_status is not None:
        base = base.where(DeviceHealth.health_status == health_status)
    if device_type is not None:
        base = base.where(Device.device_type == device_type)

    # Count total before pagination
    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Sorting. The FE Device Health table exposes a sort button per
    # column — extending the map to cover the 6 component scores means
    # those buttons actually do something instead of silently falling
    # through to ``health_score``.
    sort_column_map = {
        "health_score": DeviceHealth.health_score,
        "device_name": Device.name,
        "updated_at": DeviceHealth.updated_at,
        "reachability_score": DeviceHealth.reachability_score,
        "latency_score": DeviceHealth.latency_score,
        "drift_score": DeviceHealth.drift_score,
        "error_score": DeviceHealth.error_score,
        "utilization_score": DeviceHealth.utilization_score,
        "firmware_score": DeviceHealth.firmware_score,
    }
    sort_col = sort_column_map.get(sort_by, DeviceHealth.health_score)
    base = base.order_by(sort_col.desc()) if sort_dir == "desc" else base.order_by(sort_col.asc())

    base = base.offset(offset).limit(limit)
    result = await db.execute(base)
    rows = result.all()

    devices = []
    for row in rows:
        dh = row[0]  # DeviceHealth model instance
        devices.append(
            DeviceHealthDetail(
                device_id=dh.device_id,
                organization_id=dh.organization_id,
                site_id=dh.site_id,
                health_score=dh.health_score,
                health_status=dh.health_status.value
                if hasattr(dh.health_status, "value")
                else dh.health_status,
                reachability_score=dh.reachability_score,
                latency_score=dh.latency_score,
                drift_score=dh.drift_score,
                error_score=dh.error_score,
                utilization_score=dh.utilization_score,
                firmware_score=dh.firmware_score,
                updated_at=dh.updated_at,
                score_history=dh.score_history or [],
                device_name=row.device_name,
                device_type=row.d_type,
                ip_address=row.ip_address,
                site_name=row.site_name,
            )
        )

    return DeviceHealthListResponse(devices=devices, total=total)


@router.get("/health/top-issues", response_model=TopIssuesResponse)
async def get_top_issues(
    site_id: UUID | None = Query(None),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get top N devices with the worst health scores."""
    _org_id(user)

    q = (
        select(
            DeviceHealth,
            Device.name.label("device_name"),
            Device.device_type.label("d_type"),
            Site.name.label("site_name"),
        )
        .join(Device, DeviceHealth.device_id == Device.id)
        .outerjoin(Site, DeviceHealth.site_id == Site.id)
        # SITE-GRANT: top-issues list scoped to granted sites via
        # tenant_filter (org filter + per-user site grant in one predicate).
        .where(tenant_filter(DeviceHealth, user))
    )

    if site_id is not None:
        assert_can_access_site(user, site_id, detail="Site not found")
        q = q.where(DeviceHealth.site_id == site_id)

    q = q.order_by(DeviceHealth.health_score.asc()).limit(limit)
    result = await db.execute(q)
    rows = result.all()

    # Component score names for finding the worst component
    component_names = [
        ("reachability", "reachability_score"),
        ("latency", "latency_score"),
        ("drift", "drift_score"),
        ("error_rate", "error_score"),
        ("utilization", "utilization_score"),
        ("firmware", "firmware_score"),
    ]

    issues = []
    for row in rows:
        dh = row[0]
        # Find the worst (lowest) component score
        worst_name = "unknown"
        worst_score = 100
        for name, attr in component_names:
            val = getattr(dh, attr, None)
            if val is not None and val < worst_score:
                worst_score = val
                worst_name = name

        issues.append(
            TopHealthIssue(
                device_id=dh.device_id,
                device_name=row.device_name,
                device_type=row.d_type,
                site_name=row.site_name,
                site_id=dh.site_id,
                health_score=dh.health_score,
                health_status=dh.health_status.value
                if hasattr(dh.health_status, "value")
                else dh.health_status,
                worst_component=worst_name,
                worst_component_score=worst_score,
            )
        )

    return TopIssuesResponse(issues=issues)


@router.get("/health/infrastructure", response_model=InfrastructureHealthResponse)
async def get_infrastructure_health(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Check health of infrastructure components (database, Redis, Celery)."""
    import asyncio
    import time as _time

    from app.api.v1.endpoints.health import (
        _start_time,
        check_celery,
        check_database,
        check_redis,
    )

    db_check, redis_check, celery_check = await asyncio.gather(
        check_database(db),
        check_redis(),
        check_celery(),
        return_exceptions=True,
    )

    components: list[InfraComponentHealth] = []
    overall = "healthy"

    for name, result in [("database", db_check), ("redis", redis_check), ("celery", celery_check)]:
        if isinstance(result, BaseException):
            logger.warning("Infrastructure health check failed for %s: %s", name, result)
            components.append(
                InfraComponentHealth(
                    name=name,
                    status="unhealthy",
                    details={"error": "Health check failed"},
                )
            )
            overall = "unhealthy"
        else:
            comp_status = result.status.value if hasattr(result.status, "value") else result.status
            components.append(
                InfraComponentHealth(
                    name=name,
                    status=comp_status,
                    latency_ms=result.latency_ms,
                    details=result.details or {},
                )
            )
            if comp_status == "unhealthy":
                overall = "unhealthy"
            elif comp_status == "degraded" and overall != "unhealthy":
                overall = "degraded"

    uptime = _time.time() - _start_time

    # Collect platform version info for the System Info page.
    #
    # SECURITY: exact framework versions are CVE-target
    # recon data — an attacker who can list ``fastapi==0.115.5``,
    # ``pydantic==2.x.y``, ``postgres 18.4``, etc. for the platform can
    # immediately cross-reference CVE feeds. The full version detail is
    # only useful for admins running upgrades, so we gate it behind
    # ``system:read`` (or super-admin). Read-only / operator roles get
    # ``status`` + ``uptime`` + per-component ``latency_ms`` but no
    # version strings.
    is_admin = bool(
        is_unscoped_superuser(user)
        or getattr(user, "has_permission", lambda _p: False)("system:read")
    )

    import sys

    import cryptography as _cryptography
    import fastapi as _fastapi
    import pydantic as _pydantic
    import sqlalchemy as _sqlalchemy
    from sqlalchemy import text as _text

    from app.core.config import settings as _settings
    from app.schemas.enterprise import PlatformVersionInfo

    if is_admin:
        pg_version: str | None = None
        try:
            pg_result = await db.execute(_text("SHOW server_version"))
            pg_scalar = pg_result.scalar()
            if pg_scalar:
                pg_version = str(pg_scalar).split()[0]
        except Exception:
            pg_version = None

        redis_version: str | None = None
        try:
            from app.core.redis_client import get_async_redis

            r = get_async_redis(decode_responses=True)
            try:
                info = await r.info("server")
                if isinstance(info, dict):
                    redis_version = info.get("redis_version")
            finally:
                await r.aclose()
        except Exception:
            redis_version = None

        platform = PlatformVersionInfo(
            app_version=_settings.APP_VERSION,
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            fastapi_version=_fastapi.__version__,
            sqlalchemy_version=_sqlalchemy.__version__,
            pydantic_version=_pydantic.VERSION,
            cryptography_version=_cryptography.__version__,
            postgres_version=pg_version,
            redis_version=redis_version,
        )
    else:
        # Non-admin: surface only the public app version (already known
        # to the FE via its own bundle), redact the rest.
        platform = PlatformVersionInfo(
            app_version=_settings.APP_VERSION,
            python_version=None,
            fastapi_version=None,
            sqlalchemy_version=None,
            pydantic_version=None,
            cryptography_version=None,
            postgres_version=None,
            redis_version=None,
        )

    return InfrastructureHealthResponse(
        status=overall,
        uptime_seconds=round(uptime, 1),
        components=components,
        platform=platform,
    )


@router.get("/health/modules", response_model=list[ModuleHealthSummary])
async def get_module_health(
    site_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get health summary grouped by module (device type category)."""
    _org_id(user)

    # Device-type → module mapping
    device_type_to_module: dict[str, str] = {
        "switch": "Network",
        "router": "Network",
        "access_point": "Network",
        "gateway": "Network",
        "camera": "Cameras",
        "nvr": "Cameras",
        "voip_phone": "VoIP",
        "pbx": "VoIP",
        "firewall": "Security",
        "hypervisor": "Compute",
    }
    all_device_types = list(device_type_to_module.keys())

    # Single query grouped by device_type
    q = (
        select(
            Device.device_type,
            func.count(DeviceHealth.device_id).label("device_count"),
            func.avg(DeviceHealth.health_score).label("avg_score"),
            func.sum(case((DeviceHealth.health_status == HealthStatus.HEALTHY, 1), else_=0)).label(
                "healthy"
            ),
            func.sum(case((DeviceHealth.health_status == HealthStatus.WARNING, 1), else_=0)).label(
                "warning"
            ),
            func.sum(case((DeviceHealth.health_status == HealthStatus.DEGRADED, 1), else_=0)).label(
                "degraded"
            ),
            func.sum(case((DeviceHealth.health_status == HealthStatus.CRITICAL, 1), else_=0)).label(
                "critical"
            ),
        )
        .select_from(DeviceHealth)
        .join(Device, DeviceHealth.device_id == Device.id)
        .where(
            # SITE-GRANT: module-health rollup scoped to granted
            # sites via tenant_filter (org filter + per-user site grant).
            tenant_filter(DeviceHealth, user),
            Device.device_type.in_(all_device_types),
        )
        .group_by(Device.device_type)
    )

    if site_id is not None:
        assert_can_access_site(user, site_id, detail="Site not found")
        q = q.where(DeviceHealth.site_id == site_id)

    result = await db.execute(q)
    rows = result.all()

    # Aggregate per-device-type rows into per-module summaries
    module_data: dict[str, dict[str, Any]] = {}
    for module_name in ("Network", "Cameras", "VoIP", "Security", "Compute"):
        module_data[module_name] = {
            "device_count": 0,
            "score_sum": 0.0,
            "healthy": 0,
            "warning": 0,
            "degraded": 0,
            "critical": 0,
        }

    for row in rows:
        mod_name = device_type_to_module.get(row.device_type)
        if mod_name is None:
            continue
        md = module_data[mod_name]
        md["device_count"] += row.device_count or 0
        md["score_sum"] += float(row.avg_score or 0) * (row.device_count or 0)
        md["healthy"] += row.healthy or 0
        md["warning"] += row.warning or 0
        md["degraded"] += row.degraded or 0
        md["critical"] += row.critical or 0

    summaries: list[ModuleHealthSummary] = []
    for module_name, md in module_data.items():
        avg = md["score_sum"] / md["device_count"] if md["device_count"] > 0 else 0
        summaries.append(
            ModuleHealthSummary(
                module=module_name,
                device_count=md["device_count"],
                avg_health_score=round(avg, 1),
                healthy=md["healthy"],
                warning=md["warning"],
                degraded=md["degraded"],
                critical=md["critical"],
            )
        )

    return summaries


# ==========================================================================
# Reconciliation
# ==========================================================================


@router.post("/reconcile", response_model=ReconcileResultResponse)
async def trigger_reconciliation(
    payload: ReconcileRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """
    Trigger on-demand config reconciliation for a scope.

    Dispatches Celery tasks for drift detection on the specified devices.
    """
    from app.tasks.reconciliation import reconcile_device as reconcile_device_task

    org_id = _org_id(user)
    device_ids: list[str] = []

    if payload.scope == "device":
        # scope=device|site require scope_id. The schema permits ``None``
        # so the org-scope path can omit it, so we re-check here.
        if payload.scope_id is None:
            raise HTTPException(
                status_code=422,
                detail="scope_id is required for scope=device",
            )
        # Verify the device belongs to the user's organization
        await _verify_device_org(db, payload.scope_id, org_id, user)
        device_ids = [str(payload.scope_id)]
    elif payload.scope == "site":
        if payload.scope_id is None:
            raise HTTPException(
                status_code=422,
                detail="scope_id is required for scope=site",
            )
        # Verify the site belongs to the user's organization
        site_check = await db.execute(
            select(Site.id).where(
                Site.id == payload.scope_id,
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
            )
        )
        if not site_check.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Site not found")
        # SITE-GRANT: a site-limited operator may only reconcile a
        # site they were granted.
        assert_can_access_site(user, payload.scope_id, detail="Site not found")
        result = await db.execute(
            select(Device.id).where(
                Device.site_id == payload.scope_id,
                Device.lifecycle_state == LifecycleState.MANAGED.value,
                Device.deleted_at == None,  # noqa: E711
            )
        )
        device_ids = [str(r[0]) for r in result.all()]
    elif payload.scope == "organization":
        # org-wide reconcile dispatches one Celery task per managed
        # device with no batching/cooldown — repeated triggers can flood the
        # `sync` queue and starve other tenants. Gate with a per-org single-flight
        # lock (mirrors reconcile_all_devices' solo-lock); the lock is NOT
        # released here so its TTL enforces a cooldown between org-wide triggers.
        from app.core.celery_app import acquire_solo_lock

        if not acquire_solo_lock(f"reconcile_on_demand:{org_id}", ttl_seconds=300):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An organization-wide reconciliation was triggered recently. "
                "Wait a few minutes before retrying.",
            )
        # Always use the authenticated user's organization, never trust payload.
        # SITE-GRANT: for a site-limited operator, an "org-wide"
        # reconcile is constrained to their granted sites — it must never fan
        # out to sibling sites they can't see. No-op for unrestricted admins.
        result = await db.execute(
            select(Device.id).where(
                # SITE-GRANT: tenant_filter folds the org filter
                # (reached via Site) AND the per-user site grant — an "org-wide"
                # reconcile for a site-limited operator is constrained to their
                # granted sites and never fans out to sibling sites.
                tenant_filter(Device, user),
                Device.lifecycle_state == LifecycleState.MANAGED.value,
                Device.deleted_at == None,  # noqa: E711
            )
        )
        device_ids = [str(r[0]) for r in result.all()]

    # Dispatch tasks
    for did in device_ids:
        reconcile_device_task.apply_async(args=[did], queue="sync")

    # Audit trail for the trigger. Without this an operator can blast
    # reconciliation across an entire org and leave no record of who
    # did it; matches the SiteGroup / DeviceGroup / Template emission
    # pattern at the top of this file.
    try:
        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        await bus.publish(
            Event(
                event_type="reconcile.triggered",
                category=EventCategory.SYSTEM,
                priority=EventPriority.NORMAL,
                payload={
                    "scope": payload.scope,
                    "scope_id": str(payload.scope_id) if payload.scope_id else None,
                    "device_count": len(device_ids),
                    "user_id": str(user.id),
                },
                organization_id=str(org_id),
            )
        )
    except Exception:
        logger.debug("Failed to emit reconcile.triggered event", exc_info=True)

    return ReconcileResultResponse(
        total=len(device_ids),
        compliant=0,
        drifted=0,
        errors=0,
        devices=[{"device_id": did, "status": "queued"} for did in device_ids],
    )


# ==========================================================================
# Bulk Operations
# ==========================================================================

# Per-operation permission mapping. Previously ALL bulk ops were
# gated by a single config:write. Firmware upgrades can brick devices and
# deserve their own, more restrictive scope; reboot is a separate triage
# action we want to grant operators without giving them config push.
BULK_OPERATION_PERMISSIONS: dict[str, str] = {
    "reboot": "device:reboot",
    "push_config": "config:push",
    "firmware_update": "firmware:upgrade",
}


async def _resolve_bulk_target_site_ids(
    db: AsyncSession,
    target: Any,
    org_id: UUID,
) -> set[UUID]:
    """Resolve a BulkTarget spec to the distinct set of site_ids it hits.

    Used by the /bulk-operations endpoint to enforce per-site access BEFORE
    queueing the Celery task. Every returned site_id is already constrained
    to the caller's organization via the join on Site.organization_id.
    """
    from app.models.enterprise import DeviceGroup, DeviceGroupMembership, DeviceTag

    scope = target.scope
    scope_id = target.scope_id
    device_type = target.device_type

    conditions = [
        Device.lifecycle_state == LifecycleState.MANAGED.value,
        Device.deleted_at == None,  # noqa: E711
    ]
    if device_type:
        conditions.append(Device.device_type == device_type)

    site_ids: set[UUID] = set()

    if scope == "site":
        if scope_id is None:
            return site_ids
        site_check = await db.execute(
            select(Site.id).where(
                Site.id == scope_id,
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
            )
        )
        row = site_check.scalar_one_or_none()
        if row is not None:
            site_ids.add(row)
        return site_ids

    if scope == "device_list" and target.device_ids:
        result = await db.execute(
            select(Device.site_id)
            .join(Site, Device.site_id == Site.id)
            .where(
                Device.id.in_(target.device_ids),
                Site.organization_id == org_id,
                *conditions,
            )
            .distinct()
        )
        return {r[0] for r in result.all() if r[0] is not None}

    if scope == "device_group" and scope_id is not None:
        result = await db.execute(
            select(Device.site_id)
            .join(DeviceGroupMembership, DeviceGroupMembership.device_id == Device.id)
            .join(DeviceGroup, DeviceGroupMembership.group_id == DeviceGroup.id)
            .join(Site, Device.site_id == Site.id)
            .where(
                DeviceGroupMembership.group_id == scope_id,
                DeviceGroup.organization_id == org_id,
                Site.organization_id == org_id,
                *conditions,
            )
            .distinct()
        )
        return {r[0] for r in result.all() if r[0] is not None}

    if scope == "tag" and target.tag:
        result = await db.execute(
            select(Device.site_id)
            .join(DeviceTag, DeviceTag.device_id == Device.id)
            .join(Site, Device.site_id == Site.id)
            .where(
                DeviceTag.tag == target.tag,
                Site.organization_id == org_id,
                *conditions,
            )
            .distinct()
        )
        return {r[0] for r in result.all() if r[0] is not None}

    return site_ids


@router.post(
    "/bulk-operations",
    response_model=BulkOperationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_bulk_operation(
    payload: BulkOperationCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_active_user),
) -> Any:
    """
    Create and dispatch a bulk operation job.

    Supports push_config, reboot, and firmware_update operations
    with optional staged rollout and automatic rollback.

    Permissions are enforced per-operation (see ``BULK_OPERATION_PERMISSIONS``),
    not via a coarse ``config:write`` gate. An operator who holds only
    ``device:reboot`` can launch a reboot bulk op without being granted
    broader config-write powers.
    """
    from app.services.enterprise import BulkOperationService
    from app.tasks.bulk_operations import execute_bulk_operation

    # fail fast for users who hold none of the bulk-op permissions
    # at all — avoids exposing the operation enum to unauthenticated probers.
    if not any(user.has_permission(p) for p in BULK_OPERATION_PERMISSIONS.values()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No bulk-operation permissions granted",
        )

    # per-operation permission check
    required_perm = BULK_OPERATION_PERMISSIONS.get(payload.operation)
    if required_perm is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown operation: {payload.operation}",
        )

    if not user.has_permission(required_perm):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(f"Operation {payload.operation!r} requires '{required_perm}' permission"),
        )

    org_id = _org_id(user)

    # Foreign / non-existent ``scope_id`` used to silently 201 a zero-
    # device job — test jobs were dispatched against a fake site
    # UUID before this check landed. Verify
    # ownership BEFORE queueing so operators get 404 on typo'd UUIDs
    # instead of confused success.
    if payload.target.scope_id is not None and payload.target.scope in ("site", "device_group"):
        if payload.target.scope == "site":
            owner_check = await db.execute(
                select(Site.id).where(
                    Site.id == payload.target.scope_id,
                    Site.organization_id == org_id,
                    Site.deleted_at.is_(None),
                )
            )
            label = "Site"
        else:
            owner_check = await db.execute(
                select(DeviceGroup.id).where(
                    DeviceGroup.id == payload.target.scope_id,
                    DeviceGroup.organization_id == org_id,
                )
            )
            label = "Device group"
        if owner_check.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail=f"{label} not found")

    # verify per-site access level for every target site.
    # A user with site-restricted access cannot launch a bulk op against
    # a site they don't have the right access_level for, even if they hold
    # the required role-level permission.
    target_site_ids = await _resolve_bulk_target_site_ids(db, payload.target, org_id)
    for site_id in target_site_ids:
        if not user.has_site_permission(required_perm, site_id=site_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(f"No access to site {site_id} for operation {payload.operation!r}"),
            )

    # An empty resolved target is operator error (stale device_list,
    # tag matching nothing) — used to 201 a no-op job that wasted
    # Celery capacity and showed up as ``0/0 completed`` clutter. Fail
    # fast so the operator can fix the target.
    if not target_site_ids and payload.target.scope != "site":
        # ``scope=site`` is already 404'd above; reaching this branch
        # for site means scope_id was None, which was already an empty-
        # target case worth refusing.
        raise HTTPException(
            status_code=400,
            detail="Bulk target resolved to zero accessible devices",
        )
    if payload.target.scope == "site" and payload.target.scope_id is None:
        raise HTTPException(
            status_code=400,
            detail="scope='site' requires scope_id",
        )

    svc = BulkOperationService(db)
    job = await svc.create_job(
        organization_id=org_id,
        operation=payload.operation,
        target=payload.target.model_dump(mode="json"),
        device_ids=[],  # resolved by the Celery task
        config=payload.config,
        rollout_strategy=payload.rollout.model_dump() if payload.rollout else None,
        triggered_by=user.id,
    )
    await _emit_bulk_op_event("bulkop.created", job, user_id=user.id)

    # Propagate the operator's identity + required_perm into the task so it
    # can re-check at execution time (see tasks/bulk_operations.py).
    execute_bulk_operation.apply_async(
        args=[str(job.id)],
        kwargs={
            "triggered_by_user_id": str(user.id),
            "required_permission": required_perm,
        },
        queue="sync",
    )

    return _bulk_op_response(job)


def _bulk_op_response(job: Any) -> BulkOperationResponse:
    """Build a BulkOperationResponse from a BulkOperation row.

    Centralized so all four endpoints stay in sync with the schema —
    previously only ``created_at`` was exposed and operators couldn't
    see when a job finished or why it failed.
    """
    return BulkOperationResponse(
        job_id=job.id,
        operation=job.operation,
        status=job.status,
        devices_total=job.devices_total,
        devices_completed=job.devices_completed,
        devices_failed=job.devices_failed,
        devices_skipped=getattr(job, "devices_skipped", 0) or 0,
        current_stage=job.current_stage,
        created_at=job.created_at,
        started_at=getattr(job, "started_at", None),
        completed_at=getattr(job, "completed_at", None),
        error_message=getattr(job, "error_message", None),
    )


async def _emit_bulk_op_event(
    event_type: str,
    job: Any,
    *,
    user_id: Any,
) -> None:
    """Best-effort event-bus publish for bulk-operation lifecycle."""
    try:
        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        await bus.publish(
            Event(
                event_type=event_type,
                category=EventCategory.SYSTEM,
                priority=EventPriority.NORMAL,
                payload={
                    "job_id": str(job.id),
                    "operation": job.operation,
                    "status": job.status,
                    "devices_total": job.devices_total,
                    "user_id": str(user_id) if user_id else None,
                },
                organization_id=str(job.organization_id),
            )
        )
    except Exception:
        logger.debug("Failed to emit %s event", event_type, exc_info=True)


@router.get("/bulk-operations", response_model=list[BulkOperationResponse])
async def list_bulk_operations(
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """List bulk operations for the organization."""
    from app.services.enterprise import BulkOperationService

    org_id = _org_id(user)
    svc = BulkOperationService(db)
    jobs = await svc.list_jobs(
        organization_id=org_id,
        status_filter=status_filter,
        limit=limit,
    )
    return [_bulk_op_response(j) for j in jobs]


@router.get("/bulk-operations/{job_id}", response_model=BulkOperationResponse)
async def get_bulk_operation(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Get status and details of a bulk operation job."""
    from app.services.enterprise import BulkOperationService

    org_id = _org_id(user)
    svc = BulkOperationService(db)
    job = await svc.get_job(job_id)
    if not job or job.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Bulk operation not found")

    return _bulk_op_response(job)


# ``config:write`` is too narrow: a user who could launch a reboot
# bulk op via ``device:reboot`` couldn't abort it. Allow cancel for
# any holder of the bulk-op universe (mirrors the create-time fail-
# fast at line ~2050).
@router.post("/bulk-operations/{job_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_bulk_operation(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_active_user),
) -> Any:
    """Cancel a pending or running bulk operation."""
    from app.services.enterprise import BulkOperationService

    # Fail fast for users with no bulk-op authority at all; an op-
    # specific check happens below once we know which permission was
    # required to create the job.
    if not any(user.has_permission(p) for p in BULK_OPERATION_PERMISSIONS.values()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No bulk-operation permissions granted",
        )

    org_id = _org_id(user)
    svc = BulkOperationService(db)
    job = await svc.get_job(job_id)
    if not job or job.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Bulk operation not found")

    # Symmetric with create: holder of the originally-required perm
    # (or any caller with the perm for the op's category) can cancel.
    required_perm = BULK_OPERATION_PERMISSIONS.get(job.operation)
    if required_perm and not user.has_permission(required_perm):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(f"Cancel of {job.operation!r} requires '{required_perm}' permission"),
        )

    try:
        await svc.cancel_job(job)
    except ValueError as exc:
        # Benign FSM violation (cancel of already-terminal job) — used
        # to be ERROR with full stack trace which spammed logs.
        logger.info("Cannot cancel bulk operation %s: %s", job_id, exc)
        raise HTTPException(status_code=422, detail=str(exc))

    await _emit_bulk_op_event("bulkop.cancelled", job, user_id=user.id)
    return {"status": "cancelled", "job_id": str(job_id)}


# ==========================================================================
# Health History (Feature 2)
# ==========================================================================


@router.get("/health/history", response_model=list[HealthDailySnapshotResponse])
async def get_health_history(
    range: str = Query("7d", pattern=r"^(7d|30d|90d)$"),
    site_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get daily health snapshots for 7d, 30d, or 90d history."""
    _org_id(user)

    days_map = {"7d": 7, "30d": 30, "90d": 90}
    days = days_map.get(range, 7)
    cutoff = date.today() - timedelta(days=days)

    query = (
        select(HealthDailySnapshot)
        .where(
            # SITE-GRANT: health-history snapshots scoped to granted
            # sites via tenant_filter (org filter + per-user site grant).
            tenant_filter(HealthDailySnapshot, user),
            HealthDailySnapshot.snapshot_date >= cutoff,
        )
        .order_by(HealthDailySnapshot.snapshot_date.asc())
    )

    if site_id is not None:
        assert_can_access_site(user, site_id, detail="Site not found")
        query = query.where(HealthDailySnapshot.site_id == site_id)

    try:
        result = await db.execute(query)
        return result.scalars().all()
    except Exception:
        # Table may not exist yet (migration 006 not run)
        await db.rollback()
        return []


# ==========================================================================
# WAN Health (Feature 3)
# ==========================================================================


@router.get("/health/wan", response_model=list[WANDeviceHealth])
async def get_wan_health(
    site_id: UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get health data for WAN devices (gateways, routers, firewalls)."""
    _org_id(user)

    wan_types = ("gateway", "router", "firewall")
    query = (
        select(
            DeviceHealth.device_id,
            Device.name.label("device_name"),
            Device.device_type,
            Site.name.label("site_name"),
            Device.ip_address,
            DeviceHealth.health_score,
            DeviceHealth.latency_score,
            DeviceHealth.reachability_score,
            DeviceHealth.utilization_score,
        )
        .join(Device, DeviceHealth.device_id == Device.id)
        .outerjoin(Site, DeviceHealth.site_id == Site.id)
        .where(
            # SITE-GRANT: WAN-health list scoped to granted sites
            # via tenant_filter (org filter + per-user site grant).
            tenant_filter(DeviceHealth, user),
            Device.device_type.in_(wan_types),
        )
        .order_by(DeviceHealth.health_score.asc())
    )

    if site_id is not None:
        assert_can_access_site(user, site_id, detail="Site not found")
        query = query.where(DeviceHealth.site_id == site_id)

    query = query.limit(limit)

    result = await db.execute(query)
    rows = result.all()

    return [
        WANDeviceHealth(
            device_id=row.device_id,
            device_name=row.device_name,
            device_type=row.device_type,
            site_name=row.site_name,
            ip_address=row.ip_address,
            health_score=row.health_score,
            latency_score=row.latency_score,
            reachability_score=row.reachability_score,
            utilization_score=row.utilization_score,
        )
        for row in rows
    ]


# ==========================================================================
# Site Ranking (Feature 4)
# ==========================================================================


@router.get("/health/site-ranking", response_model=list[SiteRanking])
async def get_site_ranking(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get sites ranked by health score (worst first) with trend."""
    org_id = _org_id(user)

    # Current per-site aggregation (same as get_org_health)
    result = await db.execute(
        select(
            DeviceHealth.site_id,
            Site.name.label("site_name"),
            func.count(DeviceHealth.device_id).label("device_count"),
            func.avg(DeviceHealth.health_score).label("avg_score"),
            func.avg(DeviceHealth.reachability_score).label("avg_reachability"),
        )
        .outerjoin(Site, DeviceHealth.site_id == Site.id)
        # SITE-GRANT: a site-limited operator must only rank sites
        # they were granted, never the whole org. tenant_filter folds the org
        # filter AND the per-user site grant into one predicate.
        .where(tenant_filter(DeviceHealth, user))
        .group_by(DeviceHealth.site_id, Site.name)
    )
    current_rows = result.all()

    if not current_rows:
        return []

    # Yesterday's snapshot for trend calculation (graceful if table not yet migrated)
    yesterday = date.today() - timedelta(days=1)
    yesterday_map: dict[UUID, float] = {}
    try:
        snap_result = await db.execute(
            select(
                HealthDailySnapshot.site_id,
                HealthDailySnapshot.avg_health_score,
            ).where(
                HealthDailySnapshot.organization_id == org_id,
                HealthDailySnapshot.snapshot_date == yesterday,
            )
        )
        yesterday_map = {
            row.site_id: row.avg_health_score
            for row in snap_result.all()
            if row.site_id is not None
        }
    except Exception:
        # Table may not exist yet (migration 006 not run)
        await db.rollback()

    rankings: list[SiteRanking] = []
    for row in current_rows:
        avg = round(float(row.avg_score or 100), 1)
        uptime = round(float(row.avg_reachability), 1) if row.avg_reachability is not None else None

        yesterday_avg = yesterday_map.get(row.site_id)
        trend: Literal["up", "down", "stable"] = "stable"
        if yesterday_avg is not None:
            delta = round(avg - yesterday_avg, 1)
            if delta > 2:
                trend = "up"
            elif delta < -2:
                trend = "down"
            else:
                trend = "stable"
        else:
            delta = 0.0

        rankings.append(
            SiteRanking(
                site_id=row.site_id,
                site_name=row.site_name or "Unassigned",
                avg_health_score=avg,
                device_count=row.device_count,
                uptime_percent=uptime,
                trend=trend,
                trend_delta=delta,
            )
        )

    # Sort by avg_health_score ASC (worst first)
    rankings.sort(key=lambda r: r.avg_health_score)
    return rankings
