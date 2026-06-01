# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Alert Rules Engine API Endpoints
================================================

CRUD for alert rules and alerts,
plus evaluation trigger and lifecycle management.
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.models.core import Site
from app.models.devices import Device
from app.models.enterprise import DeviceGroup
from app.schemas.alert_rules import (
    AlertAcknowledge,
    AlertListResponse,
    AlertResolve,
    AlertResponse,
    AlertRuleCreate,
    AlertRuleEvaluateRequest,
    AlertRuleListResponse,
    AlertRuleResponse,
    AlertRuleStatsResponse,
    AlertRuleUpdate,
    AlertSuppress,
)
from app.services.alert_rules import AlertRuleService

router = APIRouter()


async def _verify_scope_ids(
    db: AsyncSession,
    scope: str | None,
    scope_ids: list[UUID] | None,
    org_id: UUID,
    user: CurrentUser | None = None,
) -> None:
    """Reject scope_ids that don't belong to the caller's org OR site grant.

    Previously rules could target ``scope=site, scope_ids=[<foreign>]``
    or ``scope=device, scope_ids=[<foreign>]`` and silently land in DB
    — site-scoped rules were also cosmetic (never used by the evaluator)
    so the issue would only surface once that gap is closed.

    Beyond org ownership, a site-limited operator must also hold a grant
    for every referenced site: without this a user granted only
    Site A could pin a rule to a sibling Site B in the same org and have
    the evaluator fire/notify against it. ``assert_can_access_site`` is a
    no-op for super_admin / org_admin / grant-less users.

    a site-limited operator must NOT author an organization-wide
    rule (``scope="organization"`` / empty scope_ids): an org-scoped rule
    is evaluated org-wide and would fire alerts + dispatch notifications
    against sibling sites the caller holds no grant for, escaping the
    per-user site boundary entirely. Confine site-limited callers to
    site/device/device_group rules anchored in their granted sites.
    """
    if not scope_ids or scope == "organization" or scope is None:
        # an org-wide rule (no site anchor) escapes the site grant.
        # A site-limited caller may not create/keep one; admins / grant-less
        # callers are unaffected (``is_site_limited`` is False for them).
        if user is not None and getattr(user, "is_site_limited", False):
            raise HTTPException(
                status_code=404,
                detail="Site(s) not found",
            )
        return
    if scope == "site":
        model, label = Site, "Site"
        owner_col = Site.organization_id
        soft = Site.deleted_at.is_(None)
    elif scope == "device_group":
        # A device group lives within a single site (``DeviceGroup.site_id``).
        # Verify org ownership AND — for a site-limited caller — that each
        # group's owning site is granted. Without this a Site-A
        # operator could pin a rule to a device group in sibling Site B.
        result = await db.execute(
            select(DeviceGroup.id, DeviceGroup.site_id).where(
                DeviceGroup.id.in_(scope_ids),
                DeviceGroup.organization_id == org_id,
            )
        )
        rows = result.all()
        owned = {row[0] for row in rows}
        missing = [str(x) for x in scope_ids if x not in owned]
        if missing:
            raise HTTPException(
                status_code=404,
                detail=f"Device group(s) not found: {', '.join(missing[:5])}",
            )
        if user is not None:
            for _grp_id, grp_site_id in rows:
                assert_can_access_site(user, grp_site_id, detail="Device group(s) not found")
        return
    elif scope == "device":
        model, label = Device, "Device"
        # Device has no direct org column on every install — join to
        # Site for ownership. Pull each device's site_id so the per-user
        # grant can be checked against the device's owning site.
        result = await db.execute(
            select(Device.id, Device.site_id)
            .join(Site, Device.site_id == Site.id)
            .where(
                Device.id.in_(scope_ids),
                Site.organization_id == org_id,
                Device.deleted_at.is_(None),
            )
        )
        rows = result.all()
        owned = {row[0] for row in rows}
        missing = [str(x) for x in scope_ids if x not in owned]
        if missing:
            raise HTTPException(
                status_code=404,
                detail=f"Device(s) not found: {', '.join(missing[:5])}",
            )
        if user is not None:
            for _dev_id, dev_site_id in rows:
                assert_can_access_site(user, dev_site_id, detail="Device(s) not found")
        return
    else:
        return
    stmt = select(model.id).where(model.id.in_(scope_ids), owner_col == org_id)
    if soft is not None:
        stmt = stmt.where(soft)
    result = await db.execute(stmt)
    owned = {row[0] for row in result.all()}
    missing = [str(x) for x in scope_ids if x not in owned]
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"{label}(s) not found: {', '.join(missing[:5])}",
        )
    # Per-user site grant: for site-scoped rules each referenced site must
    # be one the caller can access (no-op for non-site-limited callers).
    if user is not None and scope == "site":
        for sid in scope_ids:
            assert_can_access_site(user, sid, detail=f"{label}(s) not found")


async def _assert_rule_site_grant(db: AsyncSession, rule: Any, user: CurrentUser) -> None:
    """Enforce the per-user site grant on an already-org-verified rule.

    A site-scoped rule (``scope == "site"``) is bound to its ``scope_ids``
    sites; a device-scoped rule to its devices' owning sites; a
    device_group-scoped rule to its groups' owning sites. A site-limited
    operator must hold a grant for every referenced site, else the rule is
    404 to them (sibling-site rule read/mutate/delete leak).

    an organization-scoped rule (or a rule with no ``scope_ids``) has
    no site anchor and is evaluated org-wide; it is 404 to a site-limited
    caller (matching ``list_rules`` which already hides such rows from them),
    so they can neither read nor mutate/delete a rule that fires against
    sibling sites. No-op for super_admin / org_admin / grant-less callers.
    """
    if not getattr(user, "is_site_limited", False):
        return
    scope = getattr(rule, "scope", None)
    scope_ids = getattr(rule, "scope_ids", None) or []
    if scope == "organization" or not scope_ids:
        # Org-wide / unanchored rule → not reachable by a site-limited caller.
        raise HTTPException(status_code=404, detail="Alert rule not found")
    if scope == "site":
        for sid in scope_ids:
            try:
                site_uuid = UUID(str(sid))
            except (ValueError, TypeError):
                continue
            assert_can_access_site(user, site_uuid, detail="Alert rule not found")
    elif scope == "device_group":
        grp_ids: list[UUID] = []
        for sid in scope_ids:
            try:
                grp_ids.append(UUID(str(sid)))
            except (ValueError, TypeError):
                continue
        if grp_ids:
            result = await db.execute(
                select(DeviceGroup.site_id).where(DeviceGroup.id.in_(grp_ids))
            )
            for (grp_site_id,) in result.all():
                assert_can_access_site(user, grp_site_id, detail="Alert rule not found")
    elif scope == "device":
        dev_ids: list[UUID] = []
        for sid in scope_ids:
            try:
                dev_ids.append(UUID(str(sid)))
            except (ValueError, TypeError):
                continue
        if dev_ids:
            result = await db.execute(select(Device.site_id).where(Device.id.in_(dev_ids)))
            for (dev_site_id,) in result.all():
                assert_can_access_site(user, dev_site_id, detail="Alert rule not found")


# ==========================================================================
# Stats
# ==========================================================================


@router.get("/stats", response_model=AlertRuleStatsResponse)
async def get_alert_stats(
    site_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:read")),
) -> Any:
    """Get alert rules and alerts statistics."""
    service = AlertRuleService(db)
    stats = await service.get_stats(user.organization_id, site_id=site_id, current_user=user)
    return stats


# ==========================================================================
# Alert Rules CRUD
# ==========================================================================


@router.get("/rules", response_model=AlertRuleListResponse)
async def list_alert_rules(
    rule_status: str | None = Query(None, alias="status"),
    rule_type: str | None = Query(None, alias="type"),
    site_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:read")),
) -> Any:
    """List all alert rules for the organization."""
    service = AlertRuleService(db)
    rules, total = await service.list_rules(
        user.organization_id,
        status=rule_status,
        rule_type=rule_type,
        site_id=site_id,
        current_user=user,
    )
    return AlertRuleListResponse(rules=rules, total=total)


@router.post(
    "/rules",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_alert_rule(
    body: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:create")),
) -> Any:
    """Create a new alert rule."""
    await _verify_scope_ids(db, body.scope, body.scope_ids, user.organization_id, user)
    service = AlertRuleService(db)
    data = body.model_dump(exclude_unset=True)
    # ``scope_ids`` are typed UUID; JSONB column expects strings.
    if "scope_ids" in data and data["scope_ids"] is not None:
        data["scope_ids"] = [str(x) for x in data["scope_ids"]]
    rule = await service.create_rule(user.organization_id, data, created_by=user.id)
    await db.commit()
    return rule


@router.get("/rules/{rule_id}", response_model=AlertRuleResponse)
async def get_alert_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:read")),
) -> Any:
    """Get a single alert rule by ID."""
    service = AlertRuleService(db)
    rule = await service.get_rule(rule_id)
    if not rule or rule.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    await _assert_rule_site_grant(db, rule, user)
    return rule


@router.patch("/rules/{rule_id}", response_model=AlertRuleResponse)
async def update_alert_rule(
    rule_id: UUID,
    body: AlertRuleUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:update")),
) -> Any:
    """Update an alert rule."""
    service = AlertRuleService(db)
    rule = await service.get_rule(rule_id)
    if not rule or rule.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    # The rule must already be one the caller can reach: a site-limited
    # user may not mutate a rule pinned to a sibling site they can't access.
    await _assert_rule_site_grant(db, rule, user)
    # validate the POST-PATCH EFFECTIVE scope, not just the
    # incoming fields. ``exclude_unset`` distinguishes "field omitted"
    # (keep stored value) from "field explicitly set to null" (clear it),
    # so the effective scope/scope_ids must be reconstructed from the
    # merge of body-over-rule before verification.
    #
    # Without this a site-limited caller who owns a rule anchored to a
    # granted Site A could PATCH {"scope": "organization"} with NO
    # scope_ids — ``body.scope_ids is None`` skipped the old guard, the
    # rule became org-scoped, and the evaluator (``_scope_conditions``,
    # which adds a site predicate ONLY for scope=="site") then fired /
    # notified org-wide across sibling sites. Clearing scope_ids (PATCH
    # {"scope_ids": null}) or pivoting to a sibling site is the same
    # widening class. Re-running ``_verify_scope_ids`` on the effective
    # state fails such a mutation closed (rejects org/unanchored
    # scope for a site-limited caller; admins are unaffected).
    update_fields = body.model_dump(exclude_unset=True)
    scope_touched = "scope" in update_fields or "scope_ids" in update_fields
    if scope_touched or getattr(user, "is_site_limited", False):
        effective_scope = body.scope if "scope" in update_fields else rule.scope
        if "scope_ids" in update_fields:
            effective_scope_ids = body.scope_ids
        else:
            # Stored scope_ids are JSONB strings; coerce to UUID for the
            # ownership / grant lookups (drop anything unparseable).
            effective_scope_ids = []
            for raw in rule.scope_ids or []:
                try:
                    effective_scope_ids.append(UUID(str(raw)))
                except (ValueError, TypeError):
                    continue
        await _verify_scope_ids(
            db, effective_scope, effective_scope_ids, user.organization_id, user
        )
    data = body.model_dump(exclude_unset=True)
    if "scope_ids" in data and data["scope_ids"] is not None:
        data["scope_ids"] = [str(x) for x in data["scope_ids"]]
    updated = await service.update_rule(rule_id, data, updated_by=user.id)
    await db.commit()
    return updated


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:delete")),
) -> None:
    """Soft-delete an alert rule."""
    service = AlertRuleService(db)
    rule = await service.get_rule(rule_id)
    if not rule or rule.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    await _assert_rule_site_grant(db, rule, user)
    await service.delete_rule(rule_id)
    await db.commit()


# ==========================================================================
# Alerts CRUD & Lifecycle
# ==========================================================================


@router.get("/alerts", response_model=AlertListResponse)
async def list_alerts(
    alert_status: str | None = Query(None, alias="status"),
    severity: str | None = None,
    rule_id: UUID | None = None,
    site_id: UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:read")),
) -> Any:
    """List alerts for the organization with optional filters."""
    service = AlertRuleService(db)
    alerts, total = await service.list_alerts(
        user.organization_id,
        status=alert_status,
        severity=severity,
        rule_id=rule_id,
        site_id=site_id,
        limit=limit,
        offset=offset,
        current_user=user,
    )
    return AlertListResponse(alerts=alerts, total=total)


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:read")),
) -> Any:
    """Get a single alert by ID."""
    service = AlertRuleService(db)
    alert = await service.get_alert(alert_id)
    if not alert or alert.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    assert_can_access_site(user, alert.site_id, detail="Alert not found")
    return alert


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: UUID,
    body: AlertAcknowledge | None = None,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:update")),
) -> Any:
    """Acknowledge a firing alert."""
    service = AlertRuleService(db)
    alert = await service.get_alert(alert_id)
    if not alert or alert.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    assert_can_access_site(user, alert.site_id, detail="Alert not found")
    result = await service.acknowledge_alert(
        alert_id,
        user.id,
        note=body.note if body else None,
    )
    if not result:
        raise HTTPException(status_code=400, detail="Alert cannot be acknowledged in current state")
    await db.commit()
    return result


@router.post("/alerts/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: UUID,
    body: AlertResolve | None = None,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:update")),
) -> Any:
    """Manually resolve an alert."""
    service = AlertRuleService(db)
    alert = await service.get_alert(alert_id)
    if not alert or alert.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    assert_can_access_site(user, alert.site_id, detail="Alert not found")
    result = await service.resolve_alert(
        alert_id,
        user.id,
        note=body.resolution_note if body else None,
    )
    if not result:
        raise HTTPException(status_code=400, detail="Alert cannot be resolved in current state")
    await db.commit()
    return result


@router.post("/alerts/{alert_id}/suppress", response_model=AlertResponse)
async def suppress_alert(
    alert_id: UUID,
    body: AlertSuppress,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:update")),
) -> Any:
    """Suppress an alert for a specified duration."""
    service = AlertRuleService(db)
    alert = await service.get_alert(alert_id)
    if not alert or alert.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    assert_can_access_site(user, alert.site_id, detail="Alert not found")
    result = await service.suppress_alert(
        alert_id,
        body.suppress_minutes,
        reason=body.reason,
    )
    if not result:
        raise HTTPException(status_code=400, detail="Alert not found")
    await db.commit()
    return result


# ==========================================================================
# Evaluation
# ==========================================================================


@router.post("/evaluate")
async def trigger_evaluation(
    body: AlertRuleEvaluateRequest | None = None,  # noqa: ARG001 — kept for API stability
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("alert:update")),
) -> Any:
    """Manually trigger alert rule evaluation for the caller's org.

    Was a cross-tenant IDOR: ``body.organization_id`` was trusted and
    the service would fire alerts + dispatch notifications against any
    org the caller named. Now the org is always derived from the
    authenticated user; the body parameter is ignored (kept for API
    stability — pydantic ``extra='ignore'`` silently drops fields).
    Permission also raised from ``alert:create`` to ``alert:update``:
    evaluation burns notification-channel budget (SMS/webhook quotas)
    so it's more like ``execute`` than ``create``.
    """
    service = AlertRuleService(db)
    # thread the caller so a site-limited user only evaluates rules
    # targeting their granted sites (no-op for org/super-admin / background).
    result = await service.evaluate_all_rules(user.organization_id, current_user=user)
    await db.commit()
    return result
