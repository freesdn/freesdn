# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SLA Monitoring API Endpoints
============================================

CRUD for SLA policies, breach management,
and compliance summary.
"""

import asyncio
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.models.sla import SLABreach, SLAPolicyScope
from app.schemas.sla import (
    SLABreachAcknowledge,
    SLABreachListResponse,
    SLABreachResponse,
    SLAComplianceSummary,
    SLAPolicyCreate,
    SLAPolicyListResponse,
    SLAPolicyResponse,
    SLAPolicyUpdate,
)
from app.services.sla import SLAMonitoringService

router = APIRouter()


def _org_id(user: Any) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


async def _assert_policy_site_access(db: AsyncSession, user: Any, policy: Any) -> None:
    """404 if a site-limited caller may not access a site-derived policy.

    Call AFTER the org-ownership check. No-op for org_admin / super_admin /
    grant-less callers. ``site`` / ``device_group`` / ``camera`` /
    ``nvr`` scopes are confined to the caller's granted sites — the owning site
    of a device_group / camera / nvr is resolved here via its ``site_id`` rather
    than treated as org-level (the previous behavior, which let a site-limited
    caller read/mutate a sibling-site policy). ``organization`` / ``ssid`` have
    no single owning site and stay org-visible; ``site_group`` spans multiple
    sites (may include siblings) so it fails closed for a site-limited caller.
    """
    if not getattr(user, "is_site_limited", False):
        return

    from sqlalchemy import select as _select

    from app.models.sla import SLAPolicyScope

    scope = getattr(policy, "scope", None)
    scope_id = getattr(policy, "scope_id", None)
    if scope in (SLAPolicyScope.ORGANIZATION.value, "ssid"):
        return  # org-wide, no single owning site

    owning: UUID | None = None
    if scope == SLAPolicyScope.SITE.value:
        owning = scope_id
    elif scope == "device_group" and scope_id:
        from app.models.enterprise import DeviceGroup as _DeviceGroup

        owning = await db.scalar(_select(_DeviceGroup.site_id).where(_DeviceGroup.id == scope_id))
    elif scope == "camera" and scope_id:
        from app.modules.cameras.models import Camera as _Camera

        owning = await db.scalar(_select(_Camera.site_id).where(_Camera.id == scope_id))
    elif scope == "nvr" and scope_id:
        from app.modules.cameras.models import NVR as _NVR

        owning = await db.scalar(_select(_NVR.site_id).where(_NVR.id == scope_id))
    else:
        # site_group (multi-site) / unknown -> fail closed for a site-limited caller.
        raise HTTPException(status_code=404, detail="SLA policy not found")

    if owning is None or not user.can_access_site(owning):
        raise HTTPException(status_code=404, detail="SLA policy not found")


async def _verify_sla_scope(
    db: AsyncSession,
    scope: str | None,
    scope_id: UUID | None,
    organization_id: UUID,
) -> None:
    """Verify a policy's scope_id belongs to the caller's org.

    Same pattern as templates' ``_verify_template_scope`` — without
    this check, a ``config:write`` user could anchor an SLA policy
    against another tenant's site / site_group / device_group. The
    SLA service filters health data by org_id so cross-org leak is
    bounded, but the orphan reference is still a hygiene + IDOR
    surface, and ``scope=organization`` with a stray scope_id is
    just confusing.
    """
    if scope is None:
        return

    if scope == "organization":
        if scope_id is not None:
            raise HTTPException(
                status_code=422,
                detail="scope_id must be omitted for scope=organization",
            )
        return

    if scope_id is None:
        # ssid scope may legitimately have a None scope_id since SSID is
        # name-based; the rest require an anchor.
        if scope == "ssid":
            return
        raise HTTPException(
            status_code=422,
            detail=f"scope_id is required for scope={scope}",
        )

    from sqlalchemy import select as _select

    from app.models.core import Site as _Site
    from app.models.enterprise import (
        DeviceGroup as _DeviceGroup,
    )
    from app.models.enterprise import (
        SiteGroup as _SiteGroup,
    )

    if scope == "site":
        ok = await db.execute(
            _select(_Site.id).where(
                _Site.id == scope_id,
                _Site.organization_id == organization_id,
            )
        )
        if ok.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Site not found")
    elif scope == "site_group":
        ok = await db.execute(
            _select(_SiteGroup.id).where(
                _SiteGroup.id == scope_id,
                _SiteGroup.organization_id == organization_id,
            )
        )
        if ok.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Site group not found")
    elif scope == "device_group":
        ok = await db.execute(
            _select(_DeviceGroup.id)
            .join(_Site, _DeviceGroup.site_id == _Site.id)
            .where(
                _DeviceGroup.id == scope_id,
                _Site.organization_id == organization_id,
            )
        )
        if ok.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Device group not found")
    elif scope == "camera":
        from app.modules.cameras.models import Camera as _Camera

        ok = await db.execute(
            _select(_Camera.id).where(
                _Camera.id == scope_id,
                _Camera.organization_id == organization_id,
                _Camera.deleted_at.is_(None),
            )
        )
        if ok.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Camera not found")
    elif scope == "nvr":
        from app.modules.cameras.models import NVR as _NVR

        ok = await db.execute(
            _select(_NVR.id).where(
                _NVR.id == scope_id,
                _NVR.organization_id == organization_id,
            )
        )
        if ok.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="NVR not found")
    # ``ssid`` scope passes through — SSID is identifier-based, no FK to verify.


async def _emit_sla_policy_event(
    event_type: str,
    policy: Any,
    *,
    user_id: Any,
) -> None:
    """Best-effort publish for policy lifecycle.

    Before this, policy create/update/delete were invisible to the
    audit + automation + notification pipeline.
    """
    try:
        import logging

        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        await bus.publish(
            Event(
                event_type=event_type,
                category=EventCategory.SYSTEM,
                priority=EventPriority.NORMAL,
                payload={
                    "policy_id": str(policy.id),
                    "name": getattr(policy, "name", None),
                    "scope": getattr(policy, "scope", None),
                    "scope_id": str(policy.scope_id) if getattr(policy, "scope_id", None) else None,
                    "user_id": str(user_id) if user_id else None,
                },
                organization_id=str(policy.organization_id),
            )
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        import logging

        logging.getLogger(__name__).warning(
            "Failed to emit %s event",
            event_type,
            exc_info=True,
        )


async def _emit_sla_breach_event(
    event_type: str,
    breach: Any,
    *,
    user_id: Any,
) -> None:
    """Best-effort publish for breach lifecycle.

    ``sla.breach.created`` and ``sla.breach.resolved`` were emitted by
    the service layer already; ``sla.breach.acknowledged`` was the
    gap — acknowledging a breach was silent.
    """
    try:
        import logging

        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()
        severity = getattr(breach, "severity", None)
        priority = {
            "critical": EventPriority.CRITICAL,
            "high": EventPriority.HIGH,
            "medium": EventPriority.NORMAL,
            "low": EventPriority.LOW,
            "info": EventPriority.LOW,
        }.get(str(severity).lower() if severity else "medium", EventPriority.NORMAL)
        await bus.publish(
            Event(
                event_type=event_type,
                category=EventCategory.SYSTEM,
                priority=priority,
                payload={
                    "breach_id": str(breach.id),
                    "policy_id": str(breach.policy_id)
                    if getattr(breach, "policy_id", None)
                    else None,
                    "severity": str(severity) if severity else None,
                    "status": getattr(breach, "status", None),
                    "user_id": str(user_id) if user_id else None,
                },
                organization_id=str(breach.organization_id),
            )
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        import logging

        logging.getLogger(__name__).warning(
            "Failed to emit %s event",
            event_type,
            exc_info=True,
        )


# ==========================================================================
# Compliance Summary
# ==========================================================================


@router.get("/summary", response_model=SLAComplianceSummary)
async def get_compliance_summary(
    site_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Get organization-wide SLA compliance summary."""
    org_id = _org_id(user)
    # Per-user site grant: an explicit site_id must be within the caller's
    # grant set; with no site_id the service still constrains site-scoped
    # policies to granted sites for a site-limited user (via the request
    # contextvar) so the org-wide rollup never leaks sibling-site data.
    if site_id is not None:
        assert_can_access_site(user, site_id, detail="SLA compliance summary not found")
    service = SLAMonitoringService(db)
    return await service.get_compliance_summary(org_id, site_id=site_id, current_user=user)


# ==========================================================================
# SLA Policies
# ==========================================================================


@router.get("/policies", response_model=SLAPolicyListResponse)
async def list_sla_policies(
    site_id: UUID | None = Query(None),
    policy_status: str | None = Query(None, alias="status"),
    scope: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """List SLA policies for the organization."""
    org_id = _org_id(user)
    if site_id is not None:
        assert_can_access_site(user, site_id, detail="SLA policies not found")
    service = SLAMonitoringService(db)
    policies, total = await service.list_policies(
        organization_id=org_id,
        status=policy_status,
        scope=scope,
        site_id=site_id,
        limit=limit,
        offset=offset,
        current_user=user,
    )
    return SLAPolicyListResponse(policies=policies, total=total)


@router.post(
    "/policies",
    response_model=SLAPolicyResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_sla_policy(
    body: SLAPolicyCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Create a new SLA policy."""
    org_id = _org_id(user)

    # SECURITY: scope_id was previously passed straight
    # through to the DB — a foreign or non-existent UUID either
    # created an orphan or anchored an SLA policy against another
    # tenant's site_group / site / device_group. Per the templates &
    # SG patterns, validate ownership before insert.
    await _verify_sla_scope(db, body.scope, body.scope_id, org_id)

    service = SLAMonitoringService(db)
    policy = await service.create_policy(
        organization_id=org_id,
        data=body.model_dump(),
        created_by=user.id,
    )
    await db.commit()
    await _emit_sla_policy_event(
        "sla.policy.created",
        policy,
        user_id=user.id,
    )
    return policy


@router.get("/policies/{policy_id}", response_model=SLAPolicyResponse)
async def get_sla_policy(
    policy_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Get a specific SLA policy."""
    org_id = _org_id(user)
    service = SLAMonitoringService(db)
    policy = await service.get_policy(policy_id)
    if not policy or policy.organization_id != org_id:
        raise HTTPException(status_code=404, detail="SLA policy not found")
    await _assert_policy_site_access(db, user, policy)
    return policy


@router.patch("/policies/{policy_id}", response_model=SLAPolicyResponse)
async def update_sla_policy(
    policy_id: UUID,
    body: SLAPolicyUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Update an SLA policy."""
    org_id = _org_id(user)
    service = SLAMonitoringService(db)
    # Verify the policy belongs to the user's organization
    existing = await service.get_policy(policy_id)
    if not existing or existing.organization_id != org_id:
        raise HTTPException(status_code=404, detail="SLA policy not found")
    # Per-user site grant: a site-limited caller may not touch a sibling-site
    # policy even within their own org. Guard the EXISTING anchor first…
    await _assert_policy_site_access(db, user, existing)

    # SECURITY: if scope/scope_id is being changed, re-verify ownership.
    update_data = body.model_dump(exclude_unset=True)
    if "scope" in update_data or "scope_id" in update_data:
        new_scope = update_data.get("scope", existing.scope)
        new_scope_id = update_data.get("scope_id", existing.scope_id)
        await _verify_sla_scope(db, new_scope, new_scope_id, org_id)
        # …and the NEW anchor, so a policy can't be re-pointed at a site the
        # caller has no grant for.
        if new_scope == SLAPolicyScope.SITE.value:
            assert_can_access_site(user, new_scope_id, detail="SLA policy not found")

    policy = await service.update_policy(policy_id, update_data)
    if not policy:
        raise HTTPException(status_code=404, detail="SLA policy not found")
    await db.commit()
    await _emit_sla_policy_event(
        "sla.policy.updated",
        policy,
        user_id=user.id,
    )
    return policy


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sla_policy(
    policy_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> None:
    """Delete an SLA policy."""
    org_id = _org_id(user)
    service = SLAMonitoringService(db)
    # Verify the policy belongs to the user's organization
    existing = await service.get_policy(policy_id)
    if not existing or existing.organization_id != org_id:
        raise HTTPException(status_code=404, detail="SLA policy not found")
    # Per-user site grant: a site-limited caller may not delete a sibling-site policy.
    await _assert_policy_site_access(db, user, existing)

    # Stash for event emission after delete
    policy_for_event = type(
        "P",
        (),
        {
            "id": existing.id,
            "organization_id": existing.organization_id,
            "name": existing.name,
            "scope": existing.scope,
            "scope_id": existing.scope_id,
        },
    )()

    deleted = await service.delete_policy(policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="SLA policy not found")
    await db.commit()
    await _emit_sla_policy_event(
        "sla.policy.deleted",
        policy_for_event,
        user_id=user.id,
    )


# ==========================================================================
# SLA Breaches
# ==========================================================================


@router.get("/breaches", response_model=SLABreachListResponse)
async def list_sla_breaches(
    site_id: UUID | None = Query(None),
    policy_id: UUID | None = None,
    breach_status: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """List SLA breaches for the organization."""
    org_id = _org_id(user)
    if site_id is not None:
        assert_can_access_site(user, site_id, detail="SLA breaches not found")
    service = SLAMonitoringService(db)
    breaches, total = await service.list_breaches(
        organization_id=org_id,
        policy_id=policy_id,
        status=breach_status,
        site_id=site_id,
        limit=limit,
        offset=offset,
        current_user=user,
    )
    return SLABreachListResponse(breaches=breaches, total=total)


@router.post("/breaches/{breach_id}/acknowledge", response_model=SLABreachResponse)
async def acknowledge_breach(
    breach_id: UUID,
    body: SLABreachAcknowledge,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Acknowledge an SLA breach."""
    org_id = _org_id(user)
    # Verify the breach belongs to the user's organization BEFORE modifying.
    # Join the owning policy so we can also enforce the per-user site grant:
    # a site-limited caller may not acknowledge a breach on a sibling-site
    # policy even within their own org.
    from app.models.sla import SLAPolicy

    check = await db.execute(
        select(SLAPolicy.scope, SLAPolicy.scope_id)
        .select_from(SLABreach)
        .join(SLAPolicy, SLABreach.policy_id == SLAPolicy.id)
        .where(
            SLABreach.id == breach_id,
            SLABreach.organization_id == org_id,
        )
    )
    row = check.one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="SLA breach not found")
    if row.scope == SLAPolicyScope.SITE.value:
        assert_can_access_site(user, row.scope_id, detail="SLA breach not found")
    service = SLAMonitoringService(db)
    breach = await service.acknowledge_breach(
        breach_id,
        user_id=user.id,
        notes=body.notes,
        organization_id=org_id,
    )
    if not breach:
        raise HTTPException(status_code=404, detail="SLA breach not found")
    await db.commit()
    # Previously this transition emitted nothing — notifications,
    # automation hooks, and audit pipelines were blind to user-initiated
    # acknowledgement. The service-side ``sla.breach.created`` and
    # ``sla.breach.resolved`` events were already there.
    await _emit_sla_breach_event(
        "sla.breach.acknowledged",
        breach,
        user_id=user.id,
    )
    return breach


# ==========================================================================
# Manual Evaluation Trigger
# ==========================================================================


@router.post("/evaluate")
async def trigger_sla_evaluation(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Manually trigger SLA evaluation for all policies."""
    org_id = _org_id(user)
    service = SLAMonitoringService(db)
    # Per-user site grant: a site-limited operator triggers evaluation only for
    # policies they may access (no sibling-site breach/snapshot/notification
    # side-effects). No-op for org/super admins; the periodic background
    # evaluator passes no user and evaluates the full org set.
    result = await service.evaluate_all_policies(org_id, current_user=user)
    return result
