# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event Correlation API Endpoints
===============================================

CRUD for correlation rules and incidents,
plus trigger endpoint for the correlation engine.
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.schemas.correlation import (
    CorrelationRuleCreate,
    CorrelationRuleListResponse,
    CorrelationRuleResponse,
    CorrelationRuleUpdate,
    CorrelationStatsResponse,
    CorrelationTriggerRequest,
    IncidentCreate,
    IncidentEventResponse,
    IncidentListResponse,
    IncidentResponse,
    IncidentUpdate,
)
from app.services.correlation import EventCorrelationService

router = APIRouter()


def _org_id(user: Any) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


async def _emit_incident_event(
    event_type: str,
    incident: Any,
    *,
    user_id: Any,
    prior_status: str | None,
) -> None:
    """Best-effort event-bus publish for incident lifecycle.

    Before this helper existed, incident state changes were invisible to
    notifications, WebSocket broadcast, automation rules, and audit
    pipelines — operators could acknowledge / resolve / close an
    incident and the wider platform never heard about it. Subscribers
    can now route alerts off ``incident.created``,
    ``incident.acknowledged``, ``incident.resolved``, etc. Failure is
    swallowed so a bus hiccup never breaks the CRUD path.
    """
    try:
        import logging

        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()

        severity = getattr(incident, "severity", None)
        # Severity → bus priority for downstream routing.
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
                    "incident_id": str(incident.id),
                    "title": getattr(incident, "title", None),
                    "severity": str(severity) if severity else None,
                    "status": getattr(incident, "status", None),
                    "prior_status": prior_status,
                    "site_id": str(incident.site_id)
                    if getattr(incident, "site_id", None)
                    else None,
                    "user_id": str(user_id) if user_id else None,
                },
                organization_id=str(incident.organization_id),
            )
        )
    except Exception:
        logging.getLogger(__name__).debug(
            "Failed to emit %s event",
            event_type,
            exc_info=True,
        )


# ==========================================================================
# Stats
# ==========================================================================


@router.get("/stats", response_model=CorrelationStatsResponse)
async def get_correlation_stats(
    site_id: UUID | None = Query(None, description="Filter incident counts by site"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:read")),
) -> Any:
    """Get event correlation statistics."""
    org_id = _org_id(user)
    # Per-user site grant: when a site-limited operator narrows stats to a
    # specific site, it must be one they can access (no-op for admins / None).
    assert_can_access_site(user, site_id, detail="Site not found")
    service = EventCorrelationService(db)
    # the Incidents page sends site_id (queryKey varies by site)
    # but it was ignored — incident counts stayed org-wide in site mode.
    stats = await service.get_stats(org_id, site_id=site_id)
    return stats


# ==========================================================================
# Correlation Rules
# ==========================================================================


@router.get("/rules", response_model=CorrelationRuleListResponse)
async def list_correlation_rules(
    rule_status: str | None = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:read")),
) -> Any:
    """List all correlation rules for the organization."""
    org_id = _org_id(user)
    service = EventCorrelationService(db)
    rules, total = await service.list_rules(org_id, status=rule_status)
    return CorrelationRuleListResponse(rules=rules, total=total)


@router.post(
    "/rules",
    response_model=CorrelationRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_correlation_rule(
    body: CorrelationRuleCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:write")),
) -> Any:
    """Create a new correlation rule."""
    org_id = _org_id(user)
    # CorrelationRule is org-level (no site_id column) and a rule may
    # be scope="organization", firing across every sibling site — there is no
    # grantable site anchor that would make a site-limited create safe. Mirror
    # the list/get/update/delete gate and deny CREATE for site-limited
    # callers (404, consistent with the rule read/write paths). No-op for
    # super_admin / org_admin / grant-less users (is_site_limited is False).
    if getattr(user, "is_site_limited", False):
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    service = EventCorrelationService(db)
    data = body.model_dump()
    # Convert event patterns to dicts
    data["event_patterns"] = [p.model_dump() for p in body.event_patterns]
    rule = await service.create_rule(org_id, data, created_by=user.id)
    await db.commit()
    return rule


@router.get("/rules/{rule_id}", response_model=CorrelationRuleResponse)
async def get_correlation_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:read")),
) -> Any:
    """Get a specific correlation rule."""
    org_id = _org_id(user)
    service = EventCorrelationService(db)
    rule = await service.get_rule(rule_id)
    # org-level rule data is hidden from site-limited callers (mirrors
    # list_rules / get_stats rule-level gate), so a site-limited operator gets a
    # 404 rather than a sibling-site-revealing rule.
    if not rule or rule.organization_id != org_id or getattr(user, "is_site_limited", False):
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    return rule


@router.patch("/rules/{rule_id}", response_model=CorrelationRuleResponse)
async def update_correlation_rule(
    rule_id: UUID,
    body: CorrelationRuleUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:write")),
) -> Any:
    """Update a correlation rule."""
    org_id = _org_id(user)
    service = EventCorrelationService(db)
    # Verify the rule belongs to the user's organization. org-level
    # rule data is hidden from site-limited callers, so a no-op update must not
    # become a read-via-write of sibling-site rule data — 404 for site-limited.
    existing = await service.get_rule(rule_id)
    if (
        not existing
        or existing.organization_id != org_id
        or getattr(user, "is_site_limited", False)
    ):
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    data = body.model_dump(exclude_unset=True)
    if "event_patterns" in data and data["event_patterns"]:
        data["event_patterns"] = [
            p.model_dump() if hasattr(p, "model_dump") else p for p in data["event_patterns"]
        ]
    rule = await service.update_rule(rule_id, data)
    if not rule:
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    await db.commit()
    return rule


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_correlation_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:write")),
) -> None:
    """Delete a correlation rule."""
    org_id = _org_id(user)
    service = EventCorrelationService(db)
    # Verify the rule belongs to the user's organization. org-level
    # rules are hidden from site-limited callers, who therefore cannot delete
    # (or probe the existence of) them — 404 for site-limited.
    existing = await service.get_rule(rule_id)
    if (
        not existing
        or existing.organization_id != org_id
        or getattr(user, "is_site_limited", False)
    ):
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    deleted = await service.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    await db.commit()


# ==========================================================================
# Incidents
# ==========================================================================


@router.get("/incidents", response_model=IncidentListResponse)
async def list_incidents(
    incident_status: str | None = Query(None, alias="status"),
    severity: str | None = None,
    site_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:read")),
) -> Any:
    """List incidents for the organization."""
    org_id = _org_id(user)
    # Per-user site grant: when a site-limited operator narrows the list to a
    # specific site, it must be one they can access (no-op for admins / None).
    # NOTE: the no-``site_id`` case (org-wide listing) is folded into a granted
    # site-id IN(...) filter inside ``EventCorrelationService.list_incidents``
    # — see shared_helpers_to_check.
    assert_can_access_site(user, site_id, detail="Site not found")
    service = EventCorrelationService(db)
    incidents, total = await service.list_incidents(
        organization_id=org_id,
        status=incident_status,
        severity=severity,
        site_id=site_id,
        limit=limit,
        offset=offset,
    )
    return IncidentListResponse(incidents=incidents, total=total)


@router.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_incident(
    body: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:write")),
) -> Any:
    """Manually create an incident."""
    org_id = _org_id(user)

    # SECURITY: site_id was previously passed straight
    # into INSERT — a foreign or non-existent UUID either anchored an
    # incident against another tenant's site or surfaced as a raw 500
    # FK violation to the client. Verify ownership.
    if body.site_id is not None:
        from sqlalchemy import select as _sql_select

        from app.models.core import Site as _Site

        check = await db.execute(
            _sql_select(_Site.id).where(
                _Site.id == body.site_id,
                _Site.organization_id == org_id,
            )
        )
        if check.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Site not found")

        # Per-user site grant: a site-limited operator may only anchor an
        # incident to a site they hold a grant for (no-op for admins).
        assert_can_access_site(user, body.site_id, detail="Site not found")

    service = EventCorrelationService(db)
    incident = await service.create_incident(
        organization_id=org_id,
        data=body.model_dump(),
        created_by=user.id,
    )
    await db.commit()
    # Emit lifecycle event so notifications/automation/WS can react.
    await _emit_incident_event(
        "incident.created",
        incident,
        user_id=user.id,
        prior_status=None,
    )
    return incident


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:read")),
) -> Any:
    """Get a specific incident."""
    org_id = _org_id(user)
    service = EventCorrelationService(db)
    incident = await service.get_incident(incident_id)
    if not incident or incident.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    # Per-user site grant: a site-limited operator may not read an incident
    # anchored to a sibling site (no-op for admins / grant-less / null site).
    assert_can_access_site(user, incident.site_id, detail="Incident not found")
    return incident


@router.patch("/incidents/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: UUID,
    body: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:write")),
) -> Any:
    """Update an incident (status, assignment, notes)."""
    org_id = _org_id(user)
    service = EventCorrelationService(db)
    # Verify the incident belongs to the user's organization
    existing = await service.get_incident(incident_id)
    if not existing or existing.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    # Per-user site grant: a site-limited operator may not mutate an
    # incident anchored to a sibling site (no-op for admins / null site).
    assert_can_access_site(user, existing.site_id, detail="Incident not found")

    # SECURITY: assigned_to was previously unchecked — operator could
    # assign an incident to any user UUID, including cross-org. Validate
    # the assignee is a user in the caller's org.
    update_data = body.model_dump(exclude_unset=True)
    if update_data.get("assigned_to") is not None:
        from sqlalchemy import select as _sql_select

        from app.models.core import User as _User

        check = await db.execute(
            _sql_select(_User.id).where(
                _User.id == update_data["assigned_to"],
                _User.organization_id == org_id,
            )
        )
        if check.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=404,
                detail="Assignee not found in organization",
            )

    prior_status = existing.status if hasattr(existing, "status") else None
    incident = await service.update_incident(incident_id, update_data)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    await db.commit()

    # If status transitioned, emit a typed event so downstream subscribers
    # (notifications, automation, WS broadcast) can react.
    new_status = update_data.get("status")
    if new_status and new_status != prior_status:
        event_type = {
            "investigating": "incident.acknowledged",
            "mitigating": "incident.mitigating",
            "resolved": "incident.resolved",
            "closed": "incident.closed",
            "open": "incident.reopened",
        }.get(new_status, "incident.updated")
        await _emit_incident_event(
            event_type,
            incident,
            user_id=user.id,
            prior_status=prior_status,
        )

    return incident


@router.get(
    "/incidents/{incident_id}/events",
    response_model=list[IncidentEventResponse],
)
async def get_incident_events(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:read")),
) -> Any:
    """Get events linked to an incident."""
    org_id = _org_id(user)
    service = EventCorrelationService(db)
    # Verify the incident belongs to the user's organization
    incident = await service.get_incident(incident_id)
    if not incident or incident.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    # Per-user site grant: don't leak a sibling-site incident's linked events.
    assert_can_access_site(user, incident.site_id, detail="Incident not found")
    events = await service.get_incident_events(incident_id)
    return events


# ==========================================================================
# Correlation Engine Trigger
# ==========================================================================


@router.post("/trigger")
async def trigger_correlation(
    body: CorrelationTriggerRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("event:write")),
) -> Any:
    """Manually trigger the event correlation engine."""
    org_id = _org_id(user)
    # the correlation engine is irreducibly ORG-LEVEL — it loads and
    # fires ALL active org rules (CorrelationRule has no site_id column),
    # mutates their fire_count / last_fired_at, and scans org-wide events when
    # site_id is omitted. assert_can_access_site no-ops on a None site_id, so a
    # site-limited event:write caller could otherwise drive org-wide correlation
    # across sibling sites. Mirror the rule-level posture (rule list /
    # get / update / delete / rule stats are all hidden from site-limited
    # callers): refuse the trigger entirely for a site-limited operator. 404 (not
    # 403) matches the module's existence-oracle-avoiding convention. No-op for
    # super_admin / org_admin / grant-less users; the scheduled Celery task runs
    # in a background context (no request user) and is unaffected.
    if getattr(user, "is_site_limited", False):
        raise HTTPException(status_code=404, detail="Not found")
    # When a site_id IS supplied by an unrestricted caller, it must still be an
    # org-owned site they can access (no-op for admins / None site_id).
    assert_can_access_site(user, body.site_id, detail="Site not found")
    service = EventCorrelationService(db)
    result = await service.correlate(
        organization_id=org_id,
        time_window_minutes=body.time_window_minutes,
        site_id=body.site_id,
        dry_run=body.dry_run,
    )
    return result
