# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Drift Detection API
=============================================

Endpoints for viewing, querying, and resolving drift events.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.modules.gateway.schemas import (
    DriftEventListResponse,
    DriftEventResponse,
    DriftResolveRequest,
    SuppressionRuleCreate,
    SuppressionRuleResponse,
)
from app.modules.gateway.services.drift_service import DriftService
from app.modules.gateway.services.suppression_service import SuppressionService

router = APIRouter(prefix="/drift", tags=["Gateway Drift Detection"])


def _org_id(user) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _drift(session: Annotated[AsyncSession, Depends(get_session)]) -> DriftService:
    return DriftService(session)


def _suppress(session: Annotated[AsyncSession, Depends(get_session)]) -> SuppressionService:
    return SuppressionService(session)


# ── GET  /gateway/drift/events ──────────────────────────────────────────


@router.get("/events", response_model=DriftEventListResponse)
async def list_drift_events(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.drift"))],
    svc: Annotated[DriftService, Depends(_drift)],
    site_id: UUID | None = None,
    severity: str | None = None,
    resolved: bool | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List drift events with optional filters."""
    org_id = _org_id(current_user)
    if site_id:
        assert_can_access_site(current_user, site_id)
    # Convert resolved bool to resolution filter
    resolution = None
    if resolved is False:
        resolution = "pending"
    # resolved=True means any non-pending (multiple resolution types)
    exclude_resolution = None
    if resolved is True:
        exclude_resolution = "pending"
    # Per-user site grant is enforced inside ``list_events``
    # via the request-scoped ``current_user_var`` (site_scope_filter folded
    # into the SQL), so a site-limited caller never receives sibling-site rows
    # and ``total`` is correct for pagination.
    items, total = await svc.list_events(
        org_id,
        site_id=site_id,
        severity=severity,
        resolution=resolution,
        exclude_resolution=exclude_resolution,
        limit=limit,
        offset=offset,
    )
    return DriftEventListResponse(
        items=[DriftEventResponse.model_validate(e) for e in items],
        total=total,
        limit=limit,
        offset=offset,
    )


# ── GET  /gateway/drift/summary ─────────────────────────────────────────


@router.get("/summary")
async def drift_summary(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.drift"))],
    svc: Annotated[DriftService, Depends(_drift)],
    site_id: UUID | None = None,
):
    """Aggregated drift summary (counts by severity & resolution status)."""
    org_id = _org_id(current_user)
    if site_id:
        assert_can_access_site(current_user, site_id)
    # Per-user site grant is enforced inside ``get_summary`` via
    # the request-scoped ``current_user_var`` (site_scope_filter folded into the
    # aggregate), so a site-limited caller's org-wide summary already sums only
    # over granted sites.
    return await svc.get_summary(org_id, site_id=site_id)


# ── POST  /gateway/drift/check/{site_id} ────────────────────────────────


@router.post("/check/{site_id}")
async def check_site_drift(
    site_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.drift"))],
    svc: Annotated[DriftService, Depends(_drift)],
):
    """Trigger an on-demand drift check for a site."""
    org_id = _org_id(current_user)
    assert_can_access_site(current_user, site_id)
    events = await svc.check_site(site_id, org_id=org_id)
    return {
        "site_id": str(site_id),
        "new_events": len(events),
        "events": [DriftEventResponse.model_validate(e) for e in events],
    }


# ── POST  /gateway/drift/events/{event_id}/resolve ─────────────────────


@router.post("/events/{event_id}/resolve", response_model=DriftEventResponse)
async def resolve_drift_event(
    event_id: UUID,
    body: DriftResolveRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.drift"))],
    svc: Annotated[DriftService, Depends(_drift)],
):
    """Resolve a drift event (reapply / accept / ignore)."""
    org_id = _org_id(current_user)
    try:
        event = await svc.resolve_event(
            event_id=event_id,
            action=body.resolution,
            user_id=current_user.id,
            org_id=org_id,
        )
        assert_can_access_site(current_user, event.site_id, detail="Drift event not found")
        return DriftEventResponse.model_validate(event)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc))


# =====================================================================
# Suppression Rules
# =====================================================================


@router.get("/suppressions", response_model=list[SuppressionRuleResponse])
async def list_suppression_rules(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.drift"))],
    svc: Annotated[SuppressionService, Depends(_suppress)],
    site_id: UUID | None = None,
    active_only: bool = True,
):
    """List DHCP/DNS suppression rules."""
    org_id = _org_id(current_user)
    if site_id:
        assert_can_access_site(current_user, site_id)
    rules, _total = await svc.list_rules(org_id, site_id=site_id, active_only=active_only)
    # Per-user site grant: exclude sibling-site rules for a site-limited caller.
    if getattr(current_user, "is_site_limited", False):
        rules = [r for r in rules if current_user.can_access_site(r.site_id)]
    return [SuppressionRuleResponse.model_validate(r) for r in rules]


@router.post(
    "/suppressions",
    response_model=SuppressionRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_suppression_rule(
    body: SuppressionRuleCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.drift"))],
    svc: Annotated[SuppressionService, Depends(_suppress)],
):
    """Create a new suppression rule."""
    org_id = _org_id(current_user)
    assert_can_access_site(current_user, body.site_id)
    rule = await svc.create_rule(
        org_id=org_id,
        site_id=body.site_id,
        device_id=body.device_id,
        resource_type=body.resource_type,
        scope=body.scope,
        reason=body.reason,
        suppression_action=body.suppression_action,
    )
    return SuppressionRuleResponse.model_validate(rule)


@router.delete("/suppressions/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_suppression_rule(
    rule_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.drift"))],
    svc: Annotated[SuppressionService, Depends(_suppress)],
):
    """Deactivate (soft-delete) a suppression rule."""
    org_id = _org_id(current_user)
    ok = await svc.deactivate_rule(rule_id, org_id=org_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Suppression rule not found")
    # Per-user site grant: a site-limited caller may not deactivate a rule in a
    # sibling site. The assert raises 404, rolling back the flush above.
    assert_can_access_site(current_user, ok.site_id, detail="Suppression rule not found")
