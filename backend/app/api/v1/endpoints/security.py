# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Security Endpoints
==================================

Enhanced security audit endpoints matching the frontend securityAuditApi:
  GET  /events           - List security events
  GET  /events/{id}      - Get single security event
  PATCH /events/{id}/review - Review a security event
  GET  /summary          - Security summary
  GET  /anomalies        - List security anomalies
  POST /anomalies/{id}/resolve - Resolve anomaly
  GET  /user/{uid}/activity - User activity summary
  GET  /ip/{ip}/activity    - IP activity summary
  GET  /ip/blocks           - List blocked IPs
  POST /ip/block            - Block an IP
  DELETE /ip/block/{ip}     - Unblock an IP
  GET  /compliance/report   - Compliance report
  GET  /event-types         - Reference: event types
  POST /export              - Export security data
  GET  /failed-logins       - List failed login attempts
  GET  /audit-logs          - List audit log entries
  GET  /audit-logs/{id}     - Get single audit log entry

Also provides the /audit/security-events endpoint for SecurityPage.tsx.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import (
    is_platform_super_admin,
    is_unscoped_org_admin,
    is_unscoped_superuser,
    require_permissions,
)
from app.core.security_utils import escape_like
from app.core.site_access import (
    assert_can_access_site,
    site_ids_for_request,
    site_scope_filter,
)
from app.db import get_session
from app.models import User
from app.models.security_audit import (
    AnomalyType,
    AuditActionType,
    AuditLogRecord,
    AuditResourceType,
    IPBlockReason,
    SecurityEventCategory,
    SecuritySeverity,
)
from app.schemas.security_audit import (
    AnomalyResolve,
    AuditLogListResponse,
    AuditLogResponse,
    ComplianceReportResponse,
    FailedLoginListResponse,
    IPActivityResponse,
    IPBlockCreate,
    IPBlockListResponse,
    IPBlockResponse,
    SecurityAnomalyListResponse,
    SecurityAnomalyResponse,
    SecurityEventListResponse,
    SecurityEventResponse,
    SecurityEventReview,
    SecurityExportRequest,
    SecuritySummaryResponse,
    UserActivityResponse,
)
from app.services.security_audit import PersistentSecurityAuditService

router = APIRouter()

Svc = PersistentSecurityAuditService


# =============================================================================
# Helper
# =============================================================================


def require_admin(user: User) -> None:
    # scope-aware. A raw ``user.role`` check ignores the API-key
    # scope ceiling, so a super_admin/org_admin who minted a deliberately-narrowed
    # (read-only) key would still pass and reach the WRITE surfaces this gates
    # (review_security_event / resolve_anomaly / block / export). Require the
    # credential be an UNSCOPED admin instead.
    if not (is_unscoped_superuser(user) or is_unscoped_org_admin(user)):
        raise HTTPException(status_code=403, detail="Admin access required")


def require_super_admin(user: User, *, write: bool = False) -> None:
    """Gate platform-wide (non-tenant-scoped) security data to super admins.

    ``FailedLoginRecord`` and ``IPBlockRecord`` carry no
    ``organization_id`` — they are platform-global. Listing them to an org-scoped
    admin exposed cross-tenant volume, so the failed-login and IP-block read
    surfaces are restricted to ``super_admin`` as an explicit platform posture.

    the decision is now SCOPE-AWARE. A super_admin who minted a
    deliberately-narrowed API key must not exceed its scope. Reads require
    ``is_platform_super_admin`` (unscoped super_admin, or a scoped key carrying
    'audit:read'); platform WRITES (block/unblock) additionally require the
    credential be UNSCOPED — a scoped key may never MUTATE cross-tenant block
    state (there is no 'audit:write' to grant for that purpose).
    """
    if not is_platform_super_admin(user) or (write and getattr(user, "_scoped", False)):
        raise HTTPException(
            status_code=403,
            detail="Platform-wide security data is restricted to super administrators",
        )


def _is_super_admin(user: Any) -> bool:
    return is_platform_super_admin(user)


def _org_id(user: Any) -> Any:
    """Extract organization_id from the current user or raise 400."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _parse_period(period: str | None) -> tuple[datetime, datetime]:
    """Convert period string to date range."""
    now = datetime.now(UTC)
    mapping = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
        "90d": timedelta(days=90),
    }
    delta = mapping.get(period or "7d", timedelta(days=7))
    return now - delta, now


def _validate_ip_path(ip_address: str) -> str:
    """Reject non-IP strings in path parameters.

    Previously ``/ip/{ip}/activity`` and ``/ip/block/{ip}`` accepted
    any URL-encoded string, polluting downstream queries and the
    block-list output.
    """
    import ipaddress

    try:
        ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip_address!r}") from exc
    return ip_address


# =============================================================================
# Security Events
# =============================================================================


@router.get("/events", response_model=SecurityEventListResponse)
async def list_security_events(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_permissions("audit:read")),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    event_type: str | None = Query(None, max_length=64),
    severity: str | None = Query(None, max_length=32),
    category: str | None = Query(None, max_length=64),
    # ``search`` was unbounded; a 10 000-char query 200'd and echoed
    # the param back in the response envelope. Cap to 128 chars.
    search: str | None = Query(None, max_length=128),
    reviewed: bool | None = None,
    site_id: UUID | None = Query(None),
) -> Any:
    """List security events with filters."""
    items, total = await Svc.query_security_events(
        session,
        organization_id=_org_id(user),
        start_date=start_date,
        end_date=end_date,
        event_types=[event_type] if event_type else None,
        severities=[severity] if severity else None,
        categories=[category] if category else None,
        reviewed=reviewed,
        search=search,
        page=page,
        page_size=page_size,
    )
    return SecurityEventListResponse(
        items=[SecurityEventResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        has_more=(page * page_size) < total,
    )


@router.get("/events/{event_id}", response_model=SecurityEventResponse)
async def get_security_event(
    event_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Get a single security event."""
    event = await Svc.get_security_event(session, event_id, organization_id=_org_id(user))
    if not event:
        raise HTTPException(status_code=404, detail="Security event not found")
    return SecurityEventResponse.model_validate(event)


@router.patch("/events/{event_id}/review", response_model=SecurityEventResponse)
async def review_security_event(
    event_id: UUID,
    body: SecurityEventReview,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Review a security event."""
    require_admin(user)
    event = await Svc.review_security_event(
        session,
        event_id,
        reviewer_id=user.id,
        review_notes=body.review_notes,
        organization_id=_org_id(user),
    )
    if not event:
        raise HTTPException(status_code=404, detail="Security event not found")
    await session.commit()
    return SecurityEventResponse.model_validate(event)


# =============================================================================
# Summary
# =============================================================================


@router.get("/summary", response_model=SecuritySummaryResponse)
async def get_security_summary(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
    period: str | None = Query("7d"),
    site_id: UUID | None = Query(None),
) -> Any:
    """Get security summary for a period."""
    start, end = _parse_period(period)
    data = await Svc.get_security_summary(
        session,
        start_date=start,
        end_date=end,
        organization_id=_org_id(user),
        is_super_admin=_is_super_admin(user),
    )
    return SecuritySummaryResponse(**data)


# =============================================================================
# Anomalies
# =============================================================================


@router.get("/anomalies", response_model=SecurityAnomalyListResponse)
async def list_anomalies(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_permissions("audit:read")),
    period: str | None = Query("30d"),
    resolved: bool | None = None,
    severity: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    site_id: UUID | None = Query(None),
) -> Any:
    """List security anomalies."""
    start, end = _parse_period(period)
    items, total = await Svc.get_anomalies(
        session,
        organization_id=_org_id(user),
        resolved=resolved,
        severity=severity,
        start_date=start,
        end_date=end,
        page=page,
        page_size=page_size,
    )
    return SecurityAnomalyListResponse(
        items=[SecurityAnomalyResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/anomalies/{anomaly_id}/resolve",
    response_model=SecurityAnomalyResponse,
)
async def resolve_anomaly(
    anomaly_id: UUID,
    body: AnomalyResolve,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Resolve a security anomaly."""
    require_admin(user)
    anomaly = await Svc.resolve_anomaly(
        session,
        anomaly_id,
        resolved_by=user.id,
        resolution_notes=body.resolution_notes,
        organization_id=_org_id(user),
    )
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    await session.commit()
    return SecurityAnomalyResponse.model_validate(anomaly)


# =============================================================================
# User & IP Activity
# =============================================================================


@router.get("/user/{user_id}/activity", response_model=UserActivityResponse)
async def get_user_activity(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Get activity summary for a user."""
    data = await Svc.get_user_activity(session, user_id, organization_id=_org_id(user))
    # Convert ORM objects in recent_events / recent_actions
    data["recent_events"] = [
        SecurityEventResponse.model_validate(e) for e in data.get("recent_events", [])
    ]
    data["recent_actions"] = [
        AuditLogResponse.model_validate(a) for a in data.get("recent_actions", [])
    ]
    return UserActivityResponse(**data)


@router.get("/ip/{ip_address}/activity", response_model=IPActivityResponse)
async def get_ip_activity(
    ip_address: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Get activity summary for an IP address."""
    require_admin(user)
    ip_address = _validate_ip_path(ip_address)
    data = await Svc.get_ip_activity(
        session,
        ip_address,
        organization_id=_org_id(user),
        is_super_admin=_is_super_admin(user),
    )
    data["recent_events"] = [
        SecurityEventResponse.model_validate(e) for e in data.get("recent_events", [])
    ]
    if data.get("block_info"):
        data["block_info"] = IPBlockResponse.model_validate(data["block_info"])
    return IPActivityResponse(**data)


# =============================================================================
# IP Blocking
# =============================================================================


@router.get("/ip/blocks", response_model=IPBlockListResponse)
async def list_blocked_ips(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
    active_only: bool = Query(True),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    site_id: UUID | None = Query(None),
) -> Any:
    """List blocked IPs.

    ``IPBlockRecord`` is platform-wide (no org column); restricted to
    super_admin so an org-scoped admin can't enumerate sibling-tenant blocks.
    """
    require_super_admin(user)
    items, total = await Svc.get_blocked_ips(
        session, active_only=active_only, page=page, page_size=page_size
    )
    return IPBlockListResponse(
        items=[IPBlockResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/ip/block", response_model=IPBlockResponse, status_code=201)
async def block_ip(
    body: IPBlockCreate,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Manually block an IP address.

    ``IPBlockRecord`` is platform-wide (no org column; unique IP
    constraint). An org_admin must not mutate cross-tenant block state, so this
    write is restricted to super_admin (mirrors the R13 ``/ip/blocks`` read gate).

    ``write=True`` also rejects a SCOPED super_admin key — a narrowed
    credential may never mutate platform-global block state.
    """
    require_super_admin(user, write=True)
    record = await Svc.block_ip(
        session,
        ip_address=body.ip_address,
        reason=body.reason,
        details=body.details,
    )
    await session.commit()
    return IPBlockResponse.model_validate(record)


@router.delete("/ip/block/{ip_address}", response_model=IPBlockResponse)
async def unblock_ip(
    ip_address: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Unblock an IP address.

    ``IPBlockRecord`` is platform-wide (no org column); unblocking is a
    cross-tenant mutation, so it is restricted to super_admin (mirrors the R13
    ``/ip/blocks`` read gate and the POST ``/ip/block`` write gate).

    ``write=True`` also rejects a SCOPED super_admin key.
    """
    require_super_admin(user, write=True)
    ip_address = _validate_ip_path(ip_address)
    record = await Svc.unblock_ip(session, ip_address, unblocked_by=user.id)
    if not record:
        raise HTTPException(status_code=404, detail="Active block not found for IP")
    await session.commit()
    return IPBlockResponse.model_validate(record)


# =============================================================================
# Compliance
# =============================================================================


@router.get("/compliance/report", response_model=ComplianceReportResponse)
async def get_compliance_report(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
    period: str | None = Query("30d"),
) -> Any:
    """Generate a compliance report."""
    require_admin(user)
    start, end = _parse_period(period)
    data = await Svc.generate_compliance_report(
        session,
        start_date=start,
        end_date=end,
        organization_id=_org_id(user),
        is_super_admin=_is_super_admin(user),
    )
    return ComplianceReportResponse(**data)


# =============================================================================
# Event Types (Reference)
# =============================================================================


@router.get("/event-types")
async def get_event_types(
    user: User = Depends(get_current_active_user),
) -> Any:
    """List available security event types."""
    return {
        "event_categories": [e.value for e in SecurityEventCategory],
        "severity_levels": [e.value for e in SecuritySeverity],
        "anomaly_types": [e.value for e in AnomalyType],
        "ip_block_reasons": [e.value for e in IPBlockReason],
        "audit_actions": [e.value for e in AuditActionType],
        "resource_types": [e.value for e in AuditResourceType],
    }


# =============================================================================
# Export
# =============================================================================


@router.post("/export")
async def export_security_data(
    body: SecurityExportRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Export security data as CSV or JSON."""
    require_admin(user)
    data, content_type, row_count = await Svc.export_security_data(
        session,
        export_type=body.export_type,
        format=body.format,
        start_date=body.start_date,
        end_date=body.end_date,
        max_rows=body.max_rows,
        organization_id=_org_id(user),
    )
    ext = "csv" if body.format == "csv" else "json"
    filename = f"security_{body.export_type}_{datetime.now(UTC).strftime('%Y%m%d')}.{ext}"

    return Response(
        content=data,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Row-Count": str(row_count),
        },
    )


# =============================================================================
# Failed Logins
# =============================================================================


@router.get("/failed-logins", response_model=FailedLoginListResponse)
async def list_failed_logins(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
    ip_address: str | None = None,
    username: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    site_id: UUID | None = Query(None),
) -> Any:
    """List failed login attempts.

    ``FailedLoginRecord`` is platform-wide (no org column); restricted to
    super_admin so an org-scoped admin can't read other tenants' login failures.
    """
    require_super_admin(user)
    from app.schemas.security_audit import FailedLoginResponse

    items, total = await Svc.get_failed_logins(
        session,
        ip_address=ip_address,
        username=username,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size,
    )
    return FailedLoginListResponse(
        items=[FailedLoginResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
    )


# =============================================================================
# Audit Logs (DB-backed, for SecurityPage.tsx /audit/logs support)
# =============================================================================


async def _query_audit_logs_site_scoped(
    session: AsyncSession,
    user: Any,
    *,
    organization_id: UUID,
    site_id: UUID | None,
    start_date: datetime | None,
    end_date: datetime | None,
    action: str | None,
    resource_type: str | None,
    resource_id: str | None,
    actor_id: str | None,
    status_filter: str | None,
    search: str | None,
    page: int,
    page_size: int,
) -> tuple[list[AuditLogRecord], int]:
    """Site-grant-aware audit-log query for site-limited callers.

    (R5)``AuditLogRecord`` carries a ``site_id`` but the
    shared ``PersistentSecurityAuditService.query_audit_logs`` only filters by
    ``organization_id`` (and an *optional* single ``site_id`` equality). A
    site-limited operator/viewer/site_admin calling ``/security/audit-logs``
    with no ``site_id`` therefore saw audit rows for sibling sites of the same
    org. This builder mirrors the service WHERE clause but ANDs the per-user
    grant via :func:`site_scope_filter`, keeping org-level (``site_id IS NULL``)
    rows visible. It is only used when the caller is site-limited; unrestricted
    callers keep the shared service path verbatim.
    """
    conditions: list[Any] = [AuditLogRecord.organization_id == organization_id]
    if start_date:
        conditions.append(AuditLogRecord.timestamp >= start_date)
    if end_date:
        conditions.append(AuditLogRecord.timestamp <= end_date)
    if action:
        conditions.append(AuditLogRecord.action == action)
    if resource_type:
        conditions.append(AuditLogRecord.resource_type == resource_type)
    if resource_id:
        conditions.append(AuditLogRecord.resource_id == resource_id)
    if actor_id:
        conditions.append(AuditLogRecord.actor_id == actor_id)
    if status_filter:
        conditions.append(AuditLogRecord.status == status_filter)
    if site_id:
        # Sibling-site ``site_id`` already 404'd by the caller; a granted
        # explicit site simply narrows to that one site.
        conditions.append(AuditLogRecord.site_id == site_id)
    else:
        # No explicit site → restrict to the granted set; org-level rows
        # (site_id NULL) stay visible to any org member.
        conditions.append(
            or_(
                AuditLogRecord.site_id.is_(None),
                site_scope_filter(user, AuditLogRecord.site_id),
            )
        )
    if search:
        like = f"%{escape_like(search)}%"
        conditions.append(
            or_(
                AuditLogRecord.resource_name.ilike(like, escape="\\"),
                AuditLogRecord.actor_name.ilike(like, escape="\\"),
                AuditLogRecord.actor_email.ilike(like, escape="\\"),
                AuditLogRecord.request_path.ilike(like, escape="\\"),
            )
        )

    where = and_(*conditions)
    total = (await session.execute(select(func.count(AuditLogRecord.id)).where(where))).scalar_one()
    offset = (page - 1) * page_size
    rows = (
        (
            await session.execute(
                select(AuditLogRecord)
                .where(where)
                .order_by(AuditLogRecord.timestamp.desc())
                .offset(offset)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


@router.get("/audit-logs", response_model=AuditLogListResponse)
async def list_audit_logs(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    actor_id: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    search: str | None = None,
    site_id: UUID | None = Query(None),
) -> Any:
    """List persistent audit logs."""
    org_id = _org_id(user)
    # (R5): a site-limited caller may not read audit rows for a
    # sibling site. A 404 (not 403) keeps the existence-oracle shape consistent.
    if site_id is not None:
        assert_can_access_site(user, site_id, detail="Audit log not found")

    # When the caller is site-limited we must AND the per-user grant into the
    # query — the shared service filters org-only, so an unscoped call would
    # leak sibling-site audit rows. Unrestricted callers keep the service path.
    if site_ids_for_request(user) is not None:
        items, total = await _query_audit_logs_site_scoped(
            session,
            user,
            organization_id=org_id,
            site_id=site_id,
            start_date=start_date,
            end_date=end_date,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_id=actor_id,
            status_filter=status_filter,
            search=search,
            page=page,
            page_size=page_size,
        )
    else:
        items, total = await Svc.query_audit_logs(
            session,
            organization_id=org_id,
            site_id=site_id,
            start_date=start_date,
            end_date=end_date,
            actions=[action] if action else None,
            resource_types=[resource_type] if resource_type else None,
            resource_id=resource_id,
            actor_id=actor_id,
            status=status_filter,
            search=search,
            page=page,
            page_size=page_size,
        )
    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        has_more=(page * page_size) < total,
    )


@router.get("/audit-logs/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Get a single audit log entry."""
    record = await Svc.get_audit_log(session, log_id, organization_id=_org_id(user))
    if not record:
        raise HTTPException(status_code=404, detail="Audit log not found")
    # (R5): AuditLogRecord has a site_id — a site-limited
    # caller may only read rows for granted sites (org-level NULL rows pass).
    assert_can_access_site(user, record.site_id, detail="Audit log not found")
    return AuditLogResponse.model_validate(record)
