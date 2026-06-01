# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Audit Endpoints
==============================

Audit logging and security event endpoints.
"""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import (
    is_unscoped_org_admin,
    is_unscoped_superuser,
    org_scope_or_platform,
)
from app.db import get_session
from app.models import User
from app.schemas.core import PaginatedResponse
from app.services.audit import (
    AuditAction,
    AuditQuery,
    AuditService,
    ResourceType,
    SecurityEventType,
)

router = APIRouter()


# =============================================================================
# Schemas
# =============================================================================


class AuditLogResponse(BaseModel):
    """Audit log entry response."""

    id: str
    timestamp: datetime
    action: str
    resource_type: str
    resource_id: str | None = None
    resource_name: str | None = None
    actor_id: str | None = None
    actor_name: str | None = None
    actor_type: str
    status: str
    ip_address: str | None = None
    changes: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class SecurityEventResponse(BaseModel):
    """Security event response."""

    id: str
    timestamp: datetime
    event_type: str
    user_id: str | None = None
    user_email: str | None = None
    ip_address: str | None = None
    success: bool
    risk_score: int
    details: dict[str, Any] = {}


class ActivitySummaryResponse(BaseModel):
    """Activity summary response."""

    total_events: int
    by_action: dict[str, int]
    by_resource_type: dict[str, int]
    by_actor: dict[str, int]
    by_status: dict[str, int]
    period: dict[str, str]


class SecuritySummaryResponse(BaseModel):
    """Security summary response."""

    total_events: int
    failed_logins: int
    successful_logins: int
    account_lockouts: int
    suspicious_activities: int
    high_risk_events: int


class AuditExportRequest(BaseModel):
    """Audit export request.

    actions / resource_types capped to keep the IN(...) build bounded;
    each string capped at 64 chars (audit actions are short enums like
    'create' / 'login_failed').
    """

    start_date: datetime | None = None
    end_date: datetime | None = None
    actions: list[str] | None = Field(None, max_length=64)
    resource_types: list[str] | None = Field(None, max_length=64)
    format: str = Field(default="json", pattern="^(json|csv)$")

    @field_validator("actions", "resource_types")
    @classmethod
    def _cap_strs(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for s in v:
            if not isinstance(s, str) or len(s) > 64:
                raise ValueError("each filter value must be a string <= 64 chars")
        return v


# =============================================================================
# Audit Logs
# =============================================================================


@router.get("/logs", response_model=dict[str, Any])
async def get_audit_logs(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    # NOTE: accept repeated query params for action/resource_type
    # so callers can filter on multiple values in one request (e.g.
    # ?action=login&action=login_failed&resource_type=user). The legacy
    # singular ``action``/``resource_type`` params are kept and merged in
    # below for backward compat with the existing frontend.
    action: str | None = None,
    actions: Annotated[list[str] | None, Query()] = None,
    resource_type: str | None = None,
    resource_types: Annotated[list[str] | None, Query()] = None,
    resource_id: UUID | None = None,
    actor_id: UUID | None = None,
    status: str | None = Query(None, max_length=32),
    # ``search`` was unbounded — 10 000-char strings 200'd and echoed.
    search: str | None = Query(None, max_length=128),
    site_id: UUID | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
) -> Any:
    """
    Query audit logs with filters.

    Requires admin privileges.
    """
    # scope-aware admin gate. The raw role check ignored the
    # API-key scope ceiling — a scoped admin key narrowed away from audit reads
    # would still pass on its role alone. ``is_unscoped_org_admin`` keeps
    # role-based access for full/unscoped admin principals while confining
    # scoped keys to their explicit permissions.
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required",
        )

    service = AuditService(db=session)

    # NOTE: merge the singular (back-compat) and plural (new
    # multi-value) query params into a single de-duplicated list.
    merged_actions: list[str] | None = None
    if action or actions:
        merged_actions = list({*(actions or []), *([action] if action else [])})
    merged_resource_types: list[str] | None = None
    if resource_type or resource_types:
        merged_resource_types = list(
            {
                *(resource_types or []),
                *([resource_type] if resource_type else []),
            }
        )

    query = AuditQuery(
        start_date=start_date,
        end_date=end_date,
        actions=merged_actions,
        resource_types=merged_resource_types,
        resource_id=resource_id,
        actor_id=actor_id,
        organization_id=org_scope_or_platform(current_user),
        site_id=site_id,
        status=status,
        search=search,
        limit=per_page,
        offset=(page - 1) * per_page,
    )

    entries, total = await service.query(query)

    return {
        "items": [
            AuditLogResponse(
                id=str(e.id),
                timestamp=e.timestamp,
                action=e.action,
                resource_type=e.resource_type,
                resource_id=str(e.resource_id) if e.resource_id else None,
                resource_name=e.resource_name,
                actor_id=str(e.actor_id) if e.actor_id else None,
                actor_name=e.actor_name,
                actor_type=e.actor_type,
                status=e.status,
                ip_address=e.ip_address,
                changes=e.changes,
            )
            for e in entries
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 0,
    }


@router.get(
    "/logs/resource/{resource_type}/{resource_id}",
    response_model=PaginatedResponse[AuditLogResponse],
)
async def get_resource_audit_logs(
    resource_type: str,
    resource_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
) -> Any:
    """Get audit logs for a specific resource.

        SECURITY: Always scoped to the caller's organization to prevent IDOR
    . A caller in Org A cannot read Org B's audit-log history by
        supplying a foreign resource UUID — the query is filtered by
        ``organization_id`` server-side.

        NOTE: now returns a ``PaginatedResponse`` envelope
        matching ``/logs``. Use ``page``/``per_page`` query params; the
        response includes ``total``, ``page``, ``per_page``, ``pages`` so
        the frontend can render a real pager.
    """
    # scope-aware admin gate (see get_audit_logs).
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    service = AuditService(db=session)
    entries, total = await service.get_by_resource(
        resource_type=resource_type,
        resource_id=resource_id,
        organization_id=current_user.organization_id,
        limit=per_page,
        offset=(page - 1) * per_page,
    )

    items = [
        AuditLogResponse(
            id=str(e.id),
            timestamp=e.timestamp,
            action=e.action,
            resource_type=e.resource_type,
            resource_id=str(e.resource_id) if e.resource_id else None,
            resource_name=e.resource_name,
            actor_id=str(e.actor_id) if e.actor_id else None,
            actor_name=e.actor_name,
            actor_type=e.actor_type,
            status=e.status,
            ip_address=e.ip_address,
            changes=e.changes,
        )
        for e in entries
    ]
    return PaginatedResponse[AuditLogResponse].create(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get(
    "/logs/user/{user_id}",
    response_model=PaginatedResponse[AuditLogResponse],
)
async def get_user_audit_logs(
    user_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
) -> Any:
    """Get audit logs for a specific user.

    SECURITY: Always scoped to the caller's organization.
    The target user is verified to belong to the caller's org before
    serving any rows; cross-org probes return 404 (not 403) to avoid
    leaking user-UUID existence across tenants.

    NOTE: standardised on the ``PaginatedResponse``
    envelope used by ``/logs``. See :func:`get_resource_audit_logs`.
    """
    # Users can view their own logs, admins can view any.
    # scope-aware admin gate (see get_audit_logs) — a scoped
    # admin key narrowed away from audit reads must not pass on role alone.
    if current_user.id != user_id and not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    # Verify the target user belongs to the caller's org. Return 404 on
    # mismatch to avoid leaking "exists in another org" information.
    target_user = await session.get(User, user_id)
    if target_user is None or target_user.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    service = AuditService(db=session)
    entries, total = await service.get_by_actor(
        actor_id=user_id,
        organization_id=current_user.organization_id,
        start_date=start_date,
        end_date=end_date,
        limit=per_page,
        offset=(page - 1) * per_page,
    )

    items = [
        AuditLogResponse(
            id=str(e.id),
            timestamp=e.timestamp,
            action=e.action,
            resource_type=e.resource_type,
            resource_id=str(e.resource_id) if e.resource_id else None,
            resource_name=e.resource_name,
            actor_id=str(e.actor_id) if e.actor_id else None,
            actor_name=e.actor_name,
            actor_type=e.actor_type,
            status=e.status,
            ip_address=e.ip_address,
            changes=e.changes,
        )
        for e in entries
    ]
    return PaginatedResponse[AuditLogResponse].create(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


# =============================================================================
# Security Events
# =============================================================================


# SECURITY EVENT SEVERITY
# ---------------------------------
# ``SecurityEventRecord`` has NO ``severity`` column — severity is a derived
# label over the integer ``risk_score`` (0-100; see
# ``AuditService.log_security_event`` docstring + the >=70 high-risk alert
# threshold). The frontend already buckets it as
# critical >= 80 / high 50-79 / medium 20-49 / low < 20; we mirror those
# exact boundaries here so the dropdown filter and the rendered badges agree.
# Each bucket maps to an inclusive ``risk_score`` range passed to the service.
_SEVERITY_RISK_RANGES: dict[str, tuple[int, int]] = {
    "critical": (80, 100),
    "high": (50, 79),
    "medium": (20, 49),
    "low": (0, 19),
}


@router.get(
    "/security",
    response_model=PaginatedResponse[SecurityEventResponse],
)
async def get_security_events(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    user_id: UUID | None = None,
    event_type: str | None = None,
    severity: str | None = Query(None, max_length=16),
    search: str | None = Query(None, max_length=128),
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
) -> Any:
    """
    Get security events.

    Requires admin privileges.

    NOTE: standardised on the ``PaginatedResponse``
    envelope. ``limit`` is replaced by ``page`` + ``per_page`` so the
    frontend can render proper pagination instead of "first N rows".

    NOTE: the ``severity`` filter (critical|high|medium|low) is
    translated to a ``risk_score`` range — there is no ``severity`` column
    on ``SecurityEventRecord``. See ``_SEVERITY_RISK_RANGES``.
    """
    # scope-aware admin gate (see get_audit_logs).
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    service = AuditService(db=session)

    event_types = None
    if event_type:
        try:
            event_types = [SecurityEventType(event_type)]
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid event type: {event_type}",
            )

    risk_min: int | None = None
    risk_max: int | None = None
    if severity:
        sev = severity.lower()
        if sev not in _SEVERITY_RISK_RANGES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity}",
            )
        risk_min, risk_max = _SEVERITY_RISK_RANGES[sev]

    # Cross-tenant guard: org_admin sees only their org's events;
    # super_admin sees platform-wide (organization_id=None).
    org_filter = org_scope_or_platform(current_user)
    events, total = await service.get_security_events(
        user_id=user_id,
        event_types=event_types,
        start_date=start_date,
        end_date=end_date,
        organization_id=org_filter,
        risk_min=risk_min,
        risk_max=risk_max,
        search=search,
        limit=per_page,
        offset=(page - 1) * per_page,
    )

    items = [
        SecurityEventResponse(
            id=str(e.id),
            timestamp=e.timestamp,
            event_type=e.event_type.value,
            user_id=str(e.user_id) if e.user_id else None,
            user_email=e.user_email,
            ip_address=e.ip_address,
            success=e.success,
            risk_score=e.risk_score,
            details=e.details,
        )
        for e in events
    ]
    return PaginatedResponse[SecurityEventResponse].create(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


# Alias: frontend SecurityPage.tsx uses /audit/security-events
@router.get(
    "/security-events",
    response_model=PaginatedResponse[SecurityEventResponse],
)
async def get_security_events_alias(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    user_id: UUID | None = None,
    event_type: str | None = None,
    severity: str | None = Query(None, max_length=16),
    search: str | None = Query(None, max_length=128),
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
) -> Any:
    """Get security events (alias for /security)."""
    return await get_security_events(
        session=session,
        current_user=current_user,
        user_id=user_id,
        event_type=event_type,
        severity=severity,
        search=search,
        start_date=start_date,
        end_date=end_date,
        page=page,
        per_page=per_page,
    )


# =============================================================================
# Analytics
# =============================================================================


@router.get("/summary/activity", response_model=ActivitySummaryResponse)
async def get_activity_summary(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    site_id: UUID | None = Query(None),
) -> Any:
    """Get activity summary for the organization."""
    # scope-aware admin gate (see get_audit_logs).
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required",
        )

    service = AuditService(db=session)
    summary = await service.get_activity_summary(
        organization_id=current_user.organization_id,
        start_date=start_date,
        end_date=end_date,
        site_id=site_id,
    )

    return ActivitySummaryResponse(**summary)


@router.get("/summary/security", response_model=SecuritySummaryResponse)
async def get_security_summary(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    site_id: UUID | None = Query(None),
) -> Any:
    """Get security summary."""
    # scope-aware admin gate (see get_audit_logs).
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    service = AuditService(db=session)
    # get_security_summary treats a falsey organization_id as "no
    # filter" (platform-wide). A scoped super_admin key (org=None) must NOT
    # fall through to cross-tenant counts; org_scope_or_platform returns None
    # only for an unscoped super_admin and fails closed (403) otherwise.
    summary = await service.get_security_summary(
        organization_id=org_scope_or_platform(current_user),
        start_date=start_date,
        end_date=end_date,
    )

    return SecuritySummaryResponse(**summary)


# =============================================================================
# Export
# =============================================================================


@router.post("/export")
async def export_audit_logs(
    export_request: AuditExportRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """
    Export audit logs as JSON or CSV.

    Requires admin privileges.

    NOTE: exports are capped at ``EXPORT_LIMIT`` rows. Previously
    the cap was applied silently and the caller had no way to know they
    were missing data. We now:
      * count total matching rows BEFORE export,
      * if ``total > EXPORT_LIMIT``, set ``X-Result-Truncated: true`` and
        ``X-Result-Total`` response headers,
      * for JSON exports, inject ``truncated``/``total``/``limit`` keys
        into the payload so programmatic consumers see it without parsing
        headers.
    """
    # scope-aware admin gate (see get_audit_logs).
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    service = AuditService(db=session)

    EXPORT_LIMIT = 10000
    org_id = org_scope_or_platform(current_user)

    # NOTE: probe the total row count first so we can surface
    # truncation to the caller. ``query()`` returns (rows, total) so we
    # reuse it with a count-only call (limit=0-equivalent — but the
    # underlying limit can be 1, we only need the second tuple element).
    count_query = AuditQuery(
        start_date=export_request.start_date,
        end_date=export_request.end_date,
        actions=export_request.actions,
        resource_types=export_request.resource_types,
        organization_id=org_id,
        limit=1,
        offset=0,
    )
    _, total = await service.query(count_query)
    truncated = total > EXPORT_LIMIT

    query = AuditQuery(
        start_date=export_request.start_date,
        end_date=export_request.end_date,
        actions=export_request.actions,
        resource_types=export_request.resource_types,
        organization_id=org_id,
        limit=EXPORT_LIMIT,
    )

    data = await service.export(query, format=export_request.format)

    # NOTE: for JSON exports, inject a ``truncated`` envelope so
    # programmatic consumers can detect partial results without parsing
    # response headers. CSV exports keep their raw shape (header injection
    # would break csv parsers) and rely solely on the ``X-Result-*``
    # headers below.
    if export_request.format == "json" and truncated:
        try:
            import json as _json

            parsed = _json.loads(data.decode("utf-8"))
            wrapped = {
                "truncated": True,
                "total": total,
                "limit": EXPORT_LIMIT,
                "returned": len(parsed) if isinstance(parsed, list) else None,
                "items": parsed,
            }
            data = _json.dumps(wrapped, indent=2).encode("utf-8")
        except Exception:
            # If the export format is unexpected, fall back to the raw
            # payload and rely on response headers only.
            pass

    content_type = "application/json" if export_request.format == "json" else "text/csv"
    filename = f"audit_export_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{export_request.format}"

    headers = {"Content-Disposition": f"attachment; filename={filename}"}
    if truncated:
        headers["X-Result-Truncated"] = "true"
        headers["X-Result-Total"] = str(total)
        headers["X-Result-Limit"] = str(EXPORT_LIMIT)

    return StreamingResponse(
        iter([data]),
        media_type=content_type,
        headers=headers,
    )


# =============================================================================
# Reference Data
# =============================================================================


@router.get("/validate", response_model=dict[str, Any])
async def validate_audit_chain(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    start_id: UUID | None = Query(None),
    end_id: UUID | None = Query(None),
    limit: int = Query(10000, ge=1, le=100000),
) -> Any:
    """Walk the audit hash chain and report any tampering.

    Admin-only. Returns ``{"valid": bool, "broken_at": id | null,
    "broken_reason": str | null, "checked": int, "unchained": int}``.

    NOTE: this is tamper-EVIDENCE, not prevention. A
    DB admin holding both ``AUDIT_HMAC_KEY`` and direct table access
    could still re-key the entire chain. The endpoint is intended for
    SOC2/HIPAA/PCI evidence trails — operators run it on a schedule
    and alert on any non-``valid`` response.
    """
    # Super_admin only — chain validation can be expensive and the
    # response leaks structural metadata about audit volume.
    if not is_unscoped_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin privileges required",
        )

    service = AuditService(db=session)
    return await service.validate_audit_chain(
        start_id=start_id,
        end_id=end_id,
        limit=limit,
    )


# These enum vocabularies were unauthenticated, leaking the audit /
# security-event taxonomy to anonymous callers. They feed authenticated
# UI filters, so require a logged-in user (matches the rest of this file).
@router.get("/actions", response_model=list[str])
async def get_audit_actions(
    _user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get list of available audit actions."""
    return [a.value for a in AuditAction]


@router.get("/resource-types", response_model=list[str])
async def get_resource_types(
    _user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get list of available resource types."""
    return [r.value for r in ResourceType]


@router.get("/security-event-types", response_model=list[str])
async def get_security_event_types(
    _user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get list of available security event types."""
    return [e.value for e in SecurityEventType]
