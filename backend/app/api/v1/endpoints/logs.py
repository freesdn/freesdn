# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Unified Logs Endpoint
=====================================

The single source of truth for the chronological audit trail.
Aggregates audit logs + security events into one unified stream.

Endpoints:
  GET /logs              — paginated, filtered unified log list
  GET /logs/stats        — aggregate statistics + hourly histogram
  GET /logs/export/{fmt} — streaming JSON/CSV export
  GET /logs/health       — bird-eye system health overview

Other domains own their dedicated pages:
  /security/*     — failed logins, IP blocks, anomalies (SecurityPage)
  /correlation/*  — incidents, correlation rules (IncidentsPage)
  /audit/*        — audit trail drill-down (SecurityPage audit tab)
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import and_, case, desc, func, literal, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import is_unscoped_org_admin, org_scope_or_platform
from app.core.security_utils import csv_safe, escape_like
from app.db import get_session
from app.models import Site, User
from app.models.correlation import Incident
from app.models.security_audit import (
    AuditLogRecord,
    FailedLoginRecord,
    IPBlockRecord,
    SecurityAnomalyRecord,
    SecurityEventRecord,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ═══════════════════════════════════════════════════════════════════════════════
# Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class LogEntry(BaseModel):
    """Unified log entry returned to the UI."""

    id: str
    timestamp: str
    level: str  # debug | info | warning | error | critical | success
    source: str  # api | auth | device | database | system | user | network | scheduler
    message: str
    details: dict[str, Any] | None = None
    user_id: str | None = None
    user_email: str | None = None
    ip_address: str | None = None
    request_id: str | None = None
    duration_ms: float | None = None
    site_id: str | None = None
    site_name: str | None = None
    device_id: str | None = None
    device_name: str | None = None
    stack_trace: str | None = None


class LogListResponse(BaseModel):
    """Paginated log list."""

    items: list[LogEntry]
    total: int
    page: int
    per_page: int
    pages: int


class HourlyBucket(BaseModel):
    hour: str
    count: int
    errors: int


class LogStatsResponse(BaseModel):
    """Aggregate statistics for the log viewer."""

    total: int
    by_level: dict[str, int]
    by_source: dict[str, int]
    by_hour: list[HourlyBucket]
    error_rate: float
    avg_duration_ms: float | None


# ── Health / bird-eye overview model ─────────────────────────────────────────


class SystemHealthResponse(BaseModel):
    """Top-level bird-eye overview for the log dashboard."""

    # Core metrics
    total_events_24h: int
    total_events_7d: int
    error_count_24h: int
    warning_count_24h: int
    critical_count_24h: int
    success_rate: float  # percentage 0-100

    # Security posture
    failed_logins_24h: int
    active_ip_blocks: int
    unresolved_anomalies: int
    open_incidents: int

    # Trend (compared to previous period)
    event_trend: float  # percentage change vs prior period
    error_trend: float

    # Recent critical items needing attention
    needs_attention: list[dict[str, Any]]  # [{type, id, title, severity, timestamp}]

    # Throughput
    avg_response_ms: float | None
    p95_response_ms: float | None

    # By-day histogram (7 days)
    daily_histogram: list[dict[str, Any]]  # [{date, total, errors, warnings}]


# ═══════════════════════════════════════════════════════════════════════════════
# Mapping helpers — translate audit/security rows → LogEntry
# ═══════════════════════════════════════════════════════════════════════════════

# Action → level mapping
_ACTION_LEVEL: dict[str, str] = {
    "create": "success",
    "update": "info",
    "delete": "warning",
    "login": "success",
    "logout": "info",
    "login_failed": "error",
    "password_change": "info",
    "enable": "success",
    "disable": "warning",
    "adopt": "success",
    "provision": "info",
    "reboot": "warning",
    "upgrade": "info",
    "sync": "info",
    "export": "info",
    "import": "info",
    "backup": "info",
    "restore": "warning",
}

# Action → source mapping
_ACTION_SOURCE: dict[str, str] = {
    "login": "auth",
    "logout": "auth",
    "login_failed": "auth",
    "password_change": "auth",
    "password_reset": "auth",
    "mfa_enable": "auth",
    "mfa_disable": "auth",
    "mfa_verify": "auth",
    "adopt": "device",
    "provision": "device",
    "reboot": "device",
    "upgrade": "device",
    "locate": "device",
    "sync": "scheduler",
    "backup": "system",
    "restore": "system",
    "export": "system",
    "import": "system",
}

# Resource type → source
_RESOURCE_SOURCE: dict[str, str] = {
    "user": "user",
    "role": "user",
    "permission": "user",
    "device": "device",
    "controller": "device",
    "firmware": "device",
    "network": "network",
    "client": "network",
    "site": "api",
    "organization": "api",
    "alert": "system",
    "alert_rule": "system",
    "automation": "scheduler",
    "integration": "api",
    "webhook": "api",
    "api_key": "auth",
    "session": "auth",
    "config": "system",
    "settings": "system",
    "camera": "device",
    "nvr": "device",
}

# Security event type → level
_SEC_LEVEL: dict[str, str] = {
    "login_success": "success",
    "login_failed": "error",
    "logout": "info",
    "password_change": "info",
    "password_reset": "info",
    "password_reset_request": "info",
    "mfa_enabled": "success",
    "mfa_disabled": "warning",
    "mfa_failed": "error",
    "api_key_created": "info",
    "api_key_revoked": "warning",
    "api_key_used": "debug",
    "account_locked": "critical",
    "account_unlocked": "info",
    "suspicious_activity": "critical",
    "permission_escalation": "critical",
    "unauthorized_access": "error",
    "session_created": "debug",
    "session_revoked": "info",
    "brute_force_attempt": "critical",
}


def _level_for_audit(row: AuditLogRecord) -> str:
    """Derive log level from an audit record."""
    if row.status == "error" or row.error_message:
        return "error"
    if row.status == "failure":
        return "warning"
    return _ACTION_LEVEL.get(row.action, "info")


def _source_for_audit(row: AuditLogRecord) -> str:
    """Derive log source from an audit record."""
    src = _ACTION_SOURCE.get(row.action)
    if src:
        return src
    src = _RESOURCE_SOURCE.get(row.resource_type)
    if src:
        return src
    return "api"


def _message_for_audit(row: AuditLogRecord) -> str:
    """Build a human-readable message from an audit record."""
    action = (row.action or "").replace("_", " ").title()
    resource = (row.resource_type or "").replace("_", " ").title()
    name = row.resource_name or (row.resource_id[:8] if row.resource_id else "")
    actor = row.actor_name or row.actor_email or (row.actor_id[:8] if row.actor_id else "system")
    status_suffix = f" — {row.error_message}" if row.error_message else ""
    return f"{actor} · {action} {resource}{' ' + name if name else ''}{status_suffix}"


def _audit_to_log(row: AuditLogRecord) -> LogEntry:
    """Convert an AuditLogRecord to a unified LogEntry."""
    details: dict[str, Any] = {}
    if row.changes:
        details["changes"] = row.changes
    if row.request_method:
        details["method"] = row.request_method
    if row.request_path:
        details["path"] = row.request_path
    if row.response_code:
        details["status_code"] = row.response_code
    if row.extra_metadata:
        details.update(row.extra_metadata)

    return LogEntry(
        id=str(row.id),
        timestamp=row.timestamp.isoformat() if row.timestamp else "",
        level=_level_for_audit(row),
        source=_source_for_audit(row),
        message=_message_for_audit(row),
        details=details or None,
        user_id=row.actor_id,
        user_email=row.actor_email,
        ip_address=row.ip_address,
        request_id=row.request_id,
        duration_ms=row.response_time_ms,
        site_id=str(row.site_id) if row.site_id else None,
        device_id=row.resource_id
        if row.resource_type in ("device", "controller", "camera", "nvr")
        else None,
        device_name=row.resource_name
        if row.resource_type in ("device", "controller", "camera", "nvr")
        else None,
        stack_trace=row.error_message
        if row.status == "error" and row.error_message and len(row.error_message) > 80
        else None,
    )


def _security_to_log(row: SecurityEventRecord) -> LogEntry:
    """Convert a SecurityEventRecord to a unified LogEntry."""
    etype = row.event_type or ""
    level = _SEC_LEVEL.get(etype, "warning")
    label = etype.replace("_", " ").title()
    details = row.details if row.details else None

    user = row.user_email or (str(row.user_id)[:8] if row.user_id else "unknown")
    msg = f"{user} · {label}"
    if not row.success:
        msg += " (failed)"

    return LogEntry(
        id=str(row.id),
        timestamp=row.timestamp.isoformat() if row.timestamp else "",
        level=level,
        source="auth",
        message=msg,
        details=details,
        user_id=str(row.user_id) if row.user_id else None,
        user_email=row.user_email,
        ip_address=row.ip_address,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /logs  — paginated, filtered log list
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/", response_model=LogListResponse)
@router.get("/", response_model=LogListResponse, include_in_schema=False)
async def list_logs(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    # All filter params capped so a 5 KB ``search`` doesn't reach
    # the LIKE builder and a 5 KB ``level``/``source`` doesn't sit
    # in the request middleware logs uselessly.
    level: str | None = Query(
        None,
        max_length=32,
        description="Filter by level: debug|info|warning|error|critical|success",
    ),
    source: str | None = Query(
        None,
        max_length=32,
        description="Filter by source: api|auth|device|database|system|user|network|scheduler",
    ),
    search: str | None = Query(None, max_length=256, description="Full-text search in messages"),
    start_date: datetime | None = Query(None, description="Start of time window (ISO 8601)"),
    end_date: datetime | None = Query(None, description="End of time window (ISO 8601)"),
    site_id: str | None = Query(
        None,
        max_length=64,
        description="Filter by site (audit logs only; security events are not site-scoped)",
    ),
) -> Any:
    """
    Unified log viewer — merges audit logs and security events into a single
    chronological stream with level/source/search filtering.

    Requires admin privileges.
    """
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )

    # scope-aware platform decision — a scoped super_admin key (without
    # org_filter=None (platform-wide) is allowed ONLY for an UNSCOPED
    # super_admin. A scoped key or org user is confined to its own org; a
    # non-unscoped caller with no org fails closed (org_scope_or_platform raises).
    # This prevents a scoped super_admin key (organization_id None) from falling
    # through to an unfiltered cross-tenant audit/security/log query.
    org_filter = org_scope_or_platform(current_user)

    # ── Build audit query ────────────────────────────────────
    audit_conditions: list[Any] = []
    if org_filter:
        audit_conditions.append(AuditLogRecord.organization_id == org_filter)
    if start_date:
        audit_conditions.append(AuditLogRecord.timestamp >= start_date)
    if end_date:
        audit_conditions.append(AuditLogRecord.timestamp <= end_date)
    # the site selector was a no-op on the log list. AuditLogRecord
    # has site_id, so narrow audit rows to the selected site.
    if site_id:
        audit_conditions.append(AuditLogRecord.site_id == site_id)
    if search:
        escaped = escape_like(search)
        pattern = f"%{escaped}%"
        audit_conditions.append(
            or_(
                AuditLogRecord.action.ilike(pattern, escape="\\"),
                AuditLogRecord.resource_type.ilike(pattern, escape="\\"),
                AuditLogRecord.resource_name.ilike(pattern, escape="\\"),
                AuditLogRecord.actor_name.ilike(pattern, escape="\\"),
                AuditLogRecord.actor_email.ilike(pattern, escape="\\"),
                AuditLogRecord.ip_address.ilike(pattern, escape="\\"),
                AuditLogRecord.request_path.ilike(pattern, escape="\\"),
                AuditLogRecord.error_message.ilike(pattern, escape="\\"),
            )
        )

    # Source → action/resource filter
    if source:
        src_actions = [k for k, v in _ACTION_SOURCE.items() if v == source]
        src_resources = [k for k, v in _RESOURCE_SOURCE.items() if v == source]
        src_clauses = []
        if src_actions:
            src_clauses.append(AuditLogRecord.action.in_(src_actions))
        if src_resources:
            src_clauses.append(AuditLogRecord.resource_type.in_(src_resources))
        if src_clauses:
            audit_conditions.append(or_(*src_clauses))
        else:
            # source value matches nothing in audit → exclude all audit rows
            audit_conditions.append(literal(False))

    # Level filter — map to status conditions
    if level:
        if level == "error":
            audit_conditions.append(
                or_(
                    AuditLogRecord.status == "error",
                    AuditLogRecord.error_message.isnot(None),
                )
            )
        elif level == "warning":
            audit_conditions.append(AuditLogRecord.status == "failure")
        elif level == "success":
            audit_conditions.append(
                and_(
                    AuditLogRecord.status == "success",
                    AuditLogRecord.action.in_(["create", "login", "adopt", "enable"]),
                )
            )
        elif level == "critical":
            # audit logs don't produce critical — skip
            audit_conditions.append(literal(False))
        elif level == "debug":
            audit_conditions.append(literal(False))  # audit never debug
        # info → no extra filter (most audit is info)

    audit_where = and_(*audit_conditions) if audit_conditions else True

    # ── Build security query ─────────────────────────────────
    sec_conditions: list[Any] = []
    # Cross-tenant isolation: SecurityEventRecord HAS organization_id
    # but logs.py never filtered by it — an org_admin saw security
    # events (failed logins, suspicious activity, MFA failures) from
    # ALL organizations. Mirror the audit filter.
    if org_filter:
        sec_conditions.append(SecurityEventRecord.organization_id == org_filter)
    if start_date:
        sec_conditions.append(SecurityEventRecord.timestamp >= start_date)
    if end_date:
        sec_conditions.append(SecurityEventRecord.timestamp <= end_date)
    if search:
        escaped = escape_like(search)
        pattern = f"%{escaped}%"
        sec_conditions.append(
            or_(
                SecurityEventRecord.event_type.ilike(pattern, escape="\\"),
                SecurityEventRecord.user_email.ilike(pattern, escape="\\"),
                SecurityEventRecord.ip_address.ilike(pattern, escape="\\"),
            )
        )
    # Source filter — security events are always "auth"
    if source and source != "auth":
        sec_conditions.append(literal(False))
    # SecurityEventRecord has no site_id, so when a site is
    # selected exclude security events entirely rather than showing org-wide
    # ones alongside site-scoped audit rows.
    if site_id:
        sec_conditions.append(literal(False))
    # Level filter for security
    if level:
        matching_types = [k for k, v in _SEC_LEVEL.items() if v == level]
        if matching_types:
            sec_conditions.append(SecurityEventRecord.event_type.in_(matching_types))
        else:
            sec_conditions.append(literal(False))

    sec_where = and_(*sec_conditions) if sec_conditions else True

    # ── Count totals ─────────────────────────────────────────
    audit_count_q = select(func.count(AuditLogRecord.id)).where(audit_where)
    sec_count_q = select(func.count(SecurityEventRecord.id)).where(sec_where)

    audit_total = (await session.scalar(audit_count_q)) or 0
    sec_total = (await session.scalar(sec_count_q)) or 0
    total = audit_total + sec_total

    pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    # ── Fetch rows using UNION ALL sorted by timestamp desc ──
    # Use a two-table merge approach: fetch from both, sort in Python
    # This avoids complex union-all SQL while keeping it efficient.
    # We fetch slightly more than needed and trim.

    # Heuristic: fetch per_page from each, merge & sort, take per_page
    fetch_limit = per_page + 10  # small buffer

    audit_q = (
        select(AuditLogRecord)
        .where(audit_where)
        .order_by(desc(AuditLogRecord.timestamp))
        .offset(offset)
        .limit(fetch_limit)
    )
    sec_q = (
        select(SecurityEventRecord)
        .where(sec_where)
        .order_by(desc(SecurityEventRecord.timestamp))
        .offset(offset)
        .limit(fetch_limit)
    )

    audit_rows = (await session.execute(audit_q)).scalars().all()
    sec_rows = (await session.execute(sec_q)).scalars().all()

    # Resolve site names for the audit rows in a single query (no N+1).
    # Only audit rows carry a site_id; security events are not site-scoped.
    site_name_map: dict[str, str] = {}
    site_ids = {str(r.site_id) for r in audit_rows if r.site_id}
    if site_ids:
        site_name_rows = (
            await session.execute(select(Site.id, Site.name).where(Site.id.in_(site_ids)))
        ).all()
        site_name_map = {str(sid): name for sid, name in site_name_rows}

    # Convert and merge
    entries: list[LogEntry] = []
    for r in audit_rows:
        entry = _audit_to_log(r)
        if entry.site_id:
            entry.site_name = site_name_map.get(entry.site_id)
        entries.append(entry)
    entries.extend(_security_to_log(r) for r in sec_rows)

    # Sort by timestamp desc and take page slice
    entries.sort(key=lambda e: e.timestamp, reverse=True)
    entries = entries[:per_page]

    return LogListResponse(
        items=entries,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /logs/stats  — aggregate statistics + hourly histogram
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/stats", response_model=LogStatsResponse)
async def get_log_stats(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    hours: int = Query(24, ge=1, le=720, description="Look-back window in hours"),
    site_id: str | None = Query(None, description="Filter by site"),
) -> Any:
    """
    Return aggregate stats for the log viewer dashboard:
    totals, level distribution, source distribution, hourly histogram.
    """
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )

    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    # scope-aware platform decision — a scoped super_admin key (without
    # org_filter=None (platform-wide) is allowed ONLY for an UNSCOPED
    # super_admin. A scoped key or org user is confined to its own org; a
    # non-unscoped caller with no org fails closed (org_scope_or_platform raises).
    # This prevents a scoped super_admin key (organization_id None) from falling
    # through to an unfiltered cross-tenant audit/security/log query.
    org_filter = org_scope_or_platform(current_user)

    # ── Audit stats ──────────────────────────────────────────
    audit_conds = [AuditLogRecord.timestamp >= cutoff]
    if org_filter:
        audit_conds.append(AuditLogRecord.organization_id == org_filter)
    if site_id:
        audit_conds.append(AuditLogRecord.site_id == site_id)
    audit_where = and_(*audit_conds)

    # Total + avg duration
    agg = await session.execute(
        select(
            func.count(AuditLogRecord.id).label("cnt"),
            func.avg(AuditLogRecord.response_time_ms).label("avg_ms"),
        ).where(audit_where)
    )
    agg_row = agg.one()
    audit_total = agg_row.cnt or 0
    avg_ms = float(agg_row.avg_ms) if agg_row.avg_ms else None

    # By action (we'll map to levels later)
    action_rows = (
        await session.execute(
            select(AuditLogRecord.action, AuditLogRecord.status, func.count(AuditLogRecord.id))
            .where(audit_where)
            .group_by(AuditLogRecord.action, AuditLogRecord.status)
        )
    ).all()

    # By resource type (map to source)
    resource_rows = (
        await session.execute(
            select(AuditLogRecord.resource_type, func.count(AuditLogRecord.id))
            .where(audit_where)
            .group_by(AuditLogRecord.resource_type)
        )
    ).all()

    # Hourly audit histogram
    audit_hourly = (
        await session.execute(
            select(
                func.date_trunc("hour", AuditLogRecord.timestamp).label("h"),
                func.count(AuditLogRecord.id).label("cnt"),
                func.count(
                    case(
                        (
                            or_(
                                AuditLogRecord.status == "error",
                                AuditLogRecord.error_message.isnot(None),
                            ),
                            1,
                        ),
                    )
                ).label("errs"),
            )
            .where(audit_where)
            .group_by("h")
            .order_by("h")
        )
    ).all()

    # ── Security stats ───────────────────────────────────────
    # Cross-tenant isolation: apply same org_filter used for audit
    # rows. Without this, org_admin stats counted security events
    # platform-wide.
    sec_conds = [SecurityEventRecord.timestamp >= cutoff]
    if org_filter:
        sec_conds.append(SecurityEventRecord.organization_id == org_filter)
    sec_where = and_(*sec_conds)

    sec_total_val = (
        await session.scalar(select(func.count(SecurityEventRecord.id)).where(sec_where))
    ) or 0

    sec_type_rows = (
        await session.execute(
            select(SecurityEventRecord.event_type, func.count(SecurityEventRecord.id))
            .where(sec_where)
            .group_by(SecurityEventRecord.event_type)
        )
    ).all()

    sec_hourly = (
        await session.execute(
            select(
                func.date_trunc("hour", SecurityEventRecord.timestamp).label("h"),
                func.count(SecurityEventRecord.id).label("cnt"),
                func.count(
                    case(
                        (SecurityEventRecord.success == False, 1),  # noqa: E712
                    )
                ).label("errs"),
            )
            .where(sec_where)
            .group_by("h")
            .order_by("h")
        )
    ).all()

    # ── Aggregate ────────────────────────────────────────────
    total = audit_total + sec_total_val

    # Level distribution
    by_level: dict[str, int] = {
        "debug": 0,
        "info": 0,
        "warning": 0,
        "error": 0,
        "critical": 0,
        "success": 0,
    }
    for action, st, cnt in action_rows:
        lvl = "error" if st == "error" else _ACTION_LEVEL.get(action, "info")
        by_level[lvl] = by_level.get(lvl, 0) + cnt
    for etype, cnt in sec_type_rows:
        lvl = _SEC_LEVEL.get(etype, "info")
        by_level[lvl] = by_level.get(lvl, 0) + cnt

    # Source distribution
    by_source: dict[str, int] = {}
    for action, _st, cnt in action_rows:
        src = _ACTION_SOURCE.get(action, "api")
        by_source[src] = by_source.get(src, 0) + cnt
    for rtype, cnt in resource_rows:
        src = _RESOURCE_SOURCE.get(rtype, "api")
        by_source[src] = by_source.get(src, 0) + cnt
    for _etype, cnt in sec_type_rows:
        by_source["auth"] = by_source.get("auth", 0) + cnt

    # Hourly histogram — merge audit + security buckets
    hourly_map: dict[str, dict[str, int]] = {}
    for h, cnt, errs in audit_hourly:
        key = h.strftime("%H:%M") if h else "00:00"
        hourly_map.setdefault(key, {"count": 0, "errors": 0})
        hourly_map[key]["count"] += cnt
        hourly_map[key]["errors"] += errs
    for h, cnt, errs in sec_hourly:
        key = h.strftime("%H:%M") if h else "00:00"
        hourly_map.setdefault(key, {"count": 0, "errors": 0})
        hourly_map[key]["count"] += cnt
        hourly_map[key]["errors"] += errs

    by_hour = [
        HourlyBucket(hour=k, count=v["count"], errors=v["errors"])
        for k, v in sorted(hourly_map.items())
    ]

    error_count = by_level.get("error", 0) + by_level.get("critical", 0)
    error_rate = round(error_count / total * 100, 2) if total else 0.0

    return LogStatsResponse(
        total=total,
        by_level=by_level,
        by_source=by_source,
        by_hour=by_hour,
        error_rate=error_rate,
        avg_duration_ms=round(avg_ms, 1) if avg_ms else None,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /logs/export/{format}  — streaming export
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/export/{fmt}")
async def export_logs(
    fmt: str,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    level: str | None = Query(None, max_length=32),
    source: str | None = Query(None, max_length=32),
    search: str | None = Query(None, max_length=256),
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    site_id: str | None = Query(None, max_length=64),
) -> Any:
    """
    Export logs as JSON or CSV.  Delegates filtering to the list_logs logic.

    Path params:
      fmt: "json" | "csv"
    """
    if fmt not in ("json", "csv"):
        raise HTTPException(status_code=400, detail="Format must be json or csv")

    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )

    # Fetch up to 10 000 rows for export
    result = await list_logs(
        session=session,
        current_user=current_user,
        page=1,
        per_page=200,
        level=level,
        source=source,
        search=search,
        start_date=start_date,
        end_date=end_date,
        site_id=site_id,
    )
    entries = result.items

    # Also fetch remaining pages (up to 50 pages = 10k rows)
    if result.pages > 1:
        for p in range(2, min(result.pages + 1, 51)):
            page_result = await list_logs(
                session=session,
                current_user=current_user,
                page=p,
                per_page=200,
                level=level,
                source=source,
                search=search,
                start_date=start_date,
                end_date=end_date,
                site_id=site_id,
            )
            entries.extend(page_result.items)

    now_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=[
                "timestamp",
                "level",
                "source",
                "message",
                "user_email",
                "ip_address",
                "request_id",
                "duration_ms",
                "site_name",
                "device_name",
            ],
        )
        writer.writeheader()
        for e in entries:
            # neutralize CSV formula injection on every cell.
            writer.writerow(
                {
                    k: csv_safe(v)
                    for k, v in {
                        "timestamp": e.timestamp,
                        "level": e.level,
                        "source": e.source,
                        "message": e.message,
                        "user_email": e.user_email or "",
                        "ip_address": e.ip_address or "",
                        "request_id": e.request_id or "",
                        "duration_ms": e.duration_ms or "",
                        "site_name": e.site_name or "",
                        "device_name": e.device_name or "",
                    }.items()
                }
            )
        content = buf.getvalue().encode()
        return StreamingResponse(
            iter([content]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=freesdn_logs_{now_str}.csv"},
        )
    else:
        data = [e.model_dump(exclude_none=True) for e in entries]
        content = json.dumps(data, indent=2).encode()
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=freesdn_logs_{now_str}.json"},
        )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /logs/health  — bird-eye system overview
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/health", response_model=SystemHealthResponse)
async def get_system_health(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """
    Bird-eye-view dashboard: top-level system health across all log sources.
    Shows 24h/7d metrics, trends, security posture, and items needing attention.
    """
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )

    now = datetime.now(UTC)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)
    cutoff_prior_24h = cutoff_24h - timedelta(hours=24)  # for trend

    # scope-aware platform decision — a scoped super_admin key (without
    # org_filter=None (platform-wide) is allowed ONLY for an UNSCOPED
    # super_admin. A scoped key or org user is confined to its own org; a
    # non-unscoped caller with no org fails closed (org_scope_or_platform raises).
    # This prevents a scoped super_admin key (organization_id None) from falling
    # through to an unfiltered cross-tenant audit/security/log query.
    org_filter = org_scope_or_platform(current_user)

    # ── 24h audit counts ──
    audit_24h_conds = [AuditLogRecord.timestamp >= cutoff_24h]
    if org_filter:
        audit_24h_conds.append(AuditLogRecord.organization_id == org_filter)

    audit_24h_q = select(
        func.count(AuditLogRecord.id).label("total"),
        func.count(
            case(
                (or_(AuditLogRecord.status == "error", AuditLogRecord.error_message.isnot(None)), 1)
            )
        ).label("errors"),
        func.count(case((AuditLogRecord.status == "failure", 1))).label("warnings"),
        func.avg(AuditLogRecord.response_time_ms).label("avg_ms"),
        func.percentile_cont(0.95).within_group(AuditLogRecord.response_time_ms).label("p95_ms"),
    ).where(and_(*audit_24h_conds))
    a24 = (await session.execute(audit_24h_q)).one()

    # ── 7d audit count ──
    audit_7d_total = (
        await session.scalar(
            select(func.count(AuditLogRecord.id)).where(
                and_(AuditLogRecord.timestamp >= cutoff_7d, *(audit_24h_conds[1:]))
            )
        )
    ) or 0

    # ── Prior 24h audit count for trend ──
    audit_prior_conds = [
        AuditLogRecord.timestamp >= cutoff_prior_24h,
        AuditLogRecord.timestamp < cutoff_24h,
    ]
    if org_filter:
        audit_prior_conds.append(AuditLogRecord.organization_id == org_filter)
    prior_24h_total = (
        await session.scalar(select(func.count(AuditLogRecord.id)).where(and_(*audit_prior_conds)))
    ) or 0
    prior_24h_errors = (
        await session.scalar(
            select(func.count(AuditLogRecord.id)).where(
                and_(
                    *audit_prior_conds,
                    or_(AuditLogRecord.status == "error", AuditLogRecord.error_message.isnot(None)),
                )
            )
        )
    ) or 0

    # ── 24h security event counts ──
    # Apply same org filter as audit. Without it, org_admin's
    # health dashboard counted platform-wide critical events.
    sec_24h_conds = [SecurityEventRecord.timestamp >= cutoff_24h]
    if org_filter:
        sec_24h_conds.append(SecurityEventRecord.organization_id == org_filter)
    sec_24h_total = (
        await session.scalar(select(func.count(SecurityEventRecord.id)).where(and_(*sec_24h_conds)))
    ) or 0
    sec_24h_critical = (
        await session.scalar(
            select(func.count(SecurityEventRecord.id)).where(
                and_(
                    *sec_24h_conds,
                    SecurityEventRecord.event_type.in_(
                        [k for k, v in _SEC_LEVEL.items() if v == "critical"]
                    ),
                )
            )
        )
    ) or 0

    total_24h = (a24.total or 0) + sec_24h_total
    error_24h = a24.errors or 0
    warning_24h = a24.warnings or 0
    critical_24h = sec_24h_critical

    # Trends
    prior_total = prior_24h_total  # Simplified: security trend not critical
    event_trend = round(((total_24h - prior_total) / max(prior_total, 1)) * 100, 1)
    error_trend = round(((error_24h - prior_24h_errors) / max(prior_24h_errors, 1)) * 100, 1)

    success_rate = round(((total_24h - error_24h - critical_24h) / max(total_24h, 1)) * 100, 1)

    # ── Security posture ──
    # org_admin callers must NOT see platform-wide security
    # data. FailedLoginRecord / IPBlockRecord carry no tenant key (pre-auth /
    # platform-level), so they are zeroed for non-super-admins; the rest are
    # org-scoped via org_filter.
    if org_filter:
        failed_logins_24h = 0
        active_blocks = 0
    else:
        failed_logins_24h = (
            await session.scalar(
                select(func.count(FailedLoginRecord.id)).where(
                    FailedLoginRecord.timestamp >= cutoff_24h
                )
            )
        ) or 0
        active_blocks = (
            await session.scalar(
                select(func.count(IPBlockRecord.id)).where(IPBlockRecord.is_active == True)  # noqa: E712
            )
        ) or 0

    anomaly_conds = [SecurityAnomalyRecord.resolved == False]  # noqa: E712
    if org_filter:
        anomaly_conds.append(SecurityAnomalyRecord.organization_id == org_filter)
    unresolved_anomalies = (
        await session.scalar(select(func.count(SecurityAnomalyRecord.id)).where(*anomaly_conds))
    ) or 0

    incident_conds = [Incident.status.in_(["open", "investigating", "mitigating"])]
    if org_filter:
        incident_conds.append(Incident.organization_id == org_filter)
    open_incidents = (
        await session.scalar(select(func.count(Incident.id)).where(*incident_conds))
    ) or 0

    # ── Needs attention: critical/unresolved items ──
    needs_attention: list[dict[str, Any]] = []

    # Recent critical security events
    critical_sec = (
        (
            await session.execute(
                select(SecurityEventRecord)
                .where(
                    and_(
                        SecurityEventRecord.timestamp >= cutoff_24h,
                        SecurityEventRecord.event_type.in_(
                            [k for k, v in _SEC_LEVEL.items() if v == "critical"]
                        ),
                        # org-scope for non-super-admin callers
                        *(
                            [SecurityEventRecord.organization_id == org_filter]
                            if org_filter
                            else []
                        ),
                    )
                )
                .order_by(desc(SecurityEventRecord.timestamp))
                .limit(5)
            )
        )
        .scalars()
        .all()
    )
    for s in critical_sec:
        needs_attention.append(
            {
                "type": "security",
                "id": str(s.id),
                "title": f"{(s.event_type or '').replace('_', ' ').title()} — {s.user_email or s.ip_address or 'Unknown'}",
                "severity": "critical",
                "timestamp": s.timestamp.isoformat() if s.timestamp else "",
            }
        )

    # Recent error audit logs
    error_audits = (
        (
            await session.execute(
                select(AuditLogRecord)
                .where(
                    and_(
                        AuditLogRecord.timestamp >= cutoff_24h,
                        or_(
                            AuditLogRecord.status == "error",
                            AuditLogRecord.error_message.isnot(None),
                        ),
                        *(audit_24h_conds[1:]),
                    )
                )
                .order_by(desc(AuditLogRecord.timestamp))
                .limit(5)
            )
        )
        .scalars()
        .all()
    )
    for a in error_audits:
        needs_attention.append(
            {
                "type": "error",
                "id": str(a.id),
                "title": _message_for_audit(a),
                "severity": "error",
                "timestamp": a.timestamp.isoformat() if a.timestamp else "",
            }
        )

    # Unresolved anomalies
    anomaly_rows = (
        (
            await session.execute(
                select(SecurityAnomalyRecord)
                .where(
                    SecurityAnomalyRecord.resolved == False,  # noqa: E712
                    # org-scope for non-super-admin callers
                    *([SecurityAnomalyRecord.organization_id == org_filter] if org_filter else []),
                )
                .order_by(desc(SecurityAnomalyRecord.detected_at))
                .limit(5)
            )
        )
        .scalars()
        .all()
    )
    for an in anomaly_rows:
        needs_attention.append(
            {
                "type": "anomaly",
                "id": str(an.id),
                "title": an.title
                or f"{(an.anomaly_type or '').replace('_', ' ').title()} detected",
                "severity": an.severity or "medium",
                "timestamp": an.detected_at.isoformat() if an.detected_at else "",
            }
        )

    # Open incidents
    # scope the recent-incident rows to the caller's org, mirroring the
    # open_incidents COUNT above (which already uses org_filter). Without this the
    # newest open incidents were selected platform-wide and their id/title/severity
    # leaked across organizations. org_filter is None only for an unscoped
    # super_admin (platform-wide, by design).
    _recent_incident_conds = [Incident.status.in_(["open", "investigating", "mitigating"])]
    if org_filter:
        _recent_incident_conds.append(Incident.organization_id == org_filter)
    incident_rows = (
        (
            await session.execute(
                select(Incident)
                .where(*_recent_incident_conds)
                .order_by(desc(Incident.opened_at))
                .limit(5)
            )
        )
        .scalars()
        .all()
    )
    for inc in incident_rows:
        needs_attention.append(
            {
                "type": "incident",
                "id": str(inc.id),
                "title": inc.title,
                "severity": inc.severity,
                "timestamp": inc.opened_at.isoformat() if inc.opened_at else "",
            }
        )

    # Sort by timestamp desc
    needs_attention.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    needs_attention = needs_attention[:10]

    # ── Daily histogram (7 days) ──
    daily_audit = (
        await session.execute(
            select(
                func.date_trunc("day", AuditLogRecord.timestamp).label("d"),
                func.count(AuditLogRecord.id).label("total"),
                func.count(
                    case(
                        (
                            or_(
                                AuditLogRecord.status == "error",
                                AuditLogRecord.error_message.isnot(None),
                            ),
                            1,
                        )
                    )
                ).label("errors"),
                func.count(case((AuditLogRecord.status == "failure", 1))).label("warnings"),
            )
            .where(and_(AuditLogRecord.timestamp >= cutoff_7d, *(audit_24h_conds[1:])))
            .group_by("d")
            .order_by("d")
        )
    ).all()

    daily_sec = (
        await session.execute(
            select(
                func.date_trunc("day", SecurityEventRecord.timestamp).label("d"),
                func.count(SecurityEventRecord.id).label("total"),
                func.count(case((SecurityEventRecord.success == False, 1))).label("errors"),  # noqa: E712
            )
            .where(
                SecurityEventRecord.timestamp >= cutoff_7d,
                # org-scope the security histogram for org_admin
                *([SecurityEventRecord.organization_id == org_filter] if org_filter else []),
            )
            .group_by("d")
            .order_by("d")
        )
    ).all()

    daily_map: dict[str, dict[str, Any]] = {}
    for d, total, errors, warnings in daily_audit:
        key = d.strftime("%Y-%m-%d") if d else "unknown"
        daily_map.setdefault(key, {"date": key, "total": 0, "errors": 0, "warnings": 0})
        daily_map[key]["total"] += total
        daily_map[key]["errors"] += errors
        daily_map[key]["warnings"] += warnings
    for d, total, errors in daily_sec:
        key = d.strftime("%Y-%m-%d") if d else "unknown"
        daily_map.setdefault(key, {"date": key, "total": 0, "errors": 0, "warnings": 0})
        daily_map[key]["total"] += total
        daily_map[key]["errors"] += errors

    daily_histogram = list(daily_map.values())
    daily_histogram.sort(key=lambda x: x["date"])

    return SystemHealthResponse(
        total_events_24h=total_24h,
        total_events_7d=audit_7d_total + sec_24h_total,  # approx
        error_count_24h=error_24h,
        warning_count_24h=warning_24h,
        critical_count_24h=critical_24h,
        success_rate=success_rate,
        failed_logins_24h=failed_logins_24h,
        active_ip_blocks=active_blocks,
        unresolved_anomalies=unresolved_anomalies,
        open_incidents=open_incidents,
        event_trend=event_trend,
        error_trend=error_trend,
        needs_attention=needs_attention,
        avg_response_ms=round(float(a24.avg_ms), 1) if a24.avg_ms else None,
        p95_response_ms=round(float(a24.p95_ms), 1) if a24.p95_ms else None,
        daily_histogram=daily_histogram,
    )
