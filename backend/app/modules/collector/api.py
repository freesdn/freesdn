# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Collector Module API
=====================================

REST endpoints for log search, NetFlow queries, top-talker reports,
collector configuration, and service status.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    CurrentUser,
    get_current_active_user,
    is_unscoped_superuser,
)
from app.core.security_utils import escape_like
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.db import get_session
from app.models.core import Site
from app.models.devices import Device
from app.modules.collector.models import CollectorConfig, CollectorLog, FlowRecord

logger = logging.getLogger(__name__)
router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────


class CollectorConfigSchema(BaseModel):
    snmp_enabled: bool = False
    snmp_port: int = 162
    snmp_community: str = "public"
    syslog_enabled: bool = False
    syslog_port: int = 514
    netflow_enabled: bool = False
    netflow_port: int = 2055
    log_retention_days: int = 30
    flow_retention_days: int = 7
    # NOTE(C3): CIDRs from which collector packets are accepted.
    # Empty list = block all (secure default).
    allowed_source_ips: list[str] = []

    class Config:
        from_attributes = True


class CollectorConfigUpdate(BaseModel):
    snmp_enabled: bool | None = None
    snmp_port: int | None = None
    snmp_community: str | None = None
    syslog_enabled: bool | None = None
    syslog_port: int | None = None
    netflow_enabled: bool | None = None
    netflow_port: int | None = None
    log_retention_days: int | None = None
    flow_retention_days: int | None = None
    allowed_source_ips: list[str] | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _require_permission(user: CurrentUser, perm: str) -> None:
    # gate on the permission ONLY — has_permission already grants an
    # UNSCOPED org_admin/admin (which hold collector.* in the role catalog) and
    # super_admin (via the is_superuser shortcut), while honoring the API-key
    # scope ceiling for a SCOPED key. The previous raw ``is_org_admin or
    # is_superuser`` fallback bypassed that ceiling (a scoped admin key without a
    # collector scope still read logs/flows + mutated collector config).
    if not user.has_permission(perm):
        raise HTTPException(status_code=403, detail=f"Requires {perm} permission")


def _parse_time(value: str | None, default: datetime) -> datetime:
    """Parse ISO-8601 datetime string, return default on failure."""
    if not value:
        return default
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return default


# ── Mutable field whitelist (prevent mass-assignment attacks) ───────────────
_CONFIG_MUTABLE_FIELDS = frozenset(
    {
        "snmp_enabled",
        "snmp_port",
        "snmp_community",
        "syslog_enabled",
        "syslog_port",
        "netflow_enabled",
        "netflow_port",
        "log_retention_days",
        "flow_retention_days",
        "allowed_source_ips",
    }
)


def _org_id(user: CurrentUser) -> UUID:
    """Extract organization_id, raising 400 if missing."""
    oid: UUID | None = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(status_code=400, detail="Organization context required")
    return oid


def _accessible_device_subquery(current_user: CurrentUser) -> Any:
    """Subquery of device IDs the caller may see, scoped to per-user site grants.

    (sibling-site read)``/logs`` and ``/flows`` only
    filtered by ``organization_id``, so a SITE-LIMITED caller could read logs and
    flow records produced by devices in sibling sites of the same org. This
    returns ``Device.id`` for devices whose site the caller may access — a no-op
    (all org devices) for super_admin / org_admin / grant-less users via
    ``site_scope_filter``, and only granted-site devices for site-limited users.

    Callers AND ``<Model>.device_id.in_(subq)`` (paired with an
    ``<Model>.device_id.is_(None)`` allowance for org-level rows with no device)
    into their WHERE clause.
    """
    return (
        select(Device.id)
        .join(Site, Device.site_id == Site.id)
        .where(
            Site.organization_id == _org_id(current_user),
            site_scope_filter(current_user, Device.site_id),
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# Log endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/logs")
async def search_logs(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    source_type: str | None = Query(None, description="snmp_trap | syslog"),
    severity: str | None = Query(
        None, description="emergency|alert|critical|error|warning|notice|info|debug"
    ),
    device_id: UUID | None = Query(None),
    start_time: str | None = Query(None, description="ISO-8601 start time"),
    end_time: str | None = Query(None, description="ISO-8601 end time"),
    q: str | None = Query(None, description="Full-text search in message"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    """Search and filter collected log entries."""
    _require_permission(current_user, "collector.logs.read")

    now = datetime.now(UTC)
    t_start = _parse_time(start_time, now - timedelta(hours=1))
    t_end = _parse_time(end_time, now)

    conditions = [
        CollectorLog.organization_id == _org_id(current_user),
        CollectorLog.timestamp >= t_start,
        CollectorLog.timestamp <= t_end,
    ]
    if source_type:
        conditions.append(CollectorLog.source_type == source_type)
    if severity:
        conditions.append(CollectorLog.severity == severity)
    if device_id:
        conditions.append(CollectorLog.device_id == device_id)
    if q:
        conditions.append(CollectorLog.message.ilike(f"%{escape_like(q)}%", escape="\\"))

    # per-user site grant — site-limited callers only see logs from
    # devices in granted sites. Org-level logs (no device_id) remain visible.
    conditions.append(
        or_(
            CollectorLog.device_id.is_(None),
            CollectorLog.device_id.in_(_accessible_device_subquery(current_user)),
        )
    )

    base_q = select(CollectorLog).where(and_(*conditions))

    total_result = await session.execute(select(func.count()).select_from(base_q.subquery()))
    total = total_result.scalar() or 0

    result = await session.execute(
        base_q.order_by(CollectorLog.timestamp.desc()).offset((page - 1) * size).limit(size)
    )
    logs = result.scalars().all()

    def _serialize(log: CollectorLog) -> dict[str, Any]:
        return {
            "id": str(log.id),
            "source_type": log.source_type,
            "source_ip": log.source_ip,
            "device_id": str(log.device_id) if log.device_id else None,
            "severity": log.severity,
            "facility": log.facility,
            "hostname": log.hostname,
            "app_name": log.app_name,
            "message": log.message,
            "enterprise_oid": log.enterprise_oid,
            "trap_type": log.trap_type,
            "varbinds": log.varbinds,
            "timestamp": log.timestamp.isoformat(),
        }

    return {
        "logs": [_serialize(l) for l in logs],
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
    }


# NOTE(M1): ``/logs/stats`` MUST be declared BEFORE the
# ``/logs/{log_id}`` catch-all — FastAPI matches routes in declaration
# order, and ``stats`` would otherwise be eaten by the UUID path
# converter on ``log_id`` and return 422.
@router.get("/logs/stats")
async def log_stats(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(24, ge=1, le=168, description="Look-back window in hours"),
) -> dict[str, Any]:
    """Aggregate statistics: counts by severity, source type, and hour."""
    _require_permission(current_user, "collector.logs.read")

    org_id = _org_id(current_user)
    since = datetime.now(UTC) - timedelta(hours=hours)
    # scope log aggregates to the caller's accessible devices so a
    # site-limited user can't get org-wide stats spanning sibling sites. Org-level
    # logs (no device_id) stay visible. No-op for super_admin / org_admin.
    _log_site_pred = or_(
        CollectorLog.device_id.is_(None),
        CollectorLog.device_id.in_(_accessible_device_subquery(current_user)),
    )

    # Count by severity
    sev_result = await session.execute(
        select(CollectorLog.severity, func.count(CollectorLog.id).label("count"))
        .where(
            CollectorLog.organization_id == org_id, CollectorLog.timestamp >= since, _log_site_pred
        )
        .group_by(CollectorLog.severity)
        .order_by(func.count(CollectorLog.id).desc())
    )
    by_severity = [{"severity": r[0] or "unknown", "count": r[1]} for r in sev_result.all()]

    # Count by source type
    src_result = await session.execute(
        select(CollectorLog.source_type, func.count(CollectorLog.id).label("count"))
        .where(
            CollectorLog.organization_id == org_id, CollectorLog.timestamp >= since, _log_site_pred
        )
        .group_by(CollectorLog.source_type)
    )
    by_source = [{"source_type": r[0], "count": r[1]} for r in src_result.all()]

    # Count by source IP (top 10)
    ip_result = await session.execute(
        select(CollectorLog.source_ip, func.count(CollectorLog.id).label("count"))
        .where(
            CollectorLog.organization_id == org_id, CollectorLog.timestamp >= since, _log_site_pred
        )
        .group_by(CollectorLog.source_ip)
        .order_by(func.count(CollectorLog.id).desc())
        .limit(10)
    )
    top_sources = [{"source_ip": r[0], "count": r[1]} for r in ip_result.all()]

    # Total
    total_result = await session.execute(
        select(func.count(CollectorLog.id)).where(
            CollectorLog.organization_id == org_id, CollectorLog.timestamp >= since, _log_site_pred
        )
    )
    total = total_result.scalar() or 0

    return {
        "total": total,
        "hours": hours,
        "by_severity": by_severity,
        "by_source_type": by_source,
        "top_sources": top_sources,
    }


@router.get("/logs/{log_id}")
async def get_log_detail(
    log_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Get full detail of a single log entry, including raw_data."""
    _require_permission(current_user, "collector.logs.read")

    result = await session.execute(
        select(CollectorLog).where(
            CollectorLog.id == log_id,
            CollectorLog.organization_id == _org_id(current_user),
        )
    )
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Log entry not found")

    # per-user site grant — a site-limited caller may only read a log
    # whose device belongs to a granted site. Resolve the device's site and
    # enforce the grant (404 to avoid an existence oracle). Org-level logs
    # (no device_id) are unaffected.
    if log.device_id is not None:
        device_site_result = await session.execute(
            select(Device.site_id)
            .join(Site, Device.site_id == Site.id)
            .where(
                Device.id == log.device_id,
                Site.organization_id == _org_id(current_user),
            )
        )
        device_site_id = device_site_result.scalar_one_or_none()
        if device_site_id is not None:
            assert_can_access_site(current_user, device_site_id, detail="Log entry not found")

    return {
        "id": str(log.id),
        "source_type": log.source_type,
        "source_ip": log.source_ip,
        "device_id": str(log.device_id) if log.device_id else None,
        "organization_id": str(log.organization_id) if log.organization_id else None,
        "severity": log.severity,
        "facility": log.facility,
        "hostname": log.hostname,
        "app_name": log.app_name,
        "message": log.message,
        "enterprise_oid": log.enterprise_oid,
        "trap_type": log.trap_type,
        "varbinds": log.varbinds,
        "timestamp": log.timestamp.isoformat(),
        "raw_data": log.raw_data,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Flow endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/flows")
async def search_flows(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    device_id: UUID | None = Query(None),
    source_ip: str | None = Query(None),
    dest_ip: str | None = Query(None),
    protocol: int | None = Query(None, description="IP protocol number, e.g. 6=TCP 17=UDP"),
    start_time: str | None = Query(None),
    end_time: str | None = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    """Search and filter NetFlow records."""
    _require_permission(current_user, "collector.flows.read")

    now = datetime.now(UTC)
    t_start = _parse_time(start_time, now - timedelta(hours=1))
    t_end = _parse_time(end_time, now)

    conditions = [
        FlowRecord.organization_id == _org_id(current_user),
        FlowRecord.bucket_time >= t_start,
        FlowRecord.bucket_time <= t_end,
    ]
    if device_id:
        conditions.append(FlowRecord.device_id == device_id)
    if source_ip:
        conditions.append(FlowRecord.source_ip == source_ip)
    if dest_ip:
        conditions.append(FlowRecord.dest_ip == dest_ip)
    if protocol is not None:
        conditions.append(FlowRecord.protocol == protocol)

    # per-user site grant — site-limited callers only see flow records
    # from devices in granted sites. Org-level records (no device_id) remain
    # visible.
    conditions.append(
        or_(
            FlowRecord.device_id.is_(None),
            FlowRecord.device_id.in_(_accessible_device_subquery(current_user)),
        )
    )

    base_q = select(FlowRecord).where(and_(*conditions))

    total_result = await session.execute(select(func.count()).select_from(base_q.subquery()))
    total = total_result.scalar() or 0

    result = await session.execute(
        base_q.order_by(FlowRecord.bucket_time.desc()).offset((page - 1) * size).limit(size)
    )
    flows = result.scalars().all()

    def _serialize_flow(f: FlowRecord) -> dict[str, Any]:
        return {
            "id": str(f.id),
            "device_id": str(f.device_id) if f.device_id else None,
            "source_ip": f.source_ip,
            "dest_ip": f.dest_ip,
            "source_port": f.source_port,
            "dest_port": f.dest_port,
            "protocol": f.protocol,
            "bytes_in": f.bytes_in,
            "bytes_out": f.bytes_out,
            "packets": f.packets,
            "bucket_time": f.bucket_time.isoformat(),
        }

    return {
        "flows": [_serialize_flow(f) for f in flows],
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
    }


@router.get("/flows/top-talkers")
async def top_talkers(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(1, ge=1, le=168),
    limit: int = Query(10, ge=1, le=50),
    sort_by: str = Query("bytes", enum=["bytes", "packets"]),
    site_id: UUID | None = Query(
        None, description="Restrict to flows whose device is at this site"
    ),
) -> dict[str, Any]:
    """Top N source IPs by bytes or packets within a time window.

    NOTE(H5): Optional ``site_id`` narrows the aggregation to devices
    belonging to a single site — without this, group_by ran across the
    whole org which made the result useless in multi-site deployments.
    """
    _require_permission(current_user, "collector.flows.read")

    since = datetime.now(UTC) - timedelta(hours=hours)

    sort_col = (
        func.sum(FlowRecord.bytes_in + FlowRecord.bytes_out)
        if sort_by == "bytes"
        else func.sum(FlowRecord.packets)
    )

    conditions = [
        FlowRecord.organization_id == _org_id(current_user),
        FlowRecord.bucket_time >= since,
    ]
    if site_id is not None:
        # TI-16: the org filter alone lets a SITE-LIMITED caller read a sibling
        # site's flow aggregation (sibling-site read). Enforce the
        # per-user grant: admins / grant-less users pass; a site-limited user may
        # only request a site they hold a grant for.
        if not current_user.can_access_site(site_id):
            # 404 (not 403) matches the canonical assert_can_access_site
            # convention and avoids a site-existence oracle.
            raise HTTPException(status_code=404, detail="Site not found")
        # Subquery: devices at the requested site for this org. The
        # org filter above + the org scope on FlowRecord protect
        # against cross-tenant leakage if site_id were spoofed.
        from app.models.core import Site
        from app.models.devices import Device

        device_subq = (
            select(Device.id)
            .join(Site, Device.site_id == Site.id)
            .where(
                Site.id == site_id,
                Site.organization_id == _org_id(current_user),
            )
        )
        conditions.append(FlowRecord.device_id.in_(device_subq))
    else:
        # with NO site_id the org filter alone let a SITE-LIMITED caller
        # obtain org-wide top-talker aggregates (sibling-site leak by omission).
        # Constrain to flows from devices in granted sites; org-level rows with
        # no device (device_id IS NULL) remain visible. No-op (all org devices)
        # for super_admin / org_admin / grant-less users via site_scope_filter.
        conditions.append(
            or_(
                FlowRecord.device_id.is_(None),
                FlowRecord.device_id.in_(_accessible_device_subquery(current_user)),
            )
        )

    result = await session.execute(
        select(
            FlowRecord.source_ip,
            func.sum(FlowRecord.bytes_in).label("bytes_in"),
            func.sum(FlowRecord.bytes_out).label("bytes_out"),
            func.sum(FlowRecord.packets).label("packets"),
            func.count(FlowRecord.id).label("flow_count"),
        )
        .where(and_(*conditions))
        .group_by(FlowRecord.source_ip)
        .order_by(sort_col.desc())
        .limit(limit)
    )

    talkers = [
        {
            "source_ip": r[0],
            "bytes_in": r[1] or 0,
            "bytes_out": r[2] or 0,
            "total_bytes": (r[1] or 0) + (r[2] or 0),
            "packets": r[3] or 0,
            "flow_count": r[4],
        }
        for r in result.all()
    ]
    return {"top_talkers": talkers, "hours": hours, "site_id": str(site_id) if site_id else None}


@router.get("/flows/protocol-breakdown")
async def protocol_breakdown(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(1, ge=1, le=168),
) -> dict[str, Any]:
    """Traffic breakdown by IP protocol number."""
    _require_permission(current_user, "collector.flows.read")

    since = datetime.now(UTC) - timedelta(hours=hours)

    # protocol breakdown was org/time only, so a SITE-LIMITED caller got
    # org-wide aggregates spanning sibling sites. Constrain to
    # flows from devices in granted sites; org-level rows with no device
    # (device_id IS NULL) remain visible. No-op for super_admin / org_admin /
    # grant-less users via site_scope_filter inside _accessible_device_subquery.
    result = await session.execute(
        select(
            FlowRecord.protocol,
            func.sum(FlowRecord.bytes_in + FlowRecord.bytes_out).label("total_bytes"),
            func.sum(FlowRecord.packets).label("total_packets"),
            func.count(FlowRecord.id).label("flow_count"),
        )
        .where(
            FlowRecord.organization_id == _org_id(current_user),
            FlowRecord.bucket_time >= since,
            or_(
                FlowRecord.device_id.is_(None),
                FlowRecord.device_id.in_(_accessible_device_subquery(current_user)),
            ),
        )
        .group_by(FlowRecord.protocol)
        .order_by(func.sum(FlowRecord.bytes_in + FlowRecord.bytes_out).desc())
    )

    _PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 47: "GRE", 50: "ESP", 89: "OSPF"}

    breakdown = [
        {
            "protocol": r[0],
            "protocol_name": _PROTO_NAMES.get(r[0], str(r[0])),
            "total_bytes": r[1] or 0,
            "total_packets": r[2] or 0,
            "flow_count": r[3],
        }
        for r in result.all()
    ]
    return {"breakdown": breakdown, "hours": hours}


# ─────────────────────────────────────────────────────────────────────────────
# Configuration endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/config")
async def get_config(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Get collector configuration for the current user's organization."""
    _require_permission(current_user, "collector.config")

    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="No organization context")

    result = await session.execute(
        select(CollectorConfig).where(
            CollectorConfig.organization_id == current_user.organization_id
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        # Return defaults
        return CollectorConfigSchema().model_dump()

    return CollectorConfigSchema.model_validate(config).model_dump()


@router.put("/config")
async def update_config(
    body: CollectorConfigUpdate,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Update collector configuration and reload active services."""
    _require_permission(current_user, "collector.config")

    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="No organization context")

    result = await session.execute(
        select(CollectorConfig).where(
            CollectorConfig.organization_id == current_user.organization_id
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        config = CollectorConfig(organization_id=current_user.organization_id)
        session.add(config)

    # Apply only provided fields (whitelist prevents mass-assignment)
    for field, value in body.model_dump(exclude_none=True).items():
        if field in _CONFIG_MUTABLE_FIELDS:
            setattr(config, field, value)

    await session.commit()
    await session.refresh(config)

    # reload_config() stop()s + start()s the PROCESS-WIDE collector
    # receivers (a single shared SNMP/syslog/NetFlow listener serving ALL tenants in
    # this process) with THIS caller's org config — so a tenant admin triggering it
    # would disable / replace other tenants' collectors (cross-tenant DoS). The
    # per-org config row is saved above regardless; the process-wide listener reload
    # is restricted to a platform super_admin. (A fully tenant-aware collector
    # runtime — per-org dispatch on shared listeners — is tracked as follow-up.)
    if is_unscoped_superuser(current_user):
        try:
            # NOTE(C1): use the lazy accessor so the manager is built with
            # the real AsyncSessionLocal session_factory.
            from app.modules.collector.services.manager import get_collector_manager

            await get_collector_manager().reload_config(config)
        except Exception as exc:
            logger.warning("Failed to reload collector services: %s", exc)
    else:
        logger.info(
            "Collector config saved for org %s; process-wide listener reload "
            "deferred (requires platform super_admin)",
            current_user.organization_id,
        )

    return {
        "message": "Configuration updated",
        "config": CollectorConfigSchema.model_validate(config).model_dump(),
    }


@router.get("/status")
async def collector_status(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return running status of each collector service."""
    _require_permission(current_user, "collector.config")

    from app.modules.collector.services.manager import get_collector_manager

    return {"services": get_collector_manager().status()}
