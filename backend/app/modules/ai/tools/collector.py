# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - AI Tools: Collector
===================================

AI tools for querying collected logs and flow data.
Only active if the collector module is enabled.
"""

from __future__ import annotations

from datetime import UTC
from typing import Any

from app.modules.ai.tools import AITool, register_tool


async def _search_logs(
    user,
    db,
    source_type: str | None = None,
    severity: str | None = None,
    device_id: str | None = None,
    query: str | None = None,
    hours: int = 24,
    limit: int = 20,
    **kwargs,
) -> dict[str, Any]:
    """Search collected syslog and SNMP trap logs."""
    from datetime import datetime, timedelta

    from sqlalchemy import or_, select

    from app.core.site_access import site_scope_filter
    from app.models.core import Site
    from app.models.devices import Device

    try:
        from app.modules.collector.models import CollectorLog
    except ImportError:
        return {"error": "Collector module not available", "logs": []}

    # REQUIRE organization_id to prevent cross-tenant data leakage
    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required", "logs": []}

    q = select(CollectorLog).where(CollectorLog.organization_id == user.organization_id)
    # per-user site grant — the assistant must not be a cross-site
    # oracle. Restrict to logs whose device is in a granted site (org-level
    # logs with no device_id stay visible). No-op for org-admins.
    device_subq = (
        select(Device.id)
        .join(Site, Device.site_id == Site.id)
        .where(
            Site.organization_id == user.organization_id,
            site_scope_filter(user, Device.site_id),
        )
    )
    q = q.where(
        or_(
            CollectorLog.device_id.is_(None),
            CollectorLog.device_id.in_(device_subq),
        )
    )
    if source_type:
        q = q.where(CollectorLog.source_type == source_type)
    if severity:
        q = q.where(CollectorLog.severity == severity)
    if device_id:
        from uuid import UUID

        try:
            q = q.where(CollectorLog.device_id == UUID(device_id))
        except ValueError:
            return {"error": f"Invalid device_id format: {device_id}", "logs": []}
    # Time filter
    since = datetime.now(UTC) - timedelta(hours=min(hours, 720))
    q = q.where(CollectorLog.timestamp >= since)
    # Text search — escape LIKE special characters to prevent pattern injection
    if query:
        escaped = query[:100].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q = q.where(CollectorLog.message.ilike(f"%{escaped}%", escape="\\"))

    q = q.order_by(CollectorLog.timestamp.desc()).limit(max(1, min(limit, 100)))

    result = await db.execute(q)
    logs = result.scalars().all()
    return {
        "logs": [
            {
                "id": str(log.id),
                "source_type": log.source_type,
                "source_ip": log.source_ip,
                "severity": log.severity,
                "hostname": log.hostname,
                "message": (log.message or "")[:500],
                "timestamp": str(log.timestamp),
                "device_id": str(log.device_id) if log.device_id else None,
            }
            for log in logs
        ],
        "total": len(logs),
        "hours_searched": hours,
    }


async def _get_top_talkers(
    user,
    db,
    hours: int = 24,
    limit: int = 10,
    **kwargs,
) -> dict[str, Any]:
    """Get top network talkers by bytes from NetFlow data."""
    from datetime import datetime, timedelta

    from sqlalchemy import func, or_, select

    from app.core.site_access import site_scope_filter
    from app.models.core import Site
    from app.models.devices import Device

    try:
        from app.modules.collector.models import FlowRecord
    except ImportError:
        return {"error": "Collector module not available", "top_talkers": []}

    since = datetime.now(UTC) - timedelta(hours=min(hours, 720))

    # REQUIRE organization_id to prevent cross-tenant data leakage
    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required", "top_talkers": []}

    # per-user site grant — restrict the aggregation to flows from
    # devices in granted sites (org-level flows with no device_id stay
    # visible). No-op for org-admins.
    device_subq = (
        select(Device.id)
        .join(Site, Device.site_id == Site.id)
        .where(
            Site.organization_id == user.organization_id,
            site_scope_filter(user, Device.site_id),
        )
    )

    q = select(
        FlowRecord.source_ip,
        func.sum(FlowRecord.bytes_in + FlowRecord.bytes_out).label("total_bytes"),
        func.sum(FlowRecord.packets).label("total_packets"),
    ).where(
        FlowRecord.bucket_time >= since,
        FlowRecord.organization_id == user.organization_id,
        or_(
            FlowRecord.device_id.is_(None),
            FlowRecord.device_id.in_(device_subq),
        ),
    )
    q = (
        q.group_by(FlowRecord.source_ip)
        .order_by(func.sum(FlowRecord.bytes_in + FlowRecord.bytes_out).desc())
        .limit(min(limit, 50))
    )

    result = await db.execute(q)
    rows = result.all()
    return {
        "top_talkers": [
            {
                "source_ip": row.source_ip,
                "total_bytes": row.total_bytes or 0,
                "total_packets": row.total_packets or 0,
                "total_bytes_human": _human_bytes(row.total_bytes or 0),
            }
            for row in rows
        ],
        "hours_searched": hours,
    }


def _human_bytes(n: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# Register tools
register_tool(
    AITool(
        name="search_collector_logs",
        description="Search collected syslog messages and SNMP traps. Filter by source type, severity, device, or text query within a time range.",
        parameters={
            "type": "object",
            "properties": {
                "source_type": {
                    "type": "string",
                    "description": "Filter by source: syslog or snmp_trap",
                    "enum": ["syslog", "snmp_trap"],
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by syslog severity level",
                },
                "device_id": {
                    "type": "string",
                    "description": "Filter by device ID (UUID)",
                },
                "query": {
                    "type": "string",
                    "description": "Text search in log messages",
                },
                "hours": {
                    "type": "integer",
                    "description": "Search window in hours (default 24)",
                    "default": 24,
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 20)",
                    "default": 20,
                },
            },
        },
        handler=_search_logs,
        permission="collector.logs.read",
    )
)

register_tool(
    AITool(
        name="get_top_talkers",
        description="Get the top network talkers by bandwidth from NetFlow data. Shows source IPs with highest byte counts.",
        parameters={
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "description": "Time window in hours (default 24)",
                    "default": 24,
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of top talkers (default 10)",
                    "default": 10,
                },
            },
        },
        handler=_get_top_talkers,
        permission="collector.flows.read",
    )
)
