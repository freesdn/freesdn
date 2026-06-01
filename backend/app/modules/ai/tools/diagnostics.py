# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - AI Diagnostic Tools
=====================================

Tools for network diagnostics and health checks.
"""

import logging
from datetime import UTC
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.tools import AITool, register_tool

logger = logging.getLogger(__name__)


async def _get_device_health(
    user: Any, db: AsyncSession, device_id: str, **kwargs
) -> dict[str, Any]:
    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required"}
    try:
        did = UUID(device_id)
    except ValueError:
        return {"error": f"Invalid device_id format: {device_id}"}
    # Verify device belongs to user's org before returning health data
    from app.core.site_access import assert_can_access_site
    from app.models.core import Site
    from app.models.devices import Device

    # Device has no organization_id column — tenant-scope through the
    # site join (Site.organization_id), like every other Device query.
    # The prior ``Device.organization_id`` raised AttributeError.
    dev_result = await db.execute(
        select(Device.site_id)
        .join(Site, Device.site_id == Site.id)
        .where(
            Device.id == did,
            Site.organization_id == user.organization_id,
            Device.deleted_at.is_(None),
        )
    )
    dev_row = dev_result.first()
    if dev_row is None:
        return {"error": f"Device {device_id} not found"}
    # Enforce the per-user site grant: org ownership alone let a
    # site-limited caller diagnose a sibling-site device by id. 404 shape
    # (no existence oracle) — return the same "not found" the org miss does.
    device_site_id = dev_row[0]
    try:
        assert_can_access_site(user, device_site_id, detail=f"Device {device_id} not found")
    except HTTPException as exc:
        return {"error": exc.detail}
    from app.models.enterprise import DeviceHealth

    result = await db.execute(select(DeviceHealth).where(DeviceHealth.device_id == did))
    health = result.scalar_one_or_none()
    if not health:
        return {"error": f"No health data for device {device_id}"}
    return {
        "device_id": device_id,
        "status": health.status,
        "cpu_percent": health.cpu_percent,
        "memory_percent": health.memory_percent,
        "uptime_seconds": health.uptime_seconds,
        "temperature_celsius": health.temperature_celsius,
        "last_check": health.last_check.isoformat() if health.last_check else None,
    }


async def _get_bandwidth_usage(
    user: Any,
    db: AsyncSession,
    device_id: str,
    hours: int = 1,
    **kwargs,
) -> dict[str, Any]:
    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required"}
    try:
        did = UUID(device_id)
    except ValueError:
        return {"error": f"Invalid device_id format: {device_id}"}
    # Bound hours to prevent excessive queries
    hours = max(1, min(hours, 24))
    # Verify device belongs to user's org
    from app.core.site_access import assert_can_access_site
    from app.models.core import Site
    from app.models.devices import Device

    # Device has no organization_id column — tenant-scope through the
    # site join (Site.organization_id), like every other Device query.
    # The prior ``Device.organization_id`` raised AttributeError.
    dev_result = await db.execute(
        select(Device.site_id)
        .join(Site, Device.site_id == Site.id)
        .where(
            Device.id == did,
            Site.organization_id == user.organization_id,
            Device.deleted_at.is_(None),
        )
    )
    dev_row = dev_result.first()
    if dev_row is None:
        return {"error": f"Device {device_id} not found"}
    # Enforce the per-user site grant: org ownership alone let a
    # site-limited caller pull bandwidth for a sibling-site device by id.
    device_site_id = dev_row[0]
    try:
        assert_can_access_site(user, device_site_id, detail=f"Device {device_id} not found")
    except HTTPException as exc:
        return {"error": exc.detail}
    from datetime import datetime, timedelta

    from app.models.analytics import MetricDataPoint

    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    result = await db.execute(
        select(MetricDataPoint)
        .where(
            MetricDataPoint.device_id == did,
            MetricDataPoint.metric_name.in_(["bytes_rx", "bytes_tx"]),
            MetricDataPoint.timestamp >= cutoff,
        )
        .order_by(MetricDataPoint.timestamp.desc())
        .limit(100)
    )
    points = result.scalars().all()

    bytes_rx = [p.value for p in points if p.metric_name == "bytes_rx"]
    bytes_tx = [p.value for p in points if p.metric_name == "bytes_tx"]

    return {
        "device_id": device_id,
        "period_hours": hours,
        "avg_rx_bps": sum(bytes_rx) / len(bytes_rx) if bytes_rx else 0,
        "avg_tx_bps": sum(bytes_tx) / len(bytes_tx) if bytes_tx else 0,
        "samples": len(bytes_rx),
    }


register_tool(
    AITool(
        name="get_device_health",
        description="Get health metrics for a device including CPU usage, memory usage, temperature, and uptime.",
        parameters={
            "type": "object",
            "required": ["device_id"],
            "properties": {
                "device_id": {"type": "string", "description": "Device UUID"},
            },
        },
        handler=_get_device_health,
        permission="device:read",
    )
)

register_tool(
    AITool(
        name="get_bandwidth_usage",
        description="Get bandwidth usage statistics for a device over the past N hours.",
        parameters={
            "type": "object",
            "required": ["device_id"],
            "properties": {
                "device_id": {"type": "string", "description": "Device UUID"},
                "hours": {
                    "type": "integer",
                    "default": 1,
                    "description": "Look-back period in hours (max 24)",
                },
            },
        },
        handler=_get_bandwidth_usage,
        permission="device:read",
    )
)
