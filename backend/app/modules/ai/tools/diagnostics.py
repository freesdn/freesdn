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

    # CPU, memory, temperature and uptime are columns of Device (the sync
    # writes them there). This read status/cpu_percent/memory_percent/
    # uptime_seconds/temperature_celsius/last_check off DeviceHealth, which
    # has none of them, so the tool raised AttributeError for any device with
    # a health row and answered "No health data" for every other one.
    result = await db.execute(
        select(Device, DeviceHealth)
        .outerjoin(DeviceHealth, DeviceHealth.device_id == Device.id)
        .where(Device.id == did)
    )
    row = result.first()
    if row is None:
        return {"error": f"No health data for device {device_id}"}
    device, health = row
    return {
        "device_id": device_id,
        "status": str(device.status) if device.status is not None else None,
        "cpu_percent": device.cpu_usage_percent,
        "memory_percent": device.memory_usage_percent,
        "uptime_seconds": device.uptime_seconds,
        "temperature_celsius": device.temperature_celsius,
        "last_check": device.last_seen.isoformat() if device.last_seen else None,
        "health_score": health.health_score if health else None,
        "health_status": str(health.health_status) if health else None,
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

    from app.db.session import get_logdb_factory
    from app.models.analytics import MetricDataPoint
    from app.services.analytics import DEVICE_RX_BYTES, DEVICE_TX_BYTES

    # Three defects made this tool unable to answer: it read names nothing
    # writes ("bytes_rx"/"bytes_tx"), filtered on a column the model does not
    # have (MetricDataPoint.timestamp; it is ``time``), and queried the primary
    # database, while metric_data lives in the LogDB. It now reads the same
    # registry names as the device traffic endpoint, from the LogDB.
    try:
        factory = get_logdb_factory()
    except RuntimeError:
        return {"device_id": device_id, "error": "Time-series database is not configured"}
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    try:
        async with factory() as logdb:
            result = await logdb.execute(
                select(MetricDataPoint.metric_name, MetricDataPoint.value)
                .where(
                    MetricDataPoint.device_id == did,
                    MetricDataPoint.metric_name.in_([DEVICE_RX_BYTES, DEVICE_TX_BYTES]),
                    MetricDataPoint.time >= cutoff,
                )
                .order_by(MetricDataPoint.time.desc())
                .limit(100)
            )
            points = result.all()
    except Exception:  # noqa: BLE001 - an AI tool answers; it does not raise
        logger.warning("Bandwidth read failed for device %s", device_id, exc_info=True)
        return {"device_id": device_id, "error": "Traffic metrics could not be read"}

    bytes_rx = [value for name, value in points if name == DEVICE_RX_BYTES]
    bytes_tx = [value for name, value in points if name == DEVICE_TX_BYTES]

    answer: dict[str, Any] = {
        "device_id": device_id,
        "period_hours": hours,
        "avg_rx_bps": sum(bytes_rx) / len(bytes_rx) if bytes_rx else None,
        "avg_tx_bps": sum(bytes_tx) / len(bytes_tx) if bytes_tx else None,
        "samples": len(bytes_rx),
    }
    if not points:
        # Say so, rather than an average of 0 that reads as an idle link.
        answer["note"] = (
            "No traffic samples are recorded for this device. FreeSDN does not "
            "collect per-device traffic counters yet."
        )
    return answer


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
