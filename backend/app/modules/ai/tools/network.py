# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - AI Network Tools
================================

Tools for querying and managing network state.
Each handler calls existing service/DB layers directly — no HTTP round-trips.
"""

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.site_access import site_scope_filter
from app.modules.ai.tools import AITool, register_tool

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Tool Handlers
# ─────────────────────────────────────────────────────────────────────────────


async def _get_devices(
    user: Any,
    db: AsyncSession,
    status: str | None = None,
    type: str | None = None,
    site_id: str | None = None,
    limit: int = 20,
    **kwargs,
) -> dict[str, Any]:
    from app.models.core import Site
    from app.models.devices import Device

    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required", "devices": []}
    # Device is tenant-scoped via site_id → Site.organization_id (no
    # direct org column). The prior Device.organization_id raised
    # AttributeError, breaking this tool entirely.
    q = (
        select(Device)
        .join(Site, Device.site_id == Site.id)
        .where(
            Device.deleted_at.is_(None),
            Site.organization_id == user.organization_id,
            # per-user site grant — the assistant must not be a
            # cross-site oracle. Site-limited users see only granted-site
            # devices; no-op for org-admins.
            site_scope_filter(user, Device.site_id),
        )
    )
    if status:
        q = q.where(Device.status == status)
    if type:
        q = q.where(Device.device_type == type)
    if site_id:
        try:
            q = q.where(Device.site_id == UUID(site_id))
        except ValueError:
            return {"error": f"Invalid site_id format: {site_id}", "devices": []}
    q = q.limit(min(limit, 50))
    result = await db.execute(q)
    devices = result.scalars().all()
    return {
        "devices": [
            {
                "id": str(d.id),
                "name": d.name,
                "type": d.device_type,
                "status": d.status,
                "ip_address": d.ip_address,
                "mac_address": d.mac_address,
                "model": d.model,
                "firmware_version": d.firmware_version,
                "site_id": str(d.site_id) if d.site_id else None,
            }
            for d in devices
        ],
        "total": len(devices),
    }


async def _get_device_detail(
    user: Any, db: AsyncSession, device_id: str, **kwargs
) -> dict[str, Any]:
    from app.models.core import Site
    from app.models.devices import Device

    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required"}
    try:
        did = UUID(device_id)
    except ValueError:
        return {"error": f"Invalid device_id format: {device_id}"}
    # Tenant-scope via site join (Device has no organization_id column).
    result = await db.execute(
        select(Device)
        .join(Site, Device.site_id == Site.id)
        .where(
            Device.id == did,
            Site.organization_id == user.organization_id,
            # per-user site grant — site-limited users may only read a
            # device in a granted site (returns "not found" otherwise).
            site_scope_filter(user, Device.site_id),
            Device.deleted_at.is_(None),
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        return {"error": f"Device {device_id} not found"}
    return {
        "id": str(device.id),
        "name": device.name,
        "type": device.device_type,
        "status": device.status,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "model": device.model,
        "firmware_version": device.firmware_version,
        "uptime": device.uptime_seconds,
        "site_id": str(device.site_id) if device.site_id else None,
        "controller_id": str(device.controller_id) if device.controller_id else None,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
    }


async def _get_vlans(
    user: Any, db: AsyncSession, site_id: str | None = None, **kwargs
) -> dict[str, Any]:
    from app.modules.network.models import Network

    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required", "vlans": []}
    q = select(Network).where(
        Network.organization_id == user.organization_id,
        # per-user site grant — without this a site-limited user could
        # enumerate every org VLAN by omitting site_id.
        site_scope_filter(user, Network.site_id),
    )
    if site_id:
        try:
            q = q.where(Network.site_id == UUID(site_id))
        except ValueError:
            return {"error": f"Invalid site_id format: {site_id}", "vlans": []}
    result = await db.execute(q)
    networks = result.scalars().all()
    return {
        "vlans": [
            {
                "id": str(n.id),
                "name": n.name,
                "vlan_id": n.vlan_id,
                "subnet": n.subnet,
                "purpose": n.purpose,
                "is_enabled": n.is_enabled,
            }
            for n in networks
        ],
        "total": len(networks),
    }


async def _get_alerts(
    user: Any,
    db: AsyncSession,
    severity: str | None = None,
    limit: int = 10,
    **kwargs,
) -> dict[str, Any]:
    from app.models.alert_rules import Alert

    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required", "alerts": []}
    q = select(Alert).where(
        Alert.resolved_at.is_(None),
        Alert.organization_id == user.organization_id,
        # per-user site grant — site-limited users see org-level alerts
        # (site_id NULL) plus alerts for granted sites only.
        or_(
            Alert.site_id.is_(None),
            site_scope_filter(user, Alert.site_id),
        ),
    )
    if severity:
        q = q.where(Alert.severity == severity)
    q = q.order_by(Alert.created_at.desc()).limit(min(limit, 50))
    result = await db.execute(q)
    alerts = result.scalars().all()
    return {
        "alerts": [
            {
                "id": str(a.id),
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "message": a.message,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "device_id": str(a.device_id) if a.device_id else None,
            }
            for a in alerts
        ],
        "total": len(alerts),
    }


async def _get_sites(user: Any, db: AsyncSession, limit: int = 20, **kwargs) -> dict[str, Any]:
    from app.models.core import Site

    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required", "sites": []}
    q = select(Site).where(
        Site.organization_id == user.organization_id,
        # per-user site grant — the assistant must not enumerate sites
        # the caller has no grant for. site_scope_filter targets Site.id here.
        site_scope_filter(user, Site.id),
    )
    q = q.limit(min(limit, 50))
    result = await db.execute(q)
    sites = result.scalars().all()
    return {
        "sites": [
            {
                "id": str(s.id),
                "name": s.name,
                "address": s.address,
                "timezone": s.timezone,
            }
            for s in sites
        ],
        "total": len(sites),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Register Tools
# ─────────────────────────────────────────────────────────────────────────────

register_tool(
    AITool(
        name="get_devices",
        description="List network devices managed by FreeSDN. Optionally filter by status (online/offline), type (switch/access_point/camera/phone), or site.",
        parameters={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["online", "offline", "warning", "unknown"],
                    "description": "Filter by device status",
                },
                "type": {
                    "type": "string",
                    "description": "Filter by device type (switch, access_point, camera, phone, router)",
                },
                "site_id": {"type": "string", "description": "Filter by site UUID"},
                "limit": {
                    "type": "integer",
                    "default": 20,
                    "description": "Max number of devices to return (max 50)",
                },
            },
        },
        handler=_get_devices,
        permission="device:read",
    )
)

register_tool(
    AITool(
        name="get_device_detail",
        description="Get detailed information about a specific device including model, firmware, uptime, and connectivity.",
        parameters={
            "type": "object",
            "required": ["device_id"],
            "properties": {
                "device_id": {"type": "string", "description": "Device UUID"},
            },
        },
        handler=_get_device_detail,
        permission="device:read",
    )
)

register_tool(
    AITool(
        name="get_vlans",
        description="List VLANs and network segments configured in FreeSDN.",
        parameters={
            "type": "object",
            "properties": {
                "site_id": {"type": "string", "description": "Filter by site UUID"},
            },
        },
        handler=_get_vlans,
        permission="network:read",
    )
)

register_tool(
    AITool(
        name="get_alerts",
        description="List active (unresolved) alerts. Optionally filter by severity level.",
        parameters={
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Filter by severity",
                },
                "limit": {
                    "type": "integer",
                    "default": 10,
                    "description": "Max number of alerts to return",
                },
            },
        },
        handler=_get_alerts,
        permission="device:read",
    )
)

register_tool(
    AITool(
        name="get_sites",
        description="List all sites in the organization.",
        parameters={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20},
            },
        },
        handler=_get_sites,
        permission="site:read",
    )
)
