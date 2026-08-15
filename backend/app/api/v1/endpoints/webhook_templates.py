# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Webhook Templates API
=====================================

Pre-configured webhook templates for common automation scenarios.
Templates describe event types and typical use cases, making it easy to
set up webhooks without knowing the exact event type strings.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_min_role
from app.db import get_session

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Template definitions
# ─────────────────────────────────────────────────────────────────────────────

WEBHOOK_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "device-status",
        "name": "Device Status Changes",
        "description": "Trigger when any device goes online, offline, or changes status",
        "category": "network",
        "icon": "Server",
        "events": ["device.status.changed", "device.offline", "device.online"],
        "example_payload": {
            "type": "device.offline",
            "payload": {
                "device_id": "uuid-here",
                "name": "switch-core-01",
                "status": "offline",
                "site_id": "site-uuid",
            },
        },
    },
    {
        "id": "new-device",
        "name": "New Device Discovered",
        "description": "Trigger when a new device is found during network discovery",
        "category": "network",
        "icon": "ScanSearch",
        "events": ["device.discovered", "discovery.complete"],
        "example_payload": {
            "type": "device.discovered",
            "payload": {
                "ip_address": "192.168.1.100",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "device_type": "switch",
            },
        },
    },
    {
        "id": "security-events",
        "name": "Security Events",
        "description": "Trigger on security anomalies, failed logins, and IP blocks",
        "category": "security",
        "icon": "ShieldAlert",
        "events": ["security.anomaly", "audit.login_failed", "security.ip_blocked"],
        "example_payload": {
            "type": "security.anomaly",
            "payload": {
                "anomaly_type": "brute_force",
                "source_ip": "1.2.3.4",
                "severity": "high",
            },
        },
    },
    {
        "id": "backup-status",
        "name": "Backup Job Status",
        "description": "Trigger when backups start, complete, or fail",
        "category": "backup",
        "icon": "Archive",
        "events": ["backup.complete", "backup.failed", "backup.started"],
        "example_payload": {
            "type": "backup.complete",
            "payload": {
                "backup_id": "uuid-here",
                "device_name": "switch-core-01",
                "storage_location": "s3-primary",
                "size_bytes": 245760,
            },
        },
    },
    {
        "id": "alert-events",
        "name": "Alert Lifecycle",
        "description": "Trigger when alerts are created, resolved, or escalated",
        "category": "monitoring",
        "icon": "Bell",
        "events": ["alert.created", "alert.resolved", "alert.escalated"],
        "example_payload": {
            "type": "alert.created",
            "payload": {
                "alert_id": "uuid-here",
                "title": "High CPU usage",
                "severity": "warning",
                "device_id": "uuid-here",
            },
        },
    },
    {
        "id": "camera-events",
        "name": "Camera Events",
        "description": "Trigger on camera motion, alerts, or connectivity changes",
        "category": "surveillance",
        "icon": "Camera",
        "events": ["camera.motion", "camera.alert", "camera.offline"],
        "example_payload": {
            "type": "camera.motion",
            "payload": {
                "camera_id": "uuid-here",
                "camera_name": "Entrance Camera",
                "timestamp": "2026-01-01T12:00:00Z",
            },
        },
    },
]

TEMPLATE_MAP = {t["id"]: t for t in WEBHOOK_TEMPLATES}


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────


class WebhookTemplateApply(BaseModel):
    url: str
    name: str | None = None
    secret: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get("")
async def list_templates(
    # Require authentication: the template catalog enumerates the platform's
    # event types + automation surface (reconnaissance) — gate it like every
    # other read, matching the org_admin-gated apply below.
    current_user: Annotated[CurrentUser, Depends(require_min_role("viewer"))],
) -> dict[str, Any]:
    """List all available webhook templates."""
    return {"templates": WEBHOOK_TEMPLATES, "total": len(WEBHOOK_TEMPLATES)}


@router.get("/{template_id}")
async def get_template(
    template_id: str,
    current_user: Annotated[CurrentUser, Depends(require_min_role("viewer"))],
) -> Any:
    """Get a webhook template by ID."""
    template = TEMPLATE_MAP.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return template


@router.post("/{template_id}/apply")
async def apply_template(
    template_id: str,
    body: WebhookTemplateApply,
    # SECURITY: creating a real Webhook is an org-admin-gated write everywhere
    # else (POST /webhooks/ + every other webhook mutation call require_admin).
    # This template path previously gated on only get_current_active_user, so any
    # authenticated user (viewer/operator/site_admin) could register a webhook to
    # a caller-controlled URL and exfiltrate the org's event stream. Require
    # org_admin to match the direct-create boundary.
    current_user: Annotated[CurrentUser, Depends(require_min_role("org_admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """
    Create a webhook pre-filled from a template.

    Creates a real Webhook record using the template's event types.
    """
    template = TEMPLATE_MAP.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    from app.services.webhooks import PersistentWebhookService

    # NOTE: create_webhook's _CREATE_FIELDS allowlist expects "event_types" and
    # "enabled" — the old "events"/"is_active" keys were silently dropped, so the
    # webhook was created with no subscriptions. Use the correct keys.
    webhook_data = {
        "name": body.name or template["name"],
        "url": body.url,
        "event_types": template["events"],
        "secret": body.secret,
        "enabled": True,
        "organization_id": current_user.organization_id,
    }

    try:
        webhook = await PersistentWebhookService.create_webhook(
            session=session,
            data=webhook_data,
            user_id=current_user.id,
        )
    except ValueError as exc:  # e.g. SSRF-rejected URL — match direct-create 422
        logger.info("Webhook template apply rejected: %s", exc)
        raise HTTPException(status_code=422, detail=str(exc))
    await session.commit()

    return {
        "webhook_id": str(webhook.id),
        "name": webhook.name,
        "url": webhook.url,
        "events": webhook.event_types,
        "template_id": template_id,
        "message": f"Webhook created from template '{template['name']}'",
    }
