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


def _example(event: str, data: dict[str, Any]) -> dict[str, Any]:
    """The body a webhook really receives (``webhook_events.build_envelope``)."""
    return {
        "id": "7d0c3c3e-0000-4000-8000-000000000000",
        "event": event,
        "timestamp": "2026-01-01T12:00:00+00:00",
        "organization_id": "org-uuid",
        "category": event.split(".", 1)[0],
        "source": "freesdn",
        "correlation_id": "uuid-here",
        "data": data,
    }


# Every event named here must be one the platform publishes; a template that
# subscribes to a name nothing emits creates a webhook that never fires
# (tests/api/test_webhook_template_events.py). These listed eleven such names --
# device.offline/online, discovery.complete, alert.created/escalated,
# audit.login_failed, security.anomaly/ip_blocked, backup.started/complete/
# failed, camera.motion/offline -- and their example payloads showed a
# {"type", "payload"} body no delivery has ever had.
WEBHOOK_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "device-status",
        "name": "Device Status Changes",
        "description": "Trigger when a device goes offline, comes back online, or changes status",
        "category": "network",
        "icon": "Server",
        "events": ["device.status.changed"],
        "example_payload": _example(
            "device.status.changed",
            {
                "device_id": "uuid-here",
                "site_id": "site-uuid",
                "data": {"name": "switch-core-01", "old_status": "online", "new_status": "offline"},
                "device_type": "switch",
            },
        ),
    },
    {
        "id": "new-device",
        "name": "New Device Discovered",
        "description": "Trigger when a new device is found and when a discovery run finishes",
        "category": "network",
        "icon": "ScanSearch",
        "events": ["device.discovered", "discovery.completed"],
        "example_payload": _example(
            "device.discovered",
            {
                "device_id": "uuid-here",
                "site_id": "site-uuid",
                "data": {"name": "AP-Lobby", "mac": "AA:BB:CC:DD:EE:FF"},
                "device_type": "access_point",
            },
        ),
    },
    {
        "id": "security-events",
        "name": "Security Alerts",
        "description": (
            "Trigger on security alerts raised by the audit service. Failed logins "
            "and IP blocks are recorded in the audit log, not published as events."
        ),
        "category": "security",
        "icon": "ShieldAlert",
        "events": ["security.alert"],
        "example_payload": _example(
            "security.alert",
            {"event_type": "brute_force", "severity": "high", "source_ip": "198.51.100.4"},
        ),
    },
    {
        "id": "backup-status",
        "name": "Backup Validation Failures",
        "description": (
            "Trigger when a backup fails validation. Backup start and completion "
            "are not published as events yet."
        ),
        "category": "backup",
        "icon": "Archive",
        "events": ["backup.validation.failed"],
        "example_payload": _example(
            "backup.validation.failed", {"backup_id": "uuid-here", "reason": "checksum mismatch"}
        ),
    },
    {
        "id": "alert-events",
        "name": "Alert Lifecycle",
        "description": "Trigger when an alert fires and when it resolves",
        "category": "monitoring",
        "icon": "Bell",
        "events": ["alert.fired", "alert.resolved"],
        "example_payload": _example(
            "alert.fired",
            {
                "alert_id": "uuid-here",
                "title": "[CRITICAL] CPU hot",
                "severity": "critical",
                "device_id": "uuid-here",
            },
        ),
    },
    {
        "id": "camera-events",
        "name": "Camera Events",
        "description": "Trigger on camera smart-detection alerts and connectivity changes",
        "category": "surveillance",
        "icon": "Camera",
        "events": ["camera.alert.*", "camera.status.offline", "camera.status.online"],
        "example_payload": _example(
            "camera.alert.motion",
            {
                "camera_id": "uuid-here",
                "camera_name": "Entrance Camera",
                "event_type": "motion",
                "timestamp": "2026-01-01T12:00:00Z",
            },
        ),
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
