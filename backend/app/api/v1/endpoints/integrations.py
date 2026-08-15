# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Integrations API Endpoints
==========================================

Guided, typed integration connections (n8n, Slack, PagerDuty, etc.)
backed by the Webhook delivery engine.

Design:
- Every Integration owns one Webhook record (created/deleted together).
- The Integrations UI is distinct from the raw Webhooks admin page.
- SSRF protection is inherited from PersistentWebhookService.create_webhook().
- Delivery log, DLQ list, and DLQ replay use the existing Webhook endpoints
  (the webhook_id is included in every Integration response).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user, get_session
from app.models import UserRole

logger = logging.getLogger(__name__)

router = APIRouter()


# ============================================================================
# Supported integration types + template presets
# ============================================================================

INTEGRATION_TYPES = {
    "n8n": {
        "label": "n8n",
        "description": "Send FreeSDN events to an n8n workflow via webhook trigger.",
        "default_events": ["device.status.changed", "device.offline", "alert.created"],
        "setup_docs_url": "https://docs.freesdn.org/integrations/n8n",
        "icon": "Workflow",
    },
    "slack": {
        "label": "Slack",
        "description": "Post FreeSDN notifications to a Slack channel.",
        "default_events": ["alert.created", "alert.escalated", "device.offline"],
        "icon": "MessageSquare",
    },
    "teams": {
        "label": "Microsoft Teams",
        "description": "Send FreeSDN alerts to a Teams channel.",
        "default_events": ["alert.created", "alert.escalated"],
        "icon": "MessageSquare",
    },
    "pagerduty": {
        "label": "PagerDuty",
        "description": "Create and resolve PagerDuty incidents from FreeSDN alerts.",
        "default_events": ["alert.created", "alert.resolved"],
        "icon": "Bell",
    },
    "jira": {
        "label": "Jira",
        "description": "Open Jira issues for FreeSDN alerts and device events.",
        "default_events": ["alert.created"],
        "icon": "TicketCheck",
    },
    "servicenow": {
        "label": "ServiceNow",
        "description": "Create ServiceNow incidents from FreeSDN critical alerts.",
        "default_events": ["alert.created"],
        "icon": "TicketCheck",
    },
    "webhook": {
        "label": "Generic Webhook",
        "description": "Send FreeSDN events to any HTTPS endpoint.",
        "default_events": [],
        "icon": "Webhook",
    },
}

EVENT_CATEGORIES = {
    "Device Events": [
        "device.status.changed",
        "device.offline",
        "device.online",
        "device.discovered",
        "device.config.changed",
    ],
    "Alert Events": [
        "alert.created",
        "alert.resolved",
        "alert.escalated",
        "alert.acknowledged",
    ],
    "Backup Events": [
        "backup.started",
        "backup.complete",
        "backup.failed",
    ],
    "Controller Events": [
        "controller.connected",
        "controller.disconnected",
        "controller.sync.complete",
        "controller.sync.failed",
    ],
    "Security Events": [
        "security.anomaly",
        "audit.login_failed",
        "security.ip_blocked",
    ],
    "Discovery Events": [
        "discovery.started",
        "discovery.complete",
    ],
}


# ============================================================================
# Request/Response schemas
# ============================================================================

_INTEGRATION_CONFIG_MAX_BYTES = 64 * 1024


def _validate_integration_config_size(v: dict[str, Any] | None) -> dict[str, Any] | None:
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > _INTEGRATION_CONFIG_MAX_BYTES:
        raise ValueError(f"config exceeds {_INTEGRATION_CONFIG_MAX_BYTES} bytes (got {size})")
    return v


def _validate_integration_url(v: str | None) -> str | None:
    """Reject control chars, cap length, require https://."""
    if v is None:
        return v
    if len(v) > 2048:
        raise ValueError(f"url exceeds 2048 chars (got {len(v)})")
    for ch in v:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError("url must not contain control characters")
    if not v.lower().startswith("https://"):
        raise ValueError("Integration URL must use HTTPS (https://...)")
    return v


class IntegrationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    integration_type: str = Field(..., description="One of: " + ", ".join(INTEGRATION_TYPES))
    url: str = Field(
        ..., min_length=1, max_length=2048, description="HTTPS endpoint to deliver events to"
    )
    secret: str | None = Field(None, max_length=512, description="HMAC signing secret (optional)")
    # 200 event-type patterns is generous; matches the Webhook cap so
    # the underlying webhook record isn't rejected after the Integration
    # row is built.
    event_subscriptions: list[str] = Field(
        default_factory=list,
        max_length=200,
        description="Event type patterns to subscribe to. Empty list = use type defaults.",
    )
    config: dict[str, Any] = Field(default_factory=dict, description="Type-specific config")
    verify_ssl: bool = True

    @model_validator(mode="after")
    def validate_type_and_url(self) -> IntegrationCreate:
        if self.integration_type not in INTEGRATION_TYPES:
            raise ValueError(
                f"Unknown integration type '{self.integration_type}'. "
                f"Valid types: {', '.join(INTEGRATION_TYPES)}"
            )
        # H-3 + control-char + length checks consolidated into the
        # shared validator so PATCH gets the same gates as POST.
        _validate_integration_url(self.url)
        # If no events specified, use the type default
        if not self.event_subscriptions:
            self.event_subscriptions = INTEGRATION_TYPES[self.integration_type]["default_events"]
        return self

    @field_validator("config")
    @classmethod
    def _config_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_integration_config_size(v) or v


class IntegrationUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    # PATCH used to accept any URL because only ``IntegrationCreate``
    # ran the HTTPS-only validator — an HTTPS integration could be
    # silently downgraded to HTTP, defeating the original gate.
    url: str | None = Field(None, min_length=1, max_length=2048)
    secret: str | None = Field(None, max_length=512)
    event_subscriptions: list[str] | None = Field(None, max_length=200)
    config: dict[str, Any] | None = None
    verify_ssl: bool | None = None

    @field_validator("url")
    @classmethod
    def _url_shape(cls, v: str | None) -> str | None:
        return _validate_integration_url(v)

    @field_validator("config")
    @classmethod
    def _config_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_integration_config_size(v)


class IntegrationResponse(BaseModel):
    id: str
    name: str
    description: str | None
    integration_type: str
    webhook_id: str
    is_enabled: bool
    event_subscriptions: list[str]
    config: dict[str, Any]
    last_delivery_at: str | None
    last_delivery_status: str | None
    delivery_count_7d: int
    success_count_7d: int
    created_at: str
    updated_at: str | None

    model_config = {"from_attributes": True}


_ALL_KNOWN_EVENTS: frozenset[str] = frozenset(
    e for evts in EVENT_CATEGORIES.values() for e in evts
) | {"integration.test", "webhook.test"}


class TestIntegrationRequest(BaseModel):
    """Optional payload override for test event."""

    # H-1: restrict to known event types to prevent arbitrary string injection
    event_type: str = Field(
        "integration.test",
        description="Event type to simulate. Must be a known FreeSDN event type.",
    )
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            "message": "This is a test event from FreeSDN",
            "test": True,
        }
    )

    @model_validator(mode="after")
    def validate_event_type(self) -> TestIntegrationRequest:
        if self.event_type not in _ALL_KNOWN_EVENTS:
            raise ValueError(
                f"Unknown event type '{self.event_type}'. "
                "Must be a known FreeSDN event type (see /integrations/event-categories)."
            )
        return self


class ApplyTemplateRequest(BaseModel):
    """H-2: typed request body for template application."""

    url: str = Field(..., description="HTTPS endpoint to deliver events to")
    name: str | None = Field(None, max_length=200, description="Override template name")
    description: str | None = Field(None, description="Override template description")
    secret: str | None = Field(None, description="HMAC signing secret (optional)")
    event_subscriptions: list[str] | None = Field(None, description="Override template event types")
    config: dict[str, Any] = Field(default_factory=dict)
    verify_ssl: bool = True

    @model_validator(mode="after")
    def validate_url(self) -> ApplyTemplateRequest:
        if not self.url.lower().startswith("https://"):
            raise ValueError("Integration URL must use HTTPS (https://...)")
        return self


# ============================================================================
# Helpers
# ============================================================================


def _require_admin(user: Any) -> None:
    # Scope ceiling: integrations create/modify outbound
    # webhooks (URL + encrypted secret), so a deliberately-narrowed read-only
    # scoped key must NOT pass via its owner's raw role. Matches the hardened
    # sibling webhooks.py:require_admin.
    if getattr(user, "is_scoped", False):
        raise HTTPException(
            http_status.HTTP_403_FORBIDDEN,
            detail="Scoped API keys cannot satisfy role-based gates",
        )
    if getattr(user, "role", None) not in (UserRole.ORG_ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(http_status.HTTP_403_FORBIDDEN, detail="Admin access required")


def _org_id(user: Any) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(
            http_status.HTTP_400_BAD_REQUEST, detail="Organization context required"
        )
    return oid


def _integration_to_response(i: Any) -> dict[str, Any]:
    return {
        "id": str(i.id),
        "name": i.name,
        "description": i.description,
        "integration_type": i.integration_type,
        "webhook_id": str(i.webhook_id),
        "is_enabled": i.is_enabled,
        "event_subscriptions": i.event_subscriptions or [],
        "config": i.config or {},
        "last_delivery_at": i.last_delivery_at.isoformat() if i.last_delivery_at else None,
        "last_delivery_status": i.last_delivery_status,
        "delivery_count_7d": i.delivery_count_7d,
        "success_count_7d": i.success_count_7d,
        "created_at": i.created_at.isoformat() if i.created_at else "",
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
    }


# ============================================================================
# Static routes (must be before /{integration_id})
# ============================================================================


@router.get("/types")
async def list_integration_types(user: Any = Depends(get_current_active_user)) -> Any:
    """List all supported integration types with their metadata."""
    # H-5: require authentication — metadata still reveals internal topology
    return {"types": [{"id": k, **v} for k, v in INTEGRATION_TYPES.items()]}


@router.get("/event-categories")
async def list_event_categories(user: Any = Depends(get_current_active_user)) -> Any:
    """List all available event categories and their event types."""
    # H-5: require authentication
    return {
        "categories": [
            {"name": name, "events": events} for name, events in EVENT_CATEGORIES.items()
        ]
    }


@router.get("/templates")
async def list_integration_templates(user: Any = Depends(get_current_active_user)) -> Any:
    """List pre-configured integration templates (aliases for common type defaults)."""
    templates = [
        {
            "id": "n8n-device-monitor",
            "name": "n8n Device Monitor",
            "integration_type": "n8n",
            "description": "Send device status changes to an n8n workflow",
            "default_events": ["device.status.changed", "device.offline", "device.online"],
        },
        {
            "id": "slack-critical-alerts",
            "name": "Slack Critical Alerts",
            "integration_type": "slack",
            "description": "Post critical and escalated alerts to a Slack channel",
            "default_events": ["alert.created", "alert.escalated"],
        },
        {
            "id": "pagerduty-incidents",
            "name": "PagerDuty Incident Bridge",
            "integration_type": "pagerduty",
            "description": "Create and auto-resolve PagerDuty incidents from FreeSDN alerts",
            "default_events": ["alert.created", "alert.resolved"],
        },
        {
            "id": "security-event-stream",
            "name": "Security Event Stream",
            "integration_type": "webhook",
            "description": "Stream all security events to a SIEM or log aggregator",
            "default_events": ["security.anomaly", "audit.login_failed", "security.ip_blocked"],
        },
        {
            "id": "backup-status",
            "name": "Backup Status Notifications",
            "integration_type": "slack",
            "description": "Get notified on backup success and failure",
            "default_events": ["backup.complete", "backup.failed"],
        },
    ]
    return {"templates": templates}


# ============================================================================
# CRUD
# ============================================================================


@router.get("/")
async def list_integrations(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    integration_type: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """List all integrations for the organization."""
    _require_admin(user)
    from app.models.integrations import Integration

    org_id = _org_id(user)
    q = select(Integration).where(Integration.organization_id == org_id)
    count_q = (
        select(func.count()).select_from(Integration).where(Integration.organization_id == org_id)
    )

    if integration_type:
        q = q.where(Integration.integration_type == integration_type)
        count_q = count_q.where(Integration.integration_type == integration_type)

    total = (await session.execute(count_q)).scalar() or 0
    pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    rows = (
        (
            await session.execute(
                q.order_by(Integration.created_at.desc()).offset(offset).limit(per_page)
            )
        )
        .scalars()
        .all()
    )

    return {
        "items": [_integration_to_response(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.post("/", status_code=http_status.HTTP_201_CREATED)
async def create_integration(
    data: IntegrationCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """
    Create a new integration.

    This creates both an Integration record and the underlying Webhook record.
    SSRF validation is applied to the URL before saving.
    """
    _require_admin(user)
    from app.models.integrations import Integration
    from app.services.webhooks import PersistentWebhookService

    org_id = _org_id(user)

    # Create the underlying webhook first (includes SSRF validation)
    webhook_data = {
        "name": f"{data.name} (integration)",
        "description": f"Auto-created for integration: {data.name}",
        "url": data.url,
        "event_types": data.event_subscriptions,
        "enabled": True,
        "secret": data.secret,
        "verify_ssl": data.verify_ssl,
        "max_retries": 5,
        "organization_id": org_id,
    }
    try:
        wh = await PersistentWebhookService.create_webhook(session, webhook_data, user_id=user.id)
    except ValueError as exc:
        # SSRF guard / URL shape rejection bubbles up from
        # PersistentWebhookService.create_webhook → previously
        # returned 500 with a stack trace in the log instead of a
        # clean 422 for ``https://169.254.169.254/...`` etc.
        logger.info("Integration create rejected: %s", exc)
        raise HTTPException(http_status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    integration = Integration(
        organization_id=org_id,
        name=data.name,
        description=data.description,
        integration_type=data.integration_type,
        webhook_id=wh.id,
        is_enabled=True,
        event_subscriptions=data.event_subscriptions,
        config=data.config,
    )
    session.add(integration)
    await session.flush()
    await session.refresh(integration)
    await session.commit()

    return _integration_to_response(integration)


@router.get("/{integration_id}")
async def get_integration(
    integration_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Get a specific integration."""
    _require_admin(user)
    from app.models.integrations import Integration

    row = (
        await session.execute(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.organization_id == _org_id(user),
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, detail="Integration not found")
    return _integration_to_response(row)


@router.patch("/{integration_id}")
async def update_integration(
    integration_id: UUID,
    data: IntegrationUpdate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Update an integration (and its underlying webhook URL/events/secret)."""
    _require_admin(user)
    from app.models.integrations import Integration
    from app.services.webhooks import PersistentWebhookService

    org_id = _org_id(user)
    row = (
        await session.execute(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, detail="Integration not found")

    # Update Integration fields
    update_data = data.model_dump(exclude_unset=True)
    webhook_update: dict[str, Any] = {}

    for field in ("name", "description", "event_subscriptions", "config"):
        if field in update_data:
            setattr(row, field, update_data[field])

    if "event_subscriptions" in update_data:
        # H-4: must use "event_types" — the actual Webhook model column name
        webhook_update["event_types"] = update_data["event_subscriptions"]
    if "url" in update_data:
        webhook_update["url"] = update_data["url"]
    if "secret" in update_data:
        webhook_update["secret"] = update_data["secret"]
    if "verify_ssl" in update_data:
        webhook_update["verify_ssl"] = update_data["verify_ssl"]

    if webhook_update:
        try:
            await PersistentWebhookService.update_webhook(
                session, row.webhook_id, webhook_update, organization_id=org_id
            )
        except ValueError as exc:
            logger.info("Integration update rejected: %s", exc)
            raise HTTPException(http_status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    row.updated_at = datetime.now(UTC)
    await session.flush()
    await session.refresh(row)
    await session.commit()
    return _integration_to_response(row)


@router.delete("/{integration_id}", status_code=http_status.HTTP_204_NO_CONTENT)
async def delete_integration(
    integration_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    """Delete an integration and its underlying webhook."""
    _require_admin(user)
    from app.models.integrations import Integration
    from app.services.webhooks import PersistentWebhookService

    org_id = _org_id(user)
    row = (
        await session.execute(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, detail="Integration not found")

    # Delete webhook first (CASCADE will also clean WebhookDelivery + DLQ rows)
    await PersistentWebhookService.delete_webhook(session, row.webhook_id, organization_id=org_id)
    await session.delete(row)
    await session.commit()


# ============================================================================
# Enable / Disable / Test
# ============================================================================


@router.post("/{integration_id}/enable", status_code=http_status.HTTP_204_NO_CONTENT)
async def enable_integration(
    integration_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    """Enable an integration (also re-enables the underlying webhook)."""
    _require_admin(user)
    from app.models.integrations import Integration
    from app.services.webhooks import PersistentWebhookService

    org_id = _org_id(user)
    row = (
        await session.execute(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, detail="Integration not found")

    row.is_enabled = True
    await PersistentWebhookService.enable_webhook(session, row.webhook_id, organization_id=org_id)
    await session.commit()


@router.post("/{integration_id}/disable", status_code=http_status.HTTP_204_NO_CONTENT)
async def disable_integration(
    integration_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    """Disable an integration (also disables the underlying webhook)."""
    _require_admin(user)
    from app.models.integrations import Integration
    from app.services.webhooks import PersistentWebhookService

    org_id = _org_id(user)
    row = (
        await session.execute(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, detail="Integration not found")

    row.is_enabled = False
    await PersistentWebhookService.disable_webhook(session, row.webhook_id, organization_id=org_id)
    await session.commit()


@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: UUID,
    body: TestIntegrationRequest | None = None,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Send a test event to verify the integration endpoint is reachable."""
    _require_admin(user)
    from app.models.integrations import Integration
    from app.services.webhooks import PersistentWebhookService

    # Body is optional: a bare POST should still send the default test event.
    # Avoid a mutable shared default arg (a single module-level instance).
    if body is None:
        body = TestIntegrationRequest()

    org_id = _org_id(user)
    row = (
        await session.execute(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, detail="Integration not found")

    # Use the existing webhook test mechanism
    test_payload = {
        **body.payload,
        "event_type": body.event_type,
        "integration_id": str(integration_id),
        "integration_name": row.name,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    try:
        result = await PersistentWebhookService.dispatch_webhook(
            session, row.webhook_id, event_type=body.event_type, payload=test_payload
        )
    except Exception as exc:
        # dispatch_webhook can raise before/around HTTP delivery (DB flush,
        # secret decryption, etc.). A failed test should report a clean error
        # to the caller rather than surfacing an opaque 500 stack trace.
        await session.rollback()
        logger.warning("Integration test dispatch failed (webhook=%s): %s", row.webhook_id, exc)
        return {"status": "error", "error": str(exc)}
    await session.commit()

    if not result:
        return {"status": "error", "error": "Webhook not found or disabled"}

    return {
        "status": result.status,
        "delivery_id": str(result.id),
        "response_code": result.response_code,
        "response_time_ms": result.response_time_ms,
        "error": result.error_message,
    }


# ============================================================================
# Template apply
# ============================================================================


@router.post("/templates/{template_id}/apply", status_code=http_status.HTTP_201_CREATED)
async def apply_template(
    template_id: str,
    body: ApplyTemplateRequest,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """
    Create an integration pre-filled from a named template.

    Body must include at minimum: {"url": "https://..."}
    """
    _require_admin(user)

    # H-5: list_integration_templates now requires auth — pass user to avoid double-dep error
    templates = (await list_integration_templates(user))["templates"]
    tmpl = next((t for t in templates if t["id"] == template_id), None)
    if not tmpl:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, detail="Template not found")

    create_data = IntegrationCreate(
        name=body.name or tmpl["name"],
        description=body.description or tmpl.get("description"),
        integration_type=tmpl["integration_type"],
        url=body.url,
        secret=body.secret,
        event_subscriptions=body.event_subscriptions
        if body.event_subscriptions is not None
        else tmpl["default_events"],
        config=body.config,
        verify_ssl=body.verify_ssl,
    )
    return await create_integration(create_data, session, user)
