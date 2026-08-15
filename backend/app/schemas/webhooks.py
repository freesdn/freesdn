# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Webhook Management Schemas
==========================================

Pydantic schemas for webhook API request/response validation.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class BaseSchema(BaseModel):
    model_config = {"from_attributes": True}


def _validate_webhook_url(v: str | None) -> str | None:
    """Reject control chars + cap length.

    SSRF (localhost / RFC1918 / 169.254.169.254 metadata IP) is
    blocked at the service layer via ``validate_url_ssrf`` and at
    delivery time via ``safe_http_request``. This validator handles
    the input-shape gates: length, scheme, control chars (CRLF
    header smuggling). Without this, ``url='not-a-url'`` reached the
    DB CHECK constraint and 500'd; CRLF in the URL was silently
    accepted into the delivery log.
    """
    if v is None:
        return v
    if len(v) > 2048:
        raise ValueError(f"url exceeds 2048 chars (got {len(v)})")
    for ch in v:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError("url must not contain control characters")
    if not (v.startswith("http://") or v.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    return v


# =============================================================================
# Webhook
# =============================================================================


class WebhookCreate(BaseSchema):
    """Create a new webhook."""

    name: str = Field(..., min_length=1, max_length=200)
    url: str = Field(..., min_length=1, max_length=2048)
    description: str | None = Field(None, max_length=2000)
    # Each event type is a dotted-name string (e.g. ``device.online``);
    # 100 chars per type, 200 types per webhook is generous.
    event_types: list[str] = Field(default_factory=list, max_length=200)
    enabled: bool = True
    secret: str | None = Field(None, max_length=512)
    verify_ssl: bool = True

    @field_validator("url")
    @classmethod
    def _url_shape(cls, v: str) -> str:
        return _validate_webhook_url(v) or v

    @field_validator("event_types")
    @classmethod
    def _event_types_items(cls, v: list[str]) -> list[str]:
        for item in v:
            if len(item) > 100:
                raise ValueError("event_type entry exceeds 100 chars")
            for ch in item:
                if ord(ch) < 0x20:
                    raise ValueError("event_type entry contains control characters")
        return v


class WebhookUpdate(BaseSchema):
    """Update a webhook."""

    name: str | None = Field(None, min_length=1, max_length=200)
    url: str | None = Field(None, min_length=1, max_length=2048)
    description: str | None = Field(None, max_length=2000)
    event_types: list[str] | None = Field(None, max_length=200)
    enabled: bool | None = None
    secret: str | None = Field(None, max_length=512)
    verify_ssl: bool | None = None

    @field_validator("url")
    @classmethod
    def _url_shape(cls, v: str | None) -> str | None:
        return _validate_webhook_url(v)

    @field_validator("event_types")
    @classmethod
    def _event_types_items(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for item in v:
            if len(item) > 100:
                raise ValueError("event_type entry exceeds 100 chars")
            for ch in item:
                if ord(ch) < 0x20:
                    raise ValueError("event_type entry contains control characters")
        return v


class WebhookResponse(BaseSchema):
    """Webhook response matching frontend Webhook interface."""

    id: UUID
    name: str
    description: str | None = None
    url: str
    event_types: list[str] = Field(default_factory=list)
    # ``site_ids`` used to live here but the create/update service
    # silently dropped it (not in ``_CREATE_FIELDS`` / ``_ALLOWED_FIELDS``)
    # and ``dispatch_webhook`` never consulted it for filtering — the
    # field was vestigial schema-drift, not a feature. Removed from
    # the response to stop advertising a column the backend doesn't
    # honour. ``verify_ssl`` is now surfaced so the edit form doesn't
    # silently re-enable cert verification on every save.
    verify_ssl: bool = True
    enabled: bool = True
    retry_count: int = 0
    failure_count: int = 0
    success_count: int = 0
    last_triggered: datetime | None = None
    last_success: datetime | None = None
    last_failure: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class WebhookListResponse(BaseSchema):
    """Paginated webhook list."""

    items: list[WebhookResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 20
    pages: int = 1


# =============================================================================
# Webhook Delivery
# =============================================================================


class WebhookDeliveryResponse(BaseSchema):
    """Delivery log entry."""

    id: UUID
    webhook_id: UUID
    event_id: str | None = None
    event_type: str
    status: str
    response_code: int | None = None
    response_time_ms: float | None = None
    attempt_number: int = 1
    error_message: str | None = None
    created_at: datetime | None = None
    sent_at: datetime | None = None


class WebhookDeliveryListResponse(BaseSchema):
    """Paginated delivery list."""

    items: list[WebhookDeliveryResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 20


# =============================================================================
# Stats
# =============================================================================


class WebhookStatsResponse(BaseSchema):
    """Webhook statistics."""

    webhook_id: UUID
    total_deliveries: int = 0
    success: int = 0
    failed: int = 0
    pending: int = 0
    retrying: int = 0
    success_rate: float = 0.0
    avg_response_time_ms: float | None = None
    enabled: bool = True
    failure_count: int = 0
    last_triggered: datetime | None = None


# =============================================================================
# Test
# =============================================================================


class WebhookTestResponse(BaseSchema):
    """Test webhook response."""

    status: str
    delivery_id: str | None = None
    response_status: int | None = None
    response_time_ms: float | None = None
    error: str | None = None
