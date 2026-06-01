# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Webhook Management Models
==========================================

SQLAlchemy models for webhook lifecycle management:
- Webhook: Webhook configuration (URL, events, secret)
- WebhookDelivery: Delivery log for each webhook invocation
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin

if TYPE_CHECKING:
    pass


# =============================================================================
# Enums
# =============================================================================


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


# =============================================================================
# Models
# =============================================================================


class Webhook(Base, UUIDMixin, AuditMixin):
    """Webhook configuration."""

    __tablename__ = "webhooks"
    __table_args__ = (
        Index("ix_webhooks_enabled", "enabled"),
        Index("ix_webhooks_org", "organization_id"),
        {"schema": "core"},
    )

    # Identity
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str] = mapped_column(String(512), nullable=False)

    # Config
    event_types: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    site_ids: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Security
    secret: Mapped[str | None] = mapped_column(String(256))
    verify_ssl: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Retry config
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Stats (denormalized for quick display)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_triggered: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Organization scope
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL")
    )
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL")
    )


class WebhookDelivery(Base, UUIDMixin, AuditMixin):
    """Delivery log entry for a webhook invocation."""

    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        Index("ix_wh_delivery_webhook", "webhook_id"),
        Index("ix_wh_delivery_status", "status"),
        Index("ix_wh_delivery_created", "created_at"),
        {"schema": "core"},
    )

    webhook_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.webhooks.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[str | None] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)

    # Delivery info
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=DeliveryStatus.PENDING)
    response_code: Mapped[int | None] = mapped_column(Integer)
    response_time_ms: Mapped[float | None] = mapped_column(Float)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    error_message: Mapped[str | None] = mapped_column(Text)

    # Payload
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    # Timing
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebhookDeadLetter(Base, UUIDMixin):
    """
    Dead-letter queue for webhook deliveries that exhausted all retry attempts.

    When a delivery fails after max_retries, instead of silently dropping it,
    we move it here so admins can inspect and replay it manually.
    """

    __tablename__ = "webhook_dead_letters"
    __table_args__ = (
        Index("ix_wh_dlq_webhook", "webhook_id"),
        Index("ix_wh_dlq_org", "organization_id"),
        Index("ix_wh_dlq_created", "created_at"),
        {"schema": "core"},
    )

    webhook_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.webhooks.id", ondelete="CASCADE"), nullable=False
    )
    delivery_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.webhook_deliveries.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL")
    )

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Lifecycle
    final_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    replayed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replayed_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
