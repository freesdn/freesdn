# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Notification Models
===================================

Database models for the notification system:
  - InAppNotification: User-facing notifications displayed in the frontend
  - NotificationDelivery: Delivery tracking for all channels
  - NotificationPreference: Per-user notification settings
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin


class InAppNotification(Base, UUIDMixin):
    """In-app notification displayed in the user's notification center."""

    __tablename__ = "in_app_notifications"
    __table_args__ = (
        Index("ix_inapp_notif_user_read", "user_id", "read"),
        Index("ix_inapp_notif_user_created", "user_id", "created_at"),
        {"schema": "core"},
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL"),
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False, default="system")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    action_url: Mapped[str | None] = mapped_column(String(512))
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=dict)
    read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dismissed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class NotificationDelivery(Base, UUIDMixin):
    """Tracks delivery attempts for notifications across all channels.

    Retry/DLQ fields:
        attempt: number of delivery attempts made (1 = first try).
        retry_dead_letter: True once the retry task has exhausted
            ``max_retries`` and given up. Ops dashboards filter on this
            flag to surface stuck deliveries.
        last_error: most recent error string from the channel's send().
    """

    __tablename__ = "notification_deliveries"
    __table_args__ = (
        Index("ix_notif_delivery_user", "user_id"),
        Index("ix_notif_delivery_channel", "channel"),
        Index("ix_notif_delivery_status", "status"),
        Index("ix_notif_delivery_dead_letter", "retry_dead_letter"),
        {"schema": "core"},
    )

    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL"),
    )
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False, default="system")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    subject: Mapped[str | None] = mapped_column(String(255))
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="sent")
    error_message: Mapped[str | None] = mapped_column(Text)
    provider: Mapped[str | None] = mapped_column(String(50))
    message_id: Mapped[str | None] = mapped_column(String(255))
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )
    # Retry queue fields. ``attempt`` starts at 1 (initial send), increments
    # on each retry. ``retry_dead_letter`` flips True once max_retries is
    # exhausted so ops can surface stuck deliveries with a single WHERE.
    # ``last_error`` mirrors error_message for the most recent attempt.
    attempt: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
    )
    retry_dead_letter: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    last_error: Mapped[str | None] = mapped_column(Text)


class NotificationPreference(Base, UUIDMixin):
    """Per-user notification preferences stored in the database."""

    __tablename__ = "notification_preferences"
    __table_args__ = (
        Index("ix_notif_pref_user", "user_id", unique=True),
        {"schema": "core"},
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    # JSON list of enabled channels: ["email", "in_app", "slack"]
    enabled_channels: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    # Per-category overrides: {"security": {"channels": ["email", "in_app"]}, ...}
    category_settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    # Quiet hours: {"start": 22, "end": 7} (24h format)
    quiet_hours: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )


class NotificationProviderRecord(Base, UUIDMixin):
    """
    Persistent notification provider configuration.

    Stores connection details for each delivery channel (SMTP, Slack,
    Teams, Webhook, SMS, WhatsApp) so they survive container restarts and
    can be managed via the Settings UI.
    """

    __tablename__ = "notification_providers"
    __table_args__ = (
        Index("ix_notif_provider_org", "organization_id"),
        Index("ix_notif_provider_channel", "channel"),
        {"schema": "core"},
    )

    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL"),
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider_type: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        comment="e.g. smtp, slack_webhook, teams_webhook, generic_webhook, twilio_sms, twilio_whatsapp",
    )
    channel: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Matches NotificationChannel enum: email, slack, teams, webhook, sms, whatsapp, in_app",
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Channel-specific configuration (secrets stored encrypted at app layer)",
    )
    rate_limit_per_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=500)
    rate_limit_per_day: Mapped[int] = mapped_column(Integer, nullable=False, default=10000)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )
