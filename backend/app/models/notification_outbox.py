# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Committed personal notifications waiting for realtime event publication."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class InAppNotificationEvent(Base):
    """One durable event per bell row; no copied content or transport credentials."""

    __tablename__ = "in_app_notification_events"
    __table_args__ = (
        CheckConstraint("status IN ('pending', 'published', 'suppressed')", name="status"),
        CheckConstraint("attempts >= 0", name="attempts"),
        Index("ix_inapp_event_due", "status", "next_attempt_at"),
        {"schema": "core"},
    )

    notification_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.in_app_notifications.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"), nullable=False
    )
    # Keep the creation scope. Deleting a tenant must never promote its pending
    # events to platform scope, even though the older bell FK uses SET NULL.
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    suppressed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure: Mapped[str | None] = mapped_column(String(40))
