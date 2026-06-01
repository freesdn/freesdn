# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event History Models
==================================

Database models for persisting events for history and replay.
"""

import uuid
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.db.base import Base, LogBase


class EventPriority(StrEnum):
    """Event processing priority."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(StrEnum):
    """High-level event categories."""

    SYSTEM = "system"
    DEVICE = "device"
    SITE = "site"
    CONTROLLER = "controller"
    NETWORK = "network"
    SECURITY = "security"
    USER = "user"
    TASK = "task"
    AUTOMATION = "automation"


class EventRecord(LogBase):
    """
    Persisted event record for history and audit.

    Uses TimescaleDB hypertable for efficient time-series queries.
    """

    __tablename__ = "event_records"
    __table_args__ = (
        Index("ix_event_records_event_type", "event_type"),
        Index("ix_event_records_category", "category"),
        Index("ix_event_records_correlation_id", "correlation_id"),
        Index("ix_event_records_source", "source"),
        Index("ix_event_records_organization_id", "organization_id"),
        Index("ix_event_records_timestamp_brin", "timestamp", postgresql_using="brin"),
        {"schema": "events"},
    )

    # Primary fields
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(255), nullable=False, index=True)
    # NOTE: the Postgres enum types were created with the LOWERCASE member
    # *values* ("security", "high", …). Without values_callable SQLAlchemy
    # would send the member *names* ("SECURITY", "HIGH"), which Postgres
    # rejects ("invalid input value for enum") — that latent bug meant
    # persist_event() never wrote a single EventRecord. values_callable makes
    # it emit the value, matching the DB type.
    category: Column[EventCategory] = Column(
        Enum(
            EventCategory,
            name="event_category_enum",
            schema="events",
            values_callable=lambda enum_cls: [m.value for m in enum_cls],
        ),
        nullable=False,
        default=EventCategory.SYSTEM,
    )
    priority: Column[EventPriority] = Column(
        Enum(
            EventPriority,
            name="event_priority_enum",
            schema="events",
            values_callable=lambda enum_cls: [m.value for m in enum_cls],
        ),
        nullable=False,
        default=EventPriority.NORMAL,
    )

    # Event data
    payload = Column(JSONB, nullable=False, default=dict)
    event_meta = Column("metadata", JSONB, nullable=False, default=dict)

    # Tracing
    source = Column(String(100), nullable=False, default="freesdn")
    correlation_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    causation_id = Column(UUID(as_uuid=True), nullable=True)

    # Multi-tenancy
    # Plain UUID columns — no real FK in LogDB (separate database).
    # Cleanup is handled by retention policy (cleanup_old_events task).
    organization_id = Column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    site_id = Column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    # Actor info
    user_id = Column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # Timestamps
    # Part of the composite PK (id, timestamp) so the model matches the LogDB
    # hypertable DDL where the partition column MUST be in the PK.
    timestamp = Column(
        DateTime(timezone=True),
        primary_key=True,
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for event bus."""
        return {
            "id": str(self.id),
            "event_type": self.event_type,
            "category": self.category.value,
            "priority": self.priority.value,
            "payload": self.payload,
            "metadata": self.event_meta,
            "source": self.source,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "site_id": str(self.site_id) if self.site_id else None,
            "user_id": str(self.user_id) if self.user_id else None,
            "timestamp": self.timestamp.isoformat(),
        }


class EventSubscription(Base):
    """
    Persistent event subscription for webhooks and external systems.
    """

    __tablename__ = "event_subscriptions"
    __table_args__ = (
        Index("ix_event_subscriptions_pattern", "pattern"),
        Index("ix_event_subscriptions_active", "is_active"),
        {"schema": "events"},
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Subscription details
    name = Column(String(255), nullable=False)
    pattern = Column(String(255), nullable=False)  # e.g., "device.*", "site.#"

    # Delivery target
    target_type = Column(String(50), nullable=False)  # "webhook", "email", "slack"
    target_url = Column(Text, nullable=True)
    target_config = Column(JSONB, nullable=False, default=dict)

    # Filtering
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    site_ids = Column(JSONB, nullable=True)  # List of site IDs to filter

    # State
    is_active = Column(Boolean, nullable=False, default=True)
    last_triggered = Column(DateTime(timezone=True), nullable=True)
    trigger_count = Column(Integer, nullable=False, default=0)

    # Retry configuration
    retry_count = Column(Integer, nullable=False, default=3)
    retry_delay_seconds = Column(Integer, nullable=False, default=60)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
