# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event Correlation Models
========================================

Groups related events into incidents using pattern-matching rules.
"AP offline + 12 clients roamed + channel utilization spike = 1 incident, not 14 alerts."
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Organization, Site, User


# ==========================================================================
# Enumerations
# ==========================================================================


class IncidentSeverity(StrEnum):
    """Incident severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    """Incident lifecycle status."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CorrelationRuleStatus(StrEnum):
    """Whether a correlation rule is active."""

    ACTIVE = "active"
    DISABLED = "disabled"
    DRAFT = "draft"


# ==========================================================================
# Correlation Rule
# ==========================================================================


class CorrelationRule(Base, UUIDMixin, AuditMixin):
    """
    Defines a pattern for grouping events into incidents.

    A rule specifies:
      - event_patterns: list of event type patterns to match
        e.g. [{"event_type": "device.offline"}, {"event_type": "client.roamed", "min_count": 5}]
      - time_window_seconds: how close events must be to correlate
      - scope: "site" | "device_group" | "organization" — grouping boundary
      - severity: resulting incident severity when rule fires
      - conditions: additional JSONB conditions (device_type, site_id filters, etc.)
    """

    __tablename__ = "correlation_rules"
    __table_args__ = (
        Index("ix_correlation_rules_org", "organization_id"),
        Index("ix_correlation_rules_status", "status"),
        {"schema": "events"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=CorrelationRuleStatus.ACTIVE.value,
    )

    # Pattern definition
    event_patterns: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    time_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    scope: Mapped[str] = mapped_column(String(50), nullable=False, default="site")
    conditions: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Actions
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=IncidentSeverity.MEDIUM.value,
    )
    auto_resolve_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notification_channels: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Stats
    fire_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_fired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    if TYPE_CHECKING:
        organization: Organization
        incidents: list["Incident"]


# ==========================================================================
# Incident
# ==========================================================================


class Incident(Base, UUIDMixin, AuditMixin):
    """
    An incident groups correlated events into a single actionable item.

    Created by the correlation engine when a rule fires.
    """

    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_org", "organization_id"),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_rule", "rule_id"),
        Index("ix_incidents_site", "site_id"),
        Index("ix_incidents_opened_at_brin", "opened_at", postgresql_using="brin"),
        {"schema": "events"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("events.correlation_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Incident metadata
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=IncidentSeverity.MEDIUM.value,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=IncidentStatus.OPEN.value,
    )

    # Timing
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Assignment
    assigned_to: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Aggregated data
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    affected_devices: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Relationships
    if TYPE_CHECKING:
        organization: Organization
        site: Site
        rule: CorrelationRule
        assignee: User
        events: list["IncidentEvent"]


# ==========================================================================
# Incident ↔ Event Link
# ==========================================================================


class IncidentEvent(Base, UUIDMixin):
    """
    Links an event record to an incident (M:N).
    """

    __tablename__ = "incident_events"
    __table_args__ = (
        UniqueConstraint("incident_id", "event_id", name="uq_incident_event"),
        Index("ix_incident_events_incident", "incident_id"),
        Index("ix_incident_events_event", "event_id"),
        {"schema": "events"},
    )

    incident_id: Mapped[UUID] = mapped_column(
        ForeignKey("events.incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    # NOTE: ``event_id`` references ``events.event_records.id`` which lives
    # on the LogDB (TimescaleDB) instance. Postgres cannot enforce a foreign
    # key across two database instances, so this column is intentionally a
    # plain UUID with an index — referential integrity is enforced by the
    # correlation service before insert. A real FK here would also break
    # ``Base.metadata.create_all()`` because ``EventRecord`` belongs to the
    # ``LogBase`` metadata graph, not ``Base``.
    event_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )
    matched_pattern: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
