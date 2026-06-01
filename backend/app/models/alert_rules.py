# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Alert Rules Engine Models
=========================================

User-configurable alerting rules that evaluate against events and metrics
to generate alerts with multi-channel notifications.

"CPU utilization > 90% for 5 minutes → critical alert → Slack + email + in-app."
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    pass


# ==========================================================================
# Enumerations
# ==========================================================================


class AlertRuleType(StrEnum):
    """Type of alert rule evaluation."""

    THRESHOLD = "threshold"
    PATTERN = "pattern"
    ANOMALY = "anomaly"
    CUSTOM = "custom"


class AlertRuleStatus(StrEnum):
    """Whether an alert rule is active."""

    ACTIVE = "active"
    DISABLED = "disabled"
    DRAFT = "draft"


class AlertSeverity(StrEnum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    """Lifecycle status of a fired alert."""

    FIRING = "firing"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


# ==========================================================================
# AlertRule - User-configurable rule definitions
# ==========================================================================


class AlertRule(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """A configurable alert rule that evaluates conditions to fire alerts."""

    __tablename__ = "alert_rules"
    __table_args__ = (
        Index("ix_alert_rules_org", "organization_id"),
        Index("ix_alert_rules_status", "status"),
        Index("ix_alert_rules_type", "rule_type"),
        Index("ix_alert_rules_scope_ids", "scope_ids", postgresql_using="gin"),
        {"schema": "events"},
    )

    # ── Identity ──
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Rule definition ──
    rule_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=AlertRuleType.THRESHOLD,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=AlertRuleStatus.ACTIVE,
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=AlertSeverity.WARNING,
    )

    # Conditions — flexible JSONB structure:
    #   threshold: {"metric": "cpu_utilization", "operator": ">", "value": 90}
    #   pattern:   {"event_type": "device.offline", "min_count": 3}
    #   anomaly:   {"metric": "traffic_in", "std_dev_threshold": 3.0}
    conditions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # ── Scope ──
    scope: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="organization",
    )  # "organization", "site", "device_group", "device"
    scope_ids: Mapped[list[Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )  # list of UUIDs for targeted scope
    device_types: Mapped[list[Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )  # optional device type filter

    # ── Timing ──
    check_interval_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=300,
    )
    for_duration_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )  # condition must persist for N seconds before firing
    cooldown_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=300,
    )  # min time between re-firing

    # ── Resolution ──
    auto_resolve: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_resolve_after_seconds: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    # ── Notifications ──
    notification_channels: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )  # {"email": {"to": [...]}, "slack": {"channel": "..."}, "webhook": {...}}
    notify_on_resolve: Mapped[bool] = mapped_column(Boolean, default=True)

    # ── Deduplication ──
    dedupe_window_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3600,
    )

    # ── Tags & extra metadata ──
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    extra_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # ── Stats (denormalized, updated on evaluation) ──
    last_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_fired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    fire_count: Mapped[int] = mapped_column(Integer, default=0)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)

    # ── Relationships ──
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="rule",
        cascade="all, delete-orphan",
    )


# ==========================================================================
# Alert - Fired alert instances
# ==========================================================================


class Alert(Base, UUIDMixin, AuditMixin):
    """An alert instance fired by an AlertRule evaluation."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_org", "organization_id"),
        Index("ix_alerts_rule", "rule_id"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_fired_at", "fired_at"),
        {"schema": "events"},
    )

    # ── Identity ──
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id: Mapped[UUID] = mapped_column(
        ForeignKey("events.alert_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )
    device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Alert content ──
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # ── Status ──
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=AlertStatus.FIRING,
    )
    fired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    acknowledged_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Deduplication ──
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    last_occurrence_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ── Suppression ──
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppressed_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    suppression_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # ── Notification tracking ──
    notifications_sent: Mapped[int] = mapped_column(Integer, default=0)
    last_notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Tags & extra metadata ──
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    extra_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # ── Relationships ──
    rule: Mapped["AlertRule"] = relationship(
        "AlertRule",
        back_populates="alerts",
    )
