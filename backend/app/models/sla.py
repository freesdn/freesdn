# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SLA Monitoring Models
=====================================

Define SLA policies per site/SSID/device-group, monitor health scores
against thresholds, and alert on breach.
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
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Organization


# ==========================================================================
# Enumerations
# ==========================================================================


class SLAPolicyStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DRAFT = "draft"


class SLAPolicyScope(StrEnum):
    """What the SLA monitors."""

    ORGANIZATION = "organization"
    SITE = "site"
    SITE_GROUP = "site_group"
    DEVICE_GROUP = "device_group"
    SSID = "ssid"
    CAMERA = "camera"  # per-camera availability (uptime from health snapshots)
    NVR = "nvr"  # all cameras on one NVR


class SLABreachSeverity(StrEnum):
    WARNING = "warning"
    CRITICAL = "critical"


class SLABreachStatus(StrEnum):
    ACTIVE = "active"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"


# ==========================================================================
# SLA Policy
# ==========================================================================


class SLAPolicy(Base, UUIDMixin, AuditMixin):
    """
    Defines expected performance thresholds.

    Thresholds (JSONB) examples:
      {
        "health_score_min": 80,
        "uptime_percent_min": 99.5,
        "latency_ms_max": 50,
        "packet_loss_percent_max": 1.0,
        "client_satisfaction_min": 85
      }

    Evaluation windows:
      - 5min, 15min, 1h, 24h rolling windows
    """

    __tablename__ = "sla_policies"
    __table_args__ = (
        Index("ix_sla_policies_org", "organization_id"),
        Index("ix_sla_policies_status", "status"),
        Index("ix_sla_policies_scope", "scope", "scope_id"),
        {"schema": "core"},
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
        default=SLAPolicyStatus.ACTIVE.value,
    )

    # Scope: what does this SLA cover?
    scope: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=SLAPolicyScope.SITE.value,
    )
    scope_id: Mapped[UUID | None] = mapped_column(nullable=True)
    scope_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )  # Display name for the scoped entity (e.g. "Main Office", "Corporate WiFi")

    # Thresholds
    thresholds: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Evaluation config
    evaluation_window_minutes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=15,
    )
    breach_after_consecutive: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
    )  # How many consecutive violations before breach is raised
    warning_threshold_percent: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=90.0,
    )  # If metric is within 90% of breach, warn

    # Notification config
    notification_channels: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    escalation_policy: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Stats
    current_compliance_percent: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    last_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    if TYPE_CHECKING:
        organization: Organization
        breaches: list["SLABreach"]
        snapshots: list["SLASnapshot"]


# ==========================================================================
# SLA Breach
# ==========================================================================


class SLABreach(Base, UUIDMixin):
    """
    Records an SLA breach event.
    """

    __tablename__ = "sla_breaches"
    __table_args__ = (
        Index("ix_sla_breaches_policy", "policy_id"),
        Index("ix_sla_breaches_status", "status"),
        Index("ix_sla_breaches_severity", "severity"),
        Index("ix_sla_breaches_started_brin", "started_at", postgresql_using="brin"),
        {"schema": "core"},
    )

    policy_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sla_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=SLABreachSeverity.WARNING.value,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=SLABreachStatus.ACTIVE.value,
    )

    # What breached
    violated_metric: Mapped[str] = mapped_column(String(100), nullable=False)
    threshold_value: Mapped[float] = mapped_column(Float, nullable=False)
    actual_value: Mapped[float] = mapped_column(Float, nullable=False)
    deviation_percent: Mapped[float] = mapped_column(Float, nullable=False)

    # Timing
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    acknowledged_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Context
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    if TYPE_CHECKING:
        policy: SLAPolicy
        organization: Organization


# ==========================================================================
# SLA Snapshot (time-series compliance data)
# ==========================================================================


class SLASnapshot(Base, UUIDMixin):
    """
    Periodic snapshot of SLA compliance for trending and reporting.
    """

    __tablename__ = "sla_snapshots"
    __table_args__ = (
        Index("ix_sla_snapshots_policy", "policy_id"),
        Index("ix_sla_snapshots_ts_brin", "recorded_at", postgresql_using="brin"),
        {"schema": "core"},
    )

    policy_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sla_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    compliance_percent: Mapped[float] = mapped_column(Float, nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    in_breach: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


# ==========================================================================
# SLA Report
# ==========================================================================


class SLAReport(Base, UUIDMixin, AuditMixin):
    """
    A generated SLA compliance report for a given period.

    May be stored as a PDF or CSV file on disk, with a summary
    in ``report_data`` for quick access in the UI.
    """

    __tablename__ = "sla_reports"
    __table_args__ = (
        Index("ix_sla_reports_org", "organization_id"),
        Index("ix_sla_reports_period", "period_start", "period_end"),
        {"schema": "analytics"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    format: Mapped[str] = mapped_column(String(10), nullable=False, default="pdf")
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    report_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    generated_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


# ==========================================================================
# SLA Report Schedule
# ==========================================================================


class SLAReportSchedule(Base, UUIDMixin, AuditMixin):
    """
    Scheduled automatic SLA report generation.

    Defines when and for whom reports should be generated
    and emailed.
    """

    __tablename__ = "sla_report_schedules"
    __table_args__ = (
        Index("ix_sla_report_schedules_org", "organization_id"),
        Index("ix_sla_report_schedules_next_run", "next_run_at"),
        {"schema": "analytics"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    frequency: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="monthly",
    )  # weekly, monthly, quarterly
    day_of_week: Mapped[int | None] = mapped_column(Integer, nullable=True)
    day_of_month: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recipients: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    sla_policy_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
