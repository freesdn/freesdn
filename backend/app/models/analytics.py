# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Analytics Models
===============================

SQLAlchemy models for the analytics module:
- MetricDefinitionRecord: Configurable metric definitions
- MetricDataPoint: TimescaleDB hypertable for time-series data
- AnalyticsAlert: Threshold-based alerting
- DashboardWidget: User-configurable dashboard widgets
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, LogBase, UUIDMixin

if TYPE_CHECKING:
    pass


# =============================================================================
# Enums
# =============================================================================


class MetricType(StrEnum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class AggregationType(StrEnum):
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
    COUNT = "count"
    LAST = "last"
    P50 = "p50"
    P90 = "p90"
    P95 = "p95"
    P99 = "p99"


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class Granularity(StrEnum):
    RAW = "raw"
    ONE_MINUTE = "1m"
    FIVE_MINUTES = "5m"
    FIFTEEN_MINUTES = "15m"
    ONE_HOUR = "1h"
    ONE_DAY = "1d"
    ONE_WEEK = "1w"


# =============================================================================
# Models
# =============================================================================


class MetricDefinitionRecord(Base, UUIDMixin, AuditMixin):
    """
    Configurable metric definition stored in DB.
    Extends the in-memory STANDARD_METRICS with user-defined metrics.
    """

    __tablename__ = "metric_definitions"
    __table_args__ = (
        UniqueConstraint("name", name="uq_metric_definitions_name"),
        {"schema": "analytics"},
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False, default="custom")
    metric_type: Mapped[str] = mapped_column(String(20), nullable=False, default=MetricType.GAUGE)
    unit: Mapped[str | None] = mapped_column(String(50), nullable=True)
    labels: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True, default=list)

    # Aggregation
    default_aggregation: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=AggregationType.AVG,
    )

    # Retention
    retention_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=168)  # 7 days

    # Thresholds (JSONB: {"operator": ">", "value": 90})
    warning_threshold: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    critical_threshold: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class MetricDataPoint(LogBase):
    """
    Time-series metric data point.

    Uses composite primary key (time + metric_name + labels_hash) for
    TimescaleDB hypertable partitioning.
    """

    __tablename__ = "metric_data"
    __table_args__ = (
        Index("ix_metric_data_name_time", "metric_name", "time"),
        Index("ix_metric_data_site", "site_id", "time"),
        Index("ix_metric_data_device", "device_id", "time"),
        {"schema": "analytics"},
    )

    time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        nullable=False,
    )
    metric_name: Mapped[str] = mapped_column(
        String(255),
        primary_key=True,
        nullable=False,
    )
    labels_hash: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        nullable=False,
        default="",
    )

    value: Mapped[float] = mapped_column(Float, nullable=False)
    labels: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Dimensions for fast filtering (denormalized from labels)
    organization_id: Mapped[UUID | None] = mapped_column(nullable=True)
    site_id: Mapped[UUID | None] = mapped_column(nullable=True)
    device_id: Mapped[UUID | None] = mapped_column(nullable=True)


class AnalyticsAlert(Base, UUIDMixin, AuditMixin):
    """
    Alert triggered by metric threshold violations.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_severity_status", "severity", "status"),
        Index("ix_alerts_site", "site_id"),
        Index("ix_alerts_triggered", "triggered_at"),
        {"schema": "analytics"},
    )

    # Classification
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default=AlertSeverity.WARNING)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=AlertStatus.ACTIVE)
    alert_type: Mapped[str] = mapped_column(String(100), nullable=False, default="threshold")

    # Content
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Source
    metric_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metric_value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    device_id: Mapped[UUID | None] = mapped_column(nullable=True)
    site_id: Mapped[UUID | None] = mapped_column(nullable=True)
    organization_id: Mapped[UUID | None] = mapped_column(nullable=True)

    # Timestamps
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[UUID | None] = mapped_column(nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Notes
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class DashboardWidget(Base, UUIDMixin, AuditMixin):
    """
    User-configurable dashboard widget.
    """

    __tablename__ = "dashboard_widgets"
    __table_args__ = (
        Index("ix_widgets_dashboard", "dashboard_name"),
        Index("ix_widgets_owner", "owner_id"),
        {"schema": "analytics"},
    )

    dashboard_name: Mapped[str] = mapped_column(String(255), nullable=False, default="default")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    widget_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # line, bar, gauge, stat, table

    # Layout
    position_x: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    position_y: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    width: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    height: Mapped[int] = mapped_column(Integer, nullable=False, default=4)

    # Data configuration
    metrics: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    aggregation: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AggregationType.AVG
    )
    time_range: Mapped[str] = mapped_column(String(20), nullable=False, default="1h")
    display_options: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Refresh
    refresh_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)

    # Owner
    owner_id: Mapped[UUID | None] = mapped_column(nullable=True)
    organization_id: Mapped[UUID | None] = mapped_column(nullable=True)
