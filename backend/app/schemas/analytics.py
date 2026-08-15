# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Analytics Schemas
================================

Pydantic schemas for the analytics API endpoints.
Matches frontend types in api.ts (DashboardSummary, MetricDefinition, etc.)
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.analytics import (
    AggregationType,
    AlertSeverity,
    AlertStatus,
    Granularity,
    MetricType,
)

# =============================================================================
# Base
# =============================================================================


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


class TimestampSchema(BaseSchema):
    created_at: datetime
    updated_at: datetime


# =============================================================================
# Metric Definition
# =============================================================================


def _validate_threshold(v: dict[str, Any] | None) -> dict[str, Any] | None:
    """Cap threshold JSONB to a small shape (operator/value only)."""
    if v is None:
        return v
    # Real thresholds are 2-4 keys ({"operator": ">", "value": 90,
    # "duration_sec": 300, "comparison": "above"}). 16 keys with
    # 256 chars each is way more than any legitimate use.
    if len(v) > 16:
        raise ValueError("threshold must contain at most 16 keys")
    for key, val in v.items():
        if not isinstance(key, str) or len(key) > 64:
            raise ValueError("threshold keys must be strings <= 64 chars")
        if isinstance(val, str) and len(val) > 256:
            raise ValueError(f"threshold['{key}'] exceeds 256 chars")
    return v


class MetricDefinitionCreate(BaseSchema):
    name: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    category: str = Field(default="custom", max_length=100)
    metric_type: MetricType = MetricType.GAUGE
    unit: str | None = Field(default=None, max_length=50)
    # Labels list capped because every label becomes a column dimension.
    labels: list[str] | None = Field(default=None, max_length=32)
    default_aggregation: AggregationType = AggregationType.AVG
    retention_hours: int = Field(default=168, ge=1, le=8760)
    warning_threshold: dict[str, Any] | None = None
    critical_threshold: dict[str, Any] | None = None

    @field_validator("warning_threshold", "critical_threshold")
    @classmethod
    def _v_thr(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_threshold(v)


class MetricDefinitionUpdate(BaseSchema):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    category: str | None = Field(default=None, max_length=100)
    unit: str | None = Field(default=None, max_length=50)
    default_aggregation: AggregationType | None = None
    retention_hours: int | None = Field(default=None, ge=1, le=8760)
    warning_threshold: dict[str, Any] | None = None
    critical_threshold: dict[str, Any] | None = None
    is_active: bool | None = None

    @field_validator("warning_threshold", "critical_threshold")
    @classmethod
    def _v_thr(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_threshold(v)


class MetricDefinitionResponse(TimestampSchema):
    """Matches frontend MetricDefinition interface."""

    id: UUID
    name: str
    display_name: str
    description: str | None = None
    category: str
    metric_type: str
    unit: str | None = None
    labels: list[str] | None = None
    default_aggregation: str
    warning_threshold: dict[str, Any] | None = None
    critical_threshold: dict[str, Any] | None = None
    is_active: bool
    is_system: bool


# =============================================================================
# Metric Query
# =============================================================================


class MetricQueryRequest(BaseSchema):
    """Matches frontend MetricQueryRequest interface."""

    # metric_name must match a registered metric — cap to the DB
    # column width (analytics.metric_definitions.name VARCHAR(255)).
    metric_name: str = Field(min_length=1, max_length=255)
    start_time: datetime | None = None
    end_time: datetime | None = None
    granularity: Granularity | None = Granularity.FIVE_MINUTES
    aggregation: AggregationType | None = AggregationType.AVG
    # Only site_id / device_id / organization_id keys are honored
    # by query_metrics (lines 1017-1026 of services/analytics.py),
    # but the dict was unbounded. Cap at 16 keys to keep payloads
    # small; endpoint then merges organization_id from the caller
    # which OVERRIDES any client-supplied value.
    filters: dict[str, Any] | None = Field(default=None)
    limit: int | None = Field(default=1000, ge=1, le=10000)

    @field_validator("filters")
    @classmethod
    def _v_filters(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        if len(v) > 16:
            raise ValueError("filters must contain at most 16 keys")
        for key, val in v.items():
            if not isinstance(key, str) or len(key) > 64:
                raise ValueError("filter keys must be strings <= 64 chars")
            if isinstance(val, str) and len(val) > 256:
                raise ValueError(f"filters['{key}'] exceeds 256 chars")
        return v


class MetricDataPointResponse(BaseSchema):
    """Matches frontend MetricDataPoint interface."""

    timestamp: str
    value: dict[str, Any]
    labels: dict[str, Any] | None = None


class MetricQueryResponse(BaseSchema):
    """Matches frontend MetricQueryResponse interface."""

    metric_name: str
    display_name: str
    unit: str | None = None
    granularity: str
    data_points: list[MetricDataPointResponse]
    aggregations: dict[str, float] | None = None


class MetricRecordRequest(BaseSchema):
    """Record a metric data point."""

    metric_name: str
    value: float
    labels: dict[str, str] | None = None
    timestamp: datetime | None = None
    site_id: UUID | None = None
    device_id: UUID | None = None


# =============================================================================
# Dashboard
# =============================================================================


class DashboardSummaryResponse(BaseSchema):
    """Matches frontend DashboardSummary interface."""

    total_devices: int = 0
    devices_online: int = 0
    devices_offline: int = 0
    devices_warning: int = 0
    total_sites: int = 0
    total_clients: int = 0
    active_alerts: int = 0
    critical_alerts: int = 0
    total_rx_bytes_24h: int = 0
    total_tx_bytes_24h: int = 0
    health_score_avg: float = 0.0
    metrics_summary: dict[str, Any] = Field(default_factory=dict)
    top_issues: list[dict[str, Any]] = Field(default_factory=list)
    recent_alerts: list[dict[str, Any]] = Field(default_factory=list)
    timestamp: str


# =============================================================================
# Device Health
# =============================================================================


class DeviceHealthResponse(BaseSchema):
    """Matches frontend DeviceHealth interface."""

    device_id: str
    device_name: str | None = None
    is_online: bool = False
    health_score: float = 100.0
    health_issues: list[str] = Field(default_factory=list)
    cpu_usage: float | None = None
    memory_usage: float | None = None
    disk_usage: float | None = None
    temperature: float | None = None
    uptime_seconds: float | None = None
    rx_rate_bps: float | None = None
    tx_rate_bps: float | None = None
    client_count: int | None = None
    last_updated: str | None = None


# =============================================================================
# Traffic Analytics
# =============================================================================


class TrafficDataPointResponse(BaseSchema):
    """Matches frontend TrafficDataPoint interface."""

    timestamp: str
    rx_bps: float = 0.0
    tx_bps: float = 0.0
    clients: int = 0


class TrafficAnalyticsResponse(BaseSchema):
    """Matches frontend TrafficAnalytics interface."""

    site_id: str
    period_hours: int
    total_rx_bytes: int = 0
    total_tx_bytes: int = 0
    peak_rx_bps: float = 0.0
    peak_tx_bps: float = 0.0
    avg_rx_bps: float = 0.0
    avg_tx_bps: float = 0.0
    data_points: list[TrafficDataPointResponse] = Field(default_factory=list)
    top_clients: list[dict[str, Any]] = Field(default_factory=list)
    top_applications: list[dict[str, Any]] = Field(default_factory=list)
    traffic_by_category: dict[str, float] = Field(default_factory=dict)


# =============================================================================
# Client Analytics
# =============================================================================


class ClientAnalyticsResponse(BaseSchema):
    """Matches frontend ClientAnalytics interface."""

    total_clients: int = 0
    active_clients: int = 0
    wired_clients: int = 0
    wireless_clients: int = 0
    clients_by_os: dict[str, int] = Field(default_factory=dict)
    clients_by_ssid: dict[str, int] = Field(default_factory=dict)
    avg_signal_strength: float = 0.0
    avg_latency_ms: float = 0.0
    client_list: list[dict[str, Any]] = Field(default_factory=list)


# =============================================================================
# Network Overview
# =============================================================================


class NetworkOverviewResponse(BaseSchema):
    """Matches frontend NetworkOverview interface."""

    site_id: str
    site_name: str
    total_devices: int = 0
    devices_online: int = 0
    devices_offline: int = 0
    total_clients: int = 0
    wired_clients: int = 0
    wireless_clients: int = 0
    guest_clients: int = 0
    total_rx_bytes: int = 0
    total_tx_bytes: int = 0
    wan_utilization: float = 0.0
    active_alerts: int = 0
    timestamp: str


# =============================================================================
# Alerts
# =============================================================================


class AlertCreateRequest(BaseSchema):
    severity: AlertSeverity = AlertSeverity.WARNING
    alert_type: str = "threshold"
    title: str = Field(min_length=1, max_length=500)
    message: str | None = None
    metric_name: str | None = None
    metric_value: dict[str, Any] | None = None
    device_id: UUID | None = None
    site_id: UUID | None = None


class AlertUpdateRequest(BaseSchema):
    status: AlertStatus | None = None
    notes: str | None = None


class AlertResponse(TimestampSchema):
    """Matches frontend AnalyticsAlert interface."""

    id: UUID
    severity: str
    status: str
    alert_type: str
    title: str
    message: str | None = None
    metric_name: str | None = None
    metric_value: dict[str, Any] | None = None
    device_id: UUID | None = None
    site_id: UUID | None = None
    triggered_at: datetime
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    notes: str | None = None


# =============================================================================
# Dashboard Widgets
# =============================================================================


class WidgetCreateRequest(BaseSchema):
    dashboard_name: str = "default"
    title: str = Field(min_length=1, max_length=255)
    widget_type: str = Field(min_length=1, max_length=50)
    position_x: int = Field(default=0, ge=0)
    position_y: int = Field(default=0, ge=0)
    width: int = Field(default=6, ge=1, le=24)
    height: int = Field(default=4, ge=1, le=24)
    metrics: list[str] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)
    aggregation: AggregationType = AggregationType.AVG
    time_range: str = "1h"
    display_options: dict[str, Any] = Field(default_factory=dict)
    refresh_interval_seconds: int = Field(default=60, ge=10, le=3600)


class WidgetUpdateRequest(BaseSchema):
    title: str | None = None
    widget_type: str | None = None
    position_x: int | None = None
    position_y: int | None = None
    width: int | None = None
    height: int | None = None
    metrics: list[str] | None = None
    filters: dict[str, Any] | None = None
    aggregation: AggregationType | None = None
    time_range: str | None = None
    display_options: dict[str, Any] | None = None
    refresh_interval_seconds: int | None = None


class WidgetResponse(TimestampSchema):
    """Matches frontend DashboardWidget interface."""

    id: UUID
    dashboard_name: str
    title: str
    widget_type: str
    position_x: int
    position_y: int
    width: int
    height: int
    metrics: list[str]
    filters: dict[str, Any]
    aggregation: str
    time_range: str
    display_options: dict[str, Any]
    refresh_interval_seconds: int
