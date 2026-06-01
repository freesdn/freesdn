# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Analytics Service
================================

Advanced monitoring and analytics with time-series metrics collection.

Features:
- Time-series metrics collection
- Real-time dashboards
- Anomaly detection with z-score
- Trend analysis
- Custom metrics
- Performance insights
- Aggregation (sum, avg, min, max, percentiles)

Designed for TimescaleDB integration in production.
Ported from FreeSDN v1 with async/await improvements.
"""

import asyncio
import logging
import math
import statistics
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.analytics import (
        AnalyticsAlert,
        DashboardWidget,
        MetricDefinitionRecord,
    )

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================


class MetricType(StrEnum):
    """Types of metrics."""

    COUNTER = "counter"  # Monotonically increasing
    GAUGE = "gauge"  # Point-in-time value
    HISTOGRAM = "histogram"  # Distribution of values
    SUMMARY = "summary"  # Pre-computed percentiles


class AggregationType(StrEnum):
    """Aggregation methods for metrics."""

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


class TrendDirection(StrEnum):
    """Trend direction for analysis."""

    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class MetricPoint:
    """Single metric data point."""

    timestamp: datetime
    value: float
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class MetricDefinition:
    """Metric definition and configuration."""

    name: str
    metric_type: MetricType
    description: str = ""
    unit: str = ""
    labels: list[str] = field(default_factory=list)

    # Retention
    retention_hours: int = 168  # 7 days default

    # Aggregation
    aggregation_interval_seconds: int = 60
    default_aggregation: AggregationType = AggregationType.AVG


@dataclass
class TimeSeriesData:
    """Time series data for a metric."""

    metric_name: str
    labels: dict[str, str]
    points: list[tuple[datetime, float]] = field(default_factory=list)

    def add_point(self, timestamp: datetime, value: float) -> None:
        """Add a data point and keep sorted."""
        self.points.append((timestamp, value))
        self.points.sort(key=lambda x: x[0])

    def get_range(
        self,
        start: datetime,
        end: datetime,
    ) -> list[tuple[datetime, float]]:
        """Get points in time range."""
        return [(ts, val) for ts, val in self.points if start <= ts <= end]

    def aggregate(
        self,
        start: datetime,
        end: datetime,
        method: AggregationType,
    ) -> float | None:
        """Aggregate points in range."""
        points = self.get_range(start, end)
        if not points:
            return None

        values = [val for _, val in points]

        from collections.abc import Callable

        aggregators: dict[AggregationType, Callable[[list[float]], float]] = {
            AggregationType.SUM: lambda v: sum(v),
            AggregationType.AVG: lambda v: statistics.mean(v),
            AggregationType.MIN: lambda v: min(v),
            AggregationType.MAX: lambda v: max(v),
            AggregationType.COUNT: lambda v: float(len(v)),
            AggregationType.LAST: lambda v: v[-1],
            AggregationType.P50: lambda v: self._percentile(v, 50),
            AggregationType.P90: lambda v: self._percentile(v, 90),
            AggregationType.P95: lambda v: self._percentile(v, 95),
            AggregationType.P99: lambda v: self._percentile(v, 99),
        }

        aggregator = aggregators.get(method)
        return aggregator(values) if aggregator else None

    def _percentile(self, values: list[float], percentile: int) -> float:
        """Calculate percentile of values."""
        sorted_values = sorted(values)
        index = (percentile / 100) * (len(sorted_values) - 1)
        lower = math.floor(index)
        upper = math.ceil(index)

        if lower == upper:
            return sorted_values[lower]

        return sorted_values[lower] * (upper - index) + sorted_values[upper] * (index - lower)


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""

    is_anomaly: bool
    z_score: float | None
    baseline_mean: float | None
    baseline_stddev: float | None
    threshold: float


# =============================================================================
# Standard Metrics
# =============================================================================

STANDARD_METRICS: dict[str, MetricDefinition] = {
    # Device metrics
    "device.status": MetricDefinition(
        name="device.status",
        metric_type=MetricType.GAUGE,
        description="Device online/offline status (1=online, 0=offline)",
        labels=["device_id", "site_id", "device_type"],
    ),
    "device.cpu_usage": MetricDefinition(
        name="device.cpu_usage",
        metric_type=MetricType.GAUGE,
        description="Device CPU utilization percentage",
        unit="percent",
        labels=["device_id", "site_id"],
    ),
    "device.memory_usage": MetricDefinition(
        name="device.memory_usage",
        metric_type=MetricType.GAUGE,
        description="Device memory utilization percentage",
        unit="percent",
        labels=["device_id", "site_id"],
    ),
    "device.uptime": MetricDefinition(
        name="device.uptime",
        metric_type=MetricType.GAUGE,
        description="Device uptime in seconds",
        unit="seconds",
        labels=["device_id", "site_id"],
    ),
    # Network metrics
    "network.throughput_rx": MetricDefinition(
        name="network.throughput_rx",
        metric_type=MetricType.COUNTER,
        description="Network receive throughput",
        unit="bytes",
        labels=["device_id", "port", "site_id"],
    ),
    "network.throughput_tx": MetricDefinition(
        name="network.throughput_tx",
        metric_type=MetricType.COUNTER,
        description="Network transmit throughput",
        unit="bytes",
        labels=["device_id", "port", "site_id"],
    ),
    "network.errors": MetricDefinition(
        name="network.errors",
        metric_type=MetricType.COUNTER,
        description="Network errors count",
        labels=["device_id", "port", "site_id", "error_type"],
    ),
    "network.latency": MetricDefinition(
        name="network.latency",
        metric_type=MetricType.HISTOGRAM,
        description="Network latency",
        unit="milliseconds",
        labels=["device_id", "site_id"],
    ),
    # Client metrics
    "client.count": MetricDefinition(
        name="client.count",
        metric_type=MetricType.GAUGE,
        description="Connected client count",
        labels=["site_id", "connection_type", "ssid"],
    ),
    "client.signal_strength": MetricDefinition(
        name="client.signal_strength",
        metric_type=MetricType.GAUGE,
        description="Client wireless signal strength",
        unit="dBm",
        labels=["client_mac", "device_id", "site_id"],
    ),
    # API metrics
    "api.request_count": MetricDefinition(
        name="api.request_count",
        metric_type=MetricType.COUNTER,
        description="API request count",
        labels=["method", "path", "status_code"],
    ),
    "api.request_latency": MetricDefinition(
        name="api.request_latency",
        metric_type=MetricType.HISTOGRAM,
        description="API request latency",
        unit="milliseconds",
        labels=["method", "path"],
    ),
    # Alert metrics
    "alert.active_count": MetricDefinition(
        name="alert.active_count",
        metric_type=MetricType.GAUGE,
        description="Active alert count",
        labels=["site_id", "severity"],
    ),
}


# =============================================================================
# Metrics Collector
# =============================================================================


class MetricsCollector:
    """
    In-memory metrics collector.

    For production, integrate with TimescaleDB or InfluxDB.
    """

    def __init__(self, max_points_per_series: int = 10000):
        self._metrics: dict[str, MetricDefinition] = dict(STANDARD_METRICS)
        self._series: dict[str, TimeSeriesData] = {}
        self._max_points = max_points_per_series
        self._lock = asyncio.Lock()

    def _series_key(self, name: str, labels: dict[str, str]) -> str:
        """Generate unique key for a time series."""
        sorted_labels = sorted(labels.items())
        label_str = ",".join(f"{k}={v}" for k, v in sorted_labels)
        return f"{name}{{{label_str}}}"

    async def record(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        """Record a metric value."""
        labels = labels or {}
        timestamp = timestamp or datetime.now(UTC)

        key = self._series_key(name, labels)

        async with self._lock:
            if key not in self._series:
                self._series[key] = TimeSeriesData(
                    metric_name=name,
                    labels=labels,
                )

            series = self._series[key]
            series.add_point(timestamp, value)

            # Trim old points
            if len(series.points) > self._max_points:
                series.points = series.points[-self._max_points :]

    async def increment(
        self,
        name: str,
        value: float = 1.0,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Increment a counter metric."""
        labels = labels or {}
        key = self._series_key(name, labels)

        async with self._lock:
            if key not in self._series:
                self._series[key] = TimeSeriesData(
                    metric_name=name,
                    labels=labels,
                )

            series = self._series[key]
            last_value = series.points[-1][1] if series.points else 0
            series.add_point(datetime.now(UTC), last_value + value)

    async def query(
        self,
        name: str,
        labels: dict[str, str] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        aggregation: AggregationType | None = None,
        step_seconds: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Query metric data.

        Args:
            name: Metric name
            labels: Label filters (exact match)
            start: Start time
            end: End time
            aggregation: Aggregation method
            step_seconds: Aggregation step size

        Returns:
            List of data points or aggregated values
        """
        labels = labels or {}
        end = end or datetime.now(UTC)
        start = start or (end - timedelta(hours=1))

        # Find matching series
        matching_series = []

        async with self._lock:
            for _key, series in self._series.items():
                if series.metric_name != name:
                    continue

                # Check label match
                match = True
                for k, v in labels.items():
                    if series.labels.get(k) != v:
                        match = False
                        break

                if match:
                    matching_series.append(series)

        results = []

        for series in matching_series:
            if aggregation:
                # Aggregate over time steps
                current = start
                while current < end:
                    step_end = current + timedelta(seconds=step_seconds)
                    value = series.aggregate(current, step_end, aggregation)

                    if value is not None:
                        results.append(
                            {
                                "metric": name,
                                "labels": series.labels,
                                "timestamp": current.isoformat(),
                                "value": value,
                            }
                        )

                    current = step_end
            else:
                # Return raw points
                for ts, val in series.get_range(start, end):
                    results.append(
                        {
                            "metric": name,
                            "labels": series.labels,
                            "timestamp": ts.isoformat(),
                            "value": val,
                        }
                    )

        return results

    async def get_latest(
        self,
        name: str,
        labels: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Get the latest value for a metric."""
        labels = labels or {}
        key = self._series_key(name, labels)

        async with self._lock:
            series = self._series.get(key)
            if series and series.points:
                ts, val = series.points[-1]
                return {
                    "metric": name,
                    "labels": series.labels,
                    "timestamp": ts.isoformat(),
                    "value": val,
                }

        return None

    def register_metric(self, definition: MetricDefinition) -> None:
        """Register a custom metric definition."""
        self._metrics[definition.name] = definition

    def get_metric_definitions(self) -> list[MetricDefinition]:
        """Get all metric definitions."""
        return list(self._metrics.values())


# =============================================================================
# Anomaly Detector
# =============================================================================


class AnomalyDetector:
    """
    Anomaly detection using statistical methods (z-score).
    """

    def __init__(
        self,
        window_size: int = 100,
        z_score_threshold: float = 3.0,
    ):
        self.window_size = window_size
        self.z_score_threshold = z_score_threshold
        self._baselines: dict[str, tuple[float, float]] = {}  # mean, stddev

    def update_baseline(
        self,
        metric_key: str,
        values: list[float],
    ) -> None:
        """Update baseline statistics for a metric."""
        if len(values) < 2:
            return

        mean = statistics.mean(values)
        stddev = statistics.stdev(values)

        self._baselines[metric_key] = (mean, stddev)

    def is_anomaly(
        self,
        metric_key: str,
        value: float,
    ) -> AnomalyResult:
        """
        Check if a value is an anomaly.

        Returns:
            AnomalyResult with detection details
        """
        if metric_key not in self._baselines:
            return AnomalyResult(
                is_anomaly=False,
                z_score=None,
                baseline_mean=None,
                baseline_stddev=None,
                threshold=self.z_score_threshold,
            )

        mean, stddev = self._baselines[metric_key]

        if stddev == 0:
            return AnomalyResult(
                is_anomaly=False,
                z_score=None,
                baseline_mean=mean,
                baseline_stddev=stddev,
                threshold=self.z_score_threshold,
            )

        z_score = abs(value - mean) / stddev

        return AnomalyResult(
            is_anomaly=z_score > self.z_score_threshold,
            z_score=z_score,
            baseline_mean=mean,
            baseline_stddev=stddev,
            threshold=self.z_score_threshold,
        )

    def detect_trend(
        self,
        values: list[float],
        threshold: float = 0.1,
    ) -> TrendDirection:
        """
        Detect trend in values using linear regression.

        Args:
            values: List of values in time order
            threshold: Relative slope threshold

        Returns:
            TrendDirection (increasing, decreasing, stable)
        """
        if len(values) < 3:
            return TrendDirection.STABLE

        # Simple linear regression slope
        n = len(values)
        x_mean = (n - 1) / 2
        y_mean = statistics.mean(values)

        numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            return TrendDirection.STABLE

        slope = numerator / denominator

        # Normalize by mean to get percentage change
        relative_slope = slope / y_mean if y_mean != 0 else 0

        if relative_slope > threshold:
            return TrendDirection.INCREASING
        elif relative_slope < -threshold:
            return TrendDirection.DECREASING
        else:
            return TrendDirection.STABLE


# =============================================================================
# Analytics Service
# =============================================================================


class AnalyticsService:
    """
    High-level analytics service for dashboards and insights.
    """

    def __init__(self, collector: MetricsCollector | None = None):
        self.collector = collector or MetricsCollector()
        self.anomaly_detector = AnomalyDetector()

    async def get_dashboard_summary(
        self,
        organization_id: str,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """Get dashboard summary data."""
        now = datetime.now(UTC)
        hour_ago = now - timedelta(hours=1)

        labels: dict[str, str] = {"organization_id": organization_id}
        if site_id:
            labels["site_id"] = site_id

        # Get device status summary
        device_status = await self.collector.query(
            "device.status",
            labels=labels,
            start=hour_ago,
            aggregation=AggregationType.LAST,
        )

        online_count = sum(1 for d in device_status if d["value"] == 1)
        offline_count = sum(1 for d in device_status if d["value"] == 0)

        # Get client count
        client_data = await self.collector.get_latest(
            "client.count",
            labels=labels,
        )
        client_count = int(client_data["value"]) if client_data else 0

        # Get alert count
        alert_data = await self.collector.get_latest(
            "alert.active_count",
            labels=labels,
        )
        alert_count = int(alert_data["value"]) if alert_data else 0

        # Get throughput
        rx_data = await self.collector.query(
            "network.throughput_rx",
            labels=labels,
            start=hour_ago,
            aggregation=AggregationType.AVG,
            step_seconds=300,
        )

        tx_data = await self.collector.query(
            "network.throughput_tx",
            labels=labels,
            start=hour_ago,
            aggregation=AggregationType.AVG,
            step_seconds=300,
        )

        return {
            "devices": {
                "online": online_count,
                "offline": offline_count,
                "total": online_count + offline_count,
            },
            "clients": {
                "total": client_count,
            },
            "alerts": {
                "active": alert_count,
            },
            "network": {
                "throughput_rx": rx_data,
                "throughput_tx": tx_data,
            },
            "generated_at": now.isoformat(),
        }

    async def get_device_metrics(
        self,
        device_id: str,
        site_id: str,
        hours: int = 24,
    ) -> dict[str, Any]:
        """Get metrics for a specific device."""
        now = datetime.now(UTC)
        start = now - timedelta(hours=hours)
        labels = {"device_id": device_id, "site_id": site_id}

        cpu_data = await self.collector.query(
            "device.cpu_usage",
            labels=labels,
            start=start,
            aggregation=AggregationType.AVG,
            step_seconds=300,
        )

        memory_data = await self.collector.query(
            "device.memory_usage",
            labels=labels,
            start=start,
            aggregation=AggregationType.AVG,
            step_seconds=300,
        )

        uptime = await self.collector.get_latest(
            "device.uptime",
            labels=labels,
        )

        return {
            "device_id": device_id,
            "site_id": site_id,
            "period_hours": hours,
            "cpu_usage": cpu_data,
            "memory_usage": memory_data,
            "uptime_seconds": uptime["value"] if uptime else None,
            "generated_at": now.isoformat(),
        }

    async def detect_anomalies(
        self,
        metric_name: str,
        labels: dict[str, str] | None = None,
        hours: int = 24,
    ) -> list[dict[str, Any]]:
        """Detect anomalies in metric data."""
        now = datetime.now(UTC)
        start = now - timedelta(hours=hours)

        data = await self.collector.query(
            metric_name,
            labels=labels,
            start=start,
        )

        if not data:
            return []

        # Get values and update baseline
        values = [d["value"] for d in data]
        metric_key = f"{metric_name}:{labels or {}}"
        self.anomaly_detector.update_baseline(metric_key, values)

        # Check each point for anomalies
        anomalies = []
        for point in data:
            result = self.anomaly_detector.is_anomaly(metric_key, point["value"])
            if result.is_anomaly:
                anomalies.append(
                    {
                        **point,
                        "z_score": result.z_score,
                        "baseline_mean": result.baseline_mean,
                        "baseline_stddev": result.baseline_stddev,
                    }
                )

        return anomalies

    async def analyze_trend(
        self,
        metric_name: str,
        labels: dict[str, str] | None = None,
        hours: int = 24,
    ) -> dict[str, Any]:
        """Analyze trend for a metric."""
        now = datetime.now(UTC)
        start = now - timedelta(hours=hours)

        data = await self.collector.query(
            metric_name,
            labels=labels,
            start=start,
        )

        if not data:
            return {
                "metric": metric_name,
                "labels": labels,
                "trend": TrendDirection.STABLE.value,
                "data_points": 0,
            }

        values = [d["value"] for d in data]
        trend = self.anomaly_detector.detect_trend(values)

        return {
            "metric": metric_name,
            "labels": labels,
            "trend": trend.value,
            "data_points": len(values),
            "min": min(values),
            "max": max(values),
            "avg": statistics.mean(values),
            "current": values[-1],
        }


# =============================================================================
# Global Collector Instance
# =============================================================================

# Singleton collector for the application
_metrics_collector: MetricsCollector | None = None
_metrics_collector_lock: asyncio.Lock | None = None


async def get_metrics_collector() -> MetricsCollector:
    """Get or create the global metrics collector (async-safe)."""
    global _metrics_collector, _metrics_collector_lock
    if _metrics_collector is not None:
        return _metrics_collector
    if _metrics_collector_lock is None:
        _metrics_collector_lock = asyncio.Lock()
    async with _metrics_collector_lock:
        if _metrics_collector is None:
            _metrics_collector = MetricsCollector()
        return _metrics_collector


async def get_analytics_service() -> AnalyticsService:
    """Get an analytics service instance."""
    collector = await get_metrics_collector()
    return AnalyticsService(collector)


# =============================================================================
# Persistent Analytics Service (DB-backed via TimescaleDB)
# =============================================================================


class PersistentAnalyticsService:
    """
    DB-backed analytics service using TimescaleDB hypertables.

    Provides:
    - Metric data persistence and querying
    - Metric definition CRUD
    - Dashboard summary from DB
    - Device health scoring
    - Alert management
    - Dashboard widget CRUD
    - Traffic and client analytics
    """

    # ------- Metric Definitions -------

    @staticmethod
    async def list_metric_definitions(
        session: "AsyncSession",
        category: str | None = None,
        is_active: bool | None = None,
    ) -> list["MetricDefinitionRecord"]:
        from sqlalchemy import select

        from app.models.analytics import MetricDefinitionRecord

        stmt = select(MetricDefinitionRecord)
        if category:
            stmt = stmt.where(MetricDefinitionRecord.category == category)
        if is_active is not None:
            stmt = stmt.where(MetricDefinitionRecord.is_active == is_active)
        stmt = stmt.order_by(MetricDefinitionRecord.category, MetricDefinitionRecord.name)

        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_metric_definition(
        session: "AsyncSession",
        metric_name: str,
    ) -> "MetricDefinitionRecord | None":
        from sqlalchemy import select

        from app.models.analytics import MetricDefinitionRecord

        result = await session.execute(
            select(MetricDefinitionRecord).where(MetricDefinitionRecord.name == metric_name)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create_metric_definition(
        session: "AsyncSession",
        data: dict[str, Any],
        created_by: "UUID | None" = None,
    ) -> "MetricDefinitionRecord":
        from app.models.analytics import MetricDefinitionRecord

        record = MetricDefinitionRecord(**data)
        if created_by:
            record.created_by = created_by
        session.add(record)
        await session.flush()
        return record

    @staticmethod
    async def update_metric_definition(
        session: "AsyncSession",
        metric_name: str,
        data: dict[str, Any],
    ) -> "MetricDefinitionRecord | None":
        from sqlalchemy import select

        from app.models.analytics import MetricDefinitionRecord

        result = await session.execute(
            select(MetricDefinitionRecord).where(MetricDefinitionRecord.name == metric_name)
        )
        record = result.scalar_one_or_none()
        if not record:
            return None
        for key, value in data.items():
            if value is not None:
                setattr(record, key, value)
        await session.flush()
        return record

    # ------- Metric Data Points -------

    @staticmethod
    async def record_metric(
        session: "AsyncSession",
        metric_name: str,
        value: float,
        labels: dict[str, str] | None = None,
        timestamp: "datetime | None" = None,
        organization_id: "UUID | None" = None,
        site_id: "UUID | None" = None,
        device_id: "UUID | None" = None,
    ) -> None:
        """Insert a metric data point into the hypertable."""
        import hashlib

        from app.models.analytics import MetricDataPoint

        labels = labels or {}
        now = timestamp or datetime.now(UTC)
        labels_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        labels_hash = hashlib.md5(labels_str.encode()).hexdigest()[:16]

        point = MetricDataPoint(
            time=now,
            metric_name=metric_name,
            labels_hash=labels_hash,
            value=value,
            labels=labels,
            organization_id=organization_id,
            site_id=site_id,
            device_id=device_id,
        )
        session.add(point)
        await session.flush()

    @staticmethod
    async def record_metrics_batch(
        session: "AsyncSession",
        points: list[dict[str, Any]],
    ) -> int:
        """Bulk-insert metric data points."""
        import hashlib

        from app.models.analytics import MetricDataPoint

        objs = []
        for p in points:
            labels = p.get("labels") or {}
            labels_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
            labels_hash = hashlib.md5(labels_str.encode()).hexdigest()[:16]
            objs.append(
                MetricDataPoint(
                    time=p.get("timestamp") or datetime.now(UTC),
                    metric_name=p["metric_name"],
                    labels_hash=labels_hash,
                    value=p["value"],
                    labels=labels,
                    organization_id=p.get("organization_id"),
                    site_id=p.get("site_id"),
                    device_id=p.get("device_id"),
                )
            )
        session.add_all(objs)
        await session.flush()
        return len(objs)

    @staticmethod
    async def query_metrics(
        session: "AsyncSession",
        metric_name: str,
        start_time: "datetime | None" = None,
        end_time: "datetime | None" = None,
        granularity: str = "5m",
        aggregation: str = "avg",
        filters: dict[str, Any] | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Query metric data with time bucketing via TimescaleDB time_bucket().

        Returns list of {timestamp, value, labels} dicts.
        """
        from sqlalchemy import text

        end_time = end_time or datetime.now(UTC)
        start_time = start_time or (end_time - timedelta(hours=1))

        # Map granularity to a timedelta. asyncpg encodes a datetime.timedelta
        # as a PG ``interval`` natively; a raw string ('1 minute') bound to
        # time_bucket's interval arg fails (DataError: 'str' object has no
        # attribute 'days'), and a SQL CAST does not help because Postgres still
        # infers the bind-param type as interval.
        interval_map = {
            "raw": None,
            "1m": timedelta(minutes=1),
            "5m": timedelta(minutes=5),
            "15m": timedelta(minutes=15),
            "1h": timedelta(hours=1),
            "1d": timedelta(days=1),
            "1w": timedelta(weeks=1),
        }
        interval = interval_map.get(granularity)

        # Map aggregation to SQL function
        agg_map = {
            "sum": "SUM",
            "avg": "AVG",
            "min": "MIN",
            "max": "MAX",
            "count": "COUNT",
            "last": "last",
        }
        agg_func = agg_map.get(aggregation, "AVG")

        # Build filter clauses
        extra_where = ""
        params: dict[str, Any] = {
            "metric_name": metric_name,
            "start_time": start_time,
            "end_time": end_time,
            "limit": limit,
        }

        if filters:
            if "site_id" in filters:
                extra_where += " AND site_id = :site_id"
                params["site_id"] = filters["site_id"]
            # SITE-GRANT: callers pass ``site_id_in`` (a list of
            # the request's granted site IDs) so a site-limited operator who
            # did NOT pin a single site is still constrained to sites they own,
            # rather than reading org-wide time-series across sibling sites.
            # Bound the IN list and parameterise each id (no SQL injection).
            site_id_in = filters.get("site_id_in")
            if site_id_in:
                ids = [str(s) for s in site_id_in][:500]
                placeholders = ", ".join(f":site_in_{i}" for i in range(len(ids)))
                extra_where += f" AND site_id IN ({placeholders})"
                for i, sid in enumerate(ids):
                    params[f"site_in_{i}"] = sid
            if "device_id" in filters:
                extra_where += " AND device_id = :device_id"
                params["device_id"] = filters["device_id"]
            if "organization_id" in filters:
                extra_where += " AND organization_id = :organization_id"
                params["organization_id"] = filters["organization_id"]

        if interval and agg_func != "last":
            sql = f"""
                SELECT
                    time_bucket(:interval, time) AS bucket,
                    {agg_func}(value) AS agg_value
                FROM analytics.metric_data
                WHERE metric_name = :metric_name
                  AND time >= :start_time
                  AND time < :end_time
                  {extra_where}
                GROUP BY bucket
                ORDER BY bucket
                LIMIT :limit
            """
            params["interval"] = interval
        else:
            # Raw data
            sql = f"""
                SELECT time AS bucket, value AS agg_value
                FROM analytics.metric_data
                WHERE metric_name = :metric_name
                  AND time >= :start_time
                  AND time < :end_time
                  {extra_where}
                ORDER BY time
                LIMIT :limit
            """

        result = await session.execute(text(sql), params)
        rows = result.fetchall()

        return [
            {"timestamp": row.bucket.isoformat(), "value": {"value": row.agg_value}} for row in rows
        ]

    @staticmethod
    async def get_latest_metric(
        session: "AsyncSession",
        metric_name: str,
        site_id: "UUID | None" = None,
        device_id: "UUID | None" = None,
        organization_id: "UUID | None" = None,
        accessible_site_ids: "set[UUID] | None" = None,
    ) -> dict[str, Any] | None:
        """Get the most recent data point for a metric.

        SITE-GRANT: when ``accessible_site_ids`` is supplied (a
        site-limited caller's granted set who pinned neither a site nor a
        device), constrain the latest lookup to those sites so the org-wide
        latest never leaks a sibling site's data point. An empty granted set
        is fail-closed (returns no rows). ``None`` = unrestricted (admin).
        """
        from sqlalchemy import text

        extra_where = ""
        params: dict[str, Any] = {"metric_name": metric_name}
        if organization_id:
            extra_where += " AND organization_id = :organization_id"
            params["organization_id"] = str(organization_id)
        if site_id:
            extra_where += " AND site_id = :site_id"
            params["site_id"] = site_id
        if device_id:
            extra_where += " AND device_id = :device_id"
            params["device_id"] = device_id
        if accessible_site_ids is not None:
            # Fail-closed: a site-limited caller with zero grants must match no
            # rows rather than fall through to an org-wide latest. Bound + bind
            # each id (no SQL injection).
            ids = [str(s) for s in accessible_site_ids][:500]
            if ids:
                placeholders = ", ".join(f":grant_site_{i}" for i in range(len(ids)))
                extra_where += f" AND site_id IN ({placeholders})"
                for i, sid in enumerate(ids):
                    params[f"grant_site_{i}"] = sid
            else:
                extra_where += " AND 1 = 0"

        sql = f"""
            SELECT time, value, labels
            FROM analytics.metric_data
            WHERE metric_name = :metric_name {extra_where}
            ORDER BY time DESC
            LIMIT 1
        """
        result = await session.execute(text(sql), params)
        row = result.fetchone()
        if not row:
            return None
        return {
            "timestamp": row.time.isoformat(),
            "value": {"value": row.value},
            "labels": row.labels,
        }

    # ------- Dashboard Summary -------

    @staticmethod
    async def get_dashboard_summary(
        session: "AsyncSession",
        organization_id: "UUID | None" = None,
        site_id: "UUID | None" = None,
        accessible_site_ids: "set[UUID] | None" = None,
    ) -> dict[str, Any]:
        """Aggregate dashboard summary from DB tables.

        SITE-GRANT: when ``accessible_site_ids`` is supplied (a
        site-limited caller's granted set), every site-/device-scoped sub-query
        is constrained to those sites so the org-wide summary never leaks
        sibling-site counts. ``None`` = unrestricted (super/org admin).
        """
        from sqlalchemy import func, select, text
        from sqlalchemy.exc import SQLAlchemyError

        from app.models.core import Site
        from app.models.devices import Device, DeviceStatus

        now = datetime.now(UTC)
        grant_ids = list(accessible_site_ids) if accessible_site_ids is not None else None

        # Device counts — always scoped to organization
        device_q = select(
            func.count().label("total"),
            func.count().filter(Device.status == DeviceStatus.ONLINE).label("online"),
            func.count().filter(Device.status == DeviceStatus.OFFLINE).label("offline"),
        ).select_from(Device)
        if organization_id:
            device_q = device_q.where(
                Device.site_id.in_(select(Site.id).where(Site.organization_id == organization_id))
            )
        if grant_ids is not None:
            device_q = device_q.where(Device.site_id.in_(grant_ids))
        if site_id:
            device_q = device_q.where(Device.site_id == site_id)
        device_row = (await session.execute(device_q)).one()

        # Site count
        site_q = select(func.count()).select_from(Site)
        if organization_id:
            site_q = site_q.where(Site.organization_id == organization_id)
        if grant_ids is not None:
            site_q = site_q.where(Site.id.in_(grant_ids))
        total_sites = (await session.execute(site_q)).scalar() or 0

        # Alert counts
        alert_active = 0
        alert_critical = 0
        try:
            from app.models.analytics import AlertSeverity as ASev
            from app.models.analytics import AlertStatus as AS
            from app.models.analytics import AnalyticsAlert

            alert_q = select(
                func.count().label("active"),
                func.count().filter(AnalyticsAlert.severity == ASev.CRITICAL).label("critical"),
            ).where(AnalyticsAlert.status == AS.ACTIVE)
            if organization_id:
                alert_q = alert_q.where(AnalyticsAlert.organization_id == organization_id)
            if grant_ids is not None:
                alert_q = alert_q.where(
                    AnalyticsAlert.site_id.in_(grant_ids) | AnalyticsAlert.site_id.is_(None)
                )
            if site_id:
                alert_q = alert_q.where(AnalyticsAlert.site_id == site_id)
            alert_row = (await session.execute(alert_q)).one()
            alert_active = alert_row.active
            alert_critical = alert_row.critical
        except (ImportError, SQLAlchemyError):
            pass

        # Device warning count (devices with status not ONLINE or OFFLINE, e.g. degraded/error)
        devices_warning = 0
        try:
            warn_q = (
                select(func.count())
                .select_from(Device)
                .where(
                    Device.status.notin_([DeviceStatus.ONLINE, DeviceStatus.OFFLINE]),
                )
            )
            if organization_id:
                warn_q = warn_q.where(
                    Device.site_id.in_(
                        select(Site.id).where(Site.organization_id == organization_id)
                    )
                )
            if grant_ids is not None:
                warn_q = warn_q.where(Device.site_id.in_(grant_ids))
            if site_id:
                warn_q = warn_q.where(Device.site_id == site_id)
            devices_warning = (await session.execute(warn_q)).scalar() or 0
        except SQLAlchemyError:
            pass

        # Client counts from DeviceClient table
        total_clients = 0
        try:
            from app.models.devices import DeviceClient

            client_q = (
                select(func.count())
                .select_from(DeviceClient)
                .where(
                    DeviceClient.is_online.is_(True),
                )
            )
            if organization_id:
                client_q = client_q.join(Device, DeviceClient.device_id == Device.id).where(
                    Device.site_id.in_(
                        select(Site.id).where(Site.organization_id == organization_id)
                    ),
                )
            if grant_ids is not None:
                if not organization_id:
                    client_q = client_q.join(Device, DeviceClient.device_id == Device.id)
                client_q = client_q.where(Device.site_id.in_(grant_ids))
            if site_id:
                if not organization_id and grant_ids is None:
                    client_q = client_q.join(Device, DeviceClient.device_id == Device.id)
                client_q = client_q.where(Device.site_id == site_id)
            total_clients = (await session.execute(client_q)).scalar() or 0
        except (ImportError, SQLAlchemyError):
            pass

        # Traffic bytes in last 24h from DeviceClient aggregates
        total_rx_bytes_24h = 0
        total_tx_bytes_24h = 0
        try:
            from app.models.devices import DeviceClient

            cutoff = now - timedelta(hours=24)
            traffic_q = (
                select(
                    func.coalesce(func.sum(DeviceClient.rx_bytes), 0).label("rx"),
                    func.coalesce(func.sum(DeviceClient.tx_bytes), 0).label("tx"),
                )
                .select_from(DeviceClient)
                .where(
                    DeviceClient.last_seen >= cutoff,
                )
            )
            if organization_id:
                traffic_q = traffic_q.join(Device, DeviceClient.device_id == Device.id).where(
                    Device.site_id.in_(
                        select(Site.id).where(Site.organization_id == organization_id)
                    ),
                )
            if grant_ids is not None:
                if not organization_id:
                    traffic_q = traffic_q.join(Device, DeviceClient.device_id == Device.id)
                traffic_q = traffic_q.where(Device.site_id.in_(grant_ids))
            if site_id:
                if not organization_id and grant_ids is None:
                    traffic_q = traffic_q.join(Device, DeviceClient.device_id == Device.id)
                traffic_q = traffic_q.where(Device.site_id == site_id)
            traffic_row = (await session.execute(traffic_q)).one()
            total_rx_bytes_24h = int(traffic_row.rx)
            total_tx_bytes_24h = int(traffic_row.tx)
        except (ImportError, SQLAlchemyError):
            pass

        # Health score average from device metadata
        health_score_avg = 0.0
        try:
            health_q = (
                select(
                    func.avg(Device.device_metadata["health_score"].as_float()),
                )
                .select_from(Device)
                .where(
                    Device.status == DeviceStatus.ONLINE,
                    Device.device_metadata["health_score"] != text("'null'"),
                )
            )
            if organization_id:
                health_q = health_q.where(
                    Device.site_id.in_(
                        select(Site.id).where(Site.organization_id == organization_id)
                    )
                )
            if grant_ids is not None:
                health_q = health_q.where(Device.site_id.in_(grant_ids))
            if site_id:
                health_q = health_q.where(Device.site_id == site_id)
            health_result = (await session.execute(health_q)).scalar()
            if health_result is not None:
                health_score_avg = round(float(health_result), 1)
        except SQLAlchemyError:
            pass

        # Recent alerts
        recent_alerts: list[dict[str, Any]] = []
        try:
            from app.models.analytics import AnalyticsAlert

            ra_q = (
                select(AnalyticsAlert)
                .where(AnalyticsAlert.status == "active")
                .order_by(AnalyticsAlert.triggered_at.desc())
                .limit(5)
            )
            if organization_id:
                ra_q = ra_q.where(AnalyticsAlert.organization_id == organization_id)
            if grant_ids is not None:
                ra_q = ra_q.where(
                    AnalyticsAlert.site_id.in_(grant_ids) | AnalyticsAlert.site_id.is_(None)
                )
            # the Activity Feed (recent_alerts) stayed org-wide
            # in site mode while active_alerts/top_issues narrowed by site.
            if site_id:
                ra_q = ra_q.where(AnalyticsAlert.site_id == site_id)
            ra_result = await session.execute(ra_q)
            for a in ra_result.scalars().all():
                recent_alerts.append(
                    {
                        "id": str(a.id),
                        "severity": a.severity,
                        "status": a.status,
                        "title": a.title,
                        "triggered_at": a.triggered_at.isoformat(),
                    }
                )
        except (ImportError, SQLAlchemyError):
            pass

        # Top issues from critical/warning alerts
        top_issues: list[dict[str, Any]] = []
        try:
            from app.models.analytics import AlertStatus as _AS
            from app.models.analytics import AnalyticsAlert

            issues_q = (
                select(AnalyticsAlert)
                .where(AnalyticsAlert.status == _AS.ACTIVE)
                .order_by(AnalyticsAlert.severity.desc(), AnalyticsAlert.triggered_at.desc())
                .limit(5)
            )
            if organization_id:
                issues_q = issues_q.where(AnalyticsAlert.organization_id == organization_id)
            if grant_ids is not None:
                issues_q = issues_q.where(
                    AnalyticsAlert.site_id.in_(grant_ids) | AnalyticsAlert.site_id.is_(None)
                )
            if site_id:
                issues_q = issues_q.where(AnalyticsAlert.site_id == site_id)
            issues_result = await session.execute(issues_q)
            for issue in issues_result.scalars().all():
                top_issues.append(
                    {
                        "id": str(issue.id),
                        "title": issue.title,
                        "severity": issue.severity,
                        "triggered_at": issue.triggered_at.isoformat(),
                    }
                )
        except (ImportError, SQLAlchemyError):
            pass

        return {
            "total_devices": device_row.total,
            "devices_online": device_row.online,
            "devices_offline": device_row.offline,
            "devices_warning": devices_warning,
            "total_sites": total_sites,
            "total_clients": total_clients,
            "active_alerts": alert_active,
            "critical_alerts": alert_critical,
            "total_rx_bytes_24h": total_rx_bytes_24h,
            "total_tx_bytes_24h": total_tx_bytes_24h,
            "health_score_avg": health_score_avg,
            "metrics_summary": {
                "api_calls": 0,
                "events_processed": 0,
                "automation_executions": 0,
            },
            "top_issues": top_issues,
            "recent_alerts": recent_alerts,
            "timestamp": now.isoformat(),
        }

    # ------- Device Health -------

    @staticmethod
    async def get_device_health(
        session: "AsyncSession",
        logdb: "AsyncSession",
        device_id: "UUID",
    ) -> dict[str, Any] | None:
        """Calculate device health score from recent metrics.

        ``session`` = main DB (Device row); ``logdb`` = LogDB (metric_data
        hypertable). Mixing them on one session 500'd "relation
        analytics.metric_data does not exist".
        """
        from sqlalchemy import select

        from app.models.devices import Device

        result = await session.execute(
            select(Device).where(Device.id == device_id, Device.deleted_at.is_(None))
        )
        device = result.scalar_one_or_none()
        if not device:
            return None

        health_score = 100.0
        issues: list[str] = []

        # Get latest CPU/memory from the LogDB hypertable (metric_data).
        cpu_val = await PersistentAnalyticsService.get_latest_metric(
            logdb,
            "device.cpu_usage",
            device_id=device_id,
        )
        mem_val = await PersistentAnalyticsService.get_latest_metric(
            logdb,
            "device.memory_usage",
            device_id=device_id,
        )
        uptime_val = await PersistentAnalyticsService.get_latest_metric(
            logdb,
            "device.uptime",
            device_id=device_id,
        )

        cpu_usage = cpu_val["value"]["value"] if cpu_val else None
        mem_usage = mem_val["value"]["value"] if mem_val else None
        uptime = uptime_val["value"]["value"] if uptime_val else None

        if cpu_usage is not None:
            if cpu_usage > 90:
                health_score -= 30
                issues.append("CPU over 90%")
            elif cpu_usage > 70:
                health_score -= 15
                issues.append("CPU over 70%")

        if mem_usage is not None:
            if mem_usage > 90:
                health_score -= 30
                issues.append("Memory over 90%")
            elif mem_usage > 70:
                health_score -= 15
                issues.append("Memory over 70%")

        is_online = str(device.status) == "online"
        if not is_online:
            health_score -= 40
            issues.append("Device offline")

        return {
            "device_id": str(device.id),
            "device_name": device.name,
            "is_online": is_online,
            "health_score": max(0.0, health_score),
            "health_issues": issues,
            "cpu_usage": cpu_usage,
            "memory_usage": mem_usage,
            "uptime_seconds": uptime,
            "last_updated": datetime.now(UTC).isoformat(),
        }

    @staticmethod
    async def get_devices_health(
        session: "AsyncSession",
        logdb: "AsyncSession",
        site_id: "UUID | None" = None,
        device_type: str | None = None,
        limit: int = 50,
        organization_id: "UUID | None" = None,
        accessible_site_ids: "set[UUID] | None" = None,
    ) -> list[dict[str, Any]]:
        """Get health for multiple devices.

        SITE-GRANT: when ``accessible_site_ids`` is supplied
        (a site-limited caller's granted set), constrain the device fleet to
        those sites so the org-wide list never leaks sibling-site devices.
        ``None`` means unrestricted (super/org admin) — no extra filter.
        """
        from sqlalchemy import select

        from app.models.devices import Device

        stmt = select(Device).where(Device.deleted_at.is_(None))
        if organization_id:
            from app.models.core import Site

            stmt = stmt.where(
                Device.site_id.in_(select(Site.id).where(Site.organization_id == organization_id))
            )
        if accessible_site_ids is not None:
            stmt = stmt.where(Device.site_id.in_(list(accessible_site_ids)))
        if site_id:
            stmt = stmt.where(Device.site_id == site_id)
        if device_type:
            stmt = stmt.where(Device.type == device_type)
        stmt = stmt.limit(limit)

        result = await session.execute(stmt)
        devices = result.scalars().all()

        health_list = []
        for dev in devices:
            h = await PersistentAnalyticsService.get_device_health(session, logdb, dev.id)
            if h:
                health_list.append(h)

        return health_list

    # ------- Alerts -------

    @staticmethod
    async def create_alert(
        session: "AsyncSession",
        data: dict[str, Any],
        created_by: "UUID | None" = None,
    ) -> "AnalyticsAlert":
        from app.models.analytics import AnalyticsAlert

        alert = AnalyticsAlert(
            triggered_at=datetime.now(UTC),
            **data,
        )
        if created_by:
            alert.created_by = created_by
        session.add(alert)
        await session.flush()
        return alert

    @staticmethod
    async def list_alerts(
        session: "AsyncSession",
        status: str | None = None,
        severity: str | None = None,
        site_id: "UUID | None" = None,
        limit: int = 50,
        organization_id: "UUID | None" = None,
        accessible_site_ids: "set[UUID] | None" = None,
    ) -> list["AnalyticsAlert"]:
        """List analytics alerts.

        SITE-GRANT: when ``accessible_site_ids`` is supplied, a
        site-limited caller only sees alerts for granted sites. ``None`` =
        unrestricted (super/org admin). Org-level alerts (NULL site_id) stay
        visible to site-limited users intentionally — they aren't site-bound.
        """
        from sqlalchemy import select

        from app.models.analytics import AnalyticsAlert

        stmt = select(AnalyticsAlert)
        if organization_id:
            stmt = stmt.where(AnalyticsAlert.organization_id == organization_id)
        if accessible_site_ids is not None:
            stmt = stmt.where(
                AnalyticsAlert.site_id.in_(list(accessible_site_ids))
                | AnalyticsAlert.site_id.is_(None)
            )
        if status:
            stmt = stmt.where(AnalyticsAlert.status == status)
        if severity:
            stmt = stmt.where(AnalyticsAlert.severity == severity)
        if site_id:
            stmt = stmt.where(AnalyticsAlert.site_id == site_id)
        stmt = stmt.order_by(AnalyticsAlert.triggered_at.desc()).limit(limit)

        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def update_alert(
        session: "AsyncSession",
        alert_id: "UUID",
        data: dict[str, Any],
        updated_by: "UUID | None" = None,
    ) -> "AnalyticsAlert | None":
        from sqlalchemy import select

        from app.models.analytics import AnalyticsAlert

        result = await session.execute(select(AnalyticsAlert).where(AnalyticsAlert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return None

        for key, value in data.items():
            if value is not None:
                setattr(alert, key, value)

        if data.get("status") == "acknowledged":
            alert.acknowledged_at = datetime.now(UTC)
            alert.acknowledged_by = updated_by
        elif data.get("status") == "resolved":
            alert.resolved_at = datetime.now(UTC)

        if updated_by:
            alert.updated_by = updated_by
        await session.flush()
        return alert

    # ------- Dashboard Widgets -------

    @staticmethod
    async def list_widgets(
        session: "AsyncSession",
        dashboard_name: str | None = None,
        owner_id: "UUID | None" = None,
        organization_id: "UUID | None" = None,
    ) -> list["DashboardWidget"]:
        from sqlalchemy import select

        from app.models.analytics import DashboardWidget

        stmt = select(DashboardWidget)
        if organization_id:
            stmt = stmt.where(DashboardWidget.organization_id == organization_id)
        if dashboard_name:
            stmt = stmt.where(DashboardWidget.dashboard_name == dashboard_name)
        if owner_id:
            stmt = stmt.where(DashboardWidget.owner_id == owner_id)
        stmt = stmt.order_by(DashboardWidget.position_y, DashboardWidget.position_x)

        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def create_widget(
        session: "AsyncSession",
        data: dict[str, Any],
        owner_id: "UUID | None" = None,
        organization_id: "UUID | None" = None,
    ) -> "DashboardWidget":
        from app.models.analytics import DashboardWidget

        widget = DashboardWidget(**data, owner_id=owner_id, organization_id=organization_id)
        session.add(widget)
        await session.flush()
        return widget

    @staticmethod
    async def update_widget(
        session: "AsyncSession",
        widget_id: "UUID",
        data: dict[str, Any],
    ) -> "DashboardWidget | None":
        from sqlalchemy import select

        from app.models.analytics import DashboardWidget

        result = await session.execute(
            select(DashboardWidget).where(DashboardWidget.id == widget_id)
        )
        widget = result.scalar_one_or_none()
        if not widget:
            return None
        for key, value in data.items():
            if value is not None:
                setattr(widget, key, value)
        await session.flush()
        return widget

    @staticmethod
    async def delete_widget(
        session: "AsyncSession",
        widget_id: "UUID",
    ) -> bool:
        from sqlalchemy import delete

        from app.models.analytics import DashboardWidget

        result = await session.execute(
            delete(DashboardWidget).where(DashboardWidget.id == widget_id)
        )
        return bool(result.rowcount > 0)

    # ------- Cleanup -------

    @staticmethod
    async def purge_old_metrics(
        session: "AsyncSession",
        retention_hours: int = 168,
    ) -> int:
        """Delete metric data points older than retention period."""
        from sqlalchemy import text

        cutoff = datetime.now(UTC) - timedelta(hours=retention_hours)
        result = await session.execute(
            text("DELETE FROM analytics.metric_data WHERE time < :cutoff"),
            {"cutoff": cutoff},
        )
        return int(result.rowcount or 0)

    @staticmethod
    async def resolve_stale_alerts(
        session: "AsyncSession",
        hours: int = 72,
    ) -> int:
        """Auto-resolve alerts older than threshold."""
        from sqlalchemy import update

        from app.models.analytics import AnalyticsAlert

        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        result = await session.execute(
            update(AnalyticsAlert)
            .where(AnalyticsAlert.status == "active")
            .where(AnalyticsAlert.triggered_at < cutoff)
            .values(status="resolved", resolved_at=datetime.now(UTC))
        )
        return int(result.rowcount or 0)
