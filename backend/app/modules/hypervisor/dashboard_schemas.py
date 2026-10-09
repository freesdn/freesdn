# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Dashboard observations describe visible evidence, never missing data as zero."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

MetricIssue = Literal[
    "missing_statistics", "invalid_statistics", "node_not_online", "inventory_mismatch"
]


class DashboardMetricCoverage(BaseModel):
    status: Literal["available", "partial", "unavailable"]
    expected_nodes: int = Field(ge=0)
    observed_nodes: int = Field(ge=0)
    reasons: list[MetricIssue] = Field(default_factory=list)


def unavailable_metric() -> DashboardMetricCoverage:
    return DashboardMetricCoverage(status="unavailable", expected_nodes=0, observed_nodes=0)


class DashboardCoverage(BaseModel):
    cpu: DashboardMetricCoverage = Field(default_factory=unavailable_metric)
    memory: DashboardMetricCoverage = Field(default_factory=unavailable_metric)
    node_filesystem: DashboardMetricCoverage = Field(default_factory=unavailable_metric)


class DashboardNodeObservation(BaseModel):
    node: str
    status: Literal["online", "offline", "unknown"]


class DashboardMetrics(BaseModel):
    total_nodes: int | None = None
    online_nodes: int | None = None
    total_vms: int | None = None
    running_vms: int | None = None
    total_containers: int | None = None
    running_containers: int | None = None
    total_cpu_cores: int | None = None
    used_cpu_cores: float | None = None
    cpu_usage_percent: float | None = None
    total_memory_bytes: int | None = None
    used_memory_bytes: int | None = None
    memory_usage_percent: float | None = None
    # Compatibility names retained; these have always used NODE resource rows.
    total_storage_bytes: int | None = None
    used_storage_bytes: int | None = None
    storage_usage_percent: float | None = None
    metric_coverage: DashboardCoverage = Field(default_factory=DashboardCoverage)
    coverage: Literal["complete_visible", "partial", "unavailable"] = "unavailable"
    inventory_scope: Literal["credential_visible"] = "credential_visible"
    storage_scope: Literal["node_filesystems"] = "node_filesystems"
    provider_sample_time_known: Literal[False] = False
    collection_started_at: datetime | None = None
    observed_at: datetime | None = None
    served_at: datetime | None = None
    observation_age_seconds: float | None = None
    stale_after_seconds: Literal[90] = 90


class HypervisorDashboardResponse(DashboardMetrics):
    controller_id: str = ""
    cluster_name: str = ""
    quorate: bool | None = None
    ha_active: bool | None = Field(
        default=None,
        deprecated=True,
        description="HA health is not established by a status-list read; always unknown.",
    )
    ha_services_visible: int | None = None
    nodes: list[DashboardNodeObservation] = Field(default_factory=list)


class FleetClusterSummary(HypervisorDashboardResponse):
    controller_name: str
    status: Literal["online", "error"] = "error"
    error: str = ""


class FleetDashboardResponse(DashboardMetrics):
    total_clusters: int = 0
    online_clusters: int = 0
    failed_clusters: int = 0
    aggregation_scope: Literal["controller_registrations"] = "controller_registrations"
    deduplicated: Literal[False] = False
    clusters: list[FleetClusterSummary] = Field(default_factory=list)
