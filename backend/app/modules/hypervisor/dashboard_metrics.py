# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Strict aggregation of credential-visible Proxmox dashboard observations."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, Literal, cast

from app.adapters.proxmox.models import ProxmoxClusterStatus
from app.modules.hypervisor.dashboard_schemas import (
    DashboardMetricCoverage,
    DashboardNodeObservation,
    FleetClusterSummary,
    FleetDashboardResponse,
    HypervisorDashboardResponse,
    MetricIssue,
)

MAX_NODES = 1024
MAX_RESOURCES = 20000
MAX_DECODED_BYTES = 16 * 1024 * 1024
METRICS = {
    "cpu": ("maxcpu", "cpu", "total_cpu_cores", "used_cpu_cores", "cpu_usage_percent"),
    "memory": ("maxmem", "mem", "total_memory_bytes", "used_memory_bytes", "memory_usage_percent"),
    "node_filesystem": (
        "maxdisk",
        "disk",
        "total_storage_bytes",
        "used_storage_bytes",
        "storage_usage_percent",
    ),
}
COUNTS = (
    "total_nodes",
    "online_nodes",
    "total_vms",
    "running_vms",
    "total_containers",
    "running_containers",
)


def integer(value: Any, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Invalid dashboard counter")
    if not 0 <= value <= maximum or int(value) != value:
        raise ValueError("Invalid dashboard counter")
    return int(value)


def node_name(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", value):
        raise ValueError("Invalid dashboard node")
    return value


def controller_fingerprint(controller: Any) -> str:
    """Invalidate a short-lived observation on changed connection configuration.

    Raw config may contain encrypted credentials: only an in-memory digest is
    retained, never returned/logged. Vault/native ACL changes do not revalidate
    already observed data during the explicitly reported ten-second cache TTL.
    """
    names = (
        "id",
        "site_id",
        "host",
        "port",
        "use_ssl",
        "verify_ssl",
        "credential_id",
        "updated_at",
        "config",
    )
    state = {name: getattr(controller, name, None) for name in names}
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()


def ha_services(raw: Any) -> int | None:
    """Count visible service entries without interpreting daemon text as health."""
    if not isinstance(raw, list) or len(raw) > MAX_RESOURCES:
        return None
    seen: set[str] = set()
    for row in raw:
        if not isinstance(row, dict) or row.get("type") not in (
            "quorum",
            "master",
            "lrm",
            "service",
            "fencing",
        ):
            return None
        if row["type"] == "service":
            sid = row.get("sid")
            if (
                not isinstance(sid, str)
                or not re.fullmatch(r"(?:vm|ct):[1-9][0-9]{2,8}", sid)
                or sid in seen
            ):
                return None
            seen.add(sid)
    return len(seen)


def aggregate(
    controller_id: str,
    cluster: ProxmoxClusterStatus,
    resources: list[Any],
    ha: Any,
    started: datetime,
) -> HypervisorDashboardResponse:
    try:
        return _aggregate(controller_id, cluster, resources, ha, started)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ConnectionError("Proxmox dashboard response is malformed or exceeds limits") from exc


def _aggregate(
    controller_id: str,
    cluster: ProxmoxClusterStatus,
    resources: list[Any],
    ha: Any,
    started: datetime,
) -> HypervisorDashboardResponse:
    if len(resources) > MAX_RESOURCES or len(json.dumps(resources).encode()) > MAX_DECODED_BYTES:
        raise ValueError("Dashboard resource budget exceeded")
    count = integer(cluster.node_count, MAX_NODES)
    if not isinstance(cluster.nodes, list) or len(cluster.nodes) > MAX_NODES:
        raise ValueError("Dashboard node budget exceeded")
    membership: dict[str, Literal["online", "offline", "unknown"]] = {}
    for node in cluster.nodes:
        name = node_name(node.node)
        if name in membership or node.status not in {"online", "offline", "unknown"}:
            raise ValueError("Invalid dashboard membership")
        membership[name] = cast(Literal["online", "offline", "unknown"], node.status)
    nodes: dict[str, dict[str, Any]] = {}
    guests: dict[str, list[dict[str, Any]]] = {"qemu": [], "lxc": []}
    guest_ids: set[int] = set()
    for row in resources:
        if not isinstance(row, dict) or not isinstance(row.get("type"), str):
            raise ValueError("Invalid resource row")
        kind = row["type"]
        if kind == "node":
            name = node_name(row.get("node"))
            if name in nodes:
                raise ValueError("Duplicate node")
            nodes[name] = row
        elif kind in guests:
            vmid = integer(row.get("vmid"), 999999999)
            if vmid < 100 or vmid in guest_ids:
                raise ValueError("Invalid guest identity")
            guest_ids.add(vmid)
            guests[kind].append(row)
        # Storage/pool/network and future resource kinds are not node capacity.
    names = sorted(membership.keys() | nodes.keys())
    if len(names) > MAX_NODES:
        raise ValueError("Dashboard node budget exceeded")
    expected = max(count, len(names))
    inventory_matches = count == len(membership) and membership.keys() == nodes.keys()
    result = HypervisorDashboardResponse(
        controller_id=controller_id,
        cluster_name=cluster.name,
        quorate=cluster.quorate if type(cluster.quorate) is bool else None,
        total_nodes=expected,
        online_nodes=sum(status == "online" for status in membership.values()),
        collection_started_at=started,
    )
    result.nodes = [
        DashboardNodeObservation(
            node=name,
            status=membership.get(name, "unknown")
            if membership.get(name) == nodes.get(name, {}).get("status")
            else "unknown",
        )
        for name in names
    ]
    result.online_nodes = (
        sum(node.status == "online" for node in result.nodes)
        if len(result.nodes) == expected and all(node.status != "unknown" for node in result.nodes)
        else None
    )
    for kind, total_count_field, running in [
        ("qemu", "total_vms", "running_vms"),
        ("lxc", "total_containers", "running_containers"),
    ]:
        rows = guests[kind]
        setattr(result, total_count_field, len(rows))
        known = all(
            row.get("status") in {"running", "stopped", "paused", "suspended"} for row in rows
        )
        setattr(result, running, sum(row["status"] == "running" for row in rows) if known else None)
    for key, (cap_key, used_key, total_field, used_field, percent_field) in METRICS.items():
        reasons: set[MetricIssue] = set()
        if not inventory_matches:
            reasons.add("inventory_mismatch")
        capacities: list[int] = []
        usages: list[float | int] = []
        for name in names:
            row = nodes.get(name, {})
            if membership.get(name) != "online" or row.get("status") != "online":
                reasons.add("node_not_online")
                continue
            if row.get(cap_key) is None or row.get(used_key) is None:
                reasons.add("missing_statistics")
                continue
            try:
                capacity = integer(row[cap_key], 1048576 if key == "cpu" else 2**63 - 1)
                if capacity == 0:
                    raise ValueError("Unknown capacity")
                if key == "cpu":
                    value = row[used_key]
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, (int, float))
                        or not 0 <= value <= 1
                    ):
                        raise ValueError("Invalid CPU fraction")
                    used = float(value) * capacity
                else:
                    used = integer(row[used_key], capacity)
            except (ValueError, OverflowError):
                reasons.add("invalid_statistics")
                continue
            capacities.append(capacity)
            usages.append(used)
        observed = len(capacities)
        complete = expected > 0 and observed == expected and not reasons
        coverage = DashboardMetricCoverage(
            status="available" if complete else "partial" if observed else "unavailable",
            expected_nodes=expected,
            observed_nodes=observed,
            reasons=sorted(reasons),
        )
        setattr(result.metric_coverage, key, coverage)
        if complete:
            total = sum(capacities)
            used_sum = sum(usages)
            setattr(result, total_field, total)
            if used_field:
                setattr(result, used_field, used_sum)
            setattr(result, percent_field, round(100 * used_sum / total, 1))
    result.ha_services_visible = ha_services(ha)
    complete = all(getattr(result.metric_coverage, key).status == "available" for key in METRICS)
    result.coverage = (
        "complete_visible"
        if complete
        and result.quorate is not None
        and result.ha_services_visible is not None
        and result.running_vms is not None
        and result.running_containers is not None
        else "partial"
    )
    result.observed_at = datetime.now(UTC)
    result.served_at = result.observed_at
    result.observation_age_seconds = max(0.0, (result.observed_at - started).total_seconds())
    return result


def fleet(results: list[FleetClusterSummary], started: datetime) -> FleetDashboardResponse:
    report = FleetDashboardResponse(
        total_clusters=len(results),
        clusters=results,
        collection_started_at=started,
        online_clusters=sum(row.status == "online" for row in results),
        failed_clusters=sum(row.status != "online" for row in results),
    )
    usable = [row for row in results if row.status == "online"]
    all_available = bool(results) and len(usable) == len(results)
    for field in COUNTS:
        values = [getattr(row, field) for row in usable]
        if all_available and all(value is not None for value in values):
            setattr(report, field, sum(values))
    for key, (_, _, capacity, used_field, percent) in METRICS.items():
        coverages = [getattr(row.metric_coverage, key) for row in usable]
        complete = all_available and all(row.status == "available" for row in coverages)
        setattr(
            report.metric_coverage,
            key,
            DashboardMetricCoverage(
                status="available"
                if complete
                else "partial"
                if any(row.observed_nodes for row in coverages)
                else "unavailable",
                expected_nodes=sum(row.expected_nodes for row in coverages),
                observed_nodes=sum(row.observed_nodes for row in coverages),
                reasons=sorted({reason for row in coverages for reason in row.reasons}),
            ),
        )
        if complete:
            total = sum(getattr(row, capacity) for row in usable)
            setattr(report, capacity, total)
            used = sum(getattr(row, used_field) for row in usable)
            setattr(report, used_field, used)
            setattr(report, percent, round(100 * used / total, 1))
    report.coverage = (
        "complete_visible"
        if all_available and all(row.coverage == "complete_visible" for row in results)
        else "partial"
        if usable
        else "unavailable"
    )
    report.observed_at = min((row.observed_at for row in usable if row.observed_at), default=None)
    report.collection_started_at = min(
        (row.collection_started_at for row in usable if row.collection_started_at), default=started
    )
    report.served_at = datetime.now(UTC)
    report.observation_age_seconds = max(
        (
            row.observation_age_seconds
            + max(0.0, (report.served_at - row.served_at).total_seconds())
            for row in usable
            if row.observation_age_seconds is not None and row.served_at is not None
        ),
        default=None,
    )
    return report
