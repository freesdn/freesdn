# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Missing, partial and stale observations must not become healthy zero gauges."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.adapters.base import AdapterResult
from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.proxmox.models import ProxmoxClusterStatus, ProxmoxNodeInfo
from app.modules.hypervisor import dashboard_metrics as metrics
from app.modules.hypervisor import service as services
from app.modules.hypervisor.dashboard_schemas import FleetClusterSummary


def native_node(name="n1", **values):
    return {
        "type": "node",
        "node": name,
        "status": "online",
        "maxcpu": 4,
        "cpu": 0.25,
        "maxmem": 1000,
        "mem": 500,
        "maxdisk": 2000,
        "disk": 1000,
        **values,
    }


def cluster(*names):
    return ProxmoxClusterStatus(
        name="lab",
        quorate=True,
        node_count=len(names),
        version=1,
        nodes=[ProxmoxNodeInfo(node=name, status="online") for name in names],
    )


def observe(rows=None, membership=None, ha=None):
    return metrics.aggregate(
        "controller",
        membership or cluster("n1"),
        rows if rows is not None else [native_node()],
        ha if ha is not None else [],
        datetime.now(UTC),
    )


def test_complete_visible_observation_has_weighted_usage_and_named_scope():
    result = observe(
        [
            native_node(maxcpu=2, cpu=1),
            native_node("n2", maxcpu=6, cpu=0.5),
            {"type": "storage", "maxdisk": 99999999, "disk": 99999999},
        ],
        cluster("n1", "n2"),
    )
    assert result.total_cpu_cores == 8 and result.used_cpu_cores == 5
    assert result.cpu_usage_percent == 62.5
    assert result.total_storage_bytes == 4000 and result.storage_usage_percent == 50
    assert result.metric_coverage.cpu.observed_nodes == 2
    assert result.coverage == "complete_visible"
    assert (
        result.inventory_scope == "credential_visible"
        and result.storage_scope == "node_filesystems"
    )
    assert result.provider_sample_time_known is False


@pytest.mark.parametrize(
    "key,output,coverage",
    [
        ("cpu", "cpu_usage_percent", "cpu"),
        ("maxcpu", "total_cpu_cores", "cpu"),
        ("mem", "memory_usage_percent", "memory"),
        ("maxmem", "total_memory_bytes", "memory"),
        ("disk", "storage_usage_percent", "node_filesystem"),
        ("maxdisk", "total_storage_bytes", "node_filesystem"),
    ],
)
@pytest.mark.parametrize("value", [None, True, -1, "0", float("nan"), float("inf"), {}, []])
def test_invalid_or_missing_numeric_fields_never_become_zero(key, output, coverage, value):
    result = observe([native_node(**{key: value})])
    assert getattr(result, output) is None
    assert getattr(result.metric_coverage, coverage).status == "unavailable"
    assert result.coverage == "partial"


@pytest.mark.parametrize(
    "values",
    [
        {"cpu": 1.01},
        {"mem": 1001},
        {"disk": 2001},
        {"maxcpu": 1.5},
        {"maxmem": 0},
        {"maxdisk": 0},
        {"maxcpu": 0},
    ],
)
def test_impossible_or_zero_capacity_is_unknown(values):
    result = observe([native_node(**values)])
    assert result.coverage == "partial"


def test_observed_zero_is_preserved_and_missing_metric_does_not_hide_other_metrics():
    result = observe([native_node(cpu=0, mem=0, disk=0)])
    assert (
        result.cpu_usage_percent,
        result.memory_usage_percent,
        result.storage_usage_percent,
    ) == (0, 0, 0)
    result = observe([native_node(cpu=None)])
    assert result.cpu_usage_percent is None and result.memory_usage_percent == 50


def test_partial_metrics_do_not_report_subset_percentage_as_cluster_percentage():
    result = observe([native_node(), native_node("n2", mem=None)], cluster("n1", "n2"))
    assert result.metric_coverage.memory.status == "partial"
    assert result.metric_coverage.memory.observed_nodes == 1
    assert result.metric_coverage.memory.expected_nodes == 2
    assert result.total_memory_bytes is None and result.memory_usage_percent is None
    assert result.cpu_usage_percent == 25


@pytest.mark.parametrize("source", ["membership", "resources"])
def test_offline_node_capacity_never_implies_zero_usage(source):
    cs = cluster("n1")
    row = native_node()
    if source == "membership":
        cs.nodes[0].status = "offline"
    else:
        row["status"] = "offline"
    result = observe([row], cs)
    assert result.cpu_usage_percent is None and result.total_cpu_cores is None
    assert "node_not_online" in result.metric_coverage.cpu.reasons
    assert result.nodes[0].status == "unknown" and result.online_nodes is None


@pytest.mark.parametrize(
    "rows,cs",
    [
        ([], cluster("n1")),
        ([native_node(), native_node("n2")], cluster("n1")),
        ([native_node()], ProxmoxClusterStatus(name="lab", quorate=True, node_count=2, version=1)),
    ],
)
def test_inconsistent_membership_is_explicit_and_cannot_produce_complete_totals(rows, cs):
    result = observe(rows, cs)
    assert result.total_cpu_cores is None
    assert "inventory_mismatch" in result.metric_coverage.cpu.reasons


@pytest.mark.parametrize(
    "rows",
    [
        [None],
        ["node"],
        [{}],
        [native_node(), native_node()],
        [native_node(node="../node")],
        [{"type": "qemu", "vmid": True}],
        [{"type": "qemu", "vmid": 0}],
        [{"type": "qemu", "vmid": 100}, {"type": "lxc", "vmid": 100}],
    ],
)
def test_malformed_identity_rows_fail_the_read_without_echoing_payloads(rows):
    with pytest.raises(ConnectionError, match="malformed or exceeds limits"):
        observe(rows)


def test_guest_counts_describe_visible_inventory_and_unknown_running_state():
    result = observe(
        [
            native_node(),
            {"type": "qemu", "vmid": 100, "status": "unknown"},
            {"type": "lxc", "vmid": 101, "status": "stopped"},
        ]
    )
    assert result.total_vms == 1 and result.running_vms is None
    assert result.total_containers == 1 and result.running_containers == 0
    assert result.inventory_scope == "credential_visible"


@pytest.mark.parametrize(
    "limit,value", [("MAX_RESOURCES", 0), ("MAX_DECODED_BYTES", 1), ("MAX_NODES", 0)]
)
def test_decoded_response_budgets_fail_explicitly(monkeypatch, limit, value):
    monkeypatch.setattr(metrics, limit, value)
    with pytest.raises(ConnectionError):
        observe()


def test_fleet_uses_unrounded_cpu_usage_and_discloses_registration_scope():
    first = observe([native_node(cpu=0.33333)])
    second = observe([native_node(cpu=0.33333, maxcpu=3)])
    rows = [
        FleetClusterSummary(**item.model_dump(), controller_name="same-name", status="online")
        for item in [first, second]
    ]
    result = metrics.fleet(rows, datetime.now(UTC))
    assert result.used_cpu_cores == pytest.approx(0.33333 * 7)
    assert result.total_cpu_cores == 7
    assert result.deduplicated is False and result.aggregation_scope == "controller_registrations"


def test_failed_fleet_member_prevents_complete_totals_but_preserves_good_member():
    good = FleetClusterSummary(**observe().model_dump(), controller_name="one", status="online")
    bad = FleetClusterSummary(controller_id="bad", controller_name="two", error="unavailable")
    result = metrics.fleet([good, bad], datetime.now(UTC))
    assert (result.total_clusters, result.online_clusters, result.failed_clusters) == (2, 1, 1)
    assert result.cpu_usage_percent is None and result.total_nodes is None
    assert result.clusters[0].cpu_usage_percent == 25 and result.coverage == "partial"
    assert result.metric_coverage.cpu.status == "partial"


def test_empty_fleet_has_unknown_capacity_not_zero_utilization():
    result = metrics.fleet([], datetime.now(UTC))
    assert result.total_clusters == 0 and result.cpu_usage_percent is None
    assert result.coverage == "unavailable"


def test_fleet_age_includes_time_waiting_for_other_controllers():
    now = datetime.now(UTC)
    first = observe()
    first.served_at = now - timedelta(seconds=20)
    first.observation_age_seconds = 5
    row = FleetClusterSummary(**first.model_dump(), controller_name="one", status="online")
    result = metrics.fleet([row], now)
    assert result.observation_age_seconds >= 25


@pytest.fixture
def cached_service(monkeypatch):
    services._dashboard_cache.clear()
    clock = SimpleNamespace(value=100.0)
    monkeypatch.setattr(services, "time", SimpleNamespace(monotonic=lambda: clock.value))
    svc = services.HypervisorService(MagicMock())
    ctrl = SimpleNamespace(id=uuid4(), name="lab", host="lab.invalid", config={})
    mocked = AsyncMock(return_value=observe())
    monkeypatch.setattr(svc, "_get_dashboard_uncached", mocked)
    yield svc, ctrl, clock, mocked
    services._dashboard_cache.clear()


async def test_cache_retains_observation_time_reports_age_and_is_immutable(cached_service):
    svc, ctrl, clock, mocked = cached_service
    first = await svc.get_dashboard(ctrl)
    first.cpu_usage_percent = 99
    clock.value += 4
    second = await svc.get_dashboard(ctrl)
    assert second.cpu_usage_percent == 25 and second.observed_at == first.observed_at
    assert second.observation_age_seconds == 4
    second.metric_coverage.cpu.observed_nodes = 999
    third = await svc.get_dashboard(ctrl)
    assert third.metric_coverage.cpu.observed_nodes == 1
    mocked.assert_awaited_once()


async def test_failed_refresh_discards_expired_cache(cached_service):
    svc, ctrl, clock, mocked = cached_service
    await svc.get_dashboard(ctrl)
    clock.value += services._DASHBOARD_TTL
    mocked.side_effect = ConnectionError("offline")
    with pytest.raises(ConnectionError):
        await svc.get_dashboard(ctrl)
    assert str(ctrl.id) not in services._dashboard_cache


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "new.invalid"),
        ("credential_id", "new"),
        ("verify_ssl", True),
        ("config", {"token": "fixture"}),
    ],
)
async def test_connection_configuration_change_invalidates_cache(cached_service, field, value):
    svc, ctrl, _, mocked = cached_service
    await svc.get_dashboard(ctrl)
    setattr(ctrl, field, value)
    await svc.get_dashboard(ctrl)
    assert mocked.await_count == 2


async def test_different_controllers_do_not_share_observations(cached_service):
    svc, ctrl, _, mocked = cached_service
    await svc.get_dashboard(ctrl)
    ctrl.id = uuid4()
    await svc.get_dashboard(ctrl)
    assert mocked.await_count == 2


@pytest.mark.parametrize("raw,expected", [(0, False), ("0", False), (1, True), ("1", True)])
async def test_native_quorum_and_node_flags_are_strict(raw, expected):
    adapter = ProxmoxAdapter(host="192.0.2.20", username="fixture", password="fixture")
    adapter._client = SimpleNamespace(
        is_connected=True,
        get=AsyncMock(
            return_value=[
                {"type": "cluster", "name": "lab", "version": 1, "quorate": raw},
                {"type": "node", "name": "n1", "online": raw},
            ]
        ),
    )
    result = await adapter.get_cluster_status()
    assert result.success and result.data.quorate is expected
    assert result.data.nodes[0].status == ("online" if expected else "offline")


@pytest.mark.parametrize(
    "payload",
    [
        [],
        [None],
        [{"type": "node", "name": "n1"}],
        [{"type": "node", "name": "n1", "online": "false"}],
        [{"type": "node", "name": "n1", "online": 2}],
    ],
)
async def test_malformed_native_membership_does_not_become_healthy(payload):
    adapter = ProxmoxAdapter(host="192.0.2.20", username="fixture", password="fixture")
    adapter._client = SimpleNamespace(is_connected=True, get=AsyncMock(return_value=payload))
    result = await adapter.get_cluster_status()
    assert not result.success and result.error_code == "invalid_response"


async def test_standalone_native_node_is_supported():
    adapter = ProxmoxAdapter(host="192.0.2.20", username="fixture", password="fixture")
    adapter._client = SimpleNamespace(
        is_connected=True,
        get=AsyncMock(
            return_value=[
                {"type": "node", "name": "n1", "online": 1},
            ]
        ),
    )
    result = await adapter.get_cluster_status()
    assert result.success and result.data.quorate and result.data.node_count == 1


async def test_service_keeps_ha_failure_unknown_without_exposing_diagnostics():
    adapter = AsyncMock(spec=ProxmoxAdapter)
    adapter.__aenter__.return_value = adapter
    adapter.get_cluster_status.return_value = AdapterResult.ok(cluster("n1"))
    adapter.get_cluster_resources.return_value = AdapterResult.ok([native_node()])
    adapter.get_ha_status.return_value = AdapterResult.fail("private diagnostic")
    svc = services.HypervisorService(MagicMock())
    svc._get_adapter = AsyncMock(return_value=adapter)
    result = await svc._get_dashboard_uncached(SimpleNamespace(id=uuid4()))
    assert result.ha_active is None and result.coverage == "partial"
    assert "private diagnostic" not in result.model_dump_json()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ([], 0),
        ([{"type": "quorum"}, {"type": "master"}, {"type": "lrm"}], 0),
        ([{"type": "service", "sid": "vm:100", "crm_state": "error"}], 1),
        ([{"type": "service", "sid": "vm:100"}, {"type": "service", "sid": "ct:101"}], 2),
        ([{"type": "future"}], None),
        ([{"type": "service", "sid": "invalid"}], None),
        ([{"type": "service", "sid": "vm:100"}, {"type": "service", "sid": "vm:100"}], None),
        (None, None),
        ({}, None),
    ],
)
def test_ha_presence_never_establishes_active_or_healthy(raw, expected):
    assert metrics.ha_services(raw) == expected
    result = metrics.aggregate("controller", cluster("n1"), [native_node()], raw, datetime.now(UTC))
    assert result.ha_active is None and result.ha_services_visible == expected


async def test_read_deadline_cancels_outstanding_native_reads(monkeypatch):
    monkeypatch.setattr(services, "_DASHBOARD_READ_TIMEOUT", 0.01)
    cancelled = []

    async def slow():
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    adapter = AsyncMock(spec=ProxmoxAdapter)
    adapter.__aenter__.return_value = adapter
    for method in ["get_cluster_status", "get_cluster_resources", "get_ha_status"]:
        getattr(adapter, method).side_effect = slow
    svc = services.HypervisorService(MagicMock())
    svc._get_adapter = AsyncMock(return_value=adapter)
    with pytest.raises(ConnectionError, match="deadline exceeded"):
        await svc._get_dashboard_uncached(SimpleNamespace(id=uuid4()))
    assert len(cancelled) == 3


async def test_fleet_deadline_includes_time_waiting_for_a_connection_slot(monkeypatch):
    monkeypatch.setattr(services, "_fleet_semaphore", asyncio.Semaphore(0))
    monkeypatch.setattr(services, "_FLEET_TIMEOUT", 0.01)
    svc = services.HypervisorService(MagicMock())
    svc.get_dashboard = AsyncMock()
    report = await svc.get_fleet_dashboard(
        [SimpleNamespace(id=uuid4(), name="lab", host="lab.invalid")]
    )
    assert report.failed_clusters == 1 and report.cpu_usage_percent is None
    svc.get_dashboard.assert_not_awaited()
