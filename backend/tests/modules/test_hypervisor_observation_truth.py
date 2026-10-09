# SPDX-License-Identifier: AGPL-3.0-only
"""A failed read is neither an empty healthy cluster nor proof of missing backups."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.adapters.base import AdapterResult
from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.proxmox.models import ProxmoxClusterStatus
from app.modules.hypervisor.service import HypervisorService


@pytest.fixture
def observed(monkeypatch):
    adapter = AsyncMock(spec=ProxmoxAdapter)
    adapter.__aenter__.return_value = adapter
    adapter.get_cluster_resources.return_value = AdapterResult.ok(
        [
            {"vmid": n, "name": f"guest-{n}", "node": "node1", "type": "qemu"}
            for n in (100, 101, 102)
        ]
    )
    adapter.get_cluster_status.return_value = AdapterResult.ok(
        ProxmoxClusterStatus(name="test", quorate=True, node_count=1, version=1)
    )
    adapter.get_ha_status.return_value = AdapterResult.ok([])
    adapter.get_nodes.return_value = AdapterResult.ok([{"node": "node1"}])
    adapter.get_storage.return_value = AdapterResult.ok(
        [{"storage": "backups", "content": "backup"}]
    )
    now = datetime.now(UTC)
    adapter.get_storage_content.return_value = AdapterResult.ok(
        [
            {"vmid": 100, "ctime": (now - timedelta(hours=1)).timestamp()},
            {"vmid": 101, "ctime": (now - timedelta(hours=48)).timestamp()},
        ]
    )
    service = HypervisorService(MagicMock())
    monkeypatch.setattr(service, "_get_adapter", AsyncMock(return_value=adapter))
    controller = SimpleNamespace(id=uuid4(), name="test", host="test.invalid")
    return service, adapter, controller


async def test_complete_inventory_separates_fresh_stale_and_missing(observed):
    service, _, controller = observed
    report = await service.get_backup_age_report(controller)
    assert report.complete is True
    assert (
        report.total_vms,
        report.backed_up,
        report.fresh,
        report.stale,
        report.never_backed_up,
        report.unknown,
    ) == (3, 2, 1, 1, 1, 0)
    assert [v.status for v in report.vms] == ["current", "stale", "missing"]


@pytest.mark.parametrize("failure", [AdapterResult.fail("offline"), TimeoutError()])
async def test_storage_read_failure_is_unknown_not_never_backed_up(observed, failure):
    service, adapter, controller = observed
    if isinstance(failure, Exception):
        adapter.get_storage_content.side_effect = failure
    else:
        adapter.get_storage_content.return_value = failure
    report = await service.get_backup_age_report(controller)
    assert report.complete is False
    assert report.unknown == 3 and report.never_backed_up == 0 and report.stale == 0
    assert all(v.status == "unknown" and v.is_stale is None for v in report.vms)
    assert report.read_failures[0].storage == "backups"


async def test_failed_storage_discovery_does_not_prove_no_backups(observed):
    service, adapter, controller = observed
    adapter.get_storage.return_value = AdapterResult.fail("permission denied")
    report = await service.get_backup_age_report(controller)
    assert report.unknown == 3 and report.complete is False


async def test_backups_on_node_without_running_guests_are_included(observed):
    service, adapter, controller = observed
    adapter.get_nodes.return_value = AdapterResult.ok([{"node": "node1"}, {"node": "archive-node"}])
    adapter.get_storage.side_effect = lambda node: AdapterResult.ok(
        [{"storage": "vault", "content": "backup"}] if node == "archive-node" else []
    )
    report = await service.get_backup_age_report(controller)
    assert report.complete and report.fresh == 1
    adapter.get_storage_content.assert_awaited_once_with(
        "archive-node", "vault", content_type="backup"
    )


async def test_partial_report_preserves_proven_freshness_without_claiming_absence(observed):
    service, adapter, controller = observed
    adapter.get_storage.return_value = AdapterResult.ok(
        [{"storage": "backups", "content": "backup"}, {"storage": "offline", "content": "backup"}]
    )
    good = adapter.get_storage_content.return_value
    adapter.get_storage_content.side_effect = lambda _node, storage, **_kw: (
        good if storage == "backups" else AdapterResult.fail("offline")
    )
    report = await service.get_backup_age_report(controller)
    assert (report.fresh, report.unknown, report.stale, report.never_backed_up) == (1, 2, 0, 0)


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), 10**30, -1])
async def test_invalid_archive_times_never_look_fresh(observed, timestamp):
    service, adapter, controller = observed
    adapter.get_storage_content.return_value = AdapterResult.ok([{"vmid": 100, "ctime": timestamp}])
    report = await service.get_backup_age_report(controller)
    assert report.fresh == 0 and report.unknown == 3


async def test_failed_guest_inventory_is_an_error_not_an_empty_report(observed):
    service, adapter, controller = observed
    adapter.get_cluster_resources.return_value = AdapterResult.fail("offline")
    with pytest.raises(ConnectionError):
        await service.get_backup_age_report(controller)


@pytest.mark.parametrize("method", ["get_cluster_status", "get_cluster_resources"])
async def test_failed_essential_dashboard_read_cannot_mark_cluster_online(observed, method):
    service, adapter, controller = observed
    getattr(adapter, method).return_value = AdapterResult.fail("offline")
    fleet = await service.get_fleet_dashboard([controller])
    assert fleet.online_clusters == 0
    assert fleet.clusters[0].status == "error"


async def test_ha_read_failure_preserves_unknown_instead_of_inactive(observed):
    service, adapter, controller = observed
    adapter.get_ha_status.return_value = AdapterResult.fail("permission denied")
    dashboard = await service.get_dashboard(controller)
    assert dashboard.ha_active is None


@pytest.mark.parametrize("payload", [None, {}, "unexpected"])
@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("get_cluster_resources", ()),
        ("get_storage", ("node1",)),
        ("get_storage_content", ("node1", "backups")),
    ],
)
async def test_adapter_does_not_convert_malformed_inventory_to_success(method, args, payload):
    adapter = ProxmoxAdapter(host="192.0.2.20", username="fixture", password="fixture-only")
    adapter._client = SimpleNamespace(is_connected=True, get=AsyncMock(return_value=payload))
    result = await getattr(adapter, method)(*args)
    assert result.success is False
    assert result.error_code == "invalid_response"
