# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Proxmox write pre-flight safety: risk classification, read-only impact
checks, and the catastrophic-op confirmation gate."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.services.adapter_proxmox_preflight import (
    PreflightResult,
    Risk,
    assess,
    classify,
    gate,
    preflight_gate,
)


class _Res:
    def __init__(self, data):
        self.success = True
        self.data = data
        self.error = None


class _FakeAdapter:
    """Read-only stand-in: get_cluster_resources returns fixed guest rows."""

    def __init__(self, resources):
        self._r = resources

    async def get_cluster_resources(self, rtype=None):
        return _Res(self._r)


@pytest.mark.parametrize(
    "feature,operation,expected",
    [
        ("proxmox.vm.destroy", "delete", Risk.CATASTROPHIC),
        ("proxmox.node.reboot", "create", Risk.CATASTROPHIC),
        ("proxmox.node.shutdown", "create", Risk.CATASTROPHIC),
        ("proxmox.snapshot.rollback", "create", Risk.CATASTROPHIC),
        ("proxmox.storage.delete_volume", "delete", Risk.CATASTROPHIC),
        ("proxmox.vm.stop", "create", Risk.DESTRUCTIVE),
        ("proxmox.vm.shutdown", "create", Risk.DESTRUCTIVE),
        ("proxmox.vm.migrate", "create", Risk.DESTRUCTIVE),
        ("proxmox.vm.start", "create", Risk.SAFE),
        ("proxmox.vm.clone", "create", Risk.SAFE),
        ("proxmox.snapshot.create", "create", Risk.SAFE),
        # the LXC remote-migrate sibling (operation "create") must be
        # catastrophic like proxmox.vm.remote_migrate — it ships the container to
        # another cluster and destroys the source.
        ("proxmox.vm.remote_migrate", "create", Risk.CATASTROPHIC),
        ("proxmox.container.remote_migrate", "create", Risk.CATASTROPHIC),
        # replacing the node TLS cert (operation "create") can lock
        # pveproxy out → catastrophic; the delete sibling is already caught by the
        # delete-default below.
        ("proxmox.node.certificate_upload", "create", Risk.CATASTROPHIC),
        ("proxmox.node.certificate_delete", "delete", Risk.CATASTROPHIC),
        # any unclassified delete defaults to catastrophic
        ("proxmox.something.unknown", "delete", Risk.CATASTROPHIC),
        ("proxmox.something.unknown", "create", Risk.SAFE),
    ],
)
def test_classify(feature, operation, expected) -> None:
    assert classify(feature, operation) is expected


@pytest.mark.asyncio
async def test_assess_node_reboot_counts_running_guests() -> None:
    adapter = _FakeAdapter([
        {"type": "qemu", "vmid": 100, "node": "s1", "status": "running"},
        {"type": "lxc", "vmid": 101, "node": "s1", "status": "running"},
        {"type": "lxc", "vmid": 102, "node": "s1", "status": "stopped"},
        {"type": "qemu", "vmid": 200, "node": "s2", "status": "running"},
    ])
    res = await assess("proxmox.node.reboot", "create", {"node": "s1"}, adapter=adapter)
    assert res.risk is Risk.CATASTROPHIC
    assert res.impact["running_guests"] == 2  # only s1's running guests
    assert any("2 running guest" in w for w in res.warnings)
    assert res.requires_confirmation is True


@pytest.mark.asyncio
async def test_assess_vm_destroy_flags_running_vm() -> None:
    adapter = _FakeAdapter([{"type": "qemu", "vmid": 100, "node": "s1", "status": "running", "name": "db01"}])
    res = await assess("proxmox.vm.destroy", "delete", {"node": "s1", "vmid": 100}, adapter=adapter)
    assert res.impact["vm_status"] == "running"
    assert any("RUNNING" in w for w in res.warnings)


@pytest.mark.asyncio
async def test_assess_storage_delete_volume_reports_size() -> None:
    class _StorageAdapter:
        async def get_storage_content(self, node=None, storage=None):
            return _Res([
                {"volid": "local-lvm:vm-100-disk-0", "size": 8589934592,
                 "format": "raw", "vmid": 100},
            ])

    res = await assess(
        "proxmox.storage.delete_volume", "delete",
        {"node": "s1", "storage": "local-lvm", "volid": "local-lvm:vm-100-disk-0"},
        adapter=_StorageAdapter(),
    )
    assert res.risk is Risk.CATASTROPHIC
    assert res.impact["volume_size"] == 8589934592
    assert res.impact["volume_used_by"] == 100
    assert any("permanently deleted" in w for w in res.warnings)
    assert res.requires_confirmation is True


@pytest.mark.asyncio
async def test_assess_snapshot_rollback_warns_data_loss() -> None:
    res = await assess("proxmox.snapshot.rollback", "create", {"node": "s1", "vmid": 100})
    assert res.risk is Risk.CATASTROPHIC
    assert any("discards" in w.lower() for w in res.warnings)
    assert res.requires_confirmation is True


@pytest.mark.asyncio
async def test_assess_live_check_failure_degrades_to_warning_not_raise() -> None:
    class _BadAdapter:
        async def get_cluster_resources(self, rtype=None):
            raise RuntimeError("device unreachable")

    res = await assess("proxmox.node.reboot", "create", {"node": "s1"}, adapter=_BadAdapter())
    assert res.risk is Risk.CATASTROPHIC  # still classified
    assert any("incomplete" in w for w in res.warnings)  # warned, not crashed


def test_gate_blocks_catastrophic_without_confirmation() -> None:
    res = PreflightResult("proxmox.vm.destroy", "delete", Risk.CATASTROPHIC, warnings=["irreversible"])
    with pytest.raises(HTTPException) as ei:
        gate(res, {})
    assert ei.value.status_code == 409
    assert "confirmed=true" in ei.value.detail


def test_gate_allows_catastrophic_with_confirmation() -> None:
    res = PreflightResult("proxmox.vm.destroy", "delete", Risk.CATASTROPHIC)
    gate(res, {"confirmed": True})  # no raise


def test_gate_allows_destructive_and_safe_without_confirmation() -> None:
    gate(PreflightResult("proxmox.vm.stop", "create", Risk.DESTRUCTIVE), {})  # no raise
    gate(PreflightResult("proxmox.vm.start", "create", Risk.SAFE), {})  # no raise


@pytest.mark.asyncio
async def test_preflight_gate_blocks_then_allows_when_confirmed() -> None:
    adapter = _FakeAdapter([{"type": "qemu", "vmid": 100, "node": "s1", "status": "running"}])
    with pytest.raises(HTTPException) as ei:
        await preflight_gate(adapter, "proxmox.vm.destroy", "delete", {"node": "s1", "vmid": 100})
    assert ei.value.status_code == 409
    # With explicit confirmation it proceeds + returns the assessment.
    res = await preflight_gate(
        adapter, "proxmox.vm.destroy", "delete", {"node": "s1", "vmid": 100, "confirmed": True}
    )
    assert res.risk is Risk.CATASTROPHIC and res.impact.get("vm_status") == "running"
