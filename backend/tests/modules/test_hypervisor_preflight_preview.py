# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Hypervisor pre-flight preview (dry-run): the read-only endpoint that assesses
a prospective staged write BEFORE it is staged.

Locks that ``HypervisorService.preflight_preview`` wires the pre-flight assessor
through a connected (read-only) adapter and returns the serialized assessment —
risk class, confirmation requirement, and device-observed impact — without ever
mutating the cluster. Device-free: the adapter is a read-only stand-in.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.modules.hypervisor.service import HypervisorService


class _Res:
    def __init__(self, data):
        self.success = True
        self.data = data
        self.error = None


class _FakeAdapter:
    """Read-only async-context-manager adapter stand-in."""

    def __init__(self, resources=None, storage_content=None):
        self._resources = resources or []
        self._storage = storage_content or []
        self.delete_calls: list[dict] = []
        self.rollback_calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_cluster_resources(self, rtype=None):
        return _Res(self._resources)

    async def get_storage_content(self, node=None, storage=None):
        return _Res(self._storage)

    async def delete_vm(self, node, vmid, vm_type="qemu", *, confirmed=False, force=False):
        # Records HOW the second factor was passed: the direct path must thread
        # confirmed= (never force=), so the read-only gate underneath still bites.
        self.delete_calls.append({"confirmed": confirmed, "force": force})
        return _Res("UPID:del")

    async def rollback_snapshot(self, node, vmid, snapname, vm_type="qemu", *, force=False):
        self.rollback_calls.append({"force": force})
        return _Res("UPID:rollback")


def _svc(adapter: _FakeAdapter) -> HypervisorService:
    svc = HypervisorService(MagicMock())

    async def _get_adapter(_controller):
        return adapter

    svc._get_adapter = _get_adapter  # type: ignore[assignment]
    return svc


_CTRL = SimpleNamespace(id="c1", host="192.168.1.86", config={})


@pytest.mark.asyncio
async def test_preview_node_reboot_is_catastrophic_and_counts_guests() -> None:
    adapter = _FakeAdapter(resources=[
        {"type": "qemu", "vmid": 100, "node": "s1", "status": "running"},
        {"type": "lxc", "vmid": 101, "node": "s1", "status": "running"},
        {"type": "lxc", "vmid": 102, "node": "s2", "status": "running"},
    ])
    out = await _svc(adapter).preflight_preview(
        _CTRL, "proxmox.node.reboot", "create", {"node": "s1"}
    )
    assert out["risk"] == "catastrophic"
    assert out["requires_confirmation"] is True
    assert out["impact"]["running_guests"] == 2
    assert any("2 running guest" in w for w in out["warnings"])


@pytest.mark.asyncio
async def test_preview_vm_start_is_safe_no_confirmation() -> None:
    adapter = _FakeAdapter(resources=[
        {"type": "qemu", "vmid": 100, "node": "s1", "status": "stopped", "name": "db01"},
    ])
    out = await _svc(adapter).preflight_preview(
        _CTRL, "proxmox.vm.start", "create", {"vmid": 100}
    )
    assert out["risk"] == "safe"
    assert out["requires_confirmation"] is False


@pytest.mark.asyncio
async def test_preview_storage_delete_volume_reports_size() -> None:
    adapter = _FakeAdapter(storage_content=[
        {"volid": "local-lvm:vm-100-disk-0", "size": 8589934592, "format": "raw", "vmid": 100},
    ])
    out = await _svc(adapter).preflight_preview(
        _CTRL, "proxmox.storage.delete_volume", "delete",
        {"node": "s1", "storage": "local-lvm", "volid": "local-lvm:vm-100-disk-0"},
    )
    assert out["risk"] == "catastrophic"
    assert out["requires_confirmation"] is True
    assert out["impact"]["volume_size"] == 8589934592
    assert any("permanently deleted" in w for w in out["warnings"])


# ── Direct-path confirm gate (guest ops: confirmed=true, force stays False) ──


@pytest.mark.asyncio
async def test_bulk_delete_threads_confirmed_not_force() -> None:
    """Bulk delete must pass confirmed= (the type-to-confirm second factor) and
    NOT force=, so each delete still honors the read-only gate underneath."""
    adapter = _FakeAdapter()
    results = await _svc(adapter).bulk_action(
        _CTRL, [{"node": "s1", "vmid": 100, "vm_type": "qemu"}], "delete", confirmed=True
    )
    assert results[0]["success"] is True
    assert adapter.delete_calls == [{"confirmed": True, "force": False}]


@pytest.mark.asyncio
async def test_rollback_without_confirmed_raises_409() -> None:
    """Snapshot rollback is a guest-scoped destructive op: refused on the direct
    path without confirmed=true (→ AdapterConfirmationRequiredError → HTTP 409)."""
    from app.adapters.exceptions import AdapterConfirmationRequiredError

    adapter = _FakeAdapter()
    with pytest.raises(AdapterConfirmationRequiredError):
        await _svc(adapter).rollback_snapshot(_CTRL, "s1", 100, "snap1", "qemu", confirmed=False)
    assert adapter.rollback_calls == []  # never reached the adapter


@pytest.mark.asyncio
async def test_rollback_with_confirmed_dispatches_without_force() -> None:
    adapter = _FakeAdapter()
    out = await _svc(adapter).rollback_snapshot(
        _CTRL, "s1", 100, "snap1", "qemu", confirmed=True
    )
    assert out["upid"] == "UPID:rollback"
    # force NOT passed → the read-only gate still applies on the direct path.
    assert adapter.rollback_calls == [{"force": False}]
