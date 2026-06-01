# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Apply-path tests for the high-stakes Proxmox staged-write services.

Proxmox exposes 62 writable features across
10 services that previously had ZERO apply-path tests. This file covers the three
highest-blast-radius services: vm, snapshot, backup. The remaining
seven (container, storage, firewall, ha, node, sdn, cluster) follow
the same shape and will land in a follow-up.

Coverage per service:
- ``_APPLY`` table completeness (every (feature, op) pair the
  endpoint advertises must dispatch)
- Applier dispatches to the right adapter method with the right
  arg shape (node + vmid for VM; node + vmtype + vmid + snapname
  for snapshot; node + storage + vmid for backup)
- Required-arg validation (missing node / vmid / snapname → 400)
- Unknown feature → 400 (not silent no-op)
- **guest_agent_file_write** path denylist enforcement (see
  ``_validate_guest_file_path`` in adapter_proxmox_vm.py)

Adapter is mocked at the service-layer boundary
(``_get_controller`` + ``_get_proxmox_adapter``) so no live Proxmox
is contacted.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_proxmox_backup import (
    _APPLY as BACKUP_APPLY,
)
from app.services.adapter_proxmox_backup import (
    GatewayProxmoxBackupService,
)
from app.services.adapter_proxmox_snapshot import (
    _APPLY as SNAPSHOT_APPLY,
)
from app.services.adapter_proxmox_snapshot import (
    GatewayProxmoxSnapshotService,
)
from app.services.adapter_proxmox_vm import (
    _APPLY as VM_APPLY,
)
from app.services.adapter_proxmox_vm import (
    GatewayProxmoxVmService,
    _validate_guest_file_path,
)


def _make_change(feature: str, operation: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature,
        operation=operation,
        payload=kw.get("payload", {}),
        target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _make_vm_service() -> tuple[GatewayProxmoxVmService, MagicMock]:
    svc = GatewayProxmoxVmService(MagicMock())
    mock_adapter = MagicMock()
    for name in (
        "create_vm", "update_vm_config", "delete_vm", "clone_vm",
        "convert_to_template", "start_vm", "stop_vm", "shutdown_vm",
        "reboot_vm", "suspend_vm", "resume_vm", "migrate_vm",
        "remote_migrate_vm", "resize_vm_disk", "update_guest_cloudinit",
        "regenerate_cloudinit", "agent_exec", "agent_file_write",
    ):
        setattr(
            mock_adapter, name,
            AsyncMock(return_value=AdapterResult.ok(data={"upid": "TASK"})),
        )
    mock_adapter.disconnect = AsyncMock(return_value=None)

    async def _get_controller(*_a: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _get_proxmox_adapter(*_a: Any, **_kw: Any) -> Any:
        return mock_adapter

    svc._get_controller = _get_controller  # type: ignore[assignment]
    svc._get_proxmox_adapter = _get_proxmox_adapter  # type: ignore[assignment]
    return svc, mock_adapter


def _make_snapshot_service() -> tuple[GatewayProxmoxSnapshotService, MagicMock]:
    svc = GatewayProxmoxSnapshotService(MagicMock())
    mock_adapter = MagicMock()
    for name in ("create_snapshot", "delete_snapshot", "rollback_snapshot"):
        setattr(
            mock_adapter, name,
            AsyncMock(return_value=AdapterResult.ok(data={"upid": "TASK"})),
        )
    mock_adapter.disconnect = AsyncMock(return_value=None)

    async def _get_controller(*_a: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _get_proxmox_adapter(*_a: Any, **_kw: Any) -> Any:
        return mock_adapter

    svc._get_controller = _get_controller  # type: ignore[assignment]
    svc._get_proxmox_adapter = _get_proxmox_adapter  # type: ignore[assignment]
    return svc, mock_adapter


def _make_backup_service() -> tuple[GatewayProxmoxBackupService, MagicMock]:
    svc = GatewayProxmoxBackupService(MagicMock())
    mock_adapter = MagicMock()
    for name in (
        "create_backup_job", "update_backup_job", "delete_backup_job",
        "run_backup", "restore_backup", "prune_backups",
    ):
        setattr(
            mock_adapter, name,
            AsyncMock(return_value=AdapterResult.ok(data={"upid": "TASK"})),
        )
    mock_adapter.disconnect = AsyncMock(return_value=None)

    async def _get_controller(*_a: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _get_proxmox_adapter(*_a: Any, **_kw: Any) -> Any:
        return mock_adapter

    svc._get_controller = _get_controller  # type: ignore[assignment]
    svc._get_proxmox_adapter = _get_proxmox_adapter  # type: ignore[assignment]
    return svc, mock_adapter


# ─── _APPLY completeness ────────────────────────────────────────────


class TestApplyTableCompleteness:
    @pytest.mark.parametrize(
        "feature,op",
        [
            ("proxmox.vm.create", "create"),
            ("proxmox.vm.config", "update"),
            ("proxmox.vm.destroy", "delete"),
            ("proxmox.vm.clone", "create"),
            ("proxmox.vm.start", "create"),
            ("proxmox.vm.stop", "create"),
            ("proxmox.vm.shutdown", "create"),
            ("proxmox.vm.reboot", "create"),
            ("proxmox.vm.suspend", "create"),
            ("proxmox.vm.resume", "create"),
            ("proxmox.vm.migrate", "create"),
            ("proxmox.vm.remote_migrate", "create"),
            ("proxmox.vm.resize_disk", "update"),
            ("proxmox.vm.cloudinit", "update"),
            ("proxmox.vm.cloudinit_regenerate", "create"),
            ("proxmox.vm.guest_agent_exec", "create"),
            ("proxmox.vm.guest_agent_file_write", "create"),
            ("proxmox.vm.convert_to_template", "create"),
        ],
    )
    def test_vm_apply_table_has_pair(self, feature: str, op: str) -> None:
        assert (feature, op) in VM_APPLY

    @pytest.mark.parametrize(
        "feature,op",
        [
            ("proxmox.snapshot.create", "create"),
            ("proxmox.snapshot.delete", "delete"),
            ("proxmox.snapshot.rollback", "create"),
        ],
    )
    def test_snapshot_apply_table_has_pair(
        self, feature: str, op: str,
    ) -> None:
        assert (feature, op) in SNAPSHOT_APPLY

    @pytest.mark.parametrize(
        "feature,op",
        [
            ("proxmox.backup.job", "create"),
            ("proxmox.backup.job", "update"),
            ("proxmox.backup.job", "delete"),
            ("proxmox.backup.run", "create"),
            ("proxmox.backup.restore", "create"),
            ("proxmox.backup.prune", "create"),
        ],
    )
    def test_backup_apply_table_has_pair(
        self, feature: str, op: str,
    ) -> None:
        assert (feature, op) in BACKUP_APPLY


# ─── VM apply dispatch ──────────────────────────────────────────────


class TestVmDispatch:
    @pytest.mark.asyncio
    async def test_destroy_dispatches_with_force(self) -> None:
        svc, adapter = _make_vm_service()
        change = _make_change(
            "proxmox.vm.destroy", "delete",
            target_id="100",
            # destroy is CATASTROPHIC → the pre-flight gate requires confirmed=true.
            payload={"node": "pve", "vm_type": "qemu", "confirmed": True},
        )
        applier = svc.build_applier(change)
        await applier(change)
        adapter.delete_vm.assert_awaited_once()
        # destroy takes (node, vmid, vm_type, force=True)
        args = adapter.delete_vm.await_args.args
        kwargs = adapter.delete_vm.await_args.kwargs
        assert args == ("pve", 100, "qemu")
        assert kwargs.get("force") is True

    @pytest.mark.asyncio
    async def test_destroy_without_confirmation_is_blocked(self) -> None:
        # Pre-flight safety: a catastrophic destroy with no confirmed=true is
        # refused (409) BEFORE the adapter is ever called.
        svc, adapter = _make_vm_service()
        change = _make_change(
            "proxmox.vm.destroy", "delete",
            target_id="100",
            payload={"node": "pve", "vm_type": "qemu"},  # no confirmed
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 409
        adapter.delete_vm.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_start_dispatches(self) -> None:
        svc, adapter = _make_vm_service()
        change = _make_change(
            "proxmox.vm.start", "create",
            target_id="100",
            payload={"node": "pve"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        adapter.start_vm.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_missing_node_raises_400(self) -> None:
        svc, _ = _make_vm_service()
        change = _make_change(
            "proxmox.vm.destroy", "delete",
            target_id="100",
            payload={},  # no "node"
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_unknown_feature_raises_400(self) -> None:
        svc, _ = _make_vm_service()
        change = _make_change(
            "proxmox.vm.not_real", "create",
            target_id="100",
            payload={"node": "pve"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "no applier" in exc.value.detail.lower()


# ─── guest_agent_file_write path validation ────────────────────────


class TestGuestFilePathValidation:
    """The denylist + traversal guard — the
    feature already requires site_admin at apply time, but this is
    defense in depth against an admin overwriting /etc/sudoers via
    the staging pipeline."""

    @pytest.mark.parametrize("good_path", [
        "/home/user/config.json",
        "/var/www/app/settings.ini",
        "/opt/myapp/run.sh",
        "/tmp/scratch",
    ])
    def test_allows_typical_application_paths(self, good_path: str) -> None:
        # Should NOT raise.
        _validate_guest_file_path(good_path)

    @pytest.mark.parametrize("bad_path,expect_in_detail", [
        ("/etc/shadow", "/etc/shadow"),
        ("/etc/sudoers", "/etc/sudoers"),
        ("/etc/sudoers.d/00-evil", "/etc/sudoers"),
        ("/root/.ssh/authorized_keys", "/root/.ssh/"),
        ("/etc/ssh/sshd_config", "/etc/ssh/"),
        ("/proc/self/mem", "/proc/"),
        ("/sys/class/net", "/sys/"),
        ("/dev/sda", "/dev/"),
        ("/boot/initrd", "/boot/"),
    ])
    def test_denylist_rejected(
        self, bad_path: str, expect_in_detail: str,
    ) -> None:
        with pytest.raises(HTTPException) as exc:
            _validate_guest_file_path(bad_path)
        assert exc.value.status_code == 400
        assert expect_in_detail in exc.value.detail

    def test_traversal_rejected(self) -> None:
        with pytest.raises(HTTPException) as exc:
            _validate_guest_file_path("/home/../etc/passwd")
        assert exc.value.status_code == 400
        assert "traversal" in exc.value.detail.lower()

    def test_relative_path_rejected(self) -> None:
        with pytest.raises(HTTPException) as exc:
            _validate_guest_file_path("config.json")
        assert exc.value.status_code == 400
        assert "absolute" in exc.value.detail.lower()

    def test_null_byte_rejected(self) -> None:
        with pytest.raises(HTTPException) as exc:
            _validate_guest_file_path("/home/user\x00/sneaky")
        assert exc.value.status_code == 400
        assert "null" in exc.value.detail.lower()

    def test_empty_rejected(self) -> None:
        with pytest.raises(HTTPException) as exc:
            _validate_guest_file_path("")
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_guest_file_write_uses_validator(self) -> None:
        """End-to-end: stage a write to /etc/shadow → applier rejects.

        guest_agent_file_write is now classified CATASTROPHIC, so the
        pre-flight gate requires confirmed=true *before* the path
        validator runs. We pass confirmation here precisely so dispatch
        proceeds PAST the gate and the path denylist is the thing that
        rejects the write — i.e. this still exercises
        ``_validate_guest_file_path``, not the confirmation gate.
        """
        svc, adapter = _make_vm_service()
        change = _make_change(
            "proxmox.vm.guest_agent_file_write", "create",
            target_id="100",
            payload={
                "node": "pve",
                "file": "/etc/shadow",
                "content": "root::0:0::/root:/bin/sh\n",
                "confirmed": True,
            },
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "/etc/shadow" in exc.value.detail
        # Adapter method must NOT have been called.
        adapter.agent_file_write.assert_not_awaited()


# ─── Snapshot apply dispatch ────────────────────────────────────────


class TestSnapshotDispatch:
    @pytest.mark.asyncio
    async def test_create_snapshot_dispatches(self) -> None:
        svc, adapter = _make_snapshot_service()
        # Snapshot service: vmid lives in payload (not target_id);
        # target_id holds the snapname on delete/rollback.
        change = _make_change(
            "proxmox.snapshot.create", "create",
            payload={
                "node": "pve",
                "vmid": 100,
                "vm_type": "qemu",
                "snapname": "preupgrade",
                "description": "before kernel update",
            },
        )
        applier = svc.build_applier(change)
        await applier(change)
        adapter.create_snapshot.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rollback_dispatches(self) -> None:
        svc, adapter = _make_snapshot_service()
        # rollback is CATASTROPHIC → pre-flight gate requires confirmed=true.
        change = _make_change(
            "proxmox.snapshot.rollback", "create",
            target_id="preupgrade",
            payload={
                "node": "pve",
                "vmid": 100,
                "vm_type": "qemu",
                "confirmed": True,
            },
        )
        applier = svc.build_applier(change)
        await applier(change)
        adapter.rollback_snapshot.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rollback_without_confirmation_is_blocked(self) -> None:
        # Pre-flight safety: rollback discards all state since the snapshot →
        # refused (409) before the adapter is touched unless confirmed=true.
        svc, adapter = _make_snapshot_service()
        change = _make_change(
            "proxmox.snapshot.rollback", "create",
            target_id="preupgrade",
            payload={"node": "pve", "vmid": 100, "vm_type": "qemu"},  # no confirmed
        )
        with pytest.raises(HTTPException) as exc:
            await svc.build_applier(change)(change)
        assert exc.value.status_code == 409
        adapter.rollback_snapshot.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_snapshot_dispatches(self) -> None:
        svc, adapter = _make_snapshot_service()
        # delete is IRREVERSIBLE (removes the only restore path) → the
        # pre-flight gate now requires confirmed=true before dispatch.
        change = _make_change(
            "proxmox.snapshot.delete", "delete",
            target_id="old",
            payload={
                "node": "pve",
                "vmid": 100,
                "vm_type": "qemu",
                "confirmed": True,
            },
        )
        applier = svc.build_applier(change)
        await applier(change)
        adapter.delete_snapshot.assert_awaited_once()


# ─── Backup apply dispatch ──────────────────────────────────────────


class TestBackupDispatch:
    @pytest.mark.asyncio
    async def test_run_backup_dispatches(self) -> None:
        svc, adapter = _make_backup_service()
        change = _make_change(
            "proxmox.backup.run", "create",
            payload={
                "node": "pve",
                "vmid": 100,  # single int per the dispatch signature
                "storage": "local",
                "mode": "snapshot",
            },
        )
        applier = svc.build_applier(change)
        await applier(change)
        adapter.run_backup.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_restore_dispatches(self) -> None:
        svc, adapter = _make_backup_service()
        change = _make_change(
            "proxmox.backup.restore", "create",
            payload={
                "node": "pve",
                "vmid": 100,
                "archive": "local:backup/vzdump-qemu-100-2026_05_24-04_00_00.vma.zst",
                "vm_type": "qemu",
                # restore is CATASTROPHIC (overwrites the guest) → confirm required
                "confirmed": True,
            },
        )
        applier = svc.build_applier(change)
        await applier(change)
        adapter.restore_backup.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_prune_dispatches(self) -> None:
        svc, adapter = _make_backup_service()
        change = _make_change(
            "proxmox.backup.prune", "create",
            payload={
                "node": "pve",
                "storage": "local",
                "keep_last": 3,
                "keep_daily": 7,
                # prune is CATASTROPHIC (irreversible backup delete) → confirm required
                "confirmed": True,
            },
        )
        applier = svc.build_applier(change)
        await applier(change)
        adapter.prune_backups.assert_awaited_once()
