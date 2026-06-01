# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Apply-path tests for ``GatewayProxmoxStorageService``.

Storage has only two features but the security-relevant validators
(volid grammar, upload filename allow-list, upload sandbox path)
need explicit coverage — they're the last line of defense against
``delete_volume`` deleting another tenant's data or ``upload``
streaming ``/etc/passwd`` to the cluster as an ISO.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_proxmox_storage import (
    _APPLY as APPLY,
)
from app.services.adapter_proxmox_storage import (
    GatewayProxmoxStorageService,
    _validate_upload_filename,
    _validate_upload_path,
    _validate_volid,
)


def _change(feature: str, op: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature, operation=op,
        payload=kw.get("payload", {}), target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _svc() -> tuple[GatewayProxmoxStorageService, MagicMock]:
    s = GatewayProxmoxStorageService(MagicMock())
    a = MagicMock()
    for name in ("delete_storage_volume", "upload_to_storage"):
        setattr(a, name, AsyncMock(return_value=AdapterResult.ok(data={"upid": "T"})))
    # Volid IDOR guard fetches the live storage content before
    # allowing delete — default the mock to "volume present" so
    # happy-path tests dispatch; ownership-check tests override
    # the return value per-case.
    a.get_storage_content = AsyncMock(return_value=AdapterResult.ok(data=[
        {"volid": "local-lvm:vm-100-disk-0", "format": "raw", "size": 1024},
    ]))
    a.disconnect = AsyncMock()

    async def _gc(*_a, **_kw): return MagicMock()
    async def _ga(*_a, **_kw): return a
    s._get_controller = _gc  # type: ignore[assignment]
    s._get_proxmox_adapter = _ga  # type: ignore[assignment]
    return s, a


class TestApplyTable:
    @pytest.mark.parametrize("feature,op", [
        ("proxmox.storage.delete_volume", "delete"),
        ("proxmox.storage.upload", "create"),
    ])
    def test_pair_present(self, feature: str, op: str) -> None:
        assert (feature, op) in APPLY


class TestVolidValidator:
    @pytest.mark.parametrize("good", [
        "local-lvm:vm-100-disk-0",
        "local:backup/vzdump-qemu-100.vma.zst",
        "nfs1:iso/debian-12.iso",
    ])
    def test_valid_volid(self, good: str) -> None:
        assert _validate_volid(good) == good

    @pytest.mark.parametrize("bad", [
        "/etc/passwd",
        "noseparator",
        "local-lvm:",
        ":vm-100-disk-0",
        "local-lvm:../../../etc/shadow",
    ])
    def test_bad_volid_rejected(self, bad: str) -> None:
        with pytest.raises(HTTPException) as e:
            _validate_volid(bad)
        assert e.value.status_code == 400


class TestUploadValidators:
    @pytest.mark.parametrize("good", [
        "debian-12.iso", "alpine.iso", "ubuntu-22.04.iso",
        "container-template.tar.gz", "ct.tar.xz",
    ])
    def test_valid_filename(self, good: str) -> None:
        assert _validate_upload_filename(good) == good

    @pytest.mark.parametrize("bad", [
        "../etc/passwd",      # extension fail
        "image.exe",          # extension fail
        "shell.sh",           # extension fail
        "../image.iso",       # path traversal in filename
        "noslash/image.iso",  # path separator in filename
        "back\\slash.iso",    # windows-style separator
        "null\x00byte.iso",   # null byte
        "",                   # empty
    ])
    def test_bad_filename_rejected(self, bad: str) -> None:
        with pytest.raises(HTTPException) as e:
            _validate_upload_filename(bad)
        assert e.value.status_code == 400

    def test_upload_path_must_be_in_sandbox(self) -> None:
        with pytest.raises(HTTPException):
            _validate_upload_path("/etc/passwd")
        with pytest.raises(HTTPException):
            _validate_upload_path("/root/.ssh/id_rsa")


class TestDispatch:
    @pytest.mark.asyncio
    async def test_delete_volume_dispatches(self) -> None:
        svc, ad = _svc()
        # delete_volume is CATASTROPHIC → pre-flight gate requires confirmed=true.
        c = _change("proxmox.storage.delete_volume", "delete",
                    target_id="local-lvm:vm-100-disk-0",
                    payload={"node": "pve", "storage": "local-lvm", "confirmed": True})
        await svc.build_applier(c)(c)
        ad.delete_storage_volume.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_delete_volume_without_confirmation_is_blocked(self) -> None:
        # Pre-flight safety: a confirmed volume that passes the IDOR guard is
        # STILL refused (409) without confirmed=true — irreversible data loss.
        svc, ad = _svc()
        c = _change("proxmox.storage.delete_volume", "delete",
                    target_id="local-lvm:vm-100-disk-0",
                    payload={"node": "pve", "storage": "local-lvm"})  # no confirmed
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 409
        ad.delete_storage_volume.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_volume_rejects_bad_volid(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.storage.delete_volume", "delete",
                    target_id="/etc/shadow",
                    payload={"node": "pve", "storage": "local"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400
        ad.delete_storage_volume.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_volume_idor_guard_404_on_unknown_volid(self) -> None:
        """Format check alone doesn't prove the
        volume is OURS. Reject if the volid isn't in the live
        storage content for this controller."""
        svc, ad = _svc()
        # Storage content list does NOT include this volid.
        ad.get_storage_content.return_value = AdapterResult.ok(data=[
            {"volid": "local-lvm:vm-100-disk-0"},
        ])
        c = _change("proxmox.storage.delete_volume", "delete",
                    target_id="other-tenant-storage:vm-999-disk-0",
                    payload={"node": "pve", "storage": "other-tenant-storage"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 404
        ad.delete_storage_volume.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_volume_fail_closed_on_content_fetch_fail(self) -> None:
        """If we can't list the storage content, refuse the delete."""
        svc, ad = _svc()
        ad.get_storage_content.return_value = AdapterResult.fail("network down")
        c = _change("proxmox.storage.delete_volume", "delete",
                    target_id="local-lvm:vm-100-disk-0",
                    payload={"node": "pve", "storage": "local-lvm"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 502
        ad.delete_storage_volume.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_upload_requires_all_fields(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.storage.upload", "create",
                    payload={"node": "pve", "storage": "local"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_unknown_feature_400(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.storage.not_real", "create",
                    target_id="x", payload={"node": "pve"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400
