# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Apply-path tests for ``GatewayProxmoxContainerService``.

Same shape as ``test_proxmox_apply.py`` (vm/snapshot/backup) —
mirrors the per-feature dispatch from
``adapter_proxmox_container.py``.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_proxmox_container import (
    _APPLY as APPLY,
    GatewayProxmoxContainerService,
)


def _change(feature: str, op: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature, operation=op,
        payload=kw.get("payload", {}),
        target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _svc() -> tuple[GatewayProxmoxContainerService, MagicMock]:
    s = GatewayProxmoxContainerService(MagicMock())
    a = MagicMock()
    for name in (
        "create_container", "update_container_config", "delete_vm",
        "clone_container", "start_container", "stop_container",
        "shutdown_container", "reboot_container", "migrate_container",
        "remote_migrate_container", "resize_container_disk",
    ):
        setattr(a, name, AsyncMock(return_value=AdapterResult.ok(data={"upid": "T"})))
    a.disconnect = AsyncMock()

    async def _gc(*_a, **_kw): return MagicMock()
    async def _ga(*_a, **_kw): return a

    s._get_controller = _gc  # type: ignore[assignment]
    s._get_proxmox_adapter = _ga  # type: ignore[assignment]
    return s, a


class TestApplyTable:
    @pytest.mark.parametrize("feature,op", [
        ("proxmox.container.create", "create"),
        ("proxmox.container.config", "update"),
        ("proxmox.container.destroy", "delete"),
        ("proxmox.container.clone", "create"),
        ("proxmox.container.start", "create"),
        ("proxmox.container.stop", "create"),
        ("proxmox.container.shutdown", "create"),
        ("proxmox.container.reboot", "create"),
        ("proxmox.container.migrate", "create"),
        ("proxmox.container.remote_migrate", "create"),
        ("proxmox.container.resize_disk", "update"),
    ])
    def test_pair_present(self, feature: str, op: str) -> None:
        assert (feature, op) in APPLY


class TestDispatch:
    @pytest.mark.asyncio
    async def test_destroy_dispatches_with_lxc(self) -> None:
        svc, ad = _svc()
        # destroy is CATASTROPHIC: preflight_gate raises 409 unless the staged
        # payload carries confirmed=true. Pass it so dispatch proceeds.
        c = _change("proxmox.container.destroy", "delete",
                    target_id="200", payload={"node": "pve", "confirmed": True})
        await svc.build_applier(c)(c)
        ad.delete_vm.assert_awaited_once()
        args = ad.delete_vm.await_args.args
        assert args[0] == "pve" and args[1] == 200 and args[2] == "lxc"

    @pytest.mark.asyncio
    async def test_start_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.container.start", "create",
                    target_id="200", payload={"node": "pve"})
        await svc.build_applier(c)(c)
        ad.start_container.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_migrate_dispatches_with_online_flag(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.container.migrate", "create",
                    target_id="200",
                    payload={"node": "pve", "target": "pve2", "online": True})
        await svc.build_applier(c)(c)
        ad.migrate_container.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_missing_node_400(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.container.start", "create",
                    target_id="200", payload={})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_unknown_feature_400(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.container.not_real", "create",
                    target_id="200", payload={"node": "pve"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400
