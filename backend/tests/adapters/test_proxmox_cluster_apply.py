# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Apply-path tests for ``GatewayProxmoxClusterService``."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_proxmox_cluster import (
    _APPLY as APPLY,
    GatewayProxmoxClusterService,
)


def _change(feature: str, op: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature, operation=op,
        payload=kw.get("payload", {}), target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _svc() -> tuple[GatewayProxmoxClusterService, MagicMock]:
    s = GatewayProxmoxClusterService(MagicMock())
    a = MagicMock()
    for name in ("stop_task", "update_cluster_firewall_options"):
        setattr(a, name, AsyncMock(return_value=AdapterResult.ok(data={"upid": "T"})))
    a.disconnect = AsyncMock()
    async def _gc(*_a, **_kw): return MagicMock()
    async def _ga(*_a, **_kw): return a
    s._get_controller = _gc  # type: ignore[assignment]
    s._build_adapter = _ga  # type: ignore[assignment]
    s._get_proxmox_adapter = _ga  # type: ignore[assignment]
    return s, a


class TestApplyTable:
    @pytest.mark.parametrize("feature,op", [
        ("proxmox.cluster.task_stop", "create"),
        ("proxmox.cluster.firewall_options", "update"),
    ])
    def test_pair_present(self, feature: str, op: str) -> None:
        assert (feature, op) in APPLY


class TestTaskStop:
    @pytest.mark.asyncio
    async def test_task_stop_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.cluster.task_stop", "create",
                    target_id="UPID:pve:00001234:00ABCDEF:00000000:vzdump:100:joe@pam:",
                    payload={"node": "pve"})
        await svc.build_applier(c)(c)
        ad.stop_task.assert_awaited_once()


class TestFirewallOptions:
    @pytest.mark.asyncio
    async def test_update_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.cluster.firewall_options", "update",
                    payload={"enable": 1, "policy_in": "DROP"})
        await svc.build_applier(c)(c)
        ad.update_cluster_firewall_options.assert_awaited_once()


class TestUnknown:
    @pytest.mark.asyncio
    async def test_unknown_feature_400(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.cluster.not_real", "create",
                    target_id="x", payload={})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400
