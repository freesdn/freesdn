# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Apply-path tests for ``GatewayProxmoxHaService``."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_proxmox_ha import (
    _APPLY as APPLY,
    GatewayProxmoxHaService,
)


def _change(feature: str, op: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature, operation=op,
        payload=kw.get("payload", {}), target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _svc() -> tuple[GatewayProxmoxHaService, MagicMock]:
    s = GatewayProxmoxHaService(MagicMock())
    a = MagicMock()
    for name in (
        "create_ha_group", "delete_ha_group",
        "create_ha_resource", "delete_ha_resource",
    ):
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
        ("proxmox.ha.group", "create"),
        ("proxmox.ha.group", "delete"),
        ("proxmox.ha.resource", "create"),
        ("proxmox.ha.resource", "delete"),
    ])
    def test_pair_present(self, feature: str, op: str) -> None:
        assert (feature, op) in APPLY


class TestGroupDispatch:
    @pytest.mark.asyncio
    async def test_create_group_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.ha.group", "create",
                    payload={"group": "primary", "nodes": "pve:100,pve2:50"})
        await svc.build_applier(c)(c)
        ad.create_ha_group.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_requires_nodes(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.ha.group", "create", payload={"group": "primary"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_group_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.ha.group", "delete", target_id="primary", payload={"confirmed": True})
        await svc.build_applier(c)(c)
        ad.delete_ha_group.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_delete_requires_target(self) -> None:
        svc, _ = _svc()
        # confirmed=true clears the catastrophic-delete gate so this isolates the
        # target-required (400) validation that follows it.
        c = _change("proxmox.ha.group", "delete", target_id=None, payload={"confirmed": True})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400


class TestResourceDispatch:
    @pytest.mark.asyncio
    async def test_create_resource_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.ha.resource", "create",
                    payload={"sid": "vm:100", "group": "primary"})
        await svc.build_applier(c)(c)
        ad.create_ha_resource.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_requires_sid(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.ha.resource", "create", payload={"group": "primary"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_resource_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.ha.resource", "delete", target_id="vm:100", payload={"confirmed": True})
        await svc.build_applier(c)(c)
        ad.delete_ha_resource.assert_awaited_once()


class TestUnknown:
    @pytest.mark.asyncio
    async def test_unknown_feature_400(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.ha.not_real", "create", payload={"sid": "vm:100"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400
