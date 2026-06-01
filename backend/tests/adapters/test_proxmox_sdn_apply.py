# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Apply-path tests for ``GatewayProxmoxSdnService``."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_proxmox_sdn import (
    _APPLY as APPLY,
    GatewayProxmoxSdnService,
)


def _change(feature: str, op: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature, operation=op,
        payload=kw.get("payload", {}), target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _svc() -> tuple[GatewayProxmoxSdnService, MagicMock]:
    s = GatewayProxmoxSdnService(MagicMock())
    a = MagicMock()
    for name in (
        "create_sdn_zone", "delete_sdn_zone",
        "create_sdn_vnet", "delete_sdn_vnet", "apply_sdn",
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
        ("proxmox.sdn.zone", "create"),
        ("proxmox.sdn.zone", "delete"),
        ("proxmox.sdn.vnet", "create"),
        ("proxmox.sdn.vnet", "delete"),
        ("proxmox.sdn.apply", "create"),
    ])
    def test_pair_present(self, feature: str, op: str) -> None:
        assert (feature, op) in APPLY


class TestZone:
    @pytest.mark.asyncio
    async def test_create_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.sdn.zone", "create",
                    payload={"zone": "myzone", "type": "vlan"})
        await svc.build_applier(c)(c)
        ad.create_sdn_zone.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_delete_dispatches(self) -> None:
        svc, ad = _svc()
        # SDN zone delete is CATASTROPHIC-by-default (unclassified delete) and
        # is gated by preflight_gate -> 409 unless confirmed=true is staged.
        c = _change("proxmox.sdn.zone", "delete", target_id="myzone",
                    payload={"confirmed": True})
        await svc.build_applier(c)(c)
        ad.delete_sdn_zone.assert_awaited_once()


class TestVnet:
    @pytest.mark.asyncio
    async def test_create_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.sdn.vnet", "create",
                    payload={"vnet": "myvnet", "zone": "myzone"})
        await svc.build_applier(c)(c)
        ad.create_sdn_vnet.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_delete_dispatches(self) -> None:
        svc, ad = _svc()
        # SDN vnet delete is CATASTROPHIC-by-default (unclassified delete) and
        # is gated by preflight_gate -> 409 unless confirmed=true is staged.
        c = _change("proxmox.sdn.vnet", "delete", target_id="myvnet",
                    payload={"confirmed": True})
        await svc.build_applier(c)(c)
        ad.delete_sdn_vnet.assert_awaited_once()


class TestApplyFeature:
    @pytest.mark.asyncio
    async def test_apply_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.sdn.apply", "create")
        await svc.build_applier(c)(c)
        ad.apply_sdn.assert_awaited_once()


class TestUnknown:
    @pytest.mark.asyncio
    async def test_unknown_feature_400(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.sdn.not_real", "create", target_id="x")
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400
