# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Apply-path tests for ``GatewayProxmoxFirewallService``.

Cluster + guest firewall rule create/delete + guest options update,
with action/type/proto allow-list verification.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_proxmox_firewall import (
    _APPLY as APPLY,
    GatewayProxmoxFirewallService,
)


def _change(feature: str, op: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature, operation=op,
        payload=kw.get("payload", {}), target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _svc() -> tuple[GatewayProxmoxFirewallService, MagicMock]:
    s = GatewayProxmoxFirewallService(MagicMock())
    a = MagicMock()
    for name in (
        "create_firewall_rule", "delete_firewall_rule",
        "create_guest_firewall_rule", "delete_guest_firewall_rule",
        "update_guest_firewall_options",
    ):
        setattr(a, name, AsyncMock(return_value=AdapterResult.ok(data={"upid": "T"})))
    a.disconnect = AsyncMock()
    async def _gc(*_a, **_kw): return MagicMock()
    async def _ga(*_a, **_kw): return a
    s._get_controller = _gc  # type: ignore[assignment]
    # Firewall service has its own ``_build_adapter`` helper in
    # addition to the inherited ``_get_proxmox_adapter`` — mock both
    # so the applier path doesn't reach the real cred-decrypt code.
    s._get_proxmox_adapter = _ga  # type: ignore[assignment]
    s._build_adapter = _ga  # type: ignore[assignment]
    return s, a


class TestApplyTable:
    @pytest.mark.parametrize("feature,op", [
        ("proxmox.firewall.cluster_rule", "create"),
        ("proxmox.firewall.cluster_rule", "delete"),
        ("proxmox.firewall.guest_rule", "create"),
        ("proxmox.firewall.guest_rule", "delete"),
        ("proxmox.firewall.guest_options", "update"),
    ])
    def test_pair_present(self, feature: str, op: str) -> None:
        assert (feature, op) in APPLY


class TestClusterRule:
    @pytest.mark.asyncio
    async def test_create_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.firewall.cluster_rule", "create",
                    payload={"action": "ACCEPT", "type": "in", "proto": "tcp",
                             "dport": "22", "comment": "ssh"})
        await svc.build_applier(c)(c)
        ad.create_firewall_rule.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_rejects_bad_action(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.firewall.cluster_rule", "create",
                    payload={"action": "PLZ_DROP", "type": "in"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_create_rejects_bad_proto(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.firewall.cluster_rule", "create",
                    payload={"action": "ACCEPT", "type": "in",
                             "proto": "totally-not-a-proto"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_requires_pos(self) -> None:
        svc, _ = _svc()
        # confirmed=true clears the catastrophic-delete gate so this isolates the
        # pos-required (400) validation that follows it.
        c = _change(
            "proxmox.firewall.cluster_rule", "delete", target_id=None,
            payload={"confirmed": True},
        )
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400


class TestGuestRule:
    @pytest.mark.asyncio
    async def test_create_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.firewall.guest_rule", "create",
                    payload={"node": "pve", "vm_type": "qemu", "vmid": 100,
                             "rule": {"action": "ACCEPT", "type": "in",
                                      "proto": "tcp", "dport": "80"}})
        await svc.build_applier(c)(c)
        ad.create_guest_firewall_rule.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_rejects_missing_node(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.firewall.guest_rule", "create",
                    payload={"vm_type": "qemu", "vmid": 100,
                             "rule": {"action": "ACCEPT", "type": "in"}})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_create_rejects_missing_vmid(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.firewall.guest_rule", "create",
                    payload={"node": "pve", "vm_type": "qemu",
                             "rule": {"action": "ACCEPT", "type": "in"}})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.firewall.guest_rule", "delete",
                    target_id="0",
                    payload={"node": "pve", "vm_type": "qemu", "vmid": 100, "confirmed": True})
        await svc.build_applier(c)(c)
        ad.delete_guest_firewall_rule.assert_awaited_once()


class TestGuestOptions:
    @pytest.mark.asyncio
    async def test_update_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.firewall.guest_options", "update",
                    payload={"node": "pve", "vm_type": "qemu", "vmid": 100,
                             "options": {"enable": 1, "policy_in": "DROP"}})
        await svc.build_applier(c)(c)
        ad.update_guest_firewall_options.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_requires_options_dict(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.firewall.guest_options", "update",
                    payload={"node": "pve", "vm_type": "qemu", "vmid": 100,
                             "options": "not-a-dict"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400
