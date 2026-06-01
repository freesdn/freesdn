# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Apply-path tests for ``GatewayProxmoxNodeService``."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_proxmox_node import (
    _APPLY as APPLY,
)
from app.services.adapter_proxmox_node import (
    GatewayProxmoxNodeService,
)


def _change(feature: str, op: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature, operation=op,
        payload=kw.get("payload", {}), target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _svc() -> tuple[GatewayProxmoxNodeService, MagicMock]:
    s = GatewayProxmoxNodeService(MagicMock())
    a = MagicMock()
    for name in (
        "reboot_node", "shutdown_node", "node_service_action",
        "refresh_node_apt", "upload_custom_certificate",
        "delete_custom_certificate", "renew_node_acme_certificate",
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
        ("proxmox.node.reboot", "create"),
        ("proxmox.node.shutdown", "create"),
        ("proxmox.node.service_action", "create"),
        ("proxmox.node.apt_refresh", "create"),
        ("proxmox.node.certificate_upload", "create"),
        ("proxmox.node.certificate_delete", "delete"),
        ("proxmox.node.acme_renew", "create"),
    ])
    def test_pair_present(self, feature: str, op: str) -> None:
        assert (feature, op) in APPLY


class TestPower:
    @pytest.mark.asyncio
    async def test_reboot_dispatches(self) -> None:
        svc, ad = _svc()
        # node reboot is CATASTROPHIC → pre-flight gate requires confirmed=true.
        c = _change("proxmox.node.reboot", "create", target_id="pve", payload={"confirmed": True})
        await svc.build_applier(c)(c)
        ad.reboot_node.assert_awaited_once_with("pve", force=True)

    @pytest.mark.asyncio
    async def test_shutdown_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change(
            "proxmox.node.shutdown", "create", target_id="pve", payload={"confirmed": True}
        )
        await svc.build_applier(c)(c)
        ad.shutdown_node.assert_awaited_once_with("pve", force=True)

    @pytest.mark.asyncio
    async def test_reboot_without_confirmation_is_blocked(self) -> None:
        # Pre-flight safety: rebooting a node without confirmed=true is refused
        # (409) before the adapter is called.
        svc, ad = _svc()
        c = _change("proxmox.node.reboot", "create", target_id="pve")  # no confirmed
        with pytest.raises(HTTPException) as exc:
            await svc.build_applier(c)(c)
        assert exc.value.status_code == 409
        ad.reboot_node.assert_not_awaited()


class TestServiceAction:
    @pytest.mark.asyncio
    async def test_service_action_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.node.service_action", "create",
                    target_id="pveproxy",
                    payload={"node": "pve", "action": "restart"})
        await svc.build_applier(c)(c)
        ad.node_service_action.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_service_action_rejects_bad_service(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.node.service_action", "create",
                    target_id="systemd-init-shell",
                    payload={"node": "pve", "action": "restart"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_service_action_rejects_bad_action(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.node.service_action", "create",
                    target_id="pveproxy",
                    payload={"node": "pve", "action": "delete-everything"})
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400


class TestCertificate:
    @pytest.mark.asyncio
    async def test_upload_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.node.certificate_upload", "create",
                    target_id="pve",
                    payload={
                        "certificates": "-----BEGIN CERT-----...",
                        "key": "-----BEGIN KEY-----...",
                    })
        await svc.build_applier(c)(c)
        ad.upload_custom_certificate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_upload_requires_both_cert_and_key(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.node.certificate_upload", "create",
                    target_id="pve",
                    payload={"certificates": "..."})  # missing key
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.node.certificate_delete", "delete", target_id="pve")
        await svc.build_applier(c)(c)
        ad.delete_custom_certificate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_acme_renew_dispatches(self) -> None:
        svc, ad = _svc()
        c = _change("proxmox.node.acme_renew", "create", target_id="pve")
        await svc.build_applier(c)(c)
        ad.renew_node_acme_certificate.assert_awaited_once()


class TestUnknown:
    @pytest.mark.asyncio
    async def test_unknown_feature_400(self) -> None:
        svc, _ = _svc()
        c = _change("proxmox.node.not_real", "create", target_id="pve")
        with pytest.raises(HTTPException) as e:
            await svc.build_applier(c)(c)
        assert e.value.status_code == 400
