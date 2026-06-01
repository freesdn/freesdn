# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Omada as a Fabric TARGET — the network module's write operations.

``network.client.block`` and ``network.device.reboot`` let a Connection
auto-respond to an event (camera/IDS detection → block a Wi-Fi client; a health
signal → reboot an AP) by STAGING through the Omada bulk pipeline. The Fabric
never force-applies; an operator signs off via the dual-gate, and the
catastrophic-preflight gate still governs the apply.

Permission note: the enforced grants are colon-style (``network:read`` /
``network:write`` / ``network:*``), NOT the dot-style nav ``ModulePermission``s
(``network.view``) — those are granted to no role, so an op declaring one would
be super_admin-only. These tests pin the correct enforcement strings.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.modules.network.module import NetworkModule


def _ops_by_id() -> dict:
    return {op.id: op for op in NetworkModule().get_operations()}


class TestFabricOperationDeclarations:
    def test_block_and_reboot_are_staged_writes(self) -> None:
        ops = _ops_by_id()
        block = ops["network.client.block"]
        reboot = ops["network.device.reboot"]
        for op, feature in ((block, "bulk.client.block"), (reboot, "bulk.device.reboot")):
            assert op.write is True
            assert op.feature == feature          # routes to the Omada bulk applier
            assert op.handler is None             # staged, never executed raw
            assert op.permission == "network:write"
            # required routing + payload fields
            assert set(op.input_schema["required"]) == {"controller_id", "site_id", "macs"}

    def test_read_op_uses_real_colon_permission(self) -> None:
        # Regression: was "network.view" (a nav-only ModulePermission granted to
        # no role → super_admin-only). Must be the colon-style grant.
        assert _ops_by_id()["network.client.list"].permission == "network:read"

    def test_all_write_ops_declare_feature_and_permission(self) -> None:
        # The Operation dataclass enforces this, but pin it so a future edit that
        # drops the feature/permission fails loudly here, not at registry load.
        for op in NetworkModule().get_operations():
            if op.write:
                assert op.feature and op.permission


class TestBulkApplierResolvesOmadaSiteId:
    """A change staged by the Fabric executor threads only the FreeSDN site_id
    (no omada_site_id). The bulk applier must resolve omada_site_id from the
    controller's site_mappings so the write targets the right Omada site."""

    @pytest.mark.asyncio
    async def test_applier_resolves_omada_site_from_site_id(self) -> None:
        from app.services.adapter_omada_bulk import GatewayBulkService

        site_id = uuid4()
        ctrl = SimpleNamespace(
            id=uuid4(), organization_id=uuid4(),
            site_mappings={"omada-site-A": str(site_id), "omada-site-B": str(uuid4())},
        )
        client = SimpleNamespace(bulk_block_clients=AsyncMock(return_value={"ok": True}))

        svc = GatewayBulkService(AsyncMock())
        svc._get_controller = AsyncMock(return_value=ctrl)
        svc._get_client = AsyncMock(return_value=client)
        # db.get(Site, site_id) → a Site whose id matches the mapping value
        svc.db.get = AsyncMock(return_value=SimpleNamespace(id=site_id))

        change = SimpleNamespace(
            controller_id=ctrl.id, organization_id=ctrl.organization_id,
            omada_site_id=None,            # Fabric-staged → no omada_site_id
            site_id=site_id,
            feature="bulk.client.block", operation="create",
            payload={"macs": ["AA:BB:CC:00:00:01"]}, target_id=None,
        )
        applier = svc.build_applier(change)
        await applier(change)

        # resolved "omada-site-A" from site_mappings (NOT "" and NOT site-B)
        client.bulk_block_clients.assert_awaited_once_with("omada-site-A", ["AA:BB:CC:00:00:01"])

    @pytest.mark.asyncio
    async def test_applier_keeps_explicit_omada_site_id(self) -> None:
        # A REST-staged change already carries omada_site_id — don't re-resolve.
        from app.services.adapter_omada_bulk import GatewayBulkService

        ctrl = SimpleNamespace(id=uuid4(), organization_id=uuid4(), site_mappings={})
        client = SimpleNamespace(bulk_reboot_devices=AsyncMock(return_value={"ok": True}))
        svc = GatewayBulkService(AsyncMock())
        svc._get_controller = AsyncMock(return_value=ctrl)
        svc._get_client = AsyncMock(return_value=client)
        svc.db.get = AsyncMock(return_value=None)

        change = SimpleNamespace(
            controller_id=ctrl.id, organization_id=ctrl.organization_id,
            omada_site_id="omada-explicit", site_id=uuid4(),
            feature="bulk.device.reboot", operation="create",
            payload={"macs": ["AA:BB:CC:00:00:02"]}, target_id=None,
        )
        await svc.build_applier(change)(change)

        client.bulk_reboot_devices.assert_awaited_once_with("omada-explicit", ["AA:BB:CC:00:00:02"])
        svc.db.get.assert_not_awaited()  # no resolution needed
