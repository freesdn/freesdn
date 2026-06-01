# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Apply-path tests for the OpenWrt staged-write services.

These cover the IDOR + perf invariants:

1. ``_APPLY`` table contains every (feature, operation) pair the
   stage endpoint claims to support.
2. Applier dispatches each (feature, op) to the right adapter method.
3. **IDOR guard** — update/delete refuse when ``target_id`` isn't in
   the live items list (rejects guessed UCI section names from
   other tenants' controllers).
4. **Perf hint** — when the verify guard matches, the resolved
   ``uci_name`` is forwarded to the adapter so it can skip its own
   ``uci_get_all`` lookup.
5. Verify-list fetch failure → 502 (fail closed; we'd rather refuse
   a write whose target we couldn't verify than dispatch blind).

The adapter client is mocked at the service-layer boundary
(``_get_adapter`` / ``_resolve_controller_or_gateway``) so no live
OpenWrt box is contacted.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.services.adapter_openwrt_dhcp import (
    _APPLY as DHCP_APPLY,
    GatewayOpenWrtDhcpService,
)
from app.services.adapter_openwrt_firewall import (
    _APPLY as FW_APPLY,
    GatewayOpenWrtFirewallService,
)


# ─── Shared fixtures ───────────────────────────────────────────────


def _make_change(
    feature: str, operation: str, **kw: Any
) -> SimpleNamespace:
    """A change-shaped object the applier reads. Only the named fields
    are used; SimpleNamespace is sufficient (no DB row needed)."""
    return SimpleNamespace(
        feature=feature,
        operation=operation,
        payload=kw.get("payload", {}),
        target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _make_fw_service() -> tuple[GatewayOpenWrtFirewallService, MagicMock]:
    """Firewall service wired to a mocked adapter."""
    svc = GatewayOpenWrtFirewallService(MagicMock())
    mock_client = MagicMock()

    # All adapter CRUD methods return AdapterResult.ok by default; tests
    # that care about specific dispatches re-assign per case.
    for name in (
        "create_firewall_rule", "update_firewall_rule", "delete_firewall_rule",
        "create_port_forward", "update_port_forward", "delete_port_forward",
        "create_source_nat_rule", "update_source_nat_rule", "delete_source_nat_rule",
        "get_firewall_rules", "get_port_forwards", "get_source_nat_rules",
    ):
        setattr(
            mock_client, name,
            AsyncMock(return_value=AdapterResult.ok(message=f"{name} ok")),
        )

    async def _resolve(*_a: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _get_adapter(*_a: Any, **_kw: Any) -> Any:
        return mock_client

    svc._resolve_controller_or_gateway = _resolve  # type: ignore[assignment]
    svc._get_adapter = _get_adapter  # type: ignore[assignment]
    return svc, mock_client


def _make_dhcp_service() -> tuple[GatewayOpenWrtDhcpService, MagicMock]:
    svc = GatewayOpenWrtDhcpService(MagicMock())
    mock_client = MagicMock()
    for name in (
        "create_dhcp_static_mapping", "update_dhcp_static_mapping",
        "delete_dhcp_static_mapping",
        "create_dns_override", "update_dns_override", "delete_dns_override",
        "get_dhcp_static_mappings", "get_dns_overrides",
    ):
        setattr(
            mock_client, name,
            AsyncMock(return_value=AdapterResult.ok(message=f"{name} ok")),
        )

    async def _resolve(*_a: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _get_adapter(*_a: Any, **_kw: Any) -> Any:
        return mock_client

    svc._resolve_controller_or_gateway = _resolve  # type: ignore[assignment]
    svc._get_adapter = _get_adapter  # type: ignore[assignment]
    return svc, mock_client


# ─── _APPLY table completeness ──────────────────────────────────────


class TestApplyTableCompleteness:
    """Every (feature, op) the stage endpoint accepts MUST have a row
    in ``_APPLY``. Missing rows turn into 400 at apply time with a
    'no applier for feature' message — the table is the contract."""

    @pytest.mark.parametrize(
        "feature,op",
        [
            ("openwrt.firewall.rule", "create"),
            ("openwrt.firewall.rule", "update"),
            ("openwrt.firewall.rule", "delete"),
            ("openwrt.firewall.port_forward", "create"),
            ("openwrt.firewall.port_forward", "update"),
            ("openwrt.firewall.port_forward", "delete"),
            ("openwrt.firewall.source_nat", "create"),
            ("openwrt.firewall.source_nat", "update"),
            ("openwrt.firewall.source_nat", "delete"),
        ],
    )
    def test_firewall_apply_table_has_pair(
        self, feature: str, op: str,
    ) -> None:
        assert (feature, op) in FW_APPLY

    @pytest.mark.parametrize(
        "feature,op",
        [
            ("openwrt.dhcp.static_host", "create"),
            ("openwrt.dhcp.static_host", "update"),
            ("openwrt.dhcp.static_host", "delete"),
            ("openwrt.dns.override", "create"),
            ("openwrt.dns.override", "update"),
            ("openwrt.dns.override", "delete"),
        ],
    )
    def test_dhcp_apply_table_has_pair(
        self, feature: str, op: str,
    ) -> None:
        assert (feature, op) in DHCP_APPLY


# ─── Create-path dispatch ───────────────────────────────────────────


class TestCreateDispatch:
    @pytest.mark.asyncio
    async def test_firewall_rule_create_dispatches(self) -> None:
        svc, client = _make_fw_service()
        change = _make_change(
            "openwrt.firewall.rule", "create",
            payload={"name": "test", "src": "wan", "target": "DROP"},
        )
        applier = svc.build_applier(change)
        result = await applier(change)
        assert result["success"] is True
        client.create_firewall_rule.assert_awaited_once_with(
            {"name": "test", "src": "wan", "target": "DROP"},
        )
        # Verify-list should NOT be called on create (no target_id yet).
        client.get_firewall_rules.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_dhcp_static_host_create_dispatches(self) -> None:
        svc, client = _make_dhcp_service()
        change = _make_change(
            "openwrt.dhcp.static_host", "create",
            payload={"hostname": "h", "mac_address": "aa:bb:cc:dd:ee:ff",
                     "ip_address": "192.168.1.150"},
        )
        applier = svc.build_applier(change)
        result = await applier(change)
        assert result["success"] is True
        client.create_dhcp_static_mapping.assert_awaited_once()
        client.get_dhcp_static_mappings.assert_not_awaited()


# ─── IDOR guard ─────────────────────────────────────────────────────


class TestIdorGuard:
    """The applier MUST fetch the live list and verify target_id is in
    it before update/delete. Without this, an operator could guess or
    enumerate a UCI section name from another tenant's controller and
    stage a destructive write."""

    @pytest.mark.asyncio
    async def test_update_with_unknown_target_id_raises_404(self) -> None:
        svc, client = _make_fw_service()
        # Live list contains rule with id=GOOD-ID and uci_name=cfg01.
        client.get_firewall_rules.return_value = AdapterResult.ok(
            data={"rules": [
                {"id": "GOOD-ID", "uci_name": "cfg01", "name": "x"},
            ]},
        )
        change = _make_change(
            "openwrt.firewall.rule", "update",
            target_id="BOGUS-OTHER-TENANT-ID",
            payload={"name": "renamed"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 404
        assert "not found on this controller" in exc.value.detail
        # The adapter's update method must NOT have been called.
        client.update_firewall_rule.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_with_unknown_target_id_raises_404(self) -> None:
        svc, client = _make_fw_service()
        client.get_firewall_rules.return_value = AdapterResult.ok(
            data={"rules": []},
        )
        change = _make_change(
            "openwrt.firewall.rule", "delete",
            target_id="ANY",
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 404
        client.delete_firewall_rule.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_dhcp_static_update_unknown_target_raises_404(self) -> None:
        svc, client = _make_dhcp_service()
        client.get_dhcp_static_mappings.return_value = AdapterResult.ok(
            data={"static_mappings": [
                {"id": "REAL", "uci_name": "cfg01"},
            ]},
        )
        change = _make_change(
            "openwrt.dhcp.static_host", "update",
            target_id="GUESSED-FROM-OTHER-TENANT",
            payload={"hostname": "x"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 404
        client.update_dhcp_static_mapping.assert_not_awaited()


# ─── Perf: uci_name hint forwarding ─────────────────────────────────


class TestUciNameHintForwarding:
    """When the verify-list matches a target, the resolved ``uci_name``
    must be passed to the adapter so it can skip its own
    ``uci_get_all`` lookup. Saves one full UCI fetch per write."""

    @pytest.mark.asyncio
    async def test_update_forwards_resolved_uci_name(self) -> None:
        svc, client = _make_fw_service()
        client.get_firewall_rules.return_value = AdapterResult.ok(
            data={"rules": [
                {"id": "TARGET-UUID", "uci_name": "cfg_my_rule", "name": "r"},
            ]},
        )
        change = _make_change(
            "openwrt.firewall.rule", "update",
            target_id="TARGET-UUID",
            payload={"name": "new-name"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        # Adapter call must carry the resolved uci_name as a kwarg —
        # that's the perf optimization the test exists to guard.
        client.update_firewall_rule.assert_awaited_once_with(
            "TARGET-UUID", {"name": "new-name"}, uci_name="cfg_my_rule",
        )

    @pytest.mark.asyncio
    async def test_delete_firewall_rule_forwards_resolved_uci_name(
        self,
    ) -> None:
        svc, client = _make_fw_service()
        client.get_firewall_rules.return_value = AdapterResult.ok(
            data={"rules": [
                {"id": "TARGET", "uci_name": "cfg_rule", "name": "r"},
            ]},
        )
        change = _make_change(
            "openwrt.firewall.rule", "delete", target_id="TARGET",
        )
        applier = svc.build_applier(change)
        await applier(change)
        # delete_firewall_rule has the legacy signature where the
        # positional arg is already named ``uci_name``; the resolved
        # name flows in as ``resolved_uci_name=`` to skip the lookup.
        client.delete_firewall_rule.assert_awaited_once_with(
            "TARGET", resolved_uci_name="cfg_rule",
        )

    @pytest.mark.asyncio
    async def test_delete_port_forward_forwards_uci_name(self) -> None:
        svc, client = _make_fw_service()
        client.get_port_forwards.return_value = AdapterResult.ok(
            data={"port_forwards": [
                {"id": "PFTARGET", "uci_name": "cfg_pf", "name": "fwd"},
            ]},
        )
        change = _make_change(
            "openwrt.firewall.port_forward", "delete", target_id="PFTARGET",
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.delete_port_forward.assert_awaited_once_with(
            "PFTARGET", uci_name="cfg_pf",
        )

    @pytest.mark.asyncio
    async def test_target_id_matches_uci_name_directly(self) -> None:
        """Verify-list accepts a match on uci_name OR stable id —
        operators sometimes pass the UCI section name verbatim."""
        svc, client = _make_fw_service()
        client.get_firewall_rules.return_value = AdapterResult.ok(
            data={"rules": [
                {"id": "STABLE-ID", "uci_name": "cfg_rule", "name": "r"},
            ]},
        )
        change = _make_change(
            "openwrt.firewall.rule", "update",
            target_id="cfg_rule",  # using uci_name as the target_id
            payload={"name": "x"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.update_firewall_rule.assert_awaited_once_with(
            "cfg_rule", {"name": "x"}, uci_name="cfg_rule",
        )


# ─── Fail-closed: verify-list fetch failure ─────────────────────────


class TestVerifyListFailureIsClosed:
    """If we can't fetch the live list, the applier must REFUSE the
    write, not dispatch blind. The audit's threat model: an attacker
    could try to race the controller offline to bypass the IDOR
    guard."""

    @pytest.mark.asyncio
    async def test_verify_fetch_failure_raises_502(self) -> None:
        svc, client = _make_fw_service()
        client.get_firewall_rules.return_value = AdapterResult.fail(
            "controller unreachable",
        )
        change = _make_change(
            "openwrt.firewall.rule", "update",
            target_id="ANY", payload={"name": "x"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 502
        assert "could not fetch" in exc.value.detail
        client.update_firewall_rule.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unknown_feature_refused_at_apply_time(self) -> None:
        """A feature not in ``_APPLY`` must raise 400, not silently
        no-op or dispatch to a wrong method."""
        svc, client = _make_fw_service()
        change = _make_change(
            "openwrt.firewall.not_a_real_feature", "create",
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "no applier for feature" in exc.value.detail
