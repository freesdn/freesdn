# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""OPNsense write pre-flight safety: risk classification, the catastrophic-op
confirmation gate, and the central ``opnsense.*``-scoped enforcement helper.

Owner rule (production firewall): system ops + ALL deletes are blocked unless
the staged change carries ``confirmed=true``; service stop/restart + IDS
disable/disconnect/alert-drop warn but proceed.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.services.adapter_opnsense_preflight import (
    PreflightResult,
    Risk,
    assess,
    classify,
    enforce_opnsense_preflight,
    gate,
    preflight_gate,
)


class _Res:
    def __init__(self, data):
        self.success = True
        self.data = data


@pytest.mark.parametrize(
    "feature,operation,expected",
    [
        # System ops → catastrophic (regardless of operation field)
        ("opnsense.system.reboot", "create", Risk.CATASTROPHIC),
        ("opnsense.system.halt", "create", Risk.CATASTROPHIC),
        ("opnsense.system.firmware_update", "create", Risk.CATASTROPHIC),
        ("opnsense.system.backup_restore", "create", Risk.CATASTROPHIC),
        # backup_delete is registered as operation="create" but must still block
        ("opnsense.system.backup_delete", "create", Risk.CATASTROPHIC),
        # ANY delete → catastrophic
        ("opnsense.firewall.rule", "delete", Risk.CATASTROPHIC),
        ("opnsense.firewall.alias", "delete", Risk.CATASTROPHIC),
        ("opnsense.nat.source_rule", "delete", Risk.CATASTROPHIC),
        ("opnsense.nat.port_forward", "delete", Risk.CATASTROPHIC),
        ("opnsense.routing.static_route", "delete", Risk.CATASTROPHIC),
        ("opnsense.dns.host_override", "delete", Risk.CATASTROPHIC),
        ("opnsense.vpn.wireguard.peer", "delete", Risk.CATASTROPHIC),
        ("opnsense.interfaces.vlan", "delete", Risk.CATASTROPHIC),
        # Destructive → warn, not block
        ("opnsense.services.stop", "create", Risk.DESTRUCTIVE),
        ("opnsense.services.restart", "create", Risk.DESTRUCTIVE),
        ("opnsense.vpn.ipsec.disconnect", "create", Risk.DESTRUCTIVE),
        ("opnsense.ids.rule_disable", "create", Risk.DESTRUCTIVE),
        ("opnsense.ids.alert_drop", "create", Risk.DESTRUCTIVE),
        # Safe creates/updates/applies/starts
        ("opnsense.firewall.rule", "create", Risk.SAFE),
        ("opnsense.firewall.rule", "update", Risk.SAFE),
        ("opnsense.firewall.apply", "create", Risk.SAFE),
        ("opnsense.services.start", "create", Risk.SAFE),
        ("opnsense.system.backup_create", "create", Risk.SAFE),
        ("opnsense.system.firmware_check", "create", Risk.SAFE),
        ("opnsense.ids.rule_enable", "create", Risk.SAFE),
    ],
)
def test_classify(feature, operation, expected) -> None:
    assert classify(feature, operation) is expected


def test_gate_blocks_catastrophic_without_confirmation() -> None:
    res = PreflightResult("opnsense.firewall.rule", "delete", Risk.CATASTROPHIC, warnings=["x"])
    with pytest.raises(HTTPException) as ei:
        gate(res, {})
    assert ei.value.status_code == 409
    assert "confirmed=true" in ei.value.detail


def test_gate_allows_catastrophic_with_confirmation() -> None:
    res = PreflightResult("opnsense.system.reboot", "create", Risk.CATASTROPHIC)
    gate(res, {"confirmed": True})  # no raise


def test_gate_allows_destructive_and_safe_without_confirmation() -> None:
    gate(PreflightResult("opnsense.services.stop", "create", Risk.DESTRUCTIVE), {})
    gate(PreflightResult("opnsense.firewall.rule", "create", Risk.SAFE), {})


class TestEnforceHelper:
    """``enforce_opnsense_preflight`` is the central, prefix-scoped runtime gate."""

    def test_blocks_opnsense_delete_without_confirm(self) -> None:
        with pytest.raises(HTTPException) as ei:
            enforce_opnsense_preflight("opnsense.firewall.rule", "delete", {})
        assert ei.value.status_code == 409

    def test_blocks_opnsense_reboot_without_confirm(self) -> None:
        with pytest.raises(HTTPException) as ei:
            enforce_opnsense_preflight("opnsense.system.reboot", "create", None)
        assert ei.value.status_code == 409

    def test_allows_when_confirmed(self) -> None:
        enforce_opnsense_preflight("opnsense.firewall.rule", "delete", {"confirmed": True})

    def test_allows_safe_opnsense_op(self) -> None:
        enforce_opnsense_preflight("opnsense.firewall.rule", "create", {})

    @pytest.mark.parametrize(
        "feature,operation",
        [
            # Other vendors must NOT be touched by the opnsense gate, even on a delete.
            ("vpn.ipsec.policy", "delete"),
            ("proxmox.vm.destroy", "delete"),
            ("bulk.device.reboot", "create"),
            ("wifi.locate_ap", "create"),
        ],
    )
    def test_no_op_for_non_opnsense_features(self, feature, operation) -> None:
        # No raise — these are handled by their own vendors' gates, not this one.
        enforce_opnsense_preflight(feature, operation, {})

    def test_no_op_on_none_feature(self) -> None:
        enforce_opnsense_preflight(None, None, None)


@pytest.mark.asyncio
async def test_assess_backup_restore_surfaces_backup_and_warns() -> None:
    class _A:
        async def get_backup_list(self):
            return _Res([
                {"filename": "config-2026.xml", "created": "2026-06-01"},
                {"filename": "config-old.xml", "created": "2025-01-01"},
            ])

    res = await assess(
        "opnsense.system.backup_restore", "create",
        {"target_id": "config-2026.xml"}, adapter=_A(),
    )
    assert res.risk is Risk.CATASTROPHIC
    assert res.requires_confirmation is True
    assert res.impact["backup"]["filename"] == "config-2026.xml"
    assert any("ENTIRE running configuration" in w for w in res.warnings)


@pytest.mark.asyncio
async def test_assess_firewall_rule_delete_reports_rule() -> None:
    class _A:
        async def get_firewall_rules(self):
            return _Res([{"uuid": "abc-123", "description": "allow mgmt", "enabled": "1"}])

    res = await assess(
        "opnsense.firewall.rule", "delete", {"target_id": "abc-123"}, adapter=_A()
    )
    assert res.impact["rule"]["description"] == "allow mgmt"
    assert any("allow mgmt" in w for w in res.warnings)


@pytest.mark.asyncio
async def test_assess_live_check_failure_degrades_not_raises() -> None:
    class _Bad:
        async def get_backup_list(self):
            raise RuntimeError("device unreachable")

    res = await assess(
        "opnsense.system.backup_restore", "create",
        {"target_id": "x.xml"}, adapter=_Bad(),
    )
    assert res.risk is Risk.CATASTROPHIC  # still classified
    assert any("incomplete" in w for w in res.warnings)


@pytest.mark.asyncio
async def test_preflight_gate_blocks_then_allows_when_confirmed() -> None:
    class _A:
        async def get_firewall_rules(self):
            return _Res([{"uuid": "abc-123", "description": "allow mgmt", "enabled": "1"}])

    with pytest.raises(HTTPException) as ei:
        await preflight_gate(_A(), "opnsense.firewall.rule", "delete", {"target_id": "abc-123"})
    assert ei.value.status_code == 409
    res = await preflight_gate(
        _A(), "opnsense.firewall.rule", "delete", {"target_id": "abc-123", "confirmed": True}
    )
    assert res.risk is Risk.CATASTROPHIC and res.impact.get("rule")
