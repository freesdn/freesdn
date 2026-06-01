# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Omada write pre-flight safety: risk classification, the catastrophic-op
confirmation gate, and the central controller-type-scoped enforcement helper.

Owner rule (production network core): irreversible device/controller ops
(factory-reset, forget, firmware upgrade, backup restore) + ALL deletes are
blocked unless the staged change carries ``confirmed=true``; bulk reboot/kick/
SSID-disable warn but proceed.

Unlike OPNsense, Omada staged features are BARE (no ``omada.`` prefix), so the
central gate is scoped by the change's CONTROLLER TYPE, not a feature prefix —
these tests pin that scoping (a non-Omada controller is never gated by it).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models.staging import AdapterPendingChange
from app.services.adapter_omada_preflight import (
    PreflightResult,
    Risk,
    assess,
    classify,
    enforce_omada_preflight,
    gate,
    preflight_gate,
)
from app.services.adapter_staging import AdapterStagingService


class _Res:
    def __init__(self, data):
        self.success = True
        self.data = data


@pytest.mark.parametrize(
    "feature,operation,expected",
    [
        # Irreversible device/controller ops → catastrophic (op is "create")
        ("bulk.device.factory_reset", "create", Risk.CATASTROPHIC),
        ("bulk.device.forget", "create", Risk.CATASTROPHIC),
        ("firmware.upgrade", "create", Risk.CATASTROPHIC),
        ("firmware.upgrade.batch", "create", Risk.CATASTROPHIC),
        ("system.backup.restore", "create", Risk.CATASTROPHIC),
        # ANY delete → catastrophic (the production-network blanket rule)
        ("firewall.port_forward", "delete", Risk.CATASTROPHIC),
        ("vpn.wireguard.peer", "delete", Risk.CATASTROPHIC),
        ("vpn.ipsec.policy", "delete", Risk.CATASTROPHIC),
        ("system.admin", "delete", Risk.CATASTROPHIC),
        ("system.backup", "delete", Risk.CATASTROPHIC),
        ("site.template.delete", "delete", Risk.CATASTROPHIC),
        ("switch.mirror_session", "delete", Risk.CATASTROPHIC),
        ("firmware.schedule", "delete", Risk.CATASTROPHIC),
        # Destructive → warn, not block
        ("bulk.device.reboot", "create", Risk.DESTRUCTIVE),
        ("bulk.client.kick", "create", Risk.DESTRUCTIVE),
        ("bulk.ssid.set_state", "create", Risk.DESTRUCTIVE),
        # Safe creates/updates/adopts
        ("bulk.device.adopt", "create", Risk.SAFE),
        ("network.vlan", "create", Risk.SAFE),
        ("network.vlan", "update", Risk.SAFE),
        ("wifi.ssid", "create", Risk.SAFE),
        ("firmware.schedule", "create", Risk.SAFE),
        ("bulk.client.block", "create", Risk.SAFE),
    ],
)
def test_classify(feature, operation, expected) -> None:
    assert classify(feature, operation) is expected


def test_gate_blocks_catastrophic_without_confirmation() -> None:
    res = PreflightResult("bulk.device.factory_reset", "create", Risk.CATASTROPHIC, warnings=["x"])
    with pytest.raises(HTTPException) as ei:
        gate(res, {})
    assert ei.value.status_code == 409
    assert "confirmed=true" in ei.value.detail


def test_gate_allows_catastrophic_with_confirmation() -> None:
    gate(PreflightResult("system.backup.restore", "create", Risk.CATASTROPHIC), {"confirmed": True})


def test_gate_allows_destructive_and_safe_without_confirmation() -> None:
    gate(PreflightResult("bulk.device.reboot", "create", Risk.DESTRUCTIVE), {})
    gate(PreflightResult("wifi.ssid", "create", Risk.SAFE), {})


class TestEnforceHelper:
    """``enforce_omada_preflight`` is the central, controller-type-scoped gate."""

    def test_blocks_omada_delete_without_confirm(self) -> None:
        with pytest.raises(HTTPException) as ei:
            enforce_omada_preflight("omada", "vpn.ipsec.policy", "delete", {})
        assert ei.value.status_code == 409

    def test_blocks_omada_firmware_upgrade_without_confirm(self) -> None:
        with pytest.raises(HTTPException) as ei:
            enforce_omada_preflight("omada", "firmware.upgrade", "create", None)
        assert ei.value.status_code == 409

    def test_blocks_omada_factory_reset_without_confirm(self) -> None:
        with pytest.raises(HTTPException) as ei:
            enforce_omada_preflight("omada", "bulk.device.factory_reset", "create", {})
        assert ei.value.status_code == 409

    def test_allows_when_confirmed(self) -> None:
        enforce_omada_preflight("omada", "bulk.device.forget", "create", {"confirmed": True})

    def test_allows_safe_omada_op(self) -> None:
        enforce_omada_preflight("omada", "wifi.ssid", "create", {})

    def test_case_insensitive_controller_type(self) -> None:
        # controller_type is the enum value "omada"; match it case-insensitively
        # so an enum repr like "ControllerType.OMADA"-derived "Omada"/"OMADA" works.
        for ctype in ("Omada", "OMADA", "omada"):
            with pytest.raises(HTTPException):
                enforce_omada_preflight(ctype, "firmware.upgrade", "create", {})

    @pytest.mark.parametrize(
        "controller_type", ["opnsense", "proxmox", "mikrotik", "unifi", None, ""]
    )
    def test_no_op_for_non_omada_controller(self, controller_type) -> None:
        # A bare delete on a NON-Omada controller must NOT be gated here — those
        # are handled by their own vendors' gates. This is the scoping contract:
        # the same feature string is only catastrophic when the controller is Omada.
        enforce_omada_preflight(controller_type, "vpn.ipsec.policy", "delete", {})
        enforce_omada_preflight(controller_type, "firmware.upgrade", "create", {})


@pytest.mark.asyncio
async def test_assess_factory_reset_surfaces_device_impact() -> None:
    class _A:
        async def get_devices(self):
            return _Res([{"mac": "aa"}, {"mac": "bb"}, {"mac": "cc"}])

    res = await assess(
        "bulk.device.factory_reset",
        "create",
        {"device_ids": ["aa", "bb"]},
        adapter=_A(),
    )
    assert res.risk is Risk.CATASTROPHIC and res.requires_confirmation is True
    assert res.impact["device_count"] == 2
    assert res.impact["controller_device_total"] == 3
    assert any("factory-resets" in w for w in res.warnings)


@pytest.mark.asyncio
async def test_assess_backup_restore_warns_whole_config() -> None:
    res = await assess("system.backup.restore", "create", {}, adapter=None)
    assert res.risk is Risk.CATASTROPHIC
    assert any("ENTIRE running configuration" in w for w in res.warnings)


@pytest.mark.asyncio
async def test_assess_live_check_failure_degrades_not_raises() -> None:
    class _Bad:
        async def get_devices(self):
            raise RuntimeError("controller unreachable")

    res = await assess("bulk.device.forget", "create", {"device_ids": ["aa"]}, adapter=_Bad())
    assert res.risk is Risk.CATASTROPHIC  # still classified
    assert any("incomplete" in w for w in res.warnings)


@pytest.mark.asyncio
async def test_preflight_gate_blocks_then_allows_when_confirmed() -> None:
    class _A:
        async def get_devices(self):
            return _Res([{"mac": "aa"}])

    with pytest.raises(HTTPException) as ei:
        await preflight_gate(_A(), "bulk.device.factory_reset", "create", {"device_ids": ["aa"]})
    assert ei.value.status_code == 409
    res = await preflight_gate(
        _A(), "bulk.device.factory_reset", "create", {"device_ids": ["aa"], "confirmed": True}
    )
    assert res.risk is Risk.CATASTROPHIC


def _change(feature: str, operation: str, payload: dict) -> AdapterPendingChange:
    return AdapterPendingChange(
        id=uuid4(),
        organization_id=uuid4(),
        controller_id=uuid4(),
        site_id=None,
        omada_site_id="s1",
        feature=feature,
        operation=operation,
        target_id=None,
        payload=payload,
        status="pending",
        notes=None,
    )


def _session_for(change: AdapterPendingChange, controller_type: str) -> MagicMock:
    """Mock session: 1st execute = the row claim, 2nd = the controller_type lookup."""
    session = MagicMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    claim = MagicMock(scalar_one_or_none=MagicMock(return_value=change))
    ctype = MagicMock(scalar_one_or_none=MagicMock(return_value=controller_type))
    session.execute = AsyncMock(side_effect=[claim, ctype])
    return session


class TestApplyChangeChokepoint:
    """The gate fires through ``AdapterStagingService.apply_change`` itself — even
    with the dual-gate open (ADAPTER_READ_ONLY=false + force=true), a catastrophic
    Omada change without confirmed=true is refused 409 and left ``pending`` (the
    operator who opened read-only for a create cannot blind-apply a staged flash)."""

    @pytest.mark.asyncio
    async def test_catastrophic_omada_blocked_at_apply_and_left_pending(self, monkeypatch) -> None:
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService, "is_read_only", staticmethod(lambda: False)
        )
        change = _change("firmware.upgrade", "create", {})  # no confirmed
        applier = AsyncMock(return_value={"ok": True})
        svc = AdapterStagingService(_session_for(change, "omada"))

        with pytest.raises(HTTPException) as ei:
            await svc.apply_change(change.id, force=True, applier=applier)

        assert ei.value.status_code == 409
        assert change.status == "pending"  # refusal left it pending
        applier.assert_not_awaited()  # never touched the controller

    @pytest.mark.asyncio
    async def test_confirmed_catastrophic_omada_passes_the_gate(self, monkeypatch) -> None:
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService, "is_read_only", staticmethod(lambda: False)
        )
        # Confirmation is supplied at APPLY time (the sanctioned drawer path), not
        # staged into the payload — apply_change makes the request flag authoritative.
        change = _change("firmware.upgrade", "create", {})
        applier = AsyncMock(return_value={"ok": True})
        svc = AdapterStagingService(_session_for(change, "omada"))

        result = await svc.apply_change(change.id, force=True, confirmed=True, applier=applier)

        assert result.status == "applied"
        applier.assert_awaited_once_with(change)

    @pytest.mark.asyncio
    async def test_non_omada_controller_not_gated_by_omada_preflight(self, monkeypatch) -> None:
        # Same bare delete feature, but an opnsense controller → the Omada gate is a
        # no-op (feature has no omada controller type / no opnsense. prefix). We pass
        # confirmed=True so the UNIVERSAL delete backstop (which gates every delete)
        # is satisfied, isolating what this test asserts: the Omada gate is scoped and
        # does not block a non-Omada feature → the applier runs.
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService, "is_read_only", staticmethod(lambda: False)
        )
        change = _change("vpn.ipsec.policy", "delete", {})
        applier = AsyncMock(return_value={"ok": True})
        svc = AdapterStagingService(_session_for(change, "opnsense"))

        result = await svc.apply_change(change.id, force=True, confirmed=True, applier=applier)
        assert result.status == "applied"
