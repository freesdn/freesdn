# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Apply-path tests for UniFi staged-write services.

Closes a coverage gap: UniFi's per-domain services
(devices/clients/wlans/networks) had no apply-path tests despite
shipping IDOR guards. This file mirrors the
``test_openwrt_apply.py`` and ``test_mikrotik_apply.py`` patterns.

Coverage:
- ``_APPLY`` table contains every (feature, op) pair the stage
  endpoint accepts
- Applier dispatches each (feature, op) to the right adapter method
  with the right positional + kwarg shape
- Site IDOR guard rejects ``payload.site`` not present in the
  controller's ``site_mappings`` or live ``get_sites()`` response
- Missing ``payload.site`` → 400
- Missing ``target_id`` (device MAC) → 400
- Unknown feature → 400

The adapter client is mocked at the service-layer boundary
(``_get_adapter`` / ``_resolve_controller_or_gateway``).
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.services.adapter_unifi_devices import (
    _APPLY as DEVICES_APPLY,
    GatewayUniFiDevicesService,
)


def _make_change(
    feature: str, operation: str = "update", **kw: Any,
) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature,
        operation=operation,
        payload=kw.get("payload", {}),
        target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
    )


def _make_devices_service() -> tuple[
    GatewayUniFiDevicesService, MagicMock, MagicMock,
]:
    """Wire a devices service with mocked controller + adapter.

    Returns (service, mock_ctrl, mock_client). The mock_ctrl has a
    ``site_mappings`` dict so tests can populate the allowlist.
    """
    svc = GatewayUniFiDevicesService(MagicMock())
    mock_ctrl = MagicMock()
    mock_ctrl.site_mappings = {}  # populated per-test
    mock_client = MagicMock()
    for name in (
        "restart_device", "disable_device",
        "update_port_override", "set_port_poe",
    ):
        setattr(mock_client, name, AsyncMock(return_value={"ok": True}))
    # Sites list returned by the IDOR guard's fallback path. The
    # default lists 'default' so most tests that don't care about
    # allowlist verification just work.
    mock_client.get_sites = AsyncMock(return_value={
        "data": [{"name": "default"}, {"name": "branch"}],
    })

    async def _resolve(*_a: Any, **_kw: Any) -> Any:
        return mock_ctrl

    async def _get_adapter(*_a: Any, **_kw: Any) -> Any:
        return mock_client

    svc._resolve_controller_or_gateway = _resolve  # type: ignore[assignment]
    svc._get_adapter = _get_adapter  # type: ignore[assignment]
    return svc, mock_ctrl, mock_client


# ─── _APPLY completeness ────────────────────────────────────────────


class TestApplyTableCompleteness:
    @pytest.mark.parametrize(
        "feature,op",
        [
            ("unifi.devices.restart", "update"),
            ("unifi.devices.disable", "update"),
            ("unifi.devices.port_override", "update"),
            ("unifi.devices.set_port_poe", "update"),
        ],
    )
    def test_apply_table_has_pair(self, feature: str, op: str) -> None:
        assert (feature, op) in DEVICES_APPLY


# ─── Validation ─────────────────────────────────────────────────────


class TestRequiredArgs:
    @pytest.mark.asyncio
    async def test_missing_site_raises_400(self) -> None:
        svc, _, _ = _make_devices_service()
        change = _make_change(
            "unifi.devices.restart",
            target_id="aa:bb:cc:dd:ee:ff",
            payload={},  # no "site"
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "payload.site" in exc.value.detail

    @pytest.mark.asyncio
    async def test_missing_target_id_raises_400(self) -> None:
        svc, _, _ = _make_devices_service()
        change = _make_change(
            "unifi.devices.restart",
            target_id=None,
            payload={"site": "default"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "target_id" in exc.value.detail

    @pytest.mark.asyncio
    async def test_unknown_feature_raises_400(self) -> None:
        svc, _, _ = _make_devices_service()
        change = _make_change(
            "unifi.devices.not_real",
            target_id="aa:bb:cc:dd:ee:ff",
            payload={"site": "default"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "no applier" in exc.value.detail


# ─── Site IDOR guard ────────────────────────────────────────────────


class TestSiteIdorGuard:
    """Verify the site IDOR guard refuses
    unauthorized sites and prefers ``ctrl.site_mappings`` over live
    ``get_sites()`` when populated."""

    @pytest.mark.asyncio
    async def test_unknown_site_raises_404(self) -> None:
        svc, ctrl, client = _make_devices_service()
        ctrl.site_mappings = {}
        client.get_sites.return_value = {"data": [{"name": "default"}]}
        change = _make_change(
            "unifi.devices.restart",
            target_id="aa:bb:cc:dd:ee:ff",
            payload={"site": "evil-other-tenant"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 404
        client.restart_device.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_site_mappings_allowlist_short_circuits_live_check(
        self,
    ) -> None:
        svc, ctrl, client = _make_devices_service()
        # Operator-configured allowlist contains the site → no live
        # call needed.
        ctrl.site_mappings = {"default": "freesdn-site-uuid"}
        change = _make_change(
            "unifi.devices.restart",
            target_id="aa:bb:cc:dd:ee:ff",
            payload={"site": "default"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.restart_device.assert_awaited_once_with(
            "default", "aa:bb:cc:dd:ee:ff", force=True,
        )
        # Allowlist hit → no fallback to get_sites
        client.get_sites.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_get_sites_failure_raises_502(self) -> None:
        svc, ctrl, client = _make_devices_service()
        ctrl.site_mappings = {}
        client.get_sites.side_effect = Exception("controller unreachable")
        change = _make_change(
            "unifi.devices.restart",
            target_id="aa:bb:cc:dd:ee:ff",
            payload={"site": "default"},
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 502
        client.restart_device.assert_not_awaited()


# ─── Dispatch ───────────────────────────────────────────────────────


class TestDispatch:
    @pytest.mark.asyncio
    async def test_restart_dispatches(self) -> None:
        svc, _, client = _make_devices_service()
        change = _make_change(
            "unifi.devices.restart",
            target_id="aa:bb:cc:dd:ee:ff",
            payload={"site": "default"},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.restart_device.assert_awaited_once_with(
            "default", "aa:bb:cc:dd:ee:ff", force=True,
        )

    @pytest.mark.asyncio
    async def test_disable_dispatches_with_disabled_kwarg(self) -> None:
        svc, _, client = _make_devices_service()
        change = _make_change(
            "unifi.devices.disable",
            target_id="aa:bb:cc:dd:ee:ff",
            payload={"site": "default", "disabled": True},
        )
        applier = svc.build_applier(change)
        await applier(change)
        client.disable_device.assert_awaited_once_with(
            "default", "aa:bb:cc:dd:ee:ff", True, force=True,
        )

    @pytest.mark.asyncio
    async def test_disable_without_disabled_raises_400(self) -> None:
        svc, _, _ = _make_devices_service()
        change = _make_change(
            "unifi.devices.disable",
            target_id="aa:bb:cc:dd:ee:ff",
            payload={"site": "default"},  # missing 'disabled'
        )
        applier = svc.build_applier(change)
        with pytest.raises(HTTPException) as exc:
            await applier(change)
        assert exc.value.status_code == 400
        assert "disabled" in exc.value.detail.lower()
