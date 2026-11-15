# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""ADAPTER_READ_ONLY is a hard lock in every adapter write gate.

Before 26.12.0 six adapters (Hikvision, ONVIF, MikroTik, OPNsense, pfSense,
Proxmox) and the FreePBX/Grandstream config gates refused a write under
read-only mode only when the caller did NOT pass ``force=True``. Several
callers send force unconditionally: the cameras API (``_API_WRITE_FORCE``),
the hypervisor UI (power/clone/migrate/delete), and the distribution engine's
MikroTik entrypoints. So a "read-only" install still rebooted cameras and
stopped VMs.

The contract now, one rule for every gate (``apply_context.
read_only_refuses_write``):

* read-only ON: a device write is refused unless it runs inside an approved
  staged apply (``apply_window``); ``force=True`` does not lift it;
* read-only OFF: unchanged;
* non-mutating POSTs (MikroTik and pfSense ping/traceroute/DNS) are reads;
* live operator controls that change no stored configuration (camera PTZ
  moves, FreePBX call control) keep working with ``force=True``, as before.

No device is contacted: HTTP layers are mocked, and refusals fire before any
connection is attempted.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.apply_context import apply_window, read_only_refuses_write
from app.adapters.exceptions import AdapterError

FORCE_HINT = "force=true alone does not lift read-only mode"


def _ok_response(body: Any) -> MagicMock:
    resp = MagicMock(status_code=200, text="{}")
    resp.json.return_value = body
    resp.headers = {}
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# The shared rule
# ─────────────────────────────────────────────────────────────────────────────


class TestSharedRule:
    def test_read_only_refuses_outside_apply_window(self) -> None:
        assert read_only_refuses_write(True) is True

    def test_read_only_allows_inside_apply_window(self) -> None:
        with apply_window():
            assert read_only_refuses_write(True) is False

    def test_read_write_never_refuses(self) -> None:
        assert read_only_refuses_write(False) is False
        with apply_window():
            assert read_only_refuses_write(False) is False


# ─────────────────────────────────────────────────────────────────────────────
# HTTP clients: MikroTik, OPNsense, pfSense, Proxmox
# ─────────────────────────────────────────────────────────────────────────────


def _mikrotik() -> Any:
    from app.adapters.mikrotik.client import MikroTikClient

    client = MikroTikClient(
        host="192.0.2.1", username="a", password="x", port=443, verify_ssl=False
    )
    client._client = AsyncMock()
    client._client.is_closed = False
    client._client.request = AsyncMock(return_value=_ok_response({"ok": True}))
    return client


def _opnsense() -> Any:
    from app.adapters.opnsense.client import OPNsenseClient

    client = OPNsenseClient(
        host="192.0.2.1", api_key="k", api_secret="s", port=443, verify_ssl=False
    )
    client._client = AsyncMock()
    client._client.is_closed = False
    client._client.request = AsyncMock(return_value=_ok_response({"ok": True}))
    return client


def _pfsense() -> Any:
    from app.adapters.pfsense.client import PfSenseClient

    client = PfSenseClient(
        host="192.0.2.1", api_key="k", api_secret="s", port=443, verify_ssl=False
    )
    client._client = AsyncMock()
    client._client.is_closed = False
    client._client.request = AsyncMock(return_value=_ok_response({"data": "ok"}))
    return client


def _proxmox() -> Any:
    from app.adapters.proxmox.client import ProxmoxClient, ProxmoxClientConfig

    client = ProxmoxClient(
        ProxmoxClientConfig(
            host="192.0.2.1",
            port=8006,
            use_ssl=True,
            verify_ssl=False,
            username="root",
            password="x",
        )
    )
    client._http = AsyncMock()
    client._http.is_closed = False
    client._http.request = AsyncMock(return_value=_ok_response({"data": None}))
    client._authenticated = True
    return client


# (label, factory, patch target, a mutating path, the mock attr holding .request)
_CLIENTS = [
    ("mikrotik", _mikrotik, "app.adapters.mikrotik.client", "/ip/firewall/filter", "_client"),
    (
        "opnsense",
        _opnsense,
        "app.adapters.opnsense.client",
        "/api/firewall/filter/addRule",
        "_client",
    ),
    ("pfsense", _pfsense, "app.adapters.pfsense.client", "/firewall/rule", "_client"),
    (
        "proxmox",
        _proxmox,
        "app.adapters.proxmox.client",
        "/nodes/pve1/qemu/100/status/stop",
        "_http",
    ),
]


class TestClientGates:
    @pytest.mark.parametrize("label,factory,mod,path,attr", _CLIENTS, ids=[c[0] for c in _CLIENTS])
    async def test_force_does_not_lift_read_only(
        self, label: str, factory: Any, mod: str, path: str, attr: str
    ) -> None:
        client = factory()
        with patch(f"{mod}._is_adapter_read_only", lambda: True):
            with pytest.raises(AdapterError) as exc:
                await client._request("POST", path, data={}, force=True)
        assert "ADAPTER_READ_ONLY" in str(exc.value)
        assert FORCE_HINT in str(exc.value)
        getattr(client, attr).request.assert_not_called()

    @pytest.mark.parametrize("label,factory,mod,path,attr", _CLIENTS, ids=[c[0] for c in _CLIENTS])
    async def test_refusal_without_force_has_no_force_hint(
        self, label: str, factory: Any, mod: str, path: str, attr: str
    ) -> None:
        client = factory()
        with patch(f"{mod}._is_adapter_read_only", lambda: True):
            with pytest.raises(AdapterError) as exc:
                await client._request("POST", path, data={})
        assert FORCE_HINT not in str(exc.value)

    @pytest.mark.parametrize("label,factory,mod,path,attr", _CLIENTS, ids=[c[0] for c in _CLIENTS])
    async def test_staged_apply_window_writes_under_read_only(
        self, label: str, factory: Any, mod: str, path: str, attr: str
    ) -> None:
        """The sanctioned path: apply_change opens the window, then the applier
        calls the client with force=True."""
        client = factory()
        with patch(f"{mod}._is_adapter_read_only", lambda: True), apply_window():
            await client._request("POST", path, data={}, force=True)
        getattr(client, attr).request.assert_awaited_once()

    @pytest.mark.parametrize("label,factory,mod,path,attr", _CLIENTS, ids=[c[0] for c in _CLIENTS])
    async def test_read_write_mode_unchanged(
        self, label: str, factory: Any, mod: str, path: str, attr: str
    ) -> None:
        client = factory()
        with patch(f"{mod}._is_adapter_read_only", lambda: False):
            await client._request("POST", path, data={})
        getattr(client, attr).request.assert_awaited_once()


class TestDiagnosticPostsAreReads:
    """Ping/traceroute/DNS are POSTs on RouterOS and the pfSense REST package
    but change nothing. They used to get through read-only mode only by
    borrowing force=True; now they are classified as reads."""

    @pytest.mark.parametrize("path", ["/tool/ping", "/tool/traceroute"])
    async def test_mikrotik_diagnostics_run_under_read_only(self, path: str) -> None:
        client = _mikrotik()
        with patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True):
            await client._request("POST", path, data={"address": "192.0.2.9"})
        client._client.request.assert_awaited_once()

    @pytest.mark.parametrize(
        "path", ["/diagnostics/ping", "/diagnostics/traceroute", "/diagnostics/dns_lookup"]
    )
    async def test_pfsense_diagnostics_run_under_read_only(self, path: str) -> None:
        client = _pfsense()
        with patch("app.adapters.pfsense.client._is_adapter_read_only", lambda: True):
            await client._request("POST", path, data={"host": "192.0.2.9"})
        client._client.request.assert_awaited_once()

    async def test_mikrotik_lookalike_path_is_still_a_write(self) -> None:
        """Only the exact diagnostic paths are exempt."""
        client = _mikrotik()
        with patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True):
            with pytest.raises(AdapterError):
                await client._request("POST", "/tool/ping/extra", data={})
            with pytest.raises(AdapterError):
                await client._request("PUT", "/tool/ping", data={})
        client._client.request.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Cameras: config locked, live operator controls keep working with force
# ─────────────────────────────────────────────────────────────────────────────


class TestCameraGates:
    @pytest.mark.parametrize(
        "action",
        [
            "device reboot",
            "set motion detection",
            "set privacy masks",
            "set preset",
            "subscribe events",
        ],
    )
    def test_hikvision_config_refused_with_force(self, action: str) -> None:
        from app.adapters.hikvision.adapter import AdapterReadOnlyError, _enforce_read_only

        with patch("app.adapters.hikvision.adapter._is_adapter_read_only", lambda: True):
            with pytest.raises(AdapterReadOnlyError) as exc:
                _enforce_read_only(force=True, action=action)
        assert FORCE_HINT in str(exc.value)

    @pytest.mark.parametrize(
        "action", ["PTZ control", "goto preset", "start patrol", "send audio data"]
    )
    def test_hikvision_live_controls_allowed_with_force(self, action: str) -> None:
        from app.adapters.hikvision.adapter import _enforce_read_only

        with patch("app.adapters.hikvision.adapter._is_adapter_read_only", lambda: True):
            _enforce_read_only(force=True, action=action)

    def test_hikvision_live_controls_still_need_force(self) -> None:
        from app.adapters.hikvision.adapter import AdapterReadOnlyError, _enforce_read_only

        with patch("app.adapters.hikvision.adapter._is_adapter_read_only", lambda: True):
            with pytest.raises(AdapterReadOnlyError):
                _enforce_read_only(force=False, action="PTZ control")

    def test_hikvision_config_allowed_inside_apply_window(self) -> None:
        from app.adapters.hikvision.adapter import _enforce_read_only

        with (
            patch("app.adapters.hikvision.adapter._is_adapter_read_only", lambda: True),
            apply_window(),
        ):
            _enforce_read_only(force=True, action="device reboot")

    @pytest.mark.parametrize(
        "action", ["reboot", "set image settings", "set preset", "delete preset"]
    )
    def test_onvif_config_refused_with_force(self, action: str) -> None:
        from app.adapters.onvif.adapter import AdapterReadOnlyError, _enforce_read_only

        with patch("app.adapters.onvif.adapter._is_adapter_read_only", lambda: True):
            with pytest.raises(AdapterReadOnlyError):
                _enforce_read_only(force=True, action=action)

    @pytest.mark.parametrize("action", ["PTZ control", "goto preset"])
    def test_onvif_live_controls_allowed_with_force(self, action: str) -> None:
        from app.adapters.onvif.adapter import _enforce_read_only

        with patch("app.adapters.onvif.adapter._is_adapter_read_only", lambda: True):
            _enforce_read_only(force=True, action=action)

    def test_every_hikvision_operational_action_is_a_real_action(self) -> None:
        """The exemption list must name actions the adapter actually gates,
        or a typo would silently lock (or unlock) the wrong thing."""
        import inspect

        import app.adapters.hikvision.adapter as hik

        src = inspect.getsource(hik)
        for action in hik._OPERATIONAL_ACTIONS:
            assert f'action="{action}"' in src, action

    def test_every_onvif_operational_action_is_a_real_action(self) -> None:
        import inspect

        import app.adapters.onvif.adapter as onvif

        src = inspect.getsource(onvif)
        for action in onvif._OPERATIONAL_ACTIONS:
            assert f'action="{action}"' in src, action


# ─────────────────────────────────────────────────────────────────────────────
# VoIP: FreePBX config locked (call control keeps its exception), Grandstream
# ─────────────────────────────────────────────────────────────────────────────


def _bare(modpath: str, cls: str) -> Any:
    import importlib

    mod = importlib.import_module(modpath)
    adapter = getattr(mod, cls).__new__(getattr(mod, cls))
    adapter._read_only = True
    return adapter


class TestVoipGates:
    @pytest.mark.parametrize(
        "op", ["create extension", "delete trunk", "update ring group", "create IVR", "PBX reload"]
    )
    def test_freepbx_config_refused_with_force(self, op: str) -> None:
        from app.adapters.freepbx.adapter import FreePBXReadOnlyError

        adapter = _bare("app.adapters.freepbx.adapter", "FreePBXAdapter")
        with pytest.raises(FreePBXReadOnlyError) as exc:
            adapter._check_write_allowed(force=True, op=op)
        assert FORCE_HINT in str(exc.value)

    @pytest.mark.parametrize(
        "op", ["AMI Originate", "AMI Hangup", "AMI Redirect", "queue pause member"]
    )
    def test_freepbx_call_control_keeps_its_exception(self, op: str) -> None:
        adapter = _bare("app.adapters.freepbx.adapter", "FreePBXAdapter")
        adapter._check_write_allowed(force=True, op=op)

    def test_freepbx_call_control_still_needs_force(self) -> None:
        from app.adapters.freepbx.adapter import FreePBXReadOnlyError

        adapter = _bare("app.adapters.freepbx.adapter", "FreePBXAdapter")
        with pytest.raises(FreePBXReadOnlyError):
            adapter._check_write_allowed(force=False, op="AMI Originate")

    def test_freepbx_config_allowed_inside_apply_window(self) -> None:
        adapter = _bare("app.adapters.freepbx.adapter", "FreePBXAdapter")
        with apply_window():
            adapter._check_write_allowed(force=True, op="create extension")

    def test_every_freepbx_operational_op_is_a_real_op(self) -> None:
        import inspect

        import app.adapters.freepbx.adapter as fpbx

        src = inspect.getsource(fpbx)
        for op in fpbx.FreePBXAdapter._OPERATIONAL_OPS:
            assert f'self._check_write_allowed(force, "{op}")' in src, op

    @pytest.mark.parametrize(
        "op", ["reboot_phone", "factory_reset", "provision_phone", "bulk_reboot"]
    )
    def test_grandstream_changes_refused_with_force(self, op: str) -> None:
        from app.adapters.grandstream.adapter import GrandstreamReadOnlyError

        adapter = _bare("app.adapters.grandstream.adapter", "GrandstreamAdapter")
        with pytest.raises(GrandstreamReadOnlyError) as exc:
            adapter._check_write_allowed(force=True, op=op)
        assert FORCE_HINT in str(exc.value)

    def test_grandstream_allowed_inside_apply_window(self) -> None:
        adapter = _bare("app.adapters.grandstream.adapter", "GrandstreamAdapter")
        with apply_window():
            adapter._check_write_allowed(force=True, op="reboot_phone")

    def test_grandstream_read_write_mode_unchanged(self) -> None:
        adapter = _bare("app.adapters.grandstream.adapter", "GrandstreamAdapter")
        adapter._read_only = False
        adapter._check_write_allowed(force=False, op="reboot_phone")
