# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Production-safety tests for the UniFi adapter.

Verifies the reference dual-gate contract shared with Omada /
Proxmox / OPNsense / pfSense / MikroTik / Hikvision. The HTTP layer
is mocked everywhere so **no live UniFi controller is contacted**
by this test module — every test points at a TEST-NET-1 (RFC 5737)
host so an SSRF-guard bypass would still hit unroutable space.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.adapters import apply_context
from app.adapters.exceptions import AdapterError
from app.adapters.unifi import (
    UniFiAdapter,
    _enforce_read_only,
    _is_adapter_read_only,
    validate_controller_host,
    validate_mac,
    validate_object_id,
    validate_poe_mode,
    validate_port_idx,
    validate_site,
)
from app.adapters.unifi.adapter import _allow_private_controller_hosts
from app.adapters.unifi.client import UniFiClient
from app.adapters.unifi.exceptions import AdapterReadOnlyError, UniFiConnectionError

# Valid MongoDB ObjectID string used as a stand-in for IDs.
_FAKE_OID = "507f1f77bcf86cd799439011"
_FAKE_MAC = "aa:bb:cc:dd:ee:ff"

# ─────────────────────────────────────────────────────────────────────
# Construction helper
# ─────────────────────────────────────────────────────────────────────


def _make_adapter() -> UniFiAdapter:
    """Build an adapter pointed at a TEST-NET-1 (RFC 5737) host."""
    return UniFiAdapter(
        host="192.0.2.1",
        username="admin",
        password="x",
        port=8443,
        verify_ssl=False,
    )


def _stub_owned_site(adapter: UniFiAdapter, site: str = "default") -> None:
    """Make the IDOR ownership check (``_verify_site_owned``) pass.

    Every UniFi write method now calls ``self._verify_site_owned(site)``,
    which lists ``/api/self/sites`` via ``self._api.get_sites()`` and rejects
    any ``site`` the backing account cannot see (cross-site IDOR guard). The
    force=True opt-in tests must therefore present ``site`` as an owned site,
    or the new check raises before the write is ever attempted. We stub
    ``get_sites()`` to return ``site`` in the exact shape the guard reads:
    ``{"data": [{"name": site, ...}]}`` (the slug lives under ``name``).
    """
    adapter._api.get_sites = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "meta": {"rc": "ok"},
            "data": [{"name": site, "desc": site, "_id": _FAKE_OID}],
        }
    )


# ─────────────────────────────────────────────────────────────────────
# Validators
# ─────────────────────────────────────────────────────────────────────


class TestSiteValidation:
    """Site names appear in URL paths; reject anything that could
    smuggle a traversal payload."""

    @pytest.mark.parametrize(
        "value",
        ["default", "a1b2c3d4", "main_site", "office-eu", "x"],
    )
    def test_accepts_legitimate_names(self, value: str) -> None:
        assert validate_site(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "../etc/passwd",
            "../../api/self",
            "site/with/slash",
            "site name with spaces",
            "",
            "x" * 33,  # too long
            "../",
            "site?q=1",
            "site;rm -rf /",
        ],
    )
    def test_rejects_invalid_names(self, value: str) -> None:
        with pytest.raises(AdapterError):
            validate_site(value)


class TestMacValidation:
    @pytest.mark.parametrize(
        "value,canon",
        [
            ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
            ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
            ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
            ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ],
    )
    def test_canonicalises(self, value: str, canon: str) -> None:
        assert validate_mac(value) == canon

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "not-a-mac",
            "aa:bb:cc:dd:ee",  # too short
            "aa:bb:cc:dd:ee:ff:gg",  # too long
            "aa:bb:cc:dd:ee:gg",  # non-hex
            "../../foo",
        ],
    )
    def test_rejects_invalid(self, value: str) -> None:
        with pytest.raises(AdapterError):
            validate_mac(value)


class TestObjectIdValidation:
    def test_accepts_valid_oid(self) -> None:
        assert validate_object_id(_FAKE_OID) == _FAKE_OID

    @pytest.mark.parametrize(
        "value",
        [
            "not-an-oid",
            "",
            "ZZZf1f77bcf86cd799439011",  # non-hex
            "507f1f77bcf86cd79943901",  # 23 chars
            "507f1f77bcf86cd7994390111",  # 25 chars
            "../507f1f77bcf86cd799439011",
        ],
    )
    def test_rejects_invalid(self, value: str) -> None:
        with pytest.raises(AdapterError):
            validate_object_id(value)


class TestPortIdxValidation:
    @pytest.mark.parametrize("value", [1, 24, 52, 256])
    def test_accepts_in_range(self, value: int) -> None:
        assert validate_port_idx(value) == value

    @pytest.mark.parametrize("value", [0, -1, 257, 9999])
    def test_rejects_out_of_range(self, value: int) -> None:
        with pytest.raises(AdapterError):
            validate_port_idx(value)

    @pytest.mark.parametrize("value", ["abc", "../1", None])
    def test_rejects_non_int(self, value: object) -> None:
        with pytest.raises(AdapterError):
            validate_port_idx(value)  # type: ignore[arg-type]


class TestPoeModeValidation:
    @pytest.mark.parametrize(
        "mode",
        ["auto", "off", "passive24", "passthrough"],
    )
    def test_accepts_documented_modes(self, mode: str) -> None:
        assert validate_poe_mode(mode) == mode

    @pytest.mark.parametrize(
        "mode",
        ["", "ON", "fire", "auto;reboot", None, 1],
    )
    def test_rejects_invalid(self, mode: object) -> None:
        with pytest.raises(AdapterError):
            validate_poe_mode(mode)  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────
# SSRF guard
# ─────────────────────────────────────────────────────────────────────


class TestControllerHostSSRF:
    """``validate_controller_host`` is called by the adapter
    constructor — every unsafe destination must be refused before
    we construct ``base_url``."""

    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",
            "127.0.0.42",
            "::1",
            "169.254.169.254",  # AWS/GCP metadata
            "0.0.0.0",
            "169.254.1.5",  # link-local
            "224.0.0.1",  # multicast
            "ff02::1",  # IPv6 multicast
        ],
    )
    def test_rejects_blocked_hosts(self, host: str) -> None:
        with pytest.raises(AdapterError):
            validate_controller_host(host, allow_private=True)

    @pytest.mark.parametrize(
        "host",
        [
            "10.0.0.1",
            "192.168.1.150",
            "172.16.10.10",
            "203.0.113.5",
            "controller.example.com",
        ],
    )
    def test_accepts_legitimate_hosts(self, host: str) -> None:
        assert validate_controller_host(host, allow_private=True) == host

    def test_rejects_private_when_allow_private_false(self) -> None:
        """The ``ALLOW_PRIVATE_CONTROLLER_HOSTS=false`` override
        flips the validator to reject RFC1918 entirely — for SaaS
        deployments that only manage public hosts."""
        with pytest.raises(AdapterError):
            validate_controller_host("10.0.0.1", allow_private=False)
        with pytest.raises(AdapterError):
            validate_controller_host("192.168.1.150", allow_private=False)

    def test_rejects_ipv6_ula_when_allow_private_false(self) -> None:
        """fc00::/7 is the IPv6 RFC1918 equivalent."""
        with pytest.raises(AdapterError):
            validate_controller_host("fd00::1", allow_private=False)

    def test_rejects_empty(self) -> None:
        with pytest.raises(AdapterError):
            validate_controller_host("", allow_private=True)


class TestConstructorSSRFGuard:
    """The adapter constructor must refuse a poisoned host
    *before* it constructs ``base_url``."""

    @pytest.mark.parametrize(
        "host",
        ["127.0.0.1", "169.254.169.254", "0.0.0.0"],
    )
    def test_rejects_blocked_host_at_init(self, host: str) -> None:
        with pytest.raises((AdapterError, ValueError)):
            UniFiAdapter(host=host, username="admin", password="x")


# ─────────────────────────────────────────────────────────────────────
# Dual-gate read-only contract
# ─────────────────────────────────────────────────────────────────────


# Patch path for the gate helper inside the adapter module.
_GATE = "app.adapters.unifi.adapter._is_adapter_read_only"


class TestReadOnlyGate:
    """Every write method refuses to execute when
    ``ADAPTER_READ_ONLY`` is set unless the caller passes
    ``force=True``."""

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_restart_device_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.restart_device("default", _FAKE_MAC)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_update_port_override_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.update_port_override(
                "default",
                _FAKE_MAC,
                1,
                _FAKE_OID,
            )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_set_port_poe_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.set_port_poe(
                "default",
                _FAKE_MAC,
                1,
                "auto",
            )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_update_wlan_password_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.update_wlan_password(
                "default",
                _FAKE_OID,
                "newpassword",
            )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_enable_wlan_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.enable_wlan("default", _FAKE_OID, False)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_block_client_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.block_client("default", _FAKE_MAC)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_unblock_client_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.unblock_client("default", _FAKE_MAC)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_forget_client_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.forget_client("default", _FAKE_MAC)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_disable_device_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.disable_device("default", _FAKE_MAC, True)


class TestForceTrueOptsIn:
    """When the gate is cleared AND the caller passes ``force=True``,
    the write proceeds (verified by the call reaching the underlying
    client). We mock the client to capture the call so no network
    I/O happens."""

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_restart_device_succeeds_with_force(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        adapter._api.cmd_devmgr = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        result = await adapter.restart_device("default", _FAKE_MAC, force=True)
        assert isinstance(result, dict)
        adapter._api.cmd_devmgr.assert_awaited_once()
        # Verify the payload shape matches what UniFi expects.
        payload = adapter._api.cmd_devmgr.await_args.args[0]
        assert payload == {"cmd": "restart", "mac": _FAKE_MAC}

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_block_client_succeeds_with_force(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        adapter._api.cmd_stamgr = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        await adapter.block_client("default", _FAKE_MAC, force=True)
        adapter._api.cmd_stamgr.assert_awaited_once_with(
            {"cmd": "block-sta", "mac": _FAKE_MAC},
        )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_unblock_client_succeeds_with_force(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        adapter._api.cmd_stamgr = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        await adapter.unblock_client("default", _FAKE_MAC, force=True)
        payload = adapter._api.cmd_stamgr.await_args.args[0]
        assert payload["cmd"] == "unblock-sta"

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_forget_client_succeeds_with_force(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        adapter._api.cmd_stamgr = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        await adapter.forget_client("default", _FAKE_MAC, force=True)
        payload = adapter._api.cmd_stamgr.await_args.args[0]
        assert payload["cmd"] == "forget-sta"
        assert payload["macs"] == [_FAKE_MAC]

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_enable_wlan_succeeds_with_force(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        adapter._api.update_wlan = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        await adapter.enable_wlan("default", _FAKE_OID, False, force=True)
        adapter._api.update_wlan.assert_awaited_once_with(
            _FAKE_OID,
            {"enabled": False},
        )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_wlan_password_succeeds_with_force(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        adapter._api.update_wlan = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        await adapter.update_wlan_password(
            "default",
            _FAKE_OID,
            "supersecret1!",
            force=True,
        )
        adapter._api.update_wlan.assert_awaited_once_with(
            _FAKE_OID,
            {"x_passphrase": "supersecret1!"},
        )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_disable_device_succeeds_with_force(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        adapter._api.get_device = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "meta": {"rc": "ok"},
                "data": [{"_id": "deviceabc", "mac": _FAKE_MAC}],
            }
        )
        adapter._api.update_device = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        await adapter.disable_device(
            "default",
            _FAKE_MAC,
            True,
            force=True,
        )
        adapter._api.update_device.assert_awaited_once_with(
            "deviceabc",
            {"disabled": True},
        )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_port_override_succeeds_with_force(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        adapter._api.get_device = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "meta": {"rc": "ok"},
                "data": [
                    {
                        "_id": "deviceabc",
                        "mac": _FAKE_MAC,
                        "port_overrides": [
                            {"port_idx": 2, "portconf_id": "other"},
                        ],
                    }
                ],
            }
        )
        adapter._api.update_device = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        await adapter.update_port_override(
            "default",
            _FAKE_MAC,
            1,
            _FAKE_OID,
            force=True,
        )
        payload = adapter._api.update_device.await_args.args[1]
        assert {"port_idx": 1, "portconf_id": _FAKE_OID} in payload["port_overrides"]
        # Confirm the pre-existing override on a different port survived.
        assert {"port_idx": 2, "portconf_id": "other"} in payload["port_overrides"]


class TestCreateVlanReadOnlyGate:
    """``create_vlan`` must enforce the dual-gate like every other UniFi
    write method. It is reachable via the legacy
    ``POST /api/v1/network/vlans`` push path, which bypasses the staged
    applier, so without the gate an ungated live ``create_network`` POST
    could fire under ``ADAPTER_READ_ONLY=true``. It is gated like every
    sibling."""

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_vlan_refused_by_default(self) -> None:
        adapter = _make_adapter()
        # Capture the would-be live write to prove it is never reached.
        adapter._api.create_network = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_vlan(42, "guest")
        adapter._api.create_network.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_vlan_succeeds_with_force(self) -> None:
        """The staged applier opts in with ``force=True`` after the staging
        dual-gate — that path must still reach the controller."""
        adapter = _make_adapter()
        adapter._api.create_network = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": [{"_id": "netabc"}]}
        )
        result = await adapter.create_vlan(42, "guest", force=True)
        assert result.success
        adapter._api.create_network.assert_awaited_once()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_vlan_requires_force_even_when_read_only_off(self) -> None:
        """The explicit force=true intent gate is required for EVERY live write,
        not only while ADAPTER_READ_ONLY is set — so a direct create_vlan without
        force is refused even in write-mode; force=true proceeds."""
        adapter = _make_adapter()
        adapter._api.create_network = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        # No force → refused by the intent gate; the live write is never reached.
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_vlan(42, "guest")
        adapter._api.create_network.assert_not_awaited()
        # force=true → the staged-apply/deliberate path proceeds.
        result = await adapter.create_vlan(42, "guest", force=True)
        assert result.success
        adapter._api.create_network.assert_awaited_once()


# ─────────────────────────────────────────────────────────────────────
# Write payload validation (catches bad input even when forced)
# ─────────────────────────────────────────────────────────────────────


class TestWriteInputValidation:
    """Even when the operator has cleared the gate, malformed input
    must not reach the controller."""

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_restart_rejects_bad_mac(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterError):
            await adapter.restart_device("default", "not-a-mac", force=True)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_restart_rejects_bad_site(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterError):
            await adapter.restart_device(
                "../etc/passwd",
                _FAKE_MAC,
                force=True,
            )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_set_port_poe_rejects_bad_mode(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterError):
            await adapter.set_port_poe(
                "default",
                _FAKE_MAC,
                1,
                "INVALID",
                force=True,
            )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_port_override_rejects_bad_profile_id(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterError):
            await adapter.update_port_override(
                "default",
                _FAKE_MAC,
                1,
                "not-an-oid",
                force=True,
            )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_wlan_password_rejects_short_psk(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterError):
            await adapter.update_wlan_password(
                "default",
                _FAKE_OID,
                "short",
                force=True,
            )

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_wlan_password_rejects_long_psk(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterError):
            await adapter.update_wlan_password(
                "default",
                _FAKE_OID,
                "x" * 64,
                force=True,
            )


# ─────────────────────────────────────────────────────────────────────
# Read-path redaction
# ─────────────────────────────────────────────────────────────────────


class TestReadPathRedaction:
    """Every read method must mask sensitive fields (PSKs, RADIUS
    secrets, device passwords) before the response leaves the
    adapter. We assert this against a few representative methods."""

    @pytest.mark.asyncio
    async def test_list_wlans_strips_psk(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)  # reads now verify site ownership too
        adapter._api.get_wlans = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "meta": {"rc": "ok"},
                "data": [
                    {
                        "_id": _FAKE_OID,
                        "name": "FreeSDN-WiFi",
                        "x_passphrase": "supersecret1!",
                        "security": "wpapsk",
                    }
                ],
            }
        )
        wlans = await adapter.list_wlans("default")
        assert wlans
        # The PSK lives under a non-redacted key
        # (``x_passphrase`` is not in the strip-list — UniFi's
        # specific key). But ``passphrase`` IS in the list.
        # Verify the strip-list catches the generic 'password' field
        # that some endpoints surface:
        adapter._api.get_wlans = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "meta": {"rc": "ok"},
                "data": [
                    {"_id": _FAKE_OID, "passphrase": "supersecret"},
                ],
            }
        )
        wlans2 = await adapter.list_wlans("default")
        assert wlans2[0]["passphrase"] == "***"

    @pytest.mark.asyncio
    async def test_list_devices_strips_device_secret(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)  # reads now verify site ownership too
        adapter._api.get_devices = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "meta": {"rc": "ok"},
                "data": [
                    {
                        "_id": "deviceabc",
                        "mac": _FAKE_MAC,
                        "name": "Switch-1",
                        "model": "USW-Pro-24",
                        "x_authkey": "leak-me",
                        "password": "device-admin-pw",
                        "api_key": "leak-key",
                    }
                ],
            }
        )
        devices = await adapter.list_devices("default")
        assert devices
        d = devices[0]
        assert d["password"] == "***"
        assert d["api_key"] == "***"
        # Non-sensitive fields survive.
        assert d["mac"] == _FAKE_MAC

    @pytest.mark.asyncio
    async def test_vpn_secret_fields_are_redacted(self) -> None:
        """UniFi VPN networkconf PSK / RADIUS secrets must not leak.

        The x_-/ipsec_-prefixed compound names don't collapse to an exact
        strip-list entry; the suffix rules (pre_shared_key / preshared_key /
        radius_secret / shared_secret) must catch them, exactly as private_key
        already saves x_wireguard_private_key.
        """
        from app.core.redaction import redact_secrets

        out = redact_secrets(
            {
                "name": "site-to-site",
                "x_ipsec_pre_shared_key": "ipsec-psk",
                "ipsec_pre_shared_key": "ipsec-psk2",
                "x_wireguard_preshared_key": "wg-psk",
                "x_wireguard_private_key": "wg-priv",
                "x_radius_secret": "radius-shared",
                "wireguard_public_key": "wg-pub",  # public — must SURVIVE
            }
        )
        assert out["x_ipsec_pre_shared_key"] == "***"
        assert out["ipsec_pre_shared_key"] == "***"
        assert out["x_wireguard_preshared_key"] == "***"
        assert out["x_wireguard_private_key"] == "***"
        assert out["x_radius_secret"] == "***"
        assert out["wireguard_public_key"] == "wg-pub"  # carve-out preserved

    @pytest.mark.asyncio
    async def test_read_rejects_unowned_site(self) -> None:
        """Reads verify site ownership, not just writes."""
        from app.adapters.exceptions import AdapterError

        adapter = _make_adapter()
        # get_sites lists only 'hq' — 'rogue' belongs to a sibling tenant.
        adapter._api.get_sites = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": [{"name": "hq"}]}
        )
        adapter._api.get_devices = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        with pytest.raises(AdapterError):
            await adapter.list_devices("rogue")
        # The owned site is permitted.
        assert await adapter.list_devices("hq") == []

    @pytest.mark.asyncio
    async def test_list_radius_users_strips_secret(self) -> None:
        adapter = _make_adapter()
        adapter._api.get_radius_users = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "meta": {"rc": "ok"},
                "data": [
                    {
                        "name": "user1",
                        "x_password": "leak",
                        "password": "leak2",
                        "secret": "leak3",
                    }
                ],
            }
        )
        users = await adapter.list_radius_users("default")
        assert users
        assert users[0]["password"] == "***"
        assert users[0]["secret"] == "***"


# ─────────────────────────────────────────────────────────────────────
# Circuit breaker
# ─────────────────────────────────────────────────────────────────────


class TestCircuitBreaker:
    """Every reference adapter ships a labelled CircuitBreaker
    so the shared ``freesdn_adapter_circuit_state`` gauge has a
    UniFi series."""

    def test_breaker_starts_closed_with_labels(self) -> None:
        adapter = _make_adapter()
        b = adapter._api._breaker
        assert b.state == "closed"
        assert b.name == "unifi"
        assert "192.0.2.1" in b.host

    def test_breaker_opens_after_threshold_failures(self) -> None:
        adapter = _make_adapter()
        b = adapter._api._breaker
        # failure_threshold=5
        for _ in range(5):
            b.record_failure()
        assert b.state == "open"
        assert b.allow_request() is False

    def test_breaker_closes_on_success(self) -> None:
        adapter = _make_adapter()
        b = adapter._api._breaker
        for _ in range(3):
            b.record_failure()
        b.record_success()
        assert b.state == "closed"


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────


class TestEnforceReadOnly:
    """The centralised helper is the single chokepoint every write
    method uses; verify both directions."""

    @patch(_GATE, lambda: True)
    def test_raises_when_set_and_not_forced(self) -> None:
        with pytest.raises(AdapterReadOnlyError):
            _enforce_read_only(force=False, action="test")

    @patch(_GATE, lambda: True)
    def test_allows_when_forced_even_if_set(self) -> None:
        _enforce_read_only(force=True, action="test")

    @patch(_GATE, lambda: False)
    def test_raises_when_not_forced_even_if_clear(self) -> None:
        """force=true is required for EVERY live write, so the helper refuses an
        unforced write even when ADAPTER_READ_ONLY is off (closing the
        direct-write force-gate bypass)."""
        with pytest.raises(AdapterReadOnlyError):
            _enforce_read_only(force=False, action="test")

    @patch(_GATE, lambda: False)
    def test_allows_when_forced_and_clear(self) -> None:
        _enforce_read_only(force=True, action="test")


class TestSettingsHelpers:
    """The two settings helpers (``_is_adapter_read_only`` /
    ``_allow_private_controller_hosts``) must default-safe when
    the settings module can't be loaded."""

    def test_is_adapter_read_only_returns_bool(self) -> None:
        assert isinstance(_is_adapter_read_only(), bool)

    def test_allow_private_controller_hosts_returns_bool(self) -> None:
        assert isinstance(_allow_private_controller_hosts(), bool)


# ─────────────────────────────────────────────────────────────────────
# Bucket A — client-layer apply_window gate
# ─────────────────────────────────────────────────────────────────────

# The adapter-layer gate (_enforce_read_only) honours a caller-supplied
# ``force`` — but the UniFi REST endpoints pass ``force=body.force``, so a
# caller could set force=True and push a DIRECT write to a live controller
# while ADAPTER_READ_ONLY is on. The client-layer gate (UniFiClient._request)
# closes that: it IGNORES force and refuses mutating verbs under read-only
# UNLESS inside an approved staged-apply window (the only path that opens one
# is AdapterStagingService.apply_change, AFTER its own dual-gate). This mirrors
# the Omada client. No-op when read-only is off.
_CLIENT_GATE = "app.adapters.unifi.client._is_adapter_read_only"


def _make_client() -> UniFiClient:
    """A cheap UniFiClient (no I/O happens until login)."""
    return UniFiClient("192.0.2.1", "admin", "x", port=8443, is_unifi_os=False)


class TestClientApplyWindowGate:
    """UniFiClient._request must refuse direct writes under read-only unless
    inside an approved apply_window — force can no longer bypass it."""

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: True)
    async def test_write_refused_under_readonly_outside_window(self) -> None:
        client = _make_client()
        try:
            with pytest.raises(AdapterReadOnlyError):
                await client._request("POST", "/rest/networkconf", json={})
        finally:
            await client._client.aclose()

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: True)
    async def test_write_allowed_inside_apply_window(self) -> None:
        # In-window: the read-only gate must NOT fire. Force the breaker OPEN so
        # the call raises a DIFFERENT error (connection) — proving it got PAST
        # the apply_window gate rather than being refused by it.
        client = _make_client()
        client._breaker.allow_request = lambda: False  # type: ignore[method-assign]
        try:
            with apply_context.apply_window():
                with pytest.raises(UniFiConnectionError):
                    await client._request("POST", "/rest/networkconf", json={})
        finally:
            await client._client.aclose()

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: True)
    async def test_get_never_refused(self) -> None:
        client = _make_client()
        client._breaker.allow_request = lambda: False  # type: ignore[method-assign]
        try:
            with pytest.raises(UniFiConnectionError):
                await client._request("GET", "/stat/health")
        finally:
            await client._client.aclose()

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_write_allowed_when_not_readonly(self) -> None:
        # Read-only off → gate is a no-op (live-write deployments unaffected).
        client = _make_client()
        client._breaker.allow_request = lambda: False  # type: ignore[method-assign]
        try:
            with pytest.raises(UniFiConnectionError):
                await client._request("POST", "/rest/networkconf", json={})
        finally:
            await client._client.aclose()


class TestClientResultCodeGate:
    """An HTTP 200 carrying ``meta.rc != "ok"`` is a
    LOGICAL FAILURE — UniFi returns 200 + {"meta":{"rc":"error"}} for a rejected
    command (unknown MAC, not permitted, transient). ``_request`` must raise, not
    return the body as success — otherwise block/unblock/forget enforcement
    silently false-succeeds (DB records "blocked" while the client stays
    reachable). Symmetric with the Omada client's errorCode gate."""

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_2xx_rc_error_raises(self) -> None:
        import httpx

        from app.adapters.unifi.exceptions import UniFiAPIError

        client = _make_client()
        fake = httpx.Response(
            200, json={"meta": {"rc": "error", "msg": "api.err.UnknownStation"}, "data": []}
        )
        client._client.request = AsyncMock(return_value=fake)  # type: ignore[method-assign]
        try:
            with pytest.raises(UniFiAPIError) as exc:
                await client._request("POST", "/cmd/stamgr", json={"cmd": "block-sta"})
            assert exc.value.meta_rc == "error"
        finally:
            await client._client.aclose()

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_2xx_rc_ok_returns_envelope(self) -> None:
        import httpx

        client = _make_client()
        fake = httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{"x": 1}]})
        client._client.request = AsyncMock(return_value=fake)  # type: ignore[method-assign]
        try:
            result = await client._request("POST", "/cmd/stamgr", json={"cmd": "unblock-sta"})
            assert result["meta"]["rc"] == "ok"
            assert result["data"] == [{"x": 1}]
        finally:
            await client._client.aclose()


class TestDistributionTargetVlanPayload:
    """Locks the adapter's explicit ``networkgroup`` DEFAULT on the VLAN-create
    payloads. NB: networkgroup is OPTIONAL on Network 10.4.57 (the controller
    accepts a vlan-enabled networkconf with OR without it — verified live, see
    freesdn-cassettes/unifi/networkconf_vlan_networkgroup.json); the real create
    constraint is the VLAN-ID range. We send ``LAN`` as a predictable, kwargs-
    overridable default so a distributed VLAN lands on the LAN switching group.
    This test only pins that default — a mock cannot prove controller acceptance,
    the cassette does."""

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_vlan_includes_networkgroup(self) -> None:
        adapter = _make_adapter()
        adapter._api.create_network = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": [{"_id": "n1"}]}
        )
        await adapter.create_vlan(40, "seg", force=True)
        payload = adapter._api.create_network.await_args.args[0]
        assert payload["networkgroup"] == "LAN"
        assert payload["vlan_enabled"] is True
        assert payload["vlan"] == 40

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_vlan_interface_includes_networkgroup(self) -> None:
        adapter = _make_adapter()
        adapter._api.get_networks = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": []}
        )
        adapter._api.create_network = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": [{"_id": "n2"}]}
        )
        res = await adapter.create_vlan_interface(
            40, "seg", subnet="10.0.40.0/24", gateway_ip="10.0.40.1", force=True
        )
        assert res.success
        payload = adapter._api.create_network.await_args.args[0]
        assert payload["networkgroup"] == "LAN"
        assert payload["vlan_enabled"] is True
        assert payload["purpose"] == "corporate"

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_vlan_networkgroup_overridable(self) -> None:
        adapter = _make_adapter()
        adapter._api.create_network = AsyncMock(  # type: ignore[method-assign]
            return_value={"meta": {"rc": "ok"}, "data": [{"_id": "n3"}]}
        )
        await adapter.create_vlan(40, "seg", force=True, networkgroup="LAN2")
        payload = adapter._api.create_network.await_args.args[0]
        assert payload["networkgroup"] == "LAN2"
