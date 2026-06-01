# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Dual-gate + validation + redaction tests for the **expanded** UniFi
adapter write surface (Omada-parity build-out).

The original ``test_unifi_safety.py`` covers the first-generation write
methods (restart/block/wlan-password/port-override/...). This module
exercises the NEW gated methods added for Omada parity:

  * **v2 modern lane** — firewall policies + zones, NAT, QoS, traffic
    rules, traffic routes, static-DNS.
  * **v1 classic completion** — firewall groups + legacy rules, RADIUS
    accounts, port profiles, user (bandwidth) groups, DPI groups,
    port-forwards, dynamic-DNS, static routes, WLAN/SSID + network CRUD.
  * **devmgr / stamgr commands** — adopt / upgrade / force-provision /
    power-cycle-port / reconnect-client, plus the real ``locate_device``.

Every new write funnels through the shared ``_do_write`` helper
(read-only gate → site-validate → tenancy ownership → structured audit →
live client call → redact). For a representative slice of methods we
assert the reference contract:

  (a) refuses without ``force`` when ``ADAPTER_READ_ONLY`` is engaged
      (raises ``AdapterReadOnlyError``) and the client is never touched;
  (b) with ``force=True`` (gate cleared) it calls the EXPECTED client
      method with the EXPECTED payload / path-id;
  (c) the returned envelope is run through ``redact_secrets`` so any
      leaked PSK / RADIUS secret is masked;
  (d) update / delete methods validate the object id and reject a bad one.

The client is mocked throughout — every method points at a TEST-NET-1
(RFC 5737) host, so even a guard bypass would hit unroutable space and no
live UniFi controller is contacted.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.exceptions import AdapterError
from app.adapters.unifi import UniFiAdapter
from app.adapters.unifi.exceptions import AdapterReadOnlyError

_FAKE_OID = "507f1f77bcf86cd799439011"
_FAKE_OID_2 = "507f1f77bcf86cd799439012"
_FAKE_MAC = "aa:bb:cc:dd:ee:ff"
_BAD_OID = "not-an-oid"

# Patch path for the adapter-layer gate (mirrors test_unifi_safety).
_GATE = "app.adapters.unifi.adapter._is_adapter_read_only"


def _make_adapter() -> UniFiAdapter:
    """Adapter pointed at a TEST-NET-1 (RFC 5737) host — no I/O until login."""
    return UniFiAdapter(
        host="192.0.2.1",
        username="admin",
        password="x",
        port=8443,
        verify_ssl=False,
    )


def _stub_owned_site(adapter: UniFiAdapter, site: str = "default") -> None:
    """Make the IDOR ownership check (``_verify_site_owned``) pass.

    ``_do_write`` calls ``self._verify_site_owned(site)`` which lists
    ``/api/self/sites`` via ``get_sites()`` and rejects any ``site`` the
    backing account cannot see. force=True tests must present ``site`` as
    owned, in the exact shape the guard reads (slug under ``name``).
    """
    adapter._api.get_sites = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "meta": {"rc": "ok"},
            "data": [{"name": site, "desc": site, "_id": _FAKE_OID}],
        }
    )


def _ok_envelope(rows: list | None = None) -> dict:
    """A normalised ok envelope as the client would return one."""
    return {"meta": {"rc": "ok"}, "data": rows if rows is not None else []}


def _stub_client_method(adapter: UniFiAdapter, name: str, return_value=None) -> AsyncMock:
    """Replace a single client method with an AsyncMock and return it."""
    mock = AsyncMock(return_value=return_value if return_value is not None else _ok_envelope())
    setattr(adapter._api, name, mock)
    return mock


# ════════════════════════════════════════════════════════════════════════
# (a) Read-only refusal — representative methods across every domain.
#     Each refuses without force AND must never reach the client.
# ════════════════════════════════════════════════════════════════════════


class TestExpandedWritesRefusedByDefault:
    """Under ``ADAPTER_READ_ONLY`` (gate=True), every new write refuses
    without ``force`` and the underlying client method is never awaited."""

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_firewall_policy_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_firewall_policy")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_firewall_policy("default", {"name": "p"})
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_delete_firewall_policy_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_firewall_policy")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.delete_firewall_policy("default", _FAKE_OID)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_firewall_zone_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_firewall_zone")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_firewall_zone("default", {"name": "z"})
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_nat_rule_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_nat_rule")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_nat_rule("default", {"name": "n"})
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_qos_rule_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_qos_rule")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_qos_rule("default", {"name": "q"})
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_traffic_rule_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_traffic_rule")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_traffic_rule("default", {"name": "t"})
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_delete_traffic_route_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_traffic_route")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.delete_traffic_route("default", _FAKE_OID)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_static_dns_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_static_dns")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_static_dns("default", {"key": "x.local"})
        client_mock.assert_not_awaited()

    # ── v1 classic completion ──
    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_wlan_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_wlan")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_wlan("default", {"name": "ssid"})
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_firewall_group_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_firewall_group")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_firewall_group("default", {"name": "g"})
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_radius_user_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_radius_user")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_radius_user("default", {"name": "u", "x_password": "p"})
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_create_port_forward_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_port_forward")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.create_port_forward("default", {"name": "fwd"})
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_delete_network_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_network")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.delete_network("default", _FAKE_OID)
        client_mock.assert_not_awaited()

    # ── devmgr / stamgr commands ──
    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_adopt_device_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "cmd_devmgr")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.adopt_device("default", _FAKE_MAC)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_power_cycle_port_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "cmd_devmgr")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.power_cycle_port("default", _FAKE_MAC, 1)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_reconnect_client_refused(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "cmd_stamgr")
        with pytest.raises(AdapterReadOnlyError):
            await adapter.reconnect_client("default", _FAKE_MAC)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: True)
    async def test_locate_device_refused_returns_failed_result(self) -> None:
        """``locate_device`` is the BaseAdapter-contract override: instead of
        raising it traps ``AdapterReadOnlyError`` and returns a failed
        ``AdapterResult`` with ``error_code='READ_ONLY'``. The client must
        still never be reached."""
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "cmd_devmgr")
        result = await adapter.locate_device(_FAKE_MAC, True)
        assert result.success is False
        assert result.error_code == "READ_ONLY"
        client_mock.assert_not_awaited()


# ════════════════════════════════════════════════════════════════════════
# (b) force=True opts in — calls the right client method + payload / id.
# ════════════════════════════════════════════════════════════════════════


class TestExpandedWritesForceCallsClient:
    """Gate cleared + ``force=True`` → the write reaches the EXPECTED client
    method with the EXPECTED payload / path-id (no network I/O — mocked)."""

    # ── v2 modern lane ──
    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_firewall_policy_passes_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "create_firewall_policy", _ok_envelope([{"_id": "p"}]))
        payload = {"name": "Block-IoT", "action": "BLOCK"}
        await adapter.create_firewall_policy("default", payload, force=True)
        mock.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_firewall_policy_passes_id_and_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "update_firewall_policy")
        payload = {"action": "ALLOW"}
        await adapter.update_firewall_policy("default", _FAKE_OID, payload, force=True)
        mock.assert_awaited_once_with(_FAKE_OID, payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_firewall_policy_passes_id(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "delete_firewall_policy")
        await adapter.delete_firewall_policy("default", _FAKE_OID, force=True)
        mock.assert_awaited_once_with(_FAKE_OID)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_nat_rule_passes_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "create_nat_rule")
        payload = {"name": "snat-wan", "type": "SNAT"}
        await adapter.create_nat_rule("default", payload, force=True)
        mock.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_nat_rule_passes_id(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "delete_nat_rule")
        await adapter.delete_nat_rule("default", _FAKE_OID, force=True)
        mock.assert_awaited_once_with(_FAKE_OID)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_qos_rule_passes_id_and_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "update_qos_rule")
        payload = {"dscp": 46}
        await adapter.update_qos_rule("default", _FAKE_OID, payload, force=True)
        mock.assert_awaited_once_with(_FAKE_OID, payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_traffic_route_passes_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "create_traffic_route")
        payload = {"domains": ["netflix.com"], "next_hop": "wan2"}
        await adapter.create_traffic_route("default", payload, force=True)
        mock.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_static_dns_passes_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        # Faithful shape from the real static-dns write capture.
        created = {
            "_id": "6a435e75dfcf14f660ab05b3",
            "enabled": True,
            "key": "fsdn-cap.local",
            "record_type": "A",
            "value": "10.77.0.5",
        }
        mock = _stub_client_method(adapter, "create_static_dns", _ok_envelope([created]))
        payload = {"enabled": True, "key": "fsdn-cap.local", "record_type": "A", "value": "10.77.0.5"}
        await adapter.create_static_dns("default", payload, force=True)
        mock.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_static_dns_passes_id(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "delete_static_dns")
        await adapter.delete_static_dns("default", _FAKE_OID, force=True)
        mock.assert_awaited_once_with(_FAKE_OID)

    # ── v1 classic completion ──
    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_wlan_passes_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "create_wlan")
        payload = {"name": "FreeSDN-Guest", "security": "open"}
        await adapter.create_wlan("default", payload, force=True)
        mock.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_ssid_passes_id(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "delete_wlan")
        await adapter.delete_ssid("default", _FAKE_OID, force=True)
        mock.assert_awaited_once_with(_FAKE_OID)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_network_passes_id_and_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "update_network")
        payload = {"name": "VLAN20", "vlan": 20}
        await adapter.update_network("default", _FAKE_OID, payload, force=True)
        mock.assert_awaited_once_with(_FAKE_OID, payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_firewall_group_passes_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        # Faithful shape from the real firewallgroup write capture.
        payload = {"name": "fsdn-cap-grp", "group_type": "address-group", "group_members": ["10.99.99.0/24"]}
        mock = _stub_client_method(adapter, "create_firewall_group")
        await adapter.create_firewall_group("default", payload, force=True)
        mock.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_radius_user_passes_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        payload = {"name": "fsdn-cap-radius", "x_password": "RadPass12345", "tunnel_type": 13}
        mock = _stub_client_method(adapter, "create_radius_user")
        await adapter.create_radius_user("default", payload, force=True)
        mock.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_radius_user_passes_id(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "delete_radius_user")
        await adapter.delete_radius_user("default", _FAKE_OID, force=True)
        mock.assert_awaited_once_with(_FAKE_OID)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_port_profile_passes_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "create_port_profile")
        payload = {"name": "Uplink", "forward": "all"}
        await adapter.create_port_profile("default", payload, force=True)
        mock.assert_awaited_once_with(payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_dpi_app_passes_id_and_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "update_dpi_app")
        payload = {"enabled": False}
        await adapter.update_dpi_app("default", _FAKE_OID, payload, force=True)
        mock.assert_awaited_once_with(_FAKE_OID, payload)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_dynamic_dns_passes_id(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "delete_dynamic_dns")
        await adapter.delete_dynamic_dns("default", _FAKE_OID, force=True)
        mock.assert_awaited_once_with(_FAKE_OID)

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_route_passes_payload(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "create_routing")
        payload = {"name": "to-dmz", "static-route_network": "10.5.0.0/24"}
        await adapter.create_route("default", payload, force=True)
        mock.assert_awaited_once_with(payload)

    # ── devmgr / stamgr commands — assert the exact command payload ──
    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_adopt_device_sends_adopt_cmd(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "cmd_devmgr")
        await adapter.adopt_device("default", _FAKE_MAC, force=True)
        mock.assert_awaited_once_with({"cmd": "adopt", "mac": _FAKE_MAC})

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_upgrade_device_sends_upgrade_cmd(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "cmd_devmgr")
        await adapter.upgrade_device("default", _FAKE_MAC, force=True)
        mock.assert_awaited_once_with({"cmd": "upgrade", "mac": _FAKE_MAC})

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_force_provision_sends_force_provision_cmd(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "cmd_devmgr")
        await adapter.force_provision_device("default", _FAKE_MAC, force=True)
        mock.assert_awaited_once_with({"cmd": "force-provision", "mac": _FAKE_MAC})

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_power_cycle_port_sends_port_idx(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "cmd_devmgr")
        await adapter.power_cycle_port("default", _FAKE_MAC, 7, force=True)
        mock.assert_awaited_once_with({"cmd": "power-cycle", "mac": _FAKE_MAC, "port_idx": 7})

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_reconnect_client_sends_kick_sta(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "cmd_stamgr")
        await adapter.reconnect_client("default", _FAKE_MAC, force=True)
        mock.assert_awaited_once_with({"cmd": "kick-sta", "mac": _FAKE_MAC})

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_locate_device_set_locate_with_force(self) -> None:
        """``locate_device(mac, enabled=True)`` → ``set-locate``; returns a
        successful AdapterResult. NOW goes through ``_verify_site_owned`` (the
        IDOR guard added so locate matches every other write method), so the
        owned-site stub is required even on the no-site default path."""
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "cmd_devmgr")
        result = await adapter.locate_device(_FAKE_MAC, True, force=True)
        assert result.success is True
        mock.assert_awaited_once_with({"cmd": "set-locate", "mac": _FAKE_MAC})

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_locate_device_unset_locate_when_disabled(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "cmd_devmgr")
        result = await adapter.locate_device(_FAKE_MAC, False, force=True)
        assert result.success is True
        mock.assert_awaited_once_with({"cmd": "unset-locate", "mac": _FAKE_MAC})

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_voucher_builds_command(self) -> None:
        """The voucher helper assembles the hotspot command from kwargs."""
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        mock = _stub_client_method(adapter, "cmd_hotspot")
        await adapter.create_voucher(
            "default", count=3, expire_minutes=120, quota=1, note="lobby", force=True
        )
        mock.assert_awaited_once_with(
            {"cmd": "create-voucher", "n": 3, "expire": 120, "quota": 1, "note": "lobby"}
        )


# ════════════════════════════════════════════════════════════════════════
# (c) Redaction — the returned envelope is masked before it leaves the adapter.
# ════════════════════════════════════════════════════════════════════════


class TestExpandedWriteRedaction:
    """``_do_write`` returns ``redact_secrets(result)`` — a RADIUS secret /
    PSK echoed back in a create response must be masked."""

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_radius_user_redacts_secret_in_response(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        # UniFi echoes the RADIUS secret (``x_password``) verbatim in the
        # create response — it must be masked on the way out.
        created = _ok_envelope(
            [
                {
                    "_id": _FAKE_OID,
                    "name": "fsdn-cap-radius",
                    "x_password": "RadPass12345",
                    "tunnel_type": 13,
                }
            ]
        )
        _stub_client_method(adapter, "create_radius_user", created)
        result = await adapter.create_radius_user(
            "default", {"name": "fsdn-cap-radius", "x_password": "RadPass12345"}, force=True
        )
        row = result["data"][0]
        assert row["x_password"] == "***"
        # Non-sensitive fields survive.
        assert row["name"] == "fsdn-cap-radius"
        assert row["tunnel_type"] == 13

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_wlan_redacts_psk_in_response(self) -> None:
        adapter = _make_adapter()
        _stub_owned_site(adapter)
        created = _ok_envelope(
            [{"_id": _FAKE_OID, "name": "FreeSDN-WiFi", "x_passphrase": "supersecret1!"}]
        )
        _stub_client_method(adapter, "create_wlan", created)
        result = await adapter.create_wlan(
            "default", {"name": "FreeSDN-WiFi", "x_passphrase": "supersecret1!"}, force=True
        )
        row = result["data"][0]
        assert row["x_passphrase"] == "***"
        assert row["name"] == "FreeSDN-WiFi"


# ════════════════════════════════════════════════════════════════════════
# (d) ID validation — update / delete reject a bad object id.
#     Gate is cleared so a VALID id would proceed — proving the id check
#     (not the read-only gate) is what rejects.
# ════════════════════════════════════════════════════════════════════════


class TestExpandedWriteIdValidation:
    """Every update / delete method validates its path id via
    ``validate_object_id`` BEFORE reaching the client. A non-OID id is
    rejected with ``AdapterError`` and the client is never touched."""

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_firewall_policy_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_firewall_policy")
        with pytest.raises(AdapterError):
            await adapter.delete_firewall_policy("default", _BAD_OID, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_firewall_policy_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "update_firewall_policy")
        with pytest.raises(AdapterError):
            await adapter.update_firewall_policy("default", _BAD_OID, {"x": 1}, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_firewall_zone_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "update_firewall_zone")
        with pytest.raises(AdapterError):
            await adapter.update_firewall_zone("default", _BAD_OID, {"x": 1}, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_nat_rule_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_nat_rule")
        with pytest.raises(AdapterError):
            await adapter.delete_nat_rule("default", _BAD_OID, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_qos_rule_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "update_qos_rule")
        with pytest.raises(AdapterError):
            await adapter.update_qos_rule("default", _BAD_OID, {"x": 1}, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_traffic_rule_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_traffic_rule")
        with pytest.raises(AdapterError):
            await adapter.delete_traffic_rule("default", _BAD_OID, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_traffic_route_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "update_traffic_route")
        with pytest.raises(AdapterError):
            await adapter.update_traffic_route("default", _BAD_OID, {"x": 1}, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_static_dns_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_static_dns")
        with pytest.raises(AdapterError):
            await adapter.delete_static_dns("default", _BAD_OID, force=True)
        client_mock.assert_not_awaited()

    # ── v1 id validation ──
    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_ssid_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_wlan")
        with pytest.raises(AdapterError):
            await adapter.delete_ssid("default", _BAD_OID, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_network_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "update_network")
        with pytest.raises(AdapterError):
            await adapter.update_network("default", _BAD_OID, {"x": 1}, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_firewall_group_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_firewall_group")
        with pytest.raises(AdapterError):
            await adapter.delete_firewall_group("default", _BAD_OID, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_update_radius_user_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "update_radius_user")
        with pytest.raises(AdapterError):
            await adapter.update_radius_user("default", _BAD_OID, {"x": 1}, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_delete_port_profile_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "delete_port_profile")
        with pytest.raises(AdapterError):
            await adapter.delete_port_profile("default", _BAD_OID, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_revoke_voucher_rejects_bad_id(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "cmd_hotspot")
        with pytest.raises(AdapterError):
            await adapter.revoke_voucher("default", _BAD_OID, force=True)
        client_mock.assert_not_awaited()


# ════════════════════════════════════════════════════════════════════════
# Site-validation + tenancy ownership on the expanded writes
# ════════════════════════════════════════════════════════════════════════


class TestExpandedWriteSiteGuards:
    """The shared ``_do_write`` validates the site format and enforces the
    cross-site IDOR ownership check on every expanded write too."""

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_nat_rule_rejects_traversal_site(self) -> None:
        adapter = _make_adapter()
        client_mock = _stub_client_method(adapter, "create_nat_rule")
        with pytest.raises(AdapterError):
            await adapter.create_nat_rule("../etc/passwd", {"name": "n"}, force=True)
        client_mock.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(_GATE, lambda: False)
    async def test_create_static_dns_rejects_unowned_site(self) -> None:
        """A well-formed but unknown site (not in ``/api/self/sites``) is a
        cross-site IDOR attempt — refused before the write."""
        adapter = _make_adapter()
        # Owned set contains only "default"; caller targets "othersite".
        _stub_owned_site(adapter, site="default")
        client_mock = _stub_client_method(adapter, "create_static_dns")
        with pytest.raises(AdapterError):
            await adapter.create_static_dns("othersite", {"key": "x.local"}, force=True)
        client_mock.assert_not_awaited()
