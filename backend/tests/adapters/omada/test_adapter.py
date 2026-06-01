# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Comprehensive tests for OmadaAdapter.

Covers: discovery, ports, PoE, VLANs, SSIDs, clients, reboot, locate,
port profiles, gateway config, firmware, metrics, batch ops, health,
idempotency rules, normalization, and error handling.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.adapters.omada.adapter import OmadaAdapter
from app.adapters.omada.exceptions import (
    OmadaNotFoundError,
    OmadaRateLimitError,
    OmadaValidationError,
)

# ============================================================================
# Connection & Sites
# ============================================================================


class TestConnection:
    @pytest.mark.asyncio
    async def test_connect_sets_connected_flag(self, mock_client: MagicMock):
        adapter = OmadaAdapter("10.0.0.1", "admin", "secret")
        adapter._client = mock_client
        assert not adapter._connected

        await adapter.connect()

        assert adapter._connected
        mock_client.login.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_disconnect_clears_flag(self, adapter: OmadaAdapter):
        await adapter.disconnect()

        assert not adapter._connected
        adapter._client.logout.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_test_connection_returns_ok(self, adapter: OmadaAdapter):
        result = await adapter.test_connection()

        assert result.success
        assert result.data["controller_id"] == "CTRL-ABC123"

    @pytest.mark.asyncio
    async def test_get_sites_returns_normalized(self, adapter: OmadaAdapter):
        sites = await adapter.get_sites()

        assert len(sites) == 2
        assert sites[0]["id"] == "site-001"
        assert sites[1]["name"] == "Branch Office"


class TestSiteManagement:
    def test_set_active_site(self, adapter: OmadaAdapter):
        adapter.set_active_site("site-002")
        assert adapter.get_active_site_id() == "site-002"

    @pytest.mark.asyncio
    async def test_ensure_site_id_auto_resolves(self, adapter_no_site: OmadaAdapter):
        site_id = await adapter_no_site._ensure_site_id()
        assert site_id == "site-001"  # first site returned by mock

    @pytest.mark.asyncio
    async def test_ensure_site_id_uses_preset(self, adapter: OmadaAdapter):
        site_id = await adapter._ensure_site_id()
        assert site_id == "site-001"
        # Should NOT call get_sites if already set
        adapter._client.get_sites.assert_not_awaited()


# ============================================================================
# Device Discovery
# ============================================================================


class TestDiscovery:
    @pytest.mark.asyncio
    async def test_discover_devices_returns_all(self, adapter: OmadaAdapter):
        devices = await adapter.discover_devices()

        assert len(devices) == 3
        types = {d.device_type for d in devices}
        assert types == {"switch", "access_point", "gateway"}

    @pytest.mark.asyncio
    async def test_discovered_device_has_correct_fields(self, adapter: OmadaAdapter):
        devices = await adapter.discover_devices()
        switch = next(d for d in devices if d.device_type == "switch")

        assert switch.vendor == "TP-Link"
        assert switch.model == "TL-SG3428"
        assert switch.firmware_version == "1.6.3"
        assert switch.ip_address == "192.168.1.10"
        assert switch.status == "online"

    @pytest.mark.asyncio
    async def test_get_device_info_by_mac(self, adapter: OmadaAdapter):
        device = await adapter.get_device_info("AA-BB-CC-DD-EE-01")

        assert device is not None
        assert device.device_type == "switch"

    @pytest.mark.asyncio
    async def test_get_device_info_not_found(self, adapter: OmadaAdapter):
        device = await adapter.get_device_info("FF-FF-FF-FF-FF-FF")
        assert device is None

    @pytest.mark.asyncio
    async def test_get_device_status(self, adapter: OmadaAdapter):
        status = await adapter.get_device_status("AA-BB-CC-DD-EE-02")
        assert status["status"] == "online"


# ============================================================================
# Switch Ports
# ============================================================================


class TestPorts:
    @pytest.mark.asyncio
    async def test_get_ports_normalizes_data(self, adapter: OmadaAdapter):
        ports = await adapter.get_ports("AA-BB-CC-DD-EE-01")

        assert len(ports) == 3
        uplink = ports[0]
        assert uplink["port_number"] == 1
        assert uplink["name"] == "Uplink"
        assert uplink["enabled"] is True
        assert uplink["status"] == "up"
        assert uplink["speed"] == 1000
        assert uplink["poe_enabled"] is True
        assert uplink["poe_power"] == 15.3
        assert uplink["poe_max_power"] == 30.0
        assert uplink["native_vlan"] == 1
        assert uplink["tagged_vlans"] == [10, 20, 30]
        assert uplink["profile_id"] == "prof-trunk"

    @pytest.mark.asyncio
    async def test_get_ports_disabled_port(self, adapter: OmadaAdapter):
        ports = await adapter.get_ports("AA-BB-CC-DD-EE-01")
        disabled = ports[2]
        assert disabled["enabled"] is False
        assert disabled["status"] == "down"
        assert disabled["poe_enabled"] is False

    @pytest.mark.asyncio
    async def test_get_switch_ports_alias(self, adapter: OmadaAdapter):
        ports = await adapter.get_switch_ports("AA-BB-CC-DD-EE-01")
        assert len(ports) == 3

    @pytest.mark.asyncio
    async def test_configure_switch_port(self, adapter: OmadaAdapter):
        result = await adapter.configure_switch_port("AA-BB-CC-DD-EE-01", 1, {"name": "NewName"})
        assert result.success

    @pytest.mark.asyncio
    async def test_set_port_enabled(self, adapter: OmadaAdapter):
        result = await adapter.set_port_enabled("AA-BB-CC-DD-EE-01", 1, False)
        assert result.success
        assert result.data["enabled"] is False


# ============================================================================
# PoE
# ============================================================================


class TestPoE:
    @pytest.mark.asyncio
    async def test_set_port_poe(self, adapter: OmadaAdapter):
        result = await adapter.set_port_poe("AA-BB-CC-DD-EE-01", 1, True)
        assert result.success
        assert result.data["poe_enabled"] is True

    @pytest.mark.asyncio
    async def test_cycle_poe_port(self, adapter: OmadaAdapter):
        result = await adapter.cycle_poe_port("AA-BB-CC-DD-EE-01", 1, duration=0)
        assert result.success

    @pytest.mark.asyncio
    async def test_get_poe_status(self, adapter: OmadaAdapter):
        status = await adapter.get_poe_status("AA-BB-CC-DD-EE-01")
        assert status["device_id"] == "AA-BB-CC-DD-EE-01"
        assert len(status["ports"]) == 3

    @pytest.mark.asyncio
    async def test_get_port_statistics(self, adapter: OmadaAdapter):
        stats = await adapter.get_port_statistics("AA-BB-CC-DD-EE-01", 1)
        assert stats["rxBytes"] == 1024


# ============================================================================
# VLANs
# ============================================================================


class TestVlans:
    @pytest.mark.asyncio
    async def test_get_vlans_normalizes(self, adapter: OmadaAdapter):
        vlans = await adapter.get_vlans()
        assert len(vlans) == 3
        assert vlans[0]["vlan_id"] == 1
        assert vlans[0]["name"] == "LAN"
        assert vlans[0]["dhcp_enabled"] is True
        assert vlans[0]["gateway"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_create_vlan_idempotent(self, adapter: OmadaAdapter):
        """Creating VLAN with existing ID returns ok without creating."""
        result = await adapter.create_vlan(1, "LAN")
        assert result.success
        assert "already exists" in result.message.lower()
        adapter._client.create_network.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_create_vlan_new(self, adapter: OmadaAdapter):
        """Creating a new VLAN actually calls the API."""
        result = await adapter.create_vlan(50, "New VLAN")
        assert result.success
        adapter._client.create_network.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_delete_vlan_idempotent_not_found(self, adapter: OmadaAdapter):
        """Deleting non-existent VLAN returns ok (idempotent)."""
        result = await adapter.delete_vlan(999)
        assert result.success
        assert "absent" in result.message.lower()

    @pytest.mark.asyncio
    async def test_delete_vlan_existing(self, adapter: OmadaAdapter):
        result = await adapter.delete_vlan("net-001")
        assert result.success
        adapter._client.delete_network.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_vlan(self, adapter: OmadaAdapter):
        result = await adapter.update_vlan("net-002", {"name": "VoIP Updated"})
        assert result.success

    @pytest.mark.asyncio
    async def test_update_vlan_not_found(self, adapter: OmadaAdapter):
        result = await adapter.update_vlan("nonexistent", {"name": "X"})
        assert not result.success
        assert result.error_code == "NOT_FOUND"


# ============================================================================
# SSIDs
# ============================================================================


class TestSsids:
    @pytest.mark.asyncio
    async def test_get_ssids_normalizes(self, adapter: OmadaAdapter):
        ssids = await adapter.get_ssids()
        assert len(ssids) == 3
        corp = ssids[0]
        assert corp["name"] == "Corporate-WiFi"
        assert corp["enabled"] is True
        assert corp["band"] == "5g"
        assert corp["band_steering"] is True
        assert corp["guest_network"] is False

    @pytest.mark.asyncio
    async def test_create_ssid_duplicate_rejected(self, adapter: OmadaAdapter):
        """Creating SSID with duplicate name returns fail."""
        result = await adapter.create_ssid({"name": "Corporate-WiFi", "security": "wpa2_personal"})
        assert not result.success
        assert result.error_code == "DUPLICATE_SSID"
        adapter._client.create_ssid.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_create_ssid_new(self, adapter: OmadaAdapter):
        result = await adapter.create_ssid({"name": "New-Network", "security": "wpa3_personal"})
        assert result.success
        adapter._client.create_ssid.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_toggle_ssid(self, adapter: OmadaAdapter):
        result = await adapter.toggle_ssid("ssid-001", False)
        assert result.success
        assert result.data["enabled"] is False

    @pytest.mark.asyncio
    async def test_delete_ssid_idempotent(self, adapter: OmadaAdapter):
        """Deleting non-existent SSID returns ok."""
        adapter._client.delete_ssid = AsyncMock(side_effect=OmadaNotFoundError("not found"))
        result = await adapter.delete_ssid("ssid-gone")
        assert result.success
        assert "absent" in result.message.lower()


# ============================================================================
# Clients
# ============================================================================


class TestClients:
    @pytest.mark.asyncio
    async def test_get_clients_normalizes(self, adapter: OmadaAdapter):
        clients = await adapter.get_clients()
        assert len(clients) == 3

        wired = next(c for c in clients if c["connection_type"] == "wired")
        assert wired["mac_address"] == "11-22-33-44-55-02"
        assert wired["switch_mac"] == "AA-BB-CC-DD-EE-01"
        assert wired["switch_port"] == 5

        wireless = next(c for c in clients if c["mac_address"] == "11-22-33-44-55-01")
        assert wireless["connection_type"] == "wireless"
        assert wireless["ssid"] == "Corporate-WiFi"
        assert wireless["signal"] == -42

    @pytest.mark.asyncio
    async def test_kick_client(self, adapter: OmadaAdapter):
        result = await adapter.kick_client("11-22-33-44-55-01")
        assert result.success

    @pytest.mark.asyncio
    async def test_block_client(self, adapter: OmadaAdapter):
        result = await adapter.block_client("11-22-33-44-55-01")
        assert result.success

    @pytest.mark.asyncio
    async def test_block_client_already_blocked(self, adapter: OmadaAdapter):
        """Blocking already-blocked client is idempotent."""
        adapter._client.block_client = AsyncMock(
            side_effect=OmadaNotFoundError("not found")
        )
        result = await adapter.block_client("11-22-33-44-55-01")
        assert result.success

    @pytest.mark.asyncio
    async def test_unblock_client(self, adapter: OmadaAdapter):
        result = await adapter.unblock_client("11-22-33-44-55-01")
        assert result.success

    @pytest.mark.asyncio
    async def test_unblock_client_already_unblocked(self, adapter: OmadaAdapter):
        """Unblocking already-unblocked client is idempotent."""
        adapter._client.unblock_client = AsyncMock(
            side_effect=OmadaNotFoundError("not found")
        )
        result = await adapter.unblock_client("11-22-33-44-55-01")
        assert result.success

    @pytest.mark.asyncio
    async def test_get_wifi_clients_alias(self, adapter: OmadaAdapter):
        clients = await adapter.get_wifi_clients()
        assert len(clients) == 3


# ============================================================================
# Device Control (Reboot / Locate)
# ============================================================================


class TestDeviceControl:
    @pytest.mark.asyncio
    async def test_reboot_device(self, adapter: OmadaAdapter):
        result = await adapter.reboot_device("AA-BB-CC-DD-EE-01")
        assert result.success
        assert result.data["action"] == "reboot"

    @pytest.mark.asyncio
    async def test_reboot_rate_limited(self, adapter: OmadaAdapter):
        """Second reboot within cooldown period is rejected."""
        result1 = await adapter.reboot_device("AA-BB-CC-DD-EE-01")
        assert result1.success

        result2 = await adapter.reboot_device("AA-BB-CC-DD-EE-01")
        assert not result2.success
        assert result2.error_code == "RATE_LIMITED"

    @pytest.mark.asyncio
    async def test_reboot_not_found(self, adapter: OmadaAdapter):
        result = await adapter.reboot_device("FF-FF-FF-FF-FF-FF")
        assert not result.success
        assert result.error_code == "NOT_FOUND"

    @pytest.mark.asyncio
    async def test_locate_device_ap(self, adapter: OmadaAdapter):
        result = await adapter.locate_device("AA-BB-CC-DD-EE-02")
        assert result.success
        assert result.data["action"] == "locate"

    @pytest.mark.asyncio
    async def test_locate_device_not_ap_rejected(self, adapter: OmadaAdapter):
        """Locate only works on APs."""
        result = await adapter.locate_device("AA-BB-CC-DD-EE-01")  # switch
        assert not result.success
        assert result.error_code == "NOT_SUPPORTED"


# ============================================================================
# Port Profiles
# ============================================================================


class TestPortProfiles:
    @pytest.mark.asyncio
    async def test_get_port_profiles_normalizes(self, adapter: OmadaAdapter):
        profiles = await adapter.get_port_profiles()
        assert len(profiles) == 2
        assert profiles[0]["name"] == "Access-VLAN10"
        assert profiles[0]["native_vlan"] == 10
        assert profiles[0]["type"] == "access"
        assert profiles[1]["tagged_vlans"] == [10, 20, 30, 100]

    @pytest.mark.asyncio
    async def test_create_port_profile(self, adapter: OmadaAdapter):
        result = await adapter.create_port_profile({"name": "Test", "nativeVlan": 10})
        assert result.success

    @pytest.mark.asyncio
    async def test_update_port_profile(self, adapter: OmadaAdapter):
        result = await adapter.update_port_profile("prof-001", {"name": "Updated"})
        assert result.success

    @pytest.mark.asyncio
    async def test_delete_port_profile(self, adapter: OmadaAdapter):
        result = await adapter.delete_port_profile("prof-001")
        assert result.success


# ============================================================================
# Gateway / Network Config
# ============================================================================


class TestGatewayConfig:
    @pytest.mark.asyncio
    async def test_get_wan_status(self, adapter: OmadaAdapter):
        wan = await adapter.get_wan_status()
        assert "wanPortSettings" in wan

    @pytest.mark.asyncio
    async def test_get_dhcp_config(self, adapter: OmadaAdapter):
        config = await adapter.get_dhcp_config()
        assert isinstance(config, dict)

    @pytest.mark.asyncio
    async def test_get_firewall_rules_normalizes(self, adapter: OmadaAdapter):
        rules = await adapter.get_firewall_rules()
        assert len(rules) == 1
        assert rules[0]["name"] == "Allow LAN"
        assert rules[0]["action"] == "accept"

    @pytest.mark.asyncio
    async def test_get_vpn_config(self, adapter: OmadaAdapter):
        vpn = await adapter.get_vpn_config()
        assert "ipsec" in vpn


# ============================================================================
# Firmware
# ============================================================================


class TestFirmware:
    @pytest.mark.asyncio
    async def test_get_firmware_info(self, adapter: OmadaAdapter):
        info = await adapter.get_firmware_info("AA-BB-CC-DD-EE-01")
        assert info["needUpgrade"] is True
        assert info["latestVersion"] == "1.7.0"

    @pytest.mark.asyncio
    async def test_upgrade_firmware(self, adapter: OmadaAdapter):
        result = await adapter.upgrade_firmware("AA-BB-CC-DD-EE-01")
        assert result.success

    @pytest.mark.asyncio
    async def test_firmware_not_found(self, adapter: OmadaAdapter):
        result = await adapter.upgrade_firmware("FF-FF-FF-FF-FF-FF")
        assert not result.success
        assert result.error_code == "NOT_FOUND"


# ============================================================================
# Metrics
# ============================================================================


class TestMetrics:
    @pytest.mark.asyncio
    async def test_get_device_metrics(self, adapter: OmadaAdapter):
        metrics = await adapter.get_device_metrics("AA-BB-CC-DD-EE-01")
        assert metrics["cpu"] == 12.5
        assert metrics["memory"] == 45.2
        assert metrics["uptime"] == 1728000
        assert metrics["clients"] == 24
        assert metrics["temperature"] == 42.1

    @pytest.mark.asyncio
    async def test_get_device_metrics_not_found(self, adapter: OmadaAdapter):
        metrics = await adapter.get_device_metrics("FF-FF-FF-FF-FF-FF")
        assert metrics == {}


# ============================================================================
# Batch Operations
# ============================================================================


class TestBatchOps:
    @pytest.mark.asyncio
    async def test_batch_reboot(self, adapter: OmadaAdapter):
        results = await adapter.batch_reboot(["AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"])
        assert len(results) == 2
        assert results[0].success
        assert results[1].success

    @pytest.mark.asyncio
    async def test_batch_firmware_upgrade(self, adapter: OmadaAdapter):
        results = await adapter.batch_firmware_upgrade(["AA-BB-CC-DD-EE-01"])
        assert len(results) == 1
        assert results[0].success


# ============================================================================
# Health & Compatibility
# ============================================================================


class TestHealth:
    @pytest.mark.asyncio
    async def test_health_check(self, adapter: OmadaAdapter):
        health = await adapter.health_check()
        assert health["adapter_id"] == "omada"
        assert health["connected"] is True
        assert health["controller_version"] == "5.14.26.1"
        assert health["request_count"] == 42

    @pytest.mark.asyncio
    async def test_compatibility_probe(self, adapter: OmadaAdapter):
        probe = await adapter.run_compatibility_probe()
        assert probe["passed"] is True
        assert probe["controller_id"] == "CTRL-ABC123"
        assert "sites" in probe["checks"]
        assert "devices" in probe["checks"]


# ============================================================================
# Error Handling in Adapter Methods
# ============================================================================


class TestAdapterErrors:
    @pytest.mark.asyncio
    async def test_get_ports_error_returns_empty(self, adapter: OmadaAdapter):
        adapter._client.get_switch_ports = AsyncMock(side_effect=RuntimeError("boom"))
        ports = await adapter.get_ports("AA-BB-CC-DD-EE-01")
        assert ports == []

    @pytest.mark.asyncio
    async def test_get_vlans_error_returns_empty(self, adapter: OmadaAdapter):
        adapter._client.get_networks = AsyncMock(side_effect=RuntimeError("boom"))
        vlans = await adapter.get_vlans()
        assert vlans == []

    @pytest.mark.asyncio
    async def test_get_clients_error_returns_empty(self, adapter: OmadaAdapter):
        adapter._client.get_clients = AsyncMock(side_effect=RuntimeError("boom"))
        clients = await adapter.get_clients()
        assert clients == []

    @pytest.mark.asyncio
    async def test_set_port_poe_validation_error(self, adapter: OmadaAdapter):
        adapter._client.set_port_poe = AsyncMock(
            side_effect=OmadaValidationError("invalid port")
        )
        result = await adapter.set_port_poe("AA-BB-CC-DD-EE-01", 999, True)
        assert not result.success
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_create_vlan_rate_limited(self, adapter: OmadaAdapter):
        adapter._client.create_network = AsyncMock(
            side_effect=OmadaRateLimitError("slow down")
        )
        result = await adapter.create_vlan(50, "Test")
        assert not result.success
        assert result.error_code == "RATE_LIMITED"

    @pytest.mark.asyncio
    async def test_no_site_returns_fail(self, adapter: OmadaAdapter):
        adapter._site_id = None
        adapter._client.get_sites = AsyncMock(return_value=[])
        result = await adapter.set_port_poe("AA-BB-CC-DD-EE-01", 1, True)
        assert not result.success
        assert result.error_code == "NO_SITE"


# ============================================================================
# Manifest
# ============================================================================


class TestManifest:
    def test_manifest_id(self):
        assert OmadaAdapter.manifest.id == "omada"

    def test_manifest_vendor(self):
        assert OmadaAdapter.manifest.vendor == "TP-Link"

    def test_manifest_device_types(self):
        types = OmadaAdapter.manifest.device_types
        assert "switch" in types
        assert "access_point" in types
        assert "gateway" in types

    def test_manifest_switch_capabilities(self):
        from app.adapters.capabilities import Capability
        caps = OmadaAdapter.manifest.device_types["switch"].capabilities
        assert Capability.SWITCH_PORT_CONFIG in caps
        assert Capability.VLAN_MANAGEMENT in caps
        assert Capability.POE_CONTROL in caps
        assert Capability.DEVICE_METRICS in caps

    def test_manifest_ap_capabilities(self):
        from app.adapters.capabilities import Capability
        caps = OmadaAdapter.manifest.device_types["access_point"].capabilities
        assert Capability.WIFI_SSID_MANAGEMENT in caps
        assert Capability.WIFI_CLIENT_KICK in caps
        assert Capability.WIFI_CLIENT_BLOCK in caps

    def test_manifest_gateway_capabilities(self):
        from app.adapters.capabilities import Capability
        caps = OmadaAdapter.manifest.device_types["gateway"].capabilities
        assert Capability.FIREWALL_BASIC in caps
        assert Capability.DHCP_SERVER in caps
        assert Capability.VPN_IPSEC in caps
