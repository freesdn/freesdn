# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for Omada Pydantic models and normalization layer.
"""

from __future__ import annotations

from app.adapters.omada.models import (
    NormalizedClient,
    NormalizedFirewallRule,
    NormalizedPort,
    NormalizedPortProfile,
    NormalizedSsid,
    NormalizedVlan,
    OmadaApiEnvelope,
    OmadaClient,
    OmadaControllerInfo,
    OmadaControllerStatus,
    OmadaDevice,
    OmadaDeviceMetrics,
    OmadaFirewallRule,
    OmadaFirmwareInfo,
    OmadaGateway,
    OmadaNetwork,
    OmadaPaginatedData,
    OmadaPortPoe,
    OmadaPortProfile,
    OmadaPortStatistics,
    OmadaSite,
    OmadaSsid,
    OmadaSwitchPort,
    OmadaWanPort,
)

# ============================================================================
# API Envelope
# ============================================================================


class TestApiEnvelope:
    def test_success_envelope(self):
        env = OmadaApiEnvelope(errorCode=0, msg="Success", result={"key": "value"})
        assert env.errorCode == 0
        assert env.result == {"key": "value"}

    def test_error_envelope(self):
        env = OmadaApiEnvelope(errorCode=-1001, msg="session expired")
        assert env.errorCode == -1001
        assert env.result is None

    def test_default_values(self):
        env = OmadaApiEnvelope()
        assert env.errorCode == 0


class TestPaginatedData:
    def test_empty(self):
        page = OmadaPaginatedData()
        assert page.totalRows == 0
        assert page.data == []

    def test_with_data(self):
        page = OmadaPaginatedData(totalRows=2, data=[{"a": 1}, {"b": 2}])
        assert page.totalRows == 2
        assert len(page.data) == 2


# ============================================================================
# Controller & Site
# ============================================================================


class TestControllerModels:
    def test_controller_info(self):
        info = OmadaControllerInfo(omadacId="CTRL-1", controllerVer="5.14")
        assert info.omadacId == "CTRL-1"

    def test_controller_status(self):
        status = OmadaControllerStatus(cpuUtil=15.5, memUtil=60.0, uptime=86400)
        assert status.cpuUtil == 15.5

    def test_site(self):
        site = OmadaSite(siteId="s1", id="s1", name="Main", deviceCount=10)
        assert site.name == "Main"
        assert site.deviceCount == 10


# ============================================================================
# Device
# ============================================================================


class TestDeviceModel:
    def test_basic_device(self):
        dev = OmadaDevice(type="switch", mac="AA:BB:CC:DD:EE:01", name="Sw1", ip="10.0.0.1")
        assert dev.type == "switch"

    def test_cpu_coerce_int_to_float(self):
        dev = OmadaDevice(cpuUtil=42)
        assert dev.cpuUtil == 42.0

    def test_cpu_coerce_string_to_float(self):
        dev = OmadaDevice(cpuUtil="33.5")
        assert dev.cpuUtil == 33.5

    def test_cpu_coerce_none(self):
        dev = OmadaDevice(cpuUtil=None)
        assert dev.cpuUtil is None

    def test_cpu_coerce_garbage(self):
        dev = OmadaDevice(cpuUtil="not-a-number")
        assert dev.cpuUtil is None


# ============================================================================
# Switch Port & PoE
# ============================================================================


class TestSwitchPortModel:
    def test_port_from_dict(self):
        port = OmadaSwitchPort(
            port=1,
            enable=True,
            linkStatus=True,
            linkSpeed=1000,
            poe=OmadaPortPoe(enable=True, power=15.3, maxPower=30),
            pvid=10,
            taggedVlans=[20, 30],
        )
        assert port.port == 1
        assert port.enabled is True
        assert port.link_status.value == "up"
        assert port.poe_enabled is True
        assert port.poe_power == 15.3
        assert port.nativeVlan == 10

    def test_port_down(self):
        port = OmadaSwitchPort(port=3, enable=False, linkStatus=False)
        assert port.link_status.value == "down"
        assert port.poe_enabled is False
        assert port.poe_power == 0.0

    def test_port_statistics(self):
        stats = OmadaPortStatistics(port=1, rxBytes=1024, txBytes=2048, rxErrors=1)
        assert stats.rxBytes == 1024
        assert stats.rxErrors == 1


# ============================================================================
# Network / VLAN
# ============================================================================


class TestNetworkModel:
    def test_network(self):
        net = OmadaNetwork(id="n1", name="LAN", vlanId=1, gateway="192.168.1.1")
        assert net.effective_id == "n1"

    def test_network_fallback_id(self):
        net = OmadaNetwork(networkId="n2", name="VoIP")
        assert net.effective_id == "n2"


# ============================================================================
# SSID
# ============================================================================


class TestSsidModel:
    def test_ssid(self):
        ssid = OmadaSsid(id="s1", name="Corp", enable=True, ssid="Corp-WiFi")
        assert ssid.display_name == "Corp-WiFi"

    def test_ssid_no_ssid_field(self):
        ssid = OmadaSsid(id="s2", name="Guest")
        assert ssid.display_name == "Guest"


# ============================================================================
# Client
# ============================================================================


class TestClientModel:
    def test_wireless_client(self):
        c = OmadaClient(mac="AA:BB:CC:DD:EE:FF", wireless=True, ssid="Corp")
        assert c.connection_type.value == "wireless"
        assert c.display_name == "AA:BB:CC:DD:EE:FF"

    def test_wired_client(self):
        c = OmadaClient(mac="AA:BB:CC:DD:EE:FF", wireless=False, switchMac="11:22:33:44:55:66", name="Phone")
        assert c.connection_type.value == "wired"
        assert c.display_name == "Phone"

    def test_client_inferred_wired(self):
        c = OmadaClient(mac="AA:BB:CC:DD:EE:FF", switchMac="11:22:33:44:55:66")
        assert c.connection_type.value == "wired"


# ============================================================================
# Gateway Models
# ============================================================================


class TestGatewayModels:
    def test_wan_port(self):
        wp = OmadaWanPort(portName="WAN1", ip="203.0.113.1", status="online")
        assert wp.status == "online"

    def test_gateway(self):
        gw = OmadaGateway(mac="AA:BB:CC:00:00:01", model="ER7206", cpuUtil=5.0)
        assert gw.model == "ER7206"

    def test_firwall_rule(self):
        rule = OmadaFirewallRule(id="r1", name="Block", action="drop", protocol="tcp")
        assert rule.action == "drop"


# ============================================================================
# Port Profile
# ============================================================================


class TestPortProfileModel:
    def test_access_profile(self):
        p = OmadaPortProfile(id="p1", name="Access", nativeVlan=10, type="access")
        assert p.effective_id == "p1"
        assert p.nativeVlan == 10

    def test_trunk_profile(self):
        p = OmadaPortProfile(profileId="p2", name="Trunk", taggedVlans=[10, 20])
        assert p.effective_id == "p2"


# ============================================================================
# Firmware
# ============================================================================


class TestFirmwareModel:
    def test_firmware_info(self):
        fw = OmadaFirmwareInfo(currentVersion="1.6.3", latestVersion="1.7.0", needUpgrade=True)
        assert fw.needUpgrade is True


# ============================================================================
# Metrics
# ============================================================================


class TestMetricsModel:
    def test_device_metrics(self):
        m = OmadaDeviceMetrics(cpu=12.5, memory=45.0, uptime=86400)
        assert m.cpu_percent == 12.5
        assert m.memory_percent == 45.0

    def test_device_metrics_defaults(self):
        m = OmadaDeviceMetrics()
        assert m.cpu_percent == 0.0
        assert m.memory_percent == 0.0


# ============================================================================
# Normalized Output Models
# ============================================================================


class TestNormalizedModels:
    def test_normalized_port(self):
        p = NormalizedPort(port_number=1, name="Uplink", enabled=True, status="up")
        assert p.port_number == 1

    def test_normalized_vlan(self):
        v = NormalizedVlan(id="v1", vlan_id=10, name="LAN")
        assert v.vlan_id == 10

    def test_normalized_ssid(self):
        s = NormalizedSsid(id="s1", name="Corp", enabled=True)
        assert s.broadcast is True  # default

    def test_normalized_client(self):
        c = NormalizedClient(mac_address="AA:BB:CC:DD:EE:FF", connection_type="wireless")
        assert c.blocked is False

    def test_normalized_firewall_rule(self):
        r = NormalizedFirewallRule(id="r1", name="Drop", action="drop")
        assert r.enabled is True

    def test_normalized_port_profile(self):
        p = NormalizedPortProfile(id="p1", name="Access", native_vlan=10)
        assert p.tagged_vlans == []
