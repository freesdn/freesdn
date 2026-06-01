# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Shared fixtures for Omada adapter tests.

Provides pre-configured mock adapters, mock clients, and JSON fixture loaders
for all test modules in this package.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, PropertyMock

import pytest

from app.adapters.omada.adapter import OmadaAdapter
from app.adapters.omada.client import OmadaApiClient

# Path to mock JSON response files
MOCK_DIR = Path(__file__).parent / "mock_responses"


def load_mock(name: str) -> Any:
    """Load a mock JSON response file by name (without extension)."""
    path = MOCK_DIR / f"{name}.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ============================================================================
# Raw mock data fixtures
# ============================================================================


@pytest.fixture()
def mock_devices() -> list[dict[str, Any]]:
    return load_mock("devices")


@pytest.fixture()
def mock_sites_response() -> dict[str, Any]:
    return load_mock("sites")


@pytest.fixture()
def mock_switch_ports() -> list[dict[str, Any]]:
    return load_mock("switch_ports")


@pytest.fixture()
def mock_clients() -> list[dict[str, Any]]:
    return load_mock("clients")


@pytest.fixture()
def mock_ssids() -> list[dict[str, Any]]:
    return load_mock("ssids")


@pytest.fixture()
def mock_vlans() -> list[dict[str, Any]]:
    return load_mock("vlans")


@pytest.fixture()
def mock_port_profiles() -> list[dict[str, Any]]:
    return load_mock("port_profiles")


@pytest.fixture()
def mock_firmware() -> dict[str, Any]:
    return load_mock("firmware")


# ============================================================================
# OmadaApiClient mock
# ============================================================================


@pytest.fixture()
def mock_client(
    mock_devices: list[dict],
    mock_switch_ports: list[dict],
    mock_clients: list[dict],
    mock_ssids: list[dict],
    mock_vlans: list[dict],
    mock_port_profiles: list[dict],
    mock_firmware: dict,
) -> MagicMock:
    """A fully mocked OmadaApiClient with all endpoints returning fixture data."""
    client = MagicMock(spec=OmadaApiClient)

    # Auth
    client.login = AsyncMock(return_value={"controller_id": "CTRL-ABC123", "version": "5.14.26.1"})
    client.logout = AsyncMock()

    # Properties
    type(client).controller_id = PropertyMock(return_value="CTRL-ABC123")
    type(client).controller_version = PropertyMock(return_value="5.14.26.1")

    # Sites
    client.get_sites = AsyncMock(return_value=[
        {"siteId": "site-001", "id": "site-001", "name": "Default"},
        {"siteId": "site-002", "id": "site-002", "name": "Branch Office"},
    ])
    client.get_site = AsyncMock(return_value={"siteId": "site-001", "id": "site-001", "name": "Default"})

    # Devices
    client.get_devices = AsyncMock(return_value=mock_devices)
    client.get_device = AsyncMock(return_value=mock_devices[0])
    client.adopt_device = AsyncMock(return_value={})
    client.forget_device = AsyncMock(return_value={})
    client.reboot_device = AsyncMock(return_value={})

    # Switch
    client.get_switch_ports = AsyncMock(return_value=mock_switch_ports)
    client.update_switch_port = AsyncMock(return_value={})
    client.get_port_statistics = AsyncMock(return_value={"port": 1, "rxBytes": 1024, "txBytes": 512})
    client.set_port_poe = AsyncMock(return_value={})
    client.cycle_port_poe = AsyncMock(return_value={})

    # VLANs / Networks
    client.get_networks = AsyncMock(return_value=mock_vlans)
    client.create_network = AsyncMock(return_value={"id": "net-new", "vlanId": 50, "name": "New VLAN"})
    client.update_network = AsyncMock(return_value={})
    client.delete_network = AsyncMock(return_value={})

    # SSIDs
    client.get_ssids = AsyncMock(return_value=mock_ssids)
    client.create_ssid = AsyncMock(return_value={"id": "ssid-new", "name": "New-WiFi"})
    client.update_ssid = AsyncMock(return_value={})
    client.delete_ssid = AsyncMock(return_value={})

    # Clients
    client.get_clients = AsyncMock(return_value=mock_clients)
    client.get_client_history = AsyncMock(return_value=[])
    client.block_client = AsyncMock(return_value={})
    client.unblock_client = AsyncMock(return_value={})
    client.kick_client = AsyncMock(return_value={})

    # APs
    client.get_aps = AsyncMock(return_value=[mock_devices[1]])
    client.get_ap = AsyncMock(return_value=mock_devices[1])
    client.update_ap = AsyncMock(return_value={})
    client.set_ap_led = AsyncMock(return_value={})

    # Gateways
    client.get_gateways = AsyncMock(return_value=[mock_devices[2]])
    client.get_gateway = AsyncMock(return_value=mock_devices[2])
    client.get_wan_config = AsyncMock(return_value={"wanPortSettings": []})
    client.update_wan_config = AsyncMock(return_value={})
    client.get_dhcp_config = AsyncMock(return_value={})
    client.get_firewall_rules = AsyncMock(return_value=[
        {"id": "fw-1", "name": "Allow LAN", "enabled": True, "action": "accept", "protocol": "all"},
    ])
    client.get_vpn_config = AsyncMock(return_value={"ipsec": [], "wireGuard": []})

    # Port profiles
    client.get_port_profiles = AsyncMock(return_value=mock_port_profiles)
    client.create_port_profile = AsyncMock(return_value={"id": "prof-new", "name": "New Profile"})
    client.update_port_profile = AsyncMock(return_value={})
    client.delete_port_profile = AsyncMock(return_value={})

    # Firmware
    client.get_firmware_info = AsyncMock(return_value=mock_firmware)
    client.trigger_firmware_upgrade = AsyncMock(return_value={"jobId": "fw-job-1"})

    # Controller status
    client.get_controller_status = AsyncMock(return_value={"cpuUtil": 10, "memUtil": 40})
    client.get_system_info = AsyncMock(return_value={"version": "5.14.26.1"})

    # Health
    client.get_health = MagicMock(return_value={
        "logged_in": True,
        "controller_id": "CTRL-ABC123",
        "controller_version": "5.14.26.1",
        "request_count": 42,
        "error_count": 0,
        "error_rate": 0.0,
        "avg_latency_ms": 15.2,
        "cache_hit_rate": 0.6,
        "rate_limit_remaining": 55,
        "last_successful_request": None,
    })

    return client


# ============================================================================
# OmadaAdapter with injected mock client
# ============================================================================


@pytest.fixture()
def adapter(mock_client: MagicMock) -> OmadaAdapter:
    """
    A fully wired OmadaAdapter with a mocked client.
    
    Connect is pre-called so the adapter is in 'connected' state.
    """
    adpt = OmadaAdapter("10.0.0.1", "admin", "secret")
    adpt._client = mock_client
    adpt._connected = True
    adpt._site_id = "site-001"
    return adpt


@pytest.fixture()
def adapter_no_site(mock_client: MagicMock) -> OmadaAdapter:
    """Adapter with no pre-set site (tests auto-resolution)."""
    adpt = OmadaAdapter("10.0.0.1", "admin", "secret")
    adpt._client = mock_client
    adpt._connected = True
    adpt._site_id = None
    return adpt
