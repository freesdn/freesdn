# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Network Module - Unit Tests
====================================

Tests for network service layer functionality.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.devices import (
    Device as NetworkDevice,
)
from app.models.devices import (
    DeviceClient as NetworkClient,
)
from app.models.devices import (
    DevicePort as SwitchPort,
)
from app.modules.network.models import (
    Network as Vlan,
)
from app.modules.network.models import (
    WifiNetwork,
)
from app.modules.network.service import (
    ClientNotFoundError,
    DeviceNotFoundError,
    DuplicateError,
    NetworkClientService,
    NetworkDeviceService,
    NetworkSummaryService,
    SwitchPortService,
    TopologyService,
    VlanNotFoundError,
    VlanService,
    WifiNetworkNotFoundError,
    WifiNetworkService,
)

# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_session():
    """Create a mock async database session."""
    session = AsyncMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    session.delete = AsyncMock()
    return session


@pytest.fixture
def org_id():
    """Sample organization ID."""
    return uuid.uuid4()


@pytest.fixture
def site_id():
    """Sample site ID."""
    return uuid.uuid4()


@pytest.fixture
def sample_vlan(org_id, site_id):
    """Create a sample VLAN object."""
    vlan = MagicMock(spec=Vlan)
    vlan.id = uuid.uuid4()
    vlan.organization_id = org_id
    vlan.site_id = site_id
    vlan.vlan_id = 100
    vlan.name = "Management VLAN"
    vlan.description = "Management network"
    vlan.dhcp_enabled = True
    vlan.dhcp_start = "192.168.100.100"
    vlan.dhcp_end = "192.168.100.200"
    vlan.gateway = "192.168.100.1"
    vlan.subnet_mask = "255.255.255.0"
    return vlan


@pytest.fixture
def sample_wifi(org_id, site_id):
    """Create a sample WiFi network object."""
    wifi = MagicMock(spec=WifiNetwork)
    wifi.id = uuid.uuid4()
    wifi.organization_id = org_id
    wifi.site_id = site_id
    wifi.ssid = "Corporate-WiFi"
    wifi.security = "wpa2-enterprise"
    wifi.password_hash = None
    wifi.vlan_id = 200
    wifi.hidden = False
    wifi.enabled = True
    wifi.band = "both"
    wifi.client_isolation = False
    wifi.band_steering = True
    wifi.fast_roaming = True
    wifi.rate_limit_enabled = False
    wifi.rate_limit_up = None
    wifi.rate_limit_down = None
    return wifi


@pytest.fixture
def sample_device(org_id, site_id):
    """Create a sample network device object."""
    device = MagicMock(spec=NetworkDevice)
    device.id = uuid.uuid4()
    device.organization_id = org_id
    device.site_id = site_id
    device.name = "Core-Switch-01"
    device.device_type = "switch"
    device.vendor = "Omada"
    device.model = "TL-SG3428X"
    device.firmware_version = "1.2.3"
    device.ip_address = "192.168.1.10"
    device.mac_address = "AA:BB:CC:DD:EE:FF"
    device.status = "online"
    device.uptime = 86400
    device.ports = []
    return device


@pytest.fixture
def sample_port(sample_device):
    """Create a sample switch port object."""
    port = MagicMock(spec=SwitchPort)
    port.id = uuid.uuid4()
    port.device_id = sample_device.id
    port.port_number = 1
    port.port_name = "Port 1"
    port.enabled = True
    port.poe_enabled = True
    port.native_vlan = 1
    port.tagged_vlans = [100, 200]
    port.status = "up"
    port.speed = "1G"
    port.duplex = "full"
    port.poe_power_draw = 15.5
    port.rx_bytes = 1000000
    port.tx_bytes = 500000
    return port


@pytest.fixture
def sample_client(org_id, site_id):
    """Create a sample network client object."""
    client = MagicMock(spec=NetworkClient)
    client.id = uuid.uuid4()
    client.organization_id = org_id
    client.site_id = site_id
    client.mac_address = "11:22:33:44:55:66"
    client.ip_address = "192.168.1.100"
    client.hostname = "desktop-pc"
    client.display_name = "John's Desktop"
    client.connection_type = "wired"
    client.status = "online"
    client.blocked = False
    client.rx_bytes = 1000000
    client.tx_bytes = 500000
    client.last_seen = datetime.now(UTC)
    return client


# ============================================================================
# VLAN Service Tests
# ============================================================================

class TestVlanService:
    """Tests for VlanService."""

    @pytest.mark.asyncio
    async def test_list_vlans_empty(self, mock_session, org_id):
        """Test listing VLANs when none exist."""
        # Setup mock to return empty
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 0

        service = VlanService(mock_session)
        vlans, total = await service.list(org_id)

        assert vlans == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_list_vlans_with_results(self, mock_session, org_id, sample_vlan):
        """Test listing VLANs with results."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_vlan]
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1

        service = VlanService(mock_session)
        vlans, total = await service.list(org_id)

        assert len(vlans) == 1
        assert total == 1
        assert vlans[0] == sample_vlan

    @pytest.mark.asyncio
    async def test_list_vlans_with_site_filter(self, mock_session, org_id, site_id, sample_vlan):
        """Test listing VLANs filtered by site."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_vlan]
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1

        service = VlanService(mock_session)
        vlans, total = await service.list(org_id, site_id=site_id)

        assert len(vlans) == 1
        # Verify the filter was applied by checking execute was called
        assert mock_session.execute.called

    @pytest.mark.asyncio
    async def test_get_vlan_success(self, mock_session, org_id, sample_vlan):
        """Test getting a VLAN by ID."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_vlan
        mock_session.execute.return_value = mock_result

        service = VlanService(mock_session)
        vlan = await service.get(sample_vlan.id, org_id)

        assert vlan == sample_vlan

    @pytest.mark.asyncio
    async def test_get_vlan_not_found(self, mock_session, org_id):
        """Test getting a non-existent VLAN."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        service = VlanService(mock_session)

        with pytest.raises(VlanNotFoundError):
            await service.get(uuid.uuid4(), org_id)

    @pytest.mark.asyncio
    async def test_create_vlan_success(self, mock_session, org_id):
        """Test creating a new VLAN."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None  # No existing VLAN
        mock_session.execute.return_value = mock_result

        service = VlanService(mock_session)
        vlan = await service.create(
            organization_id=org_id,
            vlan_id=100,
            name="Test VLAN",
            description="Test description",
            dhcp_enabled=True,
            dhcp_start="192.168.100.100",
            dhcp_end="192.168.100.200",
            gateway="192.168.100.1",
            subnet_mask="255.255.255.0",
        )

        # Verify add was called
        assert mock_session.add.called
        assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_create_vlan_duplicate(self, mock_session, org_id, sample_vlan):
        """Test creating a duplicate VLAN."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_vlan  # Existing VLAN
        mock_session.execute.return_value = mock_result

        service = VlanService(mock_session)

        with pytest.raises(DuplicateError):
            await service.create(
                organization_id=org_id,
                vlan_id=100,
                name="Test VLAN",
            )

    @pytest.mark.asyncio
    async def test_update_vlan_success(self, mock_session, org_id, sample_vlan):
        """Test updating a VLAN."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_vlan
        mock_session.execute.return_value = mock_result

        service = VlanService(mock_session)
        updated = await service.update(
            sample_vlan.id,
            org_id,
            name="Updated VLAN",
            description="Updated description",
        )

        assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_delete_vlan_success(self, mock_session, org_id, sample_vlan):
        """Test deleting a VLAN."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_vlan
        mock_session.execute.return_value = mock_result

        service = VlanService(mock_session)
        await service.delete(sample_vlan.id, org_id)

        assert mock_session.delete.called
        assert mock_session.commit.called


# ============================================================================
# WiFi Network Service Tests
# ============================================================================

class TestWifiNetworkService:
    """Tests for WifiNetworkService."""

    @pytest.mark.asyncio
    async def test_list_wifi_networks(self, mock_session, org_id, sample_wifi):
        """Test listing WiFi networks."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_wifi]
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1

        service = WifiNetworkService(mock_session)
        networks, total = await service.list(org_id)

        assert len(networks) == 1
        assert total == 1

    @pytest.mark.asyncio
    async def test_list_wifi_networks_filtered_by_enabled(self, mock_session, org_id, sample_wifi):
        """Test listing only enabled WiFi networks."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_wifi]
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1

        service = WifiNetworkService(mock_session)
        networks, total = await service.list(org_id, enabled=True)

        assert mock_session.execute.called

    @pytest.mark.asyncio
    async def test_get_wifi_network_success(self, mock_session, org_id, sample_wifi):
        """Test getting a WiFi network by ID."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_wifi
        mock_session.execute.return_value = mock_result

        service = WifiNetworkService(mock_session)
        network = await service.get(sample_wifi.id, org_id)

        assert network == sample_wifi

    @pytest.mark.asyncio
    async def test_get_wifi_network_not_found(self, mock_session, org_id):
        """Test getting a non-existent WiFi network."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        service = WifiNetworkService(mock_session)

        with pytest.raises(WifiNetworkNotFoundError):
            await service.get(uuid.uuid4(), org_id)

    @pytest.mark.asyncio
    async def test_create_wifi_network(self, mock_session, org_id):
        """Test creating a WiFi network."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None  # No existing
        mock_session.execute.return_value = mock_result

        service = WifiNetworkService(mock_session)
        await service.create(
            organization_id=org_id,
            ssid="Guest-WiFi",
            security="wpa2-personal",
            password_hash="hashedpassword",
            vlan_id=300,
        )

        assert mock_session.add.called
        assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_create_duplicate_wifi_network(self, mock_session, org_id, sample_wifi):
        """Test creating a duplicate WiFi network."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_wifi
        mock_session.execute.return_value = mock_result

        service = WifiNetworkService(mock_session)

        with pytest.raises(DuplicateError):
            await service.create(
                organization_id=org_id,
                ssid="Corporate-WiFi",
            )

    @pytest.mark.asyncio
    async def test_toggle_wifi_enabled(self, mock_session, org_id, sample_wifi):
        """Test enabling/disabling WiFi network."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_wifi
        mock_session.execute.return_value = mock_result

        service = WifiNetworkService(mock_session)
        await service.toggle_enabled(sample_wifi.id, org_id, enabled=False)

        assert mock_session.commit.called


# ============================================================================
# Switch Port Service Tests
# ============================================================================

class TestSwitchPortService:
    """Tests for SwitchPortService."""

    @pytest.mark.asyncio
    async def test_list_ports_by_device(self, mock_session, org_id, sample_device, sample_port):
        """Test listing ports for a device."""
        # Device exists
        device_result = MagicMock()
        device_result.scalar_one_or_none.return_value = sample_device

        # Ports result
        ports_result = MagicMock()
        ports_result.scalars.return_value.all.return_value = [sample_port]

        mock_session.execute.side_effect = [device_result, ports_result]

        service = SwitchPortService(mock_session)
        ports = await service.list_by_device(sample_device.id, org_id)

        assert len(ports) == 1

    @pytest.mark.asyncio
    async def test_list_ports_device_not_found(self, mock_session, org_id):
        """Test listing ports for non-existent device."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        service = SwitchPortService(mock_session)

        with pytest.raises(DeviceNotFoundError):
            await service.list_by_device(uuid.uuid4(), org_id)

    @pytest.mark.asyncio
    async def test_get_port(self, mock_session, org_id, sample_device, sample_port):
        """Test getting a specific port."""
        device_result = MagicMock()
        device_result.scalar_one_or_none.return_value = sample_device

        port_result = MagicMock()
        port_result.scalar_one_or_none.return_value = sample_port

        mock_session.execute.side_effect = [device_result, port_result]

        service = SwitchPortService(mock_session)
        port = await service.get(sample_port.id, sample_device.id, org_id)

        assert port == sample_port

    @pytest.mark.asyncio
    async def test_set_poe_enabled(self, mock_session, org_id, sample_device, sample_port):
        """Test enabling PoE on a port."""
        device_result = MagicMock()
        device_result.scalar_one_or_none.return_value = sample_device

        port_result = MagicMock()
        port_result.scalar_one_or_none.return_value = sample_port

        mock_session.execute.side_effect = [device_result, port_result]

        service = SwitchPortService(mock_session)
        await service.set_poe(sample_port.id, sample_device.id, org_id, enabled=True)

        assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_set_port_vlan(self, mock_session, org_id, sample_device, sample_port):
        """Test setting port VLAN configuration."""
        device_result = MagicMock()
        device_result.scalar_one_or_none.return_value = sample_device

        port_result = MagicMock()
        port_result.scalar_one_or_none.return_value = sample_port

        mock_session.execute.side_effect = [device_result, port_result]

        service = SwitchPortService(mock_session)
        await service.set_vlan(
            sample_port.id, sample_device.id, org_id,
            native_vlan=100,
            tagged_vlans=[200, 300],
        )

        assert mock_session.commit.called


# ============================================================================
# Network Client Service Tests
# ============================================================================

class TestNetworkClientService:
    """Tests for NetworkClientService."""

    @pytest.mark.asyncio
    async def test_list_clients(self, mock_session, org_id, sample_client):
        """Test listing network clients."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_client]
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1

        service = NetworkClientService(mock_session)
        clients, total = await service.list(org_id)

        assert len(clients) == 1
        assert total == 1

    @pytest.mark.asyncio
    async def test_list_clients_with_search(self, mock_session, org_id, sample_client):
        """Test listing clients with search filter."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_client]
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1

        service = NetworkClientService(mock_session)
        clients, total = await service.list(org_id, search="desktop")

        assert mock_session.execute.called

    @pytest.mark.asyncio
    async def test_list_clients_filtered_by_connection_type(self, mock_session, org_id, sample_client):
        """Test listing clients filtered by connection type."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_client]
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1

        service = NetworkClientService(mock_session)
        clients, total = await service.list(org_id, connection_type="wired")

        assert mock_session.execute.called

    @pytest.mark.asyncio
    async def test_get_client(self, mock_session, org_id, sample_client):
        """Test getting a client by ID."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_client
        mock_session.execute.return_value = mock_result

        service = NetworkClientService(mock_session)
        client = await service.get(sample_client.id, org_id)

        assert client == sample_client

    @pytest.mark.asyncio
    async def test_get_client_not_found(self, mock_session, org_id):
        """Test getting a non-existent client."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        service = NetworkClientService(mock_session)

        with pytest.raises(ClientNotFoundError):
            await service.get(uuid.uuid4(), org_id)

    @pytest.mark.asyncio
    async def test_block_client(self, mock_session, org_id, sample_client):
        """Test blocking a client."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_client
        mock_session.execute.return_value = mock_result

        service = NetworkClientService(mock_session)
        await service.block(sample_client.id, org_id)

        assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_unblock_client(self, mock_session, org_id, sample_client):
        """Test unblocking a client."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_client
        mock_session.execute.return_value = mock_result

        service = NetworkClientService(mock_session)
        await service.unblock(sample_client.id, org_id)

        assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_get_client_stats(self, mock_session, org_id):
        """Test getting client statistics."""
        mock_session.scalar.side_effect = [10, 8, 6, 4]  # total, online, wired, wifi

        service = NetworkClientService(mock_session)
        stats = await service.get_stats(org_id)

        assert stats["total_clients"] == 10
        assert stats["online_clients"] == 8
        assert stats["wired_clients"] == 6
        assert stats["wifi_clients"] == 4


# ============================================================================
# Network Device Service Tests
# ============================================================================

class TestNetworkDeviceService:
    """Tests for NetworkDeviceService."""

    @pytest.mark.asyncio
    async def test_list_devices(self, mock_session, org_id, sample_device):
        """Test listing network devices."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.unique.return_value.all.return_value = [sample_device]
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1

        service = NetworkDeviceService(mock_session)
        devices, total = await service.list(org_id)

        assert len(devices) == 1
        assert total == 1

    @pytest.mark.asyncio
    async def test_list_devices_filtered_by_type(self, mock_session, org_id, sample_device):
        """Test listing devices filtered by type."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.unique.return_value.all.return_value = [sample_device]
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1

        service = NetworkDeviceService(mock_session)
        devices, total = await service.list(org_id, device_type="switch")

        assert mock_session.execute.called

    @pytest.mark.asyncio
    async def test_get_device(self, mock_session, org_id, sample_device):
        """Test getting a device by ID."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        service = NetworkDeviceService(mock_session)
        device = await service.get(sample_device.id, org_id)

        assert device == sample_device

    @pytest.mark.asyncio
    async def test_get_device_not_found(self, mock_session, org_id):
        """Test getting a non-existent device."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        service = NetworkDeviceService(mock_session)

        with pytest.raises(DeviceNotFoundError):
            await service.get(uuid.uuid4(), org_id)

    @pytest.mark.asyncio
    async def test_get_device_stats(self, mock_session, org_id):
        """Test getting device statistics."""
        mock_session.scalar.side_effect = [20, 18, 5, 3, 10, 2]  # total, online, switch, router, ap, gateway

        service = NetworkDeviceService(mock_session)
        stats = await service.get_stats(org_id)

        assert stats["total_devices"] == 20
        assert stats["online_devices"] == 18


# ============================================================================
# Topology Service Tests
# ============================================================================

class TestTopologyService:
    """Tests for TopologyService."""

    @pytest.mark.asyncio
    async def test_get_topology(self, mock_session, org_id, sample_device):
        """Test getting network topology."""
        # Devices result
        devices_result = MagicMock()
        devices_result.scalars.return_value.all.return_value = [sample_device]

        # Links result (empty)
        links_result = MagicMock()
        links_result.scalars.return_value.all.return_value = []

        mock_session.execute.side_effect = [devices_result, links_result]

        service = TopologyService(mock_session)
        topology = await service.get_topology(org_id)

        assert "nodes" in topology
        assert "links" in topology
        assert len(topology["nodes"]) == 1
        assert len(topology["links"]) == 0


# ============================================================================
# Network Summary Service Tests
# ============================================================================

class TestNetworkSummaryService:
    """Tests for NetworkSummaryService."""

    @pytest.mark.asyncio
    async def test_get_summary(self, mock_session, org_id):
        """Test getting network summary."""
        # Mock all the nested service calls
        mock_session.scalar.return_value = 0
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_result.scalars.return_value.unique.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        service = NetworkSummaryService(mock_session)
        summary = await service.get_summary(org_id)

        assert "devices" in summary
        assert "clients" in summary
        assert "total_vlans" in summary
        assert "total_wifi_networks" in summary
