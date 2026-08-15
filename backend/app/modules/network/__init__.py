# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Network Module
=====================

Core networking functionality including:
- VLAN Management
- WiFi Networks
- PoE Control
- Switch Port Management
- Network Clients
- Network Discovery
- Topology Management
"""

from app.modules.network.module import NetworkModule
from app.modules.network.service import (
    ClientNotFoundError,
    DeviceNotFoundError,
    DuplicateError,
    NetworkClientService,
    NetworkDeviceService,
    NetworkServiceError,
    NetworkSummaryService,
    PortNotFoundError,
    SwitchPortService,
    TopologyService,
    VlanNotFoundError,
    VlanService,
    WifiNetworkNotFoundError,
    WifiNetworkService,
)

__all__ = [
    "NetworkModule",
    # Services
    "VlanService",
    "WifiNetworkService",
    "SwitchPortService",
    "NetworkClientService",
    "NetworkDeviceService",
    "TopologyService",
    "NetworkSummaryService",
    # Exceptions
    "NetworkServiceError",
    "VlanNotFoundError",
    "WifiNetworkNotFoundError",
    "DeviceNotFoundError",
    "PortNotFoundError",
    "ClientNotFoundError",
    "DuplicateError",
]
