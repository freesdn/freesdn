# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — OPNsense Enterprise Adapter"""

from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.adapters.opnsense.capabilities import (
    ALL_CAPABILITIES,
    FIREWALL_CAPABILITIES,
    UTM_CAPABILITIES,
    VPN_GATEWAY_CAPABILITIES,
)
from app.adapters.opnsense.client import OPNsenseAPIError, OPNsenseClient

# Re-export the key models so callers can do:
#   from app.adapters.opnsense import OPNsenseAdapter, NormalizedSystemInfo, ...
from app.adapters.opnsense.models import (  # noqa: F401 — public re-exports
    AliasType,
    DHCPLeaseStatus,
    # enums
    FirewallAction,
    FirewallDirection,
    FirewallProtocol,
    GatewayStatus,
    IDSAlertSeverity,
    InterfaceStatus,
    IPsecPhase,
    NATType,
    NormalizedAlias,
    NormalizedARPEntry,
    NormalizedBackupInfo,
    NormalizedDeviceSummary,
    NormalizedDHCPLease,
    NormalizedDHCPStaticMapping,
    NormalizedDNSDomainOverride,
    NormalizedDNSLookupResult,
    NormalizedDNSOverride,
    NormalizedFirewallLogEntry,
    NormalizedFirewallRule,
    NormalizedFirmwareInfo,
    NormalizedGateway,
    NormalizedIDSAlert,
    NormalizedIDSRuleSet,
    NormalizedIDSSettings,
    NormalizedInterface,
    NormalizedInterfaceStatistics,
    NormalizedIPsecTunnel,
    NormalizedLogEntry,
    NormalizedNATRule,
    NormalizedOpenVPNClient,
    NormalizedOpenVPNInstance,
    NormalizedPingResult,
    NormalizedPortForward,
    NormalizedRoutingTable,
    NormalizedService,
    NormalizedStaticRoute,
    # models
    NormalizedSystemInfo,
    NormalizedTracerouteHop,
    NormalizedTrafficPipe,
    NormalizedTrafficQueue,
    NormalizedTrafficRule,
    NormalizedTrafficTop,
    NormalizedWireGuardPeer,
    NormalizedWireGuardServer,
    RouteType,
    ServiceStatus,
    TrafficShaperDirection,
    VPNRole,
    VPNStatus,
    VPNType,
)

__all__ = [
    "OPNsenseAdapter",
    "OPNsenseClient",
    "OPNsenseAPIError",
    "FIREWALL_CAPABILITIES",
    "VPN_GATEWAY_CAPABILITIES",
    "UTM_CAPABILITIES",
    "ALL_CAPABILITIES",
]
