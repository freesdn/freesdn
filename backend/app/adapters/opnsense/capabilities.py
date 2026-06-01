# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — OPNsense Capability Mapping
============================================

Maps OPNsense capabilities per device type to the global Capability enum.
Used by the adapter manifest and by runtime capability checks.
"""

from app.adapters.capabilities import Capability

# ── Firewall device type ────────────────────────────────────────────────────

FIREWALL_CAPABILITIES: list[Capability] = [
    # Device
    Capability.DEVICE_INFO,
    Capability.DEVICE_REBOOT,
    Capability.DEVICE_BACKUP,
    Capability.DEVICE_FIRMWARE_UPGRADE,
    Capability.DEVICE_LOGS,
    Capability.DEVICE_METRICS,
    # Firewall
    Capability.FIREWALL_BASIC,
    Capability.FIREWALL_ADVANCED,
    Capability.FIREWALL_LOGGING,
    # NAT
    Capability.NAT,
    # DHCP / DNS
    Capability.DHCP_SERVER,
    Capability.DHCP_RESERVATIONS,
    Capability.DNS,
    # Routing
    Capability.ROUTING_STATIC,
    Capability.WAN_FAILOVER,
    Capability.LOAD_BALANCING,
    # QoS / Shaping
    Capability.QOS,
    Capability.TRAFFIC_SHAPING,
    # Events / Alerts
    Capability.EVENTS_ALERTS,
]

# ── VPN Gateway device type ────────────────────────────────────────────────

VPN_GATEWAY_CAPABILITIES: list[Capability] = [
    Capability.VPN_WIREGUARD,
    Capability.VPN_OPENVPN,
    Capability.VPN_IPSEC,
    Capability.VPN_L2TP,
    Capability.VPN_SERVER,
    Capability.VPN_CLIENT,
]

# ── UTM device type ────────────────────────────────────────────────────────

UTM_CAPABILITIES: list[Capability] = [
    Capability.IDS_IPS,
    Capability.GEO_BLOCKING,
    Capability.APPLICATION_FILTER,
    Capability.CONTENT_FILTER,
]

# ── Combined (all unique) ──────────────────────────────────────────────────

ALL_CAPABILITIES: list[Capability] = list(
    set(FIREWALL_CAPABILITIES + VPN_GATEWAY_CAPABILITIES + UTM_CAPABILITIES)
)
