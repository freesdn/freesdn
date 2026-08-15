# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — MikroTik Normalized Models
========================================

Pydantic models that normalize MikroTik RouterOS REST API responses
into the same shape used by OPNsense, pfSense, and OpenWRT adapters.

MikroTik quirks:
  - Field names use hyphens (``dst-address``, ``mac-address``).
  - Every resource has a ``.id`` field (e.g. ``"*1A"``).
  - Booleans are strings: ``"true"`` / ``"false"``.
  - Changes take effect immediately (no commit step).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

# ═══════════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════════


class InterfaceStatus(StrEnum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class FirewallAction(StrEnum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
    PASSTHROUGH = "passthrough"
    LOG = "log"


class ServiceStatus(StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class DHCPLeaseStatus(StrEnum):
    BOUND = "bound"
    WAITING = "waiting"
    OFFERED = "offered"


# ═══════════════════════════════════════════════════════════════════════════════
# System
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedSystemInfo(BaseModel):
    """System info from /system/resource + /system/identity."""

    hostname: str = ""
    model: str = ""
    board_name: str = ""
    architecture: str = ""
    version: str = ""
    uptime: str = ""
    cpu_load: int = 0
    cpu_count: int = 0
    memory_total: int = 0
    memory_free: int = 0
    hdd_total: int = 0
    hdd_free: int = 0
    serial_number: str = ""
    firmware_type: str = ""
    factory_firmware: str = ""
    current_firmware: str = ""
    license_level: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Interfaces
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedInterface(BaseModel):
    """Network interface from /interface + /ip/address."""

    id: str = ""  # MikroTik .id (e.g. "*1A")
    name: str = ""
    type: str = ""  # ether, bridge, vlan, wlan, etc.
    status: InterfaceStatus = InterfaceStatus.DOWN
    disabled: bool = False
    running: bool = False
    mac_address: str = ""
    mtu: int = 0
    ipv4_address: str | None = None
    ipv4_network: str | None = None
    comment: str = ""
    # VLAN-specific
    vlan_id: int | None = None
    parent_interface: str | None = None
    # Traffic stats
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Firewall
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedFirewallRule(BaseModel):
    """Firewall filter rule from /ip/firewall/filter."""

    id: str = ""  # MikroTik .id
    chain: str = "forward"  # input, forward, output
    action: str = "drop"  # accept, drop, reject, passthrough
    disabled: bool = False
    src_address: str = ""
    dst_address: str = ""
    src_port: str = ""
    dst_port: str = ""
    protocol: str = ""
    in_interface: str = ""
    out_interface: str = ""
    src_address_list: str = ""
    dst_address_list: str = ""
    comment: str = ""
    log: bool = False
    log_prefix: str = ""
    bytes: int = 0
    packets: int = 0


class NormalizedNATRule(BaseModel):
    """NAT rule from /ip/firewall/nat."""

    id: str = ""
    chain: str = ""  # srcnat, dstnat
    action: str = ""  # masquerade, dst-nat, src-nat, redirect
    disabled: bool = False
    src_address: str = ""
    dst_address: str = ""
    src_port: str = ""
    dst_port: str = ""
    protocol: str = ""
    to_addresses: str = ""
    to_ports: str = ""
    in_interface: str = ""
    out_interface: str = ""
    comment: str = ""


class NormalizedAddressListEntry(BaseModel):
    """Firewall address-list entry from /ip/firewall/address-list."""

    id: str = ""
    list_name: str = Field(default="", alias="list")
    address: str = ""
    disabled: bool = False
    comment: str = ""
    creation_time: str = ""
    timeout: str = ""
    dynamic: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# DHCP
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedDHCPServer(BaseModel):
    """DHCP server from /ip/dhcp-server."""

    id: str = ""
    name: str = ""
    interface: str = ""
    address_pool: str = ""
    disabled: bool = False
    lease_time: str = "1d"
    authoritative: str = "yes"


class NormalizedDHCPLease(BaseModel):
    """DHCP lease from /ip/dhcp-server/lease."""

    id: str = ""
    mac_address: str = ""
    address: str = ""
    host_name: str = ""
    server: str = ""
    status: str = ""  # bound, waiting, offered
    active_address: str = ""
    active_mac_address: str = ""
    expires_after: str = ""
    comment: str = ""
    dynamic: bool = True
    disabled: bool = False


class NormalizedDHCPNetwork(BaseModel):
    """DHCP network from /ip/dhcp-server/network."""

    id: str = ""
    address: str = ""  # e.g. "192.168.10.0/24"
    gateway: str = ""
    dns_server: str = ""
    domain: str = ""
    comment: str = ""


class NormalizedIPPool(BaseModel):
    """IP pool from /ip/pool."""

    id: str = ""
    name: str = ""
    ranges: str = ""  # e.g. "192.168.10.100-192.168.10.200"
    comment: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# DNS
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedDNSEntry(BaseModel):
    """DNS static entry from /ip/dns/static."""

    id: str = ""
    name: str = ""  # hostname
    address: str = ""  # IP or CNAME target
    type: str = "A"  # A, AAAA, CNAME, etc.
    ttl: str = ""
    disabled: bool = False
    comment: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedRoute(BaseModel):
    """Static route from /ip/route."""

    id: str = ""
    dst_address: str = ""
    gateway: str = ""
    distance: int = 0
    scope: int = 0
    routing_table: str = "main"
    disabled: bool = False
    active: bool = False
    dynamic: bool = False
    comment: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# QoS
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedQueue(BaseModel):
    """Simple queue from /queue/simple."""

    id: str = ""
    name: str = ""
    target: str = ""
    max_limit: str = ""  # e.g. "10M/10M"
    burst_limit: str = ""
    burst_threshold: str = ""
    disabled: bool = False
    comment: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# VPN
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedWireGuardInterface(BaseModel):
    """WireGuard interface from /interface/wireguard."""

    id: str = ""
    name: str = ""
    listen_port: int = 0
    mtu: int = 1420
    running: bool = False
    disabled: bool = False
    public_key: str = ""


class NormalizedWireGuardPeer(BaseModel):
    """WireGuard peer from /interface/wireguard/peers."""

    id: str = ""
    interface: str = ""
    public_key: str = ""
    endpoint_address: str = ""
    endpoint_port: int = 0
    allowed_address: str = ""
    disabled: bool = False
    comment: str = ""
    rx: int = 0
    tx: int = 0
    last_handshake: str = ""


class NormalizedIPsecPeer(BaseModel):
    """IPsec peer from /ip/ipsec/peer."""

    id: str = ""
    name: str = ""
    address: str = ""
    profile: str = ""
    exchange_mode: str = ""
    disabled: bool = False
    comment: str = ""
