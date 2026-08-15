# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — pfSense Normalized Models
=======================================

Pydantic models that normalize pfSense REST API v2 responses into
the same shape used by OPNsense, OpenWRT, and MikroTik adapters.

pfSense uses ISC-DHCPD (not KEA) and Unbound for DNS.
API responses are unwrapped from the ``"data"`` envelope by the client.
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
    PASS = "pass"
    BLOCK = "block"
    REJECT = "reject"
    MATCH = "match"


class ServiceStatus(StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class DHCPLeaseStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    STATIC = "static"


# ═══════════════════════════════════════════════════════════════════════════════
# System
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedSystemInfo(BaseModel):
    """System info from /status/system + /system/hostname."""

    hostname: str = ""
    version: str = ""
    platform: str = ""
    netgate_id: str = ""
    uptime: str = ""
    cpu_type: str = ""
    cpu_count: int = 0
    memory_total: int = 0
    memory_used: int = 0
    disk_total: int = 0
    disk_used: int = 0
    load_average: list[float] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Interfaces
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedInterface(BaseModel):
    """Network interface from /interface."""

    id: str = ""  # pfSense interface name (e.g. "opt1")
    descr: str = ""  # User-friendly name
    if_name: str = ""  # Physical interface (e.g. "igb0")
    status: InterfaceStatus = InterfaceStatus.DOWN
    enabled: bool = True
    ipaddr: str = ""
    subnet: str = ""
    gateway: str = ""
    mac_address: str = ""
    mtu: int | None = None
    media: str = ""
    # VLAN-specific
    vlan_tag: int | None = None
    parent_if: str | None = None
    # Stats
    inbytes: int = 0
    outbytes: int = 0
    inpkts: int = 0
    outpkts: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Firewall
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedFirewallRule(BaseModel):
    """Firewall filter rule from /firewall/rule."""

    id: int = 0
    tracker: int = 0
    type: str = "pass"  # pass, block, reject, match
    interface: str = ""
    ipprotocol: str = "inet"  # inet, inet6, inet46
    protocol: str = ""
    source: str = ""
    destination: str = ""
    src_port: str = ""
    dst_port: str = ""
    descr: str = ""
    disabled: bool = False
    log: bool = False
    floating: bool = False


class NormalizedNATRule(BaseModel):
    """NAT rule from /firewall/nat/port_forward or /firewall/nat/outbound."""

    id: int = 0
    interface: str = ""
    protocol: str = ""
    source: str = ""
    destination: str = ""
    target: str = ""  # redirect target
    local_port: str = ""
    descr: str = ""
    disabled: bool = False


class NormalizedAlias(BaseModel):
    """Firewall alias from /firewall/alias."""

    name: str = ""
    type: str = ""  # host, network, port, url
    address: list[str] = Field(default_factory=list)
    descr: str = ""
    detail: list[str] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# DHCP
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedDHCPLease(BaseModel):
    """DHCP lease from /services/dhcpd/lease."""

    ip: str = ""
    mac: str = ""
    hostname: str = ""
    start: str = ""
    end: str = ""
    status: DHCPLeaseStatus = DHCPLeaseStatus.ACTIVE
    online: bool = False
    descr: str = ""


class NormalizedDHCPServer(BaseModel):
    """DHCP server config per interface from /services/dhcpd."""

    interface: str = ""
    enabled: bool = False
    range_from: str = ""
    range_to: str = ""
    gateway: str = ""
    domain: str = ""
    dns_servers: list[str] = Field(default_factory=list)
    default_lease_time: int = 7200
    max_lease_time: int = 86400


class NormalizedDHCPStaticMapping(BaseModel):
    """Static DHCP mapping from /services/dhcpd/static_mapping."""

    id: int = 0
    mac: str = ""
    ipaddr: str = ""
    hostname: str = ""
    descr: str = ""
    interface: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# DNS
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedDNSOverride(BaseModel):
    """DNS host override from /services/unbound/host_override."""

    id: int = 0
    host: str = ""
    domain: str = ""
    ip: str = ""
    descr: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedStaticRoute(BaseModel):
    """Static route from /routing/static_route."""

    id: int = 0
    network: str = ""
    gateway: str = ""
    descr: str = ""
    disabled: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# VPN
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedWireGuardTunnel(BaseModel):
    """WireGuard tunnel from /vpn/wireguard/tunnel."""

    name: str = ""
    listenport: int = 0
    publickey: str = ""
    privatekey: str = ""
    enabled: bool = True
    descr: str = ""


class NormalizedWireGuardPeer(BaseModel):
    """WireGuard peer from /vpn/wireguard/peer."""

    publickey: str = ""
    endpoint: str = ""
    allowedips: str = ""
    descr: str = ""
    enabled: bool = True


class NormalizedIPsecTunnel(BaseModel):
    """IPsec tunnel from /vpn/ipsec/phase1."""

    ikeid: int = 0
    descr: str = ""
    remote_gateway: str = ""
    protocol: str = ""
    disabled: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# Services
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedService(BaseModel):
    """Service from /status/service."""

    name: str = ""
    description: str = ""
    status: ServiceStatus = ServiceStatus.UNKNOWN
    enabled: bool = True
