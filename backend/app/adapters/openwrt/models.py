# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — OpenWRT Normalized Models
========================================

Pydantic models that normalize OpenWRT ubus/UCI responses into
the same shape used by OPNsense, pfSense, and MikroTik adapters.
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


class FirewallTarget(StrEnum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    MARK = "MARK"
    NOTRACK = "NOTRACK"


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
    """System information from OpenWRT."""

    hostname: str = ""
    model: str = ""
    board_name: str = ""
    kernel: str = ""
    release_distribution: str = "OpenWrt"
    release_version: str = ""
    release_revision: str = ""
    release_description: str = ""
    uptime: int = 0
    localtime: int = 0
    load_1m: int = 0
    load_5m: int = 0
    load_15m: int = 0
    memory_total: int = 0
    memory_free: int = 0
    memory_buffered: int = 0
    memory_shared: int = 0
    swap_total: int = 0
    swap_free: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Interfaces
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedInterface(BaseModel):
    """Network interface from OpenWRT."""

    name: str = ""
    device: str = ""
    status: InterfaceStatus = InterfaceStatus.DOWN
    enabled: bool = True
    proto: str = ""  # static, dhcp, pppoe, none
    ipv4_address: str | None = None
    ipv4_subnet: str = ""
    ipv4_gateway: str | None = None
    ipv6_address: str | None = None
    mac_address: str | None = None
    mtu: int | None = None
    is_wan: bool = False
    is_lan: bool = False
    is_bridge: bool = False
    vlan_id: int | None = None
    parent_interface: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Firewall
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedFirewallRule(BaseModel):
    """Firewall rule from OpenWRT UCI firewall config."""

    id: str = ""  # synthetic UUID
    uci_name: str = ""  # original UCI section name
    name: str = ""
    enabled: bool = True
    target: str = "DROP"
    src: str = ""  # source zone
    dest: str = ""  # destination zone
    src_ip: str = ""
    dest_ip: str = ""
    src_port: str = ""
    dest_port: str = ""
    proto: str = ""  # tcp, udp, icmp, all
    family: str = ""  # ipv4, ipv6, any
    extra: str = ""  # extra iptables args
    description: str = ""


class NormalizedNATRule(BaseModel):
    """NAT/redirect rule from OpenWRT UCI firewall config."""

    id: str = ""
    uci_name: str = ""
    name: str = ""
    enabled: bool = True
    target: str = "DNAT"  # DNAT or SNAT
    src: str = ""  # source zone
    dest: str = ""  # destination zone
    src_ip: str = ""
    src_dip: str = ""  # source DNAT IP
    src_dport: str = ""  # source DNAT port
    dest_ip: str = ""
    dest_port: str = ""
    proto: str = ""
    description: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# DHCP
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedDHCPLease(BaseModel):
    """Active DHCP lease from dnsmasq."""

    mac_address: str = ""
    ip_address: str = ""
    hostname: str = ""
    expires: int = 0  # epoch timestamp
    status: DHCPLeaseStatus = DHCPLeaseStatus.ACTIVE


class NormalizedDHCPStaticHost(BaseModel):
    """Static DHCP host from UCI dhcp config."""

    id: str = ""
    uci_name: str = ""
    mac_address: str = ""
    ip_address: str = ""
    hostname: str = ""
    dns: bool = True  # register in DNS
    description: str = ""


class NormalizedDHCPScope(BaseModel):
    """DHCP scope/pool from UCI dhcp config."""

    id: str = ""
    uci_name: str = ""
    interface: str = ""
    enabled: bool = True
    start: int = 100  # offset from network address
    limit: int = 150  # number of addresses
    leasetime: str = "12h"
    dhcpv6: str = ""  # disabled, server, relay
    ra: str = ""  # disabled, server, relay


# ═══════════════════════════════════════════════════════════════════════════════
# DNS
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedDNSOverride(BaseModel):
    """DNS host override from UCI dhcp config (domain section)."""

    id: str = ""
    uci_name: str = ""
    hostname: str = ""
    domain: str = ""  # not always present
    ip_address: str = ""
    description: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedStaticRoute(BaseModel):
    """Static route from UCI network config."""

    id: str = ""
    uci_name: str = ""
    interface: str = ""
    target: str = ""  # destination network
    netmask: str = ""
    gateway: str = ""
    metric: int = 0
    description: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Services
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedService(BaseModel):
    """Service from procd."""

    name: str = ""
    status: ServiceStatus = ServiceStatus.UNKNOWN
    running: bool = False
    instances: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Address Group (ipset)
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedAddressGroup(BaseModel):
    """Firewall ipset (OpenWRT equivalent of OPNsense aliases)."""

    id: str = ""
    uci_name: str = ""
    name: str = ""
    match: str = "src_net"  # src_net, dest_net, src_ip, dest_ip
    storage: str = "hash"  # hash, bitmap
    enabled: bool = True
    entries: list[str] = Field(default_factory=list)
    description: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Port Forwards
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedPortForward(BaseModel):
    """Port forward (DNAT redirect) from UCI firewall config."""

    id: str = ""
    uci_name: str = ""
    name: str = ""
    enabled: bool = True
    interface: str = ""  # source zone (e.g. wan)
    protocol: str = ""  # tcp, udp, tcp udp
    source_port: str = ""  # external port
    destination_port: str = ""
    target_ip: str = ""
    target_port: str = ""
    description: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# DNS Domain Overrides
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedDNSDomainOverride(BaseModel):
    """DNS domain override (conditional forwarding) from dnsmasq server list."""

    id: str = ""
    domain: str = ""
    server: str = ""  # upstream DNS IP
    description: str = ""
    enabled: bool = True


# ═══════════════════════════════════════════════════════════════════════════════
# ARP / Routing / Gateways
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedARPEntry(BaseModel):
    """ARP table entry."""

    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    interface: str = ""
    permanent: bool = False


class NormalizedRoutingTableEntry(BaseModel):
    """Kernel routing table entry."""

    destination: str = ""
    gateway: str = ""
    flags: str = ""
    interface: str = ""
    metric: int = 0


class NormalizedGateway(BaseModel):
    """Gateway/upstream status."""

    name: str = ""
    address: str = ""
    status: str = "unknown"
    interface: str = ""
    default_gateway: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# System Log
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedLogEntry(BaseModel):
    """System log entry."""

    timestamp: str = ""
    priority: str = ""
    facility: str = ""
    message: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# WireGuard
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedWireGuardServer(BaseModel):
    """WireGuard interface from UCI network config."""

    id: str = ""
    uci_name: str = ""
    name: str = ""
    enabled: bool = True
    listen_port: int = 0
    addresses: list[str] = Field(default_factory=list)
    public_key: str = ""


class NormalizedWireGuardPeer(BaseModel):
    """WireGuard peer from UCI network config."""

    id: str = ""
    uci_name: str = ""
    name: str = ""
    enabled: bool = True
    public_key: str = ""
    endpoint_host: str = ""
    endpoint_port: int = 0
    allowed_ips: list[str] = Field(default_factory=list)
    persistent_keepalive: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# SQM / QoS
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizedSQMQueue(BaseModel):
    """SQM queue from UCI sqm config."""

    id: str = ""
    uci_name: str = ""
    interface: str = ""
    enabled: bool = True
    download: int = 0  # kbit/s
    upload: int = 0  # kbit/s
    qdisc: str = "fq_codel"
    script: str = "simple.qos"
