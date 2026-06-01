# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — OPNsense Normalized Pydantic Models
====================================================

Typed models for every OPNsense API response entity so that the adapter
layer returns structured, documented data instead of raw dicts.

Follows the same normalisation pattern as the Omada adapter.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ============================================================================
# Enumerations
# ============================================================================


class FirewallAction(StrEnum):
    PASS = "pass"
    BLOCK = "block"
    REJECT = "reject"


class FirewallDirection(StrEnum):
    IN = "in"
    OUT = "out"


class FirewallProtocol(StrEnum):
    ANY = "any"
    TCP = "TCP"
    UDP = "UDP"
    TCP_UDP = "TCP/UDP"
    ICMP = "ICMP"
    ICMPV6 = "ICMPv6"
    ESP = "ESP"
    AH = "AH"
    GRE = "GRE"
    IGMP = "IGMP"
    OSPF = "OSPF"
    CARP = "CARP"


class AliasType(StrEnum):
    HOST = "host"
    NETWORK = "network"
    PORT = "port"
    URL = "url"
    URL_TABLE = "urltable"
    GEO_IP = "geoip"
    MAC = "mac"
    EXTERNAL = "external"
    DYNAMIC_IPV6 = "dynipv6host"


class NATType(StrEnum):
    SOURCE = "source"
    DESTINATION = "destination"
    PORT_FORWARD = "port_forward"
    ONE_TO_ONE = "one_to_one"
    NPT = "npt"


class InterfaceStatus(StrEnum):
    UP = "up"
    DOWN = "down"
    NO_CARRIER = "no carrier"


class GatewayStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"
    PENDING = "pending"
    LOSS = "loss"
    DELAY = "delay"
    NONE = "none"


class VPNType(StrEnum):
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"
    IPSEC = "ipsec"


class VPNRole(StrEnum):
    SERVER = "server"
    CLIENT = "client"
    PEER = "peer"


class VPNStatus(StrEnum):
    UP = "up"
    DOWN = "down"
    CONNECTING = "connecting"
    ERROR = "error"


class ServiceStatus(StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class DHCPLeaseStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    STATIC = "static"


class IPsecPhase(StrEnum):
    PHASE1 = "phase1"
    PHASE2 = "phase2"


class IDSAlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RouteType(StrEnum):
    STATIC = "static"
    GATEWAY = "gateway"


class TrafficShaperDirection(StrEnum):
    DOWNLOAD = "download"
    UPLOAD = "upload"
    BOTH = "both"


# ============================================================================
# System / Device
# ============================================================================


class NormalizedSystemInfo(BaseModel):
    """System-level information about the OPNsense instance."""

    hostname: str = ""
    domain: str = ""
    fqdn: str = ""
    version: str = ""
    product_name: str = "OPNsense"
    product_series: str = ""
    architecture: str = ""
    kernel_version: str = ""
    uptime: int | None = None
    uptime_text: str = ""
    cpu_type: str = ""
    cpu_count: int | None = None
    cpu_usage_pct: float | None = None
    memory_total_mb: int | None = None
    memory_used_mb: int | None = None
    memory_usage_pct: float | None = None
    disk_total_gb: float | None = None
    disk_used_gb: float | None = None
    disk_usage_pct: float | None = None
    swap_total_mb: int | None = None
    swap_used_mb: int | None = None
    temperature_celsius: float | None = None
    bios_vendor: str | None = None
    bios_version: str | None = None
    system_manufacturer: str | None = None
    system_product: str | None = None
    system_serial: str | None = None


class NormalizedFirmwareInfo(BaseModel):
    """Firmware / update status."""

    current_version: str = ""
    latest_version: str | None = None
    needs_update: bool = False
    update_available: bool = False
    product_name: str = ""
    product_id: str = ""
    product_target: str = ""
    last_check: str | None = None
    download_size: str | None = None
    changelog: str | None = None
    repository: str | None = None
    mirror_url: str | None = None


# ============================================================================
# Interfaces
# ============================================================================


class NormalizedInterface(BaseModel):
    """Network interface details."""

    name: str = ""
    description: str = ""
    identifier: str = ""  # e.g. "igc0", "vtnet0"
    device: str = ""  # physical device
    status: InterfaceStatus = InterfaceStatus.DOWN
    enabled: bool = True
    link_type: str = ""  # e.g. "ethernet", "vlan", "gif"
    media: str = ""  # e.g. "1000baseT <full-duplex>"
    mtu: int | None = None
    mac_address: str | None = None
    ipv4_address: str | None = None
    ipv4_subnet: str | None = None
    ipv4_gateway: str | None = None
    ipv6_address: str | None = None
    ipv6_prefix: int | None = None
    is_wan: bool = False
    is_lan: bool = False
    vlan_id: int | None = None
    parent_interface: str | None = None
    bytes_received: int = 0
    bytes_sent: int = 0
    packets_received: int = 0
    packets_sent: int = 0
    errors_in: int = 0
    errors_out: int = 0
    collisions: int = 0
    speed_mbps: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedInterfaceStatistics(BaseModel):
    """Interface traffic statistics snapshot."""

    name: str = ""
    bytes_received: int = 0
    bytes_sent: int = 0
    packets_received: int = 0
    packets_sent: int = 0
    errors_in: int = 0
    errors_out: int = 0
    collisions: int = 0
    drop_in: int = 0
    drop_out: int = 0


# ============================================================================
# Firewall Rules
# ============================================================================


class NormalizedFirewallRule(BaseModel):
    """A single firewall filter rule."""

    uuid: str = ""
    sequence: int | None = None
    enabled: bool = True
    action: FirewallAction = FirewallAction.PASS
    direction: FirewallDirection = FirewallDirection.IN
    quick: bool = True
    interface: str = ""
    interface_name: str = ""
    ip_protocol: str = "IPv4"  # IPv4, IPv6, IPv4+IPv6
    protocol: FirewallProtocol = FirewallProtocol.ANY
    source_net: str = ""  # "any", CIDR, alias name
    source_port: str = ""
    source_invert: bool = False
    destination_net: str = ""
    destination_port: str = ""
    destination_invert: bool = False
    gateway: str = ""
    log: bool = False
    description: str = ""
    category: str = ""
    state_type: str = ""  # keep state, sloppy state, etc.
    created_at: str | None = None
    updated_at: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Firewall Aliases
# ============================================================================


class NormalizedAlias(BaseModel):
    """A firewall alias (IP group, port group, URL table, etc.)."""

    uuid: str = ""
    name: str = ""
    alias_type: AliasType = AliasType.HOST
    description: str = ""
    content: list[str] = Field(default_factory=list)
    enabled: bool = True
    proto: str = ""  # IPv4, IPv6
    update_freq: str = ""  # for urltable
    counters: bool = False
    categories: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# NAT / Port Forwards
# ============================================================================


class NormalizedNATRule(BaseModel):
    """Source NAT / outbound NAT rule."""

    uuid: str = ""
    enabled: bool = True
    nat_type: NATType = NATType.SOURCE
    interface: str = ""
    interface_name: str = ""
    protocol: str = "any"
    source_net: str = ""
    source_port: str = ""
    destination_net: str = ""
    destination_port: str = ""
    target: str = ""  # NAT target address
    target_port: str = ""
    description: str = ""
    log: bool = False
    sequence: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedPortForward(BaseModel):
    """Destination NAT / port forwarding rule."""

    uuid: str = ""
    enabled: bool = True
    interface: str = ""
    interface_name: str = ""
    protocol: str = "tcp"
    source_net: str = ""
    source_port: str = ""
    destination_net: str = ""
    destination_port: str = ""
    target_ip: str = ""
    target_port: str = ""
    description: str = ""
    log: bool = False
    associated_filter_rule: str = ""
    reflection: str = ""
    sequence: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# DHCP
# ============================================================================


class NormalizedDHCPLease(BaseModel):
    """Active DHCP lease."""

    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    description: str = ""
    interface: str = ""
    interface_name: str = ""
    status: DHCPLeaseStatus = DHCPLeaseStatus.ACTIVE
    starts: str | None = None
    ends: str | None = None
    binding_state: str = ""
    manufacturer: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedDHCPStaticMapping(BaseModel):
    """Static DHCP reservation."""

    uuid: str = ""
    mac_address: str = ""
    ip_address: str = ""
    hostname: str = ""
    description: str = ""
    interface: str = ""
    dns_server: str | None = None
    gateway: str | None = None
    domain: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedDHCPScope(BaseModel):
    """DHCP scope / subnet definition tied to an interface."""

    interface: str = ""
    enabled: bool = False
    range_start: str = ""
    range_end: str = ""
    gateway: str = ""
    domain_name: str = ""
    dns_servers: list[str] = Field(default_factory=list)
    ntp_servers: list[str] = Field(default_factory=list)
    default_lease_time: int | None = None
    max_lease_time: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# VLAN Interface
# ============================================================================


class NormalizedVlanInterface(BaseModel):
    """VLAN sub-interface on OPNsense."""

    uuid: str = ""
    device: str = ""
    parent: str = ""
    parent_label: str = ""
    tag: int = 0
    priority: int = 0
    proto: str = "802.1q"
    description: str = ""


# ============================================================================
# DNS (Unbound)
# ============================================================================


class NormalizedDNSOverride(BaseModel):
    """Unbound host override (local DNS record)."""

    uuid: str = ""
    hostname: str = ""
    domain: str = ""
    fqdn: str = ""
    record_type: str = "A"  # A, AAAA, MX
    server: str = ""  # target IP
    description: str = ""
    enabled: bool = True
    mx_priority: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedDNSDomainOverride(BaseModel):
    """Unbound domain override (DNS forwarding for a specific domain)."""

    uuid: str = ""
    domain: str = ""
    server: str = ""
    description: str = ""
    enabled: bool = True
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Gateways
# ============================================================================


class NormalizedGateway(BaseModel):
    """WAN gateway health and status."""

    name: str = ""
    address: str = ""
    status: GatewayStatus = GatewayStatus.UNKNOWN
    status_text: str = ""
    loss_pct: float = 0.0
    delay_ms: float = 0.0
    stddev_ms: float = 0.0
    interface: str = ""
    monitor_ip: str = ""
    default_gateway: bool = False
    weight: int = 1
    priority: int = 255
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# VPN – WireGuard
# ============================================================================


class NormalizedWireGuardServer(BaseModel):
    """WireGuard server (local endpoint)."""

    uuid: str = ""
    name: str = ""
    enabled: bool = True
    public_key: str = ""
    listen_port: int | None = None
    tunnel_address: str = ""  # e.g. "10.10.10.1/24"
    dns_servers: str = ""
    mtu: int | None = None
    peers: list[str] = Field(default_factory=list)  # list of peer UUIDs
    instance_id: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedWireGuardPeer(BaseModel):
    """WireGuard peer / client."""

    uuid: str = ""
    name: str = ""
    enabled: bool = True
    public_key: str = ""
    preshared_key: str = ""
    server_address: str = ""
    server_port: int | None = None
    tunnel_address: str = ""  # allowed IPs
    endpoint_address: str = ""
    endpoint_port: int | None = None
    keepalive: int | None = None
    last_handshake: str | None = None
    transfer_rx: int = 0
    transfer_tx: int = 0
    connected: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# VPN – OpenVPN
# ============================================================================


class NormalizedOpenVPNInstance(BaseModel):
    """OpenVPN server or client instance."""

    uuid: str = ""
    description: str = ""
    role: VPNRole = VPNRole.SERVER
    enabled: bool = True
    protocol: str = "udp"
    port: int | None = None
    dev_type: str = "tun"
    topology: str = ""
    tunnel_network: str = ""
    local_network: str = ""
    remote_network: str = ""
    server_address: str = ""
    vpn_id: str = ""
    status: VPNStatus = VPNStatus.DOWN
    connected_clients: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedOpenVPNClient(BaseModel):
    """A connected OpenVPN client session."""

    common_name: str = ""
    real_address: str = ""
    virtual_address: str = ""
    connected_since: str = ""
    bytes_received: int = 0
    bytes_sent: int = 0
    status: VPNStatus = VPNStatus.UP


# ============================================================================
# VPN – IPsec
# ============================================================================


class NormalizedIPsecTunnel(BaseModel):
    """IPsec tunnel (Phase 1 + Phase 2)."""

    uuid: str = ""
    description: str = ""
    enabled: bool = True
    phase: IPsecPhase = IPsecPhase.PHASE1
    remote_gateway: str = ""
    local_id: str = ""
    remote_id: str = ""
    local_network: str = ""
    remote_network: str = ""
    ike_version: str = ""
    authentication_method: str = ""
    encryption_algorithms: list[str] = Field(default_factory=list)
    hash_algorithms: list[str] = Field(default_factory=list)
    dh_groups: list[str] = Field(default_factory=list)
    lifetime: int | None = None
    status: VPNStatus = VPNStatus.DOWN
    connected: bool = False
    bytes_in: int = 0
    bytes_out: int = 0
    established_time: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Routing
# ============================================================================


class NormalizedStaticRoute(BaseModel):
    """Static route entry."""

    uuid: str = ""
    network: str = ""  # destination CIDR
    gateway: str = ""
    description: str = ""
    enabled: bool = True
    metric: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedRoutingTable(BaseModel):
    """Single entry from the kernel routing table."""

    destination: str = ""
    gateway: str = ""
    flags: str = ""
    interface: str = ""
    metric: int | None = None
    mtu: int | None = None
    protocol: str = ""
    type: str = ""


# ============================================================================
# ARP Table
# ============================================================================


class NormalizedARPEntry(BaseModel):
    """ARP table entry — cross-reference with Omada client MACs."""

    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    interface: str = ""
    interface_name: str = ""
    manufacturer: str | None = None
    expires: str | int | None = None
    permanent: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Services
# ============================================================================


class NormalizedService(BaseModel):
    """System service status."""

    name: str = ""
    description: str = ""
    status: ServiceStatus = ServiceStatus.UNKNOWN
    running: bool = False
    enabled: bool = True
    pid: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# IDS/IPS (Suricata)
# ============================================================================


class NormalizedIDSAlert(BaseModel):
    """Intrusion Detection/Prevention alert."""

    uuid: str = ""
    timestamp: str = ""
    severity: IDSAlertSeverity = IDSAlertSeverity.MEDIUM
    alert_sid: str = ""
    alert_msg: str = ""
    alert_category: str = ""
    source_ip: str = ""
    source_port: int | None = None
    destination_ip: str = ""
    destination_port: int | None = None
    protocol: str = ""
    interface: str = ""
    action: str = ""  # "allowed" or "blocked"
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedIDSRuleSet(BaseModel):
    """IDS/IPS installed rule set."""

    filename: str = ""
    description: str = ""
    enabled: bool = True


class NormalizedIDSSettings(BaseModel):
    """IDS/IPS global settings snapshot."""

    enabled: bool = False
    ips_mode: bool = False  # IPS (blocking) vs IDS (detect-only)
    interfaces: list[str] = Field(default_factory=list)
    pattern_matcher: str = ""
    default_packet_size: int | None = None
    promiscuous_mode: bool = False
    home_networks: list[str] = Field(default_factory=list)
    rule_sets: list[NormalizedIDSRuleSet] = Field(default_factory=list)


# ============================================================================
# Traffic Shaper / QoS
# ============================================================================


class NormalizedTrafficPipe(BaseModel):
    """Traffic shaper pipe (bandwidth limit)."""

    uuid: str = ""
    description: str = ""
    enabled: bool = True
    bandwidth: int | None = None  # Kbit/s
    bandwidth_metric: str = "Kbit"
    queue_size: int | None = None
    mask: str = ""  # "source", "destination", "none"
    delay_ms: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedTrafficQueue(BaseModel):
    """Traffic shaper queue (weight-based scheduling)."""

    uuid: str = ""
    description: str = ""
    enabled: bool = True
    pipe: str = ""
    weight: int | None = None
    mask: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class NormalizedTrafficRule(BaseModel):
    """Traffic shaper rule (assign traffic to pipe/queue)."""

    uuid: str = ""
    description: str = ""
    enabled: bool = True
    direction: TrafficShaperDirection = TrafficShaperDirection.BOTH
    interface: str = ""
    protocol: str = ""
    source: str = ""
    source_port: str = ""
    destination: str = ""
    destination_port: str = ""
    target_pipe: str = ""
    target_queue: str = ""
    sequence: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Logs / Events
# ============================================================================


class NormalizedLogEntry(BaseModel):
    """Generic log entry (system or firewall)."""

    timestamp: str = ""
    process: str = ""
    pid: str = ""
    message: str = ""
    severity: str = ""
    facility: str = ""


class NormalizedFirewallLogEntry(BaseModel):
    """Parsed firewall filter log entry."""

    timestamp: str = ""
    action: str = ""  # "pass", "block"
    direction: str = ""
    interface: str = ""
    protocol: str = ""
    source_ip: str = ""
    source_port: int | None = None
    destination_ip: str = ""
    destination_port: int | None = None
    rule_number: str = ""
    reason: str = ""
    label: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Traffic Statistics
# ============================================================================


class NormalizedTrafficTop(BaseModel):
    """Top-talker traffic entry."""

    address: str = ""
    rate_bits_in: int = 0
    rate_bits_out: int = 0
    cumulative_bytes_in: int = 0
    cumulative_bytes_out: int = 0


# ============================================================================
# Diagnostics
# ============================================================================


class NormalizedPingResult(BaseModel):
    """Ping diagnostic result."""

    target: str = ""
    packets_sent: int = 0
    packets_received: int = 0
    loss_pct: float = 0.0
    min_ms: float = 0.0
    avg_ms: float = 0.0
    max_ms: float = 0.0
    stddev_ms: float = 0.0
    raw_output: str = ""


class NormalizedTracerouteHop(BaseModel):
    """Single hop in a traceroute."""

    hop: int = 0
    host: str = ""
    ip_address: str = ""
    rtt_ms: float | None = None
    rtt2_ms: float | None = None
    rtt3_ms: float | None = None


class NormalizedDNSLookupResult(BaseModel):
    """DNS lookup result."""

    query: str = ""
    record_type: str = ""
    answers: list[str] = Field(default_factory=list)
    nameserver: str = ""
    response_time_ms: float | None = None


# ============================================================================
# Configuration Backup
# ============================================================================


class NormalizedBackupInfo(BaseModel):
    """Configuration backup metadata."""

    filename: str = ""
    timestamp: str = ""
    size_bytes: int = 0
    description: str = ""


# ============================================================================
# Aggregate / Dashboard
# ============================================================================


class NormalizedDeviceSummary(BaseModel):
    """
    High-level device summary for dashboard / cross-adapter views.

    Combines system info, interface state, gateway health, and service counts.
    """

    hostname: str = ""
    version: str = ""
    uptime: int | None = None
    uptime_text: str = ""
    cpu_usage_pct: float | None = None
    memory_usage_pct: float | None = None
    disk_usage_pct: float | None = None
    temperature_celsius: float | None = None
    interface_count: int = 0
    interfaces_up: int = 0
    interfaces_down: int = 0
    wan_status: GatewayStatus = GatewayStatus.UNKNOWN
    wan_ip: str = ""
    wan_gateway: str = ""
    wan_loss_pct: float = 0.0
    wan_delay_ms: float = 0.0
    firewall_rule_count: int = 0
    firewall_alias_count: int = 0
    dhcp_lease_count: int = 0
    arp_entry_count: int = 0
    services_running: int = 0
    services_stopped: int = 0
    vpn_tunnels_up: int = 0
    vpn_tunnels_total: int = 0
    firmware_update_available: bool = False
    ids_enabled: bool = False
    ids_alerts_24h: int = 0
