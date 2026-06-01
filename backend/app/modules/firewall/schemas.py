# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Firewall Gateway Schemas
========================================

Pydantic v2 schemas for the gateway integration API.
"""

import ipaddress
import re
import socket
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# ═══════════════════════════════════════════════════════════════════════════════
# Host Validation Utilities
# ═══════════════════════════════════════════════════════════════════════════════

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),  # "this" network
]

_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
}

_HOST_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)


def _addr_in_blocked_network(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if ``addr`` falls inside any SSRF-blocked network range.

    RFC1918 private ranges are intentionally NOT in ``_BLOCKED_NETWORKS`` —
    legitimate firewalls/gateways live on private LANs in nearly every
    deployment — so this only trips on loopback / link-local (cloud metadata) /
    unspecified, matching the controller-path policy in adapter_base.
    """
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _validate_host_ssrf(host: str) -> str:
    """Validate a host string is safe — blocks SSRF targets.

    For IP literals the address is checked directly against ``_BLOCKED_NETWORKS``.
    For hostnames we ALSO resolve the name and re-check every resolved address,
    so an attacker cannot smuggle a blocked target (e.g. a name pointing at the
    cloud-metadata IP ``169.254.169.254`` or this host's own loopback) past the
    literal-only check. Resolution failure is treated as non-fatal here (the name
    may legitimately resolve only via internal DNS that the API host can't reach
    at validation time); the live connection is additionally pinned to the
    resolved IP at connect time (``adapter_base._pin_controller_host``) to close
    the DNS-rebinding window.
    """
    host = host.strip()
    if not host:
        raise ValueError("host must not be empty")

    # Block dangerous hostnames
    if host.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(f"host '{host}' is not allowed")

    # Check if it's an IP address
    try:
        addr = ipaddress.ip_address(host)
        if _addr_in_blocked_network(addr):
            raise ValueError(f"host '{host}' resolves to a blocked network range")
        return host
    except ValueError as e:
        if "blocked network" in str(e):
            raise
        pass  # Not an IP, treat as hostname

    # Validate hostname format
    if not _HOST_RE.match(host):
        raise ValueError(f"host '{host}' is not a valid hostname or IP address")

    # Resolve the hostname and reject if ANY resolved address is in a blocked
    # range. This closes the gap where a hostname pointing at a blocked IP
    # (cloud metadata / loopback / link-local) bypassed the IP-literal check.
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, UnicodeError):
        # Unresolvable at validation time — do not reject; connect-time pinning
        # is the authoritative second check.
        return host
    for info in infos:
        sockaddr = info[4]
        ip_raw = sockaddr[0]
        if not isinstance(ip_raw, str):
            continue
        ip_str = ip_raw.split("%", 1)[0]  # strip IPv6 scope id
        try:
            resolved = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _addr_in_blocked_network(resolved):
            raise ValueError(f"host '{host}' resolves to a blocked network range ({ip_str})")

    return host


# Characters that are never legitimate in an IP/CIDR/network address field and
# indicate possible shell injection.
_UNSAFE_ADDR_RE = re.compile(r"[;`|$&!(){}\[\]<>'\"\\\x00-\x1f]")

# Loose allowlist: alphanumeric, dots, colons, slashes, dashes, underscores,
# plus the word "any".  This covers IPv4, IPv6, CIDR notation, and interface
# names used on some firewalls.
_SAFE_ADDR_RE = re.compile(r"^[a-zA-Z0-9.:/_-]+$")


# SECURITY (write-path audit, CRITICAL): the free-form ``settings`` dict is
# splatted into the vendor adapter constructor (GatewayService._build_adapter),
# and the firewall adapters read ``direct_write_force`` from their kwargs to
# bypass the ADAPTER_READ_ONLY safety gate. An operator must never be able to set
# that (or any write-gate control) via settings, so these keys are stripped here
# (every settings validator funnels through this) and again at the constructor
# chokepoint. The staged applier sets force itself, in-window.
FORBIDDEN_ADAPTER_SETTINGS = frozenset(
    {
        "direct_write_force",
        "force",
        "read_only",
        "adapter_read_only",
    }
)


def _validate_settings_size(v: dict[str, Any] | None) -> dict[str, Any] | None:
    """Cap free-form ``settings`` JSONB at 32 KiB / 256 keys and strip adapter
    write-gate control keys (see FORBIDDEN_ADAPTER_SETTINGS).

    Gateway / VPN / IDS schemas all expose ``settings: dict[str, Any]``
    to carry vendor-specific knobs. Without caps an admin could stash
    a multi-MB blob that's reloaded on every gateway sync.
    """
    if v is None:
        return v
    v = {k: val for k, val in v.items() if str(k).lower() not in FORBIDDEN_ADAPTER_SETTINGS}
    if len(v) > 256:
        raise ValueError("settings must contain at most 256 keys")
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > 32 * 1024:
        raise ValueError(f"settings exceeds 32768 bytes (got {size})")
    return v


def _validate_network_address(v: str | None) -> str | None:
    """Validate a firewall network/address field is safe.

    Accepts IPv4, IPv6, CIDR notation, or the keyword "any".
    Rejects values containing shell-injection characters.
    """
    if v is None:
        return v
    v = v.strip()
    if not v:
        return v
    # Cap to keep DoS-shaped payloads out of vendor adapter calls.
    # Real IPv6 + CIDR is < 50 chars; 128 is comfortable headroom.
    if len(v) > 128:
        raise ValueError(f"address too long (max 128 chars): {v[:40]}...")
    if _UNSAFE_ADDR_RE.search(v):
        raise ValueError(f"address contains forbidden characters: {v!r}")
    if not _SAFE_ADDR_RE.match(v):
        raise ValueError(f"address contains invalid characters: {v!r}")
    return v


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Connection
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayConnectionCreate(BaseModel):
    """Create a new gateway connection."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    vendor: str = Field(..., pattern=r"^(opnsense|pfsense|mikrotik|openwrt)$")
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(default=443, ge=1, le=65535)
    verify_ssl: bool = False
    site_id: UUID | None = None

    # Credentials
    api_key: str | None = Field(default=None, min_length=1)  # opnsense / pfsense
    api_secret: str | None = Field(default=None, min_length=1)  # opnsense / pfsense
    username: str | None = Field(default=None, min_length=1)  # mikrotik / openwrt
    password: str | None = Field(default=None, min_length=1)  # mikrotik / openwrt

    # Sync
    sync_enabled: bool = True
    sync_interval_seconds: int = Field(default=300, ge=30, le=86400)
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("vendor")
    @classmethod
    def validate_vendor(cls, v: str) -> str:
        if v not in ("opnsense", "pfsense", "mikrotik", "openwrt"):
            raise ValueError("vendor must be opnsense, pfsense, mikrotik, or openwrt")
        return v

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host_ssrf(v)

    @field_validator("settings")
    @classmethod
    def _v_settings(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_settings_size(v) or {}


class GatewayPreflightRequest(BaseModel):
    """Describe a prospective staged write to assess BEFORE staging it.

    No mutation and (currently) no device call — the assessor classifies the
    operation's destructiveness so an operator can see whether it will require
    ``confirmed=true`` at apply time.
    """

    feature: str = Field(..., max_length=128, description="e.g. opnsense.firewall.rule")
    operation: str = Field("create", max_length=32, description="create | update | delete")
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="The change payload the staged write would carry (target_id, etc.)",
    )


class GatewayPreflightResponse(BaseModel):
    feature: str
    operation: str
    risk: str = Field(..., description="safe | destructive | catastrophic")
    requires_confirmation: bool = Field(
        ..., description="True => the staged change must carry confirmed=true to apply"
    )
    warnings: list[str] = []
    impact: dict[str, Any] = {}


class GatewayConnectionUpdate(BaseModel):
    """Partial update of a gateway connection."""

    name: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    host: str | None = Field(default=None, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    verify_ssl: bool | None = None
    site_id: UUID | None = None

    # Credential updates (optional). Caps match the credentials baseline.
    api_key: str | None = Field(default=None, max_length=512)
    api_secret: str | None = Field(default=None, max_length=16384)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=16384)

    # Sync
    sync_enabled: bool | None = None
    sync_interval_seconds: int | None = Field(default=None, ge=30, le=86400)
    settings: dict[str, Any] | None = None

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str | None) -> str | None:
        if v is not None:
            return _validate_host_ssrf(v)
        return v

    @field_validator("settings")
    @classmethod
    def _v_settings(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_settings_size(v)


class GatewayConnectionResponse(BaseModel):
    """Public representation of a gateway connection."""

    id: UUID
    org_id: UUID
    site_id: UUID | None
    device_id: UUID | None

    name: str
    description: str | None
    vendor: str
    host: str
    port: int
    verify_ssl: bool

    # Never expose raw credentials
    has_credentials: bool = True

    sync_enabled: bool
    sync_interval_seconds: int
    sync_status: str
    last_sync_at: datetime | None
    last_sync_error: str | None
    last_sync_duration_ms: int | None

    is_online: bool
    last_seen_at: datetime | None

    detected_version: str | None
    detected_hostname: str | None
    detected_model: str | None
    capabilities: list[str]

    settings: dict[str, Any]

    created_at: datetime
    updated_at: datetime | None

    class Config:
        from_attributes = True


class GatewayConnectionListResponse(BaseModel):
    """Paginated list of gateway connections."""

    items: list[GatewayConnectionResponse]
    total: int


# ═══════════════════════════════════════════════════════════════════════════════
# Connection Test
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayTestRequest(BaseModel):
    """Test connection without persisting."""

    vendor: str = Field(..., pattern=r"^(opnsense|pfsense|mikrotik|openwrt)$")
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(default=443, ge=1, le=65535)
    verify_ssl: bool = False

    api_key: str | None = Field(default=None, min_length=1)
    api_secret: str | None = Field(default=None, min_length=1)
    username: str | None = Field(default=None, min_length=1)
    password: str | None = Field(default=None, min_length=1)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host_ssrf(v)


class GatewayTestOverride(BaseModel):
    """Optional overrides for testing an ALREADY-SAVED gateway against its
    stored credentials. ONLY ``verify_ssl`` may be overridden — the test always
    connects to the gateway's STORED host/port. (a host/port
    override would replay the decrypted stored credentials to a caller-chosen
    destination, letting a low-priv viewer exfiltrate the firewall's admin
    secrets. To test an edited host/port before saving, use the unsaved
    POST /gateways/test endpoint, which is firewall.manage_rules-gated and
    requires the caller to re-supply credentials.)
    """

    verify_ssl: bool | None = None


class GatewayTestResponse(BaseModel):
    """Result of a connection test."""

    success: bool
    message: str
    vendor: str | None = None
    hostname: str | None = None
    version: str | None = None
    model: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    latency_ms: int | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# Sync
# ═══════════════════════════════════════════════════════════════════════════════


class GatewaySyncRequest(BaseModel):
    """Trigger a manual sync."""

    full_sync: bool = False  # if True, re-pull everything


class GatewaySyncLogResponse(BaseModel):
    """Single sync log entry."""

    id: UUID
    gateway_id: UUID
    started_at: datetime
    finished_at: datetime | None
    duration_ms: int | None
    status: str
    error: str | None
    items_synced: int
    items_failed: int
    details: dict[str, Any]

    class Config:
        from_attributes = True


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Status / Dashboard
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayStatusResponse(BaseModel):
    """Live status pulled from the gateway."""

    gateway_id: UUID
    vendor: str
    is_online: bool
    system: dict[str, Any] = Field(default_factory=dict)
    interfaces: dict[str, Any] | list[Any] = Field(default_factory=dict)
    gateways: dict[str, Any] | list[Any] = Field(default_factory=dict)
    services: dict[str, Any] | list[Any] = Field(default_factory=dict)
    uptime: str | None = None
    cpu_load: float | None = None
    memory_usage_pct: float | None = None


class GatewayFirewallRulesResponse(BaseModel):
    """Firewall rules pulled from the gateway."""

    gateway_id: UUID
    vendor: str
    rules: list[dict[str, Any]]
    total: int


class GatewayNATRulesResponse(BaseModel):
    """NAT rules from the gateway."""

    gateway_id: UUID
    vendor: str
    rules: list[dict[str, Any]]
    total: int


class GatewayVPNStatusResponse(BaseModel):
    """VPN status from the gateway."""

    gateway_id: UUID
    vendor: str
    tunnels: dict[str, Any]


class GatewayDHCPResponse(BaseModel):
    """DHCP leases from the gateway."""

    gateway_id: UUID
    vendor: str
    leases: list[dict[str, Any]]
    total: int


class GatewayDNSResponse(BaseModel):
    """DNS entries from the gateway."""

    gateway_id: UUID
    vendor: str
    entries: list[dict[str, Any]] | dict[str, Any]


class GatewayServicesResponse(BaseModel):
    """Services from the gateway."""

    gateway_id: UUID
    vendor: str
    services: list[dict[str, Any]] | dict[str, Any]


class GatewayInterfacesResponse(BaseModel):
    """Interfaces from the gateway."""

    gateway_id: UUID
    vendor: str
    interfaces: list[dict[str, Any]] | dict[str, Any]
    statistics: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Push (Tier A)
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayRulePushRequest(BaseModel):
    """Push a firewall rule to the gateway."""

    action: str = Field(..., pattern=r"^(allow|deny|reject|pass|block)$")
    protocol: str = Field(default="any")
    source_address: str | None = None
    source_port: str | None = None
    dest_address: str | None = None
    dest_port: str | None = None
    description: str | None = None
    enabled: bool = True
    log: bool = False
    interface: str | None = None  # pfSense / OPNsense interface name
    chain: str | None = None  # MikroTik chain (input/forward/output)

    @field_validator("source_address", "dest_address")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)


class GatewayRulePushResponse(BaseModel):
    """Result of pushing a rule."""

    success: bool
    message: str
    vendor_rule_id: str | None = None  # UUID for OPNsense, int for pfSense, *id for MikroTik
    applied: bool = False  # whether changes were auto-applied


# ═══════════════════════════════════════════════════════════════════════════════
# Summary / Stats
# ═══════════════════════════════════════════════════════════════════════════════


class GatewaySummaryResponse(BaseModel):
    """Summary stats across all gateways."""

    total_gateways: int
    online: int
    offline: int
    sync_success: int
    sync_failed: int
    sync_idle: int = 0
    sync_never: int = 0
    by_vendor: dict[str, int] = Field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# Firewall Rule Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class FirewallRuleCreate(BaseModel):
    """Create a firewall rule."""

    device_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    # description gets propagated into the vendor's rule comment field
    # on push; 2000 chars is plenty without filling vendor UIs.
    description: str | None = Field(default=None, max_length=2000)
    rule_order: int = Field(default=100, ge=0, le=100_000)
    source_address: str | None = None
    # Port specs (e.g. "8080" / "1024-2000" / "any") never legitimately
    # exceed 64 chars.
    source_port: str | None = Field(default=None, max_length=64)
    dest_address: str | None = None
    dest_port: str | None = Field(default=None, max_length=64)
    source_zone: str | None = Field(default=None, max_length=64)
    dest_zone: str | None = Field(default=None, max_length=64)
    protocol: str = Field(default="any", max_length=16)
    action: str = Field(..., pattern=r"^(allow|deny|reject|log)$")
    is_enabled: bool = True
    log_enabled: bool = False

    @field_validator("source_address", "dest_address")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)


class FirewallRuleUpdate(BaseModel):
    """Update a firewall rule (partial)."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    rule_order: int | None = Field(default=None, ge=0, le=100_000)
    source_address: str | None = None
    source_port: str | None = Field(default=None, max_length=64)
    dest_address: str | None = None
    dest_port: str | None = Field(default=None, max_length=64)
    source_zone: str | None = Field(default=None, max_length=64)
    dest_zone: str | None = Field(default=None, max_length=64)
    protocol: str | None = Field(default=None, max_length=16)
    action: str | None = Field(default=None, pattern=r"^(allow|deny|reject|log)$")
    is_enabled: bool | None = None
    log_enabled: bool | None = None

    @field_validator("source_address", "dest_address")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)


class FirewallRuleResponse(BaseModel):
    """Firewall rule response."""

    model_config = {"from_attributes": True}

    id: UUID
    device_id: UUID
    name: str
    description: str | None = None
    rule_order: int = 0
    source_address: str | None = None
    source_port: str | None = None
    dest_address: str | None = None
    dest_port: str | None = None
    source_zone: str | None = None
    dest_zone: str | None = None
    protocol: str = "any"
    action: str
    is_enabled: bool = True
    hit_count: int = 0
    log_enabled: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FirewallRuleListResponse(BaseModel):
    """Paginated firewall rule list."""

    items: list[FirewallRuleResponse]
    total: int


# ═══════════════════════════════════════════════════════════════════════════════
# NAT Rule Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class NATRuleCreate(BaseModel):
    """Create a NAT rule."""

    device_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    nat_type: str = Field(..., pattern=r"^(snat|dnat|masquerade|redirect)$")
    original_address: str | None = None
    original_port: str | None = Field(default=None, max_length=64)
    translated_address: str | None = None
    translated_port: str | None = Field(default=None, max_length=64)
    protocol: str = Field(default="tcp", max_length=16)
    # Interface names are short (eth0 / ge-0/0/0 / lan); 64 is generous.
    interface: str | None = Field(default=None, max_length=64)
    is_enabled: bool = True

    @field_validator("original_address", "translated_address")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)


class NATRuleUpdate(BaseModel):
    """Update a NAT rule (partial)."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    nat_type: str | None = Field(default=None, pattern=r"^(snat|dnat|masquerade|redirect)$")
    original_address: str | None = None
    original_port: str | None = Field(default=None, max_length=64)
    translated_address: str | None = None
    translated_port: str | None = Field(default=None, max_length=64)
    protocol: str | None = Field(default=None, max_length=16)
    interface: str | None = Field(default=None, max_length=64)
    is_enabled: bool | None = None

    @field_validator("original_address", "translated_address")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)


class NATRuleResponse(BaseModel):
    """NAT rule response."""

    model_config = {"from_attributes": True}

    id: UUID
    device_id: UUID
    name: str
    description: str | None = None
    nat_type: str
    original_address: str | None = None
    original_port: str | None = None
    translated_address: str | None = None
    translated_port: str | None = None
    protocol: str = "tcp"
    interface: str | None = None
    is_enabled: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None


class NATRuleListResponse(BaseModel):
    """Paginated NAT rule list."""

    items: list[NATRuleResponse]
    total: int


# ═══════════════════════════════════════════════════════════════════════════════
# VPN Tunnel Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class VPNTunnelCreate(BaseModel):
    """Create a VPN tunnel."""

    device_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    vpn_type: str = Field(..., pattern=r"^(ipsec|openvpn|wireguard|l2tp)$")
    remote_address: str | None = None
    # IDs are short identifiers (FQDN / keyid / email-style)
    remote_id: str | None = Field(default=None, max_length=255)
    local_address: str | None = None
    local_id: str | None = Field(default=None, max_length=255)
    # Cap subnet lists to a realistic count (a few dozen at most for
    # large VPN policies; 64 leaves headroom).
    local_subnets: list[str] = Field(default_factory=list, max_length=64)
    remote_subnets: list[str] = Field(default_factory=list, max_length=64)
    auth_type: str = Field(default="psk", max_length=32)
    status: str = Field(default="down", max_length=32)
    is_enabled: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("remote_address", "local_address")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)

    @field_validator("local_subnets", "remote_subnets")
    @classmethod
    def validate_subnets(cls, v: list[str]) -> list[str]:
        for item in v:
            _validate_network_address(item)
        return v

    @field_validator("settings")
    @classmethod
    def _v_settings(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_settings_size(v) or {}


class VPNTunnelUpdate(BaseModel):
    """Update a VPN tunnel (partial)."""

    name: str | None = None
    description: str | None = None
    vpn_type: str | None = None
    remote_address: str | None = None
    remote_id: str | None = None
    local_address: str | None = None
    local_id: str | None = None
    local_subnets: list[str] | None = None
    remote_subnets: list[str] | None = None
    auth_type: str | None = None
    status: str | None = None
    is_enabled: bool | None = None
    settings: dict[str, Any] | None = None

    @field_validator("remote_address", "local_address")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)

    @field_validator("local_subnets", "remote_subnets")
    @classmethod
    def validate_subnets(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            for item in v:
                _validate_network_address(item)
        return v


class VPNTunnelResponse(BaseModel):
    """VPN tunnel response."""

    model_config = {"from_attributes": True}

    id: UUID
    device_id: UUID
    name: str
    description: str | None = None
    vpn_type: str
    remote_address: str | None = None
    remote_id: str | None = None
    local_address: str | None = None
    local_id: str | None = None
    local_subnets: list[Any] = Field(default_factory=list)
    remote_subnets: list[Any] = Field(default_factory=list)
    auth_type: str = "psk"
    status: str = "down"
    is_enabled: bool = True
    last_connected: datetime | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    settings: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None


class VPNTunnelListResponse(BaseModel):
    """Paginated VPN tunnel list."""

    items: list[VPNTunnelResponse]
    total: int


# ═══════════════════════════════════════════════════════════════════════════════
# IDS Alert Response
# ═══════════════════════════════════════════════════════════════════════════════


class IDSAlertResponse(BaseModel):
    """IDS/IPS alert response."""

    model_config = {"from_attributes": True}

    id: UUID
    device_id: UUID | None = None
    signature_id: str | None = None
    signature_name: str
    category: str | None = None
    severity: str
    timestamp: datetime
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    action_taken: str | None = None
    description: str | None = None
    is_acknowledged: bool = False
    acknowledged_by: UUID | None = None
    acknowledged_at: datetime | None = None


class IDSAlertListResponse(BaseModel):
    """Paginated IDS alert list."""

    items: list[IDSAlertResponse]
    total: int


class IDSAlertStatsResponse(BaseModel):
    """IDS alert statistics."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unacknowledged: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Firewall Log Response
# ═══════════════════════════════════════════════════════════════════════════════


class FirewallLogResponse(BaseModel):
    """Firewall log entry response."""

    model_config = {"from_attributes": True}

    id: UUID
    device_id: UUID | None = None
    rule_id: UUID | None = None
    timestamp: datetime
    source_ip: str | None = None
    source_port: int | None = None
    source_zone: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    dest_zone: str | None = None
    protocol: str | None = None
    action: str
    bytes_sent: int | None = None
    bytes_received: int | None = None
    application: str | None = None


class FirewallLogListResponse(BaseModel):
    """Paginated firewall log list."""

    items: list[FirewallLogResponse]
    total: int


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — DNS
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayDNSOverridesResponse(BaseModel):
    """DNS host overrides from the gateway."""

    gateway_id: UUID
    vendor: str
    overrides: list[dict[str, Any]]
    count: int = 0


class GatewayDNSDomainOverridesResponse(BaseModel):
    """DNS domain overrides from the gateway."""

    gateway_id: UUID
    vendor: str
    domain_overrides: list[dict[str, Any]]
    count: int = 0


class DNSOverrideRequest(BaseModel):
    """Create/update a DNS host override."""

    hostname: str = Field(..., min_length=1, max_length=255)
    domain: str = Field(..., min_length=1, max_length=255)
    server: str = Field(..., min_length=1)
    description: str | None = None
    enabled: bool = True


class DNSDomainOverrideRequest(BaseModel):
    """Create/update a DNS domain override."""

    domain: str = Field(..., min_length=1, max_length=255)
    server: str = Field(..., min_length=1)
    description: str | None = None
    enabled: bool = True


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — DHCP static mappings
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayDHCPStaticMappingsResponse(BaseModel):
    """DHCP static mappings from the gateway."""

    gateway_id: UUID
    vendor: str
    static_mappings: list[dict[str, Any]]
    count: int = 0


class DHCPStaticMappingRequest(BaseModel):
    """Create/update a DHCP static mapping."""

    mac_address: str = Field(..., min_length=1, max_length=17)
    ip_address: str = Field(..., min_length=1)
    hostname: str | None = None
    description: str | None = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        result = _validate_network_address(v)
        assert result is not None
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Port Forwards (DNAT)
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayPortForwardsResponse(BaseModel):
    """Port forward rules from the gateway."""

    gateway_id: UUID
    vendor: str
    port_forwards: list[dict[str, Any]]
    count: int = 0


class PortForwardRequest(BaseModel):
    """Create/update a port forward rule."""

    interface: str = "wan"
    protocol: str = "tcp"
    source_net: str | None = None
    source_port: str | None = None
    destination_port: str = Field(..., min_length=1)
    target_ip: str = Field(..., min_length=1)
    target_port: str = Field(..., min_length=1)
    description: str | None = None
    enabled: bool = True
    log: bool = False

    @field_validator("target_ip", "source_net")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Source NAT
# ═══════════════════════════════════════════════════════════════════════════════


class SourceNATRuleRequest(BaseModel):
    """Create/update a source NAT rule."""

    interface: str = "wan"
    protocol: str = "any"
    source_net: str | None = None
    source_port: str | None = None
    destination_net: str | None = None
    destination_port: str | None = None
    target: str = ""
    description: str | None = None
    enabled: bool = True

    @field_validator("source_net", "destination_net", "target")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Aliases
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayAliasesResponse(BaseModel):
    """Firewall aliases from the gateway."""

    gateway_id: UUID
    vendor: str
    aliases: list[dict[str, Any]]
    count: int = 0


class AliasRequest(BaseModel):
    """Create/update a firewall alias."""

    name: str = Field(..., min_length=1, max_length=255)
    alias_type: str = "host"
    content: list[str] = Field(default_factory=list)
    description: str | None = None
    enabled: bool = True
    proto: str | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — WireGuard
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayWireGuardResponse(BaseModel):
    """WireGuard status from the gateway."""

    gateway_id: UUID
    vendor: str
    servers: list[dict[str, Any]] = Field(default_factory=list)
    peers: list[dict[str, Any]] = Field(default_factory=list)
    handshakes: dict[str, Any] | list[Any] = Field(default_factory=dict)
    count: int = 0


class WireGuardServerRequest(BaseModel):
    """Create/update a WireGuard server."""

    name: str = Field(..., min_length=1, max_length=255)
    listen_port: int = Field(default=51820, ge=1, le=65535)
    tunnel_address: str = ""
    dns_servers: str | None = None
    enabled: bool = True

    @field_validator("tunnel_address")
    @classmethod
    def validate_tunnel_address(cls, v: str | None) -> str | None:
        return _validate_network_address(v)


class WireGuardPeerRequest(BaseModel):
    """Create/update a WireGuard peer."""

    name: str = Field(..., min_length=1, max_length=255)
    public_key: str = ""
    tunnel_address: str = ""
    endpoint_address: str | None = None
    endpoint_port: int | None = Field(default=None, ge=1, le=65535)
    keepalive: int | None = None
    preshared_key: str | None = None
    enabled: bool = True

    @field_validator("tunnel_address", "endpoint_address")
    @classmethod
    def validate_addresses(cls, v: str | None) -> str | None:
        return _validate_network_address(v)


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — OpenVPN
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayOpenVPNResponse(BaseModel):
    """OpenVPN status from the gateway."""

    gateway_id: UUID
    vendor: str
    instances: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    sessions: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)


class OpenVPNInstanceRequest(BaseModel):
    """Create/update an OpenVPN instance."""

    description: str = ""
    role: str = "server"
    protocol: str = "udp"
    port: int | None = Field(default=None, ge=1, le=65535)
    dev_type: str = "tun"
    enabled: bool = True


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — IPsec
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayIPsecResponse(BaseModel):
    """IPsec status from the gateway."""

    gateway_id: UUID
    vendor: str
    phase1: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    phase2: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    sad: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    spd: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Static Routes
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayStaticRoutesResponse(BaseModel):
    """Static routes from the gateway."""

    gateway_id: UUID
    vendor: str
    routes: list[dict[str, Any]]
    count: int = 0


class GatewayRoutingTableResponse(BaseModel):
    """Kernel routing table from the gateway."""

    gateway_id: UUID
    vendor: str
    routing_table: list[dict[str, Any]]
    count: int = 0


class StaticRouteRequest(BaseModel):
    """Create/update a static route."""

    network: str = Field(..., min_length=1)
    gateway: str = Field(..., min_length=1)
    description: str | None = None
    enabled: bool = True

    @field_validator("network", "gateway")
    @classmethod
    def validate_addresses(cls, v: str) -> str:
        result = _validate_network_address(v)
        assert result is not None  # these are required fields
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — ARP
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayARPResponse(BaseModel):
    """ARP table from the gateway."""

    gateway_id: UUID
    vendor: str
    arp_entries: list[dict[str, Any]]
    count: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Gateways (WAN health)
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayHealthResponse(BaseModel):
    """WAN gateway health from the device."""

    gateway_id: UUID
    vendor: str
    gateways: list[dict[str, Any]]
    count: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — IDS/IPS
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayIDSSettingsResponse(BaseModel):
    """IDS/IPS settings from the gateway."""

    gateway_id: UUID
    vendor: str
    enabled: bool = False
    ips_mode: bool = False
    interfaces: list[str] = Field(default_factory=list)
    settings: dict[str, Any] = Field(default_factory=dict)


class GatewayIDSAlertsResponse(BaseModel):
    """IDS/IPS alerts from the gateway."""

    gateway_id: UUID
    vendor: str
    alerts: list[dict[str, Any]]
    count: int = 0


class IDSSettingsUpdateRequest(BaseModel):
    """Update IDS settings on the gateway."""

    enabled: bool | None = None
    ips_mode: bool | None = None
    # 64 interface entries is well above any realistic firewall.
    interfaces: list[str] | None = Field(default=None, max_length=64)
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("interfaces")
    @classmethod
    def _v_ifaces(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for s in v:
            if not isinstance(s, str) or len(s) > 64:
                raise ValueError("interface names must be strings <= 64 chars")
        return v

    @field_validator("settings")
    @classmethod
    def _v_settings(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_settings_size(v) or {}


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Traffic Shaper
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayShaperPipesResponse(BaseModel):
    """Traffic shaper pipes from the gateway."""

    gateway_id: UUID
    vendor: str
    pipes: list[dict[str, Any]]
    count: int = 0


class ShaperPipeRequest(BaseModel):
    """Create/update a traffic shaper pipe."""

    bandwidth: int = Field(..., ge=1)
    bandwidth_metric: Literal["Kbit", "Mbit", "Gbit"] = "Kbit"
    description: str | None = None
    mask: str = "none"
    delay_ms: int | None = None
    enabled: bool = True


class GatewayShaperQueuesResponse(BaseModel):
    """Traffic shaper queues from the gateway."""

    gateway_id: UUID
    vendor: str
    queues: list[dict[str, Any]]
    count: int = 0


class GatewayShaperRulesResponse(BaseModel):
    """Traffic shaper rules from the gateway."""

    gateway_id: UUID
    vendor: str
    rules: list[dict[str, Any]]
    count: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Backups
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayBackupsResponse(BaseModel):
    """Configuration backups from the gateway."""

    gateway_id: UUID
    vendor: str
    backups: list[dict[str, Any]]
    count: int = 0


class BackupRevertRequest(BaseModel):
    """Revert to a named backup configuration."""

    filename: str = Field(
        ...,
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9_.\-]+$",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Diagnostics
# ═══════════════════════════════════════════════════════════════════════════════


class DiagnosticPingRequest(BaseModel):
    """Ping diagnostic request."""

    host: str = Field(..., min_length=1)
    count: int = Field(default=3, ge=1, le=20)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host_ssrf(v)


class DiagnosticTracerouteRequest(BaseModel):
    """Traceroute diagnostic request."""

    host: str = Field(..., min_length=1)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host_ssrf(v)


class DiagnosticDNSLookupRequest(BaseModel):
    """DNS lookup diagnostic request."""

    hostname: str = Field(..., min_length=1)

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        return _validate_host_ssrf(v)


class GatewayDiagnosticResponse(BaseModel):
    """Generic diagnostic response."""

    gateway_id: UUID
    vendor: str
    result: dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Firmware
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayFirmwareResponse(BaseModel):
    """Firmware info from the gateway."""

    gateway_id: UUID
    vendor: str
    firmware: dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Logs
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayLogsResponse(BaseModel):
    """Logs from the gateway."""

    gateway_id: UUID
    vendor: str
    logs: list[dict[str, Any]] | dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Device Summary / Dashboard
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayDeviceSummaryResponse(BaseModel):
    """Aggregate device summary from the gateway."""

    gateway_id: UUID
    vendor: str
    summary: dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway — Service control
# ═══════════════════════════════════════════════════════════════════════════════


class ServiceControlRequest(BaseModel):
    """Control a service on the gateway."""

    action: str = Field(..., pattern=r"^(start|stop|restart)$")


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway — Generic write response
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayWriteResponse(BaseModel):
    """Generic result of a write / mutating operation on the gateway."""

    success: bool
    message: str = ""
    vendor_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Firmware extras
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayFirmwareChangelogResponse(BaseModel):
    """Firmware changelog from the gateway."""

    gateway_id: UUID
    vendor: str
    changelog: dict[str, Any]


class GatewayFirmwareCheckResponse(BaseModel):
    """Firmware update check result."""

    gateway_id: UUID
    vendor: str
    result: dict[str, Any]


class GatewayFirmwareUpgradeStatusResponse(BaseModel):
    """Firmware upgrade progress."""

    gateway_id: UUID
    vendor: str
    result: dict[str, Any]


class GatewayPackagesResponse(BaseModel):
    """Installed packages list from the gateway."""

    gateway_id: UUID
    vendor: str
    packages: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class GatewayPluginsResponse(BaseModel):
    """Installed plugins list from the gateway."""

    gateway_id: UUID
    vendor: str
    plugins: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Config download
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayConfigDownloadResponse(BaseModel):
    """Running config download from the gateway."""

    gateway_id: UUID
    vendor: str
    config: dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Interfaces extras (NDP, VIPs)
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayNDPResponse(BaseModel):
    """NDP (IPv6 neighbour) table."""

    gateway_id: UUID
    vendor: str
    ndp_entries: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class GatewayVIPResponse(BaseModel):
    """Virtual IP (CARP/IP Alias/Proxy ARP) status."""

    gateway_id: UUID
    vendor: str
    virtual_ips: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — DNS extras (Unbound status)
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayUnboundStatusResponse(BaseModel):
    """Unbound DNS resolver status."""

    gateway_id: UUID
    vendor: str
    status: dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — VPN extras (handshakes, sessions, IPsec status)
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayWireGuardHandshakesResponse(BaseModel):
    """WireGuard current handshake info."""

    gateway_id: UUID
    vendor: str
    handshakes: list[dict[str, Any]] = Field(default_factory=list)


class GatewayOpenVPNSessionsResponse(BaseModel):
    """OpenVPN active sessions."""

    gateway_id: UUID
    vendor: str
    sessions: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class GatewayIPsecStatusResponse(BaseModel):
    """IPsec service status (SA / SPD)."""

    gateway_id: UUID
    vendor: str
    status: dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — IDS/IPS extras (rulesets, rules, status, control)
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayIDSRulesetsResponse(BaseModel):
    """IDS rulesets listing."""

    gateway_id: UUID
    vendor: str
    rulesets: list[dict[str, Any]] = Field(default_factory=list)


class GatewayIDSRulesResponse(BaseModel):
    """IDS individual rules listing."""

    gateway_id: UUID
    vendor: str
    rules: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class GatewayIDSStatusResponse(BaseModel):
    """IDS service status."""

    gateway_id: UUID
    vendor: str
    status: dict[str, Any]


class IDSControlRequest(BaseModel):
    """Control the IDS service."""

    action: str = Field(..., pattern=r"^(start|stop|restart|update-rules)$")


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Shaper CRUD request schemas
# ═══════════════════════════════════════════════════════════════════════════════


class ShaperQueueRequest(BaseModel):
    """Create or update a traffic shaper queue."""

    description: str = ""
    pipe: str = ""
    weight: int = 100
    mask: str = ""
    enabled: bool = True


class ShaperRuleRequest(BaseModel):
    """Create or update a traffic shaper rule."""

    description: str = ""
    sequence: int = 1
    interface: str = ""
    protocol: str = ""
    source: str = "any"
    destination: str = "any"
    target_pipe: str = ""
    target_queue: str = ""
    direction: str = ""
    enabled: bool = True


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — Diagnostics extras (connections, PF, temperature, disk, traffic)
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayConnectionsResponse(BaseModel):
    """Active PF state connections."""

    gateway_id: UUID
    vendor: str
    connections: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


class GatewayPFInfoResponse(BaseModel):
    """PF filter info."""

    gateway_id: UUID
    vendor: str
    pf_info: dict[str, Any]


class GatewayPFStatisticsResponse(BaseModel):
    """PF statistics."""

    gateway_id: UUID
    vendor: str
    pf_statistics: dict[str, Any]


class GatewayTemperatureResponse(BaseModel):
    """Hardware temperature readings."""

    gateway_id: UUID
    vendor: str
    temperature: dict[str, Any]


class GatewayDiskUsageResponse(BaseModel):
    """Disk usage info."""

    gateway_id: UUID
    vendor: str
    disk_usage: dict[str, Any]


class GatewayTrafficStatsResponse(BaseModel):
    """Traffic statistics."""

    gateway_id: UUID
    vendor: str
    traffic: dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway Live — System extras (cron)
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayCronJobsResponse(BaseModel):
    """Cron jobs on the gateway."""

    gateway_id: UUID
    vendor: str
    cron_jobs: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Gateway — Deep health check
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayHealthCheckResponse(BaseModel):
    """Deep health check combining multiple adapter subsystems."""

    gateway_id: UUID
    vendor: str
    health: dict[str, Any]
    healthy: bool
