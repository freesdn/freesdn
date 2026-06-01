# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Discovery Pydantic Schemas
==========================================

Request/Response schemas for network discovery, scanning,
fingerprinting, and driver matching.
"""

import ipaddress
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# CIDR size limits
# ---------------------------------------------------------------------------
# A user requesting a scan of ``0.0.0.0/0`` would force the backend to
# materialize ~4 billion addresses, OOM-ing the worker and wedging the
# event loop. Cap scans at /16 for IPv4 (65 536 hosts) and /112 for IPv6.
MAX_SCAN_HOSTS_IPV4 = 65536  # /16
MAX_SCAN_HOSTS_IPV6 = 65536  # /112

# per-target caps alone are insufficient. With ``targets`` capped
# at 256 entries and each /16, a request could still queue 16.7M hosts and
# DoS the scanner. Cap the total host count across *all* targets at 262 144
# (= 4 × /16). This is enough for multi-subnet enterprise scans but makes
# the worst case bounded and memory-safe.
MAX_SCAN_HOSTS_TOTAL = 262_144


# SSRF egress block for scan targets. Unlike the generic safe_http_request
# blocklist, scanning RFC1918 is the WHOLE POINT (on-prem gear), so is_private
# is intentionally NOT blocked here. But loopback / link-local (incl. cloud
# metadata 169.254.169.254) / multicast / reserved / unspecified must be
# refused, matching what the sibling /discovery/fingerprint endpoint enforces —
# otherwise an operator-role user can turn the backend into an SSRF probe of
# 127.0.0.1 + the instance metadata service.
_SCAN_BLOCKED_IP_PROPERTIES = (
    "is_loopback",
    "is_link_local",
    "is_multicast",
    "is_reserved",
    "is_unspecified",
)
# Keep in sync with CLOUD_METADATA_IP_LITERALS in app/core/security_utils.py and
# scanner.py (added Alibaba 100.100.100.200 + Oracle 192.0.0.192 — non-link-local).
_SCAN_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200", "192.0.0.192"}


def _reject_unsafe_scan_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Raise ValueError if ``ip`` is an SSRF-sensitive address for scanning."""
    if str(ip) in _SCAN_METADATA_IPS:
        raise ValueError(f"scan target {ip} is a cloud-metadata address")
    for prop in _SCAN_BLOCKED_IP_PROPERTIES:
        if getattr(ip, prop, False):
            raise ValueError(f"scan target {ip} is a blocked ({prop[3:]}) address")


def _validate_scan_target(value: str) -> str:
    """Validate a single scan target (IP, CIDR, or ``a-b`` range).

    - Single IPs are accepted (``192.168.1.1``).
    - CIDR blocks are size-capped at :data:`MAX_SCAN_HOSTS_IPV4` / v6.
    - ``start-end`` hyphen ranges are accepted and size-capped.
    - Multicast, IETF-reserved, loopback, link-local (incl. cloud metadata),
      and unspecified targets are rejected (SSRF egress guard).

    Returns the normalized target string on success; raises
    :class:`ValueError` on any failure.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("scan target must be a non-empty string")
    v = value.strip()

    # Hyphen range: "192.168.1.10-20" or "192.168.1.10-192.168.1.120"
    if "-" in v and "/" not in v:
        left, _, right = v.partition("-")
        try:
            left_ip = ipaddress.ip_address(left)
        except ValueError as exc:
            raise ValueError(f"invalid scan target {v!r}: {exc}") from exc
        # Short form: same /24 prefix with just the last octet.
        if "." not in right and ":" not in right:
            try:
                last_octet = int(right)
            except ValueError as exc:
                raise ValueError(f"invalid scan target {v!r}: bad range end") from exc
            if not (0 <= last_octet <= 255):
                raise ValueError(f"invalid scan target {v!r}: octet out of range")
            base = int(left_ip) & ~0xFF
            right_ip = ipaddress.ip_address(base | last_octet)
        else:
            try:
                right_ip = ipaddress.ip_address(right)
            except ValueError as exc:
                raise ValueError(f"invalid scan target {v!r}: {exc}") from exc
        if int(right_ip) < int(left_ip):
            raise ValueError(f"invalid scan target {v!r}: end precedes start")
        span = int(right_ip) - int(left_ip) + 1
        cap = MAX_SCAN_HOSTS_IPV4 if left_ip.version == 4 else MAX_SCAN_HOSTS_IPV6
        if span > cap:
            raise ValueError(f"scan range {v!r} too large: {span} hosts, maximum {cap}")
        _reject_unsafe_scan_ip(left_ip)
        _reject_unsafe_scan_ip(right_ip)
        return v

    # CIDR or single IP.
    try:
        network = ipaddress.ip_network(v, strict=False)
    except ValueError:
        # Single IP (no slash) — ip_network with strict=False still accepts
        # bare IPs, so a failure here is genuinely invalid.
        raise ValueError(f"invalid CIDR or IP: {v!r}") from None

    num_hosts = network.num_addresses
    if network.version == 4 and num_hosts > MAX_SCAN_HOSTS_IPV4:
        raise ValueError(
            f"CIDR too large: /{network.prefixlen} has {num_hosts} hosts. "
            f"Maximum allowed is /16 ({MAX_SCAN_HOSTS_IPV4} hosts). "
            "Break your scan into smaller subnets."
        )
    if network.version == 6 and num_hosts > MAX_SCAN_HOSTS_IPV6:
        raise ValueError(
            f"IPv6 CIDR too large: /{network.prefixlen} has {num_hosts} hosts. "
            f"Maximum allowed is /112 ({MAX_SCAN_HOSTS_IPV6} hosts)."
        )
    if network.is_multicast or network.is_reserved:
        raise ValueError(f"CIDR targets multicast/reserved range: {v}")
    # SSRF egress guard on the network's endpoints (single IP → network==broadcast).
    _reject_unsafe_scan_ip(network.network_address)
    _reject_unsafe_scan_ip(network.broadcast_address)
    return str(network)


def _estimate_target_hosts(value: str) -> int:
    """Estimate the number of addresses a single scan target covers.

    Used by :data:`MAX_SCAN_HOSTS_TOTAL` enforcement in the model validator.
    Assumes ``value`` has already passed :func:`_validate_scan_target`, so
    it is syntactically valid — any residual ``ValueError`` means the
    estimator couldn't parse it (rare), in which case we fall back to 256.
    """
    v = value.strip()
    # Hyphen range: compute the span directly.
    if "-" in v and "/" not in v:
        left, _, right = v.partition("-")
        try:
            left_ip = ipaddress.ip_address(left)
            if "." not in right and ":" not in right:
                base = int(left_ip) & ~0xFF
                right_ip = ipaddress.ip_address(base | int(right))
            else:
                right_ip = ipaddress.ip_address(right)
            return int(right_ip) - int(left_ip) + 1
        except ValueError:
            return 256  # conservative upper bound for hyphen ranges
    # CIDR / bare IP.
    try:
        return ipaddress.ip_network(v, strict=False).num_addresses
    except ValueError:
        return 1


# ===========================================
# Base
# ===========================================


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


# ===========================================
# Scan Request / Response
# ===========================================


class ScanOptionsSchema(BaseSchema):
    """Advanced scan options."""

    max_concurrent_hosts: int = Field(50, ge=1, le=500)
    max_concurrent_ports: int = Field(100, ge=1, le=500)
    tcp_timeout: float = Field(2.0, ge=0.5, le=30.0)
    probe_services: bool = True
    resolve_hostnames: bool = True
    follow_controllers: bool = True


class ScanRequestSchema(BaseSchema):
    """Request to start a network scan."""

    targets: list[str] = Field(
        ...,
        description="Target IPs, CIDRs, or ranges (e.g., '192.168.1.0/24', '10.0.0.1-50')",
        min_length=1,
        max_length=256,
    )
    exclude_targets: list[str] = Field(
        default_factory=list,
        description="IPs/CIDRs to exclude from the scan",
        max_length=256,
    )
    site_id: str | None = Field(None, description="Optional site to associate results with")
    scan_methods: list[str] = Field(
        default_factory=lambda: ["tcp_connect", "mdns", "ssdp"],
        description="Scanning methods to use",
    )
    tcp_ports: list[int] = Field(
        default_factory=lambda: [22, 23, 80, 443, 554, 8080, 8443],
        description="TCP ports to scan",
    )
    options: ScanOptionsSchema | None = None

    @field_validator("targets", "exclude_targets")
    @classmethod
    def _validate_targets(cls, values: list[str]) -> list[str]:
        """Reject over-large CIDRs."""
        return [_validate_scan_target(v) for v in values]

    @model_validator(mode="after")
    def _check_total_host_count(self) -> "ScanRequestSchema":
        """Enforce the global host-count cap.

        Per-target validation alone lets a caller queue 256 × /16 = 16.7M
        hosts. Sum across all included targets and reject if the total
        exceeds :data:`MAX_SCAN_HOSTS_TOTAL` (4 × /16).

        the exclude list is ALSO bounded here. The earlier
        reasoning ("excludes shrink, not grow, the scan") is true for the
        scan's effective work, but ignores that ``expand_targets`` fully
        materializes every exclude entry into an in-memory set BEFORE any
        filtering — so 256 × /16 excludes = ~16.7M IP strings (~1.3 GB) and
        an event-loop stall. Cap exclude expansion independently.
        """
        total = 0
        for target in self.targets:
            total += _estimate_target_hosts(target)
            if total > MAX_SCAN_HOSTS_TOTAL:
                raise ValueError(
                    f"total hosts across targets exceeds "
                    f"{MAX_SCAN_HOSTS_TOTAL} (currently: {total}). "
                    "Break your scan into smaller batches."
                )
        exclude_total = 0
        for target in self.exclude_targets:
            exclude_total += _estimate_target_hosts(target)
            if exclude_total > MAX_SCAN_HOSTS_TOTAL:
                raise ValueError(
                    f"total hosts across exclude_targets exceeds "
                    f"{MAX_SCAN_HOSTS_TOTAL} (currently: {exclude_total}). "
                    "Use coarser exclude blocks or fewer entries."
                )
        return self


# Backwards-compatible alias + convenience wrapper used by tests that pass a
# single ``cidr=`` argument. Validates the CIDR through the same pipeline.
class DiscoveryScanRequest(BaseSchema):
    """Convenience wrapper around a single CIDR scan target.

    Used by :mod:`tests.security.test_discovery_limits` and any caller that
    only needs to validate a single CIDR block.
    """

    cidr: str = Field(..., description="A single CIDR, IP, or hyphen range")

    @field_validator("cidr")
    @classmethod
    def _validate_cidr(cls, v: str) -> str:
        return _validate_scan_target(v)


class ScanStartedResponse(BaseSchema):
    """Response when a scan is started."""

    scan_id: str
    status: str = "running"
    total_targets: int
    message: str = "Scan started"


class ScanProgressSchema(BaseSchema):
    """Live scan progress."""

    scan_id: str
    status: str  # pending | running | completed | cancelled | failed
    total_hosts: int = 0
    scanned_hosts: int = 0
    discovered_hosts: int = 0
    current_phase: str = ""
    phase_progress: float = 0.0
    progress_pct: float = 0.0
    hosts_found: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    elapsed_seconds: float = 0.0
    estimated_remaining_seconds: float | None = None
    started_at: datetime | None = None


# ===========================================
# Discovered Host/Device
# ===========================================


class DriverMatchSchema(BaseSchema):
    """Driver match result for a discovered device."""

    driver_id: str
    driver_name: str
    vendor: str
    confidence: float = 0.0
    adapter_type: str | None = None


class DiscoveredHostSchema(BaseSchema):
    """A host found during network scanning."""

    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    vendor_confidence: float = 0.0

    device_type: str | None = None
    device_type_confidence: float = 0.0

    open_ports: list[int] = Field(default_factory=list)
    services: dict[str, Any] = Field(default_factory=dict)

    discovered_via: list[str] = Field(default_factory=list)
    discovered_at: datetime | None = None
    response_time_ms: float | None = None

    mdns_services: list[str] = Field(default_factory=list)
    ssdp_info: dict[str, Any] | None = None

    likely_device_types: list[str] = Field(default_factory=list)
    http_title: str | None = None
    http_server: str | None = None

    # Driver matching (populated after fingerprinting)
    driver_match: DriverMatchSchema | None = None
    is_manageable: bool = False


class ScanResultsSchema(BaseSchema):
    """Complete scan results."""

    scan_id: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    elapsed_seconds: float = 0.0

    total_targets: int = 0
    total_discovered: int = 0
    total_manageable: int = 0

    devices: list[DiscoveredHostSchema] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ===========================================
# Fingerprint
# ===========================================


class FingerprintRequestSchema(BaseSchema):
    """Request to fingerprint a specific device.

    Port list was unbounded — a 5000-port payload caused the endpoint
    to fan out ~10 000 HTTP probes (5000 ports × 2 schemes) and timed
    out the request. 32 covers any realistic vendor-fingerprint sweep.
    Each port is a TCP port number so the int range is gated 1-65535.
    """

    ip_address: str = Field(..., max_length=64)
    ports: list[int] = Field(
        default_factory=lambda: [80, 443, 554, 8080, 8443],
        max_length=32,
    )
    credentials: dict[str, str] | None = Field(None, max_length=8)

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, v: list[int]) -> list[int]:
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f"invalid TCP port {p}: must be 1-65535")
        return v


class FingerprintResultSchema(BaseSchema):
    """Fingerprint result for a device."""

    ip_address: str
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    device_type: str | None = None
    serial_number: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    probes_tried: list[str] = Field(default_factory=list)
    probes_succeeded: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


# ===========================================
# Driver
# ===========================================


class DriverSchema(BaseSchema):
    """Driver summary."""

    id: str
    name: str
    vendor: str
    adapter_type: str
    device_types: list[str] = Field(default_factory=list)
    # Surfaced on the list too (the FE Drivers table + Capabilities stat read
    # it); DRIVER_REGISTRY rows already carry it, the list model just dropped it.
    capabilities: list[str] = Field(default_factory=list)
    version: str | None = None
    description: str | None = None


class DriverDetailsSchema(DriverSchema):
    """Full driver details."""

    config_schema: dict[str, Any] | None = None
    supported_models: list[str] = Field(default_factory=list)
    documentation_url: str | None = None


# ===========================================
# Controller Discovery (existing)
# ===========================================


class ControllerDiscoveryRequest(BaseSchema):
    """Request to discover from a specific controller."""

    sync: bool = Field(False, description="Run synchronously (block until done)")


class ControllerDiscoveryResponse(BaseSchema):
    """Result from controller discovery."""

    controller_id: str
    controller_name: str
    status: str
    devices_found: int = 0
    devices_new: int = 0
    devices_updated: int = 0
    errors: list[str] = Field(default_factory=list)
