# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Cameras Module Schemas
====================================

Pydantic request / response schemas for the Cameras module REST API.
"""

from __future__ import annotations

import ipaddress

# ═══════════════════════════════════════════════════════════════════════════════
# Validators
# ═══════════════════════════════════════════════════════════════════════════════
# Blocked IP ranges (SSRF protection) — loopback, link-local, cloud metadata,
# and unspecified addresses.  RFC 1918 private ranges are ALLOWED by default
# because FreeSDN manages on-premises cameras/NVRs on private networks.
# Set BLOCK_PRIVATE_CAMERA_SUBNETS=1 to also block 10/8, 172.16/12, 192.168/16.
import os as _os
import re
from datetime import datetime
from typing import Any, ClassVar, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.security_utils import _METADATA_IPS as _METADATA_IP_STRINGS

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),  # unspecified
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6
]

# Strict mode: also block RFC 1918 private ranges (disabled by default)
if _os.environ.get("BLOCK_PRIVATE_CAMERA_SUBNETS", "").strip() in ("1", "true", "yes"):
    _BLOCKED_NETWORKS.extend(
        [
            ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918 Class A
            ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918 Class B
            ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918 Class C
            ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
            ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking
            ipaddress.ip_network("fc00::/7"),  # IPv6 Unique Local
        ]
    )

# Allow-listed private subnets for on-prem NVR/camera deployments.
# Operators can override via ALLOWED_CAMERA_SUBNETS env var (comma-separated CIDRs).
_ALLOWED_SUBNETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_raw = _os.environ.get("ALLOWED_CAMERA_SUBNETS", "")
if _raw:
    for _cidr in _raw.split(","):
        _cidr = _cidr.strip()
        if _cidr:
            _ALLOWED_SUBNETS.append(ipaddress.ip_network(_cidr, strict=False))


# Cloud metadata endpoints — NEVER reachable (not via the allow-list, not when
# BLOCK_PRIVATE_CAMERA_SUBNETS is unset). 169.254.0.0/16 is already blocked, but
# Alibaba's 100.100.100.200 lives in CGNAT (100.64/10) and AWS's IPv6
# fd00:ec2::254 in ULA (fc00::/7) — both otherwise only blocked by the opt-in
# env flag, so a camera pointed at them would pass validation by default.
def _as_ip(_s: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    # _METADATA_IPS mixes IP literals with hostnames (e.g. metadata.google.internal);
    # the hostnames are caught via DNS resolution -> IP block, so keep only literals.
    try:
        return ipaddress.ip_address(_s)
    except ValueError:
        return None


_METADATA_ADDRS = frozenset(
    _addr for _ip in _METADATA_IP_STRINGS if (_addr := _as_ip(_ip)) is not None
)


def _is_address_allowed(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address is safe (not in blocked ranges, or explicitly allowed)."""
    # Cloud metadata endpoints are blocked unconditionally — before the
    # operator allow-list, so a broad ALLOWED_CAMERA_SUBNETS can't expose them.
    if addr in _METADATA_ADDRS:
        return False
    # Then the allow-list — operators may whitelist their camera subnets
    for allowed in _ALLOWED_SUBNETS:
        if addr in allowed:
            return True
    # Then the block-list
    return all(addr not in net for net in _BLOCKED_NETWORKS)


def _validate_url_not_ssrf(url: str | None) -> str | None:
    """SSRF guard for full URLs (RTSP / HTTP / HTTPS).

    Extracts the hostname and runs it through _validate_host_not_ssrf().
    Empty strings and None are passed through (treated as "no URL set").
    Used for camera RTSP overrides and LPR provider API URLs — these
    flow into outbound proxy/HTTP clients.
    """
    if url is None or url.strip() == "":
        return url
    s = url.strip()
    from urllib.parse import urlparse

    try:
        parsed = urlparse(s)
    except Exception as exc:
        raise ValueError(f"URL malformed: {exc}") from exc
    if parsed.scheme.lower() not in ("rtsp", "rtsps", "http", "https"):
        raise ValueError(f"URL scheme must be rtsp/rtsps/http/https, got {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("URL missing host")
    # Reuse the host-based SSRF guard (respects RFC1918 allowlist for
    # operator-managed camera subnets).
    _validate_host_not_ssrf(host)
    return s


def _validate_host_not_ssrf(host: str) -> str:
    """Block SSRF-dangerous hosts (loopback, metadata, link-local).

    Performs DNS resolution for hostnames to prevent DNS rebinding attacks.
    Private RFC 1918 subnets (10/8, 172.16/12, 192.168/16) are ALLOWED by
    default because FreeSDN is an on-premises network management tool and
    cameras/NVRs almost always live on private networks.

    Set ALLOWED_CAMERA_SUBNETS env var to allow additional non-default
    subnets.  Set BLOCK_PRIVATE_CAMERA_SUBNETS=1 to restore strict mode.
    """
    import socket

    host = host.strip()
    if not host:
        raise ValueError("Host cannot be empty")
    # Block common metadata hostnames
    _blocked_hostnames = {
        "localhost",
        "metadata.google.internal",
        "metadata",
        "instance-data",
        "metadata.google.internal.",
    }
    if host.lower() in _blocked_hostnames:
        raise ValueError(f"Host '{host}' is not allowed")
    # If it looks like an IP, validate against blocked ranges
    try:
        addr = ipaddress.ip_address(host)
        if not _is_address_allowed(addr):
            raise ValueError(f"Host '{host}' is in a blocked network range")
    except ValueError as ve:
        if "blocked" in str(ve) or "not allowed" in str(ve):
            raise
        # Not an IP — treat as hostname; block obvious internal patterns
        if re.match(r"^internal[.-]|^localhost[.-]|^127\.", host, re.IGNORECASE):
            raise ValueError(f"Host '{host}' is not allowed")
        # Resolve DNS and validate all resolved addresses
        try:
            addrs = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = {ipaddress.ip_address(a[4][0]) for a in addrs}
            for rip in resolved_ips:
                if not _is_address_allowed(rip):
                    raise ValueError(f"Host '{host}' resolves to blocked address {rip}")
        except socket.gaierror:
            pass  # DNS resolution failure — let the connection attempt handle it
    return host


# ═══════════════════════════════════════════════════════════════════════════════
# NVR Connection & Discovery
# ═══════════════════════════════════════════════════════════════════════════════


class NVRConnectionTestRequest(BaseModel):
    """Credentials to test NVR reachability."""

    host: str = Field(..., min_length=1, max_length=255, description="NVR IP address or hostname")
    port: int = Field(80, ge=1, le=65535)
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)
    vendor: str | None = Field(
        None,
        max_length=40,
        description="Optional NVR vendor (e.g. 'hikvision'). When omitted the "
        "server auto-detects: Hikvision ISAPI first, then ONVIF.",
    )

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host_not_ssrf(v)


class NVRConnectionTestResponse(BaseModel):
    """Result of connection test."""

    success: bool
    device_id: str | None = None
    device_name: str | None = None
    device_type: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    mac_address: str | None = None
    error: str | None = None


class DiscoveredChannelResponse(BaseModel):
    """A discovered camera channel on an NVR."""

    channel_id: int
    name: str
    enabled: bool
    online: bool
    source_ip: str | None = None
    has_ptz: bool = False
    has_audio: bool = False
    rtsp_main: str | None = None
    rtsp_sub: str | None = None


class SMARTAttribute(BaseModel):
    """Individual S.M.A.R.T. attribute from disk health test."""

    id: int = 0
    name: str = ""
    current: int = 0
    worst: int = 0
    threshold: int = 0
    raw_value: str = ""
    status: str = ""


class DiskInfo(BaseModel):
    """Per-disk detail returned from the NVR."""

    id: int | None = None
    name: str = ""
    capacity_mb: int = 0
    free_mb: int = 0
    status: str = "unknown"
    hdd_type: str = ""
    property: str = ""

    # Extended fields from /ISAPI/System/Storage/hdd
    model: str | None = None
    serial_number: str | None = None
    firmware: str | None = None
    capacity_bytes: int | None = None

    # S.M.A.R.T. health
    smart_status: str | None = None
    temperature_c: int | None = None
    power_on_hours: int | None = None
    smart_self_test_percent: int | None = None
    smart_attributes: list[SMARTAttribute] = Field(default_factory=list)


class NVRStorageSummary(BaseModel):
    """Summarised storage info with per-disk SMART health."""

    total_gb: float = 0.0
    used_gb: float = 0.0
    free_gb: float = 0.0
    percent_used: float = 0.0
    disk_count: int = 0
    healthy_count: int = 0
    unhealthy_count: int = 0
    disks: list[DiskInfo] = Field(default_factory=list)


class NVRDeviceInfo(BaseModel):
    """NVR metadata from ISAPI discovery."""

    device_id: str = ""
    name: str = ""
    model: str = ""
    firmware: str = ""
    serial_number: str = ""
    mac_address: str = ""


class NVRDiscoveryResponse(BaseModel):
    """Result of NVR channel discovery."""

    device_type: str = "nvr"  # "nvr", "camera", or "unknown"
    nvr: NVRDeviceInfo
    channels: list[DiscoveredChannelResponse]
    storage: NVRStorageSummary | dict = Field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# NVR Import
# ═══════════════════════════════════════════════════════════════════════════════


class NVRImportRequest(BaseModel):
    """Request to import an NVR and its cameras."""

    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(80, ge=1, le=65535)
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)
    site_id: UUID
    name: str | None = Field(None, max_length=255)
    selected_channels: list[int] | None = Field(None, max_length=256)  # None = all

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host_not_ssrf(v)

    # every channel index that
    # eventually hits an ISAPI URL must be 1..256 (Hikvision's
    # documented upper bound). The default validator only enforces
    # ``max_length`` on the list itself; tighten the per-item range
    # so a hostile caller can't smuggle a negative / out-of-range
    # value into the import flow.
    @field_validator("selected_channels")
    @classmethod
    def _validate_channel_range(cls, v: list[int] | None) -> list[int] | None:
        if v is None:
            return v
        for ch in v:
            if not (1 <= int(ch) <= 256):
                raise ValueError(f"channel {ch} out of range — must be 1..256")
        return v


class ImportedCameraSummary(BaseModel):
    """Short camera record in import response."""

    id: UUID
    name: str
    channel_id: int | None = None

    model_config = {"from_attributes": True}


class NVRImportResponse(BaseModel):
    """Result of NVR import."""

    nvr_id: UUID
    nvr_name: str
    cameras_imported: int
    cameras_skipped: int
    cameras: list[ImportedCameraSummary]
    # True when the NVR already existed and was re-synced instead of created
    # fresh (idempotent re-import) — lets the wizard show "Re-synced" vs "Added".
    synced: bool = False


class StandaloneCameraImportRequest(BaseModel):
    """Request to import a standalone camera (not attached to an NVR)."""

    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(80, ge=1, le=65535)
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)
    site_id: UUID
    name: str | None = Field(None, max_length=255)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        return _validate_host_not_ssrf(v)


class StandaloneCameraImportResponse(BaseModel):
    """Result of standalone camera import."""

    camera_id: UUID
    camera_name: str


# ═══════════════════════════════════════════════════════════════════════════════
# NVR Sync
# ═══════════════════════════════════════════════════════════════════════════════


class NVRSyncResponse(BaseModel):
    """Result of NVR sync."""

    added: int
    removed: int
    updated: int


# ═══════════════════════════════════════════════════════════════════════════════
# Camera CRUD
# ═══════════════════════════════════════════════════════════════════════════════


class CameraCreateRequest(BaseModel):
    """Create standalone camera."""

    name: str = Field(..., min_length=1, max_length=255)
    site_id: UUID
    ip_address: str
    port: int = Field(554, ge=1, le=65535)
    camera_type: str = Field("ip_camera", max_length=50)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        return _validate_host_not_ssrf(v)

    vendor: str | None = Field(None, max_length=100)
    model: str | None = Field(None, max_length=100)
    device_type: str | None = Field(None, max_length=50)
    username: str | None = Field(None, max_length=100)
    password: str | None = Field(None, max_length=200)
    rtsp_main_stream: str | None = Field(None, max_length=500)
    rtsp_sub_stream: str | None = Field(None, max_length=500)

    @field_validator("rtsp_main_stream", "rtsp_sub_stream")
    @classmethod
    def validate_rtsp(cls, v: str | None) -> str | None:
        # SSRF on the runtime proxy: the HLS bridge dereferences this
        # URL whenever a client opens a stream. Without this check an
        # operator with cameras.manage could set rtsp_main_stream to
        # rtsp://127.0.0.1:6379/foo and use the HLS bridge to probe
        # internal services.
        return _validate_url_not_ssrf(v)

    has_ptz: bool = False
    has_audio: bool = False
    location: str | None = Field(None, max_length=255)
    floor: str | None = Field(None, max_length=100)


class CameraUpdateRequest(BaseModel):
    """Partial camera update."""

    name: str | None = Field(None, min_length=1, max_length=255)
    ip_address: str | None = None
    port: int | None = Field(None, ge=1, le=65535)
    camera_type: str | None = Field(None, max_length=50)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str | None) -> str | None:
        if v is not None:
            return _validate_host_not_ssrf(v)
        return v

    rtsp_main_stream: str | None = Field(None, max_length=500)
    rtsp_sub_stream: str | None = Field(None, max_length=500)

    @field_validator("rtsp_main_stream", "rtsp_sub_stream")
    @classmethod
    def validate_rtsp(cls, v: str | None) -> str | None:
        return _validate_url_not_ssrf(v)

    has_ptz: bool | None = None
    has_audio: bool | None = None
    location: str | None = Field(None, max_length=255)
    floor: str | None = Field(None, max_length=100)
    status: str | None = Field(None, max_length=50)
    stream_encryption_key: str | None = Field(
        None,
        description="Hikvision stream encryption key (hex). "
        "Required when stream encryption is enabled on the camera/NVR.",
        max_length=64,
    )


class NVRRef(BaseModel):
    """Lightweight NVR reference (id + name) embedded in a camera response.

    Lets the frontend group/filter cameras by their parent NVR without an
    extra round-trip. Populated by a batched lookup in the list path (no
    N+1) — see ``CameraService.attach_nvr_refs``.
    """

    id: UUID
    name: str

    model_config = {"from_attributes": True}


class CameraResponse(BaseModel):
    """Camera detail response."""

    id: UUID
    name: str
    description: str | None = None
    camera_type: str
    ip_address: str
    port: int
    mac_address: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    channel_id: int | None = None
    device_type: str | None = None
    has_ptz: bool
    has_audio: bool
    has_two_way_audio: bool = False
    has_ir: bool = False
    status: str
    last_seen: datetime | None = None
    is_recording: bool = False
    motion_detection_enabled: bool = True
    nvr_id: UUID | None = None
    # Nested parent-NVR ref (id + name). Populated by a batched lookup in the
    # list/detail path so the frontend can filter/group cameras by NVR without
    # dereferencing the lazy="raise" Camera.nvr relationship.
    nvr: NVRRef | None = None
    site_id: UUID
    location: str | None = None
    floor: str | None = None
    rtsp_main_stream: str | None = None
    rtsp_sub_stream: str | None = None
    stream_encryption_key: bool = False
    settings: dict | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_validator("rtsp_main_stream", "rtsp_sub_stream", mode="before")
    @classmethod
    def _mask_rtsp_credentials(cls, v: str | None) -> str | None:
        """Strip embedded credentials from RTSP URLs before serialisation."""
        if v and "://" in v and "@" in v:
            # Use greedy match up to the LAST @ before the host
            import re

            return re.sub(r"://[^/]*@", "://*****@", v, count=1)
        return v

    # Without ``ClassVar``, pydantic v2 promotes ``_SETTINGS_SENSITIVE_KEYS``
    # to a ``ModelPrivateAttr`` descriptor — and ``cls._SETTINGS_SENSITIVE_KEYS``
    # then returns the descriptor object, not the frozenset, breaking the
    # ``k not in cls._SETTINGS_SENSITIVE_KEYS`` check with
    # ``TypeError: argument of type 'ModelPrivateAttr' is not iterable``.
    # The bug was latent — only triggered when a camera's settings dict
    # was non-empty (caught during the post-session smoke test after a
    # PUT /lpr/config probe persisted an ``lpr_config`` settings entry).
    _SETTINGS_SENSITIVE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "stream_encryption_key",
            "password",
            "api_key",
            "token",
            "secret",
            "credentials",
            "private_key",
            "auth_token",
        }
    )

    @model_validator(mode="before")
    @classmethod
    def _extract_encryption_key(cls, data: Any) -> Any:
        """Indicate whether stream_encryption_key is set (never expose the actual key)."""
        if hasattr(data, "settings"):
            settings = data.settings or {}
        elif isinstance(data, dict):
            settings = data.get("settings") or {}
        else:
            return data
        has_key = isinstance(settings, dict) and bool(settings.get("stream_encryption_key"))
        if hasattr(data, "__dict__"):
            data.__dict__["stream_encryption_key"] = has_key
        elif isinstance(data, dict):
            data["stream_encryption_key"] = has_key
        # Sanitize settings — strip sensitive keys
        if isinstance(settings, dict):
            sanitized = {k: v for k, v in settings.items() if k not in cls._SETTINGS_SENSITIVE_KEYS}
            if hasattr(data, "__dict__"):
                data.__dict__["settings"] = sanitized
            elif isinstance(data, dict):
                data["settings"] = sanitized
        # Resolve the nested NVR ref. ``Camera.nvr`` is lazy="raise", so reading
        # it on an ORM object whose relationship was NOT eagerly populated would
        # raise. The list path pre-loads it via CameraService.attach_nvr_refs;
        # here we only read it when it is already loaded and otherwise emit
        # None — so the single-camera detail/create/update responses never
        # trigger the lazy="raise" guard.
        if hasattr(data, "__dict__") and not isinstance(data, dict):
            if "nvr" not in data.__dict__:
                data.__dict__["nvr"] = None
        return data

    model_config = {"from_attributes": True}


class CameraListResponse(BaseModel):
    """Paginated camera list."""

    items: list[CameraResponse]
    total: int
    limit: int
    offset: int


# ═══════════════════════════════════════════════════════════════════════════════
# NVR CRUD
# ═══════════════════════════════════════════════════════════════════════════════


class NVRCreateRequest(BaseModel):
    """Manual NVR creation (prefer import endpoint instead)."""

    name: str = Field(..., min_length=1, max_length=255)
    site_id: UUID
    ip_address: str
    port: int = Field(80, ge=1, le=65535)
    device_type: str = Field("hikvision", max_length=50)
    vendor: str | None = Field(None, max_length=100)
    model: str | None = Field(None, max_length=100)
    channel_count: int = Field(0, ge=0, le=256)
    username: str | None = Field(None, min_length=1, max_length=100)
    password: str | None = Field(None, min_length=1, max_length=200)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        return _validate_host_not_ssrf(v)


class NVRUpdateRequest(BaseModel):
    """Partial NVR update."""

    name: str | None = Field(None, min_length=1, max_length=255)
    ip_address: str | None = None
    port: int | None = Field(None, ge=1, le=65535)
    status: str | None = Field(None, max_length=50)
    channel_count: int | None = Field(None, ge=0, le=256)
    username: str | None = Field(None, min_length=1, max_length=100)
    password: str | None = Field(None, min_length=1, max_length=200)
    stream_encryption_key: str | None = Field(
        None,
        description="Hikvision stream encryption key (hex). Shared by all cameras on this NVR.",
        max_length=64,
    )

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str | None) -> str | None:
        if v is not None:
            return _validate_host_not_ssrf(v)
        return v


class NVRResponse(BaseModel):
    """NVR detail response."""

    id: UUID
    name: str
    description: str | None = None
    ip_address: str
    port: int
    mac_address: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    device_type: str
    channel_count: int
    storage_total_gb: float | None = None
    storage_used_gb: float | None = None
    status: str
    last_seen: datetime | None = None
    last_synced_at: datetime | None = None
    site_id: UUID
    created_at: datetime | None = None
    updated_at: datetime | None = None
    stream_encryption_key: bool = False
    settings: dict | None = None

    # Same pydantic v2 ClassVar fix as CameraResponse — see comment there.
    _SETTINGS_SENSITIVE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "stream_encryption_key",
            "password",
            "api_key",
            "token",
            "secret",
            "credentials",
            "private_key",
            "auth_token",
        }
    )

    @model_validator(mode="before")
    @classmethod
    def _extract_nvr_encryption_key(cls, values: Any) -> Any:
        """Indicate whether stream_encryption_key is set (never expose the actual key)."""
        if hasattr(values, "__dict__"):
            settings = getattr(values, "settings", None) or {}
        elif isinstance(values, dict):
            settings = values.get("settings") or {}
        else:
            return values
        has_key = isinstance(settings, dict) and bool(settings.get("stream_encryption_key"))
        if hasattr(values, "__dict__"):
            values.stream_encryption_key = has_key
        else:
            values["stream_encryption_key"] = has_key
        # Sanitize settings — strip sensitive keys
        if isinstance(settings, dict):
            sanitized = {k: v for k, v in settings.items() if k not in cls._SETTINGS_SENSITIVE_KEYS}
            if hasattr(values, "__dict__"):
                values.__dict__["settings"] = sanitized
            elif isinstance(values, dict):
                values["settings"] = sanitized
        return values

    model_config = {"from_attributes": True}


class NVRListResponse(BaseModel):
    """Paginated NVR list."""

    items: list[NVRResponse]
    total: int
    limit: int
    offset: int


# ═══════════════════════════════════════════════════════════════════════════════
# Camera Stats
# ═══════════════════════════════════════════════════════════════════════════════


class CameraStatsResponse(BaseModel):
    """Camera statistics."""

    total: int = 0
    online: int = 0
    offline: int = 0
    recording: int = 0
    error: int = 0


class NVRStatsResponse(BaseModel):
    """NVR statistics."""

    total: int = 0
    online: int = 0
    offline: int = 0
    recording: int = 0
    error: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# PTZ Control
# ═══════════════════════════════════════════════════════════════════════════════


class PTZControlRequest(BaseModel):
    """PTZ move / zoom / stop command."""

    action: str = Field(
        ...,
        description=(
            "PTZ action: up, down, left, right, up_left, up_right, "
            "down_left, down_right, zoom_in, zoom_out, stop"
        ),
    )
    speed: int = Field(50, ge=1, le=100)
    preset: int | None = None


class PTZPresetResponse(BaseModel):
    """PTZ preset info."""

    id: int
    name: str
    enabled: bool = True
    pan: int | None = None
    tilt: int | None = None
    zoom: int | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# Recordings
# ═══════════════════════════════════════════════════════════════════════════════


class RecordingResponse(BaseModel):
    """Recording segment."""

    id: UUID
    camera_id: UUID
    nvr_id: UUID | None = None
    start_time: datetime
    end_time: datetime | None = None
    duration_seconds: int | None = None
    recording_type: str = "continuous"
    file_size_bytes: int | None = None
    is_locked: bool = False

    model_config = {"from_attributes": True}


# ═══════════════════════════════════════════════════════════════════════════════
# Events
# ═══════════════════════════════════════════════════════════════════════════════


class CameraEventResponse(BaseModel):
    """Camera event record."""

    id: UUID
    camera_id: UUID
    event_type: str
    timestamp: datetime
    description: str | None = None
    snapshot_url: str | None = None
    is_acknowledged: bool = False
    acknowledged_by: UUID | None = None
    acknowledged_at: datetime | None = None
    # Object-classification metadata from the NVR (e.g. {"target_type": "human"}).
    # The events page derives the person/vehicle category tabs from
    # ``metadata_json.target_type`` — without carrying this column through, those
    # tabs never match.
    metadata_json: dict | None = None

    @model_validator(mode="before")
    @classmethod
    def _sanitize_snapshot(cls, values: Any) -> Any:
        """Convert internal snapshot_path to a safe relative URL."""
        path = None
        if hasattr(values, "snapshot_path"):
            path = getattr(values, "snapshot_path", None)
        elif isinstance(values, dict):
            path = values.get("snapshot_path")
        if path and isinstance(path, str):
            # Expose only the filename, not the full filesystem path
            from pathlib import PurePosixPath

            safe_name = PurePosixPath(path).name
            url = f"/api/v1/cameras/events/snapshots/{safe_name}" if safe_name else None
            if hasattr(values, "__dict__"):
                values.__dict__["snapshot_url"] = url
            elif isinstance(values, dict):
                values["snapshot_url"] = url
        return values

    model_config = {"from_attributes": True}


class CameraEventListResponse(BaseModel):
    """Paginated camera event list."""

    items: list[CameraEventResponse]
    total: int
    limit: int
    offset: int


class UnacknowledgedCountResponse(BaseModel):
    """Unacknowledged event count."""

    count: int


class BulkAcknowledgeResponse(BaseModel):
    """Bulk acknowledge result."""

    status: str = "ok"
    acknowledged_count: int


class BulkAcknowledgeRequest(BaseModel):
    """Bulk event acknowledgement."""

    event_ids: list[UUID] = Field(..., max_length=1000)


# ═══════════════════════════════════════════════════════════════════════════════
# Camera Groups
# ═══════════════════════════════════════════════════════════════════════════════


class GroupCreateRequest(BaseModel):
    """Create a camera group with optional initial members."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=500)
    color: str = Field("#3b82f6", max_length=7, pattern=r"^#[0-9a-fA-F]{6}$")
    icon: str = Field("folder", max_length=50)
    camera_ids: list[UUID] | None = None


class GroupUpdateRequest(BaseModel):
    """Partial update for a camera group."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=500)
    color: str | None = Field(None, max_length=7, pattern=r"^#[0-9a-fA-F]{6}$")
    icon: str | None = Field(None, max_length=50)
    camera_ids: list[UUID] | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# Camera Views (Custom Layouts)
# ═══════════════════════════════════════════════════════════════════════════════


class ViewCreateRequest(BaseModel):
    """Create a custom camera view/layout."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=500)
    layout: str = Field("2x2", max_length=50)
    camera_ids: list[UUID] = Field(default_factory=list)
    is_shared: bool = False


class ViewUpdateRequest(BaseModel):
    """Partial update for a camera view."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=500)
    layout: str | None = Field(None, max_length=50)
    camera_ids: list[UUID] | None = None
    is_shared: bool | None = None
    is_default: bool | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# Image Settings (brightness / contrast / etc.)
# ═══════════════════════════════════════════════════════════════════════════════


class ImageSettingsRequest(BaseModel):
    """Camera image tuning parameters."""

    brightness: int | None = Field(None, ge=0, le=100)
    contrast: int | None = Field(None, ge=0, le=100)
    saturation: int | None = Field(None, ge=0, le=100)
    sharpness: int | None = Field(None, ge=0, le=100)


# ═══════════════════════════════════════════════════════════════════════════════
# Motion Detection
# ═══════════════════════════════════════════════════════════════════════════════


class MotionDetectionResponse(BaseModel):
    """Current motion detection configuration from NVR."""

    enabled: bool = False
    sensitivity_level: int = 0
    grid_map: str | None = None


class MotionDetectionUpdateRequest(BaseModel):
    """Set motion detection configuration on a camera channel."""

    enabled: bool
    sensitivity_level: int = Field(50, ge=0, le=100)
    grid_map: str | None = Field(None, max_length=2000, description="Hex bitstring for 22×18 grid")


# ═══════════════════════════════════════════════════════════════════════════════
# Privacy Masks
# ═══════════════════════════════════════════════════════════════════════════════


class PrivacyMaskRegion(BaseModel):
    """A single privacy mask rectangular region."""

    id: int | None = None
    enabled: bool = True
    coordinates: list[dict] = Field(
        default_factory=list,
        description="List of {x, y} normalised coordinate pairs",
    )


class PrivacyMaskResponse(BaseModel):
    """Current privacy mask configuration."""

    enabled: bool = False
    regions: list[PrivacyMaskRegion] = Field(default_factory=list)


class PrivacyMaskUpdateRequest(BaseModel):
    """Set privacy mask configuration on a camera channel."""

    enabled: bool
    regions: list[PrivacyMaskRegion] = Field(default_factory=list, max_length=8)


# ═══════════════════════════════════════════════════════════════════════════════
# Line Crossing Detection
# ═══════════════════════════════════════════════════════════════════════════════


class LineCrossingRule(BaseModel):
    """A single line-crossing detection rule."""

    id: int | None = None
    enabled: bool = True
    sensitivity: int = Field(50, ge=0, le=100)
    direction: str = Field("both", description="both | left-to-right | right-to-left")
    coordinates: list[dict] = Field(
        default_factory=list,
        description="Start/end points [{x,y}, {x,y}]",
    )


class LineCrossingResponse(BaseModel):
    """Current line crossing detection configuration."""

    enabled: bool = False
    rules: list[LineCrossingRule] = Field(default_factory=list)


class LineCrossingUpdateRequest(BaseModel):
    """Set line crossing detection configuration."""

    enabled: bool
    rules: list[LineCrossingRule] = Field(default_factory=list, max_length=4)


# ═══════════════════════════════════════════════════════════════════════════════
# Intrusion Detection (Field Detection)
# ═══════════════════════════════════════════════════════════════════════════════


class IntrusionDetectionRule(BaseModel):
    """A single intrusion / field detection rule."""

    id: int | None = None
    enabled: bool = True
    sensitivity: int = Field(50, ge=0, le=100)
    time_threshold: int = Field(0, ge=0, le=10, description="Seconds before trigger")
    coordinates: list[dict] = Field(
        default_factory=list,
        description="Polygon [{x,y}, …]",
    )


class IntrusionDetectionResponse(BaseModel):
    """Current intrusion (field) detection configuration."""

    enabled: bool = False
    rules: list[IntrusionDetectionRule] = Field(default_factory=list)


class IntrusionDetectionUpdateRequest(BaseModel):
    """Set intrusion detection configuration."""

    enabled: bool
    rules: list[IntrusionDetectionRule] = Field(default_factory=list, max_length=4)


# ═══════════════════════════════════════════════════════════════════════════════
# Face Detection
# ═══════════════════════════════════════════════════════════════════════════════


class FaceDetectionResponse(BaseModel):
    """Current face detection configuration."""

    enabled: bool = False
    sensitivity: int = Field(50, ge=0, le=100)
    snap_interval: int = Field(0, ge=0, description="Snapshot capture interval (0=every frame)")
    generation_speed: int = Field(3, ge=1, le=5)
    min_width: int = 0
    min_height: int = 0
    max_width: int = 0
    max_height: int = 0


class FaceDetectionUpdateRequest(BaseModel):
    """Set face detection configuration."""

    enabled: bool
    sensitivity: int = Field(50, ge=0, le=100)
    snap_interval: int = Field(0, ge=0)
    generation_speed: int = Field(3, ge=1, le=5)


# ═══════════════════════════════════════════════════════════════════════════════
# Holiday Schedule
# ═══════════════════════════════════════════════════════════════════════════════


class HolidayEntry(BaseModel):
    """A single NVR holiday definition."""

    id: int = 0
    enabled: bool = True
    name: str = ""
    mode: str = Field("date", description="date | week | month")
    start_month: int = Field(1, ge=1, le=12)
    start_day: int = Field(1, ge=1, le=31)
    end_month: int = Field(1, ge=1, le=12)
    end_day: int = Field(1, ge=1, le=31)


class HolidayListResponse(BaseModel):
    """List of NVR-level holidays."""

    holidays: list[HolidayEntry] = Field(default_factory=list)


class HolidayUpdateRequest(BaseModel):
    """Update NVR-level holidays."""

    holidays: list[HolidayEntry] = Field(default_factory=list, max_length=32)


class HolidayScheduleResponse(BaseModel):
    """Holiday recording schedule for a channel (same shape as weekly schedule)."""

    enabled: bool = False
    days: list[ScheduleDay] = Field(default_factory=list)


class HolidayScheduleUpdateRequest(BaseModel):
    """Set holiday recording schedule for a channel."""

    enabled: bool
    days: list[ScheduleDay] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# PTZ Tours / Patrols
# ═══════════════════════════════════════════════════════════════════════════════


class PTZPatrolAction(BaseModel):
    """A single step in a PTZ patrol (visit a preset with dwell time)."""

    id: int = 0
    preset_id: int = Field(..., ge=1, le=255)
    dwell: int = Field(10, ge=1, le=300, description="Seconds to stay at preset")
    speed: int = Field(50, ge=1, le=100)


class PTZPatrolResponse(BaseModel):
    """A PTZ patrol / tour."""

    id: int
    name: str = ""
    enabled: bool = True
    actions: list[PTZPatrolAction] = Field(default_factory=list)


class PTZPatrolCreateRequest(BaseModel):
    """Create or update a PTZ patrol."""

    name: str = Field(..., min_length=1, max_length=50)
    enabled: bool = True
    actions: list[PTZPatrolAction] = Field(..., min_length=1, max_length=32)


class PTZPatrolStartStop(BaseModel):
    """Response for start/stop patrol."""

    success: bool
    status_code: int | None = (
        None  # ═══════════════════════════════════════════════════════════════════════════════
    )


# Smart Capabilities
# ═══════════════════════════════════════════════════════════════════════════════


class SmartCapabilitiesResponse(BaseModel):
    """Which smart / AI features a camera channel supports."""

    motion_detection: bool = False
    line_crossing: bool = False
    intrusion_detection: bool = False
    privacy_mask: bool = False
    face_detection: bool = False
    vehicle_detection: bool = False
    person_detection: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# Recording Schedule
# ═══════════════════════════════════════════════════════════════════════════════


class ScheduleTimeBlock(BaseModel):
    """A time range within a weekday."""

    begin_time: str = Field("00:00", description="HH:MM begin time")
    end_time: str = Field("23:59", description="HH:MM end time")
    record_type: str = Field("continuous", description="continuous | motion | alarm | none")


class ScheduleDay(BaseModel):
    """Single day schedule (NVR returns id 1=Mon … 7=Sun)."""

    id: int = Field(0, ge=0, description="Day index from NVR (1=Mon … 7=Sun)")
    action_type: str = "record"
    time_blocks: list[ScheduleTimeBlock] = Field(default_factory=list)


class RecordingScheduleResponse(BaseModel):
    """Current recording schedule on a channel.

    ``supported`` is False when the NVR doesn't expose a per-channel recording
    schedule via ISAPI (many NVR models 401/403 the per-channel schedule path
    because recording is managed at the NVR level). The endpoint returns 200
    with supported=False in that case instead of a 502, so the UI can show an
    honest "managed by NVR" message rather than a server-error banner.
    """

    supported: bool = True
    enabled: bool = False
    days: list[ScheduleDay] = Field(default_factory=list)


class RecordingScheduleUpdateRequest(BaseModel):
    """Set recording schedule on a channel."""

    enabled: bool
    days: list[ScheduleDay] = Field(default_factory=list, max_length=7)


class RecordingScheduleTemplateResponse(BaseModel):
    """Saved schedule template."""

    id: UUID
    name: str
    description: str | None = None
    is_builtin: bool = False
    schedule: dict = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class RecordingScheduleTemplateCreateRequest(BaseModel):
    """Create a schedule template."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=500)
    schedule: dict = Field(..., description="JSON schedule definition")

    @field_validator("schedule")
    @classmethod
    def _validate_schedule_size(cls, v: dict) -> dict:
        """Limit schedule size to prevent storage abuse."""
        import json

        encoded = json.dumps(v)
        if len(encoded) > 64_000:
            raise ValueError("Schedule definition too large (max 64KB)")
        return v


# ═══════════════════════════════════════════════════════════════════════════════
# Video Clip Export
# ═══════════════════════════════════════════════════════════════════════════════


class VideoExportRequest(BaseModel):
    """Request to download a video clip from NVR."""

    start_time: datetime
    end_time: datetime
    playback_uri: str | None = Field(
        None,
        description="Specific track URI; auto-resolved if omitted",
        max_length=500,
    )
    watermark: bool = Field(
        True,
        description="Burn a chain-of-custody overlay (operator + export time) into the "
        "clip via ffmpeg. When false, the original NVR bytes stream unchanged.",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Camera Health Monitoring
# ═══════════════════════════════════════════════════════════════════════════════


class CameraHealthResponse(BaseModel):
    """Live health / bandwidth for a single camera."""

    camera_id: UUID
    is_online: bool = False
    bitrate_kbps: int | None = None
    frame_rate: int | None = None
    codec: str | None = None
    resolution_width: int | None = None
    resolution_height: int | None = None
    captured_at: datetime | None = None


class CameraHealthHistoryResponse(BaseModel):
    """Historical health snapshots for chart display."""

    camera_id: UUID
    snapshots: list[CameraHealthResponse] = Field(default_factory=list)


class ChannelStatusItem(BaseModel):
    """NVR channel online/offline status."""

    id: int
    name: str = ""
    online: bool = False
    ip_address: str | None = None


class NVRChannelStatusResponse(BaseModel):
    """All channel statuses for an NVR."""

    nvr_id: UUID
    channels: list[ChannelStatusItem] = Field(default_factory=list)


class FleetHealthSummary(BaseModel):
    """Summary health statistics across all cameras."""

    total_cameras: int = 0
    online_cameras: int = 0
    offline_cameras: int = 0
    avg_bitrate_kbps: float = 0.0
    total_bandwidth_mbps: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Streaming & Tokens
# ═══════════════════════════════════════════════════════════════════════════════


class StreamUrlResponse(BaseModel):
    """Live stream URL result."""

    url: str
    protocol: str


class StreamTokenResponse(BaseModel):
    """Short-lived JWT stream token."""

    token: str
    expires_in: int = 60


class NvrConnectionStatsItem(BaseModel):
    """Per-NVR connection statistics."""

    active: int = 0
    max: int = 6
    available: int = 6


class StreamStatsResponse(BaseModel):
    """Global stream pool statistics."""

    active_streams: int = 0
    target_fps: float = 10.0
    frame_interval_ms: float = 100.0
    per_nvr: dict[str, NvrConnectionStatsItem] = Field(default_factory=dict)
    overloaded_nvrs: list[str] = Field(default_factory=list)
    snapshot_cache_channels: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# PTZ Response Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class PTZPresetItem(BaseModel):
    """A single PTZ preset."""

    id: int | str
    name: str = ""
    enabled: bool = True


class PTZPresetsListResponse(BaseModel):
    """List of PTZ presets for a camera."""

    items: list[PTZPresetItem] = Field(default_factory=list)


class PTZActionResponse(BaseModel):
    """Generic PTZ action result."""

    status: str = "ok"


# ═══════════════════════════════════════════════════════════════════════════════
# Recording Response Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class RecordingItem(BaseModel):
    """A recording entry from search results."""

    id: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    recording_type: str | None = None
    duration_seconds: float | None = None
    channel: int | None = None
    file_size: int | None = None


class RecordingSearchResponse(BaseModel):
    """Recording search results."""

    items: list[RecordingItem] = Field(default_factory=list)
    total: int = 0


class PlaybackUrlResponse(BaseModel):
    """Playback URL for a recording."""

    url: str
    protocol: str = "rtsp"


class LockRecordingResponse(BaseModel):
    """Recording lock result."""

    status: str = "ok"
    locked: bool


# ═══════════════════════════════════════════════════════════════════════════════
# Image Settings
# ═══════════════════════════════════════════════════════════════════════════════


class ImageSettingsResponse(BaseModel):
    """Camera image settings."""

    brightness: int | None = None
    contrast: int | None = None
    saturation: int | None = None
    sharpness: int | None = None
    hue: int | None = None
    wide_dynamic_range: int | None = None
    backlight_compensation: int | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# NVR Detail Responses
# ═══════════════════════════════════════════════════════════════════════════════


class NVRChannelItem(BaseModel):
    """A single NVR channel (backed by a managed Camera row).

    ``id`` is the Camera UUID (string) — the frontend channels list navigates
    to ``/cameras/{id}`` — and ``channel_id`` is the NVR's integer channel
    index. The previous schema declared ``id: int`` (channel number), which
    collided with the Camera UUID the service returns and raised 16 validation
    errors → 500 on every Hikvision NVR channels fetch.
    """

    id: str
    name: str = ""
    channel_id: int | None = None
    status: str | None = None
    ip_address: str | None = None
    camera_type: str | None = None
    has_ptz: bool = False
    has_audio: bool = False
    is_recording: bool = False
    model: str | None = None
    vendor: str | None = None
    resolution: str | None = None
    codec: str | None = None


class NVRChannelsListResponse(BaseModel):
    """List of NVR channels."""

    items: list[NVRChannelItem] = Field(default_factory=list)
    total: int = 0


class NVRSystemInfoResponse(BaseModel):
    """NVR system information (passthrough from adapter)."""

    data: dict[str, Any] = Field(default_factory=dict)


class NVRNetworkResponse(BaseModel):
    """NVR network configuration."""

    data: dict[str, Any] = Field(default_factory=dict)


class NVRRecordingStatusResponse(BaseModel):
    """NVR recording track status.

    ``data`` is the per-channel list of recording tracks from the NVR
    (get_recording_tracks → list of dicts). It was previously typed as a
    dict, so every NVR returning the real list failed response validation
    → 500. The frontend reads it as ``RecordingTrack[]``.
    """

    data: list[dict[str, Any]] = Field(default_factory=list)


class NVRRecordingSearchResponse(BaseModel):
    """NVR recording search results."""

    data: dict[str, Any] = Field(default_factory=dict)


class NVRRebootResponse(BaseModel):
    """NVR reboot result."""

    status: str = "ok"
    message: str = ""


class NVRPlaybackResponse(BaseModel):
    """NVR playback stream info."""

    data: dict[str, Any] = Field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# Generic Status Responses
# ═══════════════════════════════════════════════════════════════════════════════


class StatusResponse(BaseModel):
    """Generic status-only response."""

    status: str = "ok"


class StatusIdResponse(BaseModel):
    """Generic status + resource ID response."""

    status: str = "ok"
    id: str


class DeletedResponse(BaseModel):
    """Generic deletion confirmation."""

    status: str = "ok"
    deleted: int | str


# ═══════════════════════════════════════════════════════════════════════════════
# Camera Groups Response Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class GroupSummaryItem(BaseModel):
    """Group summary in list response."""

    id: str
    name: str
    description: str | None = None
    color: str = "#3b82f6"
    icon: str = "folder"
    sort_order: int = 0
    is_default: bool = False
    camera_count: int = 0
    created_at: str | None = None


class GroupListResponse(BaseModel):
    """List of camera groups."""

    items: list[GroupSummaryItem] = Field(default_factory=list)
    total: int = 0


class GroupCreateResponse(BaseModel):
    """Newly created group."""

    id: str
    name: str
    color: str = "#3b82f6"
    icon: str = "folder"


class GroupMemberItem(BaseModel):
    """Camera member of a group."""

    camera_id: str
    sort_order: int = 0
    name: str = ""
    status: str | None = None


class GroupDetailResponse(BaseModel):
    """Full group detail with member cameras."""

    id: str
    name: str
    description: str | None = None
    color: str = "#3b82f6"
    icon: str = "folder"
    sort_order: int = 0
    is_default: bool = False
    camera_count: int = 0
    cameras: list[GroupMemberItem] = Field(default_factory=list)
    created_at: str | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# Camera Views Response Schemas
# ═══════════════════════════════════════════════════════════════════════════════


class ViewSummaryItem(BaseModel):
    """View summary in list response."""

    id: str
    name: str
    description: str | None = None
    layout: str | None = None
    camera_ids: list[str] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)
    is_default: bool = False
    is_shared: bool = False
    is_owner: bool = False
    sort_order: int = 0
    created_at: str | None = None


class ViewListResponse(BaseModel):
    """List of camera views."""

    items: list[ViewSummaryItem] = Field(default_factory=list)
    total: int = 0


class ViewCreateResponse(BaseModel):
    """Newly created view."""

    id: str
    name: str
    layout: str | None = None
    camera_ids: list[str] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Camera Access Control (Per-Camera RBAC)
# ═══════════════════════════════════════════════════════════════════════════════


class CameraAccessGrantCreate(BaseModel):
    """Create a per-camera or per-group access grant."""

    user_id: UUID
    camera_id: UUID | None = None
    group_id: UUID | None = None
    access_level: str = Field("viewer", pattern=r"^(viewer|operator|full)$")
    can_live: bool = True
    can_playback: bool = False
    can_ptz: bool = False
    can_export: bool = False
    can_configure: bool = False
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def _validate_target(self) -> CameraAccessGrantCreate:
        if self.camera_id and self.group_id:
            raise ValueError("Specify exactly one of camera_id or group_id, not both")
        if not self.camera_id and not self.group_id:
            raise ValueError("One of camera_id or group_id is required")
        return self


class CameraAccessGrantUpdate(BaseModel):
    """Update an existing access grant."""

    access_level: str | None = Field(None, pattern=r"^(viewer|operator|full)$")
    can_live: bool | None = None
    can_playback: bool | None = None
    can_ptz: bool | None = None
    can_export: bool | None = None
    can_configure: bool | None = None
    expires_at: datetime | None = None


class CameraAccessGrantResponse(BaseModel):
    """Camera access grant detail."""

    id: UUID
    user_id: UUID
    camera_id: UUID | None = None
    group_id: UUID | None = None
    access_level: str
    can_live: bool = True
    can_playback: bool = False
    can_ptz: bool = False
    can_export: bool = False
    can_configure: bool = False
    expires_at: datetime | None = None
    created_at: datetime | None = None
    # Denormalized user info (for display in frontend)
    user_email: str | None = None
    user_name: str | None = None

    model_config = {"from_attributes": True}


class CameraAccessGrantListResponse(BaseModel):
    """List of camera access grants."""

    items: list[CameraAccessGrantResponse] = Field(default_factory=list)
    total: int = 0


class CameraAccessCheckResponse(BaseModel):
    """Result of checking a user's effective permissions on a camera."""

    has_access: bool = False
    access_level: str | None = None
    can_live: bool = False
    can_playback: bool = False
    can_ptz: bool = False
    can_export: bool = False
    can_configure: bool = False
    grant_source: str | None = None  # "role", "camera_grant", "group_grant"


# =============================================================================
# HLS Streaming
# =============================================================================


class HLSSessionStartRequest(BaseModel):
    quality: str = Field("source", pattern=r"^(low|medium|high|source)$")


class TimelineSegment(BaseModel):
    """A contiguous recorded segment on a camera's timeline (REAL UTC ISO)."""

    start: str
    end: str
    type: str = "continuous"


class CameraTimelineResponse(BaseModel):
    """Recorded-footage availability for a camera over a time window — the data
    behind the Protect-style scrubber (segments + the gaps between them)."""

    segments: list[TimelineSegment] = Field(default_factory=list)
    start: str
    end: str
    supported: bool = True


class PlaybackHLSStartRequest(BaseModel):
    """Start a RECORDED-playback HLS session from an absolute instant.

    ``quality`` defaults to ``low`` (transcoded H.264 ~360p) because that is the
    only setting that sustains real-time on a 4K-HEVC source AND plays in every
    browser; ``source`` copies the original HEVC (real-time, HEVC-capable
    clients only). ``duration_s`` is the forward window per session (10s..1h).
    """

    start_time: datetime
    quality: str = Field("low", pattern=r"^(low|medium|high|source)$")
    duration_s: int = Field(600, ge=10, le=3600)


class HLSSessionStartResponse(BaseModel):
    session_id: str
    playlist_url: str
    heartbeat_url: str
    codec: str  # "h264_copy" or "h264_transcode"
    quality: str


class HLSHeartbeatResponse(BaseModel):
    alive: bool
    viewers: int = 0


class HLSStatsResponse(BaseModel):
    active_sessions: int
    total_viewers: int
    sessions: list[dict] = Field(default_factory=list)


# =============================================================================
# Cross-site Recording Search
# =============================================================================


class CrossSiteRecordingSearchRequest(BaseModel):
    site_ids: list[UUID] | None = Field(None, max_length=100)
    camera_ids: list[UUID] | None = Field(None, max_length=500)
    start_time: datetime | None = None
    end_time: datetime | None = None
    event_type: str | None = None
    recording_type: str | None = None


class CrossSiteRecordingResult(BaseModel):
    camera_id: UUID
    camera_name: str
    site_id: UUID | None = None
    site_name: str | None = None
    nvr_id: UUID | None = None
    start_time: datetime
    end_time: datetime | None = None
    duration_seconds: int | None = None
    recording_type: str | None = None
    file_size_bytes: int | None = None
    source: str = "db"  # "db" or "nvr_live"


class CrossSiteRecordingSearchResponse(BaseModel):
    results: list[CrossSiteRecordingResult] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 50


# =============================================================================
# Scheduled Reports
# =============================================================================


class CameraReportResponse(BaseModel):
    id: UUID
    report_type: str
    period_start: datetime
    period_end: datetime
    data: dict = Field(default_factory=dict)
    generated_at: datetime
    model_config = {"from_attributes": True}


class CameraReportListResponse(BaseModel):
    items: list[CameraReportResponse] = Field(default_factory=list)
    total: int = 0


# =============================================================================
# Two-way Audio
# =============================================================================


class AudioSessionResponse(BaseModel):
    status: Literal["started", "stopped"]
    camera_id: UUID
    codec: str = "g711u"
    sample_rate: int = 8000


class AudioSessionStopResponse(BaseModel):
    status: str = "stopped"


# =============================================================================
# Codec / Transcode Info
# =============================================================================


class CodecDetectionResponse(BaseModel):
    codec: str  # "h264", "h265", "unknown"
    resolution: str | None = None
    bitrate_kbps: int | None = None
    needs_transcode: bool = False


# =============================================================================
# Thermal Camera
# =============================================================================


class ThermalCapabilitiesResponse(BaseModel):
    is_thermal: bool = False
    supported: bool = False
    min_temp: float | None = None
    max_temp: float | None = None
    current_temp: float | None = None
    emissivity: float | None = None
    palette: str | None = None


class ThermalThresholdRequest(BaseModel):
    min_temp: float = Field(..., ge=-40, le=550)
    max_temp: float = Field(..., ge=-40, le=550)
    alert_enabled: bool = True

    @model_validator(mode="after")
    def check_temp_order(self) -> ThermalThresholdRequest:
        if self.min_temp >= self.max_temp:
            raise ValueError("min_temp must be less than max_temp")
        return self


class ThermalThresholdResponse(BaseModel):
    min_temp: float
    max_temp: float
    alert_enabled: bool = True
    status: str = "ok"


# =============================================================================
# LPR (License Plate Recognition)
# =============================================================================


class LPRConfigRequest(BaseModel):
    enabled: bool = True
    provider: str = Field("plate_recognizer", pattern=r"^(plate_recognizer|openalpr|custom)$")
    # SSRF: the api_url is dereferenced by the backend on every LPR
    # request (sending base64-encoded snapshots to the provider). An
    # admin could otherwise point this at http://127.0.0.1:6379 or
    # cloud metadata IPs and exfiltrate via the LPR fetch.
    api_url: str = Field("", max_length=2048)
    api_key: str = Field("", max_length=512)
    regions: list[str] = Field(default_factory=list, max_length=50)
    confidence_threshold: float = Field(0.7, ge=0.0, le=1.0)

    @field_validator("api_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return _validate_url_not_ssrf(v) or ""


class LPRConfigResponse(BaseModel):
    enabled: bool = False
    provider: str = ""
    api_url: str = ""
    has_api_key: bool = False
    regions: list[str] = Field(default_factory=list)
    confidence_threshold: float = 0.7


class LPRReadResult(BaseModel):
    plate_text: str
    confidence: float
    vehicle_type: str | None = None
    region: str | None = None
    camera_id: UUID
    camera_name: str | None = None
    timestamp: datetime
    snapshot_available: bool = False


class LPRSearchResponse(BaseModel):
    results: list[LPRReadResult] = Field(default_factory=list)
    total: int = 0


# =============================================================================
# AI Scene Labeling
# =============================================================================


class SceneLabelResponse(BaseModel):
    labels: list[str] = Field(default_factory=list)
    analyzed_at: datetime | None = None
    camera_id: UUID


# =============================================================================
# PTZ Auto-tracking
# =============================================================================


class PTZAutoTrackingResponse(BaseModel):
    supported: bool = False
    enabled: bool = False
    track_duration_sec: int = 30
    sensitivity: int = 50


class PTZAutoTrackingRequest(BaseModel):
    enabled: bool
    track_duration_sec: int = Field(30, ge=5, le=300)
    sensitivity: int = Field(50, ge=1, le=100)


# =============================================================================
# Time Sync Drift Detection
# =============================================================================


class TimeDriftEntry(BaseModel):
    nvr_id: UUID
    nvr_name: str
    drift_seconds: float
    device_time: str
    server_time: str
    severity: Literal["normal", "warning", "critical"] = "normal"


class TimeDriftSummaryResponse(BaseModel):
    threshold_seconds: int = 30
    total_nvrs: int = 0
    drifted_count: int = 0
    drifted: list[TimeDriftEntry] = Field(default_factory=list)
