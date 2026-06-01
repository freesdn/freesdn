# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VoIP Module Schemas
==================================

Pydantic request/response schemas for VoIP API endpoints.
GDMS-style fleet management schemas included.
"""

import re
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# A MAC is 12 hex digits with optional :/- separators (or bare). Validated on
# Phone create/update because the value becomes a provisioning-config FILENAME
# downstream — a non-MAC like '../../x' is a path-traversal write vector
# The provisioning sink re-checks too (defense-in-depth), since
# discovery-ingested MACs bypass this schema.
_MAC_ADDRESS_RE = re.compile(r"^(?:[0-9a-fA-F]{2}([:-]?)){5}[0-9a-fA-F]{2}$|^[0-9a-fA-F]{12}$")


def _validate_mac_address(v: str | None) -> str | None:
    if v is None or v == "":
        return v
    if not _MAC_ADDRESS_RE.match(v):
        raise ValueError("mac_address must be 12 hex digits (optional ':'/'-' separators)")
    return v


def _validate_firmware_url_ssrf(url: str | None) -> str | None:
    """SSRF guard on FirmwareTrackCreate.download_url.

    Phones (Grandstream GXP and similar) fetch firmware from this URL
    on upgrade triggers. Without an SSRF check an admin could:
    - Set download_url to ``file:///etc/passwd`` and have the agent
      attempt to read local files (some vendors honor file://)
    - Set it to ``http://127.0.0.1:8000/...`` to probe the backend
    - Use ``gopher://`` / SMB / TFTP schemes for protocol smuggling
    Allow https:// or http:// (some vendor firmware servers don't
    have HTTPS); block any other scheme; route hostname through the
    central validate_target_host() guard.
    """
    if url is None or url.strip() == "":
        return url
    s = url.strip()
    if len(s) > 500:
        raise ValueError("download_url exceeds 500 chars")
    from urllib.parse import urlparse

    try:
        parsed = urlparse(s)
    except Exception as exc:
        raise ValueError(f"download_url malformed: {exc}") from exc
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"download_url must use http/https, got {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("download_url missing host")
    from app.core.security_utils import validate_target_host

    try:
        validate_target_host(host)
    except ValueError as exc:
        raise ValueError(f"download_url SSRF check failed: {exc}") from exc
    return s


# =============================================================================
# Enums
# =============================================================================


class PBXType(StrEnum):
    """Supported PBX system types."""

    ASTERISK = "asterisk"
    FREEPBX = "freepbx"
    FREESWITCH = "freeswitch"
    THREE_CX = "3cx"
    OTHER = "other"


class ConnectionStatus(StrEnum):
    """PBX connection test status."""

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    AUTH_ERROR = "auth_error"


# =============================================================================
# PBX Schemas
# =============================================================================


class PBXCreate(BaseModel):
    """Schema for creating a new PBX connection."""

    site_id: UUID | None = Field(
        default=None,
        description="Site to scope the PBX to. Auto-resolved if omitted.",
    )
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    pbx_type: PBXType = PBXType.FREEPBX
    ip_address: str = Field(..., min_length=1, max_length=45)
    api_port: int = Field(default=443, ge=1, le=65535)
    sip_port: int = Field(default=5060, ge=1, le=65535)
    is_active: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)

    # Connection credentials (stored in settings)
    api_username: str | None = None
    api_password: str | None = None
    api_key: str | None = None
    # OAuth2 client_credentials (FreePBX 16+ Admin API → M2M Application).
    # When BOTH set, the adapter prefers OAuth2 + GraphQL over web-session
    # auth (78 query fields, 105 mutations on a stock install). Secret is
    # encrypted at rest in ``api_client_secret_enc``.
    api_client_id: str | None = None
    api_client_secret: str | None = None
    # Per-PBX TLS verification acknowledgement. False (default) means the
    # adapter refuses to connect with ``verify_ssl=False``. True means the
    # operator explicitly accepts the downgrade (self-signed / expired
    # cert). The acknowledgement gate is enforced in
    # ``service._adapter_from_pbx``; this flag is audit-logged.
    tls_verify_disabled_acknowledged: bool = False


class PBXUpdate(BaseModel):
    """Schema for updating a PBX connection."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    pbx_type: PBXType | None = None
    ip_address: str | None = Field(default=None, min_length=1, max_length=45)
    api_port: int | None = Field(default=None, ge=1, le=65535)
    sip_port: int | None = Field(default=None, ge=1, le=65535)
    is_active: bool | None = None
    settings: dict[str, Any] | None = None
    api_username: str | None = None
    api_password: str | None = None
    api_key: str | None = None
    api_client_id: str | None = None
    api_client_secret: str | None = None
    tls_verify_disabled_acknowledged: bool | None = None


class PBXTestConnection(BaseModel):
    """Schema for testing PBX connectivity."""

    pbx_type: PBXType = PBXType.FREEPBX
    ip_address: str = Field(..., min_length=1, max_length=45)
    api_port: int = Field(default=443, ge=1, le=65535)
    api_username: str | None = None
    api_password: str | None = None
    api_key: str | None = None
    api_client_id: str | None = None
    api_client_secret: str | None = None
    verify_ssl: bool = True


class PBXTestResult(BaseModel):
    """Response from a PBX connection test."""

    status: ConnectionStatus
    message: str
    pbx_version: str | None = None
    extensions_found: int | None = None
    response_time_ms: float | None = None


class PBXResponse(BaseModel):
    """PBX system response."""

    id: UUID
    site_id: UUID
    name: str
    description: str | None = None
    pbx_type: str
    ip_address: str
    api_port: int
    sip_port: int
    is_active: bool
    last_seen: datetime | None = None
    settings: dict[str, Any] = {}
    # Computed count of non-deleted extensions (populated by the list/detail
    # endpoints) — the PBX list surfaces this as a column/stat.
    extension_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True

    @field_validator("settings", mode="before")
    @classmethod
    def strip_sensitive_settings(cls, v: Any) -> dict[str, Any]:
        """Remove credential fields from the settings dict before serialization."""
        if not isinstance(v, dict):
            return {}
        _sensitive = {
            "api_password",
            "api_key",
            "ami_secret",
            "ami_password",
            "ari_password",
            "web_password",
        }
        return {k: val for k, val in v.items() if k not in _sensitive}


# =============================================================================
# PBX Dashboard & System Info
# =============================================================================


class PBXDashboard(BaseModel):
    """Comprehensive PBX dashboard statistics."""

    pbx_id: UUID
    name: str
    pbx_type: str
    status: str = "unknown"
    uptime: str | None = None
    asterisk_version: str | None = None
    total_extensions: int = 0
    online_extensions: int = 0
    total_trunks: int = 0
    active_calls: int = 0
    calls_today: int = 0
    voicemail_boxes: int = 0
    unread_voicemails: int = 0
    ring_groups: int = 0
    queues: int = 0
    ivrs: int = 0
    ami_connected: bool = False
    ari_connected: bool = False
    rest_available: bool = False
    last_sync: datetime | None = None


class PBXSystemInfo(BaseModel):
    """Detailed PBX system information from adapter."""

    host: str
    asterisk_version: str | None = None
    freepbx_version: str | None = None
    ami_connected: bool = False
    ari_connected: bool = False
    rest_available: bool = False
    ari_info: dict[str, Any] | None = None
    freepbx_status: dict[str, Any] | None = None


# =============================================================================
# PBX Sub-resource Schemas (Trunks, Queues, IVR, Active Calls)
# =============================================================================


class TrunkResponse(BaseModel):
    """SIP Trunk information."""

    trunk_id: str | None = None
    name: str
    trunk_type: str | None = None
    technology: str | None = None
    host: str | None = None
    port: int | None = None
    username: str | None = None
    status: str | None = None
    channels_used: int = 0
    max_channels: int | None = None
    provider: str | None = None
    settings: dict[str, Any] = {}


class QueueResponse(BaseModel):
    """Call queue information."""

    name: str
    display_name: str | None = None
    strategy: str | None = None
    members: list[dict[str, Any]] = []
    member_count: int = 0
    callers_waiting: int = 0
    calls_taken: int = 0
    holdtime: int = 0
    talk_time: int = 0
    completed: int = 0
    abandoned: int = 0
    service_level: float | None = None
    settings: dict[str, Any] = {}


class IVRResponse(BaseModel):
    """IVR menu information."""

    ivr_id: str | None = None
    name: str
    description: str | None = None
    announcement: str | None = None
    direct_dial: bool = False
    timeout: int = 10
    entries: list[dict[str, Any]] = []
    settings: dict[str, Any] = {}


class ActiveCallResponse(BaseModel):
    """Active call / channel information."""

    channel: str
    caller_id_name: str | None = None
    caller_id_num: str | None = None
    connected_line_name: str | None = None
    connected_line_num: str | None = None
    state: str | None = None
    application: str | None = None
    duration: int = 0
    bridge_id: str | None = None
    context: str | None = None
    extension: str | None = None


class VoicemailBoxResponse(BaseModel):
    """Voicemail box information."""

    mailbox: str
    context: str | None = None
    name: str | None = None
    email: str | None = None
    new_messages: int = 0
    old_messages: int = 0
    settings: dict[str, Any] = {}


# =============================================================================
# PBX Extension CRUD
# =============================================================================


class ExtensionCreate(BaseModel):
    """Create a new extension on the PBX."""

    extension_number: str = Field(..., min_length=1, max_length=20, pattern=r"^\d{1,20}$")
    display_name: str = Field(..., min_length=1, max_length=255)
    caller_id_name: str | None = Field(default=None, max_length=255)
    caller_id_number: str | None = Field(default=None, max_length=20, pattern=r"^[\d*#+]*$")
    voicemail_enabled: bool = True
    voicemail_pin: str | None = Field(default=None, min_length=4, max_length=10, pattern=r"^\d+$")
    password: str | None = Field(default=None, min_length=8, max_length=128)
    settings: dict[str, Any] = Field(default_factory=dict)


class ExtensionUpdate(BaseModel):
    """Update an extension on the PBX."""

    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    caller_id_name: str | None = Field(default=None, max_length=255)
    caller_id_number: str | None = Field(default=None, max_length=20, pattern=r"^[\d*#+]*$")
    voicemail_enabled: bool | None = None
    voicemail_pin: str | None = Field(default=None, min_length=4, max_length=10, pattern=r"^\d+$")
    is_active: bool | None = None
    settings: dict[str, Any] | None = None


# =============================================================================
# PBX Ring Group CRUD
# =============================================================================


class RingGroupCreate(BaseModel):
    """Create a new ring group on the PBX.

    Mirrors :class:`ExtensionCreate` — minimal required surface (the
    group number + a human name), the rest defaulted to FreePBX-sane
    values. ``members`` is the list of extension numbers that ring.
    """

    pbx_id: UUID = Field(..., description="PBX the ring group belongs to")
    group_number: str = Field(..., min_length=1, max_length=20, pattern=r"^\d{1,20}$")
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=255)
    ring_strategy: str = Field(
        default="ringall",
        pattern=r"^(ringall|ringall-prim|hunt|memoryhunt|"
        r"firstavail|firstnotonphone|random|rrmemory|rrordered)$",
    )
    ring_time: int = Field(default=20, ge=1, le=300)
    members: list[str] = Field(
        default_factory=list,
        description="Extension numbers that ring (in order for sequential strategies)",
    )
    settings: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# PBX Call Control
# =============================================================================


class OriginateCallRequest(BaseModel):
    """Originate an outbound call."""

    extension: str = Field(
        ...,
        min_length=1,
        max_length=20,
        pattern=r"^[0-9A-Za-z*#]+$",
        description="Extension to call from",
    )
    destination: str = Field(
        ...,
        min_length=1,
        max_length=40,
        pattern=r"^[0-9A-Za-z*#+]+$",
        description="Number/extension to dial",
    )
    caller_id: str | None = Field(default=None, max_length=80)
    context: str = Field(default="from-internal", pattern=r"^from-internal(-additional)?$")


class HangupCallRequest(BaseModel):
    """Hang up an active call."""

    channel: str = Field(
        ...,
        min_length=1,
        max_length=200,
        pattern=r"^(SIP|PJSIP|IAX2|Local|DAHDI)/[\w@/.\-]+$",
        description="Channel to hang up",
    )


class TransferCallRequest(BaseModel):
    """Transfer an active call."""

    channel: str = Field(
        ...,
        min_length=1,
        max_length=200,
        pattern=r"^(SIP|PJSIP|IAX2|Local|DAHDI)/[\w@/.\-]+$",
        description="Active channel to transfer",
    )
    destination: str = Field(
        ...,
        min_length=1,
        max_length=40,
        pattern=r"^[0-9A-Za-z*#+]+$",
        description="Extension to transfer to",
    )
    context: str = Field(default="from-internal", pattern=r"^from-internal(-additional)?$")


class QueueMemberRequest(BaseModel):
    """Add/remove/pause a queue member."""

    queue_name: str = Field(..., min_length=1, max_length=80, pattern=r"^[\w\-]+$")
    interface: str = Field(
        ..., min_length=1, max_length=120, pattern=r"^(SIP|PJSIP|Local|IAX2|DAHDI)/[\w@.\-]+$"
    )
    member_name: str | None = Field(default=None, max_length=80)
    paused: bool | None = None
    reason: str | None = Field(default=None, max_length=200)


class ReloadConfigRequest(BaseModel):
    """Reload PBX configuration."""

    module: str | None = Field(
        default=None, description="Specific module to reload, or None for all"
    )


# =============================================================================
# Phone Schemas (Enhanced for GDMS-style fleet management)
# =============================================================================


class PhoneCreate(BaseModel):
    """Schema for creating a new phone.

    ``site_id`` is optional — when omitted, the endpoint resolves it
    from the user's globally-selected site (front-end ``siteStore``)
    via the ``X-Selected-Site`` header or falls back to the user's
    default/first accessible site. The Add Phone modal doesn't
    currently expose a Site picker, so the optional shape is what
    makes that flow work end-to-end.
    """

    site_id: UUID | None = None
    pbx_id: UUID | None = None
    extension_id: UUID | None = None
    config_template_id: UUID | None = None
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    ip_address: str | None = Field(default=None, max_length=45)
    mac_address: str | None = Field(default=None, max_length=17)
    vendor: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=100)
    firmware_version: str | None = None
    serial_number: str | None = None
    location: str | None = None
    status: str = "offline"
    lifecycle_state: str = "discovered"
    discovery_method: str = "manual"
    tags: list[str] = Field(default_factory=list)
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mac_address")
    @classmethod
    def _validate_mac(cls, v: str | None) -> str | None:
        return _validate_mac_address(v)


class PhoneUpdate(BaseModel):
    """Schema for updating a phone."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    pbx_id: UUID | None = None
    extension_id: UUID | None = None
    config_template_id: UUID | None = None
    ip_address: str | None = Field(default=None, max_length=45)
    mac_address: str | None = Field(default=None, max_length=17)
    vendor: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=100)
    firmware_version: str | None = None
    serial_number: str | None = None
    location: str | None = None
    status: str | None = None
    lifecycle_state: str | None = None
    firmware_target: str | None = None
    tags: list[str] | None = None
    settings: dict[str, Any] | None = None

    @field_validator("mac_address")
    @classmethod
    def _validate_mac(cls, v: str | None) -> str | None:
        return _validate_mac_address(v)


class PhoneResponse(BaseModel):
    """Full phone response with fleet management fields."""

    id: UUID
    site_id: UUID
    pbx_id: UUID | None = None
    extension_id: UUID | None = None
    config_template_id: UUID | None = None
    controller_id: UUID | None = None
    name: str
    description: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    status: str
    last_seen: datetime | None = None
    lifecycle_state: str
    discovery_method: str | None = None
    discovered_at: datetime | None = None
    onboarded_at: datetime | None = None
    provision_status: str | None = None
    last_provisioned_at: datetime | None = None
    config_checksum: str | None = None
    firmware_target: str | None = None
    uptime_seconds: int | None = None
    sip_registered: bool = False
    sip_server: str | None = None
    last_reboot: datetime | None = None
    cpu_usage: float | None = None
    memory_usage: float | None = None
    subnet: str | None = None
    vlan_id: int | None = None
    lldp_switch_port: str | None = None
    location: str | None = None
    tags: list[str] = []
    settings: dict[str, Any] = {}
    created_at: datetime | None = None
    updated_at: datetime | None = None

    # Joined fields populated by the service layer from voip.extensions
    # and voip.pbx when the phone is linked. The frontend uses these to
    # render the "Extension" column in the Phone Fleet table without
    # having to fan out one detail-fetch per row.
    extension: str | None = None
    extension_display: str | None = None
    pbx_system_id: UUID | None = None
    pbx_system_name: str | None = None
    sip_user: str | None = None

    class Config:
        from_attributes = True

    @field_validator("settings", mode="before")
    @classmethod
    def strip_phone_sensitive_settings(cls, v: Any) -> dict[str, Any]:
        """Remove credential fields from phone settings before serialization."""
        if not isinstance(v, dict):
            return {}
        _sensitive = {"web_password", "web_secret", "admin_password", "sip_password"}
        return {k: val for k, val in v.items() if k not in _sensitive}


class PhoneOnboardRequest(BaseModel):
    """Request to onboard a discovered phone into managed state.

    The phone is identified by the ``{phone_id}`` path parameter; the
    optional ``phone_id`` body field (if sent) is ignored by the service.
    """

    phone_id: UUID | None = None
    name: str | None = None
    pbx_id: UUID | None = None
    extension_id: UUID | None = None
    config_template_id: UUID | None = None
    location: str | None = None
    tags: list[str] = Field(default_factory=list)
    auto_provision: bool = True


class PhoneProvisionRequest(BaseModel):
    """Request to provision/re-provision a phone."""

    force: bool = False  # Force even if config unchanged
    reboot_after: bool = True  # Reboot phone after config push


# =============================================================================
# Phone Connection / Login Schemas
# =============================================================================


class PhoneCredentials(BaseModel):
    """Credentials for authenticating to phone web UIs during discovery."""

    username: str = Field(default="admin", max_length=64)
    password: str = Field(default="admin", max_length=128)


class PhoneConnectionTestRequest(BaseModel):
    """Request to test connectivity and login to a phone."""

    ip_address: str | None = Field(
        default=None,
        description="Phone IP address. If omitted, uses the phone's stored IP.",
    )
    username: str = Field(default="admin", max_length=64)
    password: str = Field(default="admin", max_length=128)
    save_credentials: bool = Field(
        default=False,
        description="Save credentials to the phone record on success.",
    )


class PhoneConnectionTestResult(BaseModel):
    """Result of a phone connection test."""

    success: bool
    status: str  # connected, identified, reachable, unreachable, locked_out, error
    ip_address: str
    mac_address: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    vendor: str | None = None
    authenticated: bool = False
    api_accessible: bool = False  # True if api.values.get returns data
    sip_registered: bool = False
    sip_account: str | None = None
    sip_registrar: str | None = None
    sip_accounts: list[dict[str, Any]] = []  # Per-account SIP config
    lockout_status: str | None = None  # ok, locked
    config_items: int | None = None  # metaconfig item count
    network_info: dict[str, str] = {}  # IP, VLAN, gateway, DNS from P-values
    auth_note: str | None = None  # Explains auth status (e.g. cross-subnet)
    error: str | None = None
    raw_data: dict[str, Any] = {}


# =============================================================================
# Discovery Schemas
# =============================================================================


class DiscoveryScanRequest(BaseModel):
    """Request to trigger a network discovery scan."""

    site_id: UUID | None = Field(
        default=None,
        description="Site to scope the scan to. Auto-resolved if omitted.",
    )
    scan_type: str = Field(default="full", pattern="^(full|arp|sip|http)$")
    subnet: str | None = Field(
        default=None, max_length=18, description="CIDR subnet to scan, e.g. 192.168.1.0/24"
    )
    port_range: str | None = Field(
        default=None, max_length=50, description="Port range for SIP probes, e.g. 5060-5061"
    )
    auto_onboard: bool = Field(default=False, description="Automatically onboard discovered phones")
    config_template_id: UUID | None = Field(
        default=None,
        alias="default_template_id",
        description="Template to assign to auto-onboarded phones",
    )
    credentials: PhoneCredentials | None = Field(
        default=None,
        description="Credentials for phone web UI login during discovery. "
        "Defaults to admin/admin if omitted.",
    )

    model_config = {"populate_by_name": True}

    @field_validator("config_template_id", mode="before")
    @classmethod
    def _empty_str_to_none(cls, v: Any) -> Any:
        if v == "":
            return None
        return v

    @field_validator("subnet", mode="before")
    @classmethod
    def _validate_cidr_subnet(cls, v: Any) -> Any:
        """Validate CIDR notation (e.g. 192.168.1.0/24). Max /16."""
        if v is None or v == "":
            return None
        import ipaddress

        try:
            net = ipaddress.ip_network(str(v), strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: {v}. Expected format like 192.168.1.0/24")
        if net.prefixlen < 16:
            raise ValueError(
                f"Subnet /{net.prefixlen} is too large. Maximum allowed is /16 (65,536 hosts)."
            )
        # SSRF guard: refuse subnets that fall in loopback / link-local /
        # multicast / reserved / unspecified ranges (e.g. 127.0.0.0/24,
        # 169.254.0.0/16 which covers the cloud-metadata IP). RFC1918 LANs are
        # the legitimate scan target and stay allowed. The expanded host list is
        # additionally filtered per-IP in discovery.py as defense in depth.
        if (
            net.is_loopback
            or net.is_link_local
            or net.is_multicast
            or net.is_reserved
            or net.is_unspecified
        ):
            raise ValueError(
                f"Subnet {net} targets a forbidden range "
                "(loopback / link-local / multicast / reserved)."
            )
        # Normalise to the network address form
        return str(net)


class DiscoveredDeviceResult(BaseModel):
    """Single discovered device from a scan."""

    ip_address: str
    mac_address: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    discovery_method: str
    is_new: bool = True
    existing_phone_id: UUID | None = None
    sip_registered: bool = False
    sip_account: str | None = None
    sip_registrar: str | None = None
    http_reachable: bool = False
    authenticated: bool = False
    raw_data: dict[str, Any] = {}


class DiscoveryScanResponse(BaseModel):
    """Response for a discovery scan."""

    id: UUID
    site_id: UUID
    scan_type: str
    subnet: str | None = None
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    devices_found: int = 0
    new_devices: int = 0
    updated_devices: int = 0
    duration_seconds: float = 0.0
    results: list[DiscoveredDeviceResult] = []
    error_message: str | None = None

    class Config:
        from_attributes = True


# =============================================================================
# Config Template Schemas
# =============================================================================


class ConfigTemplateCreate(BaseModel):
    """Schema for creating a configuration template."""

    # was required, so the create dialog (which has no site
    # picker) always 422'd. Now optional; the endpoint resolves it from the
    # selected site or the org's first site (mirrors Add Phone).
    # this field is client-controlled, so the create_template
    # endpoint validates a SUPPLIED site_id with assert_can_access_site and,
    # when auto-selecting, scopes to the caller's GRANTED sites; the
    # provisioning service re-checks site membership (defence in depth).
    site_id: UUID | None = None
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    vendor: str = Field(..., min_length=1, max_length=100)
    model_pattern: str | None = Field(default=None, max_length=100)
    is_default: bool = False
    sip_settings: dict[str, Any] = Field(default_factory=dict)
    network_settings: dict[str, Any] = Field(default_factory=dict)
    provisioning_settings: dict[str, Any] = Field(default_factory=dict)
    feature_settings: dict[str, Any] = Field(default_factory=dict)
    line_key_settings: list[dict[str, Any]] = Field(default_factory=list)
    raw_overrides: dict[str, Any] = Field(default_factory=dict)
    firmware_version: str | None = None


class ConfigTemplateUpdate(BaseModel):
    """Schema for updating a configuration template."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    # vendor was omitted, so the edit dialog's vendor dropdown
    # silently no-op'd (Pydantic's default extra='ignore' dropped it before
    # the service's setattr loop ran). The model column is mutable.
    vendor: str | None = Field(default=None, min_length=1, max_length=100)
    model_pattern: str | None = None
    is_default: bool | None = None
    sip_settings: dict[str, Any] | None = None
    network_settings: dict[str, Any] | None = None
    provisioning_settings: dict[str, Any] | None = None
    feature_settings: dict[str, Any] | None = None
    line_key_settings: list[dict[str, Any]] | None = None
    raw_overrides: dict[str, Any] | None = None
    firmware_version: str | None = None


class ConfigTemplateResponse(BaseModel):
    """Configuration template response."""

    id: UUID
    site_id: UUID
    name: str
    description: str | None = None
    vendor: str
    model_pattern: str | None = None
    is_default: bool
    sip_settings: dict[str, Any] = {}
    network_settings: dict[str, Any] = {}
    provisioning_settings: dict[str, Any] = {}
    feature_settings: dict[str, Any] = {}
    line_key_settings: list[dict[str, Any]] = []
    raw_overrides: dict[str, Any] = {}
    firmware_version: str | None = None
    phone_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


# =============================================================================
# Firmware Schemas
# =============================================================================


class FirmwareTrackCreate(BaseModel):
    """Schema for registering a firmware version."""

    site_id: UUID
    vendor: str = Field(..., min_length=1, max_length=100)
    model: str = Field(..., min_length=1, max_length=100)
    version: str = Field(..., min_length=1, max_length=50)
    release_date: datetime | None = None
    changelog: str | None = Field(default=None, max_length=10000)
    download_url: str | None = Field(default=None, max_length=500)
    # Checksum is hex (sha256 = 64 chars / md5 = 32) so 128 is generous.
    file_checksum: str | None = Field(default=None, max_length=128)
    # 4 GB cap on file_size_bytes (no realistic phone firmware exceeds this).
    file_size_bytes: int | None = Field(default=None, ge=0, le=4 * 1024**3)
    is_stable: bool = True
    is_recommended: bool = False

    @field_validator("download_url")
    @classmethod
    def _v_download_url(cls, v: str | None) -> str | None:
        return _validate_firmware_url_ssrf(v)


class FirmwareTrackResponse(BaseModel):
    """Firmware version response."""

    id: UUID
    site_id: UUID
    vendor: str
    model: str
    version: str
    release_date: datetime | None = None
    changelog: str | None = None
    download_url: str | None = None
    file_checksum: str | None = None
    file_size_bytes: int | None = None
    is_stable: bool
    is_recommended: bool
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class FirmwareComplianceReport(BaseModel):
    """Fleet firmware compliance report."""

    vendor: str
    model: str
    recommended_version: str | None = None
    total_phones: int = 0
    compliant: int = 0
    non_compliant: int = 0
    unknown: int = 0
    versions: dict[str, int] = {}  # version -> count


# =============================================================================
# Bulk Operation Schemas
# =============================================================================


class BulkOperationRequest(BaseModel):
    """Request for bulk phone operations."""

    phone_ids: list[UUID] = Field(..., min_length=1, max_length=200)


class BulkProvisionRequest(BulkOperationRequest):
    """Bulk provisioning request."""

    config_template_id: UUID | None = None
    force: bool = False
    reboot_after: bool = True


class BulkFirmwareRequest(BulkOperationRequest):
    """Bulk firmware upgrade request."""

    target_version: str = Field(..., min_length=1, max_length=50)
    schedule_at: datetime | None = None  # None = immediate


class BulkConnectRequest(BulkOperationRequest):
    """Bulk connect — set credentials and fully connect selected phones."""

    username: str = Field(default="admin", max_length=64)
    password: str = Field(default="admin", max_length=128)


class BulkOperationResponse(BaseModel):
    """Response for bulk operations."""

    operation: str
    total: int
    succeeded: int
    failed: int
    skipped: int
    errors: list[dict[str, str]] = []


class BulkConnectResponse(BulkOperationResponse):
    """Response for bulk connect — includes per-phone results."""

    results: list[dict[str, Any]] = []


# =============================================================================
# Fleet Dashboard Schemas
# =============================================================================


class FleetDashboard(BaseModel):
    """Fleet overview dashboard data."""

    total_phones: int = 0
    online: int = 0
    offline: int = 0
    in_call: int = 0
    by_lifecycle: dict[str, int] = {}
    by_vendor: dict[str, int] = {}
    by_model: dict[str, int] = {}
    by_firmware: dict[str, int] = {}
    firmware_compliant: int = 0
    firmware_non_compliant: int = 0
    recently_discovered: int = 0
    pending_provision: int = 0
    sip_registered: int = 0
    sip_unregistered: int = 0


# =============================================================================
# Voicemail Schemas
# =============================================================================


class VoicemailResponse(BaseModel):
    """Voicemail message response."""

    id: UUID
    pbx_id: UUID | None = None
    extension_id: UUID | None = None
    extension_number: str
    caller_id: str
    caller_name: str | None = None
    duration: int
    message_date: datetime
    is_read: bool
    is_urgent: bool
    transcription: str | None = None
    file_path: str | None = None
    folder: str = "INBOX"

    class Config:
        from_attributes = True


class VoicemailUpdate(BaseModel):
    """Schema for updating a voicemail."""

    is_read: bool | None = None
    folder: str | None = None
