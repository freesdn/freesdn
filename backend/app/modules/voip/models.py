# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VoIP Module Models
================================

Database models for voice over IP — GDMS-style fleet management.
"""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

# =============================================================================
# Enums
# =============================================================================


class PhoneStatus(StrEnum):
    """Phone registration status."""

    ONLINE = "online"
    OFFLINE = "offline"
    RINGING = "ringing"
    IN_CALL = "in_call"
    DND = "dnd"


class PhoneLifecycleState(StrEnum):
    """GDMS-style device lifecycle state."""

    DISCOVERED = "discovered"  # Found on network, not yet managed
    ONBOARDING = "onboarding"  # Being provisioned / adopted
    MANAGED = "managed"  # Fully managed, config pushed
    MAINTENANCE = "maintenance"  # Temporarily under maintenance
    FIRMWARE_UPDATING = "firmware_updating"  # Firmware upgrade in progress
    DECOMMISSIONED = "decommissioned"  # Removed from fleet


class DiscoveryMethod(StrEnum):
    """How the phone was discovered."""

    MANUAL = "manual"  # Added manually by admin
    ARP_SCAN = "arp_scan"  # Found via ARP/subnet scan
    MDNS = "mdns"  # Found via mDNS/Bonjour
    SIP_PROBE = "sip_probe"  # Found via SIP OPTIONS probe
    HTTP_PROBE = "http_probe"  # Found via HTTP web UI probe
    DHCP_SNOOP = "dhcp_snoop"  # Found via DHCP lease inspection
    PBX_SYNC = "pbx_sync"  # Discovered via PBX extension sync
    CDP_LLDP = "cdp_lldp"  # Discovered via CDP/LLDP


class ProvisionStatus(StrEnum):
    """Provisioning state."""

    PENDING = "pending"  # Waiting for config generation
    GENERATED = "generated"  # Config file generated
    PUSHED = "pushed"  # Config pushed to phone
    APPLIED = "applied"  # Phone confirmed config applied
    FAILED = "failed"  # Provisioning failed
    STALE = "stale"  # Config out of date


class CallDirection(StrEnum):
    """Call direction."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class CallStatus(StrEnum):
    """Call status."""

    ANSWERED = "answered"
    MISSED = "missed"
    VOICEMAIL = "voicemail"
    FAILED = "failed"


class ScanStatus(StrEnum):
    """Discovery scan status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# =============================================================================
# Phone Model (Enhanced for GDMS-style fleet management)
# =============================================================================


class Phone(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    IP Phone device — full lifecycle tracking for GDMS-style management.
    """

    __tablename__ = "phones"
    __table_args__ = (
        Index("ix_phones_site_id", "site_id"),
        Index("ix_phones_pbx_id", "pbx_id"),
        Index("ix_phones_status", "status"),
        Index("ix_phones_mac_address", "mac_address", unique=True),
        Index("ix_phones_lifecycle_state", "lifecycle_state"),
        Index("ix_phones_template_id", "config_template_id"),
        {"schema": "voip"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    pbx_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("voip.pbx.id", ondelete="SET NULL"),
        nullable=True,
    )
    extension_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("voip.extensions.id", ondelete="SET NULL"),
        nullable=True,
    )
    controller_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )
    config_template_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("voip.config_templates.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Connection
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)

    # Device Info
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Registration & Status
    status: Mapped[str] = mapped_column(String(20), default=PhoneStatus.OFFLINE.value)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- GDMS Fleet Management Fields ---

    # Lifecycle
    lifecycle_state: Mapped[str] = mapped_column(
        String(30), default=PhoneLifecycleState.DISCOVERED.value
    )
    discovery_method: Mapped[str | None] = mapped_column(String(30), nullable=True)
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    onboarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Provisioning
    provision_status: Mapped[str | None] = mapped_column(
        String(20), default=ProvisionStatus.PENDING.value
    )
    last_provisioned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    provisioning_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    config_checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Firmware Management
    firmware_target: Mapped[str | None] = mapped_column(String(50), nullable=True)
    firmware_upgrade_scheduled: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Health Monitoring
    uptime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sip_registered: Mapped[bool] = mapped_column(Boolean, default=False)
    sip_server: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_reboot: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cpu_usage: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_usage: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Network Info
    subnet: Mapped[str | None] = mapped_column(String(18), nullable=True)  # e.g. 192.168.1.0/24
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lldp_switch_port: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Settings
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Location
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Tags for fleet grouping
    tags: Mapped[dict] = mapped_column(JSONB, default=list)

    # ── Encrypted secret columns (Fernet tokens, never round-tripped to UI) ──
    # SIP/auth credentials and admin web passwords previously lived in the
    # ``settings`` / ``synced_cache`` JSONB blobs in plaintext. Round-tripping
    # them through GET responses was a critical leak vector. They now live in
    # dedicated columns encrypted via ``app.core.crypto.encrypt_credential``
    # and MUST be redacted on all read paths.
    sip_password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    admin_password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    xml_password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Transport hardening: Grandstream phones default to HTTP for backwards
    # compatibility. Sites that have not run a deliberate plaintext-acceptance
    # workflow MUST set ``use_ssl=True`` (the default for new rows). The opt-in
    # column flips a refusal in the client to a warning so existing brownfield
    # deployments can be migrated incrementally.
    # server_default mirrors migration 014 so a fresh create_all() build matches
    # the migration-built schema (NOT NULL booleans need a DB
    # default or raw inserts fail on fresh installs but succeed on upgraded DBs).
    use_ssl: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default=text("true")
    )
    acknowledge_plaintext: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, server_default=text("false")
    )

    # Relationships
    pbx: Mapped["PBX | None"] = relationship("PBX", back_populates="phones")
    extension: Mapped["Extension | None"] = relationship("Extension", back_populates="phone")
    config_template: Mapped["ConfigTemplate | None"] = relationship(
        "app.modules.voip.models.ConfigTemplate", back_populates="phones"
    )


class PBX(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    PBX (Private Branch Exchange) system.
    """

    __tablename__ = "pbx"
    __table_args__ = (
        Index("ix_pbx_site_id", "site_id"),
        {"schema": "voip"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    pbx_type: Mapped[str] = mapped_column(
        String(50), default="asterisk"
    )  # asterisk, freepbx, 3cx, etc.

    # Connection
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    api_port: Mapped[int] = mapped_column(Integer, default=443)
    sip_port: Mapped[int] = mapped_column(Integer, default=5060)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Settings
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)

    # ── Encrypted secret columns (Fernet tokens, never round-tripped to UI) ──
    # AMI / ARI / FreePBX web-admin credentials previously lived as plaintext
    # keys in the ``settings`` JSONB blob (``ami_secret``, ``ari_password``,
    # ``web_password``, ``api_password``, ``api_key``). They now live in
    # dedicated encrypted columns and MUST be redacted on all read paths.
    ami_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    ari_password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    web_password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── OAuth2 client_credentials (FreePBX 16+ Admin API → Applications) ──
    # The Machine-to-Machine app pair. ``api_client_id`` is opaque-but-not-
    # secret (it's like a username), so it lives in a plain Text column.
    # ``api_client_secret_enc`` is the actual secret and is Fernet-encrypted
    # like the other ``*_enc`` columns. Both are optional; without them the
    # adapter falls back to web-session auth using ``web_password_enc``.
    # When set, the FreePBX REST + GraphQL paths activate automatically.
    api_client_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_client_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # TLS verification opt-out. The 3 FreePBX clients (REST + ARI + AMI-TLS)
    # default to ``verify_ssl=True``. Brownfield installs running a self-signed
    # FreePBX cert must explicitly acknowledge they are accepting the
    # downgrade — that's the only way the client will skip verification.
    tls_verify_disabled_acknowledged: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default=text("false"),  # mirror migration 014
    )

    # Relationships
    phones: Mapped[list["Phone"]] = relationship("Phone", back_populates="pbx")
    extensions: Mapped[list["Extension"]] = relationship("Extension", back_populates="pbx")
    ring_groups: Mapped[list["RingGroup"]] = relationship("RingGroup", back_populates="pbx")


class Extension(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Phone extension.
    """

    __tablename__ = "extensions"
    __table_args__ = (
        Index("ix_extensions_pbx_id", "pbx_id"),
        Index("ix_extensions_number", "extension_number"),
        {"schema": "voip"},
    )

    # Foreign Keys
    pbx_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("voip.pbx.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Extension Info
    extension_number: Mapped[str] = mapped_column(String(20), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Caller ID
    caller_id_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    caller_id_number: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Voicemail
    voicemail_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    voicemail_pin: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Settings
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    pbx: Mapped["PBX"] = relationship("PBX", back_populates="extensions")
    phone: Mapped["Phone | None"] = relationship("Phone", back_populates="extension")


class RingGroup(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Ring group for simultaneous/sequential ringing.
    """

    __tablename__ = "ring_groups"
    __table_args__ = (
        Index("ix_ring_groups_pbx_id", "pbx_id"),
        {"schema": "voip"},
    )

    # Foreign Keys
    pbx_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("voip.pbx.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Group Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    group_number: Mapped[str] = mapped_column(String(20), nullable=False)

    # Ring Strategy
    ring_strategy: Mapped[str] = mapped_column(
        String(20), default="ringall"
    )  # ringall, hunt, memoryhunt
    ring_time: Mapped[int] = mapped_column(Integer, default=20)  # seconds

    # Members (stored as JSON array of extension IDs)
    members: Mapped[dict] = mapped_column(JSONB, default=list)

    # Settings
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    pbx: Mapped["PBX"] = relationship("PBX", back_populates="ring_groups")


class CallLog(Base, UUIDMixin):
    """
    Call Detail Record (CDR).
    """

    __tablename__ = "call_logs"
    __table_args__ = (
        Index("ix_call_logs_pbx_id", "pbx_id"),
        Index("ix_call_logs_start_time", "start_time"),
        Index("ix_call_logs_caller", "caller_number"),
        Index("ix_call_logs_callee", "callee_number"),
        Index("ix_call_logs_direction", "direction"),
        Index("ix_call_logs_status", "status"),
        {"schema": "voip"},
    )

    # Foreign Keys
    pbx_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("voip.pbx.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Call ID
    unique_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Parties
    caller_number: Mapped[str] = mapped_column(String(50), nullable=False)
    caller_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    callee_number: Mapped[str] = mapped_column(String(50), nullable=False)
    callee_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Direction and Status
    direction: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)

    # Timing
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    answer_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[int] = mapped_column(Integer, default=0)
    ring_duration_seconds: Mapped[int] = mapped_column(Integer, default=0)

    # Recording
    recording_path: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Additional Info
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict)


class VoicemailMessage(Base, UUIDMixin, SoftDeleteMixin):
    """
    Voicemail message.
    """

    __tablename__ = "voicemail_messages"
    __table_args__ = (
        Index("ix_voicemail_extension_id", "extension_id"),
        Index("ix_voicemail_message_date", "message_date"),
        {"schema": "voip"},
    )

    # Foreign Keys
    pbx_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("voip.pbx.id", ondelete="SET NULL"),
        nullable=True,
    )
    extension_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("voip.extensions.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Extension number (denormalized for quick access)
    extension_number: Mapped[str] = mapped_column(String(20), nullable=False)

    # Caller info
    caller_id: Mapped[str] = mapped_column(String(100), nullable=False)
    caller_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Message details
    duration: Mapped[int] = mapped_column(Integer, default=0)  # seconds
    message_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Status
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    is_urgent: Mapped[bool] = mapped_column(Boolean, default=False)

    # Content
    transcription: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Context
    folder: Mapped[str] = mapped_column(String(20), default="INBOX")  # INBOX, Old, Trash


# =============================================================================
# GDMS-Style Fleet Management Models
# =============================================================================


class ConfigTemplate(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Reusable configuration template for phone provisioning.

    Like GDMS config profiles — define SIP, network, codec, BLF,
    and other settings once, assign to many phones.
    """

    __tablename__ = "config_templates"
    __table_args__ = (
        Index("ix_config_templates_site_id", "site_id"),
        Index("ix_config_templates_vendor", "vendor"),
        {"schema": "voip"},
    )

    # Scope
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Template Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor: Mapped[str] = mapped_column(String(100), nullable=False)  # grandstream, yealink, etc.
    model_pattern: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )  # GXP2170, GRP26*, etc.
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    # SIP Configuration
    sip_settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    # {server, port, transport, codec_priority, dtmf_mode, ...}

    # Network Configuration
    network_settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    # {vlan_id, dhcp, ntp_server, syslog_server, ...}

    # Provisioning Configuration
    provisioning_settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    # {server_url, upgrade_server, config_server_path, ...}

    # Phone UI / Features
    feature_settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    # {admin_password, timezone, language, date_format, screensaver, ...}

    # Line Keys / BLF
    line_key_settings: Mapped[dict] = mapped_column(JSONB, default=list)
    # [{index, mode, label, value, account}, ...]

    # Raw P-value overrides (vendor-specific)
    raw_overrides: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Firmware target for phones using this template
    firmware_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Relationships
    phones: Mapped[list["Phone"]] = relationship(
        "app.modules.voip.models.Phone", back_populates="config_template"
    )


class FirmwareTrack(Base, UUIDMixin, AuditMixin):
    """
    Firmware version tracking and upgrade management.

    Tracks available firmware versions per vendor/model for fleet-wide
    firmware compliance monitoring and scheduled upgrades.
    """

    __tablename__ = "firmware_tracks"
    __table_args__ = (
        Index("ix_firmware_vendor_model", "vendor", "model"),
        {"schema": "voip"},
    )

    # Scope
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Device Target
    vendor: Mapped[str] = mapped_column(String(100), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)

    # Firmware Info
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    release_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    changelog: Mapped[str | None] = mapped_column(Text, nullable=True)
    download_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    file_checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Track type
    is_stable: Mapped[bool] = mapped_column(Boolean, default=True)
    is_recommended: Mapped[bool] = mapped_column(Boolean, default=False)

    # Metadata
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict)


class DiscoveryScan(Base, UUIDMixin, AuditMixin):
    """
    Network discovery scan record.

    Tracks discovery scan executions, their parameters, and results
    for audit trail and result review before onboarding.
    """

    __tablename__ = "discovery_scans"
    __table_args__ = (
        Index("ix_discovery_scans_site_id", "site_id"),
        Index("ix_discovery_scans_status", "status"),
        {"schema": "voip"},
    )

    # Scope
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    triggered_by: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Scan Parameters
    scan_type: Mapped[str] = mapped_column(String(30), nullable=False)  # full, arp, sip, http
    subnet: Mapped[str | None] = mapped_column(String(18), nullable=True)  # e.g. 192.168.1.0/24
    port_range: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Status
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.PENDING.value)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Results Summary
    devices_found: Mapped[int] = mapped_column(Integer, default=0)
    new_devices: Mapped[int] = mapped_column(Integer, default=0)
    updated_devices: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)

    # Detailed Results (array of discovered device dicts)
    results: Mapped[dict] = mapped_column(JSONB, default=list)

    # Metadata
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict)
