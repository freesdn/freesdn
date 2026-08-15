# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Firewall Module Models
====================================

Database models for firewall and network security.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin


class RuleAction(StrEnum):
    """Firewall rule action."""

    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    LOG = "log"


class Protocol(StrEnum):
    """Network protocol."""

    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    GRE = "gre"
    ESP = "esp"
    AH = "ah"


class NATType(StrEnum):
    """NAT type."""

    SNAT = "snat"
    DNAT = "dnat"
    MASQUERADE = "masquerade"
    REDIRECT = "redirect"


class VPNType(StrEnum):
    """VPN tunnel type."""

    IPSEC = "ipsec"
    OPENVPN = "openvpn"
    WIREGUARD = "wireguard"
    L2TP = "l2tp"


class VPNStatus(StrEnum):
    """VPN tunnel status."""

    UP = "up"
    DOWN = "down"
    CONNECTING = "connecting"
    ERROR = "error"


class AlertSeverity(StrEnum):
    """IDS alert severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GatewayVendor(StrEnum):
    """Supported gateway vendors."""

    OPNSENSE = "opnsense"
    PFSENSE = "pfsense"
    MIKROTIK = "mikrotik"
    OPENWRT = "openwrt"


class GatewaySyncStatus(StrEnum):
    """Gateway sync status."""

    IDLE = "idle"
    SYNCING = "syncing"
    SUCCESS = "success"
    FAILED = "failed"
    NEVER = "never"


class FirewallDevice(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Firewall/UTM device.
    """

    __tablename__ = "devices"
    __table_args__ = (
        Index("ix_firewall_devices_site_id", "site_id"),
        {"schema": "firewall"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    controller_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_type: Mapped[str] = mapped_column(String(50), default="firewall")

    # Connection
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=443)

    # Device Info
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Status
    is_online: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Capabilities
    supports_ids: Mapped[bool] = mapped_column(Boolean, default=False)
    supports_vpn: Mapped[bool] = mapped_column(Boolean, default=False)

    # Settings
    default_policy: Mapped[str] = mapped_column(String(20), default=RuleAction.DENY.value)
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=lambda: {})

    # Relationships
    rules: Mapped[list["FirewallRule"]] = relationship("FirewallRule", back_populates="device")
    nat_rules: Mapped[list["NATRule"]] = relationship("NATRule", back_populates="device")
    vpn_tunnels: Mapped[list["VPNTunnel"]] = relationship("VPNTunnel", back_populates="device")
    gateway_connection: Mapped["GatewayConnection | None"] = relationship(
        "GatewayConnection", back_populates="device", uselist=False
    )


class GatewayConnection(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Gateway integration connection.

    Stores credentials and sync state for an external firewall/router
    managed via OPNsense, pfSense, or MikroTik adapter APIs.
    """

    __tablename__ = "gateway_connections"
    __table_args__ = (
        Index("ix_gateway_connections_org_id", "org_id"),
        Index("ix_gateway_connections_site_id", "site_id"),
        Index("ix_gateway_connections_vendor", "vendor"),
        Index("ix_gateway_connections_org_deleted", "org_id", "deleted_at"),
        UniqueConstraint("org_id", "name", "deleted_at", name="uq_gateway_connections_org_name"),
        {"schema": "firewall"},
    )

    # Ownership
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )
    device_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("firewall.devices.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Connection identity
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # opnsense | pfsense | mikrotik | openwrt

    # Network
    host: Mapped[str] = mapped_column(String(255), nullable=False)  # hostname or IP
    port: Mapped[int] = mapped_column(Integer, default=443)
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=False)

    # Credentials (stored as encrypted JSON)
    credentials: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=lambda: {})
    # For opnsense/pfsense: {"api_key": "...", "api_secret": "..."}
    # For mikrotik:          {"username": "...", "password": "..."}

    # Sync configuration
    sync_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=300)

    # Sync state
    sync_status: Mapped[str] = mapped_column(String(20), default=GatewaySyncStatus.NEVER.value)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_sync_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Online state
    is_online: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Detected capabilities / info cache
    detected_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    detected_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detected_model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    capabilities: Mapped[list[Any]] = mapped_column(
        JSONB, default=lambda: []
    )  # list of Capability strings

    # Vendor-specific settings (NOTE: splatted into the adapter constructor by
    # GatewayService._build_adapter — do NOT stash non-adapter keys here).
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=lambda: {})

    # Fabric health monitor last-known snapshot (transition-only event emission).
    # Separate from settings so it never reaches the adapter constructor.
    fabric_health: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    device: Mapped["FirewallDevice | None"] = relationship(
        "FirewallDevice", back_populates="gateway_connection"
    )
    sync_logs: Mapped[list["GatewaySyncLog"]] = relationship(
        "GatewaySyncLog", back_populates="gateway", cascade="all, delete-orphan"
    )


class GatewaySyncLog(Base, UUIDMixin):
    """
    Audit log for gateway sync operations.
    """

    __tablename__ = "gateway_sync_logs"
    __table_args__ = (
        Index("ix_gateway_sync_logs_gw_id", "gateway_id"),
        Index("ix_gateway_sync_logs_timestamp", "started_at"),
        {"schema": "firewall"},
    )

    gateway_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Timing
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Result
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # success | failed | partial
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # What was synced
    items_synced: Mapped[int] = mapped_column(Integer, default=0)
    items_failed: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=lambda: {})
    # e.g. {"rules_pulled": 45, "nat_pulled": 12, "vpn_pulled": 3}

    # Relationships
    gateway: Mapped["GatewayConnection"] = relationship(
        "GatewayConnection", back_populates="sync_logs"
    )


class FirewallRule(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Firewall rule.
    """

    __tablename__ = "rules"
    __table_args__ = (
        Index("ix_firewall_rules_device_id", "device_id"),
        Index("ix_firewall_rules_order", "rule_order"),
        {"schema": "firewall"},
    )

    # Foreign Keys
    device_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("firewall.devices.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_order: Mapped[int] = mapped_column(Integer, default=100)

    # Source
    source_address: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )  # IP, CIDR, or "any"
    source_port: Mapped[str | None] = mapped_column(String(50), nullable=True)  # Port or range
    source_zone: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Destination
    dest_address: Mapped[str | None] = mapped_column(String(100), nullable=True)
    dest_port: Mapped[str | None] = mapped_column(String(50), nullable=True)
    dest_zone: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Protocol and Action
    protocol: Mapped[str] = mapped_column(String(20), default=Protocol.ANY.value)
    action: Mapped[str] = mapped_column(String(20), nullable=False)

    # Logging
    log_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # Schedule
    schedule_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    # Status
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    last_hit: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    device: Mapped["FirewallDevice"] = relationship("FirewallDevice", back_populates="rules")


class NATRule(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    NAT/Port forwarding rule.
    """

    __tablename__ = "nat_rules"
    __table_args__ = (
        Index("ix_nat_rules_device_id", "device_id"),
        {"schema": "firewall"},
    )

    # Foreign Keys
    device_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("firewall.devices.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    nat_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Original
    original_address: Mapped[str | None] = mapped_column(String(100), nullable=True)
    original_port: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Translated
    translated_address: Mapped[str | None] = mapped_column(String(100), nullable=True)
    translated_port: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Protocol
    protocol: Mapped[str] = mapped_column(String(20), default=Protocol.TCP.value)

    # Interface
    interface: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Status
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationships
    device: Mapped["FirewallDevice"] = relationship("FirewallDevice", back_populates="nat_rules")


class VPNTunnel(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    VPN tunnel configuration.
    """

    __tablename__ = "vpn_tunnels"
    __table_args__ = (
        Index("ix_vpn_tunnels_device_id", "device_id"),
        Index("ix_vpn_tunnels_status", "status"),
        {"schema": "firewall"},
    )

    # Foreign Keys
    device_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("firewall.devices.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    vpn_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Remote Endpoint
    remote_address: Mapped[str | None] = mapped_column(String(100), nullable=True)
    remote_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Local Configuration
    local_address: Mapped[str | None] = mapped_column(String(100), nullable=True)
    local_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    local_subnets: Mapped[list[Any]] = mapped_column(JSONB, default=lambda: [])

    # Remote Subnets
    remote_subnets: Mapped[list[Any]] = mapped_column(JSONB, default=lambda: [])

    # Authentication
    auth_type: Mapped[str] = mapped_column(String(20), default="psk")  # psk, certificate

    # Status
    status: Mapped[str] = mapped_column(String(20), default=VPNStatus.DOWN.value)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_connected: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Traffic Stats
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)

    # Configuration
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=lambda: {})

    # Relationships
    device: Mapped["FirewallDevice"] = relationship("FirewallDevice", back_populates="vpn_tunnels")


class IDSAlert(Base, UUIDMixin):
    """
    IDS/IPS alert.
    """

    __tablename__ = "ids_alerts"
    __table_args__ = (
        Index("ix_ids_alerts_device_id", "device_id"),
        Index("ix_ids_alerts_timestamp", "timestamp"),
        Index("ix_ids_alerts_severity", "severity"),
        {"schema": "firewall"},
    )

    # Foreign Keys
    device_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("firewall.devices.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Alert Info
    signature_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    signature_name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    # Timestamp
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Source
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Destination
    dest_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Protocol
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Action Taken
    action_taken: Mapped[str | None] = mapped_column(String(20), nullable=True)  # logged, blocked

    # Details
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=lambda: {})

    # Status
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FirewallLog(Base, UUIDMixin):
    """
    Firewall traffic log entry.
    """

    __tablename__ = "logs"
    __table_args__ = (
        Index("ix_firewall_logs_device_id", "device_id"),
        Index("ix_firewall_logs_timestamp", "timestamp"),
        Index("ix_firewall_logs_action", "action"),
        {"schema": "firewall"},
    )

    # Foreign Keys
    device_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("firewall.devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    rule_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("firewall.rules.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Timestamp
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Source
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_zone: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Destination
    dest_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dest_zone: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Protocol
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Action
    action: Mapped[str] = mapped_column(String(20), nullable=False)

    # Traffic
    bytes_sent: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_received: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Application
    application: Mapped[str | None] = mapped_column(String(100), nullable=True)
