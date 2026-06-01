# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Models
=========================

SQLAlchemy models for VPN integration:
- VPNConnectionRecord: Persisted VPN connection status
- SiteVPNConfiguration: Per-site VPN config
- VPNHealthCheck: Health check results (TimescaleDB hypertable)
- VPNEvent: VPN audit trail / event log
- VPNReconnectState: Auto-reconnect state tracking
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, LogBase, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Controller, Site


# =============================================================================
# Enums
# =============================================================================


class VPNType(StrEnum):
    TAILSCALE = "tailscale"
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"
    NETBIRD = "netbird"
    IPSEC = "ipsec"
    ZEROTIER = "zerotier"
    GENERIC = "generic"


class VPNSource(StrEnum):
    """How this VPN config was created."""

    MANUAL = "manual"
    BRAIN_IMPORT = "brain_import"
    AGENT_PROVISION = "agent_provision"


class VPNEventSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class VPNReconnectStatus(StrEnum):
    IDLE = "idle"
    RETRYING = "retrying"
    EXHAUSTED = "exhausted"
    SUCCESS = "success"


class VPNStatus(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"


# =============================================================================
# Models
# =============================================================================


class VPNConnectionRecord(Base, UUIDMixin, AuditMixin):
    """
    Persisted VPN connection status.
    Updated by health check tasks.
    """

    __tablename__ = "vpn_connections"
    __table_args__ = (
        UniqueConstraint("name", "organization_id", name="uq_vpn_connections_name_org"),
        Index("ix_vpn_connections_status", "status"),
        Index("ix_vpn_connections_type", "vpn_type"),
        Index("ix_vpn_connections_org", "organization_id"),
        Index("ix_vpn_connections_org_status", "organization_id", "status"),
        {"schema": "vpn"},
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vpn_type: Mapped[str] = mapped_column(String(20), nullable=False, default=VPNType.TAILSCALE)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=VPNStatus.NOT_CONFIGURED
    )

    # Connection details
    endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    local_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    remote_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    allowed_ips: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True, default=list)
    dns_servers: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True, default=list)

    # Status timestamps
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_handshake: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Metrics
    rx_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tx_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Extra
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=dict)

    # Provider-specific fields
    # OpenVPN
    openvpn_config_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    openvpn_protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)  # tcp/udp
    # The full .ovpn config text. SECURITY: encrypted at rest via
    # encrypt_credential() (it carries inline private keys), and the contents are
    # validated against dangerous directives (up/down/script-security/plugin →
    # host RCE) at the schema layer. Materialized to /etc/openvpn/client/<name>.conf
    # by the connect path so the daemon (in the privileged vpn sidecar) can consume
    # it — without this the connect action has no on-disk config and always fails.
    openvpn_config_content: Mapped[str | None] = mapped_column(Text, nullable=True)

    # WireGuard
    # The full wg-quick INI config. SECURITY: encrypted at rest (carries the
    # interface PrivateKey + PSK), and validated against PostUp/PostDown/PreUp/
    # PreDown (wg-quick runs them as shell → host RCE) at the schema layer.
    # Materialized to /etc/wireguard/<iface>.conf so the vpn sidecar can
    # `wg-quick up` it (wg-quick needs NET_ADMIN, which only the sidecar holds).
    wireguard_config_content: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Netbird
    # SECURITY: netbird_setup_key is a credential and MUST be encrypted
    # via encrypt_credential() before storage. The API endpoint is
    # responsible for encrypting on create/update; use decrypt_credential()
    # (or _safe_decrypt) when reading back for operational use.
    netbird_setup_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    netbird_management_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Organization scope
    organization_id: Mapped[UUID | None] = mapped_column(nullable=True)


class SiteVPNConfiguration(Base, UUIDMixin, AuditMixin):
    """
    Per-site VPN configuration.
    Stores how a site is connected via VPN.
    """

    __tablename__ = "site_vpn_configs"
    __table_args__ = (
        Index("ix_site_vpn_configs_site", "site_id"),
        Index("ix_site_vpn_configs_controller", "controller_id"),
        Index("ix_site_vpn_configs_org", "organization_id"),
        {"schema": "vpn"},
    )

    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    vpn_type: Mapped[str] = mapped_column(String(20), nullable=False, default=VPNType.TAILSCALE)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_connect: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # ── Brain-VPN integration ───────────────────────────────────
    # Optional link to the controller acting as the brain/VPN gateway
    controller_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )
    vpn_source: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=VPNSource.MANUAL,
    )
    # Cached brain VPN server info (for display/troubleshooting)
    brain_vpn_server_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_config_sync: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Tailscale-specific
    tailscale_node: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tailscale_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tailscale_tags: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True, default=list)

    # WireGuard-specific
    wireguard_interface: Mapped[str | None] = mapped_column(String(50), nullable=True)
    wireguard_peer_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    wireguard_endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    wireguard_allowed_ips: Mapped[list[str] | None] = mapped_column(
        JSONB, nullable=True, default=list
    )

    # Generic
    vpn_endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vpn_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # OpenVPN-specific (full config support — not just a path)
    openvpn_config_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    openvpn_protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    openvpn_config_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    openvpn_mode: Mapped[str | None] = mapped_column(String(10), nullable=True)  # client|server

    # ZeroTier-specific
    zerotier_network_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    zerotier_node_id: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # Netbird-specific
    netbird_peer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    netbird_group: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Health check
    health_check_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    health_check_interval: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    latency_threshold_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Subnets
    remote_subnets: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True, default=list)
    local_subnets: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True, default=list)

    # Status cache
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=VPNStatus.NOT_CONFIGURED
    )
    last_health_check: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Certificate metadata — OpenVPN/IPsec cert tracking
    cert_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # cert_metadata format: {issuer, subject, serial, not_before, not_after, fingerprint}
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Organization scope (for multi-VPN)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=True,
    )

    # Relationships — lazy="raise" to prevent N+1; use selectinload() explicitly in endpoints
    site: Mapped["Site"] = relationship(lazy="raise")
    controller: Mapped["Controller | None"] = relationship(
        lazy="raise", foreign_keys=[controller_id]
    )


class VPNHealthCheck(LogBase):
    """
    VPN health check result.
    TimescaleDB hypertable for time-series health data.
    """

    __tablename__ = "vpn_health_checks"
    __table_args__ = (
        Index("ix_vpn_health_site", "site_id", "time"),
        Index("ix_vpn_health_conn", "connection_id", "time"),
        Index("ix_vpn_health_tunnel", "tunnel_id", "time"),
        {"schema": "vpn"},
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4, nullable=False)
    # Part of the composite PK (id, time): the hypertable partition column must
    # be in the PK; matches the migrate_logdb.py DDL.
    time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        nullable=False,
    )
    connection_id: Mapped[UUID | None] = mapped_column(nullable=True)
    site_id: Mapped[UUID | None] = mapped_column(nullable=True)
    tunnel_id: Mapped[UUID | None] = mapped_column(nullable=True)  # S2S tunnel ref

    is_healthy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tunnel metrics
    rx_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tx_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    peer_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


# =============================================================================
# VPN Tunnel Template
# =============================================================================


class VPNTunnelTemplate(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Reusable VPN tunnel configuration template.

    Stores default settings for a particular VPN type and topology
    so that site-to-site tunnels can be provisioned quickly.
    """

    __tablename__ = "vpn_tunnel_templates"
    __table_args__ = (
        Index("ix_vpn_templates_org", "organization_id"),
        {"schema": "vpn"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vpn_type: Mapped[str] = mapped_column(String(20), nullable=False)  # ipsec, wireguard, openvpn
    topology: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # hub_spoke, full_mesh, point_to_point
    config_template: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    default_subnets: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # MTU/MSS tunnel tuning
    mtu: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )  # e.g. 1420 for WG, 1500 default
    mss_clamp: Mapped[int | None] = mapped_column(Integer, nullable=True)  # MSS clamping value


# =============================================================================
# Site-to-Site Tunnel
# =============================================================================


class SiteToSiteTunnel(Base, UUIDMixin, AuditMixin):
    """
    A provisioned VPN tunnel between two sites.

    Created from a VPNTunnelTemplate; stores per-side configuration,
    gateway device references, and operational status.
    """

    __tablename__ = "site_to_site_tunnels"
    __table_args__ = (
        UniqueConstraint("site_a_id", "site_b_id", name="uq_s2s_tunnel_sites"),
        Index("ix_s2s_tunnels_org", "organization_id"),
        Index("ix_s2s_tunnels_template", "template_id"),
        Index("ix_s2s_tunnels_status", "status"),
        {"schema": "vpn"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    template_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vpn.vpn_tunnel_templates.id", ondelete="SET NULL"),
        nullable=True,
    )
    site_a_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_b_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    gateway_a_device_id: Mapped[UUID | None] = mapped_column(nullable=True)
    gateway_b_device_id: Mapped[UUID | None] = mapped_column(nullable=True)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default="pending")

    config_a: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    config_b: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    provisioned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_health_check: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


# =============================================================================
# VPN Event (Audit Trail)
# =============================================================================


class VPNEvent(Base, UUIDMixin):
    """
    VPN audit trail / event log.
    Records state transitions, config changes, health alerts, and reconnect attempts.
    """

    __tablename__ = "vpn_events"
    __table_args__ = (
        Index("ix_vpn_events_org_time", "organization_id", "created_at"),
        Index("ix_vpn_events_site", "site_id", "created_at"),
        Index("ix_vpn_events_type", "event_type"),
        {"schema": "vpn"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )
    connection_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vpn.vpn_connections.id", ondelete="SET NULL"),
        nullable=True,
    )
    tunnel_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vpn.site_to_site_tunnels.id", ondelete="SET NULL"),
        nullable=True,
    )

    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default=VPNEventSeverity.INFO,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    source: Mapped[str | None] = mapped_column(String(50), nullable=True)
    actor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=None,
    )


# =============================================================================
# VPN Reconnect State
# =============================================================================


class VPNReconnectState(Base, UUIDMixin):
    """
    Tracks auto-reconnect attempts per VPN connection.
    Managed by the VPNReconnectService / vpn.auto_reconnect Celery task.
    """

    __tablename__ = "vpn_reconnect_state"
    __table_args__ = (
        UniqueConstraint("connection_id", name="uq_vpn_reconnect_conn"),
        {"schema": "vpn"},
    )

    connection_id: Mapped[UUID] = mapped_column(
        ForeignKey("vpn.vpn_connections.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_vpn_config_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vpn.site_vpn_configs.id", ondelete="SET NULL"),
        nullable=True,
    )

    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    backoff_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    state: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=VPNReconnectStatus.IDLE,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=None,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=None,
        onupdate=lambda: datetime.now(UTC),
    )
