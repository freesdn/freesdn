# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Network Module Models
====================================

Unified data models for network management.

All tables live in the ``network`` PostgreSQL schema.
This is the single source of truth for network domain data —
used by controller_sync, the v1 API endpoints, and the module service.
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Controller, Site
    from app.models.devices import Device


# =============================================================================
# Enums
# =============================================================================


class WifiSecurityType(StrEnum):
    OPEN = "open"
    WPA2_PERSONAL = "wpa2_personal"
    WPA2_ENTERPRISE = "wpa2_enterprise"
    WPA3_PERSONAL = "wpa3_personal"
    WPA3_ENTERPRISE = "wpa3_enterprise"
    WPA_WPA2_PERSONAL = "wpa_wpa2_personal"
    WPA2_WPA3_PERSONAL = "wpa2_wpa3_personal"


class WifiBand(StrEnum):
    BAND_2_4 = "2.4ghz"
    BAND_5 = "5ghz"
    BAND_6 = "6ghz"
    BOTH = "both"
    ALL = "all"


class LAGMode(StrEnum):
    STATIC = "static"
    LACP = "lacp"


# =============================================================================
# Network / VLAN
# =============================================================================


class Network(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Network / VLAN imported from a controller.

    Represents an L2/L3 network segment (typically a VLAN) that
    exists in the controller.  The ``external_id`` maps back to
    the controller's own network/VLAN identifier so we can push
    changes back.
    """

    __tablename__ = "vlans"
    __table_args__ = (
        Index("ix_net_vlans_controller_id", "controller_id"),
        Index("ix_net_vlans_site_id", "site_id"),
        Index("ix_net_vlans_vlan_id", "vlan_id"),
        {"schema": "network"},
    )

    # Foreign Keys
    controller_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=True,
    )

    # Identity
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vlan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    purpose: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # L3 / DHCP
    gateway: Mapped[str | None] = mapped_column(String(45), nullable=True)
    subnet: Mapped[str | None] = mapped_column(String(45), nullable=True)
    subnet_mask: Mapped[str | None] = mapped_column(String(45), nullable=True)
    cidr: Mapped[str | None] = mapped_column(String(49), nullable=True)
    dhcp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    dhcp_start: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dhcp_end: Mapped[str | None] = mapped_column(String(45), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Extended data blob from controller
    network_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationships
    controller: Mapped["Controller"] = relationship("Controller", lazy="selectin")
    site: Mapped["Site"] = relationship("Site", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Network VLAN {self.vlan_id} – {self.name}>"


# =============================================================================
# WiFi Network / SSID
# =============================================================================


class WifiNetwork(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    WiFi network (SSID) imported from a controller.
    """

    __tablename__ = "wifi_networks"
    __table_args__ = (
        Index("ix_net_wifi_controller_id", "controller_id"),
        Index("ix_net_wifi_site_id", "site_id"),
        {"schema": "network"},
    )

    # Foreign Keys
    controller_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=True,
    )

    # Identity
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ssid: Mapped[str] = mapped_column(String(64), nullable=False)

    # Security
    security: Mapped[str] = mapped_column(String(50), default="wpa2_personal", nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Band / Radio
    band: Mapped[str] = mapped_column(String(20), default="both", nullable=False)

    # VLAN binding
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Feature flags
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    hidden: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    client_isolation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    band_steering: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    fast_roaming: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Rate limiting
    rate_limit_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rate_limit_up: Mapped[int | None] = mapped_column(Integer, nullable=True)  # kbps
    rate_limit_down: Mapped[int | None] = mapped_column(Integer, nullable=True)  # kbps

    # Roaming settings
    roaming_protocol: Mapped[str | None] = mapped_column(String(30), nullable=True)
    minimum_rssi: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Extended data blob from controller
    wifi_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationships
    controller: Mapped["Controller"] = relationship("Controller", lazy="selectin")
    site: Mapped["Site"] = relationship("Site", lazy="selectin")

    def __repr__(self) -> str:
        return f"<WifiNetwork {self.ssid}>"


# =============================================================================
# Port Profile
# =============================================================================


class PortProfile(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Switch port profile – a reusable collection of port settings
    that can be applied to multiple ports.
    """

    __tablename__ = "port_profiles"
    __table_args__ = (
        Index("ix_net_pp_controller_id", "controller_id"),
        Index("ix_net_pp_site_id", "site_id"),
        {"schema": "network"},
    )

    # Foreign Keys
    controller_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=True,
    )

    # Identity
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    profile_type: Mapped[str] = mapped_column(String(50), default="custom", nullable=False)

    # VLAN settings
    native_vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tagged_vlans: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)
    voice_vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # PoE
    poe_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # STP
    stp_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # Port count (how many ports use this profile)
    ports_using: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Extended data
    profile_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationships
    controller: Mapped["Controller"] = relationship("Controller", lazy="selectin")
    site: Mapped["Site"] = relationship("Site", lazy="selectin")

    def __repr__(self) -> str:
        return f"<PortProfile {self.name}>"


# =============================================================================
# Link Aggregation Group
# =============================================================================


class LinkAggregationGroup(Base, UUIDMixin, AuditMixin):
    """
    LAG (Link Aggregation Group) on a switch.
    """

    __tablename__ = "link_aggregation_groups"
    __table_args__ = (
        Index("ix_net_lags_device_id", "device_id"),
        {"schema": "network"},
    )

    # Foreign Keys
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Identity
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    lag_id: Mapped[int] = mapped_column(Integer, nullable=False)

    # Configuration
    mode: Mapped[str] = mapped_column(String(20), default="lacp", nullable=False)
    member_ports: Mapped[list[int]] = mapped_column(ARRAY(Integer), default=list, nullable=False)
    lacp_mode: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    lacp_timeout: Mapped[str] = mapped_column(String(20), default="long", nullable=False)

    # Status
    status: Mapped[str] = mapped_column(String(20), default="up", nullable=False)
    active_ports: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    aggregate_speed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Extended
    lag_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationships
    device: Mapped["Device"] = relationship("Device", lazy="selectin")

    def __repr__(self) -> str:
        return f"<LAG {self.name} ({self.mode})>"


# =============================================================================
# Topology Link
# =============================================================================


class TopologyLink(Base, UUIDMixin, AuditMixin):
    """
    A link between two devices – derived from LLDP, CDP, or
    controller-reported uplink/downlink data.
    """

    __tablename__ = "topology_links"
    __table_args__ = (
        Index("ix_net_topo_source", "source_device_id"),
        Index("ix_net_topo_target", "target_device_id"),
        {"schema": "network"},
    )

    # Foreign Keys
    source_device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Port info
    source_port: Mapped[str | None] = mapped_column(String(50), nullable=True)
    target_port: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Link attributes
    speed: Mapped[str | None] = mapped_column(String(20), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="up", nullable=False)
    link_type: Mapped[str] = mapped_column(String(30), default="ethernet", nullable=False)

    # Protocol that discovered this link
    discovered_via: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Extended
    link_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationships
    source_device: Mapped["Device"] = relationship(
        "Device",
        foreign_keys=[source_device_id],
        lazy="selectin",
    )
    target_device: Mapped["Device"] = relationship(
        "Device",
        foreign_keys=[target_device_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<TopologyLink {self.source_device_id} → {self.target_device_id}>"


# =============================================================================
# Client Roaming Event
# =============================================================================


class ClientRoamingEvent(Base, UUIDMixin):
    """
    Records a single client roaming event between two APs.

    Captures the before/after BSSID, RSSI, roam latency,
    and the roaming mechanism used (802.11r, reassociation, etc.).
    """

    __tablename__ = "client_roaming_events"
    __table_args__ = (
        Index("ix_roaming_client", "client_mac", "timestamp"),
        Index("ix_roaming_org", "organization_id"),
        {"schema": "network"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    client_mac: Mapped[str] = mapped_column(String(17), nullable=False)

    from_device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    to_device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="SET NULL"),
        nullable=True,
    )

    from_bssid: Mapped[str | None] = mapped_column(String(17), nullable=True)
    to_bssid: Mapped[str | None] = mapped_column(String(17), nullable=True)

    from_rssi: Mapped[int | None] = mapped_column(Integer, nullable=True)
    to_rssi: Mapped[int | None] = mapped_column(Integer, nullable=True)

    roam_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    roam_type: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )  # "802.11r", "reassociation", "full_auth"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Relationships
    from_device: Mapped["Device"] = relationship(
        "Device",
        foreign_keys=[from_device_id],
        lazy="selectin",
    )
    to_device: Mapped["Device"] = relationship(
        "Device",
        foreign_keys=[to_device_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<ClientRoamingEvent {self.client_mac} @ {self.timestamp}>"
