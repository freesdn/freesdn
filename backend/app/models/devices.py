# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device Models
===========================

Models for network devices discovered from controllers.
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Controller, Site


class DeviceType(StrEnum):
    """Device type enumeration."""

    # Network Devices
    SWITCH = "switch"
    ROUTER = "router"
    ACCESS_POINT = "access_point"
    GATEWAY = "gateway"
    FIREWALL = "firewall"

    # Security Devices
    CAMERA = "camera"
    NVR = "nvr"
    DVR = "dvr"
    ACCESS_CONTROL = "access_control"
    INTERCOM = "intercom"

    # VoIP / Telephony
    VOIP_PHONE = "voip_phone"
    PBX = "pbx"

    # Infrastructure
    SERVER = "server"
    HYPERVISOR = "hypervisor"
    IOT = "iot"
    SENSOR = "sensor"
    OTHER = "other"


class DeviceStatus(StrEnum):
    """Device online status."""

    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"
    ADOPTING = "adopting"
    PROVISIONING = "provisioning"
    ADOPTION_FAILED = "adoption_failed"


class ConnectionType(StrEnum):
    """Device connection type."""

    WIRED = "wired"
    WIRELESS = "wireless"
    POE = "poe"
    FIBER = "fiber"


# ===========================================
# Device Model
# ===========================================


class Device(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Device - A network or security device discovered from a controller.

    Devices are synced from external controllers and represent the
    actual hardware in the network.
    """

    __tablename__ = "devices"
    __table_args__ = (
        Index("ix_devices_controller_id", "controller_id"),
        Index("ix_devices_site_id", "site_id"),
        Index("ix_devices_mac", "mac_address"),
        # One ALIVE device per real MAC. The discovery dedup is app-level and
        # races (overlapping syncs miss each other's locked rows) — this is the
        # DB backstop that makes ``discovery._discover_devices_for_controller_impl``'s
        # IntegrityError handler real. Excludes NULL *and* empty-string MACs:
        # adapters that surface a MAC-less "self" device (firewall/gateway) write
        # mac="" and are deduped by the app-level MAC-less fallback, not here.
        # Mirrors the migration's uq_devices_mac_alive so create_all() (tests,
        # dev bootstrap) and alembic agree.
        Index(
            "uq_devices_mac_alive",
            "mac_address",
            unique=True,
            postgresql_where=text(
                "mac_address IS NOT NULL AND mac_address <> '' AND deleted_at IS NULL"
            ),
        ),
        Index("ix_devices_status", "status"),
        Index("ix_devices_type", "device_type"),
        # Mirror the migration's PERF_INDEXES that aren't otherwise on the model,
        # so a create_all() fresh-install (scripts/migrate.py) gets them too —
        # the same model-vs-migration drift class that left uq_devices_mac_alive
        # uncreated on the live DB. (is_active/status/device_type are already
        # indexed via index=True / named indexes above; FKs are NOT auto-indexed
        # by Postgres, and the composite is create_all-invisible without this.)
        Index("ix_devices_type_site_deleted", "device_type", "site_id", "deleted_at"),
        Index("ix_devices_credential_id", "credential_id"),
        Index(
            "ix_devices_external_id",
            "external_id",
            unique=True,
            postgresql_where=text("external_id IS NOT NULL"),
        ),
        {"schema": "devices"},
    )

    # Foreign Keys
    controller_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Identity
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=True)  # XX:XX:XX:XX:XX:XX
    serial_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)  # ID in controller

    # Classification
    device_type: Mapped[DeviceType] = mapped_column(String(50), nullable=False)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String(100), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Network
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv4 or IPv6
    connection_type: Mapped[ConnectionType | None] = mapped_column(String(20), nullable=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Location
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    floor: Mapped[str | None] = mapped_column(String(50), nullable=True)
    room: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Status
    status: Mapped[DeviceStatus] = mapped_column(
        String(20),
        default=DeviceStatus.UNKNOWN,
        nullable=False,
    )
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    uptime_seconds: Mapped[int | None] = mapped_column(nullable=True)

    # Metrics (latest snapshot)
    cpu_usage_percent: Mapped[float | None] = mapped_column(nullable=True)
    memory_usage_percent: Mapped[float | None] = mapped_column(nullable=True)
    temperature_celsius: Mapped[float | None] = mapped_column(nullable=True)

    # Extended data (controller-specific)
    device_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Lifecycle (enterprise state machine)
    lifecycle_state: Mapped[str] = mapped_column(
        String(20),
        default="discovered",
        nullable=False,
        comment="FSM state: discovered, adopting, provisioning, managed, updating, offline, error, decommissioned, ignored",
    )
    lifecycle_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    lifecycle_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable error when lifecycle_state=error",
    )

    # Management
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_managed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Adoption & Onboarding
    is_adopted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    adopted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    adopted_by: Mapped[UUID | None] = mapped_column(nullable=True)  # user ID who adopted
    driver_id: Mapped[str | None] = mapped_column(String(100), nullable=True)  # matched driver
    credential_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    discovery_method: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )  # scanner, controller, agent
    discovery_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )  # raw scan data

    # Relationships
    controller: Mapped["Controller"] = relationship(
        "Controller",
        back_populates="devices",
    )
    site: Mapped["Site"] = relationship(
        "Site",
        back_populates="devices",
    )
    ports: Mapped[list["DevicePort"]] = relationship(
        "DevicePort",
        back_populates="device",
        cascade="all, delete-orphan",
    )


# ===========================================
# Device Port Model (for switches/APs)
# ===========================================


class PortType(StrEnum):
    """Port type enumeration."""

    ETHERNET = "ethernet"
    SFP = "sfp"
    SFP_PLUS = "sfp+"
    QSFP = "qsfp"
    CONSOLE = "console"
    USB = "usb"


class PortStatus(StrEnum):
    """Port status enumeration."""

    UP = "up"
    DOWN = "down"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class DevicePort(Base, UUIDMixin):
    """
    DevicePort - A physical or logical port on a device.

    Tracks port configuration and statistics.
    """

    __tablename__ = "device_ports"
    __table_args__ = (
        Index("ix_device_ports_device_id", "device_id"),
        Index("ix_device_ports_status", "status"),
        {"schema": "devices"},
    )

    # Foreign Key
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Identity
    port_number: Mapped[int] = mapped_column(nullable=False)
    name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    port_type: Mapped[PortType] = mapped_column(String(20), default=PortType.ETHERNET)

    # Status
    status: Mapped[PortStatus] = mapped_column(
        String(20),
        default=PortStatus.UNKNOWN,
        nullable=False,
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_poe_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Configuration
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    speed_mbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duplex: Mapped[str | None] = mapped_column(String(20), nullable=True)  # full, half, auto

    # PoE
    poe_power_watts: Mapped[float | None] = mapped_column(nullable=True)
    poe_class: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Statistics (latest)
    tx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    rx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    tx_packets: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    rx_packets: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    errors: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Connected device (if detected)
    connected_mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    connected_device_id: Mapped[UUID | None] = mapped_column(nullable=True)

    # Extended data
    port_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationship
    device: Mapped["Device"] = relationship(
        "Device",
        back_populates="ports",
    )


# ===========================================
# Device Client Model (for wireless clients)
# ===========================================


class DeviceClient(Base, UUIDMixin):
    """
    DeviceClient - A wireless client connected to a device (AP).

    Tracks wireless client connections and statistics.
    """

    __tablename__ = "device_clients"
    __table_args__ = (
        Index("ix_device_clients_device_id", "device_id"),
        Index("ix_device_clients_mac", "mac_address"),
        {"schema": "devices"},
    )

    # Foreign Key
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Identity
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Wireless details
    ssid: Mapped[str | None] = mapped_column(String(32), nullable=True)
    band: Mapped[str | None] = mapped_column(String(10), nullable=True)  # 2.4GHz, 5GHz, 6GHz
    channel: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signal_dbm: Mapped[int | None] = mapped_column(Integer, nullable=True)
    noise_dbm: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Connection
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Statistics
    tx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    rx_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    tx_rate_mbps: Mapped[float | None] = mapped_column(nullable=True)
    rx_rate_mbps: Mapped[float | None] = mapped_column(nullable=True)

    # Extended data
    client_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationship
    device: Mapped["Device"] = relationship("Device")


class DiscoveredHost(Base, UUIDMixin, SoftDeleteMixin):
    """A host the agent has SEEN on the network but that hasn't been
    adopted as a managed Device yet.

    Storage backing for `POST /api/v1/discovery/results` (HTTP push)
    and the WS `scan_result` handler in `services/remote_agent.py`.

    Dedup contract: (site_id, mac_address) is unique when mac is non-NULL.
    When mac is NULL (ICMP-only discovery) the row coexists with future
    MAC-keyed observations and is merged at the service layer once a
    MAC appears for the same IP. The dedup is enforced by the partial
    unique index ``uq_discovered_hosts_site_mac``.
    """

    __tablename__ = "discovered_hosts"
    __table_args__ = (
        Index("ix_discovered_hosts_site", "site_id"),
        Index("ix_discovered_hosts_org", "organization_id"),
        Index("ix_discovered_hosts_ip", "ip_address"),
        Index("ix_discovered_hosts_agent", "discovered_by_agent_id"),
        Index("ix_discovered_hosts_last_seen", "last_seen"),
        # Dedup (site_id, mac_address) when MAC is known — mirrors migration
        # 021. Without it on the model, a non-alembic create_all() (e.g. tests)
        # would allow duplicate discovered hosts per (site, mac).
        Index(
            "uq_discovered_hosts_site_mac",
            "site_id",
            "mac_address",
            unique=True,
            postgresql_where=text("mac_address IS NOT NULL AND deleted_at IS NULL"),
        ),
        {"schema": "devices"},
    )

    # Tenant scope
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Identity
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Classification (best guess; not authoritative)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manufacturer_confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Source attribution
    discovered_by_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.remote_agents.id", ondelete="SET NULL"),
        nullable=True,
    )
    # List of scanner names that have seen this host. e.g. ["arp","mdns","lldp"]
    discovered_via: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default=text("'[]'::jsonb"),
    )

    # Rich per-source data
    open_ports: Mapped[list[int]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default=text("'[]'::jsonb"),
    )
    services: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    mdns_services: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default=text("'[]'::jsonb"),
    )
    ssdp_info: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    http_title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_server: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # L2 topology hints (LLDP/CDP)
    lldp_chassis_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lldp_port_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lldp_system_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lldp_capabilities: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    # Heuristic adoption hints
    likely_device_types: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default=text("'[]'::jsonb"),
    )
    recommended_driver: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Adoption tracking
    is_adopted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    adopted_device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    adopted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ignored: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ignored_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Time bookkeeping
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )


class TopologyEdge(Base, UUIDMixin, SoftDeleteMixin):
    """L2 topology edge observed by the agent via LLDP/CDP/etc.

    One row per ``(site_id, agent_interface, neighbor_chassis,
    neighbor_port)`` tuple. Re-observations merge by advancing
    ``last_seen``; the dedup index is partial so soft-deleted rows
    don't block the unique constraint.

    Map to a managed Device by setting ``neighbor_device_id`` once an
    operator identifies the LLDP neighbor as a known device. Until
    then the edge is "unmapped" but still queryable from the topology
    view in the UI.
    """

    __tablename__ = "topology_edges"
    __table_args__ = (
        Index("ix_topology_edges_site", "site_id"),
        Index("ix_topology_edges_org", "organization_id"),
        Index("ix_topology_edges_neighbor_chassis", "neighbor_chassis_id"),
        Index("ix_topology_edges_neighbor_device", "neighbor_device_id"),
        Index("ix_topology_edges_last_seen", "last_seen"),
        # Dedup an edge sighting — mirrors migration 022. Without it on the
        # model, a non-alembic create_all() would allow duplicate edges for the
        # same (site, local iface, neighbor chassis, neighbor port).
        Index(
            "uq_topology_edges_dedup",
            "site_id",
            "local_interface",
            "neighbor_chassis_id",
            "neighbor_port_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        {"schema": "devices"},
    )

    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Source attribution
    discovered_by_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.remote_agents.id", ondelete="SET NULL"),
        nullable=True,
    )
    protocol: Mapped[str] = mapped_column(
        String(8),
        nullable=False,
        server_default=text("'lldp'"),
    )

    # Local side (agent host's interface that observed the frame)
    local_interface: Mapped[str] = mapped_column(String(64), nullable=False)

    # Neighbor side (advertised in LLDP/CDP TLVs)
    neighbor_chassis_id: Mapped[str] = mapped_column(String(64), nullable=False)
    neighbor_chassis_subtype: Mapped[str | None] = mapped_column(String(16), nullable=True)
    neighbor_port_id: Mapped[str] = mapped_column(String(64), nullable=False)
    neighbor_port_subtype: Mapped[str | None] = mapped_column(String(16), nullable=True)
    neighbor_port_description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    neighbor_system_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    neighbor_system_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    neighbor_capabilities: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    neighbor_mgmt_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Adoption: cross-link to a managed Device once an operator maps it
    neighbor_device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="SET NULL"),
        nullable=True,
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
