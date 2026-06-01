# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Gateway Module Models
====================================

All SQLAlchemy models for the gateway / orchestration module.

Organised into three groups:
  1.  Orchestration models   – Site roles, canonical resources, distribution, drift
  2.  Imported-cache models  – Read-only snapshots of brain configuration
  3.  Supporting models      – Templates, import sessions, suppression rules
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, TimestampMixin, UUIDMixin

# ═══════════════════════════════════════════════════════════════════════════════
# Enumerations
# ═══════════════════════════════════════════════════════════════════════════════


class NetworkRole(StrEnum):
    """Role a device plays in site networking."""

    BRAIN = "brain"
    BRAIN_STANDBY = "brain_standby"
    LIMB = "limb"
    OBSERVER = "observer"


class ManagementState(StrEnum):
    """How FreeSdn manages a resource."""

    MANAGED = "managed"
    ADOPTED = "adopted"
    MONITORED = "monitored"
    IGNORED = "ignored"


class DistributionStatus(StrEnum):
    """Status of a distribution action."""

    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class DriftType(StrEnum):
    """Type of configuration drift."""

    RESOURCE_MISSING = "resource_missing"
    RESOURCE_MODIFIED = "resource_modified"
    RESOURCE_ADDED = "resource_added"
    SUPPRESSION_VIOLATED = "suppression_violated"
    TAG_REMOVED = "tag_removed"


class DriftSeverity(StrEnum):
    """Severity of a drift event."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class DriftResolution(StrEnum):
    """How a drift event was resolved."""

    PENDING = "pending"
    AUTO_FIXED = "auto_fixed"
    MANUALLY_FIXED = "manually_fixed"
    ACCEPTED = "accepted"
    IGNORED = "ignored"


class ImportStatus(StrEnum):
    """Import wizard session status."""

    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VLANPurpose(StrEnum):
    """Intended purpose of a VLAN."""

    GENERAL = "general"
    MANAGEMENT = "management"
    GUEST = "guest"
    IOT = "iot"
    VOIP = "voip"
    CAMERAS = "cameras"
    SERVERS = "servers"
    DMZ = "dmz"


class ResourceAuthority(StrEnum):
    """Who is authoritative for a resource type at a site."""

    BRAIN = "brain"
    LIMB = "limb"
    FREESDN = "freesdn"
    EXTERNAL = "external"


class DNSRecordType(StrEnum):
    """DNS record types."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    PTR = "PTR"
    MX = "MX"
    TXT = "TXT"
    SRV = "SRV"


class AddressGroupType(StrEnum):
    """Address group / alias types."""

    NETWORK = "network"
    HOST = "host"
    URL = "url"


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  Site Role Map
# ═══════════════════════════════════════════════════════════════════════════════


class SiteRoleMap(Base, UUIDMixin, TimestampMixin):
    """
    Maps devices to roles at a site.

    Stores which device is the "brain" (firewall/router), which are "limbs"
    (switches, APs), and the per-resource authority defaults.
    """

    __tablename__ = "gw_site_role_maps"
    __table_args__ = (
        Index("ix_gw_role_maps_org", "organization_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_reconciled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Per-resource authority defaults  (see ResourceAuthority enum)
    authority_map: Mapped[dict] = mapped_column(
        JSONB,
        default=lambda: {
            "vlan_interface": ResourceAuthority.BRAIN,
            "vlan_l2": ResourceAuthority.FREESDN,
            "dhcp_scope": ResourceAuthority.BRAIN,
            "dns_record": ResourceAuthority.BRAIN,
            "address_group": ResourceAuthority.BRAIN,
            "firewall_rule": ResourceAuthority.BRAIN,
            "nat_rule": ResourceAuthority.BRAIN,
            "vpn_tunnel": ResourceAuthority.BRAIN,
            "port_profile": ResourceAuthority.LIMB,
            "ssid": ResourceAuthority.LIMB,
            "poe": ResourceAuthority.LIMB,
        },
    )

    # Relationships
    assignments: Mapped[list[SiteRoleAssignment]] = relationship(
        "SiteRoleAssignment",
        back_populates="role_map",
        cascade="all, delete-orphan",
        order_by="SiteRoleAssignment.priority",
    )


class SiteRoleAssignment(Base, UUIDMixin, TimestampMixin):
    """
    Assigns a role to a specific device at a site.

    Polymorphic: exactly one of ``gateway_id`` or ``controller_id`` must be set.
    - Brain devices are typically gateway connections (OPNsense, pfSense, MikroTik).
    - Limb devices can be either gateway connections OR controllers (Omada, UniFi).
    """

    __tablename__ = "gw_site_role_assignments"
    __table_args__ = (
        Index("ix_gw_role_assign_map", "role_map_id"),
        Index("ix_gw_role_assign_controller", "controller_id"),
        CheckConstraint(
            "(gateway_id IS NOT NULL AND controller_id IS NULL) OR "
            "(gateway_id IS NULL AND controller_id IS NOT NULL)",
            name="ck_role_assign_one_device",
        ),
        {"schema": "gateway"},
    )

    role_map_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("gateway.gw_site_role_maps.id", ondelete="CASCADE"),
        nullable=False,
    )
    gateway_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=True,
    )
    controller_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.controllers.id", ondelete="CASCADE"),
        nullable=True,
    )

    # "gateway" or "controller" — denormalized for fast queries
    device_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="gateway",
    )

    role: Mapped[str] = mapped_column(String(20), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=0)

    # Discovered capabilities (probed during import)
    capabilities: Mapped[dict] = mapped_column(JSONB, default=dict)
    # {"can_vlan": true, "can_dhcp": true, "can_dns": true, ...}

    suppress_dhcp: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    role_map: Mapped[SiteRoleMap] = relationship(
        "SiteRoleMap",
        back_populates="assignments",
    )

    @property
    def device_id(self) -> UUID:
        """Return whichever FK is set."""
        return self.gateway_id or self.controller_id  # type: ignore[return-value]


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  Canonical Resource Models
# ═══════════════════════════════════════════════════════════════════════════════


class CanonicalVLAN(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Platform-agnostic VLAN definition.

    The *desired state* that the Distribution Engine pushes to brain + limbs.
    """

    __tablename__ = "gw_canonical_vlans"
    __table_args__ = (
        Index("ix_gw_vlans_org", "organization_id"),
        Index("ix_gw_vlans_site", "site_id"),
        UniqueConstraint("site_id", "vlan_id", name="uq_gw_vlan_per_site"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # VLAN identity
    vlan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # L3 configuration (applied to brain)
    subnet: Mapped[str] = mapped_column(String(18), nullable=False)
    gateway_ip: Mapped[str] = mapped_column(String(45), nullable=False)

    # DHCP (brain-side)
    dhcp_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    dhcp_range_start: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dhcp_range_end: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dhcp_lease_time: Mapped[int] = mapped_column(Integer, default=86400)
    dhcp_dns_servers: Mapped[list] = mapped_column(JSONB, default=list)
    dhcp_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Purpose & management
    purpose: Mapped[str] = mapped_column(
        String(20),
        default=VLANPurpose.GENERAL,
    )
    management_state: Mapped[str] = mapped_column(
        String(20),
        default=ManagementState.MANAGED,
    )

    # Source tracking  (null → created in FreeSdn)
    source_device_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Template reference (optional)
    template_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("gateway.gw_vlan_templates.id", ondelete="SET NULL"),
        nullable=True,
    )

    # External IDs on real devices  ({device_uuid: "opt3"})
    external_ids: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    dhcp_scope: Mapped[CanonicalDHCPScope | None] = relationship(
        "CanonicalDHCPScope",
        back_populates="vlan",
        uselist=False,
        cascade="all, delete-orphan",
    )
    dhcp_reservations: Mapped[list[CanonicalDHCPReservation]] = relationship(
        "CanonicalDHCPReservation",
        back_populates="vlan",
        cascade="all, delete-orphan",
    )
    address_group: Mapped[CanonicalAddressGroup | None] = relationship(
        "CanonicalAddressGroup",
        primaryjoin="CanonicalVLAN.id == foreign(CanonicalAddressGroup.source_vlan_id)",
        uselist=False,
    )


class CanonicalDHCPScope(Base, UUIDMixin, TimestampMixin):
    """
    DHCP scope — always served by the brain device.
    """

    __tablename__ = "gw_canonical_dhcp_scopes"
    __table_args__ = (
        Index("ix_gw_dhcp_scopes_site", "site_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    vlan_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("gateway.gw_canonical_vlans.id", ondelete="CASCADE"),
        nullable=False,
    )

    range_start: Mapped[str] = mapped_column(String(45), nullable=False)
    range_end: Mapped[str] = mapped_column(String(45), nullable=False)
    subnet_mask: Mapped[str] = mapped_column(String(45), nullable=False)
    gateway: Mapped[str] = mapped_column(String(45), nullable=False)
    lease_time: Mapped[int] = mapped_column(Integer, default=86400)

    # DHCP options
    dns_servers: Mapped[list] = mapped_column(JSONB, default=list)
    ntp_servers: Mapped[list] = mapped_column(JSONB, default=list)
    domain_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    custom_options: Mapped[dict] = mapped_column(JSONB, default=dict)

    management_state: Mapped[str] = mapped_column(
        String(20),
        default=ManagementState.MANAGED,
    )
    external_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Relationships
    vlan: Mapped[CanonicalVLAN] = relationship(
        "CanonicalVLAN",
        back_populates="dhcp_scope",
    )


class CanonicalDHCPReservation(Base, UUIDMixin, TimestampMixin):
    """Static DHCP reservation — applied to brain."""

    __tablename__ = "gw_canonical_dhcp_reservations"
    __table_args__ = (
        Index("ix_gw_dhcp_res_vlan", "vlan_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    vlan_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("gateway.gw_canonical_vlans.id", ondelete="CASCADE"),
        nullable=False,
    )

    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    management_state: Mapped[str] = mapped_column(
        String(20),
        default=ManagementState.MANAGED,
    )
    external_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Relationships
    vlan: Mapped[CanonicalVLAN] = relationship(
        "CanonicalVLAN",
        back_populates="dhcp_reservations",
    )


class CanonicalDNSRecord(Base, UUIDMixin, TimestampMixin):
    """DNS record — applied to brain's DNS resolver/forwarder."""

    __tablename__ = "gw_canonical_dns_records"
    __table_args__ = (
        Index("ix_gw_dns_site", "site_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    record_type: Mapped[str] = mapped_column(String(10), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    ttl: Mapped[int] = mapped_column(Integer, default=3600)
    priority: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    management_state: Mapped[str] = mapped_column(
        String(20),
        default=ManagementState.MANAGED,
    )
    external_id: Mapped[str | None] = mapped_column(String(100), nullable=True)


class CanonicalAddressGroup(Base, UUIDMixin, TimestampMixin):
    """Address group / alias — applied to brain for firewall object references."""

    __tablename__ = "gw_canonical_address_groups"
    __table_args__ = (
        Index("ix_gw_addrgrp_site", "site_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    group_type: Mapped[str] = mapped_column(String(20), nullable=False)
    members: Mapped[list] = mapped_column(JSONB, default=list)

    auto_generated: Mapped[bool] = mapped_column(Boolean, default=False)
    source_vlan_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("gateway.gw_canonical_vlans.id", ondelete="SET NULL"),
        nullable=True,
    )

    management_state: Mapped[str] = mapped_column(
        String(20),
        default=ManagementState.MANAGED,
    )
    external_id: Mapped[str | None] = mapped_column(String(100), nullable=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 3.  Distribution Engine Models
# ═══════════════════════════════════════════════════════════════════════════════


class DistributionRecord(Base, UUIDMixin, TimestampMixin):
    """Log of a distribution action."""

    __tablename__ = "gw_distribution_records"
    __table_args__ = (
        Index("ix_gw_dist_site", "site_id"),
        Index("ix_gw_dist_status", "status"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # What was distributed
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    # create | update | delete | suppress

    # Plan  (list of steps per tier)
    plan: Mapped[dict] = mapped_column(JSONB, default=dict)
    step_results: Mapped[list] = mapped_column(JSONB, default=list)

    # Execution
    status: Mapped[str] = mapped_column(
        String(20),
        default=DistributionStatus.PENDING,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Rollback
    rollback_plan: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    rollback_executed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Error details
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    error_device_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )
    error_tier: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Who triggered it
    triggered_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )


class DistributionLock(Base):
    """
    Prevents concurrent distributions to the same site.

    Only one distribution can run per site at a time.  Locks auto-expire
    after 5 minutes to handle worker crashes.
    """

    __tablename__ = "gw_distribution_locks"
    __table_args__ = ({"schema": "gateway"},)

    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
    )
    locked_by: Mapped[str] = mapped_column(String(100), nullable=False)
    locked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    distribution_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 4.  Drift Detection Models
# ═══════════════════════════════════════════════════════════════════════════════


class DriftEvent(Base, UUIDMixin, TimestampMixin):
    """Record of a detected configuration drift."""

    __tablename__ = "gw_drift_events"
    __table_args__ = (
        Index("ix_gw_drift_site", "site_id"),
        Index("ix_gw_drift_severity", "severity"),
        Index("ix_gw_drift_resolution", "resolution"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=False,
    )

    drift_type: Mapped[str] = mapped_column(String(30), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )

    expected_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    actual_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)

    # Resolution
    resolution: Mapped[str] = mapped_column(
        String(20),
        default=DriftResolution.PENDING,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 5.  Suppression Rules
# ═══════════════════════════════════════════════════════════════════════════════


class SuppressionRule(Base, UUIDMixin, TimestampMixin):
    """Active suppression of a capability on a device."""

    __tablename__ = "gw_suppression_rules"
    __table_args__ = (
        Index("ix_gw_suppress_site", "site_id"),
        Index("ix_gw_suppress_device", "device_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=False,
    )

    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scope: Mapped[str] = mapped_column(String(100), nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    suppression_action: Mapped[str] = mapped_column(String(50), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 6.  Import Wizard
# ═══════════════════════════════════════════════════════════════════════════════


class ImportSession(Base, UUIDMixin, TimestampMixin):
    """Tracks the state of an import / reconciliation wizard session."""

    __tablename__ = "gw_import_sessions"
    __table_args__ = (
        Index("ix_gw_import_site", "site_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # State machine
    current_step: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(
        String(20),
        default=ImportStatus.IN_PROGRESS,
    )

    # Per-step payloads (flexible JSONB so the wizard is versionable)
    discovered_devices: Mapped[dict] = mapped_column(JSONB, default=dict)
    role_assignments: Mapped[dict] = mapped_column(JSONB, default=dict)
    scan_results: Mapped[dict] = mapped_column(JSONB, default=dict)
    conflicts: Mapped[list] = mapped_column(JSONB, default=list)
    reconciliation_decisions: Mapped[dict] = mapped_column(JSONB, default=dict)
    distribution_ids: Mapped[list] = mapped_column(JSONB, default=list)
    verification_report: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Who ran it
    initiated_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 7.  VLAN Templates
# ═══════════════════════════════════════════════════════════════════════════════


class VLANTemplate(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Org-level VLAN template.

    Templates provide a reusable blueprint for canonical VLANs so that
    new sites can be stood up with a consistent VLAN scheme.
    """

    __tablename__ = "gw_vlan_templates"
    __table_args__ = (
        Index("ix_gw_tmpl_org", "organization_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # VLAN defaults
    vlan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    subnet_template: Mapped[str] = mapped_column(String(18), nullable=False)
    gateway_ip_template: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        server_default="",
    )
    purpose: Mapped[str] = mapped_column(
        String(20),
        default=VLANPurpose.GENERAL,
    )
    dhcp_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    dhcp_options: Mapped[dict] = mapped_column(JSONB, default=dict)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# 8.  Imported Cache Models  (read-only snapshots from brain)
# ═══════════════════════════════════════════════════════════════════════════════


class ImportedFirewallRule(Base, UUIDMixin, TimestampMixin):
    """Cached firewall rule from brain — read-only display."""

    __tablename__ = "gw_imported_firewall_rules"
    __table_args__ = (
        Index("ix_gw_fw_rule_site", "site_id"),
        Index("ix_gw_fw_rule_device", "device_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=False,
    )

    external_id: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    rule_index: Mapped[int] = mapped_column(Integer, default=0)
    direction: Mapped[str] = mapped_column(String(20), nullable=False)
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    source: Mapped[dict] = mapped_column(JSONB, default=dict)
    destination: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    last_hit: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)


class ImportedNATRule(Base, UUIDMixin, TimestampMixin):
    """Cached NAT rule from brain — read-only display."""

    __tablename__ = "gw_imported_nat_rules"
    __table_args__ = (
        Index("ix_gw_nat_site", "site_id"),
        Index("ix_gw_nat_device", "device_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=False,
    )

    external_id: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    nat_type: Mapped[str] = mapped_column(String(20), nullable=False)
    source: Mapped[dict] = mapped_column(JSONB, default=dict)
    destination: Mapped[dict] = mapped_column(JSONB, default=dict)
    translation: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)


class ImportedVPNTunnel(Base, UUIDMixin, TimestampMixin):
    """Cached VPN tunnel from brain — read-only display."""

    __tablename__ = "gw_imported_vpn_tunnels"
    __table_args__ = (
        Index("ix_gw_vpn_site", "site_id"),
        Index("ix_gw_vpn_device", "device_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=False,
    )

    external_id: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    vpn_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    local_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    remote_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)

    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)


class ImportedIDSEvent(Base, UUIDMixin, TimestampMixin):
    """Cached IDS/IPS alert from brain — read-only display."""

    __tablename__ = "gw_imported_ids_events"
    __table_args__ = (
        Index("ix_gw_ids_site", "site_id"),
        Index("ix_gw_ids_severity", "severity"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=False,
    )

    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    signature: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action_taken: Mapped[str | None] = mapped_column(String(20), nullable=True)
    message: Mapped[str | None] = mapped_column(String(500), nullable=True)

    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)


class ImportedDHCPLease(Base, UUIDMixin, TimestampMixin):
    """Cached DHCP lease from brain — read-only display."""

    __tablename__ = "gw_imported_dhcp_leases"
    __table_args__ = (
        Index("ix_gw_dhcp_lease_site", "site_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=False,
    )

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    interface: Mapped[str | None] = mapped_column(String(50), nullable=True)
    starts: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    ends: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    status: Mapped[str | None] = mapped_column(String(20), nullable=True)

    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class ImportedInterface(Base, UUIDMixin, TimestampMixin):
    """Cached network interface from brain — read-only display."""

    __tablename__ = "gw_imported_interfaces"
    __table_args__ = (
        Index("ix_gw_iface_site", "site_id"),
        {"schema": "gateway"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("firewall.gateway_connections.id", ondelete="CASCADE"),
        nullable=False,
    )

    external_id: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    if_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    mtu: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_up: Mapped[bool] = mapped_column(Boolean, default=False)
    ipv4_address: Mapped[str | None] = mapped_column(String(18), nullable=True)
    ipv4_subnet: Mapped[str | None] = mapped_column(String(18), nullable=True)
    ipv6_address: Mapped[str | None] = mapped_column(String(43), nullable=True)
    vlan_tag: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parent_interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)

    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# ALL_MODELS  — used by module.get_models()
# ═══════════════════════════════════════════════════════════════════════════════

ALL_MODELS: list[type] = [
    SiteRoleMap,
    SiteRoleAssignment,
    CanonicalVLAN,
    CanonicalDHCPScope,
    CanonicalDHCPReservation,
    CanonicalDNSRecord,
    CanonicalAddressGroup,
    DistributionRecord,
    DistributionLock,
    DriftEvent,
    SuppressionRule,
    ImportSession,
    VLANTemplate,
    ImportedFirewallRule,
    ImportedNATRule,
    ImportedVPNTunnel,
    ImportedIDSEvent,
    ImportedDHCPLease,
    ImportedInterface,
]
