# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - ZTP & Provisioning Models
========================================

Zero-Touch Provisioning (ZTP) models for automated device adoption:
- AutoAdoptionRule: criteria-based auto-adoption rules
- MACPreRegistration: pre-register MACs for instant adoption
- AdoptionJob: multi-step adoption pipeline tracking
- ProvisioningProfile: pre-built config packages for device types
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
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Organization
    from app.models.devices import Device


# ==========================================================================
# Enumerations
# ==========================================================================


class AdoptionJobStatus(StrEnum):
    """Adoption pipeline status."""

    PENDING = "pending"
    ADOPTING = "adopting"
    FIRMWARE_CHECK = "firmware_check"
    PROVISIONING = "provisioning"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"


class AdoptionTrigger(StrEnum):
    """How the adoption was triggered."""

    AUTO_RULE = "auto_rule"
    MAC_PREREGISTER = "mac_preregister"
    MANUAL = "manual"
    API = "api"


# ==========================================================================
# Auto-Adoption Rule
# ==========================================================================


class AutoAdoptionRule(Base, UUIDMixin, AuditMixin):
    """
    Rule that auto-adopts devices matching specified criteria.

    Rules are evaluated in priority order (lower = higher priority) when
    a new device is discovered. The first matching rule triggers adoption.
    """

    __tablename__ = "auto_adoption_rules"
    __table_args__ = (
        Index("ix_ztp_rules_org", "organization_id"),
        Index("ix_ztp_rules_priority", "priority"),
        Index("ix_ztp_rules_org_enabled_priority", "organization_id", "enabled", "priority"),
        {"schema": "devices"},
    )

    # Ownership
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Rule metadata
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Match criteria (all optional — AND logic, NULL = match any)
    match_device_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    match_manufacturer: Mapped[str | None] = mapped_column(String(100), nullable=True)
    match_model_pattern: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="SQL LIKE pattern, e.g. 'EAP%' or 'TL-SG%'",
    )
    match_controller_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )
    match_site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Actions on match
    target_site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
        comment="Move device to this site on adoption",
    )
    provisioning_profile_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.provisioning_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )
    auto_firmware_update: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", lazy="selectin")

    def __repr__(self) -> str:
        return f"<AutoAdoptionRule {self.name} priority={self.priority}>"


# ==========================================================================
# MAC Pre-Registration
# ==========================================================================


class MACPreRegistration(Base, UUIDMixin, AuditMixin):
    """
    Pre-register MAC addresses for instant adoption.

    When a device with a pre-registered MAC is discovered, it is
    immediately adopted with the specified settings.
    """

    __tablename__ = "mac_pre_registrations"
    __table_args__ = (
        UniqueConstraint("mac_address", "organization_id", name="uq_mac_preregistrations_mac_org"),
        Index("ix_mac_prereg_org", "organization_id"),
        Index("ix_mac_prereg_mac", "mac_address"),
        {"schema": "devices"},
    )

    # Ownership
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Registration data
    mac_address: Mapped[str] = mapped_column(
        String(17),
        nullable=False,
        comment="Normalized MAC: AA:BB:CC:DD:EE:FF",
    )
    device_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Adoption settings
    target_site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )
    provisioning_profile_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.provisioning_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )

    # State tracking
    adopted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    adopted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    adopted_device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="SET NULL"),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<MACPreRegistration {self.mac_address} adopted={self.adopted}>"


# ==========================================================================
# Adoption Job
# ==========================================================================


class AdoptionJob(Base, UUIDMixin, AuditMixin):
    """
    Tracks a multi-step adoption pipeline for a device.

    Pipeline steps: validate → adopt → firmware_check → provision → verify
    """

    __tablename__ = "adoption_jobs"
    __table_args__ = (
        Index("ix_adoption_jobs_device", "device_id"),
        Index("ix_adoption_jobs_status", "status"),
        Index("ix_adoption_jobs_org", "organization_id"),
        {"schema": "devices"},
    )

    # References
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Pipeline state
    status: Mapped[str] = mapped_column(
        String(30),
        default=AdoptionJobStatus.PENDING,
        nullable=False,
    )
    current_step: Mapped[str] = mapped_column(
        String(30),
        default="validate",
        nullable=False,
    )
    steps_completed: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Trigger info
    triggered_by: Mapped[str] = mapped_column(
        String(30),
        default=AdoptionTrigger.MANUAL,
        nullable=False,
    )
    rule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.auto_adoption_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    profile_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.provisioning_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    device: Mapped["Device"] = relationship("Device", lazy="selectin")

    def __repr__(self) -> str:
        return f"<AdoptionJob device={self.device_id} status={self.status}>"


# ==========================================================================
# Provisioning Profile
# ==========================================================================


class ProvisioningProfile(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Pre-built config package for device types.

    Applied during ZTP adoption or manually to existing devices.
    Examples: "Office AP", "Retail Switch", "Warehouse Gateway"
    """

    __tablename__ = "provisioning_profiles"
    __table_args__ = (
        Index("ix_prov_profiles_org", "organization_id"),
        Index("ix_prov_profiles_type", "device_type"),
        {"schema": "devices"},
    )

    # Ownership
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Profile metadata
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Target device type: access_point, switch, gateway, etc.",
    )
    manufacturer: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="Optional: restrict to specific manufacturer",
    )

    # Config payload (merged into desired_config during adoption)
    config_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Config blob: {wifi: [...], vlans: [...], ports: [...]}",
    )

    # Optional link to enterprise ConfigTemplate for inheritance
    config_template_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.config_templates.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Firmware settings
    auto_firmware_update: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    target_firmware_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Default profile per device_type per org
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<ProvisioningProfile {self.name} type={self.device_type}>"
