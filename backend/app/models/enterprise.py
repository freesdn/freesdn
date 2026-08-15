# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Enterprise Config Models
=======================================

Three-State Config Model, Device Groups, Site Groups,
Config Templates, Device Tags, and Device Health.

These are the foundational building blocks for enterprise-grade
network management: drift detection, template inheritance,
bulk operations, and health scoring.
"""

from datetime import date, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Organization, Site, User
    from app.models.devices import Device


# ==========================================================================
# Enumerations
# ==========================================================================


class LifecycleState(StrEnum):
    """Device lifecycle states — formal FSM."""

    DISCOVERED = "discovered"
    ADOPTING = "adopting"
    PROVISIONING = "provisioning"
    MANAGED = "managed"
    UPDATING = "updating"
    OFFLINE = "offline"
    ERROR = "error"
    DECOMMISSIONED = "decommissioned"
    IGNORED = "ignored"


class ConfigPushResult(StrEnum):
    """Result of a config push to a device."""

    PENDING = "pending"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class HealthStatus(StrEnum):
    """Aggregated health tier from score."""

    HEALTHY = "healthy"  # 90-100
    WARNING = "warning"  # 70-89
    DEGRADED = "degraded"  # 50-69
    CRITICAL = "critical"  # 0-49
    UNKNOWN = "unknown"  # not yet computed


class BulkOperationStatus(StrEnum):
    """Status of a bulk operation job."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"


class TemplateScope(StrEnum):
    """Where a config template is applied."""

    ORGANIZATION = "organization"
    SITE_GROUP = "site_group"
    SITE = "site"
    DEVICE_GROUP = "device_group"


class LifecycleTrigger(StrEnum):
    """What caused a lifecycle state transition."""

    USER_ACTION = "user_action"
    AUTO_DISCOVERY = "auto_discovery"
    AUTO_RECONCILE = "auto_reconcile"
    HEALTH_CHECK = "health_check"
    FIRMWARE_UPDATE = "firmware_update"
    SYSTEM = "system"
    AGENT = "agent"


# ==========================================================================
# Valid lifecycle transitions
# ==========================================================================

LIFECYCLE_TRANSITIONS: dict[LifecycleState, set[LifecycleState]] = {
    LifecycleState.DISCOVERED: {
        LifecycleState.ADOPTING,
        LifecycleState.IGNORED,
    },
    LifecycleState.ADOPTING: {
        LifecycleState.PROVISIONING,
        LifecycleState.ERROR,
        LifecycleState.DISCOVERED,  # adoption cancelled
    },
    LifecycleState.PROVISIONING: {
        LifecycleState.MANAGED,
        LifecycleState.ERROR,
    },
    LifecycleState.MANAGED: {
        LifecycleState.UPDATING,
        LifecycleState.PROVISIONING,  # drift re-provision
        LifecycleState.OFFLINE,
        LifecycleState.ERROR,
        LifecycleState.DECOMMISSIONED,
    },
    LifecycleState.UPDATING: {
        LifecycleState.MANAGED,
        LifecycleState.ERROR,
    },
    LifecycleState.OFFLINE: {
        LifecycleState.MANAGED,  # came back online
        LifecycleState.ERROR,
        LifecycleState.DECOMMISSIONED,
    },
    LifecycleState.ERROR: {
        LifecycleState.MANAGED,  # manual acknowledge + fix
        LifecycleState.PROVISIONING,  # retry provisioning
        LifecycleState.DECOMMISSIONED,
    },
    LifecycleState.DECOMMISSIONED: set(),  # terminal
    LifecycleState.IGNORED: {
        LifecycleState.ADOPTING,  # user changes mind
    },
}


# ==========================================================================
# Site Group Model
# ==========================================================================


class SiteGroup(Base, UUIDMixin, AuditMixin):
    """
    SiteGroup — Logical grouping of sites for template inheritance.

    Example groups: "Branch Offices", "Data Centers", "Retail Stores".
    Supports nesting (parent_id) for multi-level hierarchy.
    """

    __tablename__ = "site_groups"
    __table_args__ = (
        Index("ix_site_groups_org_id", "organization_id"),
        Index("ix_site_groups_parent_id", "parent_id"),
        UniqueConstraint("organization_id", "name", name="uq_site_groups_org_name"),
        {"schema": "core"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    parent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.site_groups.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Fields
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    parent: Mapped["SiteGroup | None"] = relationship(
        "SiteGroup",
        remote_side="SiteGroup.id",
        back_populates="children",
    )
    children: Mapped[list["SiteGroup"]] = relationship(
        "SiteGroup",
        back_populates="parent",
    )
    sites: Mapped[list["Site"]] = relationship(
        "Site",
        back_populates="site_group",
        foreign_keys="Site.site_group_id",
    )


# ==========================================================================
# Device Group Model
# ==========================================================================


class DeviceGroup(Base, UUIDMixin, AuditMixin):
    """
    DeviceGroup — Logical grouping of devices within a site.

    Devices can belong to a group via explicit membership or
    match rules (e.g. all APs on floor 3, all switches with tag "core").
    """

    __tablename__ = "device_groups"
    __table_args__ = (
        Index("ix_device_groups_org_id", "organization_id"),
        Index("ix_device_groups_site_id", "site_id"),
        UniqueConstraint("site_id", "name", name="uq_device_groups_site_name"),
        {"schema": "devices"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Fields
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Match rules — auto-populate group based on device properties
    # e.g. {"device_type": "access_point", "tags": ["floor-3"]}
    match_rules: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


# ==========================================================================
# Device Tag Model
# ==========================================================================


class DeviceTag(Base):
    """
    DeviceTag — Flexible labels on devices for grouping and policy.

    Tags are simple key strings (e.g. "floor-3", "core-switch", "guest-zone").
    Used by DeviceGroup match_rules and Config Template targeting.
    """

    __tablename__ = "device_tags"
    __table_args__ = (
        Index("ix_device_tags_tag", "tag"),
        Index("ix_device_tags_device_id", "device_id"),
        {"schema": "devices"},
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        primary_key=True,
    )
    tag: Mapped[str] = mapped_column(String(100), primary_key=True)


# ==========================================================================
# Device Group Membership (explicit)
# ==========================================================================


class DeviceGroupMembership(Base):
    """Explicit device ↔ group association."""

    __tablename__ = "device_group_members"
    __table_args__ = ({"schema": "devices"},)

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        primary_key=True,
    )
    group_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.device_groups.id", ondelete="CASCADE"),
        primary_key=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )


# ==========================================================================
# Three-State Device Config Model
# ==========================================================================


class DeviceConfig(Base, UUIDMixin, AuditMixin):
    """
    DeviceConfig — The heart of enterprise config management.

    Maintains three config states per device:
      - desired_config:  What templates + overrides say should be running
      - pushed_config:   What was last sent to the device via adapter
      - running_config:  What the device reports it's actually running

    drift = diff(desired_config, running_config)
    """

    __tablename__ = "device_configs"
    __table_args__ = (
        Index("ix_device_configs_org_id", "organization_id"),
        Index("ix_device_configs_drift", "organization_id", "has_drift"),
        UniqueConstraint("device_id", name="uq_device_configs_device"),
        {"schema": "devices"},
    )

    # Foreign Keys
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # ── The Three States ──

    desired_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Source of truth — resolved from template hierarchy + overrides",
    )
    pushed_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Last config pushed to device via adapter",
    )
    running_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Config read back from device (actual running state)",
    )

    # ── Push Metadata ──

    desired_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    desired_updated_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    push_result: Mapped[ConfigPushResult | None] = mapped_column(
        String(20),
        nullable=True,
    )
    push_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    running_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Drift ──

    has_drift: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="True when desired_config != running_config",
    )
    drift_details: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="JSON diff of desired vs running for quick inspection",
    )
    drift_detected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    drift_acknowledged: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # ── Reconciliation Settings ──

    auto_remediate: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="If True, reconciliation loop auto-pushes desired_config on drift",
    )

    # ── Optimistic Locking ──

    config_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )

    # ── Device-level config overrides ──
    # These are merged LAST during template resolution (most specific)
    device_overrides: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Per-device overrides applied on top of template hierarchy",
    )

    # Relationships
    device: Mapped["Device"] = relationship("Device", backref="config_state")


# ==========================================================================
# Config Template Model
# ==========================================================================


class ConfigTemplate(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    ConfigTemplate — Reusable config fragments with hierarchical inheritance.

    Templates apply at different scopes (org → site_group → site → device_group)
    and are merged top-down. Lower scopes override higher scopes.
    """

    __tablename__ = "config_templates"
    __table_args__ = (
        Index("ix_config_templates_org_id", "organization_id"),
        Index("ix_config_templates_scope", "scope", "scope_id"),
        {"schema": "core"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Identity
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Scope
    scope: Mapped[TemplateScope] = mapped_column(
        String(20),
        nullable=False,
        comment="Level in hierarchy: organization, site_group, site, device_group",
    )
    scope_id: Mapped[UUID | None] = mapped_column(
        nullable=True,
        comment="ID of the scoped entity (site_group, site, or device_group). NULL for org-level.",
    )

    # Target device type (NULL = all device types)
    device_type: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        comment="Filter: only apply to this device_type. NULL = all.",
    )

    # Template content — partial config merged during resolution
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Partial config fragment merged during template resolution",
    )

    # Ordering within same scope level (lower = higher priority)
    priority: Mapped[int] = mapped_column(
        Integer,
        default=100,
        nullable=False,
    )

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")


# ==========================================================================
# Device Lifecycle Log
# ==========================================================================


class DeviceLifecycleLog(Base, UUIDMixin):
    """
    DeviceLifecycleLog — Audit trail of every lifecycle state transition.

    Every time a device changes state (discovered → adopting → managed → etc.),
    a row is inserted here with who/what/when/why.
    """

    __tablename__ = "device_lifecycle_log"
    __table_args__ = (
        Index("ix_lifecycle_log_device", "device_id", "created_at"),
        Index("ix_lifecycle_log_org", "organization_id", "created_at"),
        {"schema": "devices"},
    )

    # Foreign Keys
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Transition
    from_state: Mapped[LifecycleState] = mapped_column(String(20), nullable=False)
    to_state: Mapped[LifecycleState] = mapped_column(String(20), nullable=False)
    trigger: Mapped[LifecycleTrigger] = mapped_column(String(30), nullable=False)

    # Who / Why
    triggered_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User ID — NULL if system-triggered",
    )
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # When
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )


# ==========================================================================
# Device Health Model
# ==========================================================================


class DeviceHealth(Base):
    """
    DeviceHealth — Composite health score computed from multiple signals.

    Updated periodically by a Celery worker. Drives the dashboard
    health indicators and alerting thresholds.
    """

    __tablename__ = "device_health"
    __table_args__ = (
        Index("ix_device_health_org", "organization_id", "health_status"),
        Index("ix_device_health_site", "site_id", "health_score"),
        {"schema": "devices"},
    )

    # Primary key
    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
    )

    # 1-to-1 with Device
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=True,
    )

    # ── Overall Score ──

    health_score: Mapped[int] = mapped_column(
        SmallInteger,
        default=100,
        nullable=False,
        comment="Composite score 0-100",
    )
    health_status: Mapped[HealthStatus] = mapped_column(
        String(20),
        default=HealthStatus.UNKNOWN,
        nullable=False,
    )

    # ── Component Scores ──
    # Column names must match the migration: score_reachability, score_latency, etc.

    reachability_score: Mapped[int | None] = mapped_column(
        "score_reachability",
        SmallInteger,
        nullable=True,
    )
    latency_score: Mapped[int | None] = mapped_column(
        "score_latency",
        SmallInteger,
        nullable=True,
    )
    drift_score: Mapped[int | None] = mapped_column(
        "score_drift",
        SmallInteger,
        nullable=True,
    )
    error_score: Mapped[int | None] = mapped_column(
        "score_error_rate",
        SmallInteger,
        nullable=True,
    )
    utilization_score: Mapped[int | None] = mapped_column(
        "score_utilization",
        SmallInteger,
        nullable=True,
    )
    firmware_score: Mapped[int | None] = mapped_column(
        "score_firmware",
        SmallInteger,
        nullable=True,
    )

    # ── Metadata ──

    # Last 24h of scores as JSON array for dashboard sparklines
    score_history: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )

    # Relationships
    device: Mapped["Device"] = relationship("Device", backref="health")

    # ── Utility ──

    @staticmethod
    def compute_status(score: int) -> HealthStatus:
        """Derive HealthStatus tier from numeric score."""
        if score >= 90:
            return HealthStatus.HEALTHY
        if score >= 70:
            return HealthStatus.WARNING
        if score >= 50:
            return HealthStatus.DEGRADED
        return HealthStatus.CRITICAL


# --------------------------------------------------------------------------
# Bulk Operations
# --------------------------------------------------------------------------


class BulkOperation(Base, UUIDMixin, AuditMixin):
    """
    Tracks a bulk operation job (push_config, reboot, firmware_update).

    Stores the target scope, rollout strategy, per-device results,
    and enables staged rollouts with automatic rollback on failure.
    """

    __tablename__ = "bulk_operations"
    __table_args__ = (
        Index("ix_bulk_operations_org_status", "organization_id", "status"),
        {"schema": "devices"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id"),
        nullable=False,
    )
    operation: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=BulkOperationStatus.PENDING,
    )
    # Target specification as JSON
    target: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    # Optional config payload
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Rollout strategy
    rollout_strategy: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Progress tracking
    devices_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    devices_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    devices_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    devices_skipped: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_stage: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)

    # Per-device results: [{device_id, status, error?, duration_ms}]
    device_results: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)

    # User who triggered + optional error
    triggered_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id"),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
        foreign_keys=[organization_id],
    )
    triggered_by_user: Mapped["User"] = relationship(
        "User",
        foreign_keys=[triggered_by],
    )


# ==========================================================================
# Auto-Backup Policy
# ==========================================================================


class AutoBackupPolicy(Base, UUIDMixin, AuditMixin):
    """
    AutoBackupPolicy — Auto-backup before config changes.

    Controls whether automatic backups are taken before specific
    operations (config push, firmware update, adoption) and how
    many backup snapshots to retain per device.
    """

    __tablename__ = "auto_backup_policies"
    __table_args__ = (
        UniqueConstraint("organization_id", name="uq_auto_backup_policies_org"),
        {"schema": "enterprise"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # Triggers
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    trigger_on_config_push: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    trigger_on_firmware_update: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    trigger_on_adoption: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Retention
    retention_count: Mapped[int] = mapped_column(
        Integer,
        default=5,
        nullable=False,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")


# ==========================================================================
# Config Version (Immutable Config Snapshots)
# ==========================================================================


class ConfigVersion(Base, UUIDMixin):
    """
    ConfigVersion — Immutable config snapshot.

    Every config change (push, manual save, rollback, adoption) creates
    a new ConfigVersion row. Enables full audit trail and rollback.
    """

    __tablename__ = "config_versions"
    __table_args__ = (
        Index("ix_config_versions_device", "device_id", "version_number"),
        Index("ix_config_versions_org_device", "organization_id", "device_id"),
        UniqueConstraint("device_id", "version_number", name="uq_config_versions_device_version"),
        {"schema": "enterprise"},
    )

    # Foreign Keys
    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Versioning
    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    change_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="config_push, manual_save, rollback, adoption",
    )

    # Who created this version
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # When
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )

    # Relationships
    device: Mapped["Device"] = relationship("Device")
    created_by_user: Mapped["User | None"] = relationship("User")


# ==========================================================================
# Health Daily Snapshot
# ==========================================================================


class HealthDailySnapshot(Base):
    """
    HealthDailySnapshot — Daily aggregation of device health per org/site.

    Populated nightly by a Celery task. Drives the 7d/30d/90d history
    charts on the health dashboard.
    """

    __tablename__ = "health_daily_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "site_id",
            "snapshot_date",
            name="uq_health_daily_org_site_date",
        ),
        {"schema": "enterprise"},
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id"),
        nullable=False,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id"),
        nullable=True,
    )
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False)
    avg_health_score: Mapped[float] = mapped_column(Float, nullable=False)
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    healthy_count: Mapped[int] = mapped_column(Integer, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, default=0)
    degraded_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
