# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Firmware Management Models
==========================================

SQLAlchemy models for firmware lifecycle management:
- FirmwareImage: Firmware repository catalog
- DeviceFirmwareStatus: Per-device firmware tracking
- FirmwareUpgradeJob: Background upgrade operations
- FirmwareSchedule: Automated upgrade policies
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin

if TYPE_CHECKING:
    pass


# =============================================================================
# Enums
# =============================================================================


class ReleaseType(StrEnum):
    STABLE = "stable"
    BETA = "beta"
    RC = "rc"
    HOTFIX = "hotfix"
    NIGHTLY = "nightly"


class FirmwareJobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIALLY_FAILED = "partially_failed"


class ScheduleFrequency(StrEnum):
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ON_RELEASE = "on_release"


# =============================================================================
# Models
# =============================================================================


class FirmwareImage(Base, UUIDMixin, AuditMixin):
    """Firmware image in the repository catalog."""

    __tablename__ = "firmware_images"
    __table_args__ = (
        Index("ix_firmware_vendor_model", "vendor", "model"),
        Index("ix_firmware_version", "version"),
        Index("ix_firmware_device_type", "device_type"),
        Index("ix_firmware_release_type", "release_type"),
        {"schema": "core"},
    )

    # Identity
    vendor: Mapped[str] = mapped_column(String(100), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    device_type: Mapped[str | None] = mapped_column(String(50))
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    release_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ReleaseType.STABLE
    )

    # Metadata
    display_name: Mapped[str | None] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    release_notes: Mapped[str | None] = mapped_column(Text)
    release_notes_url: Mapped[str | None] = mapped_column(String(512))
    release_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # File details
    file_path: Mapped[str | None] = mapped_column(String(512))
    file_size_bytes: Mapped[int | None] = mapped_column(Integer)
    download_url: Mapped[str | None] = mapped_column(String(512))
    checksum_md5: Mapped[str | None] = mapped_column(String(32))
    checksum_sha256: Mapped[str | None] = mapped_column(String(64))

    # Flags
    is_latest: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_critical: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_recommended: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_cached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cached_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Compatibility
    min_version: Mapped[str | None] = mapped_column(String(50))
    max_version: Mapped[str | None] = mapped_column(String(50))
    compatible_models: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    upgrade_path: Mapped[list[str] | None] = mapped_column(JSONB, default=list)

    # Device count (denormalized for performance)
    device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    devices_up_to_date: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Organization scope (None = global)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL")
    )


class DeviceFirmwareStatus(Base, UUIDMixin, AuditMixin):
    """Tracks firmware status for each device."""

    __tablename__ = "device_firmware_status"
    __table_args__ = (
        Index("ix_devfw_device", "device_id", unique=True),
        Index("ix_devfw_site", "site_id"),
        Index("ix_devfw_update_avail", "update_available"),
        {"schema": "core"},
    )

    device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"), nullable=False
    )
    site_id: Mapped[UUID | None] = mapped_column(ForeignKey("core.sites.id", ondelete="SET NULL"))

    # Current state
    current_version: Mapped[str | None] = mapped_column(String(50))
    latest_version: Mapped[str | None] = mapped_column(String(50))
    recommended_version: Mapped[str | None] = mapped_column(String(50))

    # Status flags
    is_up_to_date: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    update_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    critical_update_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    can_upgrade: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Path to latest
    upgrade_path: Mapped[list[str] | None] = mapped_column(JSONB, default=list)

    # Device info (denormalized)
    device_name: Mapped[str | None] = mapped_column(String(200))
    device_type: Mapped[str | None] = mapped_column(String(50))
    vendor: Mapped[str | None] = mapped_column(String(100))
    model: Mapped[str | None] = mapped_column(String(100))

    # Last check
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FirmwareUpgradeJob(Base, UUIDMixin, AuditMixin):
    """Tracks a firmware upgrade job (one or more devices)."""

    __tablename__ = "firmware_upgrade_jobs"
    __table_args__ = (
        Index("ix_fwjob_status", "status"),
        Index("ix_fwjob_site", "site_id"),
        Index("ix_fwjob_created_by", "created_by"),
        {"schema": "core"},
    )

    # Job info
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=FirmwareJobStatus.PENDING
    )
    firmware_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.firmware_images.id", ondelete="SET NULL")
    )
    firmware_version: Mapped[str | None] = mapped_column(String(50))

    # Targeting
    device_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    site_id: Mapped[UUID | None] = mapped_column(ForeignKey("core.sites.id", ondelete="SET NULL"))

    # Options
    backup_before: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rollback_on_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    batch_size: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    delay_between_batches: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    notify_on_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    notify_on_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Scheduling
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Progress
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total_devices: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    successful: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Per-device detail
    devices: Mapped[list[Any] | None] = mapped_column(JSONB, default=list)

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)

    # Who
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL")
    )
    celery_task_id: Mapped[str | None] = mapped_column(String(64))


class FirmwareSchedule(Base, UUIDMixin, AuditMixin):
    """Automated firmware upgrade schedule / policy."""

    __tablename__ = "firmware_schedules"
    __table_args__ = (
        Index("ix_fwsched_enabled", "is_enabled"),
        Index("ix_fwsched_site", "site_id"),
        {"schema": "core"},
    )

    # Identity
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Targeting
    site_id: Mapped[UUID | None] = mapped_column(ForeignKey("core.sites.id", ondelete="SET NULL"))
    device_type: Mapped[str | None] = mapped_column(String(50))
    vendor: Mapped[str | None] = mapped_column(String(100))
    model: Mapped[str | None] = mapped_column(String(100))
    tags: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    device_ids: Mapped[list[str] | None] = mapped_column(JSONB, default=list)

    # Version targeting
    auto_latest: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    target_version: Mapped[str | None] = mapped_column(String(50))
    release_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ReleaseType.STABLE
    )

    # Schedule config
    frequency: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ScheduleFrequency.WEEKLY
    )
    time_of_day: Mapped[str | None] = mapped_column(String(5))  # "HH:MM"
    day_of_week: Mapped[int | None] = mapped_column(Integer)  # 0=Mon, 6=Sun
    day_of_month: Mapped[int | None] = mapped_column(Integer)  # 1-28
    timezone: Mapped[str | None] = mapped_column(String(50))

    # Maintenance window
    maintenance_window_start: Mapped[str | None] = mapped_column(String(5))
    maintenance_window_end: Mapped[str | None] = mapped_column(String(5))

    # Upgrade options
    backup_before: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rollback_on_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    max_concurrent: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    batch_size: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    delay_between_batches: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    # Notifications
    notify_before: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notify_before_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    notify_on_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    notify_on_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # State
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_job_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.firmware_upgrade_jobs.id", ondelete="SET NULL")
    )
    total_runs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Organization scope
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL")
    )
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL")
    )
