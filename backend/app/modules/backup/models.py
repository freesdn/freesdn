# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Backup Module Models
====================================

Unified data models for backup management.

All tables live in the ``backup`` PostgreSQL schema.
This is the single source of truth — used by the backup service,
the v1 API endpoints, and the module tasks.
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Organization, Site, User


# =============================================================================
# Enums
# =============================================================================


class BackupType(StrEnum):
    """Types of backup."""

    FULL = "full"
    DEVICE_CONFIG = "device_config"
    SITE_CONFIG = "site_config"
    DATABASE = "database"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class BackupStatus(StrEnum):
    """Backup job status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BackupStorageType(StrEnum):
    """Where backups are stored."""

    LOCAL = "local"
    S3 = "s3"
    SFTP = "sftp"
    FTP = "ftp"
    NFS = "nfs"
    GOOGLE_DRIVE = "google_drive"
    DROPBOX = "dropbox"
    WEBDAV = "webdav"


# =============================================================================
# Storage Location
# =============================================================================


class StorageLocation(Base, UUIDMixin, TimestampMixin):
    """Configured storage locations for backups (S3, SFTP, Google Drive, etc.)."""

    __tablename__ = "storage_locations"
    __table_args__ = (
        Index("ix_bak_storage_org_id", "organization_id"),
        {"schema": "backup"},
    )

    # Basic info
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    # Connection test
    last_test_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_test_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_test_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Storage configuration (JSON)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Encrypted credentials (stored separately for security)
    encrypted_credentials: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Organization association
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=True,
    )

    organization: Mapped["Organization"] = relationship(lazy="selectin")

    def __repr__(self) -> str:
        return f"<StorageLocation {self.name} ({self.storage_type})>"


# =============================================================================
# Backup Schedule
# =============================================================================


class BackupSchedule(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """Scheduled backup configuration."""

    __tablename__ = "backup_schedules"
    __table_args__ = (
        Index("ix_bak_sched_enabled", "is_enabled"),
        Index("ix_bak_sched_next_run", "next_run_at"),
        {"schema": "backup"},
    )

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Schedule configuration (cron-like)
    schedule_type: Mapped[str] = mapped_column(String(20), default="daily")
    cron_expression: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")

    # When to run (for simple schedules)
    run_time: Mapped[str] = mapped_column(String(5), default="02:00")
    run_days: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    run_day_of_month: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Backup settings
    backup_type: Mapped[str] = mapped_column(String(50), default="full")
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    max_backups: Mapped[int] = mapped_column(Integer, default=10)
    device_ids: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=True)

    # Storage
    storage_type: Mapped[str] = mapped_column(String(20), default="local")
    storage_config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    storage_location_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("backup.storage_locations.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Scope
    include_devices: Mapped[bool] = mapped_column(Boolean, default=True)
    include_vlans: Mapped[bool] = mapped_column(Boolean, default=True)
    include_ssids: Mapped[bool] = mapped_column(Boolean, default=True)
    include_users: Mapped[bool] = mapped_column(Boolean, default=True)
    include_automation: Mapped[bool] = mapped_column(Boolean, default=True)

    # Status
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Associations
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=True,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(lazy="selectin")
    site: Mapped["Site"] = relationship(lazy="selectin")
    storage_location: Mapped["StorageLocation"] = relationship(lazy="selectin")
    backups: Mapped[list["Backup"]] = relationship(
        back_populates="schedule",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<BackupSchedule {self.name}>"


# =============================================================================
# Backup
# =============================================================================


class Backup(Base, UUIDMixin, AuditMixin):
    """Backup record model - tracks all backup operations."""

    __tablename__ = "backups"
    __table_args__ = (
        Index("ix_bak_backups_status", "status"),
        Index("ix_bak_backups_created_at", "created_at"),
        Index("ix_bak_backups_site_id", "site_id"),
        Index("ix_bak_backups_schedule_id", "schedule_id"),
        Index("ix_bak_backups_expires_at", "expires_at"),
        # NOTE C4: Backups MUST be filterable by org for tenant isolation.
        Index("ix_bak_backups_organization_id", "organization_id"),
        {"schema": "backup"},
    )

    # Identification
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    backup_type: Mapped[str] = mapped_column(String(50), default="full")

    # Status tracking
    status: Mapped[str] = mapped_column(String(20), default="pending")
    progress: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Storage info
    storage_type: Mapped[str] = mapped_column(String(20), default="local")
    storage_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    file_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Integrity
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Encryption
    # NOTE H1: Default is now True. Backups contain sensitive config data
    # (creds excluded, but device/user/automation rules can still be
    # competitively sensitive). Operators can opt out per-backup.
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    encryption_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Scope (what's included)
    include_devices: Mapped[bool] = mapped_column(Boolean, default=True)
    include_vlans: Mapped[bool] = mapped_column(Boolean, default=True)
    include_ssids: Mapped[bool] = mapped_column(Boolean, default=True)
    include_users: Mapped[bool] = mapped_column(Boolean, default=True)
    include_automation: Mapped[bool] = mapped_column(Boolean, default=True)
    # Full ("vault") backup: carries decrypted secrets + user logins, sealed under
    # an operator passphrase (NOT the instance SECRET_KEY) so it is portable and
    # re-keys onto the target instance at restore. False = the secret-free config
    # snapshot (.fsdn). True = the secure .fsdnvault. Drives the UI Config/Full badge.
    include_secrets: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    # Device list (if device-specific backup)
    device_ids: Mapped[list[str] | None] = mapped_column(JSONB, default=list)

    # Stats
    device_count: Mapped[int] = mapped_column(Integer, default=0)

    # Error tracking
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Retention
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Extra metadata
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Associations
    # NOTE C4: Direct org column eliminates the fragile inferred-from-joins
    # logic. Set at backup creation and enforced on every read query.
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=True,
    )
    created_by_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    schedule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("backup.backup_schedules.id", ondelete="SET NULL"),
        nullable=True,
    )
    storage_location_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("backup.storage_locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Rollback-slot linkage (enterprise backup v2 — Cisco DNA-style undo).
    # When operators run a restore, the BackupService auto-captures the
    # pre-restore state as a Backup with ``backup_type='rollback_slot'``
    # and sets this column to the RestoreJob it precedes. The catalog UI
    # uses it to render an "Undo last restore" button next to each
    # restore job's row. NULL on user-created backups + on rollback
    # slots whose linked job has since been deleted (SET NULL cascade).
    rollback_for_restore_job_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("backup.restore_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(lazy="selectin")
    site: Mapped["Site"] = relationship(lazy="selectin")
    created_by: Mapped["User"] = relationship(lazy="selectin")  # type: ignore[assignment]
    schedule: Mapped["BackupSchedule"] = relationship(
        back_populates="backups",
        lazy="selectin",
    )
    storage_location: Mapped["StorageLocation"] = relationship(lazy="selectin")

    def __repr__(self) -> str:
        return f"<Backup {self.name} - {self.status}>"


# =============================================================================
# Restore Job
# =============================================================================


class RestoreJob(Base, UUIDMixin, TimestampMixin):
    """Restore operation tracking."""

    __tablename__ = "restore_jobs"
    __table_args__ = (
        Index("ix_bak_restore_status", "status"),
        Index("ix_bak_restore_backup_id", "backup_id"),
        {"schema": "backup"},
    )

    # Source backup
    backup_id: Mapped[UUID] = mapped_column(
        ForeignKey("backup.backups.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Status
    status: Mapped[str] = mapped_column(String(20), default="pending")
    progress: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Restore options
    restore_devices: Mapped[bool] = mapped_column(Boolean, default=True)
    restore_vlans: Mapped[bool] = mapped_column(Boolean, default=True)
    restore_ssids: Mapped[bool] = mapped_column(Boolean, default=True)
    restore_users: Mapped[bool] = mapped_column(Boolean, default=False)
    restore_automation: Mapped[bool] = mapped_column(Boolean, default=True)
    overwrite_existing: Mapped[bool] = mapped_column(Boolean, default=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)

    # Target
    target_site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Results
    items_restored: Mapped[int] = mapped_column(Integer, default=0)
    items_failed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    restore_log: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    dry_run_report: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Who initiated
    initiated_by_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    # Disambiguate the FK SQLAlchemy uses for the ``backup`` association:
    # there are now TWO FKs linking RestoreJob and Backup —
    # ``RestoreJob.backup_id → backups.id`` (this relationship, the source
    # backup being restored) and ``Backup.rollback_for_restore_job_id →
    # restore_jobs.id`` (the rollback-slot linkage, added by migration
    # 031). Without the explicit ``foreign_keys`` SQLAlchemy raises
    # AmbiguousForeignKeysError during mapper configuration.
    backup: Mapped["Backup"] = relationship(
        lazy="selectin",
        foreign_keys="RestoreJob.backup_id",
    )
    target_site: Mapped["Site"] = relationship(lazy="selectin")
    initiated_by: Mapped["User"] = relationship(lazy="selectin")

    def __repr__(self) -> str:
        return f"<RestoreJob {self.id} - {self.status}>"
