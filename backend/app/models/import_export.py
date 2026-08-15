# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Data Import/Export Models
=========================================

SQLAlchemy models for data import/export and migration:
- ExportJob: Tracks background export operations
- ImportJob: Tracks background import operations with rollback support
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


class ExportFormat(StrEnum):
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"


class ExportScope(StrEnum):
    """What to include in an export."""

    FULL = "full"
    DEVICES = "devices"
    SITES = "sites"
    CONTROLLERS = "controllers"
    VLANS = "vlans"
    USERS = "users"
    AGENTS = "agents"
    VPN = "vpn"
    CUSTOM = "custom"


class ImportSource(StrEnum):
    """Source format for imports."""

    FREESDN = "freesdn"
    UNIFI = "unifi"
    MERAKI = "meraki"
    GENERIC_CSV = "generic_csv"
    GENERIC_JSON = "generic_json"


class ConflictResolution(StrEnum):
    """How to handle conflicts during import."""

    SKIP = "skip"
    OVERWRITE = "overwrite"
    MERGE = "merge"


class JobStatus(StrEnum):
    """Status of an import/export job."""

    PENDING = "pending"
    VALIDATING = "validating"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"


# =============================================================================
# Models
# =============================================================================


class ExportJob(Base, UUIDMixin, AuditMixin):
    """Tracks a background export operation."""

    __tablename__ = "export_jobs"
    __table_args__ = (
        Index("ix_export_jobs_status", "status"),
        Index("ix_export_jobs_user", "created_by"),
        {"schema": "core"},
    )

    # Job info
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=JobStatus.PENDING)
    export_format: Mapped[str] = mapped_column(
        String(10), nullable=False, default=ExportFormat.JSON
    )
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default=ExportScope.FULL)

    # Scope details (for CUSTOM scope)
    entity_types: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    entity_filters: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=dict)

    # Organization context
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL")
    )
    site_ids: Mapped[list[str] | None] = mapped_column(JSONB, default=list)

    # Progress
    progress_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total_entities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exported_entities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Result
    file_path: Mapped[str | None] = mapped_column(String(512))
    file_size_bytes: Mapped[int | None] = mapped_column(Integer)
    download_url: Mapped[str | None] = mapped_column(String(512))
    error_message: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Who created
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL")
    )

    # Celery task mapping
    celery_task_id: Mapped[str | None] = mapped_column(String(64))


class ImportJob(Base, UUIDMixin, AuditMixin):
    """Tracks a background import operation with rollback support."""

    __tablename__ = "import_jobs"
    __table_args__ = (
        Index("ix_import_jobs_status", "status"),
        Index("ix_import_jobs_user", "created_by"),
        {"schema": "core"},
    )

    # Job info
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=JobStatus.PENDING)
    source_format: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ImportSource.FREESDN
    )
    conflict_resolution: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ConflictResolution.SKIP
    )

    # File info
    original_filename: Mapped[str | None] = mapped_column(String(255))
    file_path: Mapped[str | None] = mapped_column(String(512))
    file_size_bytes: Mapped[int | None] = mapped_column(Integer)

    # Organization context
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL")
    )

    # Validation results (computed before import starts)
    validation_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    # Progress
    progress_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total_entities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    imported_entities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped_entities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_entities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Results summary
    result_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error_message: Mapped[str | None] = mapped_column(Text)
    errors: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    warnings: Mapped[list[str] | None] = mapped_column(JSONB, default=list)

    # Rollback data (stores created entity IDs for rollback)
    rollback_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    can_rollback: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Timing
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Who created
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL")
    )

    # Celery task mapping
    celery_task_id: Mapped[str | None] = mapped_column(String(64))
