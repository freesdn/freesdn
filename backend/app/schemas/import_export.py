# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Data Import/Export Schemas
==========================================

Pydantic schemas for data import/export API endpoints.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.import_export import (
    ConflictResolution,
    ExportFormat,
    ExportScope,
    ImportSource,
)

# =============================================================================
# Base
# =============================================================================


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


# =============================================================================
# Export
# =============================================================================


class ExportRequest(BaseSchema):
    """Request to start an export job."""

    format: ExportFormat = ExportFormat.JSON
    scope: ExportScope = ExportScope.FULL
    entity_types: list[str] | None = None
    entity_filters: dict[str, Any] | None = None
    organization_id: UUID | None = None
    site_ids: list[UUID] | None = None


class ExportJobResponse(BaseSchema):
    """Export job status response."""

    id: UUID
    status: str
    export_format: str
    scope: str
    entity_types: list[str] | None = None
    entity_filters: dict[str, Any] | None = None
    organization_id: UUID | None = None
    site_ids: list[str] | None = None
    progress_pct: float = 0.0
    total_entities: int = 0
    exported_entities: int = 0
    file_size_bytes: int | None = None
    download_url: str | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None
    celery_task_id: str | None = None


class ExportJobListResponse(BaseSchema):
    """Paginated list of export jobs."""

    items: list[ExportJobResponse]
    total: int


# =============================================================================
# Import Validation / Preview
# =============================================================================


class ImportValidationResult(BaseSchema):
    """Result of import file validation (preview)."""

    valid: bool = True
    source_format: str
    total_entities: int = 0
    entity_summary: dict[str, int] = Field(default_factory=dict)
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    preview_entities: list[dict[str, Any]] = Field(default_factory=list)


class ImportPreviewRequest(BaseSchema):
    """Request to validate/preview an import file."""

    source_format: ImportSource = ImportSource.FREESDN


# =============================================================================
# Import
# =============================================================================


class ImportRequest(BaseSchema):
    """Request to start an import job."""

    source_format: ImportSource = ImportSource.FREESDN
    conflict_resolution: ConflictResolution = ConflictResolution.SKIP
    organization_id: UUID | None = None


class ImportJobResponse(BaseSchema):
    """Import job status response."""

    id: UUID
    status: str
    source_format: str
    conflict_resolution: str
    original_filename: str | None = None
    file_size_bytes: int | None = None
    organization_id: UUID | None = None
    validation_result: dict[str, Any] | None = None
    progress_pct: float = 0.0
    total_entities: int = 0
    imported_entities: int = 0
    skipped_entities: int = 0
    failed_entities: int = 0
    result_summary: dict[str, Any] | None = None
    error_message: str | None = None
    errors: list[dict[str, Any]] | None = None
    warnings: list[str] | None = None
    can_rollback: bool = True
    created_at: datetime
    completed_at: datetime | None = None
    rolled_back_at: datetime | None = None
    celery_task_id: str | None = None


class ImportJobListResponse(BaseSchema):
    """Paginated list of import jobs."""

    items: list[ImportJobResponse]
    total: int


# =============================================================================
# Combined
# =============================================================================


class DataJobSummary(BaseSchema):
    """Summary of all import/export activity."""

    recent_exports: list[ExportJobResponse] = Field(default_factory=list)
    recent_imports: list[ImportJobResponse] = Field(default_factory=list)
    active_jobs: int = 0
    total_exports: int = 0
    total_imports: int = 0
