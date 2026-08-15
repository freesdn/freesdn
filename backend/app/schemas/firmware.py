# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Firmware Management Schemas
==========================================

Pydantic schemas for firmware management API request/response validation.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

# =============================================================================
# Base
# =============================================================================


class BaseSchema(BaseModel):
    model_config = {"from_attributes": True}


# =============================================================================
# Firmware Image
# =============================================================================


class FirmwareCreate(BaseSchema):
    """Create a new firmware image entry."""

    vendor: str
    model: str
    version: str
    device_type: str | None = None
    release_type: str = "stable"
    display_name: str | None = None
    description: str | None = None
    release_notes: str | None = None
    release_notes_url: str | None = None
    release_date: datetime | None = None
    download_url: str | None = None
    checksum_md5: str | None = None
    checksum_sha256: str | None = None
    is_critical: bool = False
    is_recommended: bool = False
    min_version: str | None = None
    max_version: str | None = None
    compatible_models: list[str] | None = None


class FirmwareUpdate(BaseSchema):
    """Update firmware metadata."""

    display_name: str | None = None
    description: str | None = None
    release_notes: str | None = None
    release_notes_url: str | None = None
    release_type: str | None = None
    is_latest: bool | None = None
    is_critical: bool | None = None
    is_recommended: bool | None = None
    is_deprecated: bool | None = None
    download_url: str | None = None
    min_version: str | None = None
    max_version: str | None = None
    compatible_models: list[str] | None = None


class FirmwareResponse(BaseSchema):
    """Full firmware image response (matches frontend FirmwareSummary)."""

    id: UUID
    vendor: str
    model: str
    device_type: str | None = None
    version: str
    release_type: str
    display_name: str | None = None
    description: str | None = None
    release_notes: str | None = None
    release_notes_url: str | None = None
    release_date: datetime | None = None
    file_path: str | None = None
    file_size_bytes: int | None = None
    download_url: str | None = None
    checksum_md5: str | None = None
    checksum_sha256: str | None = None
    is_latest: bool = False
    is_critical: bool = False
    is_recommended: bool = False
    is_deprecated: bool = False
    is_cached: bool = False
    cached_at: datetime | None = None
    min_version: str | None = None
    max_version: str | None = None
    compatible_models: list[str] | None = None
    upgrade_path: list[str] | None = None
    device_count: int = 0
    devices_up_to_date: int = 0
    organization_id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FirmwareListResponse(BaseSchema):
    """Paginated firmware list."""

    items: list[FirmwareResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 20


# =============================================================================
# Device Firmware Status
# =============================================================================


class DeviceFirmwareStatusResponse(BaseSchema):
    """Per-device firmware status."""

    id: UUID
    device_id: UUID
    site_id: UUID | None = None
    current_version: str | None = None
    latest_version: str | None = None
    recommended_version: str | None = None
    is_up_to_date: bool = True
    update_available: bool = False
    critical_update_available: bool = False
    can_upgrade: bool = True
    upgrade_path: list[str] | None = None
    device_name: str | None = None
    device_type: str | None = None
    vendor: str | None = None
    model: str | None = None
    last_checked_at: datetime | None = None


class DeviceFirmwareStatusListResponse(BaseSchema):
    """Paginated device firmware status list."""

    items: list[DeviceFirmwareStatusResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 20


# =============================================================================
# Upgrade Jobs
# =============================================================================


class UpgradeJobCreate(BaseSchema):
    """Create a firmware upgrade job."""

    device_ids: list[UUID] = Field(max_length=1000)
    firmware_id: UUID | None = None
    firmware_version: str | None = None
    site_id: UUID | None = None
    scheduled_at: datetime | None = None
    backup_before: bool = True
    rollback_on_failure: bool = True
    batch_size: int = 5
    delay_between_batches: int = 30
    notify_on_complete: bool = True
    notify_on_failure: bool = True


class UpgradeJobResponse(BaseSchema):
    """Firmware upgrade job response."""

    id: UUID
    status: str
    firmware_id: UUID | None = None
    firmware_version: str | None = None
    device_ids: list[UUID] = Field(default_factory=list)
    site_id: UUID | None = None
    backup_before: bool = True
    rollback_on_failure: bool = True
    batch_size: int = 5
    delay_between_batches: int = 30
    notify_on_complete: bool = True
    notify_on_failure: bool = True
    scheduled_at: datetime | None = None
    progress: float = 0.0
    total_devices: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    devices: list[dict[str, Any]] | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    created_by: UUID | None = None
    celery_task_id: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class UpgradeJobListResponse(BaseSchema):
    """Paginated job list."""

    items: list[UpgradeJobResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 20


# =============================================================================
# Schedules
# =============================================================================


class ScheduleCreate(BaseSchema):
    """Create a firmware upgrade schedule."""

    name: str
    description: str | None = None
    is_enabled: bool = True
    site_id: UUID | None = None
    device_type: str | None = None
    vendor: str | None = None
    model: str | None = None
    tags: list[str] | None = None
    device_ids: list[UUID] | None = Field(default=None, max_length=1000)
    auto_latest: bool = True
    target_version: str | None = None
    release_type: str = "stable"
    frequency: str = "weekly"
    time_of_day: str | None = None
    day_of_week: int | None = None
    day_of_month: int | None = None
    timezone: str | None = None
    maintenance_window_start: str | None = None
    maintenance_window_end: str | None = None
    backup_before: bool = True
    rollback_on_failure: bool = True
    max_concurrent: int = 5
    batch_size: int = 5
    delay_between_batches: int = 30
    notify_before: bool = False
    notify_before_hours: int = 24
    notify_on_complete: bool = True
    notify_on_failure: bool = True


class ScheduleUpdate(BaseSchema):
    """Update a firmware schedule."""

    name: str | None = None
    description: str | None = None
    is_enabled: bool | None = None
    site_id: UUID | None = None
    device_type: str | None = None
    vendor: str | None = None
    model: str | None = None
    tags: list[str] | None = None
    device_ids: list[UUID] | None = None
    auto_latest: bool | None = None
    target_version: str | None = None
    release_type: str | None = None
    frequency: str | None = None
    time_of_day: str | None = None
    day_of_week: int | None = None
    day_of_month: int | None = None
    timezone: str | None = None
    maintenance_window_start: str | None = None
    maintenance_window_end: str | None = None
    backup_before: bool | None = None
    rollback_on_failure: bool | None = None
    max_concurrent: int | None = None
    batch_size: int | None = None
    delay_between_batches: int | None = None
    notify_before: bool | None = None
    notify_before_hours: int | None = None
    notify_on_complete: bool | None = None
    notify_on_failure: bool | None = None


class ScheduleResponse(BaseSchema):
    """Firmware schedule response."""

    id: UUID
    name: str
    description: str | None = None
    is_enabled: bool = True
    site_id: UUID | None = None
    device_type: str | None = None
    vendor: str | None = None
    model: str | None = None
    tags: list[str] | None = None
    device_ids: list[UUID] | None = None
    auto_latest: bool = True
    target_version: str | None = None
    release_type: str = "stable"
    frequency: str = "weekly"
    time_of_day: str | None = None
    day_of_week: int | None = None
    day_of_month: int | None = None
    timezone: str | None = None
    maintenance_window_start: str | None = None
    maintenance_window_end: str | None = None
    backup_before: bool = True
    rollback_on_failure: bool = True
    max_concurrent: int = 5
    batch_size: int = 5
    delay_between_batches: int = 30
    notify_before: bool = False
    notify_before_hours: int = 24
    notify_on_complete: bool = True
    notify_on_failure: bool = True
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    last_job_id: UUID | None = None
    total_runs: int = 0
    organization_id: UUID | None = None
    created_by: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ScheduleListResponse(BaseSchema):
    """Paginated schedule list."""

    items: list[ScheduleResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 20


# =============================================================================
# Summary / Dashboard
# =============================================================================


class FirmwareSummaryResponse(BaseSchema):
    """Firmware dashboard summary."""

    total_devices: int = 0
    up_to_date: int = 0
    update_available: int = 0
    critical_updates: int = 0
    total_firmware_images: int = 0
    active_jobs: int = 0
    scheduled_jobs: int = 0
    by_vendor: dict[str, Any] = Field(default_factory=dict)
    by_device_type: dict[str, Any] = Field(default_factory=dict)
    recent_upgrades: list[dict[str, Any]] = Field(default_factory=list)
    repo_stats: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Compatibility Check
# =============================================================================


class CompatibilityCheckRequest(BaseSchema):
    """Request to check firmware/device compatibility."""

    firmware_id: UUID
    device_ids: list[UUID] = Field(max_length=1000)


class CompatibilityCheckResponse(BaseSchema):
    """Compatibility check result."""

    firmware_id: UUID
    compatible: list[UUID] = Field(default_factory=list)
    incompatible: list[dict[str, Any]] = Field(default_factory=list)  # [{device_id, reason}]
    warnings: list[dict[str, Any]] = Field(default_factory=list)


class DeviceRollbackRequest(BaseSchema):
    """Rollback a device to a previous firmware version."""

    target_version: str | None = None
    backup_id: str | None = None


class CheckUpdatesRequest(BaseSchema):
    """Request to check firmware updates for devices."""

    device_ids: list[UUID] | None = Field(default=None, max_length=1000)
    site_id: UUID | None = None
