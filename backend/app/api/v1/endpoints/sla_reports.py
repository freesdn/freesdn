# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SLA Reports API Endpoints
=========================================

On-demand report generation, report listing, download,
and report schedule management.

Endpoints:
  Reports
  - POST /sla/reports/generate              - Generate on-demand report
  - GET  /sla/reports                        - List generated reports
  - GET  /sla/reports/{id}/download          - Download report file

  Schedules
  - GET    /sla/report-schedules             - List report schedules
  - POST   /sla/report-schedules             - Create schedule
  - PUT    /sla/report-schedules/{id}        - Update schedule
  - DELETE /sla/report-schedules/{id}        - Delete schedule
"""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import site_ids_for_request
from app.core.tenancy import tenant_filter
from app.models.sla import SLAPolicy, SLAReportDelivery
from app.services.sla import SLAMonitoringService
from app.services.sla_calendar import ScheduleTimingError, validate_timezone
from app.services.sla_report_delivery import ReportDeliveryError
from app.services.sla_reports import REPORTS_BASE_DIR, SLAReportGenerator
from app.services.sla_schedule_authorization import ScheduleAuthorizationError

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Inline Pydantic Schemas
# ─────────────────────────────────────────────────────────────────────────────


class SLAReportGenerateRequest(BaseModel):
    period_start: datetime
    period_end: datetime
    policy_ids: list[UUID] | None = None
    format: str = Field("pdf", description="pdf or csv", pattern=r"^(pdf|csv)$")
    title: str | None = Field(None, max_length=255)

    @field_validator("period_start", "period_end")
    @classmethod
    def normalize_period_timezone(cls, value: datetime) -> datetime:
        """Legacy timestamps without an offset mean UTC, like stored reports."""
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_period(self):
        if self.period_start >= self.period_end:
            raise ValueError("period_start must be before period_end")
        if self.period_end - self.period_start > timedelta(days=366):
            raise ValueError("Report period cannot exceed 1 year")
        return self


class SLAReportResponse(BaseModel):
    id: UUID
    organization_id: UUID
    title: str
    period_start: datetime
    period_end: datetime
    format: str
    file_path: str | None = None
    file_size: int | None = None
    report_data: dict[str, Any] = Field(default_factory=dict)
    generated_by: UUID | None = None
    generated_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class SLAReportListResponse(BaseModel):
    reports: list[SLAReportResponse]
    total: int


class SLAReportScheduleCreate(BaseModel):
    name: str = Field(..., max_length=255)
    frequency: str = Field(
        "monthly", description="weekly, monthly, quarterly", pattern=r"^(weekly|monthly|quarterly)$"
    )
    day_of_week: int | None = Field(None, ge=0, le=6)
    day_of_month: int | None = Field(None, ge=1, le=31)
    timezone: str = Field("UTC", min_length=1, max_length=128)
    time_of_day: str = Field("09:00", pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
    recipients: list[str] = Field(default_factory=list, max_length=50)
    sla_policy_ids: list[UUID] = Field(default_factory=list)
    enabled: bool = True
    delivery_enabled: bool = False
    delivery_provider_id: UUID | None = None
    next_run_at: datetime | None = None

    @field_validator("timezone")
    @classmethod
    def validate_schedule_timezone(cls, value: str) -> str:
        return validate_timezone(value)

    @field_validator("next_run_at")
    @classmethod
    def normalize_next_run(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @field_validator("recipients")
    @classmethod
    def validate_recipients(cls, v):
        if v:
            email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
            for addr in v:
                if not email_re.fullmatch(addr):
                    raise ValueError("Invalid email address")
        return v


class SLAReportScheduleUpdate(BaseModel):
    name: str | None = Field(None, max_length=255)
    frequency: str | None = Field(None, pattern=r"^(weekly|monthly|quarterly)$")
    day_of_week: int | None = Field(None, ge=0, le=6)
    day_of_month: int | None = Field(None, ge=1, le=31)
    timezone: str | None = Field(None, min_length=1, max_length=128)
    time_of_day: str | None = Field(None, pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
    recipients: list[str] | None = Field(None, max_length=50)
    sla_policy_ids: list[UUID] | None = None
    enabled: bool | None = None
    delivery_enabled: bool | None = None
    delivery_provider_id: UUID | None = None
    next_run_at: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_null_required_fields(cls, data):
        if isinstance(data, dict):
            for key in (
                "name",
                "frequency",
                "recipients",
                "sla_policy_ids",
                "enabled",
                "delivery_enabled",
                "timezone",
                "time_of_day",
            ):
                if key in data and data[key] is None:
                    raise ValueError(f"{key} cannot be null")
        return data

    @field_validator("timezone")
    @classmethod
    def validate_schedule_timezone(cls, value: str) -> str:
        return validate_timezone(value)

    @field_validator("next_run_at")
    @classmethod
    def normalize_next_run(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @field_validator("recipients")
    @classmethod
    def validate_recipients(cls, v):
        if v:
            email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
            for addr in v:
                if not email_re.fullmatch(addr):
                    raise ValueError("Invalid email address")
        return v


class SLAReportScheduleResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    frequency: str
    day_of_week: int | None = None
    day_of_month: int | None = None
    timezone: str = "UTC"
    time_of_day: str = "09:00"
    recipients: list[Any] = Field(default_factory=list)
    sla_policy_ids: list[Any] = Field(default_factory=list)
    enabled: bool = True
    delivery_enabled: bool = False
    delivery_provider_id: UUID | None = None
    execution_error: str | None = None
    last_generated_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class SLAReportScheduleListResponse(BaseModel):
    schedules: list[SLAReportScheduleResponse]
    total: int


class SLAReportDeliveryResponse(BaseModel):
    id: UUID
    recipient_email: str
    state: str
    attempts: int
    error_code: str | None = None
    next_attempt_at: datetime
    accepted_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _org_id(user: Any) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


async def _assert_schedule_policies_accessible(
    db: AsyncSession,
    user: Any,
    org_id: UUID,
    policy_ids: list[UUID] | None,
) -> None:
    """Validate organization and live site scope before approving a schedule.

    Execution also revalidates the saved approval; this check provides a 404
    response for inaccessible policy references at create/update time.
    """
    granted = site_ids_for_request(user)
    if not policy_ids:
        if granted is not None:
            raise HTTPException(status_code=404, detail="SLA policy not found")
        return
    accessible_subq = select(SLAPolicy.id).where(
        tenant_filter(SLAPolicy, user),
        SLAPolicy.organization_id == org_id,
        SLAPolicy.id.in_(policy_ids),
    )
    predicate = SLAMonitoringService._policy_grant_predicate(user)
    if predicate is not None:
        accessible_subq = accessible_subq.where(predicate)
    rows = (await db.execute(accessible_subq)).scalars().all()
    accessible = set(rows)
    if any(pid not in accessible for pid in policy_ids):
        raise HTTPException(status_code=404, detail="SLA policy not found")


# ─────────────────────────────────────────────────────────────────────────────
# Reports
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/reports/generate",
    response_model=SLAReportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def generate_report(
    body: SLAReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Generate an SLA compliance report on demand."""
    org_id = _org_id(user)
    service = SLAReportGenerator(db)
    report = await service.generate_report(
        org_id=org_id,
        period_start=body.period_start,
        period_end=body.period_end,
        policy_ids=body.policy_ids,
        report_format=body.format,
        generated_by=user.id,
        title=body.title,
    )
    await db.commit()
    return SLAReportResponse.model_validate(report)


@router.get("/reports", response_model=SLAReportListResponse)
async def list_reports(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """List generated SLA reports."""
    org_id = _org_id(user)
    service = SLAReportGenerator(db)
    reports, total = await service.list_reports(org_id, limit=limit, offset=offset)
    return SLAReportListResponse(
        reports=[SLAReportResponse.model_validate(r) for r in reports],
        total=total,
    )


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Download a rendered file; legacy missing or mislabeled renders must regenerate."""
    org_id = _org_id(user)
    service = SLAReportGenerator(db)
    report = await service.get_report(report_id)

    if not report or report.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.file_path:
        resolved = Path(report.file_path).resolve()
        base = (Path(REPORTS_BASE_DIR) / str(org_id)).resolve()
        # Path traversal guard: verify the resolved path is strictly
        # inside the base directory.  Using is_relative_to() is safer
        # than a string prefix check (which can be fooled by sibling
        # directories sharing a common prefix).
        try:
            resolved.relative_to(base)
        except ValueError:
            raise HTTPException(status_code=403, detail="Access denied")
        if not resolved.is_file():
            raise HTTPException(
                status_code=404,
                detail="Report file not found on disk",
            )
        if report.format not in {"pdf", "csv"}:
            raise HTTPException(
                status_code=409, detail="Unsupported report format; regenerate report"
            )
        if report.format == "pdf":
            with resolved.open("rb") as rendered:
                if rendered.read(5) != b"%PDF-":
                    raise HTTPException(
                        status_code=409,
                        detail="Legacy or invalid PDF render; regenerate report",
                    )
        media_type = "application/pdf" if report.format == "pdf" else "text/csv"
        safe_title = re.sub(r"[^\w\s\-.]", "", report.title)[:100]
        filename = f"{safe_title}.{report.format}"
        return FileResponse(
            path=str(resolved),
            media_type=media_type,
            filename=filename,
        )

    raise HTTPException(status_code=409, detail="Report has no rendered file; regenerate report")


# ─────────────────────────────────────────────────────────────────────────────
# Schedules
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/report-schedules", response_model=SLAReportScheduleListResponse)
async def list_schedules(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """List SLA report schedules."""
    org_id = _org_id(user)
    service = SLAReportGenerator(db)
    schedules, total = await service.list_schedules(org_id, limit=limit, offset=offset)
    return SLAReportScheduleListResponse(
        schedules=[SLAReportScheduleResponse.model_validate(s) for s in schedules],
        total=total,
    )


@router.post(
    "/report-schedules",
    response_model=SLAReportScheduleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_schedule(
    body: SLAReportScheduleCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Create an SLA report schedule."""
    org_id = _org_id(user)
    # Per-user site grant: a site-limited operator may not schedule a report
    # over sibling-site policies (replayed later in grant-less background ctx).
    await _assert_schedule_policies_accessible(db, user, org_id, body.sla_policy_ids)
    service = SLAReportGenerator(db)
    try:
        schedule = await service.create_schedule(
            org_id,
            body.model_dump(),
            created_by=user.id,
            current_user=user,
        )
    except ReportDeliveryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except ScheduleAuthorizationError:
        raise HTTPException(status_code=404, detail="SLA policy not found") from None
    await db.commit()
    return SLAReportScheduleResponse.model_validate(schedule)


@router.put(
    "/report-schedules/{schedule_id}",
    response_model=SLAReportScheduleResponse,
)
async def update_schedule(
    schedule_id: UUID,
    body: SLAReportScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Update an SLA report schedule."""
    org_id = _org_id(user)
    service = SLAReportGenerator(db)

    existing = await service.get_schedule(schedule_id, org_id=org_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Schedule not found")

    update_data = body.model_dump(exclude_unset=True)
    # Editing recipients or re-enabling a schedule also requires access to its
    # effective policy scope, even when the body does not replace policy IDs.
    effective_ids = update_data.get("sla_policy_ids", existing.sla_policy_ids)
    if effective_ids is None:
        raise HTTPException(status_code=422, detail="sla_policy_ids cannot be null")
    try:
        effective_ids = [UUID(str(policy_id)) for policy_id in effective_ids]
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="SLA policy not found") from None
    await _assert_schedule_policies_accessible(db, user, org_id, effective_ids)

    try:
        updated = await service.update_schedule(
            schedule_id,
            update_data,
            org_id=org_id,
            current_user=user,
        )
    except ReportDeliveryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except ScheduleAuthorizationError:
        raise HTTPException(status_code=404, detail="SLA policy not found") from None
    except ScheduleTimingError:
        raise HTTPException(
            status_code=409,
            detail="Stored schedule timing is invalid; supply corrected calendar settings.",
        ) from None
    if not updated:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.commit()
    return SLAReportScheduleResponse.model_validate(updated)


@router.delete(
    "/report-schedules/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_schedule(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> None:
    """Delete an SLA report schedule."""
    org_id = _org_id(user)
    service = SLAReportGenerator(db)
    deleted = await service.delete_schedule(schedule_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.commit()


@router.get("/reports/{report_id}/deliveries", response_model=list[SLAReportDeliveryResponse])
async def list_report_deliveries(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Operator status; archive site grants and organization apply to every row."""
    org_id = _org_id(user)
    report = await SLAReportGenerator(db).get_report(report_id)
    if report is None or report.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Report not found")
    rows = await db.scalars(
        select(SLAReportDelivery)
        .where(
            SLAReportDelivery.report_id == report_id,
            SLAReportDelivery.organization_id == org_id,
        )
        .order_by(SLAReportDelivery.created_at, SLAReportDelivery.id)
        .limit(50)
    )
    return [SLAReportDeliveryResponse.model_validate(row) for row in rows]


@router.post(
    "/reports/{report_id}/deliveries/{delivery_id}/cancel", response_model=SLAReportDeliveryResponse
)
async def cancel_report_delivery(
    report_id: UUID,
    delivery_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Cancel unclaimed mail only. Accepted or uncertain outcomes cannot be undone."""
    org_id = _org_id(user)
    report = await SLAReportGenerator(db).get_report(report_id)
    if report is None or report.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Report not found")
    row = await db.scalar(
        select(SLAReportDelivery)
        .where(
            SLAReportDelivery.id == delivery_id,
            SLAReportDelivery.report_id == report_id,
            SLAReportDelivery.organization_id == org_id,
        )
        .with_for_update()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Delivery not found")
    if row.state not in {"pending", "retry"}:
        raise HTTPException(
            status_code=409, detail="Only pending or retrying deliveries can be cancelled"
        )
    row.state, row.error_code = "cancelled", "cancelled_by_operator"
    await db.commit()
    return SLAReportDeliveryResponse.model_validate(row)
