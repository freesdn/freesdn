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
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import site_ids_for_request
from app.models.sla import SLAPolicy, SLAPolicyScope
from app.services.sla_reports import REPORTS_BASE_DIR, SLAReportGenerator

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Inline Pydantic Schemas
# ─────────────────────────────────────────────────────────────────────────────


class SLAReportGenerateRequest(BaseModel):
    period_start: datetime
    period_end: datetime
    policy_ids: list[UUID] | None = None
    format: str = Field("pdf", description="pdf or csv", pattern=r"^(pdf|csv)$")
    title: str | None = None

    @model_validator(mode="after")
    def validate_period(self):
        if self.period_start >= self.period_end:
            raise ValueError("period_start must be before period_end")
        if (self.period_end - self.period_start).days > 366:
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
    recipients: list[str] = Field(default_factory=list, max_length=50)
    sla_policy_ids: list[UUID] = Field(default_factory=list)
    enabled: bool = True
    next_run_at: datetime | None = None

    @field_validator("recipients", mode="before")
    @classmethod
    def validate_recipients(cls, v):
        if v:
            email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
            for addr in v:
                if not email_re.match(addr):
                    raise ValueError(f"Invalid email address: {addr}")
        return v


class SLAReportScheduleUpdate(BaseModel):
    name: str | None = Field(None, max_length=255)
    frequency: str | None = Field(None, pattern=r"^(weekly|monthly|quarterly)$")
    day_of_week: int | None = None
    day_of_month: int | None = None
    recipients: list[str] | None = Field(None, max_length=50)
    sla_policy_ids: list[UUID] | None = None
    enabled: bool | None = None
    next_run_at: datetime | None = None

    @field_validator("recipients", mode="before")
    @classmethod
    def validate_recipients(cls, v):
        if v:
            email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
            for addr in v:
                if not email_re.match(addr):
                    raise ValueError(f"Invalid email address: {addr}")
        return v


class SLAReportScheduleResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    frequency: str
    day_of_week: int | None = None
    day_of_month: int | None = None
    recipients: list[Any] = Field(default_factory=list)
    sla_policy_ids: list[Any] = Field(default_factory=list)
    enabled: bool = True
    last_generated_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class SLAReportScheduleListResponse(BaseModel):
    schedules: list[SLAReportScheduleResponse]
    total: int


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
    """Reject schedules referencing SLA policies the caller may not access.

    Per-user site grant: a scheduled report is later run in BACKGROUND context
    (``generate_scheduled`` — the request contextvar is unset there), so the
    stored ``sla_policy_ids`` are replayed without any grant filter and the
    rendered report is emailed to the schedule's recipients. Without this
    check a site-limited operator could enqueue a schedule pointing at a
    sibling-site policy and exfiltrate that site's compliance + breach history.

    Enforce the grant HERE, at write time, where the request user is known.
    No-op for org_admin / super_admin / grant-less callers (``site_ids_for_request``
    returns ``None``) and for an empty policy list (no site-scoped reference).
    Uses a 404 shape (no existence oracle), matching the policy-by-id guards.
    """
    if not policy_ids:
        return
    granted = site_ids_for_request(user)
    if granted is None:
        return
    ids = list(granted)
    accessible_subq = select(SLAPolicy.id).where(
        SLAPolicy.organization_id == org_id,
        SLAPolicy.id.in_(policy_ids),
        or_(
            SLAPolicy.scope != SLAPolicyScope.SITE.value,
            SLAPolicy.scope_id.in_(ids) if ids else SLAPolicy.scope_id.in_([]),
        ),
    )
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
    """
    Download a generated SLA report file.

    If no file has been rendered yet (file_path is null),
    the report_data JSON is returned instead.
    """
    org_id = _org_id(user)
    service = SLAReportGenerator(db)
    report = await service.get_report(report_id)

    if not report or report.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.file_path:
        resolved = Path(report.file_path).resolve()
        base = Path(REPORTS_BASE_DIR).resolve()
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
        media_type = "application/pdf" if report.format == "pdf" else "text/csv"
        safe_title = re.sub(r"[^\w\s\-.]", "", report.title)[:100]
        filename = f"{safe_title}.{report.format}"
        return FileResponse(
            path=str(resolved),
            media_type=media_type,
            filename=filename,
        )

    # No rendered file — return the data payload
    return {
        "id": str(report.id),
        "title": report.title,
        "format": report.format,
        "report_data": report.report_data,
    }


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
    schedule = await service.create_schedule(
        org_id,
        body.model_dump(),
        created_by=user.id,
    )
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
    # Per-user site grant: if the policy set is being (re)pointed, the new ids
    # must all be accessible to a site-limited caller — otherwise the schedule
    # would later aggregate sibling-site data in background context.
    if "sla_policy_ids" in update_data:
        await _assert_schedule_policies_accessible(db, user, org_id, update_data["sla_policy_ids"])

    updated = await service.update_schedule(
        schedule_id,
        update_data,
        org_id=org_id,
    )
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
