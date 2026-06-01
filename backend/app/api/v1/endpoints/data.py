# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Data Import/Export Endpoints
============================================

REST API for data import/export operations:
  GET    /summary          - Job summary (recent exports/imports)
  POST   /exports          - Start an export job
  GET    /exports           - List export jobs
  GET    /exports/{id}      - Get export job status
  GET    /exports/{id}/download - Download exported file
  POST   /imports/validate  - Validate/preview an import file
  POST   /imports           - Start an import job
  GET    /imports            - List import jobs
  GET    /imports/{id}       - Get import job status
  POST   /imports/{id}/rollback - Rollback a completed import
"""

from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import is_unscoped_org_admin
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.models import User
from app.schemas.import_export import (
    DataJobSummary,
    ExportJobListResponse,
    ExportJobResponse,
    ExportRequest,
    ImportJobListResponse,
    ImportJobResponse,
    ImportValidationResult,
)
from app.services.import_export import DATA_DIR, DataImportExportService

router = APIRouter()

Svc = DataImportExportService

# DoS guard: upper bound on the in-memory ExportJob scan used by the
# site-limited /exports branch (ExportJob.site_ids is JSONB, so the per-user
# site-grant visibility filter can't be pushed into SQL). Without a cap a
# site-limited user could force the whole org's ExportJob table into memory.
# Generous enough to fully cover normal orgs; pathological orgs see the
# most-recent window. Proper fix = SQL-native JSONB membership filtering.
_EXPORT_SCAN_CAP = 2000


def require_admin(user: User) -> None:
    # Scope-aware: a scoped key narrowed below admin must not pass.
    if not is_unscoped_org_admin(user):
        raise HTTPException(status_code=403, detail="Admin access required")


def _org_id(user: User) -> Any:
    """Extract organization_id from the current user, raising if absent."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _export_visible_to(user: User, job: Any) -> bool:
    """Per-user site-grant visibility for an export job.

    An :class:`ExportJob` carries ``site_ids`` (JSONB list of the site UUIDs the
    export targets). The data-export endpoints previously filtered only on
    ``organization_id``, so a site-limited operator could list / read / download
    a SIBLING site's export — or an org-wide export containing every site's data.

    Rules (no-op for super_admin / org_admin / grant-less users, exactly like
    ``can_access_site``):
      * non site-limited user  → always visible (returns True).
      * site-limited user, job targets specific ``site_ids`` → visible only if
        EVERY targeted site is within the user's grant.
      * site-limited user, job has EMPTY ``site_ids`` → org-wide export (data
        across all sites); NOT visible — it would leak sibling-site data.
    """
    if not getattr(user, "is_site_limited", False):
        return True
    raw_ids = getattr(job, "site_ids", None) or []
    if not raw_ids:
        # Org-wide export spans every site → off-limits to a site-limited user.
        return False
    for sid in raw_ids:
        try:
            site_uuid = sid if isinstance(sid, UUID) else UUID(str(sid))
        except (ValueError, TypeError):
            # Unparseable site id → fail closed.
            return False
        if not user.can_access_site(site_uuid):
            return False
    return True


# =============================================================================
# Summary
# =============================================================================


@router.get("/summary", response_model=DataJobSummary)
async def get_job_summary(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Get summary of import/export activity scoped to user's organization."""
    from app.models.import_export import ExportJob, ImportJob, JobStatus

    org_id = _org_id(user)

    # Fetch org-scoped summary (all counters constrained to this organization)
    data = await Svc.get_job_summary(session, organization_id=org_id)

    # Filter recent exports to this organization AND the caller's site grant.
    # (A site-limited user must not see sibling-site / org-wide export jobs.)
    data["recent_exports"] = [
        ExportJobResponse.model_validate(e)
        for e in data["recent_exports"]
        if e.organization_id == org_id and _export_visible_to(user, e)
    ]
    # Filter recent imports to this organization (imports carry no site dimension)
    data["recent_imports"] = [
        ImportJobResponse.model_validate(i)
        for i in data["recent_imports"]
        if i.organization_id == org_id
    ]

    # Recount totals scoped to organization (and to the caller's site grant for
    # exports, which are site-targetable).
    if "total_exports" in data:
        if getattr(user, "is_site_limited", False):
            org_exports = (
                (
                    await session.execute(
                        select(ExportJob).where(ExportJob.organization_id == org_id)
                    )
                )
                .scalars()
                .all()
            )
            data["total_exports"] = sum(1 for e in org_exports if _export_visible_to(user, e))
        else:
            count_exports = select(func.count(ExportJob.id)).where(
                ExportJob.organization_id == org_id
            )
            data["total_exports"] = (await session.execute(count_exports)).scalar_one()
    if "total_imports" in data:
        count_imports = select(func.count(ImportJob.id)).where(ImportJob.organization_id == org_id)
        data["total_imports"] = (await session.execute(count_imports)).scalar_one()

    # active_jobs from the service is already org-scoped. For a site-limited
    # caller the EXPORT portion must also honour the per-user site grant
    # (ExportJob.site_ids is JSONB, not a SQL-AND-able column), exactly like
    # total_exports above. Recompute the visible active-export count and add the
    # org-scoped active-import count (imports carry no site dimension).
    if getattr(user, "is_site_limited", False):
        active_export_rows = (
            (
                await session.execute(
                    select(ExportJob).where(
                        ExportJob.organization_id == org_id,
                        ExportJob.status.in_([JobStatus.PENDING, JobStatus.IN_PROGRESS]),
                    )
                )
            )
            .scalars()
            .all()
        )
        visible_active_exports = sum(1 for e in active_export_rows if _export_visible_to(user, e))
        data["active_jobs"] = visible_active_exports + data.get("active_imports", 0)
    # Drop the helper components so they are not passed to DataJobSummary(**data)
    # (the schema has no such fields).
    data.pop("active_exports", None)
    data.pop("active_imports", None)

    return DataJobSummary(**data)


# =============================================================================
# Exports
# =============================================================================


@router.post("/exports", response_model=ExportJobResponse, status_code=201)
async def create_export(
    body: ExportRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Start a new export job (runs in background)."""
    require_admin(user)
    org_id = _org_id(user)
    # Per-user site-grant: a caller may only export sites they can access.
    # require_admin already restricts this route to org/super admins (never
    # site-limited), but assert defensively in case the grant model evolves.
    for sid in body.site_ids or []:
        assert_can_access_site(user, sid, detail="Export job not found")
    job = await Svc.create_export_job(
        session,
        export_format=body.format,
        scope=body.scope,
        entity_types=body.entity_types,
        entity_filters=body.entity_filters,
        organization_id=org_id,
        site_ids=body.site_ids,
        created_by=user.id,
    )
    await session.commit()

    # Dispatch Celery task
    from app.tasks.import_export import run_export_job

    try:
        task = run_export_job.delay(str(job.id))
    except Exception as exc:
        # Broker unavailable / disconnected: the job row is committed but could
        # not be queued. Surface 503 so the client knows the export won't run
        # instead of leaking a kombu OperationalError as a generic 500.
        raise HTTPException(
            status_code=503, detail="Export service temporarily unavailable"
        ) from exc

    # Update with task ID
    job.celery_task_id = task.id
    await session.commit()

    return ExportJobResponse.model_validate(job)


@router.get("/exports", response_model=ExportJobListResponse)
async def list_exports(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
    limit: int = Query(20, ge=1, le=100),
) -> Any:
    """List export jobs scoped to the current user's organization."""
    from app.models.import_export import ExportJob

    org_id = _org_id(user)
    base = select(ExportJob).where(ExportJob.organization_id == org_id)

    if getattr(user, "is_site_limited", False):
        # Per-user site grant: ExportJob.site_ids is a JSONB list, so visibility
        # cannot be expressed as a single AND-able column predicate. Fetch the
        # org-scoped jobs and filter through the same rule used for single-
        # resource reads, then report the visible total.
        all_rows = (
            (
                await session.execute(
                    base.order_by(ExportJob.created_at.desc()).limit(_EXPORT_SCAN_CAP)
                )
            )
            .scalars()
            .all()
        )
        visible = [j for j in all_rows if _export_visible_to(user, j)]
        total = len(visible)
        items = visible[:limit]
    else:
        count_q = select(func.count(ExportJob.id)).where(ExportJob.organization_id == org_id)
        total = (await session.execute(count_q)).scalar_one()
        result = await session.execute(base.order_by(ExportJob.created_at.desc()).limit(limit))
        items = list(result.scalars().all())

    return ExportJobListResponse(
        items=[ExportJobResponse.model_validate(j) for j in items],
        total=total,
    )


@router.get("/exports/{job_id}", response_model=ExportJobResponse)
async def get_export(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Get export job status."""
    job = await Svc.get_export_job(session, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Export job not found")
    if job.organization_id != _org_id(user):
        raise HTTPException(status_code=404, detail="Export job not found")
    # Per-user site grant: a site-limited user may not read a sibling-site or
    # org-wide export job (404 shape — no existence oracle).
    if not _export_visible_to(user, job):
        raise HTTPException(status_code=404, detail="Export job not found")
    return ExportJobResponse.model_validate(job)


@router.get("/exports/{job_id}/download")
async def download_export(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Download the exported file."""
    job = await Svc.get_export_job(session, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Export job not found")
    if job.organization_id != _org_id(user):
        raise HTTPException(status_code=404, detail="Export job not found")
    # Per-user site grant: a site-limited user may not download a
    # sibling-site or org-wide export file (404 shape — no existence oracle).
    if not _export_visible_to(user, job):
        raise HTTPException(status_code=404, detail="Export job not found")
    if not job.file_path or not Path(job.file_path).exists():
        raise HTTPException(status_code=404, detail="Export file not available")

    # Path containment validation to prevent path traversal
    resolved = Path(job.file_path).resolve()
    export_base = DATA_DIR.resolve()
    try:
        resolved.relative_to(export_base)
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied")

    filename = Path(job.file_path).name
    media_type = "application/x-yaml" if job.export_format == "yaml" else "application/json"
    return FileResponse(
        path=job.file_path,
        filename=filename,
        media_type=media_type,
    )


# =============================================================================
# Import Validation
# =============================================================================


@router.post("/imports/validate", response_model=ImportValidationResult)
async def validate_import_file(
    file: UploadFile = File(...),
    source_format: str = Form("freesdn"),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Validate and preview an import file before starting import."""
    require_admin(user)

    # Save temp file
    upload_dir = DATA_DIR / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    from app.core.security_utils import MAX_CONFIG_IMPORT_BYTES, sanitize_filename

    safe_name = sanitize_filename(file.filename or "import.json")
    temp_path = upload_dir / f"validate_{safe_name}"

    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CONFIG_IMPORT_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large. Maximum size is {MAX_CONFIG_IMPORT_BYTES // (1024 * 1024)} MB",
                )
            chunks.append(chunk)
        content = b"".join(chunks)
        with open(temp_path, "wb") as f:
            f.write(content)

        result = await Svc.validate_import_file(str(temp_path), source_format)
        return ImportValidationResult(**result)
    finally:
        if temp_path.exists():
            temp_path.unlink()


# =============================================================================
# Imports
# =============================================================================


@router.post("/imports", response_model=ImportJobResponse, status_code=201)
async def create_import(
    file: UploadFile = File(...),
    source_format: str = Form("freesdn"),
    conflict_resolution: str = Form("skip"),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Start a new import job. Uploads file and runs in background."""
    require_admin(user)
    org_id = _org_id(user)

    # Save uploaded file
    upload_dir = DATA_DIR / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    from app.core.security_utils import MAX_CONFIG_IMPORT_BYTES, sanitize_filename

    safe_name = sanitize_filename(file.filename or "import.json")
    dest_path = upload_dir / f"import_{safe_name}"

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_CONFIG_IMPORT_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {MAX_CONFIG_IMPORT_BYTES // (1024 * 1024)} MB",
            )
        chunks.append(chunk)
    content = b"".join(chunks)
    with open(dest_path, "wb") as f:
        f.write(content)

    job = await Svc.create_import_job(
        session,
        source_format=source_format,
        conflict_resolution=conflict_resolution,
        organization_id=org_id,
        original_filename=file.filename,
        file_path=str(dest_path),
        file_size_bytes=len(content),
        created_by=user.id,
    )
    await session.commit()

    # Dispatch Celery task
    from app.tasks.import_export import run_import_job

    try:
        task = run_import_job.delay(str(job.id))
    except Exception as exc:
        # Broker unavailable / disconnected: the job row is committed but could
        # not be queued. Surface 503 so the client knows the import won't run
        # instead of leaking a kombu OperationalError as a generic 500.
        raise HTTPException(
            status_code=503, detail="Import service temporarily unavailable"
        ) from exc

    job.celery_task_id = task.id
    await session.commit()

    return ImportJobResponse.model_validate(job)


@router.get("/imports", response_model=ImportJobListResponse)
async def list_imports(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
    limit: int = Query(20, ge=1, le=100),
) -> Any:
    """List import jobs scoped to the current user's organization."""
    from app.models.import_export import ImportJob

    org_id = _org_id(user)
    base = select(ImportJob).where(ImportJob.organization_id == org_id)
    count_q = select(func.count(ImportJob.id)).where(ImportJob.organization_id == org_id)
    total = (await session.execute(count_q)).scalar_one()
    result = await session.execute(base.order_by(ImportJob.created_at.desc()).limit(limit))
    items = list(result.scalars().all())
    return ImportJobListResponse(
        items=[ImportJobResponse.model_validate(j) for j in items],
        total=total,
    )


@router.get("/imports/{job_id}", response_model=ImportJobResponse)
async def get_import(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Get import job status."""
    job = await Svc.get_import_job(session, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Import job not found")
    if job.organization_id != _org_id(user):
        raise HTTPException(status_code=404, detail="Import job not found")
    return ImportJobResponse.model_validate(job)


@router.post("/imports/{job_id}/rollback", response_model=ImportJobResponse)
async def rollback_import(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> Any:
    """Rollback a completed import by deleting created entities."""
    require_admin(user)
    org_id = _org_id(user)

    # Verify job belongs to user's organization before rollback
    job_check = await Svc.get_import_job(session, job_id)
    if not job_check:
        raise HTTPException(status_code=404, detail="Import job not found")
    if job_check.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Import job not found")

    result = await Svc.rollback_import(session, job_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    await session.commit()

    job = await Svc.get_import_job(session, job_id)
    return ImportJobResponse.model_validate(job)
