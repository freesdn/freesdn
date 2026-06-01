# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Backup Endpoints
===============================

Complete backup and restore API:
- Backup CRUD (list, create, get, delete, download)
- Stats
- Export / Import (instant config JSON, pfSense-style)
- Schedules CRUD + toggle
- Storage locations CRUD + test + supported-types
- Restore + restore-job status
"""

from __future__ import annotations

import logging
import os
import re
from datetime import UTC
from typing import Annotated, Any
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import is_unscoped_org_admin, is_unscoped_superuser
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.models import User
from app.models.core import Site
from app.schemas.backup import (
    BackupCreate,
    BackupListResponse,
    BackupManifestPreview,
    BackupResponse,
    BackupScheduleCreate,
    BackupScheduleResponse,
    BackupScheduleUpdate,
    BackupStats,
    ImportResult,
    RestoreJobResponse,
    RestoreRequest,
    StorageLocationCreate,
    StorageLocationResponse,
    StorageLocationTestResult,
    StorageLocationUpdate,
    SupportedStorageTypes,
)
from app.services.backup import SUPPORTED_STORAGE_TYPES, BackupService

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Org-isolation helpers
# ---------------------------------------------------------------------------


def _org_id(user: Any) -> Any:
    """Extract organization_id, raising 400 if missing."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _org_site_filter(organization_id: UUID) -> Any:
    """Subquery of site IDs for the given organization."""
    return (
        select(Site.id)
        .where(Site.organization_id == organization_id, Site.deleted_at.is_(None))
        .scalar_subquery()
    )


def _scope_rows_to_grants(user: Any, rows: Any) -> list[Any]:
    """Drop site-scoped rows the caller's per-user grant excludes.

    The org-scoped list endpoints (``/`` backups, ``/schedules``) previously
    returned every site in the org. A site-limited operator who omits the
    ``site_id`` filter would still see sibling-site rows. This narrows an
    already-fetched list to ``accessible_site_ids`` for site-limited callers,
    and is a NO-OP for super_admin / org_admin / grant-less users (whose
    ``is_site_limited`` is False) so org-wide views are unaffected. Rows with a
    ``None`` site_id (org-level, no site) are always kept, matching
    ``assert_can_access_site`` semantics.
    """
    if not getattr(user, "is_site_limited", False):
        return list(rows)
    granted = user.accessible_site_ids or set()
    return [r for r in rows if getattr(r, "site_id", None) is None or r.site_id in granted]


async def _assert_storage_in_org(
    session: AsyncSession, storage_location_id: Any, org_id: UUID
) -> None:
    """Reject a caller-supplied storage_location_id outside the caller's org.

    the backup create/schedule paths previously validated only
    site_id, letting an org bind a backup to another org's StorageLocation
    (cross-tenant write + use of the other org's decrypted storage creds), with
    the Celery scheduler re-firing it. The service-layer _resolve_storage is now
    org-scoped too; this gives the caller an immediate 404 instead of a silent
    run-time failure (and mirrors the storage GET/PATCH/DELETE guards).
    """
    if storage_location_id is None:
        return
    loc = await BackupService(session).get_storage_location(storage_location_id)
    if not loc or loc.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Storage location not found")


def _safe_download_filename(name: str | None, fallback: str) -> str:
    """NOTE H7: sanitize filenames before embedding in Content-Disposition.

    Attackers could otherwise inject newlines / quotes to forge headers
    (e.g. CRLF → ``\\r\\nSet-Cookie``) since storage_path is operator-
    controlled JSON. Strip directory parts and restrict to a safe charset.
    """
    base = os.path.basename(name or "") or fallback
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    # Belt-and-suspenders: cap length & enforce non-empty
    safe = safe[:255] or fallback
    return safe


# ---------------------------------------------------------------------------
# Storage locations sub-router (must be before main router to avoid
# /{backup_id} catch-all swallowing /storage-locations)
# ---------------------------------------------------------------------------

storage_router = APIRouter()


@storage_router.get("/types/supported", response_model=SupportedStorageTypes)
async def get_supported_storage_types(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Return all supported storage backend types with their config fields."""
    return {"types": SUPPORTED_STORAGE_TYPES}


@storage_router.get("", response_model=list[StorageLocationResponse])
async def list_storage_locations(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    storage_type: str | None = None,
    is_active: bool | None = None,
) -> Any:
    """List all configured storage locations."""
    svc = BackupService(session)
    return await svc.list_storage_locations(
        storage_type=storage_type,
        is_active=is_active,
        organization_id=_org_id(current_user),
    )


@storage_router.get("/{location_id}", response_model=StorageLocationResponse)
async def get_storage_location(
    location_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    loc = await BackupService(session).get_storage_location(location_id)
    if not loc or loc.organization_id != _org_id(current_user):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Storage location not found")
    return loc


@storage_router.post(
    "", response_model=StorageLocationResponse, status_code=status.HTTP_201_CREATED
)
async def create_storage_location(
    data: StorageLocationCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    try:
        return await BackupService(session).create_storage_location(
            **data.model_dump(exclude_unset=True),
            organization_id=_org_id(current_user),
        )
    except ValueError as exc:
        # _validate_endpoint_url SSRF rejection bubbles as ValueError.
        # Translate to 400 so the FE can show a clear error.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@storage_router.patch("/{location_id}", response_model=StorageLocationResponse)
async def update_storage_location(
    location_id: UUID,
    data: StorageLocationUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    existing = await BackupService(session).get_storage_location(location_id)
    if not existing or existing.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Storage location not found")
    loc = await BackupService(session).update_storage_location(
        location_id, **data.model_dump(exclude_unset=True)
    )
    if not loc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Storage location not found")
    return loc


@storage_router.delete("/{location_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_storage_location(
    location_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    existing = await BackupService(session).get_storage_location(location_id)
    if not existing or existing.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Storage location not found")
    ok = await BackupService(session).delete_storage_location(location_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Storage location not found")


@storage_router.post("/{location_id}/test", response_model=StorageLocationTestResult)
async def test_storage_location(
    location_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    # align with create/update — the test endpoint
    # triggers a real outbound connection to the configured storage host, so
    # it must carry the same admin-only gate; without it any authenticated
    # user could trigger SSRF probes against internal hosts.
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    existing = await BackupService(session).get_storage_location(location_id)
    if not existing or existing.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Storage location not found")
    return await BackupService(session).test_storage_location(location_id)


# ---------------------------------------------------------------------------
# Main backups router
# ---------------------------------------------------------------------------

router = APIRouter()

# Mount storage-locations sub-router FIRST
router.include_router(storage_router, prefix="/storage-locations", tags=["Storage Locations"])


# ── Stats ──────────────────────────────────────────────────────────────────


@router.get("/stats", response_model=BackupStats)
async def get_backup_stats(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    site_id: UUID | None = None,
) -> Any:
    """Get aggregate backup statistics."""
    org_id = _org_id(current_user)
    # validate the explicit site_id against the caller's per-user grant.
    assert_can_access_site(current_user, site_id, detail="Site not found")
    return await BackupService(session).get_stats(
        site_id=site_id,
        organization_id=org_id,
    )


# ── Export / Import ────────────────────────────────────────────────────────


@router.get("/export")
async def export_config(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    include_devices: bool = True,
    include_vlans: bool = True,
    include_ssids: bool = True,
    include_users: bool = True,
    include_automation: bool = True,
    include_settings: bool = True,
    compress: bool = False,
) -> Any:
    """
    Instant configuration export (pfSense-style).
    Returns a JSON file download.
    """
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)

    data = await BackupService(session).export_config(
        include_devices=include_devices,
        include_vlans=include_vlans,
        include_ssids=include_ssids,
        include_users=include_users,
        include_automation=include_automation,
        include_settings=include_settings,
        compress=compress,
        organization_id=org_id,
    )

    from datetime import datetime

    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    if compress:
        filename = _safe_download_filename(f"freesdn_config_{ts}.json.gz", "config.json.gz")
        media = "application/gzip"
    else:
        filename = _safe_download_filename(f"freesdn_config_{ts}.json", "config.json")
        media = "application/json"

    return Response(
        content=data,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/import", response_model=ImportResult)
async def import_config(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    file: UploadFile = File(...),
    dry_run: bool = Query(True),
    overwrite_existing: bool = Query(False),
) -> Any:
    """
    Import a .fsdn configuration file.

    NOTE H11: aligned with /restore — SUPER_ADMIN ONLY. Import is functionally
    a restore-from-arbitrary-file (it INSERTs/UPDATEs Site, Controller, Device
    and User rows) so the same privilege gate applies.
    NOTE C5: only the .fsdn format (with SHA-256 verification) is accepted.
    Use dry_run=true to preview what would be imported.
    """
    if not is_unscoped_superuser(current_user):  # scope-aware
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Super admin required for import (aligned with /restore)",
        )
    org_id = _org_id(current_user)

    from app.core.security_utils import MAX_CONFIG_IMPORT_BYTES

    # Enforce file size limit — read in chunks
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
    contents = b"".join(chunks)

    result = await BackupService(session).import_config(
        contents,
        dry_run=dry_run,
        overwrite_existing=overwrite_existing,
        organization_id=org_id,
    )
    return result


# ── Schedules ──────────────────────────────────────────────────────────────


@router.get("/schedules", response_model=list[BackupScheduleResponse])
async def list_schedules(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    site_id: UUID | None = None,
    is_enabled: bool | None = None,
) -> Any:
    org_id = _org_id(current_user)
    # validate an explicit site_id, then narrow the org-wide result to
    # the caller's granted sites (no-op for super_admin / org_admin).
    assert_can_access_site(current_user, site_id, detail="Site not found")
    schedules = await BackupService(session).list_schedules(
        site_id=site_id,
        is_enabled=is_enabled,
        organization_id=org_id,
    )
    return _scope_rows_to_grants(current_user, schedules)


@router.get("/schedules/{schedule_id}", response_model=BackupScheduleResponse)
async def get_schedule(
    schedule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    org_id = _org_id(current_user)
    s = await BackupService(session).get_schedule_for_organization(schedule_id, org_id)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    # enforce the per-user site grant on the resolved schedule.
    assert_can_access_site(current_user, s.site_id, detail="Schedule not found")
    return s


@router.post(
    "/schedules",
    response_model=BackupScheduleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_schedule(
    data: BackupScheduleCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    # Verify the target site belongs to the user's organization
    dump = data.model_dump(exclude_unset=True)
    if dump.get("site_id"):
        site = await session.get(Site, dump["site_id"])
        if not site or site.organization_id != org_id or site.deleted_at is not None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")
    await _assert_storage_in_org(session, dump.get("storage_location_id"), org_id)
    dump["organization_id"] = org_id
    return await BackupService(session).create_schedule(**dump)


@router.put("/schedules/{schedule_id}", response_model=BackupScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    data: BackupScheduleUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    existing = await BackupService(session).get_schedule_for_organization(schedule_id, org_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    updates = data.model_dump(exclude_unset=True)
    if updates.get("site_id"):
        site = await session.get(Site, updates["site_id"])
        if not site or site.organization_id != org_id or site.deleted_at is not None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    await _assert_storage_in_org(session, updates.get("storage_location_id"), org_id)
    s = await BackupService(session).update_schedule(schedule_id, **updates)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    return s


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    existing = await BackupService(session).get_schedule_for_organization(schedule_id, org_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    ok = await BackupService(session).delete_schedule(schedule_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")


class ToggleBody(BaseModel):
    is_enabled: bool = True


@router.post("/schedules/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: UUID,
    body: ToggleBody,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Toggle a schedule on/off."""
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    existing = await BackupService(session).get_schedule_for_organization(schedule_id, org_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    s = await BackupService(session).toggle_schedule(schedule_id, body.is_enabled)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    return {"ok": True}


# ── Restore ────────────────────────────────────────────────────────────────


@router.post("/restore", response_model=RestoreJobResponse)
async def restore_backup(
    data: RestoreRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Restore from a backup. Use dry_run=true to preview changes."""
    if not is_unscoped_superuser(current_user):  # scope-aware
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Super admin required for restore")
    org_id = _org_id(current_user)
    svc = BackupService(session)
    backup = await svc.get_backup_for_organization(data.backup_id, org_id)
    if not backup:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found")
    # Verify the target site belongs to the user's organization
    if data.target_site_id:
        target_site = await session.get(Site, data.target_site_id)
        if (
            not target_site
            or target_site.organization_id != org_id
            or target_site.deleted_at is not None
        ):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Target site not found")
    try:
        return await svc.restore_from_backup(
            data.backup_id,
            restore_devices=data.restore_devices,
            restore_vlans=data.restore_vlans,
            restore_ssids=data.restore_ssids,
            restore_users=data.restore_users,
            restore_automation=data.restore_automation,
            overwrite_existing=data.overwrite_existing,
            dry_run=data.dry_run,
            target_site_id=data.target_site_id,
            organization_id=org_id,
            initiated_by_id=current_user.id,
            contributors=data.contributors,
            passphrase=data.passphrase,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


@router.get("/{backup_id}/manifest", response_model=BackupManifestPreview)
async def preview_backup_manifest(
    backup_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Preview a backup's manifest WITHOUT restoring — the per-contributor
    sections + counts + per-contributor restorability. Powers the
    pre-restore selection UI. Super-admin only (same gate as restore,
    since the preview decrypts the archive)."""
    if not is_unscoped_superuser(current_user):  # scope-aware
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Super admin required to preview a backup")
    org_id = _org_id(current_user)
    try:
        return await BackupService(session).preview_backup_manifest(
            backup_id,
            org_id,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))


@router.get("/restore/{job_id}", response_model=RestoreJobResponse)
async def get_restore_job(
    job_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get status of a restore job."""
    org_id = _org_id(current_user)
    job = await BackupService(session).get_restore_job_for_organization(job_id, org_id)
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Restore job not found")
    return job


# ── Backup CRUD ────────────────────────────────────────────────────────────


@router.get("/", response_model=BackupListResponse)
async def list_backups(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    site_id: UUID | None = None,
    backup_type: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    storage_type: str | None = None,
    search: str | None = Query(None, max_length=256),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=200),
) -> Any:
    """List backups with filters and pagination."""
    org_id = _org_id(current_user)
    # validate an explicit site_id against the caller's per-user grant.
    assert_can_access_site(current_user, site_id, detail="Site not found")
    result = await BackupService(session).list_backups(
        site_id=site_id,
        backup_type=backup_type,
        status=status_filter,
        storage_type=storage_type,
        search=search,
        page=page,
        per_page=per_page,
        organization_id=org_id,
    )
    # Site-limited callers who omit site_id must not see sibling-site backups.
    # Narrow the page to granted sites and reflect the filtered count (no-op for
    # super_admin / org_admin, whose is_site_limited is False).
    if getattr(current_user, "is_site_limited", False):
        scoped = _scope_rows_to_grants(current_user, result.get("items", []))
        result["items"] = scoped
        result["total"] = len(scoped)
        result["pages"] = 1 if scoped else 0
    return result


@router.get("/{backup_id}", response_model=BackupResponse)
async def get_backup(
    backup_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    org_id = _org_id(current_user)
    backup = await BackupService(session).get_backup_for_organization(backup_id, org_id)
    if not backup:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found")
    # enforce the per-user site grant on the resolved backup.
    assert_can_access_site(current_user, backup.site_id, detail="Backup not found")
    return backup


@router.post("/", response_model=BackupResponse, status_code=status.HTTP_201_CREATED)
async def create_backup(
    data: BackupCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """
    Create and execute a backup.

    - Full backup: all config data
    - Device-specific: only selected devices
    - Supports local, S3, SFTP, FTP, Google Drive, Dropbox, WebDAV storage
    """
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    # Verify the target site belongs to the user's organization
    if data.site_id:
        site = await session.get(Site, data.site_id)
        if not site or site.organization_id != org_id or site.deleted_at is not None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")
    await _assert_storage_in_org(session, data.storage_location_id, org_id)

    try:
        return await BackupService(session).create_backup(
            name=data.name,
            description=data.description,
            backup_type=data.backup_type,
            site_id=data.site_id,
            device_ids=data.device_ids,
            include_devices=data.include_devices,
            include_vlans=data.include_vlans,
            include_ssids=data.include_ssids,
            include_users=data.include_users,
            include_automation=data.include_automation,
            storage_type=data.storage_type,
            storage_location_id=data.storage_location_id,
            is_encrypted=data.is_encrypted,
            include_secrets=data.include_secrets,
            passphrase=data.passphrase,
            retention_days=data.retention_days,
            created_by_id=current_user.id,
            organization_id=org_id,  # NOTE C4: tenant-scope
        )
    except ValueError as e:
        # Operator-actionable input error (e.g. a Full backup without a passphrase) —
        # surface it rather than the generic 500 below, which hides the cause.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception:
        # Previously leaked the raw exception string (e.g.
        # ``type object 'Device' has no attribute 'organization_id'``)
        # which discloses internal model shape to any admin caller.
        # Log full traceback for ops, return a generic message.
        log.exception("Backup creation failed for org=%s user=%s", org_id, current_user.id)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Backup creation failed",
        )


@router.get("/{backup_id}/download")
async def download_backup(
    backup_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Download a backup file."""
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    svc = BackupService(session)
    backup = await svc.get_backup_for_organization(backup_id, org_id)
    if not backup:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found")

    result = await svc.download_backup(backup_id)
    if not result:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup file not found")

    data, filename = result
    # NOTE H7: sanitize before embedding in the header — storage_path is
    # operator-controlled and could otherwise inject CRLF / quotes.
    safe_name = _safe_download_filename(filename, f"backup_{backup_id}.fsdn")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@router.delete("/{backup_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_backup(
    backup_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Delete a backup and its storage file."""
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin required")
    org_id = _org_id(current_user)
    svc = BackupService(session)
    backup = await svc.get_backup_for_organization(backup_id, org_id)
    if not backup:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found")

    ok = await svc.delete_backup(backup_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found")
