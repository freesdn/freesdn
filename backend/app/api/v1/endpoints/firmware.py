# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Firmware Management API Endpoints
================================================

REST endpoints for firmware lifecycle management.
Matches the frontend firmwareApi client at /api/v1/firmware/*.
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user, get_session
from app.core.site_access import assert_can_access_site, site_ids_for_request
from app.models import UserRole
from app.models.core import Site
from app.schemas.firmware import (
    CheckUpdatesRequest,
    CompatibilityCheckRequest,
    CompatibilityCheckResponse,
    DeviceFirmwareStatusListResponse,
    DeviceFirmwareStatusResponse,
    DeviceRollbackRequest,
    FirmwareCreate,
    FirmwareListResponse,
    FirmwareResponse,
    FirmwareSummaryResponse,
    FirmwareUpdate,
    ScheduleCreate,
    ScheduleListResponse,
    ScheduleResponse,
    ScheduleUpdate,
    UpgradeJobCreate,
    UpgradeJobListResponse,
    UpgradeJobResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _org_id(user: Any) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _org_site_filter(organization_id: UUID) -> dict[str, Any]:
    return (
        select(Site.id)
        .where(Site.organization_id == organization_id, Site.deleted_at.is_(None))
        .scalar_subquery()
    )


def require_admin(user: Any) -> None:
    # Scope ceiling: a scoped API key must not satisfy this role-only admin gate
    # via its owner's raw role. Firmware dispatch can brick a fleet.
    if getattr(user, "is_scoped", False):
        raise HTTPException(
            status_code=403, detail="Scoped API keys cannot satisfy role-based gates"
        )
    if getattr(user, "role", None) not in (UserRole.ORG_ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=403, detail="Admin access required")


def _validate_site_grant(
    user: Any, site_id: UUID | None, *, detail: str = "Site not found"
) -> None:
    """Per-user site-grant guard.

    No-op for super_admin / org_admin and for a ``None`` site_id; raises 404 for
    a site-limited user lacking the grant. Wraps the canonical
    ``assert_can_access_site`` so site_id query/body params are uniformly guarded.
    """
    assert_can_access_site(user, site_id, detail=detail)


# =========================================================================
# Firmware Repository
# =========================================================================


@router.get("/", response_model=FirmwareListResponse)
async def list_firmwares(
    vendor: str | None = None,
    model: str | None = None,
    device_type: str | None = None,
    release_type: str | None = None,
    is_latest: bool | None = None,
    is_critical: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    result = await svc.list_firmwares(
        session,
        vendor=vendor,
        model=model,
        device_type=device_type,
        release_type=release_type,
        is_latest=is_latest,
        is_critical=is_critical,
        organization_id=organization_id,
        page=page,
        page_size=page_size,
    )
    return result


@router.get("/summary", response_model=FirmwareSummaryResponse)
async def get_summary(
    site_id: UUID | None = None,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    _validate_site_grant(user, site_id)
    return await svc.get_summary(
        session,
        site_id=site_id,
        organization_id=organization_id,
        site_ids=site_ids_for_request(user),
    )


@router.post("/", response_model=FirmwareResponse, status_code=201)
async def create_firmware(
    data: FirmwareCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    payload = data.model_dump(exclude_unset=True)
    payload["organization_id"] = organization_id
    fw = await svc.create_firmware(session, payload)
    await session.commit()
    return fw


@router.put("/{firmware_id}", response_model=FirmwareResponse)
async def update_firmware(
    firmware_id: UUID,
    data: FirmwareUpdate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    fw = await svc.get_firmware(session, firmware_id)
    if not fw or fw.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Firmware not found")
    payload = data.model_dump(exclude_unset=True)
    payload.pop("organization_id", None)
    fw = await svc.update_firmware(session, firmware_id, payload)
    await session.commit()
    return fw


@router.delete("/{firmware_id}", status_code=204)
async def delete_firmware(
    firmware_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    fw = await svc.get_firmware(session, firmware_id)
    if not fw or fw.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Firmware not found")
    deleted = await svc.delete_firmware(session, firmware_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Firmware not found")
    await session.commit()


@router.post("/upload", response_model=FirmwareResponse, status_code=201)
async def upload_firmware(
    file: UploadFile = File(...),
    vendor: str = Query(...),
    model: str = Query(...),
    version: str = Query(...),
    release_type: str = Query("stable"),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)

    from app.core.security_utils import MAX_FIRMWARE_UPLOAD_BYTES
    from app.services.firmware import PersistentFirmwareService as svc

    # Enforce file size limit — read in chunks to avoid unbounded memory
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)  # 1 MB at a time
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FIRMWARE_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {MAX_FIRMWARE_UPLOAD_BYTES // (1024 * 1024)} MB",
            )
        chunks.append(chunk)
    content = b"".join(chunks)

    organization_id = _org_id(user)
    fw = await svc.upload_firmware(
        session,
        file_content=content,
        filename=file.filename or "firmware.bin",
        vendor=vendor,
        model=model,
        version=version,
        release_type=release_type,
        organization_id=organization_id,
    )
    await session.commit()
    return fw


@router.post("/{firmware_id}/cache", status_code=200)
async def cache_firmware(
    firmware_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    fw = await svc.get_firmware(session, firmware_id)
    if not fw or fw.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Firmware not found")
    fw = await svc.cache_firmware(session, firmware_id)
    await session.commit()
    return {"status": "cached", "firmware_id": str(firmware_id)}


# =========================================================================
# Device Firmware Status
# =========================================================================


@router.get("/devices/status", response_model=DeviceFirmwareStatusListResponse)
async def list_device_status(
    site_id: UUID | None = None,
    device_type: str | None = None,
    vendor: str | None = None,
    update_available: bool | None = None,
    critical_only: bool = False,
    search: str | None = Query(None, max_length=255),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    _validate_site_grant(user, site_id)
    return await svc.list_device_status(
        session,
        site_id=site_id,
        device_type=device_type,
        vendor=vendor,
        update_available=update_available,
        critical_only=critical_only,
        search=search,
        organization_id=organization_id,
        site_ids=site_ids_for_request(user),
        page=page,
        page_size=page_size,
    )


@router.get("/devices/{device_id}/status", response_model=DeviceFirmwareStatusResponse)
async def get_device_status(
    device_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    status = await svc.get_device_status(session, device_id)
    org_sites = (
        (
            await session.execute(
                select(Site.id).where(
                    Site.organization_id == organization_id, Site.deleted_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    if not status or status.site_id not in org_sites:
        raise HTTPException(status_code=404, detail="Device firmware status not found")
    # a site-limited caller may only read status for a
    # device in their granted sites (404 — no existence oracle).
    _validate_site_grant(user, status.site_id, detail="Device firmware status not found")
    return status


@router.post("/devices/check")
async def check_updates(
    data: CheckUpdatesRequest,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    _validate_site_grant(user, data.site_id)
    result = await svc.check_updates(
        session,
        device_ids=data.device_ids,
        site_id=data.site_id,
        organization_id=organization_id,
        site_ids=site_ids_for_request(user),
    )
    await session.commit()
    return result


@router.post("/devices/{device_id}/rollback")
async def rollback_device(
    device_id: UUID,
    data: DeviceRollbackRequest,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    # Verify device belongs to org before rollback
    status = await svc.get_device_status(session, device_id)
    org_sites = (
        (
            await session.execute(
                select(Site.id).where(
                    Site.organization_id == organization_id, Site.deleted_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    if not status or status.site_id not in org_sites:
        raise HTTPException(status_code=404, detail="Device firmware status not found")
    # site-grant boundary on the rollback action.
    _validate_site_grant(user, status.site_id, detail="Device firmware status not found")

    result = await svc.rollback_device(
        session,
        device_id,
        target_version=data.target_version,
        backup_id=data.backup_id,
    )
    await session.commit()
    return result


# =========================================================================
# Compatibility Check
# =========================================================================


@router.post("/compatibility/check", response_model=CompatibilityCheckResponse)
async def check_compatibility(
    data: CompatibilityCheckRequest,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    # Verify the firmware image belongs to the user's org
    fw = await svc.get_firmware(session, data.firmware_id)
    if not fw or fw.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Firmware not found")
    return await svc.check_compatibility(
        session,
        data.firmware_id,
        data.device_ids,
        organization_id=organization_id,
        site_ids=site_ids_for_request(user),
    )


# =========================================================================
# Upgrade Jobs
# =========================================================================


@router.get("/jobs", response_model=UpgradeJobListResponse)
async def list_jobs(
    status: str | None = None,
    site_id: UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    _validate_site_grant(user, site_id)
    return await svc.list_jobs(
        session,
        status=status,
        site_id=site_id,
        organization_id=organization_id,
        site_ids=site_ids_for_request(user),
        page=page,
        page_size=page_size,
    )


@router.get("/jobs/{job_id}", response_model=UpgradeJobResponse)
async def get_job(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    org_sites = (
        (
            await session.execute(
                select(Site.id).where(
                    Site.organization_id == organization_id, Site.deleted_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    job = await svc.get_job(session, job_id)
    if not job or job.site_id not in org_sites:
        raise HTTPException(status_code=404, detail="Job not found")
    # site-grant boundary on reading a job by id.
    _validate_site_grant(user, job.site_id, detail="Job not found")
    return job


@router.post("/jobs", response_model=UpgradeJobResponse, status_code=201)
async def create_job(
    data: UpgradeJobCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    payload = data.model_dump(exclude_unset=True)
    # Org sites are reused for site_id + device_id + firmware ownership checks.
    org_sites = (
        (
            await session.execute(
                select(Site.id).where(
                    Site.organization_id == organization_id, Site.deleted_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    # Validate that the site_id (if provided) belongs to the user's org
    site_id = payload.get("site_id")
    if site_id:
        if site_id not in org_sites:
            raise HTTPException(status_code=404, detail="Site not found")
        # a site-limited admin may only create a job
        # targeting one of their granted sites.
        _validate_site_grant(user, site_id, detail="Site not found")

    # Cross-tenant guard: every device_id must belong to a site in the caller's
    # org AND (for a site-limited admin) one of their granted sites. Otherwise a
    # job could be queued against foreign device IDs and dispatched to Celery.
    device_ids = payload.get("device_ids") or []
    if device_ids:
        from app.models.devices import Device

        dev_q = select(Device.id).where(
            Device.id.in_(device_ids),
            Device.site_id.in_(org_sites),
        )
        grant_sites = site_ids_for_request(user)
        if grant_sites is not None:
            dev_q = dev_q.where(Device.site_id.in_(list(grant_sites)))
        owned = set((await session.execute(dev_q)).scalars().all())
        if set(device_ids) - owned:
            # 404 (not 403) to avoid an existence oracle for foreign device ids.
            raise HTTPException(status_code=404, detail="Device not found")

    # Cross-tenant guard: firmware_id (if provided) must belong to the org.
    firmware_id = payload.get("firmware_id")
    if firmware_id:
        fw = await svc.get_firmware(session, firmware_id)
        if not fw or fw.organization_id != organization_id:
            raise HTTPException(status_code=404, detail="Firmware not found")

    job = await svc.create_job(session, payload, user_id=user.id)
    await session.commit()

    # Dispatch Celery task if not scheduled for later
    if not data.scheduled_at:
        try:
            from app.tasks.firmware import run_firmware_upgrade

            run_firmware_upgrade.delay(str(job.id))
        except Exception as e:
            logger.warning("Could not dispatch firmware upgrade task: %s", e)

    return job


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    org_sites = (
        (
            await session.execute(
                select(Site.id).where(
                    Site.organization_id == organization_id, Site.deleted_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    existing = await svc.get_job(session, job_id)
    if not existing or existing.site_id not in org_sites:
        raise HTTPException(status_code=404, detail="Job not found")
    # site-grant boundary on cancelling a job.
    _validate_site_grant(user, existing.site_id, detail="Job not found")

    job = await svc.cancel_job(session, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    await session.commit()
    return {"status": "cancelled", "job_id": str(job_id)}


@router.post("/jobs/{job_id}/retry", response_model=UpgradeJobResponse)
async def retry_job(
    job_id: UUID,
    failed_only: bool = Query(True),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    org_sites = (
        (
            await session.execute(
                select(Site.id).where(
                    Site.organization_id == organization_id, Site.deleted_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    existing = await svc.get_job(session, job_id)
    if not existing or existing.site_id not in org_sites:
        raise HTTPException(status_code=404, detail="Job not found")
    # site-grant boundary on retrying a job.
    _validate_site_grant(user, existing.site_id, detail="Job not found")

    new_job = await svc.retry_job(session, job_id, failed_only=failed_only)
    if not new_job:
        raise HTTPException(status_code=404, detail="Job not found")
    await session.commit()

    # Dispatch the retry job
    try:
        from app.tasks.firmware import run_firmware_upgrade

        run_firmware_upgrade.delay(str(new_job.id))
    except Exception as e:
        logger.warning("Could not dispatch firmware retry task: %s", e)

    return new_job


# =========================================================================
# Schedules
# =========================================================================


@router.get("/schedules", response_model=ScheduleListResponse)
async def list_schedules(
    site_id: UUID | None = None,
    is_enabled: bool | None = None,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    _validate_site_grant(user, site_id)
    items = await svc.list_schedules(
        session,
        site_id=site_id,
        is_enabled=is_enabled,
        organization_id=organization_id,
        site_ids=site_ids_for_request(user),
    )
    return {"items": items, "total": len(items), "page": 1, "page_size": len(items) or 20}


@router.post("/schedules", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    data: ScheduleCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    payload = data.model_dump(exclude_unset=True)
    _validate_site_grant(user, payload.get("site_id"))
    payload["organization_id"] = organization_id
    schedule = await svc.create_schedule(session, payload, user_id=user.id)
    await session.commit()
    return schedule


@router.put("/schedules/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    data: ScheduleUpdate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    existing = await svc.get_schedule(session, schedule_id)
    if not existing or existing.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    # site-grant boundary on updating a schedule.
    _validate_site_grant(user, existing.site_id, detail="Schedule not found")
    payload = data.model_dump(exclude_unset=True)
    payload.pop("organization_id", None)
    # A site-limited admin cannot re-target the schedule to a site outside
    # their grants either.
    if "site_id" in payload:
        _validate_site_grant(user, payload.get("site_id"), detail="Schedule not found")
    schedule = await svc.update_schedule(session, schedule_id, payload)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await session.commit()
    return schedule


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    existing = await svc.get_schedule(session, schedule_id)
    if not existing or existing.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    # site-grant boundary on deleting a schedule.
    _validate_site_grant(user, existing.site_id, detail="Schedule not found")
    deleted = await svc.delete_schedule(session, schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await session.commit()


@router.post("/schedules/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    existing = await svc.get_schedule(session, schedule_id)
    if not existing or existing.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    # site-grant boundary on toggling a schedule.
    _validate_site_grant(user, existing.site_id, detail="Schedule not found")

    schedule = await svc.toggle_schedule(session, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await session.commit()
    return {"id": str(schedule.id), "is_enabled": schedule.is_enabled}


@router.post("/schedules/{schedule_id}/run-now", response_model=UpgradeJobResponse)
async def run_schedule_now(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    require_admin(user)
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    existing = await svc.get_schedule(session, schedule_id)
    if not existing or existing.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    # site-grant boundary on running a schedule now.
    _validate_site_grant(user, existing.site_id, detail="Schedule not found")

    job = await svc.run_schedule_now(session, schedule_id)
    if not job:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await session.commit()

    # Dispatch the job
    try:
        from app.tasks.firmware import run_firmware_upgrade

        run_firmware_upgrade.delay(str(job.id))
    except Exception as e:
        logger.warning("Could not dispatch scheduled firmware task: %s", e)

    return job


# =========================================================================
# Single Firmware Lookup (declared AFTER static paths to prevent
# /{firmware_id} from shadowing /jobs, /schedules, etc.)
# =========================================================================


@router.get("/{firmware_id}", response_model=FirmwareResponse)
async def get_firmware(
    firmware_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    from app.services.firmware import PersistentFirmwareService as svc

    organization_id = _org_id(user)
    fw = await svc.get_firmware(session, firmware_id)
    if not fw or fw.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Firmware not found")
    return fw
