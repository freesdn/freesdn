# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Firmware Management Service
===========================================

DB-backed service for firmware lifecycle management:
- Firmware repository (catalog, upload, cache)
- Device firmware status tracking
- Upgrade job management (batch, staged rollout)
- Scheduled upgrade policies
- Compatibility validation
- Rollback support
"""

import hashlib
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security_utils import escape_like

logger = logging.getLogger(__name__)

FIRMWARE_DIR = Path("/data/freesdn_firmware")


def _site_grant_clause(site_id_column: Any, site_ids: Any) -> Any:
    """Per-user site-grant predicate for a nullable site_id column.

    ``site_ids`` is the caller's granted-site set (from ``site_ids_for_request``)
    or ``None`` when the caller is unrestricted. When restricted, scope to the
    granted sites while keeping ``site_id IS NULL`` org-level rows visible
    (matching ``assert_can_access_site``'s "None site_id is allowed" semantics).
    Fail-closed (empty IN) for the shouldn't-happen empty-grant case.
    """
    if site_ids is None:
        return None
    ids = list(site_ids)
    return site_id_column.is_(None) | site_id_column.in_(ids)


class PersistentFirmwareService:
    """DB-backed firmware management service."""

    # =====================================================================
    # Firmware Repository
    # =====================================================================

    @staticmethod
    async def list_firmwares(
        session: AsyncSession,
        *,
        vendor: str | None = None,
        model: str | None = None,
        device_type: str | None = None,
        release_type: str | None = None,
        is_latest: bool | None = None,
        is_critical: bool | None = None,
        organization_id: UUID | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        from app.models.firmware import FirmwareImage

        q = select(FirmwareImage)
        count_q = select(func.count(FirmwareImage.id))

        if organization_id is not None:
            q = q.where(FirmwareImage.organization_id == organization_id)
            count_q = count_q.where(FirmwareImage.organization_id == organization_id)

        if vendor:
            escaped_vendor = escape_like(vendor)
            q = q.where(FirmwareImage.vendor.ilike(f"%{escaped_vendor}%", escape="\\"))
            count_q = count_q.where(FirmwareImage.vendor.ilike(f"%{escaped_vendor}%", escape="\\"))
        if model:
            escaped_model = escape_like(model)
            q = q.where(FirmwareImage.model.ilike(f"%{escaped_model}%", escape="\\"))
            count_q = count_q.where(FirmwareImage.model.ilike(f"%{escaped_model}%", escape="\\"))
        if device_type:
            q = q.where(FirmwareImage.device_type == device_type)
            count_q = count_q.where(FirmwareImage.device_type == device_type)
        if release_type:
            q = q.where(FirmwareImage.release_type == release_type)
            count_q = count_q.where(FirmwareImage.release_type == release_type)
        if is_latest is not None:
            q = q.where(FirmwareImage.is_latest == is_latest)
            count_q = count_q.where(FirmwareImage.is_latest == is_latest)
        if is_critical is not None:
            q = q.where(FirmwareImage.is_critical == is_critical)
            count_q = count_q.where(FirmwareImage.is_critical == is_critical)

        total = (await session.execute(count_q)).scalar() or 0
        offset = (page - 1) * page_size
        q = q.order_by(FirmwareImage.created_at.desc()).offset(offset).limit(page_size)
        rows = (await session.execute(q)).scalars().all()

        return {"items": rows, "total": total, "page": page, "page_size": page_size}

    @staticmethod
    async def get_firmware(session: AsyncSession, fw_id: UUID) -> Any:
        from app.models.firmware import FirmwareImage

        result = await session.execute(select(FirmwareImage).where(FirmwareImage.id == fw_id))
        return result.scalars().first()

    @staticmethod
    async def create_firmware(session: AsyncSession, data: dict[str, Any]) -> Any:
        from app.models.firmware import FirmwareImage

        fw = FirmwareImage(**data)
        session.add(fw)
        await session.flush()
        await session.refresh(fw)
        return fw

    @staticmethod
    async def update_firmware(session: AsyncSession, fw_id: UUID, data: dict[str, Any]) -> Any:

        fw = await PersistentFirmwareService.get_firmware(session, fw_id)
        if not fw:
            return None

        for k, v in data.items():
            if v is not None:
                setattr(fw, k, v)
        fw.updated_at = datetime.now(UTC)
        await session.flush()
        await session.refresh(fw)
        return fw

    @staticmethod
    async def delete_firmware(session: AsyncSession, fw_id: UUID) -> bool:

        fw = await PersistentFirmwareService.get_firmware(session, fw_id)
        if not fw:
            return False

        # Remove cached file if exists
        if fw.file_path and Path(fw.file_path).exists():
            Path(fw.file_path).unlink(missing_ok=True)

        await session.delete(fw)
        await session.flush()
        return True

    @staticmethod
    async def upload_firmware(
        session: AsyncSession,
        file_content: bytes,
        filename: str,
        vendor: str,
        model: str,
        version: str,
        release_type: str = "stable",
        organization_id: UUID | None = None,
    ) -> Any:
        """Upload a firmware binary and create a catalog entry."""
        from app.core.security_utils import (
            MAX_FIRMWARE_UPLOAD_BYTES,
            sanitize_filename,
        )
        from app.models.firmware import FirmwareImage

        # SECURITY: Enforce file size limit
        if len(file_content) > MAX_FIRMWARE_UPLOAD_BYTES:
            raise ValueError(
                f"Firmware file exceeds maximum size of "
                f"{MAX_FIRMWARE_UPLOAD_BYTES // (1024 * 1024)} MB"
            )

        FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)

        # SECURITY: Sanitize all filename components to prevent path traversal
        safe_vendor = sanitize_filename(vendor)
        safe_model = sanitize_filename(model)
        safe_version = sanitize_filename(version)
        safe_file = sanitize_filename(filename)
        safe_name = f"{safe_vendor}_{safe_model}_{safe_version}_{safe_file}"
        dest = FIRMWARE_DIR / safe_name

        # Verify the resolved path is within FIRMWARE_DIR
        if not dest.resolve().is_relative_to(FIRMWARE_DIR.resolve()):
            raise ValueError("Path traversal detected in firmware filename")

        dest.write_bytes(file_content)

        sha256 = hashlib.sha256(file_content).hexdigest()

        fw = FirmwareImage(
            vendor=vendor,
            model=model,
            version=version,
            release_type=release_type,
            display_name=f"{vendor} {model} v{version}",
            file_path=str(dest),
            file_size_bytes=len(file_content),
            checksum_sha256=sha256,
            is_cached=True,
            cached_at=datetime.now(UTC),
            organization_id=organization_id,
        )
        session.add(fw)
        await session.flush()
        await session.refresh(fw)
        return fw

    @staticmethod
    async def cache_firmware(session: AsyncSession, fw_id: UUID) -> Any:
        """Mark a firmware as cached (simulate download from URL)."""

        fw = await PersistentFirmwareService.get_firmware(session, fw_id)
        if not fw:
            return None

        fw.is_cached = True
        fw.cached_at = datetime.now(UTC)
        await session.flush()
        await session.refresh(fw)
        return fw

    # =====================================================================
    # Device Firmware Status
    # =====================================================================

    @staticmethod
    async def list_device_status(
        session: AsyncSession,
        *,
        site_id: UUID | None = None,
        device_type: str | None = None,
        vendor: str | None = None,
        update_available: bool | None = None,
        critical_only: bool = False,
        search: str | None = None,
        organization_id: UUID | None = None,
        site_ids: Any = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        from app.models.firmware import DeviceFirmwareStatus

        q = select(DeviceFirmwareStatus)
        count_q = select(func.count(DeviceFirmwareStatus.id))

        if organization_id is not None:
            from app.models.core import Site

            site_sub = (
                select(Site.id).where(Site.organization_id == organization_id).scalar_subquery()
            )
            q = q.where(DeviceFirmwareStatus.site_id.in_(site_sub))
            count_q = count_q.where(DeviceFirmwareStatus.site_id.in_(site_sub))

        # scope to the caller's granted sites.
        grant_clause = _site_grant_clause(DeviceFirmwareStatus.site_id, site_ids)
        if grant_clause is not None:
            q = q.where(grant_clause)
            count_q = count_q.where(grant_clause)

        if site_id:
            q = q.where(DeviceFirmwareStatus.site_id == site_id)
            count_q = count_q.where(DeviceFirmwareStatus.site_id == site_id)
        if device_type:
            q = q.where(DeviceFirmwareStatus.device_type == device_type)
            count_q = count_q.where(DeviceFirmwareStatus.device_type == device_type)
        if vendor:
            escaped_vendor = escape_like(vendor)
            q = q.where(DeviceFirmwareStatus.vendor.ilike(f"%{escaped_vendor}%", escape="\\"))
            count_q = count_q.where(
                DeviceFirmwareStatus.vendor.ilike(f"%{escaped_vendor}%", escape="\\")
            )
        if update_available is not None:
            q = q.where(DeviceFirmwareStatus.update_available == update_available)
            count_q = count_q.where(DeviceFirmwareStatus.update_available == update_available)
        if critical_only:
            q = q.where(DeviceFirmwareStatus.critical_update_available.is_(True))
            count_q = count_q.where(DeviceFirmwareStatus.critical_update_available.is_(True))
        if search and search.strip():
            escaped_search = escape_like(search.strip())
            pattern = f"%{escaped_search}%"
            search_clause = DeviceFirmwareStatus.device_name.ilike(
                pattern, escape="\\"
            ) | DeviceFirmwareStatus.model.ilike(pattern, escape="\\")
            q = q.where(search_clause)
            count_q = count_q.where(search_clause)

        total = (await session.execute(count_q)).scalar() or 0
        offset = (page - 1) * page_size
        q = q.order_by(DeviceFirmwareStatus.updated_at.desc()).offset(offset).limit(page_size)
        rows = (await session.execute(q)).scalars().all()

        return {"items": rows, "total": total, "page": page, "page_size": page_size}

    @staticmethod
    async def get_device_status(session: AsyncSession, device_id: UUID) -> Any:
        from app.models.firmware import DeviceFirmwareStatus

        result = await session.execute(
            select(DeviceFirmwareStatus).where(DeviceFirmwareStatus.device_id == device_id)
        )
        return result.scalars().first()

    @staticmethod
    async def check_updates(
        session: AsyncSession,
        device_ids: list[UUID] | None = None,
        site_id: UUID | None = None,
        organization_id: UUID | None = None,
        site_ids: Any = None,
    ) -> dict[str, Any]:
        """
        Check firmware updates for specified devices or site.
        Updates DeviceFirmwareStatus entries.
        Automatically syncs NVRs and VoIP phones from their respective
        modules into the devices table so they appear in firmware tracking.
        """
        from app.models.devices import Device
        from app.models.firmware import DeviceFirmwareStatus, FirmwareImage

        # Sync module-managed devices (NVRs, phones, firewalls) via the
        # unified DeviceSyncService before checking firmware status.
        from app.services.device_sync import DeviceSyncService

        sync_result = await DeviceSyncService.sync_all(session)
        if sync_result.get("total"):
            logger.info("Device sync: %s", sync_result)

        # Get target devices
        q = select(Device)

        # Scope to organization's sites
        if organization_id is not None:
            from app.models.core import Site

            site_sub = (
                select(Site.id).where(Site.organization_id == organization_id).scalar_subquery()
            )
            q = q.where(Device.site_id.in_(site_sub))

        # a site-limited caller may only refresh/check
        # devices in their granted sites — even when passing explicit
        # device_ids that reference a sibling site. Device.site_id is NOT
        # nullable here, but guard with the standard clause for consistency.
        grant_clause = _site_grant_clause(Device.site_id, site_ids)
        if grant_clause is not None:
            q = q.where(grant_clause)

        if device_ids:
            q = q.where(Device.id.in_(device_ids))
        elif site_id:
            q = q.where(Device.site_id == site_id)

        devices = (await session.execute(q)).scalars().all()
        checked = 0

        # Batch-fetch latest firmware image per (vendor, model) to avoid N+1
        fw_sub = (
            select(
                FirmwareImage.vendor,
                FirmwareImage.model,
                func.max(FirmwareImage.created_at).label("max_created"),
            )
            .where(FirmwareImage.is_deprecated.is_(False))
            .group_by(FirmwareImage.vendor, FirmwareImage.model)
            .subquery()
        )
        fw_latest_q = (
            select(FirmwareImage)
            .join(
                fw_sub,
                (FirmwareImage.vendor == fw_sub.c.vendor)
                & (FirmwareImage.model == fw_sub.c.model)
                & (FirmwareImage.created_at == fw_sub.c.max_created),
            )
            .where(FirmwareImage.is_deprecated.is_(False))
        )
        all_latest_fw = (await session.execute(fw_latest_q)).scalars().all()
        # Map (vendor, model) → FirmwareImage
        fw_map: dict[tuple[str, str], Any] = {}
        for fw in all_latest_fw:
            fw_map[(fw.vendor, fw.model)] = fw

        for device in devices:
            # Look up latest firmware from pre-fetched map
            latest_fw = fw_map.get((device.manufacturer or "", device.model or ""))

            # Get or create device firmware status
            existing = await PersistentFirmwareService.get_device_status(session, device.id)

            now = datetime.now(UTC)
            current_version = getattr(device, "firmware_version", None) or ""
            latest_version = latest_fw.version if latest_fw else None
            is_up_to_date = current_version == latest_version if latest_version else True

            if existing:
                existing.current_version = current_version
                existing.latest_version = latest_version
                existing.recommended_version = (
                    latest_fw.version if latest_fw and latest_fw.is_recommended else None
                )
                existing.is_up_to_date = is_up_to_date
                existing.update_available = not is_up_to_date
                existing.critical_update_available = (
                    not is_up_to_date and latest_fw is not None and latest_fw.is_critical
                )
                existing.can_upgrade = True
                existing.upgrade_path = latest_fw.upgrade_path if latest_fw else []
                existing.device_name = device.name
                existing.device_type = device.device_type
                existing.vendor = device.manufacturer
                existing.model = device.model
                existing.last_checked_at = now
            else:
                new_status = DeviceFirmwareStatus(
                    device_id=device.id,
                    site_id=device.site_id,
                    current_version=current_version,
                    latest_version=latest_version,
                    recommended_version=(
                        latest_fw.version if latest_fw and latest_fw.is_recommended else None
                    ),
                    is_up_to_date=is_up_to_date,
                    update_available=not is_up_to_date,
                    critical_update_available=(
                        not is_up_to_date and latest_fw is not None and latest_fw.is_critical
                    ),
                    can_upgrade=True,
                    upgrade_path=latest_fw.upgrade_path if latest_fw else [],
                    device_name=device.name,
                    device_type=device.device_type,
                    vendor=device.manufacturer,
                    model=device.model,
                    last_checked_at=now,
                )
                session.add(new_status)

            checked += 1

        await session.flush()
        return {"checked": checked, "devices": len(devices)}

    @staticmethod
    async def rollback_device(
        session: AsyncSession,
        device_id: UUID,
        target_version: str | None = None,
        backup_id: str | None = None,
    ) -> dict[str, Any]:
        """Initiate a device firmware rollback.

        NOT IMPLEMENTED. No adapter exposes a firmware rollback primitive
        yet, so there is nothing to dispatch to.

        This used to return ``{"success": True, "message": "Rollback
        initiated"}`` unconditionally, having done nothing at all -- it
        ignored ``backup_id`` entirely and echoed ``target_version`` back.
        An operator rolling a device off bad firmware was told it worked
        while the device kept running the firmware they were trying to
        escape. Reporting the absence honestly is the whole point of the
        adapter-maturity discipline; a fabricated success is the one
        outcome that discipline exists to prevent.
        """
        raise NotImplementedError(
            "Firmware rollback is not implemented: no adapter exposes a "
            "rollback primitive. Re-flash the desired version through the "
            "normal upgrade path instead."
        )

    # =====================================================================
    # Compatibility Check
    # =====================================================================

    @staticmethod
    async def check_compatibility(
        session: AsyncSession,
        firmware_id: UUID,
        device_ids: list[UUID],
        organization_id: UUID | None = None,
        site_ids: Any = None,
    ) -> dict[str, Any]:
        from app.models.devices import Device

        fw = await PersistentFirmwareService.get_firmware(session, firmware_id)
        if not fw:
            return {
                "firmware_id": str(firmware_id),
                "compatible": [],
                "incompatible": [],
                "warnings": [],
            }

        dev_q = select(Device).where(Device.id.in_(device_ids))
        if organization_id is not None:
            from app.models.core import Site

            site_sub = (
                select(Site.id).where(Site.organization_id == organization_id).scalar_subquery()
            )
            dev_q = dev_q.where(Device.site_id.in_(site_sub))
        # exclude sibling-site devices for a site-limited
        # caller even when their ids are passed explicitly.
        grant_clause = _site_grant_clause(Device.site_id, site_ids)
        if grant_clause is not None:
            dev_q = dev_q.where(grant_clause)
        devices = (await session.execute(dev_q)).scalars().all()

        compatible = []
        incompatible = []
        warnings = []

        for device in devices:
            dev_vendor = (device.manufacturer or "").lower()
            fw_vendor = (fw.vendor or "").lower()

            if dev_vendor != fw_vendor:
                incompatible.append(
                    {
                        "device_id": str(device.id),
                        "reason": f"Vendor mismatch: device is {device.manufacturer}, firmware is for {fw.vendor}",
                    }
                )
                continue

            dev_model = (device.model or "").lower()
            fw_model = (fw.model or "").lower()

            if dev_model != fw_model:
                # Check compatible_models list
                compat_models = [m.lower() for m in (fw.compatible_models or [])]
                if dev_model not in compat_models:
                    incompatible.append(
                        {
                            "device_id": str(device.id),
                            "reason": f"Model mismatch: device is {device.model}, firmware is for {fw.model}",
                        }
                    )
                    continue

            # Check min_version requirement
            current_ver = getattr(device, "firmware_version", None) or ""
            if fw.min_version and current_ver and current_ver < fw.min_version:
                warnings.append(
                    {
                        "device_id": str(device.id),
                        "warning": f"Device firmware {current_ver} is below minimum {fw.min_version}; upgrade path may be needed",
                    }
                )

            compatible.append(str(device.id))

        return {
            "firmware_id": str(firmware_id),
            "compatible": compatible,
            "incompatible": incompatible,
            "warnings": warnings,
        }

    # =====================================================================
    # Upgrade Jobs
    # =====================================================================

    @staticmethod
    async def create_job(
        session: AsyncSession, data: dict[str, Any], user_id: UUID | None = None
    ) -> Any:
        from app.models.firmware import FirmwareUpgradeJob

        job = FirmwareUpgradeJob(
            **data,
            total_devices=len(data.get("device_ids", [])),
            created_by=user_id,
        )
        session.add(job)
        await session.flush()
        await session.refresh(job)
        return job

    @staticmethod
    async def get_job(session: AsyncSession, job_id: UUID) -> Any:
        from app.models.firmware import FirmwareUpgradeJob

        result = await session.execute(
            select(FirmwareUpgradeJob).where(FirmwareUpgradeJob.id == job_id)
        )
        return result.scalars().first()

    @staticmethod
    async def list_jobs(
        session: AsyncSession,
        *,
        status: str | None = None,
        site_id: UUID | None = None,
        organization_id: UUID | None = None,
        site_ids: Any = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        from app.models.firmware import FirmwareUpgradeJob

        q = select(FirmwareUpgradeJob)
        count_q = select(func.count(FirmwareUpgradeJob.id))

        if organization_id is not None:
            from app.models.core import Site

            site_sub = (
                select(Site.id).where(Site.organization_id == organization_id).scalar_subquery()
            )
            q = q.where(FirmwareUpgradeJob.site_id.in_(site_sub))
            count_q = count_q.where(FirmwareUpgradeJob.site_id.in_(site_sub))

        # scope to the caller's granted sites.
        grant_clause = _site_grant_clause(FirmwareUpgradeJob.site_id, site_ids)
        if grant_clause is not None:
            q = q.where(grant_clause)
            count_q = count_q.where(grant_clause)

        if status:
            q = q.where(FirmwareUpgradeJob.status == status)
            count_q = count_q.where(FirmwareUpgradeJob.status == status)
        if site_id:
            q = q.where(FirmwareUpgradeJob.site_id == site_id)
            count_q = count_q.where(FirmwareUpgradeJob.site_id == site_id)

        total = (await session.execute(count_q)).scalar() or 0
        offset = (page - 1) * page_size
        q = q.order_by(FirmwareUpgradeJob.created_at.desc()).offset(offset).limit(page_size)
        rows = (await session.execute(q)).scalars().all()

        return {"items": rows, "total": total, "page": page, "page_size": page_size}

    @staticmethod
    async def cancel_job(session: AsyncSession, job_id: UUID) -> Any:
        from app.models.firmware import FirmwareJobStatus

        job = await PersistentFirmwareService.get_job(session, job_id)
        if not job:
            return None
        if job.status not in (FirmwareJobStatus.PENDING, FirmwareJobStatus.RUNNING):
            return job

        job.status = FirmwareJobStatus.CANCELLED
        job.completed_at = datetime.now(UTC)
        await session.flush()
        await session.refresh(job)
        return job

    @staticmethod
    async def retry_job(session: AsyncSession, job_id: UUID, failed_only: bool = True) -> Any:
        """Create a new job that retries failed devices from a previous job."""
        from app.models.firmware import FirmwareJobStatus, FirmwareUpgradeJob

        original = await PersistentFirmwareService.get_job(session, job_id)
        if not original:
            return None

        # Get failed device IDs from the original job
        if failed_only and original.devices:
            retry_ids = [d["device_id"] for d in original.devices if d.get("status") == "failed"]
        else:
            retry_ids = original.device_ids

        if not retry_ids:
            return original  # Nothing to retry

        new_job = FirmwareUpgradeJob(
            status=FirmwareJobStatus.PENDING,
            firmware_id=original.firmware_id,
            firmware_version=original.firmware_version,
            device_ids=retry_ids,
            site_id=original.site_id,
            backup_before=original.backup_before,
            rollback_on_failure=original.rollback_on_failure,
            batch_size=original.batch_size,
            delay_between_batches=original.delay_between_batches,
            notify_on_complete=original.notify_on_complete,
            notify_on_failure=original.notify_on_failure,
            total_devices=len(retry_ids),
            created_by=original.created_by,
        )
        session.add(new_job)
        await session.flush()
        await session.refresh(new_job)
        return new_job

    @staticmethod
    async def run_upgrade_job(session: AsyncSession, job_id: UUID) -> dict[str, Any]:
        """
        Execute a firmware upgrade job. Called by Celery task.
        In production, this would call device adapters to push firmware.
        """
        from app.models.firmware import FirmwareJobStatus

        job = await PersistentFirmwareService.get_job(session, job_id)
        if not job:
            return {"error": "Job not found"}

        # refuse to re-run a job that has already reached a terminal
        # state. Celery with acks_late redelivers the SAME message on worker loss,
        # which would otherwise flip a COMPLETED/CANCELLED job back to RUNNING and
        # accumulate `successful` on top of its prior value (terminal states must
        # be sticky; the executor must be idempotent under redelivery).
        if job.status in (
            FirmwareJobStatus.COMPLETED,
            FirmwareJobStatus.PARTIALLY_FAILED,
            FirmwareJobStatus.FAILED,
            FirmwareJobStatus.CANCELLED,
        ):
            return {
                "job_id": str(job_id),
                "status": job.status,
                "skipped": "already terminal",
            }

        job.status = FirmwareJobStatus.RUNNING
        job.started_at = datetime.now(UTC)
        # Reset counters so a legitimate redelivery of a still-non-terminal job
        # is idempotent rather than additive.
        job.successful = 0
        job.failed = 0
        device_results = []

        for i, device_id in enumerate(job.device_ids):
            # Simulate per-device upgrade
            device_results.append(
                {
                    "device_id": str(device_id),
                    "status": "completed",
                    "started_at": datetime.now(UTC).isoformat(),
                    "completed_at": datetime.now(UTC).isoformat(),
                }
            )
            job.successful += 1
            job.progress = ((i + 1) / job.total_devices) * 100.0
            await session.flush()

        job.devices = device_results
        job.status = (
            FirmwareJobStatus.COMPLETED if job.failed == 0 else FirmwareJobStatus.PARTIALLY_FAILED
        )
        job.completed_at = datetime.now(UTC)
        job.progress = 100.0
        await session.flush()

        return {
            "job_id": str(job_id),
            "status": job.status,
            "successful": job.successful,
            "failed": job.failed,
        }

    # =====================================================================
    # Schedules
    # =====================================================================

    @staticmethod
    def compute_next_run(schedule: Any, *, after: datetime | None = None) -> datetime | None:
        """Next fire time for a firmware schedule, in UTC.

        NOTHING in the codebase ever wrote ``FirmwareSchedule.next_run_at``.
        ``create_schedule`` passes the API payload straight through and the API
        does not collect it; ``update_schedule`` copies fields verbatim;
        ``run_schedule_now`` advanced last_run_at / last_job_id / total_runs and
        left next_run_at alone. So the column was NULL on every row ever
        created.

        The beat task selects ``next_run_at <= now``, and NULL never satisfies
        a comparison. Firmware upgrade schedules have therefore never run --
        not late, not partially: never. The operator configured "upgrade the
        APs Sunday 02:00", the UI listed the schedule as enabled, the
        five-minute checker ran on time and matched zero rows every time.

        ``on_release`` schedules are deliberately excluded: those are meant to
        fire when a new release appears, not on a clock, so a wall-clock
        next_run_at would be wrong rather than merely absent.
        """
        from app.models.firmware import ScheduleFrequency

        frequency = str(getattr(schedule, "frequency", "") or "")
        if frequency == ScheduleFrequency.ON_RELEASE:
            return None

        base = after or datetime.now(UTC)

        # "HH:MM" in the schedule's own timezone; default 02:00, the
        # conventional maintenance hour and what the UI placeholder shows.
        hour, minute = 2, 0
        time_of_day = getattr(schedule, "time_of_day", None)
        if isinstance(time_of_day, str) and ":" in time_of_day:
            try:
                raw_h, raw_m = time_of_day.split(":", 1)
                hour, minute = int(raw_h), int(raw_m)
            except (TypeError, ValueError):
                hour, minute = 2, 0
        hour = max(0, min(23, hour))
        minute = max(0, min(59, minute))

        tz = UTC
        tz_name = getattr(schedule, "timezone", None)
        if tz_name:
            try:
                from zoneinfo import ZoneInfo

                tz = ZoneInfo(str(tz_name))
            except Exception:
                # An unknown tz must not make the schedule unschedulable; UTC
                # is late or early by hours, NULL is never.
                tz = UTC

        local = base.astimezone(tz)
        candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)

        if frequency == ScheduleFrequency.MONTHLY:
            day = getattr(schedule, "day_of_month", None) or 1
            day = max(1, min(28, int(day)))  # 28 keeps every month valid
            candidate = candidate.replace(day=day)
            while candidate <= local:
                month = candidate.month + 1
                year = candidate.year + (month > 12)
                candidate = candidate.replace(year=year, month=(month - 1) % 12 + 1, day=day)
        else:
            # WEEKLY (the default) and anything unrecognised.
            target = getattr(schedule, "day_of_week", None)
            target = 6 if target is None else max(0, min(6, int(target)))  # 0=Mon
            delta = (target - candidate.weekday()) % 7
            candidate += timedelta(days=delta)
            if candidate <= local:
                candidate += timedelta(days=7)

        return candidate.astimezone(UTC)

    @staticmethod
    async def create_schedule(
        session: AsyncSession, data: dict[str, Any], user_id: UUID | None = None
    ) -> Any:
        from app.models.firmware import FirmwareSchedule

        schedule = FirmwareSchedule(**data, created_by=user_id)
        if schedule.next_run_at is None:
            schedule.next_run_at = PersistentFirmwareService.compute_next_run(schedule)
        session.add(schedule)
        await session.flush()
        await session.refresh(schedule)
        return schedule

    @staticmethod
    async def get_schedule(session: AsyncSession, schedule_id: UUID) -> Any:
        from app.models.firmware import FirmwareSchedule

        result = await session.execute(
            select(FirmwareSchedule).where(FirmwareSchedule.id == schedule_id)
        )
        return result.scalars().first()

    @staticmethod
    async def list_schedules(
        session: AsyncSession,
        *,
        site_id: UUID | None = None,
        is_enabled: bool | None = None,
        organization_id: UUID | None = None,
        site_ids: Any = None,
    ) -> list[Any]:
        from app.models.firmware import FirmwareSchedule

        q = select(FirmwareSchedule)
        if organization_id is not None:
            q = q.where(FirmwareSchedule.organization_id == organization_id)
        # scope to the caller's granted sites.
        grant_clause = _site_grant_clause(FirmwareSchedule.site_id, site_ids)
        if grant_clause is not None:
            q = q.where(grant_clause)
        if site_id:
            q = q.where(FirmwareSchedule.site_id == site_id)
        if is_enabled is not None:
            q = q.where(FirmwareSchedule.is_enabled == is_enabled)

        q = q.order_by(FirmwareSchedule.created_at.desc())
        return list((await session.execute(q)).scalars().all())

    @staticmethod
    async def update_schedule(
        session: AsyncSession, schedule_id: UUID, data: dict[str, Any]
    ) -> Any:

        schedule = await PersistentFirmwareService.get_schedule(session, schedule_id)
        if not schedule:
            return None

        timing_fields = {"frequency", "time_of_day", "day_of_week", "day_of_month", "timezone"}
        retimed = any(k in timing_fields for k in data)

        for k, v in data.items():
            if v is not None:
                setattr(schedule, k, v)
        # Moving a schedule from Sunday to Wednesday has to move its next fire
        # time, or the edit is cosmetic. Also recompute when a schedule is
        # re-enabled, since a disabled one may have gone stale.
        if retimed or data.get("is_enabled") is True or schedule.next_run_at is None:
            schedule.next_run_at = PersistentFirmwareService.compute_next_run(schedule)
        schedule.updated_at = datetime.now(UTC)
        await session.flush()
        await session.refresh(schedule)
        return schedule

    @staticmethod
    async def delete_schedule(session: AsyncSession, schedule_id: UUID) -> bool:

        schedule = await PersistentFirmwareService.get_schedule(session, schedule_id)
        if not schedule:
            return False
        await session.delete(schedule)
        await session.flush()
        return True

    @staticmethod
    async def toggle_schedule(session: AsyncSession, schedule_id: UUID) -> Any:

        schedule = await PersistentFirmwareService.get_schedule(session, schedule_id)
        if not schedule:
            return None
        schedule.is_enabled = not schedule.is_enabled
        schedule.updated_at = datetime.now(UTC)
        await session.flush()
        await session.refresh(schedule)
        return schedule

    @staticmethod
    async def run_schedule_now(session: AsyncSession, schedule_id: UUID) -> Any:
        """Trigger an immediate run of a schedule, creating a job."""
        schedule = await PersistentFirmwareService.get_schedule(session, schedule_id)
        if not schedule:
            return None

        job_data = {
            "device_ids": schedule.device_ids or [],
            "site_id": schedule.site_id,
            "backup_before": schedule.backup_before,
            "rollback_on_failure": schedule.rollback_on_failure,
            "batch_size": schedule.batch_size,
            "delay_between_batches": schedule.delay_between_batches,
            "notify_on_complete": schedule.notify_on_complete,
            "notify_on_failure": schedule.notify_on_failure,
        }

        job = await PersistentFirmwareService.create_job(session, job_data, schedule.created_by)

        now = datetime.now(UTC)
        schedule.last_run_at = now
        schedule.last_job_id = job.id
        schedule.total_runs += 1
        # Advance the clock. Without this a schedule that somehow DID have a
        # next_run_at would re-fire on every five-minute tick, which is the
        # opposite failure and worse: a firmware upgrade every five minutes.
        schedule.next_run_at = PersistentFirmwareService.compute_next_run(schedule, after=now)
        await session.flush()

        return job

    # =====================================================================
    # Summary / Dashboard
    # =====================================================================

    @staticmethod
    async def get_summary(
        session: AsyncSession,
        site_id: UUID | None = None,
        organization_id: UUID | None = None,
        site_ids: Any = None,
    ) -> dict[str, Any]:
        from app.models.firmware import (
            DeviceFirmwareStatus,
            FirmwareImage,
            FirmwareJobStatus,
            FirmwareUpgradeJob,
        )

        # Build org-scoped site subquery if organization_id provided
        site_sub = None
        if organization_id is not None:
            from app.models.core import Site

            site_sub = (
                select(Site.id).where(Site.organization_id == organization_id).scalar_subquery()
            )

        # per-user site-grant predicates for the two
        # site-bound aggregate sources (DeviceFirmwareStatus + FirmwareUpgradeJob).
        # ``None`` when the caller is unrestricted. FirmwareImage is org-scoped
        # (no site_id) so its counts are unaffected.
        dev_grant = _site_grant_clause(DeviceFirmwareStatus.site_id, site_ids)
        job_grant = _site_grant_clause(FirmwareUpgradeJob.site_id, site_ids)

        # Device counts
        dev_q = select(func.count(DeviceFirmwareStatus.id))
        if site_sub is not None:
            dev_q = dev_q.where(DeviceFirmwareStatus.site_id.in_(site_sub))
        if dev_grant is not None:
            dev_q = dev_q.where(dev_grant)
        if site_id:
            dev_q = dev_q.where(DeviceFirmwareStatus.site_id == site_id)

        total_devices = (await session.execute(dev_q)).scalar() or 0

        up_to_date_q = dev_q.where(DeviceFirmwareStatus.is_up_to_date.is_(True))
        up_to_date = (await session.execute(up_to_date_q)).scalar() or 0

        update_q = dev_q.where(DeviceFirmwareStatus.update_available.is_(True))
        update_available = (await session.execute(update_q)).scalar() or 0

        critical_q = dev_q.where(DeviceFirmwareStatus.critical_update_available.is_(True))
        critical_updates = (await session.execute(critical_q)).scalar() or 0

        # Firmware image count
        fw_count_q = select(func.count(FirmwareImage.id))
        if organization_id is not None:
            fw_count_q = fw_count_q.where(FirmwareImage.organization_id == organization_id)
        fw_count = (await session.execute(fw_count_q)).scalar() or 0

        # Active and scheduled jobs
        active_q = select(func.count(FirmwareUpgradeJob.id)).where(
            FirmwareUpgradeJob.status.in_([FirmwareJobStatus.PENDING, FirmwareJobStatus.RUNNING])
        )
        if site_sub is not None:
            active_q = active_q.where(FirmwareUpgradeJob.site_id.in_(site_sub))
        if job_grant is not None:
            active_q = active_q.where(job_grant)
        active_jobs = (await session.execute(active_q)).scalar() or 0

        scheduled_q = select(func.count(FirmwareUpgradeJob.id)).where(
            FirmwareUpgradeJob.status == FirmwareJobStatus.PENDING,
            FirmwareUpgradeJob.scheduled_at.isnot(None),
        )
        if site_sub is not None:
            scheduled_q = scheduled_q.where(FirmwareUpgradeJob.site_id.in_(site_sub))
        if job_grant is not None:
            scheduled_q = scheduled_q.where(job_grant)
        scheduled_jobs = (await session.execute(scheduled_q)).scalar() or 0

        # Vendor breakdown
        vendor_q = select(
            DeviceFirmwareStatus.vendor,
            func.count(DeviceFirmwareStatus.id),
        ).group_by(DeviceFirmwareStatus.vendor)
        if site_sub is not None:
            vendor_q = vendor_q.where(DeviceFirmwareStatus.site_id.in_(site_sub))
        if dev_grant is not None:
            vendor_q = vendor_q.where(dev_grant)
        vendor_rows = (await session.execute(vendor_q)).all()
        by_vendor = {r[0] or "Unknown": r[1] for r in vendor_rows}

        # Device type breakdown
        type_q = select(
            DeviceFirmwareStatus.device_type,
            func.count(DeviceFirmwareStatus.id),
        ).group_by(DeviceFirmwareStatus.device_type)
        if site_sub is not None:
            type_q = type_q.where(DeviceFirmwareStatus.site_id.in_(site_sub))
        if dev_grant is not None:
            type_q = type_q.where(dev_grant)
        type_rows = (await session.execute(type_q)).all()
        by_device_type = {r[0] or "Unknown": r[1] for r in type_rows}

        # Recent upgrades (last 10 completed jobs)
        recent_q = (
            select(FirmwareUpgradeJob)
            .where(FirmwareUpgradeJob.status == FirmwareJobStatus.COMPLETED)
            .order_by(FirmwareUpgradeJob.completed_at.desc())
            .limit(10)
        )
        if site_sub is not None:
            recent_q = recent_q.where(FirmwareUpgradeJob.site_id.in_(site_sub))
        if job_grant is not None:
            recent_q = recent_q.where(job_grant)
        recent_jobs = (await session.execute(recent_q)).scalars().all()
        recent_upgrades = [
            {
                "id": str(j.id),
                "firmware_version": j.firmware_version,
                "total_devices": j.total_devices,
                "successful": j.successful,
                "failed": j.failed,
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            }
            for j in recent_jobs
        ]

        # Repo stats
        total_size_q = select(func.sum(FirmwareImage.file_size_bytes))
        if organization_id is not None:
            total_size_q = total_size_q.where(FirmwareImage.organization_id == organization_id)
        total_size = (await session.execute(total_size_q)).scalar() or 0

        return {
            "total_devices": total_devices,
            "up_to_date": up_to_date,
            "update_available": update_available,
            "critical_updates": critical_updates,
            "total_firmware_images": fw_count,
            "active_jobs": active_jobs,
            "scheduled_jobs": scheduled_jobs,
            "by_vendor": by_vendor,
            "by_device_type": by_device_type,
            "recent_upgrades": recent_upgrades,
            "repo_stats": {
                "total_images": fw_count,
                "total_size_bytes": total_size,
            },
        }
