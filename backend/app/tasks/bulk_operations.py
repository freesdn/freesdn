# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Bulk Operations Tasks
=====================================

Celery tasks for executing bulk operations:
  - push_config: Push config to multiple devices
  - reboot: Reboot multiple devices
  - firmware_update: Stage firmware updates

Supports staged rollouts with automatic rollback on failure.
"""

import asyncio
import logging
import time
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.models.devices import Device
from app.models.enterprise import (
    BulkOperation,
    BulkOperationStatus,
    LifecycleState,
)
from app.services.enterprise import (
    BulkOperationService,
    TemplateResolver,
)

logger = logging.getLogger("freesdn.tasks.bulk_operations")


# ==========================================================================
# Resolve target device IDs from a bulk target specification
# ==========================================================================


async def _resolve_device_ids(db: AsyncSession, target: dict[str, Any], org_id: UUID) -> list[UUID]:
    """
    Resolve a BulkTarget spec to a concrete list of device UUIDs.

    Supported scopes:
      - site:         all managed devices in a site
      - device_group: all managed devices in a device group
      - tag:          all managed devices with a specific tag
      - device_list:  explicit list of device IDs
    """
    from app.models.core import Site
    from app.models.enterprise import DeviceGroup, DeviceGroupMembership, DeviceTag

    scope = target.get("scope")
    scope_id = target.get("scope_id")
    device_ids_raw = target.get("device_ids", [])
    tag = target.get("tag")
    device_type = target.get("device_type")

    conditions = [
        Device.lifecycle_state == LifecycleState.MANAGED,
        Device.deleted_at == None,  # noqa: E711
    ]
    if device_type:
        conditions.append(Device.device_type == device_type)

    if scope == "device_list" and device_ids_raw:
        requested_ids = [UUID(d) if isinstance(d, str) else d for d in device_ids_raw]
        result = await db.execute(
            select(Device.id)
            .join(Site, Device.site_id == Site.id)
            .where(
                Device.id.in_(requested_ids),
                Site.organization_id == org_id,
                *conditions,
            )
        )
        return [row[0] for row in result.all()]

    if scope == "site":
        result = await db.execute(
            select(Device.id)
            .join(Site, Device.site_id == Site.id)
            .where(
                Site.id == UUID(str(scope_id)),
                Site.organization_id == org_id,
                *conditions,
            )
        )
        return [row[0] for row in result.all()]

    elif scope == "device_group":
        result = await db.execute(
            select(Device.id)
            .join(DeviceGroupMembership, DeviceGroupMembership.device_id == Device.id)
            .join(DeviceGroup, DeviceGroupMembership.group_id == DeviceGroup.id)
            .join(Site, Device.site_id == Site.id)
            .where(
                DeviceGroupMembership.group_id == UUID(str(scope_id)),
                DeviceGroup.organization_id == org_id,
                Site.organization_id == org_id,
                *conditions,
            )
        )
        return [row[0] for row in result.all()]

    elif scope == "tag":
        result = await db.execute(
            select(Device.id)
            .join(DeviceTag, DeviceTag.device_id == Device.id)
            .join(Site, Device.site_id == Site.id)
            .where(
                DeviceTag.tag == tag,
                Site.organization_id == org_id,
                *conditions,
            )
        )
        return [row[0] for row in result.all()]

    return []


# ==========================================================================
# Execute bulk operation
# ==========================================================================


@celery_app.task(  # type: ignore[untyped-decorator]
    name="bulk_operations.execute",
    bind=True,
    max_retries=0,
    queue="sync",
    soft_time_limit=600,
    time_limit=720,
)
def execute_bulk_operation(
    self: Any,
    job_id: str,
    triggered_by_user_id: str | None = None,
    required_permission: str | None = None,
) -> None:
    """
    Execute a bulk operation job.

    Handles staged rollouts: processes devices in stages based on the
    rollout strategy, pausing between stages and checking failure thresholds
    for automatic rollback.

    ``triggered_by_user_id`` and ``required_permission`` let the
    task re-verify the submitter still holds the permission on every target
    site at execution time (guarding against permissions being revoked
    between queue submission and execution).
    """
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            _execute_bulk_operation(
                job_id,
                triggered_by_user_id=triggered_by_user_id,
                required_permission=required_permission,
            )
        )
    except Exception as e:
        logger.exception("Bulk operation %s crashed: %s", job_id, e)
    finally:
        loop.close()


async def _load_user_for_authz(
    db: AsyncSession,
    user_id: UUID,
) -> Any | None:
    """Load the triggering user + their site access rows for re-auth checks."""
    from app.core.dependencies import CurrentUser, _load_user_permissions
    from app.models import User

    result = await db.execute(
        select(User)
        .options(selectinload(User.site_access))
        .where(User.id == user_id, User.deleted_at == None)  # noqa: E711
    )
    user_obj = result.scalar_one_or_none()
    if user_obj is None or not user_obj.is_active:
        return None

    perms = await _load_user_permissions(user_obj)
    site_accesses = (
        user_obj.site_access if hasattr(user_obj, "site_access") and user_obj.site_access else []
    )
    return CurrentUser(
        user=user_obj,
        permissions=perms,
        accessible_site_ids={sa.site_id for sa in site_accesses},
        site_access_levels={sa.site_id: sa.access_level for sa in site_accesses},
    )


async def _execute_bulk_operation(
    job_id: str,
    triggered_by_user_id: str | None = None,
    required_permission: str | None = None,
) -> None:
    """Async implementation of the bulk operation executor."""
    async with AsyncSessionLocal() as db:
        svc = BulkOperationService(db)
        # Use SELECT ... FOR UPDATE to prevent concurrent execution of same job
        from sqlalchemy import select as sa_select

        from app.models.enterprise import BulkOperation

        result = await db.execute(
            sa_select(BulkOperation)
            .where(BulkOperation.id == UUID(job_id))
            .with_for_update(skip_locked=True)
        )
        job = result.scalar_one_or_none()
        if not job:
            logger.error("Bulk operation %s not found or locked by another worker", job_id)
            return

        if job.status != BulkOperationStatus.PENDING:
            logger.warning("Bulk operation %s is not pending (status=%s)", job_id, job.status)
            return

        # resolve the submitting user (if recorded) so we can
        # re-check site-level permission for each device at execution time.
        authz_user: Any | None = None
        if triggered_by_user_id and required_permission:
            try:
                authz_user = await _load_user_for_authz(db, UUID(triggered_by_user_id))
            except Exception:
                logger.exception(
                    "Bulk op %s: failed to load triggering user %s for re-auth",
                    job_id,
                    triggered_by_user_id,
                )
                authz_user = None
            if authz_user is None:
                logger.warning(
                    "Bulk op %s: triggering user %s is no longer valid — aborting",
                    job_id,
                    triggered_by_user_id,
                )
                await svc.complete_job(
                    job,
                    BulkOperationStatus.FAILED,
                    error_message="Triggering user revoked or deleted",
                )
                return

        # Resolve device IDs
        device_ids = await _resolve_device_ids(db, job.target, job.organization_id)
        job.devices_total = len(device_ids)
        job = await svc.start_job(job)

        if not device_ids:
            await svc.complete_job(job, BulkOperationStatus.COMPLETED)
            return

        strategy = job.rollout_strategy or {}
        stages = strategy.get("stages", [])
        is_staged = strategy.get("strategy") == "staged" and stages

        if is_staged:
            await _execute_staged(
                db,
                svc,
                job,
                device_ids,
                stages,
                authz_user=authz_user,
                required_permission=required_permission,
            )
        else:
            await _execute_immediate(
                db,
                svc,
                job,
                device_ids,
                authz_user=authz_user,
                required_permission=required_permission,
            )


async def _execute_immediate(
    db: AsyncSession,
    svc: BulkOperationService,
    job: BulkOperation,
    device_ids: list[UUID],
    authz_user: Any | None = None,
    required_permission: str | None = None,
) -> None:
    """Execute all devices at once (no staging)."""
    for device_id in device_ids:
        if svc.should_rollback(job):
            logger.warning("Bulk operation %s: failure threshold exceeded, stopping", job.id)
            await svc.complete_job(
                job,
                BulkOperationStatus.FAILED,
                error_message="Failure threshold exceeded",
            )
            return

        await _execute_on_device(
            db,
            svc,
            job,
            device_id,
            authz_user=authz_user,
            required_permission=required_permission,
        )

    final_status = (
        BulkOperationStatus.COMPLETED if job.devices_failed == 0 else BulkOperationStatus.FAILED
    )
    await svc.complete_job(job, final_status)


async def _execute_staged(
    db: AsyncSession,
    svc: BulkOperationService,
    job: BulkOperation,
    device_ids: list[UUID],
    stages: list[dict[str, Any]],
    authz_user: Any | None = None,
    required_permission: str | None = None,
) -> None:
    """Execute in stages with wait periods between stages."""
    processed = 0

    for stage_idx, stage in enumerate(stages):
        job.current_stage = stage_idx
        await db.commit()

        count = svc.get_stage_device_count(job, stage_idx)
        stage_devices = device_ids[processed : processed + count]
        wait_minutes = stage.get("wait_minutes", 0)

        logger.info(
            "Bulk operation %s: stage %d — processing %d devices",
            job.id,
            stage_idx + 1,
            len(stage_devices),
        )

        for device_id in stage_devices:
            if svc.should_rollback(job):
                logger.warning(
                    "Bulk operation %s: failure threshold exceeded at stage %d",
                    job.id,
                    stage_idx + 1,
                )
                await svc.complete_job(
                    job,
                    BulkOperationStatus.FAILED,
                    error_message=f"Failure threshold exceeded at stage {stage_idx + 1}",
                )
                return

            await _execute_on_device(
                db,
                svc,
                job,
                device_id,
                authz_user=authz_user,
                required_permission=required_permission,
            )

        processed += len(stage_devices)

        # Wait between stages (skip on last stage)
        if stage_idx < len(stages) - 1 and wait_minutes > 0:
            logger.info(
                "Bulk operation %s: waiting %d minutes before next stage",
                job.id,
                wait_minutes,
            )
            await asyncio.sleep(wait_minutes * 60)

    # Process any remaining devices not covered by stages
    if processed < len(device_ids):
        remaining = device_ids[processed:]
        for device_id in remaining:
            await _execute_on_device(
                db,
                svc,
                job,
                device_id,
                authz_user=authz_user,
                required_permission=required_permission,
            )

    final_status = (
        BulkOperationStatus.COMPLETED if job.devices_failed == 0 else BulkOperationStatus.FAILED
    )
    await svc.complete_job(job, final_status)


async def _execute_on_device(
    db: AsyncSession,
    svc: BulkOperationService,
    job: BulkOperation,
    device_id: UUID,
    authz_user: Any | None = None,
    required_permission: str | None = None,
) -> None:
    """Execute the bulk operation on a single device."""
    start = time.monotonic()
    try:
        result = await db.execute(
            select(Device).options(selectinload(Device.site)).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()
        if not device:
            await svc.record_device_result(job, device_id, "skipped", error="Device not found")
            return

        if not device.site or device.site.organization_id != job.organization_id:
            await svc.record_device_result(
                job,
                device_id,
                "skipped",
                error="Device outside organization scope",
            )
            return

        # re-check site-level permission at execution time in case
        # the triggering user's permissions or site access changed between
        # queueing and execution.
        if authz_user is not None and required_permission:
            if not authz_user.has_site_permission(required_permission, site_id=device.site_id):
                logger.warning(
                    "Bulk op %s: permission %s revoked for user %s on site %s — skipping device %s",
                    job.id,
                    required_permission,
                    authz_user.id,
                    device.site_id,
                    device_id,
                )
                await svc.record_device_result(
                    job,
                    device_id,
                    "skipped",
                    error="permission_revoked",
                )
                return

        if job.operation == "push_config":
            await _push_config_to_device(db, device, job.config)
        elif job.operation == "reboot":
            await _reboot_device(device)
        elif job.operation == "firmware_update":
            await _firmware_update_device(device, job.config)
        else:
            await svc.record_device_result(
                job,
                device_id,
                "skipped",
                error=f"Unknown operation: {job.operation}",
            )
            return

        duration_ms = int((time.monotonic() - start) * 1000)
        await svc.record_device_result(job, device_id, "success", duration_ms=duration_ms)

    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.error(
            "Bulk operation %s failed on device %s: %s",
            job.id,
            device_id,
            exc,
        )
        await svc.record_device_result(
            job,
            device_id,
            "failed",
            error=str(exc),
            duration_ms=duration_ms,
        )


# ==========================================================================
# Per-operation executors
# ==========================================================================


async def _push_config_to_device(
    db: AsyncSession, device: Device, config: dict[str, Any] | None
) -> None:
    """Push resolved config to a single device via its adapter."""
    from app.adapters import adapter_factory  # type: ignore[attr-defined]

    resolver = TemplateResolver(db)
    desired = await resolver.resolve(device)

    # Merge explicit config payload if provided
    if config:
        from app.services.enterprise import deep_merge

        desired = deep_merge(desired, config)

    adapter = await adapter_factory(device)
    async with adapter:
        running = await adapter.get_running_config()
        normalized_desired = adapter.normalize_config(desired)
        diff = adapter.diff_config(running, normalized_desired)

        if diff:
            await adapter.push_full_config(normalized_desired)
            logger.info("Config pushed to device %s (%d changes)", device.id, len(diff))
        else:
            logger.info("Device %s already compliant", device.id)


async def _reboot_device(device: Device) -> None:
    """Reboot a device via its adapter."""
    from app.adapters import adapter_factory  # type: ignore[attr-defined]

    adapter = await adapter_factory(device)
    async with adapter:
        if hasattr(adapter, "reboot"):
            await adapter.reboot()
            logger.info("Reboot sent to device %s", device.id)
        else:
            raise NotImplementedError(f"Adapter for {device.model} does not support reboot")


async def _firmware_update_device(device: Device, config: dict[str, Any] | None) -> None:
    """Trigger firmware update on a device via its adapter."""
    from app.adapters import adapter_factory  # type: ignore[attr-defined]

    firmware_url = (config or {}).get("firmware_url")
    firmware_version = (config or {}).get("firmware_version")

    if not firmware_url:
        raise ValueError("firmware_url is required for firmware_update operation")

    adapter = await adapter_factory(device)
    async with adapter:
        if hasattr(adapter, "firmware_update"):
            await adapter.firmware_update(firmware_url, firmware_version)
            logger.info("Firmware update triggered for device %s", device.id)
        else:
            raise NotImplementedError(
                f"Adapter for {device.model} does not support firmware updates"
            )
