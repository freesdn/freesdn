# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Enterprise Reconciliation Tasks
===============================================

Periodic Celery tasks for:
  - Config reconciliation loop (desired vs running drift detection)
  - Health score recomputation
"""

import asyncio
import logging
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import selectinload

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.models.devices import Device
from app.models.enterprise import (
    DeviceConfig,
    DeviceHealth,
    HealthDailySnapshot,
    HealthStatus,
    LifecycleState,
)
from app.services.enterprise import HealthService, TemplateResolver

logger = logging.getLogger("freesdn.tasks.reconciliation")


# ==========================================================================
# Config Reconciliation
# ==========================================================================


async def _reconcile_device(device_id: str) -> dict[str, Any]:
    """Reconcile a single device's config (desired vs running)."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Device)
            .options(
                selectinload(Device.controller),
                selectinload(Device.site),
            )
            .where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()

        if not device:
            return {"success": False, "error": f"Device {device_id} not found"}

        if device.lifecycle_state not in (
            LifecycleState.MANAGED.value,
            LifecycleState.UPDATING.value,
        ):
            return {
                "success": True,
                "skipped": True,
                "reason": f"Device lifecycle is '{device.lifecycle_state}', skipping",
            }

        # Get or create device config
        dc_result = await session.execute(
            select(DeviceConfig).where(DeviceConfig.device_id == device.id)
        )
        dc = dc_result.scalar_one_or_none()

        if not dc:
            return {
                "success": True,
                "skipped": True,
                "reason": "No device config record — not yet provisioned",
            }

        try:
            # Resolve desired config from template hierarchy
            resolver = TemplateResolver(session)
            desired = await resolver.resolve(device)

            # Update desired_config on the record
            dc.desired_config = desired

            # For now, we can't read the actual running config without an
            # adapter connection, so compare desired vs pushed.
            # Full adapter-based reconciliation happens in reconcile_site.
            if dc.pushed_config and dc.pushed_config != desired:
                dc.has_drift = True
                dc.drift_details = {
                    "type": "desired_ahead_of_pushed",
                    "detected_at": datetime.now(UTC).isoformat(),
                }
            elif dc.running_config and dc.running_config != dc.pushed_config:
                dc.has_drift = True
                dc.drift_details = {
                    "type": "running_drifted_from_pushed",
                    "detected_at": datetime.now(UTC).isoformat(),
                }
            else:
                dc.has_drift = False
                dc.drift_details = None

            await session.commit()

            return {
                "success": True,
                "device_id": str(device.id),
                "has_drift": dc.has_drift,
            }

        except Exception as exc:
            logger.exception("Reconciliation error for device %s", device_id)
            await session.rollback()
            return {"success": False, "error": str(exc)}


@celery_app.task(
    name="app.tasks.reconciliation.reconcile_device",
    bind=True,
    max_retries=2,
    soft_time_limit=60,
)
def reconcile_device(self: Any, device_id: str) -> dict[str, Any]:
    """Celery task: reconcile a single device."""
    return asyncio.run(_reconcile_device(device_id))


async def _reconcile_all_devices() -> dict[str, Any]:
    """Fan-out reconciliation for all managed devices."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Device.id).where(
                Device.lifecycle_state.in_(
                    [
                        LifecycleState.MANAGED.value,
                        LifecycleState.UPDATING.value,
                    ]
                )
            )
        )
        device_ids = [str(row[0]) for row in result.all()]

    dispatched = 0
    for device_id in device_ids:
        reconcile_device.apply_async(
            args=[device_id],
            queue="sync",
        )
        dispatched += 1

    logger.info("Reconciliation fan-out: dispatched %d device tasks", dispatched)
    return {"dispatched": dispatched}


@celery_app.task(
    name="app.tasks.reconciliation.reconcile_all_devices",
    bind=True,
    soft_time_limit=120,
)
def reconcile_all_devices(self: Any) -> dict[str, Any]:
    """Celery task: fan-out reconciliation to all managed devices."""
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    if not acquire_solo_lock("reconcile_all_devices", ttl_seconds=120):
        return {"skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_reconcile_all_devices())
    finally:
        release_solo_lock("reconcile_all_devices")


# ==========================================================================
# Health Score Recomputation
# ==========================================================================


async def _recompute_device_health(device_id: str) -> dict[str, Any]:
    """Recompute health score for a single device."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Device).options(selectinload(Device.site)).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()

        if not device:
            return {"success": False, "error": f"Device {device_id} not found"}

        # Get device config for drift info
        dc_result = await session.execute(
            select(DeviceConfig).where(DeviceConfig.device_id == device.id)
        )
        dc = dc_result.scalar_one_or_none()

        try:
            health_svc = HealthService(session)

            scores = {
                "reachability_score": HealthService.score_reachability(device.status == "online"),
                "drift_score": HealthService.score_drift(dc.has_drift if dc else False),
                # Latency, utilization, firmware, error_rate can be sourced
                # from metrics collection tasks — use defaults for now
                "latency_score": None,
                "utilization_score": None,
                "firmware_score": HealthService.score_firmware(True),
                "error_score": 100,
            }

            health = await health_svc.compute_device_health(device, **scores)
            await session.commit()

            return {
                "success": True,
                "device_id": str(device.id),
                "health_score": health.health_score,
                "health_status": health.health_status,
            }

        except Exception as exc:
            logger.exception("Health computation error for device %s", device_id)
            await session.rollback()
            return {"success": False, "error": str(exc)}


@celery_app.task(
    name="app.tasks.reconciliation.recompute_device_health",
    bind=True,
    max_retries=2,
    soft_time_limit=30,
)
def recompute_device_health(self: Any, device_id: str) -> dict[str, Any]:
    """Celery task: recompute health score for a single device."""
    return asyncio.run(_recompute_device_health(device_id))


async def _recompute_all_health() -> dict[str, Any]:
    """Fan-out health recomputation for all managed devices."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Device.id).where(
                Device.lifecycle_state.in_(
                    [
                        LifecycleState.MANAGED.value,
                        LifecycleState.UPDATING.value,
                    ]
                )
            )
        )
        device_ids = [str(row[0]) for row in result.all()]

    dispatched = 0
    for device_id in device_ids:
        recompute_device_health.apply_async(
            args=[device_id],
            queue="metrics",
        )
        dispatched += 1

    logger.info("Health recomputation fan-out: dispatched %d tasks", dispatched)
    return {"dispatched": dispatched}


@celery_app.task(
    name="app.tasks.reconciliation.recompute_all_health",
    bind=True,
    soft_time_limit=120,
)
def recompute_all_health(self: Any) -> dict[str, Any]:
    """Celery task: fan-out health recomputation to all managed devices."""
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    if not acquire_solo_lock("recompute_all_health", ttl_seconds=120):
        return {"skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_recompute_all_health())
    finally:
        release_solo_lock("recompute_all_health")


# ==========================================================================
# Health Daily Snapshots (nightly aggregation)
# ==========================================================================


async def _snapshot_daily_health() -> dict[str, Any]:
    """Aggregate current DeviceHealth into daily snapshots per (org, site)."""
    today = date.today()

    async with AsyncSessionLocal() as session:
        # Group by (organization_id, site_id) and compute aggregates
        result = await session.execute(
            select(
                DeviceHealth.organization_id,
                DeviceHealth.site_id,
                func.avg(DeviceHealth.health_score).label("avg_score"),
                func.count(DeviceHealth.device_id).label("device_count"),
                func.count()
                .filter(DeviceHealth.health_status == HealthStatus.HEALTHY)
                .label("healthy_count"),
                func.count()
                .filter(DeviceHealth.health_status == HealthStatus.WARNING)
                .label("warning_count"),
                func.count()
                .filter(DeviceHealth.health_status == HealthStatus.DEGRADED)
                .label("degraded_count"),
                func.count()
                .filter(DeviceHealth.health_status == HealthStatus.CRITICAL)
                .label("critical_count"),
            ).group_by(DeviceHealth.organization_id, DeviceHealth.site_id)
        )
        rows = result.all()

        upserted = 0
        for row in rows:
            # Skip rows with NULL site_id — org-wide aggregates can be
            # computed at query time from per-site rows.  NULL != NULL in
            # unique indexes, so these would duplicate on every run.
            if row.site_id is None:
                continue

            values = {
                "organization_id": row.organization_id,
                "site_id": row.site_id,
                "snapshot_date": today,
                "avg_health_score": round(float(row.avg_score or 0), 1),
                "device_count": row.device_count,
                "healthy_count": row.healthy_count,
                "warning_count": row.warning_count,
                "degraded_count": row.degraded_count,
                "critical_count": row.critical_count,
            }
            stmt = pg_insert(HealthDailySnapshot).values(**values)
            stmt = stmt.on_conflict_do_update(
                index_elements=["organization_id", "site_id", "snapshot_date"],
                set_={
                    "avg_health_score": stmt.excluded.avg_health_score,
                    "device_count": stmt.excluded.device_count,
                    "healthy_count": stmt.excluded.healthy_count,
                    "warning_count": stmt.excluded.warning_count,
                    "degraded_count": stmt.excluded.degraded_count,
                    "critical_count": stmt.excluded.critical_count,
                },
            )
            await session.execute(stmt)
            upserted += 1

        await session.commit()

    logger.info("Health daily snapshot: upserted %d rows for %s", upserted, today)
    return {"upserted": upserted, "date": str(today)}


@celery_app.task(
    name="app.tasks.reconciliation.snapshot_daily_health",
    bind=True,
    soft_time_limit=300,
)
def snapshot_daily_health(self: Any) -> dict[str, Any]:
    """Celery task: nightly health snapshot aggregation."""
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    if not acquire_solo_lock("snapshot_daily_health", ttl_seconds=300):
        return {"skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_snapshot_daily_health())
    finally:
        release_solo_lock("snapshot_daily_health")
