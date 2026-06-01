# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Firmware Management Celery Tasks
================================================

Background tasks for firmware operations:
- run_firmware_upgrade: Execute upgrade job
- check_scheduled_upgrades: Check and trigger scheduled upgrades
- refresh_device_firmware_status: Update device firmware status
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True, base=FreeSDNTask, name="firmware.run_upgrade", soft_time_limit=600, time_limit=720
)
def run_firmware_upgrade(self, job_id: str) -> dict[str, Any]:
    """
    Execute a firmware upgrade job in the background.
    """

    async def _run() -> dict[str, Any]:
        from uuid import UUID

        from app.services.firmware import PersistentFirmwareService as svc

        async with AsyncSessionLocal() as session:
            try:
                result = await svc.run_upgrade_job(session, UUID(job_id))
                await session.commit()
                logger.info("Firmware upgrade job %s completed: %s", job_id, result)
                return result
            except Exception as e:
                await session.rollback()
                logger.error("Firmware upgrade job %s failed: %s", job_id, e)
                return {"success": False, "error": str(e)}

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="firmware.check_scheduled",
    soft_time_limit=120,
    time_limit=180,
)
def check_scheduled_upgrades(self) -> dict[str, Any]:
    """
    Check for scheduled firmware upgrades that are due to run.
    Runs every 5 minutes.
    """

    async def _run() -> dict[str, Any]:
        from sqlalchemy import select

        from app.models.firmware import FirmwareSchedule

        async with AsyncSessionLocal() as session:
            now = datetime.now(UTC)

            # Find enabled schedules that are due
            q = select(FirmwareSchedule).where(
                FirmwareSchedule.is_enabled.is_(True),
                FirmwareSchedule.next_run_at <= now,
            )
            schedules = (await session.execute(q)).scalars().all()

            triggered = 0
            for schedule in schedules:
                try:
                    from app.services.firmware import PersistentFirmwareService as svc

                    job = await svc.run_schedule_now(session, schedule.id)
                    if job:
                        triggered += 1
                        # Dispatch the upgrade task
                        run_firmware_upgrade.delay(str(job.id))
                except Exception as e:
                    logger.error("Failed to trigger schedule %s: %s", schedule.id, e)

            await session.commit()
            return {"checked": len(schedules), "triggered": triggered}

    return asyncio.run(_run())


@celery_app.task(
    bind=True, base=FreeSDNTask, name="firmware.refresh_status", soft_time_limit=120, time_limit=180
)
def refresh_device_firmware_status(self) -> dict[str, Any]:
    """
    Refresh all device firmware statuses.
    Runs every hour.
    """

    async def _run() -> dict[str, Any]:
        from app.services.firmware import PersistentFirmwareService as svc

        async with AsyncSessionLocal() as session:
            try:
                result = await svc.check_updates(session)
                await session.commit()
                logger.info("Firmware status refresh: %s", result)
                return result
            except Exception as e:
                await session.rollback()
                logger.error("Firmware status refresh failed: %s", e)
                return {"error": str(e)}

    return asyncio.run(_run())
