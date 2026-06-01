# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device Adoption Tasks
====================================

Celery tasks for executing the ZTP adoption pipeline.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.models.ztp import AdoptionJob, AdoptionJobStatus
from app.services.ztp import AdoptionOrchestrator

logger = logging.getLogger(__name__)

MAX_RETRY_COUNT = 3


@celery_app.task(
    bind=True, max_retries=2, name="adoption.execute", soft_time_limit=300, time_limit=360
)
def execute_adoption(self, job_id: str) -> dict[str, Any]:
    """Run AdoptionOrchestrator for a specific adoption job."""
    try:
        return asyncio.run(_execute_adoption(job_id))
    except Exception as e:
        logger.exception("Adoption task failed for job %s", job_id)
        raise self.retry(exc=e, countdown=60)


async def _execute_adoption(job_id: str) -> dict[str, Any]:
    """Execute the adoption pipeline."""
    from uuid import UUID as _UUID

    async with AsyncSessionLocal() as session:
        try:
            orchestrator = AdoptionOrchestrator()
            result = await orchestrator.execute(_UUID(job_id), session)
            if result.get("success"):
                await session.commit()
            else:
                await session.rollback()
            return result
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name="adoption.retry_failed", soft_time_limit=120, time_limit=180)
def retry_failed_adoptions() -> dict[str, Any]:
    """Periodic: retry failed adoption jobs (up to max retries)."""
    return asyncio.run(_retry_failed_adoptions())


async def _retry_failed_adoptions() -> dict[str, Any]:
    """Find failed adoption jobs and retry them."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdoptionJob)
            .where(
                AdoptionJob.status == AdoptionJobStatus.FAILED,
                AdoptionJob.retry_count < MAX_RETRY_COUNT,
            )
            .limit(100)
            .with_for_update(skip_locked=True)
        )
        failed_jobs = result.scalars().all()

        retried = 0
        for job in failed_jobs:
            job.status = AdoptionJobStatus.PENDING
            job.retry_count += 1
            job.error_message = None
            job.started_at = datetime.now(UTC)
            job.completed_at = None
            retried += 1

        await session.commit()

        # Dispatch retry tasks
        for job in failed_jobs:
            execute_adoption.delay(str(job.id))

        return {
            "success": True,
            "retried": retried,
        }
