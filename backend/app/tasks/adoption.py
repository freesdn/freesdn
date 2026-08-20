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


async def _record_terminal_failure(job_id: str, error: str) -> None:
    """Persist a job's FAILED state in its own transaction.

    ``AdoptionOrchestrator._fail_job`` sets status/error_message/completed_at
    and then ``flush()``es -- it never commits, because the caller owns the
    transaction. The caller then rolled the whole thing back, which is right for
    the pipeline's partial device writes and wrong for the verdict: the FAILED
    status went with it and the row stayed PENDING.

    That mattered because PENDING is a work queue. ``sync_controller`` selects
    every AdoptionJob in PENDING for its controller and dispatches
    ``execute_adoption`` for each, on every sync. So a job that failed was
    re-run in full -- validate, provision, configure, the whole pipeline,
    against real hardware -- on every single sync cycle, forever.

    And it bypassed the designed backstop entirely: ``retry_failed_adoptions``
    only looks at FAILED jobs and honours MAX_RETRY_COUNT. A job that never
    reaches FAILED is never counted, so the cap it enforces never applied.

    The UPDATE is guarded on ``status == PENDING`` so this cannot clobber a job
    another worker has since claimed, and cannot re-fail one that the "job is
    not in pending state" branch already declined to touch.
    """
    from uuid import UUID as _UUID

    from sqlalchemy import update as _update

    try:
        async with AsyncSessionLocal() as session:
            await session.execute(
                _update(AdoptionJob)
                .where(
                    AdoptionJob.id == _UUID(job_id),
                    AdoptionJob.status == AdoptionJobStatus.PENDING,
                )
                .values(
                    status=AdoptionJobStatus.FAILED,
                    error_message=(error or "Adoption failed")[:2000],
                    completed_at=datetime.now(UTC),
                )
            )
            await session.commit()
    except Exception:
        # Best-effort: never let the bookkeeping write mask the real failure.
        logger.warning(
            "Could not record terminal failure for adoption job %s", job_id, exc_info=True
        )


async def _execute_adoption(job_id: str) -> dict[str, Any]:
    """Execute the adoption pipeline."""
    from uuid import UUID as _UUID

    async with AsyncSessionLocal() as session:
        try:
            orchestrator = AdoptionOrchestrator()
            result = await orchestrator.execute(_UUID(job_id), session)
            if result.get("success"):
                await session.commit()
                return result
            await session.rollback()
        except Exception as exc:
            await session.rollback()
            await _record_terminal_failure(job_id, str(exc))
            raise

    # Rolled back the pipeline's partial work; now record the verdict, so the
    # job leaves the PENDING work queue instead of being re-dispatched forever.
    await _record_terminal_failure(job_id, str(result.get("error") or "Adoption failed"))
    return result


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
