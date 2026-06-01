# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SLA Monitoring Tasks
====================================

Periodic Celery tasks for:
  - Evaluating SLA policies against health scores
  - Recording compliance snapshots
"""

import asyncio
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.services.sla import SLAMonitoringService

logger = logging.getLogger("freesdn.tasks.sla")


# ==========================================================================
# SLA Evaluation
# ==========================================================================


async def _evaluate_sla_for_org(organization_id: str) -> dict[str, Any]:
    """Evaluate all SLA policies for a single organization."""
    async with AsyncSessionLocal() as session:
        service = SLAMonitoringService(session)
        try:
            result = await service.evaluate_all_policies(UUID(organization_id))
            logger.info(
                "SLA evaluation for org %s: %d policies, %d breaches created, %d resolved",
                organization_id,
                result["policies_evaluated"],
                result["breaches_created"],
                result["breaches_resolved"],
            )
            return result
        except Exception as exc:
            logger.exception("SLA evaluation error for org %s", organization_id)
            await session.rollback()
            return {"success": False, "error": str(exc)}


@celery_app.task(
    name="app.tasks.sla.evaluate_sla_policies",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
)
def evaluate_sla_policies(self, organization_id: str) -> dict[str, Any]:
    """Celery task: evaluate SLA policies for one organization."""
    return asyncio.run(_evaluate_sla_for_org(organization_id))


async def _evaluate_all_orgs() -> dict[str, Any]:
    """Fan-out SLA evaluation only to orgs that have SLA policies.

    Previously fanned out one task per org every cycle (incl. ~all empty
    fixture orgs), flooding the worker. Scope to orgs with ≥1 SLA policy.
    """
    from app.models.sla import SLAPolicy

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(SLAPolicy.organization_id).distinct())
        org_ids = [str(row[0]) for row in result.all() if row[0]]

    dispatched = 0
    for org_id in org_ids:
        evaluate_sla_policies.apply_async(args=[org_id], queue="metrics")
        dispatched += 1

    logger.info("SLA evaluation fan-out: dispatched %d org tasks (orgs with policies)", dispatched)
    return {"dispatched": dispatched}


@celery_app.task(
    name="app.tasks.sla.evaluate_all_sla",
    bind=True,
    soft_time_limit=30,
)
def evaluate_all_sla(self) -> dict[str, Any]:
    """Celery task: fan-out SLA evaluation for all orgs."""
    return asyncio.run(_evaluate_all_orgs())
