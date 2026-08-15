# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event Correlation Tasks
=======================================

Periodic Celery tasks for:
  - Running the event correlation engine
  - Auto-resolving stale incidents
"""

import asyncio
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.services.correlation import EventCorrelationService

logger = logging.getLogger("freesdn.tasks.correlation")


# ==========================================================================
# Event Correlation
# ==========================================================================


async def _correlate_events_for_org(organization_id: str) -> dict[str, Any]:
    """Run event correlation for a single organization."""
    async with AsyncSessionLocal() as session:
        service = EventCorrelationService(session)
        try:
            result = await service.correlate(
                organization_id=UUID(organization_id),
                time_window_minutes=15,
            )
            logger.info(
                "Correlation for org %s: %d rules, %d incidents created, %d updated",
                organization_id,
                result["rules_evaluated"],
                result["incidents_created"],
                result["incidents_updated"],
            )
            return result
        except Exception as exc:
            logger.exception("Correlation error for org %s", organization_id)
            await session.rollback()
            return {"success": False, "error": str(exc)}


@celery_app.task(
    name="app.tasks.correlation.correlate_events",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
)
def correlate_events(self: Any, organization_id: str) -> dict[str, Any]:
    """Celery task: run event correlation for one organization."""
    return asyncio.run(_correlate_events_for_org(organization_id))


async def _correlate_all_orgs() -> dict[str, Any]:
    """Fan-out correlation only to orgs that have correlation rules.

    Previously fanned out one task per org every cycle (incl. ~all empty
    fixture orgs), flooding the worker. Scope to orgs with ≥1 correlation rule.
    """
    from app.models.correlation import CorrelationRule

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(CorrelationRule.organization_id).distinct())
        org_ids = [str(row[0]) for row in result.all() if row[0]]

    dispatched = 0
    for org_id in org_ids:
        correlate_events.apply_async(args=[org_id], queue="default")
        dispatched += 1

    logger.info("Correlation fan-out: dispatched %d org tasks (orgs with rules)", dispatched)
    return {"dispatched": dispatched}


@celery_app.task(
    name="app.tasks.correlation.correlate_all_events",
    bind=True,
    soft_time_limit=30,
)
def correlate_all_events(self: Any) -> dict[str, Any]:
    """Celery task: fan-out event correlation for all orgs."""
    return asyncio.run(_correlate_all_orgs())


# ==========================================================================
# Auto-Resolve Stale Incidents
# ==========================================================================


async def _auto_resolve_for_org(organization_id: str) -> dict[str, Any]:
    """Auto-resolve incidents for a single organization."""
    async with AsyncSessionLocal() as session:
        service = EventCorrelationService(session)
        try:
            resolved = await service.auto_resolve_incidents(UUID(organization_id))
            if resolved:
                logger.info("Auto-resolved %d incidents for org %s", resolved, organization_id)
            return {"resolved": resolved}
        except Exception as exc:
            logger.exception("Auto-resolve error for org %s", organization_id)
            await session.rollback()
            return {"success": False, "error": str(exc)}


@celery_app.task(
    name="app.tasks.correlation.auto_resolve_incidents",
    bind=True,
    soft_time_limit=60,
)
def auto_resolve_incidents(self: Any, organization_id: str) -> dict[str, Any]:
    """Celery task: auto-resolve stale incidents."""
    return asyncio.run(_auto_resolve_for_org(organization_id))


async def _auto_resolve_all() -> dict[str, Any]:
    """Fan-out incident auto-resolve only to orgs that have correlation rules."""
    from app.models.correlation import CorrelationRule

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(CorrelationRule.organization_id).distinct())
        org_ids = [str(row[0]) for row in result.all() if row[0]]

    dispatched = 0
    for org_id in org_ids:
        auto_resolve_incidents.apply_async(args=[org_id], queue="default")
        dispatched += 1

    return {"dispatched": dispatched}


@celery_app.task(
    name="app.tasks.correlation.auto_resolve_all",
    bind=True,
    soft_time_limit=30,
)
def auto_resolve_all(self: Any) -> dict[str, Any]:
    """Celery task: fan-out auto-resolve for all orgs."""
    return asyncio.run(_auto_resolve_all())
