# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Alert Rules Engine Tasks
========================================

Periodic Celery tasks for:
  - Evaluating alert rules across all organizations
  - Auto-resolving stale alerts
  - Unsuppressing expired alert suppressions
"""

import asyncio
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.services.alert_rules import AlertRuleService

logger = logging.getLogger("freesdn.tasks.alert_rules")


# ==========================================================================
# Alert Rule Evaluation
# ==========================================================================


async def _evaluate_alerts_for_org(organization_id: str) -> dict[str, Any]:
    """Evaluate all active alert rules for a single organization."""
    async with AsyncSessionLocal() as session:
        service = AlertRuleService(session)
        try:
            result = await service.evaluate_all_rules(UUID(organization_id))
            await session.commit()
            logger.info(
                "Alert evaluation for org %s: %d rules, %d alerts fired",
                organization_id,
                result["rules_evaluated"],
                result["alerts_fired"],
            )
            return result
        except Exception as exc:
            logger.exception("Alert evaluation error for org %s", organization_id)
            await session.rollback()
            return {"success": False, "error": str(exc)}


@celery_app.task(
    name="app.tasks.alert_rules.evaluate_alert_rules",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
)
def evaluate_alert_rules(self: Any, organization_id: str) -> dict[str, Any]:
    """Celery task: evaluate alert rules for one organization."""
    return asyncio.run(_evaluate_alerts_for_org(organization_id))


async def _evaluate_all_orgs() -> dict[str, Any]:
    """Fan-out alert evaluation only to orgs that have ≥1 ACTIVE alert rule.

    Previously fanned out one task PER organization every minute — including
    the many empty/inactive orgs — which floods the worker (e.g. 278 orgs → 278
    no-op tasks/min). Scoping to orgs that actually have active rules cuts that
    to just the orgs doing alerting.
    """
    from app.models.alert_rules import AlertRule, AlertRuleStatus

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AlertRule.organization_id)
            .where(
                AlertRule.status == AlertRuleStatus.ACTIVE,
                AlertRule.deleted_at.is_(None),
            )
            .distinct()
        )
        org_ids = [str(row[0]) for row in result.all() if row[0]]

    dispatched = 0
    for org_id in org_ids:
        evaluate_alert_rules.apply_async(args=[org_id], queue="default")
        dispatched += 1

    logger.info(
        "Alert evaluation fan-out: dispatched %d org tasks (orgs with active rules)",
        dispatched,
    )
    return {"dispatched": dispatched}


@celery_app.task(
    name="app.tasks.alert_rules.evaluate_all_alert_rules",
    bind=True,
    soft_time_limit=60,
)
def evaluate_all_alert_rules(self: Any) -> dict[str, Any]:
    """Celery task: fan out alert evaluation to all organizations."""
    return asyncio.run(_evaluate_all_orgs())


# ==========================================================================
# Auto-Resolution
# ==========================================================================


async def _auto_resolve_for_org(organization_id: str) -> dict[str, Any]:
    """Auto-resolve stale alerts for one organization."""
    async with AsyncSessionLocal() as session:
        service = AlertRuleService(session)
        try:
            resolved = await service.auto_resolve_alerts(UUID(organization_id))
            await session.commit()
            return {"resolved": resolved}
        except Exception as exc:
            logger.exception("Auto-resolve error for org %s", organization_id)
            await session.rollback()
            return {"success": False, "error": str(exc)}


@celery_app.task(
    name="app.tasks.alert_rules.auto_resolve_alerts",
    bind=True,
    soft_time_limit=60,
)
def auto_resolve_alerts(self: Any, organization_id: str) -> dict[str, Any]:
    """Celery task: auto-resolve stale alerts for one org."""
    return asyncio.run(_auto_resolve_for_org(organization_id))


async def _auto_resolve_all() -> dict[str, Any]:
    """Fan-out auto-resolve only to orgs that have alert rules."""
    from app.models.alert_rules import AlertRule

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AlertRule.organization_id).where(AlertRule.deleted_at.is_(None)).distinct()
        )
        org_ids = [str(row[0]) for row in result.all() if row[0]]

    dispatched = 0
    for org_id in org_ids:
        auto_resolve_alerts.apply_async(args=[org_id], queue="default")
        dispatched += 1
    return {"dispatched": dispatched}


@celery_app.task(
    name="app.tasks.alert_rules.auto_resolve_all_alerts",
    bind=True,
    soft_time_limit=60,
)
def auto_resolve_all_alerts(self: Any) -> dict[str, Any]:
    """Celery task: fan out auto-resolve to all organizations."""
    return asyncio.run(_auto_resolve_all())


# ==========================================================================
# Suppression Cleanup
# ==========================================================================


async def _unsuppress_expired() -> dict[str, Any]:
    """Remove expired suppressions across all orgs."""
    async with AsyncSessionLocal() as session:
        service = AlertRuleService(session)
        try:
            count = await service.unsuppress_expired()
            await session.commit()
            return {"unsuppressed": count}
        except Exception as exc:
            logger.exception("Unsuppress error")
            await session.rollback()
            return {"success": False, "error": str(exc)}


@celery_app.task(
    name="app.tasks.alert_rules.unsuppress_expired_alerts",
    bind=True,
    soft_time_limit=30,
)
def unsuppress_expired_alerts(self: Any) -> dict[str, Any]:
    """Celery task: unsuppress alerts past their suppression window."""
    return asyncio.run(_unsuppress_expired())
