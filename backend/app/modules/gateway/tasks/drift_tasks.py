# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Drift Detection Tasks
===============================================

Periodic Celery tasks that run drift checks on all sites
with active role maps.
"""

import asyncio
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.modules.gateway.models import SiteRoleMap

logger = logging.getLogger(__name__)


# ── Async helpers ────────────────────────────────────────────────────────


async def _check_site_drift(site_id: str) -> dict[str, Any]:
    from app.modules.gateway.services.drift_service import DriftService

    async with AsyncSessionLocal() as session:
        svc = DriftService(session)
        events = await svc.check_site(UUID(site_id))
        await session.commit()
        return {
            "site_id": site_id,
            "new_events": len(events),
        }


async def _check_all_sites() -> dict[str, Any]:
    from app.modules.gateway.services.drift_service import DriftService

    async with AsyncSessionLocal() as session:
        # Get all sites that have a role map
        stmt = select(SiteRoleMap.site_id)
        result = await session.execute(stmt)
        site_ids = [row[0] for row in result.all()]

        if not site_ids:
            return {"success": True, "message": "No sites configured", "checked": 0}

        svc = DriftService(session)
        total_events = 0
        errors: list[str] = []
        for sid in site_ids:
            try:
                events = await svc.check_site(sid)
                total_events += len(events)
            except Exception:
                logger.exception("Drift check failed for site %s", sid)
                errors.append(str(sid))

        await session.commit()
        return {
            "success": len(errors) == 0,
            "sites_checked": len(site_ids),
            "new_events": total_events,
            "failed_sites": errors,
        }


# ── Celery tasks ─────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=1,
    name="gateway.check_site_drift",
    soft_time_limit=300,
    time_limit=360,
)
def check_site_drift(self, site_id: str) -> dict[str, Any]:
    """Run drift check for a single site."""
    try:
        return asyncio.run(_check_site_drift(site_id))
    except Exception as exc:
        logger.exception("check_site_drift failed for %s", site_id)
        self.retry(exc=exc, countdown=60)


@celery_app.task(
    name="gateway.check_all_sites_drift",
    soft_time_limit=600,
    time_limit=660,
)
def check_all_sites_drift() -> dict[str, Any]:
    """Periodic: run drift checks on all sites with role maps."""
    try:
        return asyncio.run(_check_all_sites())
    except Exception:
        logger.exception("check_all_sites_drift failed")
        return {"success": False, "error": "see logs"}
