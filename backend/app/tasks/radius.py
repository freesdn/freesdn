# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - RADIUS / 802.1X Celery Tasks
==========================================

Background tasks for RADIUS integration:
- sync_dot1x_events:  Pull 802.1X auth events from all controllers
                       that have at least one Dot1xPortConfig.
- check_radius_health: TCP-probe every RadiusServerProfile and update
                       its ``is_healthy`` / ``last_health_check`` fields.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Sync 802.1X auth events (every 5 min)
# ─────────────────────────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="radius.sync_dot1x_events",
    soft_time_limit=120,
    time_limit=180,
)
def sync_dot1x_events(self) -> dict[str, Any]:
    """
    Pull recent 802.1X auth events from every controller that has at
    least one Dot1xPortConfig.  Designed to run on a 5-minute schedule.
    """

    async def _run() -> dict[str, Any]:
        from sqlalchemy import distinct, select

        from app.models.radius import Dot1xPortConfig
        from app.services.radius import RadiusProfileService

        synced_total = 0
        errors = 0

        async with AsyncSessionLocal() as session:
            try:
                # Find distinct controller IDs that have 802.1X configs
                result = await session.execute(
                    select(distinct(Dot1xPortConfig.controller_id)).where(
                        Dot1xPortConfig.push_status == "pushed",
                        Dot1xPortConfig.deleted_at.is_(None),
                    )
                )
                controller_ids = [row[0] for row in result.all()]

                for ctrl_id in controller_ids:
                    try:
                        svc = RadiusProfileService(session)
                        outcome = await svc.sync_auth_events(ctrl_id)
                        synced_total += outcome.get("synced", 0)
                        if not outcome.get("success"):
                            errors += 1
                    except Exception as exc:
                        logger.warning(
                            "sync_dot1x_events failed for controller %s: %s",
                            ctrl_id,
                            exc,
                        )
                        errors += 1

                await session.commit()
                logger.info(
                    "sync_dot1x_events complete: %d events synced from %d controllers, %d errors",
                    synced_total,
                    len(controller_ids),
                    errors,
                )
            except Exception as exc:
                logger.error("sync_dot1x_events task failed: %s", exc)
                await session.rollback()
                errors += 1

        return {
            "synced": synced_total,
            "errors": errors,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    return asyncio.run(_run())


# ─────────────────────────────────────────────────────────────────────────────
# RADIUS health check (every 2 min)
# ─────────────────────────────────────────────────────────────────────────────


@celery_app.task(
    bind=True, base=FreeSDNTask, name="radius.check_health", soft_time_limit=120, time_limit=180
)
def check_radius_health(self) -> dict[str, Any]:
    """
    TCP-probe every active RadiusServerProfile and update its health
    status.  Designed to run on a 2-minute schedule.
    """

    async def _run() -> dict[str, Any]:
        from sqlalchemy import select

        from app.models.radius import RadiusServerProfile
        from app.services.radius import RadiusProfileService

        checked = 0
        healthy = 0
        errors = 0

        async with AsyncSessionLocal() as session:
            try:
                result = await session.execute(
                    select(RadiusServerProfile).where(
                        RadiusServerProfile.deleted_at.is_(None),
                    )
                )
                profiles = result.scalars().all()

                svc = RadiusProfileService(session)
                for profile in profiles:
                    try:
                        outcome = await svc.health_check_profile(profile)
                        checked += 1
                        if outcome.get("is_healthy"):
                            healthy += 1
                    except Exception as exc:
                        logger.warning(
                            "Health check failed for RADIUS profile %s: %s",
                            profile.id,
                            exc,
                        )
                        errors += 1

                await session.commit()
                logger.info(
                    "check_radius_health complete: %d checked, %d healthy, %d errors",
                    checked,
                    healthy,
                    errors,
                )
            except Exception as exc:
                logger.error("check_radius_health task failed: %s", exc)
                await session.rollback()
                errors += 1

        return {
            "checked": checked,
            "healthy": healthy,
            "errors": errors,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    return asyncio.run(_run())
