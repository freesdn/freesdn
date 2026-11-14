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
        skipped = 0

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
                from app.core.device_breaker import CLOSED, controller_breaker, controller_key
                from app.core.device_poll import device_poll
                from app.core.device_slot import controller_slot_key
                from app.models.core import Controller

                controllers = {
                    c.id: c
                    for c in (
                        await session.execute(
                            select(Controller).where(Controller.id.in_(controller_ids))
                        )
                    ).scalars()
                }

                for ctrl_id in controller_ids:
                    ctrl = controllers.get(ctrl_id)
                    # A controller the health check found unreachable is left to
                    # it (this sync only peeks the breaker), and one that another
                    # poller is talking to is read on the next cycle.
                    if controller_breaker.peek(controller_key(ctrl_id)) != CLOSED:
                        skipped += 1
                        continue
                    async with device_poll(
                        slot_key=controller_slot_key(ctrl) if ctrl else f"controller:{ctrl_id}",
                        breaker=None,
                        breaker_key=None,
                        holder="802.1X event sync",
                    ) as turn:
                        if turn.skipped:
                            skipped += 1
                            logger.info(
                                "sync_dot1x_events: controller %s skipped: %s", ctrl_id, turn.reason
                            )
                            continue
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
            "skipped": skipped,
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
        skipped = 0

        async with AsyncSessionLocal() as session:
            try:
                result = await session.execute(
                    select(RadiusServerProfile).where(
                        RadiusServerProfile.deleted_at.is_(None),
                    )
                )
                profiles = result.scalars().all()

                from app.core.device_poll import device_poll
                from app.core.device_slot import host_slot_key

                svc = RadiusProfileService(session)
                for profile in profiles:
                    # A RADIUS server is often a managed box (a firewall's
                    # FreeRADIUS): the probe takes its turn like every poller,
                    # and a server another poller has is checked next cycle.
                    async with device_poll(
                        slot_key=host_slot_key(profile.host, fallback=f"radius:{profile.id}"),
                        breaker=None,
                        breaker_key=None,
                        holder="RADIUS health check",
                    ) as turn:
                        if turn.skipped:
                            skipped += 1
                            continue
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
            "skipped": skipped,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    return asyncio.run(_run())
