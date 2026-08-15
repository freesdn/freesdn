# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Sync Tasks
====================================

Periodic Celery tasks that refresh the imported-cache tables
from brain gateway devices.
"""

import asyncio
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.modules.gateway.models import NetworkRole, SiteRoleAssignment

logger = logging.getLogger(__name__)


# ── Async helpers ────────────────────────────────────────────────────────


async def _sync_gateway(gateway_id: str) -> dict[str, Any]:
    """Sync a single gateway device."""
    from app.modules.gateway.services.sync_service import SyncService

    async with AsyncSessionLocal() as session:
        svc = SyncService(session)
        result = await svc.sync_gateway(UUID(gateway_id))
        await session.commit()
        return result


async def _sync_all_brain_gateways() -> dict[str, Any]:
    """Sync all gateway devices assigned as brain in any role map."""
    from app.modules.gateway.services.sync_service import SyncService

    async with AsyncSessionLocal() as session:
        # Find all brain gateways
        stmt = select(SiteRoleAssignment.gateway_id).where(
            SiteRoleAssignment.role == NetworkRole.BRAIN
        )
        result = await session.execute(stmt)
        brain_ids = [row[0] for row in result.all()]

        if not brain_ids:
            return {
                "success": True,
                "message": "No brain gateways configured",
                "synced": 0,
            }

        svc = SyncService(session)
        results = []
        for gw_id in brain_ids:
            try:
                r = await svc.sync_gateway(gw_id)
                results.append({"gateway_id": str(gw_id), **r})
            except Exception:
                logger.exception("Sync failed for gateway %s", gw_id)
                results.append({"gateway_id": str(gw_id), "status": "failed", "error": "exception"})

        await session.commit()

        ok = [r for r in results if r.get("status") == "success"]
        failed = [r for r in results if r.get("status") == "failed"]

        return {
            "success": True,
            "total": len(brain_ids),
            "synced": len(ok),
            "failed": len(failed),
            "details": results,
        }


# ── Celery tasks ─────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=2,
    name="gateway.sync_gateway",
    soft_time_limit=300,
    time_limit=360,
)
def sync_gateway(self, gateway_id: str) -> dict[str, Any]:
    """Sync imported data from a single gateway device."""
    try:
        return asyncio.run(_sync_gateway(gateway_id))
    except Exception as exc:
        logger.exception("sync_gateway failed for %s", gateway_id)
        self.retry(exc=exc, countdown=30)


@celery_app.task(
    name="gateway.sync_all_gateways",
    soft_time_limit=600,
    time_limit=660,
)
def sync_all_gateways() -> dict[str, Any]:
    """Periodic: sync all brain gateways.

    Uses a solo-lock so a slow run (each brain gateway is synced serially
    and the task may run up to its 11-minute hard limit on a 5-minute beat)
    cannot overlap a fresh run across workers — overlap would otherwise
    double the device load and re-run the delete-then-insert replace on
    the imported cache tables.
    """
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    if not acquire_solo_lock("gateway.sync_all_gateways", ttl_seconds=600):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_sync_all_brain_gateways())
    except Exception:
        logger.exception("sync_all_gateways failed")
        return {"success": False, "error": "see logs"}
    finally:
        release_solo_lock("gateway.sync_all_gateways")
