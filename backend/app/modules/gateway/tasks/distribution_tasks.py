# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Distribution Tasks
============================================

Celery tasks for async VLAN distribution and lock cleanup.
"""

import asyncio
import logging
from typing import Any
from uuid import UUID

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal

logger = logging.getLogger(__name__)


# ── Async helpers ────────────────────────────────────────────────────────


async def _execute_distribution(vlan_id: str, site_id: str, triggered_by: str) -> dict[str, Any]:
    from app.modules.gateway.services.canonical_service import CanonicalService
    from app.modules.gateway.services.distribution_service import DistributionService
    from app.modules.gateway.services.role_map_service import RoleMapService

    async with AsyncSessionLocal() as session:
        canon = CanonicalService(session)
        roles = RoleMapService(session)

        vlan = await canon.get_vlan(UUID(vlan_id))
        role_map = await roles.get_role_map(UUID(site_id))
        if role_map is None:
            return {"status": "error", "message": f"No role map for site {site_id}"}

        svc = DistributionService(session)
        record = await svc.distribute_vlan(
            vlan=vlan,
            role_map=role_map,
            triggered_by=UUID(triggered_by) if triggered_by else None,
        )
        await session.commit()
        return {
            "id": str(record.id),
            "status": record.status.value
            if hasattr(record.status, "value")
            else str(record.status),
        }


async def _cleanup_locks() -> dict[str, Any]:
    from app.modules.gateway.services.distribution_service import DistributionService

    async with AsyncSessionLocal() as session:
        svc = DistributionService(session)
        cleaned = await svc.cleanup_expired_locks()
        await session.commit()
        return {"cleaned": cleaned}


# ── Celery tasks ─────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    max_retries=1,
    name="gateway.execute_distribution",
    soft_time_limit=300,
    time_limit=360,
)
def execute_distribution(self, vlan_id: str, site_id: str, triggered_by: str) -> dict[str, Any]:
    """Execute a VLAN distribution asynchronously."""
    try:
        return asyncio.run(_execute_distribution(vlan_id, site_id, triggered_by))
    except Exception as exc:
        logger.exception("execute_distribution failed")
        self.retry(exc=exc, countdown=60)


@celery_app.task(
    name="gateway.cleanup_distribution_locks",
    soft_time_limit=60,
    time_limit=90,
)
def cleanup_distribution_locks() -> dict[str, Any]:
    """Periodic: clean up expired distribution locks."""
    try:
        return asyncio.run(_cleanup_locks())
    except Exception:
        logger.exception("cleanup_distribution_locks failed")
        return {"success": False, "error": "see logs"}
