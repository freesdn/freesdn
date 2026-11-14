# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Network device configuration backup tasks
===================================================

* ``config_backup.dispatch_due`` (beat, every 10 minutes, "default"): discover
  exportable devices, lease up to 20 due targets, enqueue one capture each.
  Database work only; it never contacts a device.
* ``config_backup.capture`` ("sync", the device-I/O lane): ONE read-only export
  of ONE device under its lease. Never retried by Celery: a failure is recorded
  and rescheduled with backoff by the service.

See app/services/device_config_backup.py for the gentleness rules.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from uuid import UUID

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    base=FreeSDNTask,
    name="config_backup.dispatch_due",
    queue="default",
    soft_time_limit=120,
    time_limit=180,
)
def dispatch_due(self: Any) -> dict[str, Any]:
    async def _run() -> dict[str, Any]:
        from app.services.device_config_backup import DeviceConfigBackupService

        async with AsyncSessionLocal() as session:
            service = DeviceConfigBackupService(session)
            discovered = await service.sync_targets()
            claims = await service.claim_due()
            await session.commit()
        for claim in claims:
            capture.delay(str(claim.target_id), str(claim.token), "scheduled", None)
        return {"dispatched": len(claims), **discovered}

    return asyncio.run(_run())


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    base=FreeSDNTask,
    name="config_backup.capture",
    queue="sync",
    # Never re-run an export automatically: the service records failures and
    # reschedules with backoff, so a retry could only mean a second export.
    autoretry_for=(),
    max_retries=0,
    soft_time_limit=180,
    time_limit=240,
)
def capture(
    self: Any, target_id: str, token: str, trigger: str = "scheduled", user_id: str | None = None
) -> dict[str, Any]:
    async def _run() -> dict[str, Any]:
        from app.services.device_config_backup import Claim, DeviceConfigBackupService

        async with AsyncSessionLocal() as session:
            outcome = await DeviceConfigBackupService(session).capture(
                Claim(UUID(target_id), UUID(token)),
                trigger="manual" if trigger == "manual" else "scheduled",
                user_id=UUID(user_id) if user_id else None,
            )
        return {"target_id": target_id, "outcome": outcome}

    return asyncio.run(_run())
