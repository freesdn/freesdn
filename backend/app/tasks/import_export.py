# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Data Import/Export Celery Tasks
===============================================

Background tasks for data import/export:
- run_export_job: Execute an export in the background
- run_import_job: Execute an import in the background
- cleanup_old_data_files: Purge old export/import files
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True, base=FreeSDNTask, name="data.run_export_job", soft_time_limit=600, time_limit=720
)
def run_export_job(self, job_id: str) -> dict[str, Any]:
    """
    Execute an export job in the background.
    """

    async def _run() -> dict[str, Any]:
        from uuid import UUID

        from app.services.import_export import DataImportExportService as svc

        async with AsyncSessionLocal() as session:
            try:
                result = await svc.run_export(session, UUID(job_id))
                await session.commit()
                logger.info("Export job %s completed: %s", job_id, result)
                return result
            except Exception as e:
                await session.rollback()
                logger.error("Export job %s failed: %s", job_id, e)
                return {"success": False, "error": str(e)}

    return asyncio.run(_run())


@celery_app.task(
    bind=True, base=FreeSDNTask, name="data.run_import_job", soft_time_limit=600, time_limit=720
)
def run_import_job(self, job_id: str) -> dict[str, Any]:
    """
    Execute an import job in the background.
    """

    async def _run() -> dict[str, Any]:
        from uuid import UUID

        from app.services.import_export import DataImportExportService as svc

        async with AsyncSessionLocal() as session:
            try:
                result = await svc.run_import(session, UUID(job_id))
                await session.commit()
                logger.info("Import job %s completed: %s", job_id, result)

                # Update firmware status for any newly imported devices
                if result.get("imported", 0) > 0:
                    try:
                        from app.services.firmware import PersistentFirmwareService

                        await PersistentFirmwareService.check_updates(session)
                        await session.commit()
                    except Exception:
                        logger.debug("Post-import firmware check failed", exc_info=True)

                return result
            except Exception as e:
                await session.rollback()
                logger.error("Import job %s failed: %s", job_id, e)
                return {"success": False, "error": str(e)}

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="data.cleanup_old_data_files",
    soft_time_limit=120,
    time_limit=180,
)
def cleanup_old_data_files(self) -> dict[str, Any]:
    """
    Clean up old export/import files. Runs daily.
    Removes files older than 7 days.
    """
    from app.services.import_export import DATA_DIR

    cutoff = datetime.now(UTC) - timedelta(days=7)
    deleted = 0
    errors = 0

    try:
        for filepath in DATA_DIR.rglob("*"):
            if filepath.is_file():
                try:
                    mtime = datetime.fromtimestamp(filepath.stat().st_mtime, tz=UTC)
                    if mtime < cutoff:
                        filepath.unlink()
                        deleted += 1
                except OSError as e:
                    logger.warning("Failed to clean up %s: %s", filepath, e)
                    errors += 1
    except Exception as e:
        logger.error("Data file cleanup failed: %s", e)

    if deleted:
        logger.info("Cleaned up %d old data files", deleted)

    return {"deleted": deleted, "errors": errors}
