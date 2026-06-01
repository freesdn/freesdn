# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Backup Celery Tasks
===================================

Background tasks for the backup system:
- run_backup: Execute a backup job (on-demand or from schedule)
- run_scheduled_backups: Check and trigger due schedules (runs every 60s)
- cleanup_expired_backups: Delete expired backups (runs daily)
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True, base=FreeSDNTask, name="backup.run_backup", soft_time_limit=600, time_limit=720
)
def run_backup(self, backup_params: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a backup job in the background.

    backup_params should contain all keyword arguments for
    BackupService.create_backup(), including ``organization_id``.
    """

    async def _run() -> dict[str, Any]:
        from uuid import UUID

        from app.services.backup import BackupService

        async with AsyncSessionLocal() as session:
            try:
                svc = BackupService(session)
                # Convert string UUIDs back
                # NOTE C4: organization_id added — required by create_backup().
                for key in (
                    "site_id",
                    "storage_location_id",
                    "created_by_id",
                    "schedule_id",
                    "organization_id",
                ):
                    if backup_params.get(key):
                        backup_params[key] = UUID(backup_params[key])
                if backup_params.get("device_ids"):
                    backup_params["device_ids"] = [UUID(d) for d in backup_params["device_ids"]]

                backup = await svc.create_backup(**backup_params)
                logger.info("Background backup %s completed", backup.id)
                return {
                    "success": True,
                    "backup_id": str(backup.id),
                    "status": backup.status,
                    "file_size": backup.file_size,
                }
            except Exception as e:
                logger.error("Background backup failed: %s", e)
                return {"success": False, "error": str(e)}

    return asyncio.run(_run())


@celery_app.task(
    bind=True, base=FreeSDNTask, name="backup.run_scheduled", soft_time_limit=300, time_limit=360
)
def run_scheduled_backups(self) -> dict[str, Any]:
    """
    Check for backup schedules that are due and trigger them.
    Should be called every 60 seconds by Celery Beat.

    NOTE H9: each schedule iteration now opens a fresh AsyncSessionLocal()
    so a failure on one schedule cannot corrupt or leak transactional state
    into the next.
    NOTE H10: we claim due schedules via ``SELECT ... FOR UPDATE SKIP LOCKED``
    so concurrent Beat fires do not double-run the same row. Missed runs
    are intentionally NOT replayed — we pick the latest "now" instead of
    catching up history. Re-running every cron tick that was missed during
    an outage would create a thundering herd of backups.
    """

    async def _claim_due_ids() -> list[Any]:
        """Return the list of schedule IDs that are due, locking them."""
        from sqlalchemy import select

        from app.modules.backup.models import BackupSchedule

        async with AsyncSessionLocal() as picker:
            now = datetime.now(UTC)
            q = (
                select(BackupSchedule.id)
                .where(
                    BackupSchedule.is_enabled.is_(True),
                    BackupSchedule.next_run_at.isnot(None),
                    BackupSchedule.next_run_at <= now,
                )
                # NOTE H10: SKIP LOCKED prevents double-fire when Beat
                # accidentally invokes us twice (e.g. on worker restart).
                .with_for_update(skip_locked=True)
            )
            result = await picker.execute(q)
            ids = [row[0] for row in result.all()]
            # Release the locks immediately — each iteration will re-acquire
            # its own row in its own session below.
            await picker.commit()
            return ids

    async def _run_one(schedule_id: Any) -> bool:
        """Process a single schedule in its own session. Returns success."""
        from sqlalchemy import select

        from app.modules.backup.models import BackupSchedule
        from app.services.backup import BackupService

        # NOTE H9: fresh session per iteration.
        async with AsyncSessionLocal() as session:
            try:
                # Re-acquire & lock the specific schedule row in this session
                row = (
                    await session.execute(
                        select(BackupSchedule)
                        .where(BackupSchedule.id == schedule_id)
                        .with_for_update(skip_locked=True)
                    )
                ).scalar_one_or_none()
                if row is None:
                    # Another worker won the race — silently skip.
                    return False

                schedule = row
                now = datetime.now(UTC)
                svc = BackupService(session)
                name = f"{schedule.name} — {now.strftime('%Y-%m-%d %H:%M')}"

                # NOTE C4: forward organization_id so the backup is org-scoped.
                await svc.create_backup(
                    name=name,
                    description=f"Scheduled backup from '{schedule.name}'",
                    backup_type=schedule.backup_type or "full",
                    site_id=schedule.site_id,
                    device_ids=schedule.device_ids,
                    include_devices=schedule.include_devices,
                    include_vlans=schedule.include_vlans,
                    include_ssids=schedule.include_ssids,
                    include_users=schedule.include_users,
                    include_automation=schedule.include_automation,
                    storage_type=schedule.storage_type or "local",
                    storage_location_id=schedule.storage_location_id,
                    is_encrypted=schedule.is_encrypted,
                    retention_days=schedule.retention_days,
                    schedule_id=schedule.id,
                    organization_id=schedule.organization_id,
                )

                # NOTE H10: pick the NEXT scheduled time relative to NOW —
                # do NOT replay missed runs. This is intentional.
                schedule.last_run_at = now
                schedule.next_run_at = svc._calculate_next_run(
                    schedule.cron_expression or "0 2 * * *",
                    schedule.timezone or "UTC",
                )

                # Enforce max_backups: delete oldest if over limit
                if schedule.max_backups and schedule.max_backups > 0:
                    from sqlalchemy import func as sqlfunc

                    from app.modules.backup.models import Backup, BackupStatus

                    count_q = select(sqlfunc.count(Backup.id)).where(
                        Backup.schedule_id == schedule.id,
                        Backup.status == BackupStatus.COMPLETED,
                    )
                    count = (await session.execute(count_q)).scalar() or 0
                    if count > schedule.max_backups:
                        excess = count - schedule.max_backups
                        oldest_q = (
                            select(Backup.id)
                            .where(
                                Backup.schedule_id == schedule.id,
                                Backup.status == BackupStatus.COMPLETED,
                            )
                            .order_by(Backup.created_at.asc())
                            .limit(excess)
                        )
                        oldest = (await session.execute(oldest_q)).scalars().all()
                        for bid in oldest:
                            try:
                                await svc.delete_backup(bid)
                            except (SQLAlchemyError, OSError) as exc:
                                logger.error(
                                    "Failed to delete old backup %s for schedule '%s': %s",
                                    bid,
                                    schedule.name,
                                    exc,
                                )

                # NOTE H9: BackupService.create_backup() already commits.
                # The schedule-row updates above are still pending — flush
                # them with one final commit. The previous code committed
                # twice in a row, doubling the round-trips.
                await session.commit()
                return True
            except Exception as e:
                logger.error(
                    "Failed to run scheduled backup '%s': %s",
                    schedule_id,
                    e,
                )
                await session.rollback()
                return False

    async def _run() -> dict[str, Any]:
        ids = await _claim_due_ids()
        triggered = 0
        errors = 0
        for sid in ids:
            ok = await _run_one(sid)
            if ok:
                triggered += 1
            else:
                errors += 1
        logger.info(
            "Scheduled backups check: %d due, %d triggered, %d errors",
            len(ids),
            triggered,
            errors,
        )
        return {"due": len(ids), "triggered": triggered, "errors": errors}

    return asyncio.run(_run())


@celery_app.task(
    bind=True, base=FreeSDNTask, name="backup.cleanup_expired", soft_time_limit=120, time_limit=180
)
def cleanup_expired_backups(self) -> dict[str, Any]:
    """
    Delete backups that have passed their expiry date.
    Should be called daily by Celery Beat.
    """

    async def _run() -> dict[str, Any]:
        from app.services.backup import BackupService

        async with AsyncSessionLocal() as session:
            try:
                svc = BackupService(session)
                deleted = await svc.cleanup_expired_backups()
                logger.info("Expired backup cleanup: %d deleted", deleted)
                return {"deleted": deleted}
            except Exception as e:
                logger.error("Expired backup cleanup failed: %s", e)
                return {"deleted": 0, "error": str(e)}

    return asyncio.run(_run())


# Per-org timeout on the inner restore_from_backup call. Without this a
# single hung org (corrupt .fsdn, stalled
# storage backend, plugin deadlock) burns the whole Celery task's 30-min
# soft_time_limit and every subsequent org goes unvalidated that month.
# 60 seconds is generous for a dry-run restore but tight enough that one
# bad backup costs at most one minute of the budget.
_PER_ORG_VALIDATE_TIMEOUT_SECONDS = 60.0


async def _validate_restore_async() -> dict[str, Any]:
    """Async body of ``backup.validate_restore`` — extracted to module
    scope so tests can drive the loop without going through Celery's
    bind/self machinery.

    Result rows per org:
      - ``ok``      — backup parsed and validated successfully
      - ``warn``    — no completed backup in the last 60 days
      - ``error``   — restore validation raised
      - ``timeout`` — restore exceeded the per-org budget (readiness
        audit); the loop continues to the next org instead
        of blocking the whole monthly job behind one stuck org.
    """
    from datetime import timedelta

    from sqlalchemy import select

    from app.models.core import Organization
    from app.modules.backup.models import Backup, BackupStatus
    from app.services.backup import BackupService

    results: list[dict[str, Any]] = []
    cutoff = datetime.now(UTC) - timedelta(days=60)

    async with AsyncSessionLocal() as session:
        orgs = (await session.execute(select(Organization))).scalars().all()
        logger.info("validate_restore: %d orgs to scan", len(orgs))

        for org in orgs:
            # Most recent completed backup for this org.
            stmt = (
                select(Backup)
                .where(
                    Backup.organization_id == org.id,
                    Backup.status == BackupStatus.COMPLETED,
                    Backup.completed_at.isnot(None),
                )
                .order_by(Backup.completed_at.desc())
                .limit(1)
            )
            backup = (await session.execute(stmt)).scalar_one_or_none()

            if backup is None or (backup.completed_at and backup.completed_at < cutoff):
                results.append(
                    {
                        "organization_id": str(org.id),
                        "status": "warn",
                        "reason": "no_recent_completed_backup",
                    }
                )
                continue

            start = datetime.now(UTC)
            try:
                svc = BackupService(session)
                # per-org timeout. asyncio.wait_for cancels
                # the inner coroutine on timeout so a hung restore
                # cannot consume the rest of the budget.
                job = await asyncio.wait_for(
                    svc.restore_from_backup(
                        backup_id=backup.id,
                        organization_id=org.id,
                        dry_run=True,
                        # Restore-everything switches so the validation
                        # exercises every branch of the loader.
                        restore_devices=True,
                        restore_vlans=True,
                        restore_ssids=True,
                        restore_users=True,
                        restore_automation=True,
                    ),
                    timeout=_PER_ORG_VALIDATE_TIMEOUT_SECONDS,
                )
                duration = (datetime.now(UTC) - start).total_seconds()
                ok = job.status == "completed"
                results.append(
                    {
                        "organization_id": str(org.id),
                        "backup_id": str(backup.id),
                        "restore_job_id": str(job.id),
                        "status": "ok" if ok else "error",
                        "job_status": job.status,
                        "duration_sec": duration,
                    }
                )
                if not ok:
                    await _emit_validation_failure(
                        org_id=org.id,
                        backup_id=backup.id,
                        reason=f"dry-run restore status={job.status}",
                    )
            except TimeoutError:
                duration = (datetime.now(UTC) - start).total_seconds()
                logger.warning(
                    "validate_restore TIMED OUT for org %s after %.1fs",
                    org.id,
                    duration,
                )
                results.append(
                    {
                        "organization_id": str(org.id),
                        "backup_id": str(backup.id),
                        "status": "timeout",
                        "duration_sec": duration,
                        "reason": (f"per-org timeout ({_PER_ORG_VALIDATE_TIMEOUT_SECONDS:.0f}s)"),
                    }
                )
                await _emit_validation_failure(
                    org_id=org.id,
                    backup_id=backup.id,
                    reason=(
                        f"dry-run restore timed out after {_PER_ORG_VALIDATE_TIMEOUT_SECONDS:.0f}s"
                    ),
                )
            except SQLAlchemyError as e:
                # DB errors are recoverable across the loop; log and continue.
                logger.exception("validate_restore DB error for org %s", org.id)
                results.append(
                    {
                        "organization_id": str(org.id),
                        "backup_id": str(backup.id),
                        "status": "error",
                        "reason": str(e)[:200],
                    }
                )
                await _emit_validation_failure(
                    org_id=org.id,
                    backup_id=backup.id,
                    reason=str(e)[:200],
                )
            except Exception as e:
                logger.exception("validate_restore failed for org %s", org.id)
                results.append(
                    {
                        "organization_id": str(org.id),
                        "backup_id": str(backup.id),
                        "status": "error",
                        "reason": str(e)[:200],
                    }
                )
                await _emit_validation_failure(
                    org_id=org.id,
                    backup_id=backup.id,
                    reason=str(e)[:200],
                )

    ok_count = sum(1 for r in results if r["status"] == "ok")
    error_count = sum(1 for r in results if r["status"] == "error")
    warn_count = sum(1 for r in results if r["status"] == "warn")
    timeout_count = sum(1 for r in results if r["status"] == "timeout")
    logger.info(
        "validate_restore done: ok=%d warn=%d error=%d timeout=%d",
        ok_count,
        warn_count,
        error_count,
        timeout_count,
    )
    return {
        "ok": ok_count,
        "warn": warn_count,
        "error": error_count,
        "timeout": timeout_count,
        "results": results,
    }


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="backup.validate_restore",
    soft_time_limit=1800,
    time_limit=2100,
)
def validate_restore(self) -> dict[str, Any]:
    """Monthly backup → dry-run-restore validation.

    A backup that has never been read back is a backup you cannot
    trust. Once per month per organization we pick the most recent
    completed backup and run ``restore_from_backup(dry_run=True)``
    against it. The dry-run path loads the .fsdn header, verifies the
    SHA-256 checksum, decrypts the payload, parses the inner JSON
    and walks the restore plan — all without touching live tables.
    """
    return asyncio.run(_validate_restore_async())


async def _emit_validation_failure(
    *,
    org_id: Any,
    backup_id: Any,
    reason: str,
) -> None:
    """Push a critical event on validation failure so ops gets paged.

    Kept defensive: any error here must not poison the validation loop.
    """
    try:
        from app.core.events import (
            Event,
            EventCategory,
            EventPriority,
            get_event_bus,
        )

        bus = get_event_bus()
        await bus.publish(
            Event(
                event_type="backup.validation.failed",
                category=EventCategory.SYSTEM,
                priority=EventPriority.CRITICAL,
                payload={
                    "organization_id": str(org_id),
                    "backup_id": str(backup_id),
                    "reason": reason,
                },
                organization_id=str(org_id),
            )
        )
    except Exception:
        logger.debug("failed to emit backup.validation.failed event", exc_info=True)
