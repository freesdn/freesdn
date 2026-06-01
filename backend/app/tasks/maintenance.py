# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Maintenance Tasks
===============================

Celery tasks for system maintenance:
- Cleanup old data
- Database maintenance
- Cache management
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, text

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.db.session import get_logdb_celery_factory
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)

# LogDB session factory for time-series writes (mandatory — requires LOGDB_URL)
# Lazy: defers RuntimeError to task execution, not module import
_logdb_factory = None


def _get_logdb() -> Any:
    global _logdb_factory
    if _logdb_factory is None:
        _logdb_factory = get_logdb_celery_factory()
    return _logdb_factory


@celery_app.task(bind=True, base=FreeSDNTask, soft_time_limit=300, time_limit=360)  # type: ignore[untyped-decorator]
def cleanup_old_events(self: Any, days: int = 90) -> dict[str, Any]:
    """
    Clean up old events from the database.

    By default, keeps events for 90 days (TimescaleDB retention policy).
    This task does manual cleanup for any orphaned data.

    Args:
        days: Number of days to retain events
    """

    async def _run() -> dict[str, Any]:
        from app.models.events import EventRecord

        cutoff = datetime.now(UTC) - timedelta(days=days)

        async with _get_logdb()() as session:
            # Count events to delete
            count_result = await session.execute(
                select(func.count(EventRecord.id)).where(EventRecord.timestamp < cutoff)
            )
            count = count_result.scalar() or 0

            if count == 0:
                return {
                    "success": True,
                    "message": f"No events older than {days} days",
                    "deleted": 0,
                }

            self.update_progress(0, 1, f"Deleting {count} old events...")

            # Delete old events in batches
            deleted = 0
            max_iterations = 100

            while max_iterations > 0:
                max_iterations -= 1
                result = await session.execute(
                    delete(EventRecord)
                    .where(EventRecord.timestamp < cutoff)
                    .execution_options(synchronize_session=False)
                )

                batch_deleted = result.rowcount
                if batch_deleted == 0:
                    break

                deleted += batch_deleted
                await session.commit()

                self.update_progress(deleted, count, f"Deleted {deleted}/{count} old events")

            return {
                "success": True,
                "deleted": deleted,
                "cutoff_date": cutoff.isoformat(),
            }

    return asyncio.run(_run())


@celery_app.task(bind=True, base=FreeSDNTask, soft_time_limit=60, time_limit=120)  # type: ignore[untyped-decorator]
def reap_stuck_omada_pending_changes(self: Any, max_age_minutes: int = 5) -> dict[str, Any]:
    """Recover ``adapter_pending_changes`` rows stuck in ``"applying"``.

    The apply path flips a row to ``"applying"`` BEFORE invoking the
    Omada client. If the worker process is killed mid-call (SIGKILL,
    OOM, controller hang past request timeout), the row stays in
    ``"applying"`` forever — operators can't discard it via the
    normal endpoint and the apply endpoint refuses any non-pending
    status.

    This janitor flips ``"applying"`` rows older than
    ``max_age_minutes`` (updated_at threshold) to ``"failed"`` so the
    operator sees a clear failure and can re-stage. Default 5 min is
    conservative — typical Omada applies finish in < 30 s.
    """
    from sqlalchemy import update

    from app.models.staging import AdapterPendingChange

    cutoff = datetime.now(UTC) - timedelta(minutes=max_age_minutes)

    async def _run() -> int:
        async with AsyncSessionLocal() as session:
            stmt = (
                update(AdapterPendingChange)
                .where(
                    AdapterPendingChange.status == "applying",
                    AdapterPendingChange.updated_at < cutoff,
                )
                .values(
                    status="failed",
                    failure_reason="janitor_timeout",
                )
            )
            result = await session.execute(stmt)
            await session.commit()
            return int(result.rowcount or 0)

    reaped = asyncio.run(_run())
    if reaped:
        logger.warning(
            "Reaped %d stuck adapter_pending_changes (status=applying > %dm)",
            reaped,
            max_age_minutes,
        )
    return {"success": True, "reaped": reaped, "cutoff_minutes": max_age_minutes}


@celery_app.task(bind=True, base=FreeSDNTask, soft_time_limit=120, time_limit=180)  # type: ignore[untyped-decorator]
def cleanup_stale_progress(self: Any, hours: int = 24) -> dict[str, Any]:
    """
    Clean up stale task progress entries from Redis.

    Removes progress entries for tasks that:
    - Are older than the specified hours
    - Are stuck in non-terminal states

    Args:
        hours: Hours after which to consider progress stale
    """
    from app.tasks.base import progress_store

    cutoff = datetime.now(UTC) - timedelta(hours=hours)

    # Get all progress entries
    all_progress = progress_store.get_all_active("*")

    cleaned = 0
    for progress in all_progress:
        # Check if started too long ago
        if progress.started_at and progress.started_at < cutoff:
            progress_store.delete_progress(progress.task_id)
            cleaned += 1
            logger.info("Cleaned up stale task progress: %s", progress.task_id)

    return {
        "success": True,
        "cleaned": cleaned,
        "checked": len(all_progress),
    }


@celery_app.task(bind=True, base=FreeSDNTask, soft_time_limit=120, time_limit=180)  # type: ignore[untyped-decorator]
def cleanup_orphan_sessions(self: Any, hours: int = 24) -> dict[str, Any]:
    """
    Clean up orphaned user sessions.

    Removes sessions that:
    - Are expired
    - Haven't been used in the specified hours
    """

    async def _run() -> dict[str, Any]:
        from app.models import UserSession
        from app.models.sso import SSOSession

        now = datetime.now(UTC)
        cutoff = now - timedelta(hours=hours)

        async with AsyncSessionLocal() as session:
            user_result = await session.execute(
                delete(UserSession).where(
                    (UserSession.expires_at < now) | (UserSession.last_activity_at < cutoff)  # type: ignore[attr-defined]
                )
            )
            # SSO sessions are short-lived (10-min TTL) and single-use; expired or
            # completed rows — each holding the full IdP-response claims JSONB —
            # must be reaped or they accumulate forever. There was no SSOSession
            # reaper before, only this UserSession one.
            sso_result = await session.execute(
                delete(SSOSession).where(
                    (SSOSession.expires_at < now) | (SSOSession.completed_at.isnot(None))
                )
            )

            await session.commit()

            user_deleted = user_result.rowcount or 0  # type: ignore[attr-defined]
            sso_deleted = sso_result.rowcount or 0  # type: ignore[attr-defined]
            return {
                "success": True,
                "deleted": user_deleted + sso_deleted,
                "user_sessions": user_deleted,
                "sso_sessions": sso_deleted,
            }

    return asyncio.run(_run())


@celery_app.task(bind=True, base=FreeSDNTask, soft_time_limit=600, time_limit=720)  # type: ignore[untyped-decorator]
def vacuum_database(self: Any) -> dict[str, Any]:
    """
    Run VACUUM ANALYZE on frequently updated tables.

    This helps maintain database performance.
    """

    async def _run() -> dict[str, Any]:
        import re

        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        # Allowlist of known safe table names
        ALLOWED_TABLES = frozenset(
            {
                "devices",
                "device_ports",
                "device_clients",
                "event_records",
            }
        )

        tables = list(ALLOWED_TABLES)

        async with AsyncSessionLocal() as session:
            results = {}

            for i, table in enumerate(tables, 1):
                self.update_progress(i, len(tables), f"Vacuuming {table}...")

                # Validate table name is a safe SQL identifier and in the allowlist
                if table not in ALLOWED_TABLES or not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", table):
                    results[table] = "skipped: invalid table name"
                    continue

                try:
                    # Note: VACUUM cannot run inside a transaction
                    # This would need to use a separate connection with autocommit
                    # Table names cannot use bind parameters; validated against allowlist above
                    await session.execute(text("ANALYZE " + table))
                    results[table] = "analyzed"
                except SQLAlchemyError as e:
                    results[table] = f"error: {str(e)}"

            await session.commit()

            return {
                "success": True,
                "tables": results,
            }

    return asyncio.run(_run())


@celery_app.task(bind=True, base=FreeSDNTask, soft_time_limit=120, time_limit=180)  # type: ignore[untyped-decorator]
def refresh_materialized_views(self: Any) -> dict[str, Any]:
    """
    Refresh materialized views if any exist.
    """

    async def _run() -> dict[str, Any]:
        import re

        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        async with AsyncSessionLocal() as session:
            # Get list of materialized views
            result = await session.execute(
                text("""
                    SELECT matviewname
                    FROM pg_matviews
                    WHERE schemaname = 'public'
                """)
            )
            views = [row[0] for row in result]

            if not views:
                return {
                    "success": True,
                    "message": "No materialized views to refresh",
                    "refreshed": [],
                }

            refreshed = []
            for view in views:
                # Validate view name is a safe SQL identifier (letters, digits, underscores)
                if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", view):
                    logger.warning("Skipping suspicious view name: %s", view)
                    continue
                try:
                    # View names cannot use bind parameters; validated via regex above
                    await session.execute(
                        text('REFRESH MATERIALIZED VIEW CONCURRENTLY "' + view + '"')
                    )
                    refreshed.append(view)
                except SQLAlchemyError as e:
                    logger.warning("Could not refresh view %s: %s", view, e)

            await session.commit()

            return {
                "success": True,
                "refreshed": refreshed,
            }

    return asyncio.run(_run())


@celery_app.task(bind=True, base=FreeSDNTask, soft_time_limit=600, time_limit=720)  # type: ignore[untyped-decorator]
def prune_collector_logs(self: Any) -> dict[str, Any]:
    """Prune old collector logs and flow records per CollectorConfig retention.

    NOTE(C5): Without this task ``collector.collector_logs`` and
    ``collector.flow_records`` grow forever — both tables receive UDP
    ingest with no built-in TTL. We read each org's retention policy
    from ``CollectorConfig`` and DELETE rows older than the configured
    horizon. Defaults (30d logs / 7d flows) apply when no config row
    exists.
    """

    async def _run() -> dict[str, Any]:
        from app.modules.collector.models import CollectorConfig

        results: dict[str, Any] = {"orgs": {}, "logs_deleted": 0, "flows_deleted": 0}

        async with AsyncSessionLocal() as session:
            cfg_result = await session.execute(select(CollectorConfig))
            configs = cfg_result.scalars().all()

            # Always run at least the default-retention sweep if no
            # org-level config exists, so orphaned (org_id IS NULL) rows
            # don't accumulate either.
            if not configs:
                configs = []  # falls through to the orphan sweep below

            for cfg in configs:
                org_id = cfg.organization_id
                log_days = int(cfg.log_retention_days or 30)
                flow_days = int(cfg.flow_retention_days or 7)

                # Bind parameters for the interval — never interpolate
                # user-derived integers into SQL.
                logs_res = await session.execute(
                    text(
                        "DELETE FROM collector.collector_logs "
                        "WHERE organization_id = :org "
                        "AND timestamp < NOW() - make_interval(days => :days)"
                    ),
                    {"org": org_id, "days": log_days},
                )
                flows_res = await session.execute(
                    text(
                        "DELETE FROM collector.flow_records "
                        "WHERE organization_id = :org "
                        "AND bucket_time < NOW() - make_interval(days => :days)"
                    ),
                    {"org": org_id, "days": flow_days},
                )
                logs_deleted = int(logs_res.rowcount or 0)
                flows_deleted = int(flows_res.rowcount or 0)
                results["orgs"][str(org_id)] = {
                    "logs_deleted": logs_deleted,
                    "flows_deleted": flows_deleted,
                    "log_retention_days": log_days,
                    "flow_retention_days": flow_days,
                }
                results["logs_deleted"] += logs_deleted
                results["flows_deleted"] += flows_deleted

            # Orphan sweep: rows with NULL organization_id (e.g. legacy
            # rows from the pre-fix era when receivers weren't tagging
            # org_id). Use a conservative 30-day floor.
            orphan_logs = await session.execute(
                text(
                    "DELETE FROM collector.collector_logs "
                    "WHERE organization_id IS NULL "
                    "AND timestamp < NOW() - INTERVAL '30 days'"
                )
            )
            orphan_flows = await session.execute(
                text(
                    "DELETE FROM collector.flow_records "
                    "WHERE organization_id IS NULL "
                    "AND bucket_time < NOW() - INTERVAL '7 days'"
                )
            )
            results["orphan_logs_deleted"] = int(orphan_logs.rowcount or 0)
            results["orphan_flows_deleted"] = int(orphan_flows.rowcount or 0)
            results["logs_deleted"] += results["orphan_logs_deleted"]
            results["flows_deleted"] += results["orphan_flows_deleted"]

            await session.commit()

        results["success"] = True
        return results

    return asyncio.run(_run())


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    base=FreeSDNTask,
    name="app.tasks.maintenance.cleanup_stale_applying_changes",
    soft_time_limit=60,
    time_limit=120,
)
def cleanup_stale_applying_changes(self: Any) -> dict[str, Any]:
    """
    Sweep ``adapter_pending_changes`` rows stuck in ``applying`` state.

    The applier flips a row to ``applying`` inside ``SELECT … FOR
    UPDATE`` and back to ``applied``/``failed`` on completion. If the
    worker crashes between those two writes, the row stays
    ``applying`` and blocks any subsequent retry on the same gateway
    (the apply endpoint refuses non-pending rows).

    ``AdapterStagingService._recover_stale_applying`` already does
    opportunistic recovery, but only fires when something ELSE calls
    ``stage_change`` or ``list_pending``. If no traffic hits the
    service, the row sits forever. This task closes that gap with a
    scheduled scan independent of request traffic.

    Runs every minute via beat. The recovery is org-agnostic (passes
    ``organization_id=None``) so all tenants get swept in one call.
    """

    async def _run() -> dict[str, Any]:
        from app.services.adapter_staging import AdapterStagingService

        async with AsyncSessionLocal() as session:
            svc = AdapterStagingService(session)
            recovered = await svc._recover_stale_applying(
                organization_id=None,
            )
        if recovered:
            logger.warning(
                "Recovered %d stale 'applying' pending-change rows",
                recovered,
            )
        return {"success": True, "recovered": recovered}

    return asyncio.run(_run())
