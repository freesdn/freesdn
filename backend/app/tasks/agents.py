# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Agent Management Tasks
=====================================

Celery tasks for remote agent lifecycle:
- Stale agent detection and cleanup
- Heartbeat data pruning
- Agent health monitoring and alerting
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.db.session import get_logdb_celery_factory
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)

# LogDB session factory for time-series writes (mandatory — requires LOGDB_URL)
# Lazy: defers RuntimeError to task execution, not module import
_logdb_factory = None


def _get_logdb():
    global _logdb_factory
    if _logdb_factory is None:
        _logdb_factory = get_logdb_celery_factory()
    return _logdb_factory


# =============================================================================
# Stale Agent Cleanup
# =============================================================================


@celery_app.task(
    bind=True, base=FreeSDNTask, name="agents.cleanup_stale", soft_time_limit=120, time_limit=180
)  # type: ignore[misc,untyped-decorator]
def cleanup_stale_agents(
    self: Any,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Mark agents offline + dispatch notifications.

    Uses per-agent ``offline_threshold_seconds`` (default 180s = 3×
    default heartbeat interval) rather than a single global timeout.
    The ``timeout_seconds`` parameter is kept for backward compatibility
    with the prior signature; it's used as the fallback when an agent
    has the default threshold and the operator wants to override.

    When an agent transitions online → offline:
    - status flips to "offline", disconnected_at = now
    - notification_channels on the agent gets a dispatch (if set)
    - offline_notified_at = now to dedup repeat alerts

    Runs on Celery Beat (every 60s recommended).
    """

    async def _run() -> dict[str, Any]:
        from app.models.agents import RemoteAgent
        from app.services.notification_helpers import dispatch_notifications

        now = datetime.now(UTC)

        async with AsyncSessionLocal() as session:
            # Pull every online agent whose last_heartbeat is older than
            # the per-agent threshold. We do this in Python (instead of
            # one SQL UPDATE) because we need the row data for the
            # notification dispatch + to bump offline_notified_at.
            q = await session.execute(
                select(RemoteAgent).where(
                    RemoteAgent.status == "online",
                    RemoteAgent.deleted_at.is_(None),
                    RemoteAgent.last_heartbeat.isnot(None),
                )
            )
            online_agents = q.scalars().all()

            count_offline = 0
            count_notified = 0
            for agent in online_agents:
                threshold = agent.offline_threshold_seconds or timeout_seconds
                if agent.last_heartbeat is None:
                    continue
                age = (now - agent.last_heartbeat).total_seconds()
                if age < threshold:
                    continue
                # Transition to offline
                agent.status = "offline"
                agent.disconnected_at = now
                count_offline += 1

                # Dispatch alert if channels configured + not already
                # notified for THIS offline transition
                if agent.notification_channels and agent.offline_notified_at is None:
                    title = f"[FreeSDN] Agent OFFLINE: {agent.name}"
                    body_lines = [
                        f"Agent: {agent.name}",
                        f"Agent ID: {agent.id}",
                        f"Site: {agent.site_id}",
                        f"Last heartbeat: {agent.last_heartbeat.isoformat()}",
                        f"Stale for: {int(age)} seconds (threshold {threshold}s)",
                    ]
                    try:
                        await dispatch_notifications(
                            session,
                            channels_config=agent.notification_channels,
                            title=title,
                            body="\n".join(body_lines),
                        )
                        agent.offline_notified_at = now
                        count_notified += 1
                    except Exception:
                        logger.exception(
                            "Failed to dispatch offline alert for agent %s",
                            agent.id,
                        )

            await session.commit()

            if count_offline > 0:
                logger.warning(
                    "Marked %d agent(s) as offline; dispatched %d alert(s)",
                    count_offline,
                    count_notified,
                )

            return {
                "success": True,
                "marked_offline": count_offline,
                "notifications_dispatched": count_notified,
                "checked_at": now.isoformat(),
            }

    return asyncio.run(_run())


# =============================================================================
# Heartbeat History Pruning
# =============================================================================


@celery_app.task(
    bind=True, base=FreeSDNTask, name="agents.purge_heartbeats", soft_time_limit=300, time_limit=360
)  # type: ignore[misc,untyped-decorator]
def purge_old_heartbeats(
    self: Any,
    retention_days: int = 7,
) -> dict[str, Any]:
    """
    Delete heartbeat records older than retention period.

    Runs on Celery Beat schedule (default: daily at 3 AM).

    Args:
        retention_days: Days to retain heartbeat records
    """

    async def _run() -> dict[str, Any]:
        from app.models.agents import AgentHeartbeat

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)

        async with _get_logdb()() as logdb:
            # Count before delete
            count_result = await logdb.execute(
                select(func.count(AgentHeartbeat.id)).where(AgentHeartbeat.timestamp < cutoff)
            )
            count = count_result.scalar() or 0

            if count == 0:
                return {
                    "success": True,
                    "message": f"No heartbeats older than {retention_days} days",
                    "deleted": 0,
                }

            self.update_progress(0, 1, f"Deleting {count} old heartbeat records...")

            # Delete in batches to avoid lock contention
            deleted = 0
            batch_size = 5000
            max_iterations = 100

            while max_iterations > 0:
                max_iterations -= 1
                result = await logdb.execute(
                    delete(AgentHeartbeat)
                    .where(AgentHeartbeat.timestamp < cutoff)
                    .execution_options(synchronize_session=False)
                )
                batch_deleted = result.rowcount or 0  # type: ignore[attr-defined]
                deleted += batch_deleted
                await logdb.commit()

                if batch_deleted < batch_size:
                    break

            self.update_progress(1, 1, f"Deleted {deleted} heartbeat records")

            logger.info(f"Purged {deleted} heartbeat records older than {retention_days} days")

            return {
                "success": True,
                "deleted": deleted,
                "retention_days": retention_days,
            }

    return asyncio.run(_run())


# =============================================================================
# Orphan Heartbeat Cleanup
# =============================================================================


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="agents.purge_orphan_heartbeats",
    soft_time_limit=300,
    time_limit=360,
)  # type: ignore[misc,untyped-decorator]
def purge_orphan_heartbeats(self: Any) -> dict[str, Any]:
    """
    Delete heartbeat records in LogDB whose agent no longer exists
    in the primary database (hard-deleted or org-cascade).

    This is a safety net for cross-database consistency.  The primary
    deletion path (soft_delete_agent) purges heartbeats immediately,
    but DB-level CASCADE (e.g. organization deletion) cannot reach
    across to LogDB.

    Runs on Celery Beat schedule (default: daily).
    """

    async def _run() -> dict[str, Any]:
        from app.models.agents import AgentHeartbeat, RemoteAgent

        # 1. Collect all agent_ids that have heartbeats in LogDB
        async with _get_logdb()() as logdb:
            hb_result = await logdb.execute(select(AgentHeartbeat.agent_id).distinct())
            logdb_agent_ids = {row[0] for row in hb_result.all()}

        if not logdb_agent_ids:
            return {"success": True, "orphan_agent_ids": 0, "deleted": 0}

        # 2. Check which of those agent_ids still exist in primary DB
        #    (include soft-deleted agents — their heartbeats were purged
        #    at soft-delete time; only truly missing IDs are orphans)
        async with AsyncSessionLocal() as session:
            existing_result = await session.execute(
                select(RemoteAgent.id).where(RemoteAgent.id.in_(logdb_agent_ids))
            )
            existing_agent_ids = {row[0] for row in existing_result.all()}

        orphan_ids = logdb_agent_ids - existing_agent_ids
        if not orphan_ids:
            return {"success": True, "orphan_agent_ids": 0, "deleted": 0}

        # 3. Purge heartbeats for orphaned agent_ids from LogDB
        async with _get_logdb()() as logdb:
            result = await logdb.execute(
                delete(AgentHeartbeat).where(AgentHeartbeat.agent_id.in_(list(orphan_ids)))
            )
            deleted = result.rowcount or 0
            await logdb.commit()

        logger.info(
            "Purged %d orphan heartbeat records for %d missing agent(s)",
            deleted,
            len(orphan_ids),
        )

        return {
            "success": True,
            "orphan_agent_ids": len(orphan_ids),
            "deleted": deleted,
        }

    return asyncio.run(_run())


# =============================================================================
# Agent Health Monitoring
# =============================================================================


@celery_app.task(
    bind=True, base=FreeSDNTask, name="agents.health_check", soft_time_limit=120, time_limit=180
)  # type: ignore[misc,untyped-decorator]
def check_agent_health(self: Any) -> dict[str, Any]:
    """
    Check all online agents' health metrics and raise alerts
    if thresholds are exceeded.

    Runs on Celery Beat schedule (default: every 5 minutes).

    Thresholds:
    - CPU > 90% sustained
    - Memory > 90%
    - Disk > 85%
    - No heartbeat in 60 seconds
    """

    async def _run() -> dict[str, Any]:
        from app.models.agents import AgentHeartbeat, RemoteAgent

        alerts: list[dict[str, Any]] = []
        now = datetime.now(UTC)

        # Read agent list from primary DB
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(RemoteAgent).where(
                    RemoteAgent.status == "online",
                    RemoteAgent.deleted_at.is_(None),
                )
            )
            # Pull organization_id alongside identity so the alert
            # event can carry Event.organization_id for cross-tenant
            # WS routing. Without it, agent.health.*
            # events would be dropped by the fail-closed WS router.
            agents = [
                (a.id, a.name, a.last_heartbeat, a.organization_id) for a in result.scalars().all()
            ]

        # Query latest heartbeat metrics from LogDB (time-series database)
        async with _get_logdb()() as logdb:
            for agent_id, agent_name, last_heartbeat, agent_org_id in agents:
                # Check heartbeat freshness (from primary DB timestamp)
                if last_heartbeat:
                    elapsed = (now - last_heartbeat).total_seconds()
                    if elapsed > 60:
                        alerts.append(
                            {
                                "agent_id": str(agent_id),
                                "agent_name": agent_name,
                                "organization_id": (str(agent_org_id) if agent_org_id else None),
                                "type": "heartbeat_stale",
                                "message": f"No heartbeat for {int(elapsed)}s",
                            }
                        )

                # Get latest heartbeat metrics from LogDB
                hb_result = await logdb.execute(
                    select(AgentHeartbeat)
                    .where(AgentHeartbeat.agent_id == agent_id)
                    .order_by(AgentHeartbeat.timestamp.desc())
                    .limit(1)
                )
                latest_hb = hb_result.scalar_one_or_none()

                if latest_hb:
                    org_str = str(agent_org_id) if agent_org_id else None
                    if latest_hb.cpu_percent > 90:
                        alerts.append(
                            {
                                "agent_id": str(agent_id),
                                "agent_name": agent_name,
                                "organization_id": org_str,
                                "type": "high_cpu",
                                "value": latest_hb.cpu_percent,
                                "message": f"CPU at {latest_hb.cpu_percent:.1f}%",
                            }
                        )

                    if latest_hb.memory_percent > 90:
                        alerts.append(
                            {
                                "agent_id": str(agent_id),
                                "agent_name": agent_name,
                                "organization_id": org_str,
                                "type": "high_memory",
                                "value": latest_hb.memory_percent,
                                "message": f"Memory at {latest_hb.memory_percent:.1f}%",
                            }
                        )

                    if latest_hb.disk_percent > 85:
                        alerts.append(
                            {
                                "agent_id": str(agent_id),
                                "agent_name": agent_name,
                                "organization_id": org_str,
                                "type": "high_disk",
                                "value": latest_hb.disk_percent,
                                "message": f"Disk at {latest_hb.disk_percent:.1f}%",
                            }
                        )

        if alerts:
            logger.warning(
                "Agent health check: %d alert(s) for %d agent(s)",
                len(alerts),
                len({a["agent_id"] for a in alerts}),
            )
            # Publish each alert to the event bus. ``organization_id``
            # on the Event is required for cross-tenant WS routing —
            # the fail-closed router drops events without it.
            from app.core.events import Event, EventCategory, EventPriority, get_event_bus

            bus = get_event_bus()
            for alert in alerts:
                await bus.publish(
                    Event(
                        event_type=f"agent.health.{alert['type']}",
                        category=EventCategory.DEVICE,
                        priority=EventPriority.HIGH,
                        organization_id=alert.get("organization_id"),
                        payload=alert,
                    )
                )

        return {
            "success": True,
            "agents_checked": len(agents),
            "alerts": alerts,
            "alert_count": len(alerts),
        }

    return asyncio.run(_run())


# =============================================================================
# Task Timeout Cleanup
# =============================================================================


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="agents.cleanup_stuck_tasks",
    soft_time_limit=120,
    time_limit=180,
)  # type: ignore[misc,untyped-decorator]
def cleanup_stuck_tasks(
    self: Any,
    timeout_minutes: int = 30,
) -> dict[str, Any]:
    """
    Mark running tasks as failed if they have been running
    longer than the timeout period.

    Runs on Celery Beat schedule (default: every 10 minutes).

    Args:
        timeout_minutes: Minutes before a running task is considered stuck
    """

    async def _run() -> dict[str, Any]:
        from app.models.agents import AgentTask

        cutoff = datetime.now(UTC) - timedelta(minutes=timeout_minutes)
        now = datetime.now(UTC)

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                update(AgentTask)
                .where(
                    AgentTask.status == "running",
                    AgentTask.started_at < cutoff,
                )
                .values(
                    status="failed",
                    error_message=f"Task timed out after {timeout_minutes} minutes",
                    completed_at=now,
                )
            )
            count = result.rowcount or 0  # type: ignore[attr-defined]
            await session.commit()

            if count > 0:
                logger.warning("Marked %s stuck task(s) as failed", count)

            return {
                "success": True,
                "failed_tasks": count,
                "timeout_minutes": timeout_minutes,
            }

    return asyncio.run(_run())


@celery_app.task(
    bind=True, base=FreeSDNTask, name="agents.notify_offline", soft_time_limit=60, time_limit=90
)  # type: ignore[misc,untyped-decorator]
def notify_offline_agent(
    self: Any,
    agent_id: str,
    agent_name: str,
    site_id: str,
    last_heartbeat_iso: str,
    stale_seconds: int,
    channels: dict[str, Any],
) -> dict[str, Any]:
    """Dispatch an agent-offline alert as a separate task.

    cleanup_stale_agents previously did all
    dispatches inline, holding the periodic-task slot for as long as
    the slowest SMTP / Slack RTT. Push the dispatch + the
    offline_notified_at flag update out to this task so the periodic
    loop returns quickly + concurrent agents alert in parallel.
    """
    from uuid import UUID

    from sqlalchemy import update as _update

    from app.models.agents import RemoteAgent
    from app.services.notification_helpers import dispatch_notifications

    async def _run() -> dict[str, Any]:
        title = f"[FreeSDN] Agent OFFLINE: {agent_name}"
        body = "\n".join(
            [
                f"Agent: {agent_name}",
                f"Agent ID: {agent_id}",
                f"Site: {site_id}",
                f"Last heartbeat: {last_heartbeat_iso}",
                f"Stale for: {stale_seconds} seconds",
            ]
        )
        async with AsyncSessionLocal() as session:
            try:
                await dispatch_notifications(
                    session,
                    channels_config=channels,
                    title=title,
                    body=body,
                )
            except Exception:
                logger.exception("Offline alert dispatch failed for %s", agent_id)
                return {"success": False}

            # Mark notified so the periodic detector skips this agent
            # until reconnect (which clears the flag in the WS handler).
            await session.execute(
                _update(RemoteAgent)
                .where(RemoteAgent.id == UUID(agent_id))
                .values(offline_notified_at=datetime.now(UTC))
            )
            await session.commit()
        return {"success": True}

    return asyncio.run(_run())
