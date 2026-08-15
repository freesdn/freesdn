# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Analytics Celery Tasks
=====================================

Background tasks for the analytics module:
- collect_device_metrics: Periodic metric collection from all devices
- aggregate_metrics: Downsample raw data into time buckets
- purge_old_metrics: Delete data past retention
- check_metric_thresholds: Evaluate alert rules
- resolve_stale_alerts: Auto-resolve old alerts
"""

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

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


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="analytics.collect_device_metrics",
    soft_time_limit=120,
    time_limit=180,
)
def collect_device_metrics(self) -> dict[str, Any]:
    """
    Collect CPU, memory, uptime metrics for all online devices
    and insert into the analytics.metric_data hypertable.
    """

    async def _run() -> dict[str, Any]:
        from app.models.devices import Device, DeviceStatus
        from app.services.analytics import PersistentAnalyticsService as svc

        collected = 0
        errors = 0

        # Read device list from primary DB
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Device).where(Device.status == DeviceStatus.ONLINE)
            )
            online_devices = [(d.id, d.site_id) for d in result.scalars().all()]
            result_offline = await session.execute(
                select(Device).where(Device.status == DeviceStatus.OFFLINE)
            )
            offline_devices = [(d.id, d.site_id) for d in result_offline.scalars().all()]

        # Write metrics to LogDB (time-series database)
        async with _get_logdb()() as logdb:
            for device_id, site_id in online_devices:
                try:
                    await svc.record_metric(
                        logdb,
                        metric_name="device.status",
                        value=1.0,
                        labels={"device_id": str(device_id), "site_id": str(site_id)},
                        site_id=site_id,
                        device_id=device_id,
                    )
                    collected += 1
                except Exception as e:
                    logger.debug("Error collecting metrics for device %s: %s", device_id, e)
                    errors += 1

            for device_id, site_id in offline_devices:
                with contextlib.suppress(SQLAlchemyError):
                    await svc.record_metric(
                        logdb,
                        metric_name="device.status",
                        value=0.0,
                        labels={"device_id": str(device_id), "site_id": str(site_id)},
                        site_id=site_id,
                        device_id=device_id,
                    )

            await logdb.commit()

        return {
            "collected": collected,
            "errors": errors,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="analytics.purge_old_metrics",
    soft_time_limit=300,
    time_limit=360,
)
def purge_old_metrics(self, retention_hours: int = 168) -> dict[str, Any]:
    """Delete metric data older than retention period (default 7 days)."""

    async def _run() -> dict[str, Any]:
        from app.services.analytics import PersistentAnalyticsService as svc

        async with _get_logdb()() as logdb:
            deleted = await svc.purge_old_metrics(logdb, retention_hours=retention_hours)
            await logdb.commit()

        return {
            "deleted_rows": deleted,
            "retention_hours": retention_hours,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="analytics.check_metric_thresholds",
    soft_time_limit=120,
    time_limit=180,
)
def check_metric_thresholds(self) -> dict[str, Any]:
    """
    Evaluate alert rules by checking latest metric values against
    defined thresholds in metric_definitions.
    """

    async def _run() -> dict[str, Any]:
        from app.models.analytics import MetricDefinitionRecord
        from app.services.analytics import PersistentAnalyticsService as svc

        alerts_created = 0

        # Read metric definitions from primary DB
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(MetricDefinitionRecord).where(
                    MetricDefinitionRecord.is_active,
                    MetricDefinitionRecord.critical_threshold.isnot(None),
                )
            )
            definitions = result.scalars().all()

        # Read latest metric values from LogDB, write alerts to primary
        async with _get_logdb()() as logdb:
            async with AsyncSessionLocal() as session:
                for defn in definitions:
                    try:
                        latest = await svc.get_latest_metric(logdb, defn.name)
                        if not latest:
                            continue

                        value = latest["value"]["value"]
                        threshold = defn.critical_threshold

                        if not threshold or "value" not in threshold:
                            continue

                        operator = threshold.get("operator", ">")
                        threshold_val = threshold["value"]

                        triggered = False
                        if (
                            operator == ">"
                            and value > threshold_val
                            or operator == "<"
                            and value < threshold_val
                            or operator == ">="
                            and value >= threshold_val
                            or operator == "<="
                            and value <= threshold_val
                        ):
                            triggered = True

                        if triggered:
                            await svc.create_alert(
                                session,
                                {
                                    "severity": "critical",
                                    "alert_type": "threshold",
                                    "title": f"{defn.display_name} threshold exceeded: {value:.1f} {operator} {threshold_val}",
                                    "metric_name": defn.name,
                                    "metric_value": {"value": value, "threshold": threshold_val},
                                },
                            )
                            alerts_created += 1

                    except Exception as e:
                        logger.debug("Error checking threshold for %s: %s", defn.name, e)

                await session.commit()

        return {
            "definitions_checked": len(definitions),
            "alerts_created": alerts_created,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="analytics.resolve_stale_alerts",
    soft_time_limit=120,
    time_limit=180,
)
def resolve_stale_alerts(self, hours: int = 72) -> dict[str, Any]:
    """Auto-resolve alerts older than the specified hours."""

    async def _run() -> dict[str, Any]:
        from app.services.analytics import PersistentAnalyticsService as svc

        async with AsyncSessionLocal() as session:
            resolved = await svc.resolve_stale_alerts(session, hours=hours)
            await session.commit()

        return {
            "resolved": resolved,
            "threshold_hours": hours,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    return asyncio.run(_run())
