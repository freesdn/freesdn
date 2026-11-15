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
from datetime import UTC, datetime, timedelta
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


# A device row's resource columns are a snapshot from the last controller sync
# or discovery. Only devices seen within this window get resource points, so a
# value the controller stopped reporting is not re-stamped as current forever.
_FRESH_FOR = timedelta(minutes=15)

# metric name -> Device column. Units: percent, percent, seconds, Celsius.
_RESOURCE_COLUMNS = (
    ("device.cpu_usage", "cpu_usage_percent"),
    ("device.memory_usage", "memory_usage_percent"),
    ("device.uptime", "uptime_seconds"),
    ("device.temperature", "temperature_celsius"),
)

# Every metric name this collector writes. Readers must use one of these or a
# name explicitly recorded as not yet collected (tests/tasks/test_metric_names_agree.py).
COLLECTED_METRICS = frozenset(
    {"device.status", "device.clients", *(name for name, _ in _RESOURCE_COLUMNS)}
)

# Device types whose client count means something (APs, switches, gateways).
_CLIENT_SERVING_TYPES = frozenset({"access_point", "switch", "router", "gateway", "firewall"})


async def _resource_points(
    session: Any, online_ids: list[Any], online_rows: list[Any]
) -> list[dict[str, Any]]:
    """Build resource metric points for online devices from their synced rows."""
    if not online_ids:
        return []
    from sqlalchemy import func

    from app.models.devices import Device, DeviceClient

    now = datetime.now(UTC)
    fresh_after = now - _FRESH_FOR
    org_by_device = {row[0]: (row[1], row[2]) for row in online_rows}

    devices = (
        await session.execute(
            select(
                Device.id,
                Device.device_type,
                Device.last_seen,
                *(getattr(Device, column) for _, column in _RESOURCE_COLUMNS),
            ).where(Device.id.in_(online_ids), Device.deleted_at.is_(None))
        )
    ).all()
    clients = dict(
        (
            await session.execute(
                select(DeviceClient.device_id, func.count(DeviceClient.id))
                .where(
                    DeviceClient.device_id.in_(online_ids),
                    DeviceClient.is_online.is_(True),
                    DeviceClient.last_seen >= fresh_after,
                )
                .group_by(DeviceClient.device_id)
            )
        ).all()
    )

    points: list[dict[str, Any]] = []
    for row in devices:
        device_id, device_type, last_seen = row[0], row[1], row[2]
        if last_seen is None or last_seen < fresh_after:
            continue
        site_id, organization_id = org_by_device[device_id]
        base = {
            "labels": {"device_id": str(device_id), "site_id": str(site_id)},
            "organization_id": organization_id,
            "site_id": site_id,
            "device_id": device_id,
            "timestamp": now,
        }
        for (metric_name, _column), value in zip(_RESOURCE_COLUMNS, row[3:], strict=True):
            if value is not None:
                points.append({**base, "metric_name": metric_name, "value": float(value)})
        if str(getattr(device_type, "value", device_type)) in _CLIENT_SERVING_TYPES:
            points.append(
                {**base, "metric_name": "device.clients", "value": float(clients.get(device_id, 0))}
            )
    return points


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="analytics.collect_device_metrics",
    soft_time_limit=120,
    time_limit=180,
)
def collect_device_metrics(self) -> dict[str, Any]:
    """
    Record device status and resource metrics in the analytics.metric_data hypertable.

    Every device: ``device.status`` (1 online / 0 offline). Every ONLINE device
    seen in the last ``_FRESH_FOR``: ``device.cpu_usage``, ``device.memory_usage``,
    ``device.uptime`` and ``device.temperature`` where the controller reports
    them, and ``device.clients`` for devices that serve clients.

    The values come from the device rows that controller sync and discovery
    keep current. Nothing here contacts a device: the earlier per-device
    collector (``app.tasks.metrics.collect_all_device_metrics``) logged into a
    device's controller once per device every five minutes and then discarded
    what it fetched, while the health score, device detail and anomaly rules
    read ``device.cpu_usage`` / ``device.memory_usage`` / ``device.uptime``
    that nothing ever wrote. One series per device per metric.
    """

    async def _run() -> dict[str, Any]:
        from app.models.devices import Device, DeviceStatus
        from app.services.analytics import PersistentAnalyticsService as svc

        collected = 0
        errors = 0

        from app.models.core import Site

        # Read device list from primary DB, joined to Site for the organization.
        #
        # ORGANIZATION_ID IS THE POINT OF THIS JOIN. Metrics were written with
        # site_id and device_id but organization_id NULL, and the analytics
        # query endpoint hard-codes ``filters["organization_id"] = str(org)``
        # for tenant isolation. So the filter was correct and matched nothing:
        # 25,720 rows in the hypertable and ``/analytics/metrics/query``
        # returned ``data_points: []`` for every operator, always. Confirmed
        # against the live instance before this was changed. Device carries no
        # organization_id of its own; it reaches one through its Site.
        #
        # The soft-delete filters are the same class of bug one level down: a
        # deleted device kept producing status points forever, and a deleted
        # site's devices were still collected under an organization that no
        # longer lists them.
        def _devices_with(status: Any) -> Any:
            return (
                select(Device.id, Device.site_id, Site.organization_id)
                .join(Site, Device.site_id == Site.id)
                .where(
                    Device.status == status,
                    Device.alive(),
                    Site.alive(),
                )
            )

        async with AsyncSessionLocal() as session:
            result = await session.execute(_devices_with(DeviceStatus.ONLINE))
            online_devices = list(result.all())
            result_offline = await session.execute(_devices_with(DeviceStatus.OFFLINE))
            offline_devices = list(result_offline.all())
            resource_points = await _resource_points(
                session, [row[0] for row in online_devices], online_devices
            )

        # Write metrics to LogDB (time-series database)
        async with _get_logdb()() as logdb:
            for device_id, site_id, organization_id in online_devices:
                try:
                    await svc.record_metric(
                        logdb,
                        metric_name="device.status",
                        value=1.0,
                        labels={"device_id": str(device_id), "site_id": str(site_id)},
                        organization_id=organization_id,
                        site_id=site_id,
                        device_id=device_id,
                    )
                    collected += 1
                except Exception as e:
                    logger.debug("Error collecting metrics for device %s: %s", device_id, e)
                    errors += 1

            for device_id, site_id, organization_id in offline_devices:
                with contextlib.suppress(SQLAlchemyError):
                    await svc.record_metric(
                        logdb,
                        metric_name="device.status",
                        value=0.0,
                        labels={"device_id": str(device_id), "site_id": str(site_id)},
                        organization_id=organization_id,
                        site_id=site_id,
                        device_id=device_id,
                    )

            await logdb.commit()

            # Separate transaction: a failed resource batch must not take the
            # status points above down with it.
            if resource_points:
                try:
                    collected += await svc.record_metrics_batch(logdb, resource_points)
                    await logdb.commit()
                except SQLAlchemyError as e:
                    await logdb.rollback()
                    logger.warning("Could not record device resource metrics: %s", e)
                    errors += len(resource_points)

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
                                    # Attribute the alert to the tenant whose
                                    # reading breached. Omitting these left
                                    # organization_id NULL, and every reader
                                    # filters on it, so the alert was created
                                    # and then invisible to everyone.
                                    "organization_id": latest.get("organization_id"),
                                    "site_id": latest.get("site_id"),
                                    "device_id": latest.get("device_id"),
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
