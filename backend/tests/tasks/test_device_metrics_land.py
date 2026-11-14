# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Synced device metrics land in analytics.metric_data, and the readers find them.

Two collectors ran every five minutes and neither stored what the product reads:

* ``app.tasks.metrics.collect_all_device_metrics`` logged into each online
  device's controller, fetched its metrics and returned them to a Celery result
  nobody read;
* ``analytics.collect_device_metrics`` stored only ``device.status``.

Meanwhile the device health score, the device metrics view and anomaly rules
read ``device.cpu_usage`` / ``device.memory_usage`` / ``device.uptime`` from the
LogDB, which nothing wrote. On the soak VM every metric row was device.status.

This runs the real Celery task body against the real database: device rows as
controller sync leaves them -> collector -> rows in analytics.metric_data ->
``PersistentAnalyticsService.get_device_health`` reading them back.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text

from app.db.base import LogBase
from app.db.session import CelerySessionLocal, get_logdb_celery_factory
from app.models.analytics import MetricDataPoint
from app.models.core import Organization, Site
from app.models.devices import Device, DeviceClient, DeviceStatus
from app.services.analytics import PersistentAnalyticsService
from app.tasks import analytics as analytics_tasks


async def _ensure_metric_table() -> None:
    """Plain-Postgres test databases have no LogDB migration; create the table."""
    factory = get_logdb_celery_factory()
    async with factory() as logdb:
        await logdb.execute(text("CREATE SCHEMA IF NOT EXISTS analytics"))
        await logdb.commit()
        conn = await logdb.connection()
        await conn.run_sync(
            lambda sync: LogBase.metadata.create_all(sync, tables=[MetricDataPoint.__table__])
        )
        await logdb.commit()


@pytest.fixture
def estate():
    org, site = uuid4(), uuid4()
    ap, switch, stale, offline = uuid4(), uuid4(), uuid4(), uuid4()
    now = datetime.now(UTC)

    async def _create() -> None:
        await _ensure_metric_table()
        async with CelerySessionLocal() as db:
            db.add(Organization(id=org, name="Metrics fixture", slug="met-" + org.hex))
            await db.flush()
            db.add(Site(id=site, name="Metrics site", slug="met-" + site.hex, organization_id=org))
            await db.flush()
            db.add_all(
                [
                    Device(
                        id=ap,
                        site_id=site,
                        name="ap-1",
                        device_type="access_point",
                        status=DeviceStatus.ONLINE,
                        last_seen=now,
                        cpu_usage_percent=95.0,
                        memory_usage_percent=40.0,
                        uptime_seconds=86400,
                        temperature_celsius=51.5,
                    ),
                    Device(
                        id=switch,
                        site_id=site,
                        name="sw-1",
                        device_type="switch",
                        status=DeviceStatus.ONLINE,
                        last_seen=now,
                        cpu_usage_percent=12.0,
                    ),
                    # Online on paper, but its controller has not reported it for
                    # hours: its CPU figure is not a current reading.
                    Device(
                        id=stale,
                        site_id=site,
                        name="stale",
                        device_type="switch",
                        status=DeviceStatus.ONLINE,
                        last_seen=now - timedelta(hours=3),
                        cpu_usage_percent=99.0,
                    ),
                    Device(
                        id=offline,
                        site_id=site,
                        name="gone",
                        device_type="access_point",
                        status=DeviceStatus.OFFLINE,
                        last_seen=now - timedelta(hours=3),
                        cpu_usage_percent=5.0,
                    ),
                ]
            )
            await db.flush()
            db.add_all(
                [
                    DeviceClient(
                        device_id=ap,
                        mac_address=f"02:00:00:00:00:0{i}",
                        is_online=True,
                        last_seen=now,
                    )
                    for i in range(2)
                ]
                + [
                    # Left over from an old sync: not a current client.
                    DeviceClient(
                        device_id=ap,
                        mac_address="02:00:00:00:00:09",
                        is_online=True,
                        last_seen=now - timedelta(days=1),
                    )
                ]
            )
            await db.commit()

    async def _drop() -> None:
        ids = [ap, switch, stale, offline]
        async with get_logdb_celery_factory()() as logdb:
            await logdb.execute(delete(MetricDataPoint).where(MetricDataPoint.device_id.in_(ids)))
            await logdb.commit()
        async with CelerySessionLocal() as db:
            await db.execute(delete(DeviceClient).where(DeviceClient.device_id.in_(ids)))
            await db.execute(delete(Device).where(Device.id.in_(ids)))
            await db.execute(delete(Site).where(Site.id == site))
            await db.execute(delete(Organization).where(Organization.id == org))
            await db.commit()

    asyncio.run(_create())
    try:
        yield {
            "org": org,
            "site": site,
            "ap": ap,
            "switch": switch,
            "stale": stale,
            "offline": offline,
        }
    finally:
        asyncio.run(_drop())


def _landed(device_ids) -> list[MetricDataPoint]:
    async def _read():
        async with get_logdb_celery_factory()() as logdb:
            rows = await logdb.execute(
                select(MetricDataPoint).where(MetricDataPoint.device_id.in_(device_ids))
            )
            return list(rows.scalars().all())

    return asyncio.run(_read())


def test_synced_device_metrics_land_with_tenant_and_one_series_per_metric(estate):
    analytics_tasks.collect_device_metrics.run()

    rows = _landed([estate[k] for k in ("ap", "switch", "stale", "offline")])
    by_device: dict = {}
    for row in rows:
        by_device.setdefault(row.device_id, {})[row.metric_name] = row.value
        # Every point is attributable: the analytics query filters on org.
        assert row.organization_id == estate["org"]
        assert row.site_id == estate["site"]
        assert row.labels == {"device_id": str(row.device_id), "site_id": str(estate["site"])}

    assert by_device[estate["ap"]] == {
        "device.status": 1.0,
        "device.cpu_usage": 95.0,
        "device.memory_usage": 40.0,
        "device.uptime": 86400.0,
        "device.temperature": 51.5,
        # Two current clients; the day-old row is not counted.
        "device.clients": 2.0,
    }
    # Only what the controller reported; a switch serving no client reports 0.
    assert by_device[estate["switch"]] == {
        "device.status": 1.0,
        "device.cpu_usage": 12.0,
        "device.clients": 0.0,
    }
    # A stale snapshot is not re-stamped as a current reading.
    assert by_device[estate["stale"]] == {"device.status": 1.0}
    assert by_device[estate["offline"]] == {"device.status": 0.0}
    # One point per series per run (sane cardinality).
    assert len(rows) == sum(len(m) for m in by_device.values())


def test_the_health_score_reads_what_the_collector_stored(estate):
    analytics_tasks.collect_device_metrics.run()

    async def _health():
        async with CelerySessionLocal() as db, get_logdb_celery_factory()() as logdb:
            return await PersistentAnalyticsService.get_device_health(db, logdb, estate["ap"])

    health = asyncio.run(_health())
    assert health is not None
    assert "CPU over 90%" in health["health_issues"], health
    assert health["cpu_usage"] == 95.0
