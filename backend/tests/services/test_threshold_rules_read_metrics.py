# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A threshold alert rule on a metric fires from the metric's latest value.

``evaluate_threshold_rule`` read only EventRecord rows whose event_type
LIKE-matched the metric name with its underscores stripped -- for
``device.cpu_usage`` that is ``%device.cpuusage%``, which no event is called --
so "CPU above 90 %" could never fire however hot a device ran. Metrics live in
analytics.metric_data; the rule now reads the latest point of each series there.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest_asyncio
from sqlalchemy import delete, select, text

from app.db.base import LogBase
from app.db.session import CelerySessionLocal, get_logdb_celery_factory
from app.models.alert_rules import Alert, AlertRule
from app.models.analytics import MetricDataPoint
from app.models.core import Organization, Site
from app.models.devices import Device, DeviceStatus
from app.services.alert_rules import AlertRuleService


async def _ensure_metric_table() -> None:
    async with get_logdb_celery_factory()() as logdb:
        await logdb.execute(text("CREATE SCHEMA IF NOT EXISTS analytics"))
        await logdb.commit()
        conn = await logdb.connection()
        await conn.run_sync(
            lambda sync: LogBase.metadata.create_all(sync, tables=[MetricDataPoint.__table__])
        )
        await logdb.commit()


@pytest_asyncio.fixture
async def fleet(monkeypatch):
    await _ensure_metric_table()
    org, site, hot, cool = uuid4(), uuid4(), uuid4(), uuid4()
    async with CelerySessionLocal() as db:
        db.add(Organization(id=org, name="Threshold fixture", slug="thr-" + org.hex))
        await db.flush()
        db.add(Site(id=site, name="Threshold site", slug="thr-" + site.hex, organization_id=org))
        await db.flush()
        for device_id, name in ((hot, "hot"), (cool, "cool")):
            db.add(
                Device(
                    id=device_id,
                    site_id=site,
                    name=name,
                    device_type="switch",
                    status=DeviceStatus.ONLINE,
                )
            )
        await db.commit()
    # NullPool LogDB sessions: the pooled API engine would outlive this loop.
    monkeypatch.setattr(AlertRuleService, "_logdb_factory", staticmethod(get_logdb_celery_factory))
    try:
        yield {"org": org, "site": site, "hot": hot, "cool": cool}
    finally:
        async with get_logdb_celery_factory()() as logdb:
            await logdb.execute(
                delete(MetricDataPoint).where(MetricDataPoint.organization_id == org)
            )
            await logdb.commit()
        async with CelerySessionLocal() as db:
            await db.execute(delete(Alert).where(Alert.organization_id == org))
            await db.execute(delete(AlertRule).where(AlertRule.organization_id == org))
            await db.execute(delete(Device).where(Device.id.in_([hot, cool])))
            await db.execute(delete(Site).where(Site.id == site))
            await db.execute(delete(Organization).where(Organization.id == org))
            await db.commit()


async def _points(fleet, *readings):
    """readings: (device key, value, seconds ago)."""
    now = datetime.now(UTC)
    async with get_logdb_celery_factory()() as logdb:
        for key, value, ago in readings:
            device_id = fleet[key]
            labels = {"device_id": str(device_id), "site_id": str(fleet["site"])}
            logdb.add(
                MetricDataPoint(
                    time=now - timedelta(seconds=ago),
                    metric_name="device.cpu_usage",
                    labels_hash=str(device_id).replace("-", "")[:16],
                    value=value,
                    labels=labels,
                    organization_id=fleet["org"],
                    site_id=fleet["site"],
                    device_id=device_id,
                )
            )
        await logdb.commit()


async def _evaluate(fleet) -> tuple[dict, list[Alert]]:
    async with CelerySessionLocal() as db:
        db.add(
            AlertRule(
                organization_id=fleet["org"],
                name="CPU hot",
                rule_type="threshold",
                severity="critical",
                conditions={"metric": "device.cpu_usage", "operator": ">", "value": 90},
                check_interval_seconds=300,
            )
        )
        await db.flush()
        result = await AlertRuleService(db).evaluate_all_rules(fleet["org"])
        await db.commit()
    async with CelerySessionLocal() as db:
        alerts = list(
            (await db.execute(select(Alert).where(Alert.organization_id == fleet["org"])))
            .scalars()
            .all()
        )
    return result, alerts


async def test_a_device_over_the_threshold_fires_one_alert_for_that_device(fleet):
    await _points(fleet, ("hot", 70.0, 240), ("hot", 96.5, 30), ("cool", 12.0, 30))

    result, alerts = await _evaluate(fleet)

    assert result["alerts_fired"] == 1
    assert [(a.device_id, a.site_id) for a in alerts] == [(fleet["hot"], fleet["site"])]
    assert alerts[0].details["source"] == "analytics.metric_data"
    assert alerts[0].details["value"] == 96.5
    assert "device.cpu_usage is 96.5" in alerts[0].message


async def test_only_the_latest_reading_counts(fleet):
    # Hot five minutes ago, fine now: nothing to alert on.
    await _points(fleet, ("hot", 97.0, 300), ("hot", 40.0, 20))

    result, alerts = await _evaluate(fleet)

    assert result["alerts_fired"] == 0
    assert alerts == []
