# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Every metric name the product reads is one something writes.

analytics.metric_data is keyed by a free-text metric name, so a reader and a
writer that spell a concept differently never meet and nobody is told: the
query just returns no rows. That is how the AI bandwidth tool read
"bytes_rx"/"bytes_tx" and the device traffic endpoint read "device.rx_bytes"
for the same thing, while nothing wrote either, and how the health score read
device.cpu_usage for months before anything wrote it.

The registry is ``STANDARD_METRICS`` (app/services/analytics.py) for names an
operator can query and the collector's ``COLLECTED_METRICS`` for names actually
written. This scans the app for every literal metric name in a read position
and requires it to be registered AND collected, or listed below as a known,
explained gap. The next reader of a name nothing writes fails here.
"""

from __future__ import annotations

import ast
import pathlib
import re

from app.services.analytics import DEVICE_TRAFFIC_METRICS, STANDARD_METRICS
from app.tasks.analytics import COLLECTED_METRICS

APP = pathlib.Path(__file__).resolve().parents[2] / "app"

_NAME = re.compile(r"^[a-z_]+\.[a-z_.]+$")

# Calls whose string arguments / ``metric_name=`` keyword name a metric series.
_READ_CALLS = {"query", "get_latest", "get_latest_metric", "query_metrics"}

# Read but not collected, each with the reason. Shrink this; never grow it
# without a reason as good as these.
_TRAFFIC_GAP = (
    "per-device traffic: adapters report cumulative counters since boot, and "
    "rates need per-device state the collector does not keep yet; both readers "
    "say no data instead of reporting 0 as idle"
)
NOT_YET_COLLECTED: dict[str, str] = {
    **dict.fromkeys(DEVICE_TRAFFIC_METRICS, _TRAFFIC_GAP),
    # Site traffic page and site network stats (api/v1/endpoints/analytics.py).
    # Same root cause as device traffic; the page builds its buckets from the
    # throughput series, so collecting the client count alone would not show.
    **dict.fromkeys(
        (
            "network.throughput_rx",
            "network.throughput_tx",
            "network.client_count",
            "network.wan_utilization",
        ),
        "site traffic: " + _TRAFFIC_GAP,
    ),
    # Read only by the in-memory AnalyticsService.get_dashboard_summary, which
    # nothing instantiates (get_analytics_service has no caller): dead reads of
    # a store nothing feeds. Delete that class or wire it, then drop these.
    **dict.fromkeys(
        ("client.count", "alert.active_count"),
        "dead in-memory AnalyticsService; no caller",
    ),
}


def _constants(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [c.value for c in node.elts if isinstance(c, ast.Constant)]
    return []


def _read_names_in(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    # A comparison against the metric_name column is a metric name whatever it
    # looks like ("bytes_rx" had no dot); call arguments must look like one,
    # because ``query`` is a common method name.
    column: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            label = getattr(func, "attr", getattr(func, "id", ""))
            if label in _READ_CALLS:
                for arg in node.args:
                    found.update(_constants(arg))
                for kw in node.keywords:
                    if kw.arg == "metric_name":
                        found.update(_constants(kw.value))
            # MetricDataPoint.metric_name.in_([...])
            if (
                label == "in_"
                and isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "metric_name"
            ):
                for arg in node.args:
                    column.update(_constants(arg))
        # MetricDataPoint.metric_name == "..."
        elif isinstance(node, ast.Compare) and (
            isinstance(node.left, ast.Attribute) and node.left.attr == "metric_name"
        ):
            for comparator in node.comparators:
                column.update(_constants(comparator))
    return {name for name in found if _NAME.match(name)} | column


def read_metric_names() -> dict[str, set[str]]:
    reads: dict[str, set[str]] = {}
    for path in sorted(APP.rglob("*.py")):
        if "__pycache__" in path.parts or "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "metric" not in text:
            continue
        for name in _read_names_in(ast.parse(text)):
            reads.setdefault(name, set()).add(str(path.relative_to(APP)))
    return reads


def test_the_scan_sees_the_known_readers():
    # Guard against a scan that silently finds nothing.
    reads = read_metric_names()
    assert {"device.status", "device.cpu_usage", "device.memory_usage"} <= set(reads)


def test_every_read_metric_is_registered_and_collected():
    problems = []
    for name, where in sorted(read_metric_names().items()):
        if name in NOT_YET_COLLECTED:
            continue
        if name not in STANDARD_METRICS:
            problems.append(f"{name} (read in {sorted(where)}) is not in STANDARD_METRICS")
        elif name not in COLLECTED_METRICS:
            problems.append(f"{name} (read in {sorted(where)}) is written by nothing")
    assert not problems, "\n".join(problems)


def test_the_traffic_readers_use_the_registry_names():
    reads = read_metric_names()
    for path in ("modules/ai/tools/diagnostics.py", "modules/network/api.py"):
        text = (APP / path).read_text(encoding="utf-8")
        assert "DEVICE_" in text, f"{path} spells traffic metric names by hand"
    # And nobody reads the old spelling any more.
    assert not {"bytes_rx", "bytes_tx"} & set(reads)


def test_every_collected_metric_is_registered():
    # So an operator can find it under /analytics/metrics/definitions.
    assert set(STANDARD_METRICS) >= COLLECTED_METRICS


def test_the_known_gap_is_not_silently_collected_too():
    # If a collector starts writing a traffic name, remove it from the gap list.
    assert not set(NOT_YET_COLLECTED) & COLLECTED_METRICS


# --------------------------------------------------------------------------
# The AI bandwidth tool actually reads the LogDB now (real databases)
# --------------------------------------------------------------------------


async def test_the_bandwidth_tool_reads_registry_named_points_from_the_logdb(monkeypatch):
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    from sqlalchemy import delete, text

    from app.core.dependencies import CurrentUser
    from app.db import session as db_session
    from app.db.base import LogBase
    from app.db.session import CelerySessionLocal, get_logdb_celery_factory
    from app.models.analytics import MetricDataPoint
    from app.models.core import Organization, Site, User
    from app.models.devices import Device, DeviceStatus
    from app.modules.ai.tools.diagnostics import _get_bandwidth_usage
    from app.services.analytics import DEVICE_RX_BYTES, DEVICE_TX_BYTES

    logdb_factory = get_logdb_celery_factory()
    monkeypatch.setattr(db_session, "logdb_session_factory", logdb_factory)
    async with logdb_factory() as logdb:
        await logdb.execute(text("CREATE SCHEMA IF NOT EXISTS analytics"))
        await logdb.commit()
        conn = await logdb.connection()
        await conn.run_sync(
            lambda sync: LogBase.metadata.create_all(sync, tables=[MetricDataPoint.__table__])
        )
        await logdb.commit()

    org, site, device = uuid4(), uuid4(), uuid4()
    async with CelerySessionLocal() as db:
        db.add(Organization(id=org, name="bw", slug="bw-" + org.hex))
        await db.flush()
        db.add(Site(id=site, name="bw", slug="bw-" + site.hex, organization_id=org))
        await db.flush()
        db.add(
            Device(
                id=device,
                site_id=site,
                name="sw",
                device_type="switch",
                status=DeviceStatus.ONLINE,
            )
        )
        await db.commit()
    user = CurrentUser(
        user=User(
            id=uuid4(),
            email="bw@example.com",
            organization_id=org,
            role="org_admin",
            hashed_password="x",
            is_active=True,
        ),
        permissions=["device:read"],
        accessible_site_ids=set(),
    )
    try:
        async with CelerySessionLocal() as db:
            empty = await _get_bandwidth_usage(user, db, str(device), hours=1)
        assert empty["samples"] == 0 and empty["avg_rx_bps"] is None
        assert "does not collect" in empty["note"]

        now = datetime.now(UTC)
        async with logdb_factory() as logdb:
            for i, (name, value) in enumerate(
                [(DEVICE_RX_BYTES, 100.0), (DEVICE_RX_BYTES, 300.0), (DEVICE_TX_BYTES, 50.0)]
            ):
                logdb.add(
                    MetricDataPoint(
                        time=now - timedelta(minutes=i + 1),
                        metric_name=name,
                        labels_hash=f"bw{i}",
                        value=value,
                        organization_id=org,
                        site_id=site,
                        device_id=device,
                    )
                )
            await logdb.commit()

        async with CelerySessionLocal() as db:
            answer = await _get_bandwidth_usage(user, db, str(device), hours=1)
        assert answer["avg_rx_bps"] == 200.0
        assert answer["avg_tx_bps"] == 50.0
        assert answer["samples"] == 2 and "note" not in answer
    finally:
        async with logdb_factory() as logdb:
            await logdb.execute(delete(MetricDataPoint).where(MetricDataPoint.device_id == device))
            await logdb.commit()
        async with CelerySessionLocal() as db:
            await db.execute(delete(Device).where(Device.id == device))
            await db.execute(delete(Site).where(Site.id == site))
            await db.execute(delete(Organization).where(Organization.id == org))
            await db.commit()
