"""Exercise raw analytics SQL against actual rows, including an empty grant set.

SQLite is sufficient here: raw queries do not call TimescaleDB functions. The
adapter presents the same two result attributes used from asyncpg. These tests
do not replace TimescaleDB aggregation or production-volume qualification.
"""

import sqlite3
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.services.analytics import PersistentAnalyticsService


class RowsSession:
    def __init__(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute("ATTACH DATABASE ':memory:' AS analytics")
        self.connection.execute(
            "CREATE TABLE analytics.metric_data "
            "(time TEXT, metric_name TEXT, value REAL, organization_id TEXT, site_id TEXT, device_id TEXT)"
        )
        self.now = datetime.now(UTC)
        self.connection.executemany(
            "INSERT INTO analytics.metric_data VALUES (?, ?, ?, ?, ?, ?)",
            [
                (self.now.isoformat(), "cpu", value, org, site, "device-" + site)
                for value, org, site in [
                    (11, "org-a", "site-a"),
                    (22, "org-a", "site-b"),
                    (99, "org-b", "site-c"),
                ]
            ],
        )

    async def execute(self, statement, params):
        bound = {
            key: value.isoformat() if isinstance(value, datetime) else value
            for key, value in params.items()
        }
        rows = self.connection.execute(str(statement), bound).fetchall()
        return SimpleNamespace(
            fetchall=lambda: [
                SimpleNamespace(bucket=datetime.fromisoformat(r[0]), agg_value=r[1]) for r in rows
            ]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ceiling,explicit,expected",
    [
        ([], None, []),
        ([], "site-a", []),
        (["site-a"], None, [11]),
        (["site-a"], "site-b", []),
        (["site-a", "site-b"], None, [11, 22]),
        (["site-c"], None, []),
        (["site-a') OR 1=1 --"], None, []),
    ],
)
async def test_raw_metrics_keep_grant_and_tenant_intersection(ceiling, explicit, expected):
    session = RowsSession()
    try:
        filters = {"organization_id": "org-a", "site_id_in": ceiling}
        if explicit is not None:
            filters["site_id"] = explicit
        actual = await PersistentAnalyticsService.query_metrics(
            session,
            "cpu",
            start_time=session.now - timedelta(seconds=1),
            end_time=session.now + timedelta(seconds=1),
            granularity="raw",
            filters=filters,
        )
        assert sorted(row["value"]["value"] for row in actual) == expected
    finally:
        session.connection.close()


@pytest.mark.asyncio
async def test_absent_ceiling_preserves_unrestricted_org_query():
    session = RowsSession()
    try:
        actual = await PersistentAnalyticsService.query_metrics(
            session,
            "cpu",
            start_time=session.now - timedelta(seconds=1),
            end_time=session.now + timedelta(seconds=1),
            granularity="raw",
            filters={"organization_id": "org-a"},
        )
        assert sorted(row["value"]["value"] for row in actual) == [11, 22]
    finally:
        session.connection.close()
