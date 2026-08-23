# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
``metrics.read``: letting a plugin ask questions about time.

Before this, a plugin could see that a device is offline right now and nothing
else. Every interesting question about an estate is a question about time -- has
this AP been flapping, is that uplink degrading, which site got worse this week
-- and none of them could be asked, so a whole category of plugin could not
exist.

Building it turned up two live defects in the platform's own metrics path,
neither of them plugin-related:

  ORGANIZATION_ID WAS NEVER RECORDED
      ``collect_device_metrics`` wrote ``site_id`` and ``device_id`` and left
      ``organization_id`` NULL on every row. ``/analytics/metrics/query``
      hard-codes ``filters["organization_id"] = str(org)`` for tenant
      isolation, so the filter was correct and matched nothing. 25,720 rows in
      the hypertable and ``data_points: []`` for every operator, always.
      Confirmed against the live instance, then confirmed fixed: the same call
      now returns values.

  METRICS FOR DELETED DEVICES, FOREVER
      The same query had no soft-delete filter. Of 40 devices in status
      online/offline on the dev estate, 24 were soft-deleted and all 24 were
      still having their status recorded every five minutes, indefinitely.

The SDK scopes by SITE rather than organization, which is the interesting
decision here and is explained where it is made.
"""

from __future__ import annotations

import inspect
import pathlib
from uuid import UUID

import pytest

ORG = UUID("11111111-1111-1111-1111-111111111111")
SITE_A = UUID("aaaaaaaa-0000-0000-0000-000000000001")
SITE_B = UUID("bbbbbbbb-0000-0000-0000-000000000002")


# ── stubs ───────────────────────────────────────────────────────


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows

    def scalars(self):
        return self

    def first(self):
        return self._rows[0] if self._rows else None


class _RecordingSession:
    """Captures the statements issued so the query itself can be asserted on."""

    def __init__(self, rows=()):
        self.statements = []
        self._rows = list(rows)

    async def execute(self, stmt):
        self.statements.append(stmt)
        return _Rows(self._rows)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def sql(self) -> str:
        return " ".join(str(s) for s in self.statements)


def _sdk(caps=("metrics.read",), sites=(SITE_A,), monkeypatch=None, logdb=None):
    from app.plugins.sdk import MetricsSDK

    sdk = MetricsSDK("probe", list(caps), ORG, _RecordingSession([(s,) for s in sites]))
    if monkeypatch is not None:
        monkeypatch.setattr(
            type(sdk), "_logdb_factory", staticmethod(lambda: (lambda: logdb) if logdb else None)
        )
    return sdk


# ── the capability ──────────────────────────────────────────────


def test_the_capability_exists_and_maps_to_a_real_permission():
    """
    The vocabulary's founding bug was ``alerts.write`` mapping to
    ``alert:write``, a permission that exists nowhere in FreeSDN -- so the
    guard refused precisely the role that drives a plugin route. A new
    capability that maps to a nonexistent permission would repeat it.
    """
    from app.plugins.capabilities import CAPABILITIES

    cap = CAPABILITIES["metrics.read"]
    assert cap.core_permissions == frozenset({"analytics:read"})

    root = pathlib.Path(__file__).resolve().parents[2]
    endpoints = (root / "app" / "api" / "v1" / "endpoints" / "analytics.py").read_text(
        encoding="utf-8"
    )
    assert 'require_permissions("analytics:read")' in endpoints, (
        "metrics.read maps to a permission the platform does not use"
    )


def test_reading_metrics_is_not_a_mutating_capability():
    from app.plugins.capabilities import MUTATING_CAPABILITIES

    assert "metrics.read" not in MUTATING_CAPABILITIES


async def test_an_undeclared_capability_is_refused(monkeypatch):
    """Declared in plugin.yaml or it does not work, like every other capability."""
    sdk = _sdk(caps=(), monkeypatch=monkeypatch, logdb=_RecordingSession())
    with pytest.raises(PermissionError, match="metrics.read"):
        await sdk.query("device.status")


# ── scoping ─────────────────────────────────────────────────────


async def test_the_query_is_confined_to_the_organizations_sites(monkeypatch):
    """
    Site-scoped rather than organization-scoped, deliberately. Every row written
    before the collector fix has ``organization_id`` NULL, so an org-scoped SDK
    would return nothing for exactly the historical data a trend plugin needs.
    Site works for old and new rows alike.
    """
    logdb = _RecordingSession()
    sdk = _sdk(monkeypatch=monkeypatch, logdb=logdb)
    await sdk.query("device.status")

    sql = logdb.sql()
    assert "site_id IN" in sql, "the metric query is not constrained to the caller's sites"
    assert "metric_name" in sql


async def test_a_site_filter_narrows_and_never_widens(monkeypatch):
    """
    A plugin often gets a site id from its caller. Treating it as a replacement
    for the scope rather than an intersection would turn any plugin route that
    accepts a site parameter into a cross-tenant read.
    """
    logdb = _RecordingSession()
    sdk = _sdk(sites=(SITE_A,), monkeypatch=monkeypatch, logdb=logdb)

    assert await sdk.query("device.status", site_id=SITE_B) == []
    assert not logdb.statements, "LogDB was queried for a site the caller cannot see"

    assert await sdk.series("device.status", site_id=SITE_B) == []
    assert not logdb.statements


async def test_no_visible_sites_means_no_query_at_all(monkeypatch):
    """
    Not merely an empty result: a scoped principal with no sites must not reach
    LogDB at all, so an empty ``IN ()`` can never be constructed.
    """
    logdb = _RecordingSession()
    sdk = _sdk(sites=(), monkeypatch=monkeypatch, logdb=logdb)

    assert await sdk.query("device.status") == []
    assert await sdk.series("device.status") == []
    assert await sdk.metric_names() == []
    assert not logdb.statements


def test_site_grants_are_applied_to_the_site_lookup():
    """
    A site-limited operator driving a plugin route must see only the series for
    the sites they hold. Scoping by site gets this for free -- as long as the
    lookup consults the grant.
    """
    from app.plugins.sdk import MetricsSDK

    src = inspect.getsource(MetricsSDK._visible_site_ids)
    assert "site_ids_for_request()" in src
    assert "Site.alive()" in src, "a deleted site's metrics are still readable"


def test_soft_deleted_sites_do_not_contribute_metrics():
    from app.plugins.sdk import MetricsSDK

    assert "Site.alive()" in inspect.getsource(MetricsSDK._visible_site_ids)


# ── limits ──────────────────────────────────────────────────────


async def test_the_row_cap_is_enforced_not_advisory(monkeypatch):
    """
    A metrics table is the largest thing a plugin can ask for by a wide margin.
    An unbounded query over a hypertable is how one plugin takes the API process
    down with it.
    """
    from app.plugins.sdk import MetricsSDK

    logdb = _RecordingSession()
    sdk = _sdk(monkeypatch=monkeypatch, logdb=logdb)
    await sdk.query("device.status", limit=999_999)

    # Assert on the bound parameters, not on a string that could match either
    # way. The first version of this test used an ``or`` over two loose checks
    # and stayed green with the clamp removed entirely.
    bound = list(logdb.statements[0].compile().params.values())
    assert 999_999 not in bound, "the caller's limit reached the database unclamped"
    assert MetricsSDK.MAX_POINTS in bound, "the cap was not applied"


async def test_an_absurd_time_range_is_clamped(monkeypatch):
    """
    ``hours=99999`` would otherwise scan the whole hypertable. Clamped rather
    than rejected: a plugin asking for more history than exists should get what
    there is, not an exception.
    """
    from datetime import UTC, datetime, timedelta

    from app.plugins.sdk import MetricsSDK

    logdb = _RecordingSession()
    sdk = _sdk(monkeypatch=monkeypatch, logdb=logdb)
    await sdk.query("device.status", hours=99_999)

    params = logdb.statements[0].compile().params
    since = next(v for v in params.values() if isinstance(v, datetime))
    horizon = datetime.now(UTC) - timedelta(days=MetricsSDK.MAX_RANGE_DAYS)
    assert since >= horizon - timedelta(minutes=1), "the time range is not clamped"


async def test_the_aggregation_is_an_allowlist(monkeypatch):
    """
    ``aggregation`` reaches ``getattr(func, ...)``, so an allowlist is the
    difference between a named SQL function and whatever the caller supplies.
    """
    sdk = _sdk(monkeypatch=monkeypatch, logdb=_RecordingSession())
    with pytest.raises(ValueError, match="aggregation must be one of"):
        await sdk.series("device.status", aggregation="; DROP TABLE metric_data")
    for good in ("avg", "min", "max", "sum", "count"):
        await sdk.series("device.status", aggregation=good)


async def test_bucketing_happens_in_the_database(monkeypatch):
    """
    A week of per-minute data for one site is already past the row cap, so
    reducing in Python would silently answer with a truncated slice: right for
    the last few hours, wrong for the week that was asked for, and nothing in
    the result to say which.
    """
    logdb = _RecordingSession()
    sdk = _sdk(monkeypatch=monkeypatch, logdb=logdb)
    await sdk.series("device.status", bucket_minutes=60)
    assert "date_bin" in logdb.sql(), "series is not aggregating in SQL"
    assert "GROUP BY" in logdb.sql()


def test_bucketing_does_not_require_timescale():
    """
    ``date_bin`` is plain Postgres 14+. ``time_bucket`` is a TimescaleDB
    extension function, and a LogDB without the extension is a supported shape.
    """
    from app.plugins.sdk import MetricsSDK

    # Comment-insensitive: the note explaining the choice names the function
    # being searched for.
    code = "\n".join(
        line
        for line in inspect.getsource(MetricsSDK.series).splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "date_bin" in code
    assert "time_bucket" not in code


# ── no LogDB is a supported deployment ──────────────────────────


async def test_without_logdb_every_method_degrades_instead_of_raising(monkeypatch):
    """
    Time-series is an optional tier. A plugin installed on a lite deployment
    should return nothing, not crash on import of a database that was never
    configured.
    """
    sdk = _sdk(monkeypatch=monkeypatch, logdb=None)

    assert await sdk.available() is False
    assert await sdk.query("device.status") == []
    assert await sdk.series("device.status") == []
    assert await sdk.latest("device.status") is None
    assert await sdk.metric_names() == []


async def test_available_lets_a_plugin_tell_empty_from_absent(monkeypatch):
    """
    Without it, "no metrics in the last 24 hours" and "this deployment has no
    metrics database" are the same answer -- and reporting the first when the
    second is true is a wrong answer delivered confidently, which is the failure
    mode that matters most for something an operator acts on.
    """
    assert await _sdk(monkeypatch=monkeypatch, logdb=_RecordingSession()).available() is True


async def test_latest_returns_none_rather_than_raising(monkeypatch):
    """
    "This device has no recent data" is an ordinary answer, not an error. A
    plugin that has to wrap every read in a try block writes worse code.
    """
    sdk = _sdk(monkeypatch=monkeypatch, logdb=_RecordingSession())
    assert await sdk.latest("device.status") is None


# ── the two collector defects ───────────────────────────────────


def _collector_source() -> str:
    root = pathlib.Path(__file__).resolve().parents[2]
    src = (root / "app" / "tasks" / "analytics.py").read_text(encoding="utf-8")
    return src.split("def collect_device_metrics", 1)[1].split("@celery_app.task", 1)[0]


def test_the_collector_records_the_organization():
    """
    The defect that made ``/analytics/metrics/query`` return nothing for
    everyone, forever. Device carries no organization_id of its own; it reaches
    one through its Site, which is why the join is there.
    """
    block = _collector_source()
    assert "Site.organization_id" in block, "the collector does not resolve an organization"
    # BOTH loops -- online and offline. Checking for one occurrence stayed green
    # when the online branch dropped it, which would have left half the metrics
    # invisible and looked fixed.
    assert block.count("organization_id=organization_id") == 2, (
        "the organization is resolved but not recorded on every write path"
    )


def test_the_collector_skips_deleted_devices_and_sites():
    """
    24 of 40 devices on the dev estate were soft-deleted and every one was still
    having its status recorded every five minutes, indefinitely.
    """
    block = _collector_source()
    assert "Device.alive()" in block
    assert "Site.alive()" in block
    # Both statuses go through the same builder, so one filter covers both. If
    # they are ever split apart again, this catches the half-filtered version.
    assert block.count("_devices_with(DeviceStatus") == 2


def test_the_analytics_query_still_filters_by_organization():
    """
    The premise for the fix above. If this filter were ever removed as the
    "cause" of the empty results, every operator would see every tenant's
    time-series instead -- trading a silent nothing for a silent leak.
    """
    root = pathlib.Path(__file__).resolve().parents[2]
    src = (root / "app" / "api" / "v1" / "endpoints" / "analytics.py").read_text(encoding="utf-8")
    assert 'filters["organization_id"] = str(org)' in src


# ── wiring ──────────────────────────────────────────────────────


def test_metrics_is_on_the_plugin_context():
    from app.plugins.sdk import PluginContext

    assert "metrics" in PluginContext.__annotations__


def test_the_sdk_uses_its_own_logdb_session():
    """
    LogDB is a separate database with a separate engine. Reusing the plugin's
    primary session would not merely be wrong, it would query the wrong server.
    """
    from app.plugins.sdk import MetricsSDK

    src = inspect.getsource(MetricsSDK.query)
    assert "async with factory() as logdb" in src
    assert "logdb.execute" in src


def test_site_resolution_uses_the_scoped_primary_session():
    """
    The site lookup runs against the PRIMARY database and must therefore honour
    the per-entry-point session like every other SDK -- otherwise a scheduled
    run resolving sites would race whatever else the plugin is doing.
    """
    from app.plugins.sdk import MetricsSDK

    assert "_plugin_session.get()" in inspect.getsource(MetricsSDK._db.fget)


def test_a_plugin_declaring_metrics_read_passes_manifest_validation():
    from app.plugins.schema import PluginManifest

    manifest = PluginManifest(
        id="probe",
        name="Probe",
        version="1.0.0",
        class_name="Probe",
        permissions=[{"code": "metrics.read", "name": "Read metrics"}],
    )
    assert manifest.permissions[0].code == "metrics.read"


def test_a_typo_in_the_capability_is_caught_at_install_time():
    from app.plugins.schema import PluginManifest

    with pytest.raises(ValueError, match="Unknown plugin capability"):
        PluginManifest(
            id="probe",
            name="Probe",
            version="1.0.0",
            class_name="Probe",
            permissions=[{"code": "metric.read", "name": "Typo"}],
        )
