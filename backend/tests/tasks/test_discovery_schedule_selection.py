# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The scheduled discovery honours each controller's Auto sync switch and interval.

Add/Edit Controller offers "Auto sync" (``sync_enabled``) and "Sync interval"
(``sync_interval_seconds``, minimum 60 s), and the details sheet shows them.
Nothing read either: the discover-all-devices beat (every 5 minutes) selected
every active controller, so turning auto sync off, or raising the interval to
spare a struggling appliance, changed nothing; each controller was fully
discovered every 5 minutes. The user-triggered "Discover all" still runs every
enabled controller in the caller's org, as before.

Fails on the previous task (the disabled and the not-yet-due controllers are
discovered); runs on real PostgreSQL with discovery itself stubbed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import app.tasks.discovery as discovery
from app.models.core import Controller, Organization, Site


async def _graph(db_session):
    suffix = uuid4().hex[:8]
    org = Organization(name="Sched Org", slug=f"sched-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="Sched Site", slug=f"sched-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    now = datetime.now(UTC)

    def ctrl(name, **kw):
        return Controller(
            name=f"{name} {suffix}",
            controller_type="omada",
            host="192.0.2.30",
            port=8043,
            site_id=site.id,
            is_active=True,
            config={},
            **kw,
        )

    rows = {
        # 11 minutes, not 6: the scheduled run now applies the
        # CONTROLLER_SYNC_MIN_INTERVAL_SECONDS floor (10 min by default) above a
        # controller's own 300 s, so a 6-minute-old sync is no longer due.
        "due": ctrl(
            "due",
            sync_enabled=True,
            sync_interval_seconds=300,
            last_sync=now - timedelta(minutes=11),
        ),
        "never": ctrl("never", sync_enabled=True, sync_interval_seconds=3600, last_sync=None),
        "not_due": ctrl(
            "not-due",
            sync_enabled=True,
            sync_interval_seconds=3600,
            last_sync=now - timedelta(minutes=6),
        ),
        "auto_off": ctrl("auto-off", sync_enabled=False, sync_interval_seconds=300, last_sync=None),
    }
    db_session.add_all(rows.values())
    await db_session.flush()
    return org, rows


def _stub(monkeypatch, db_session):
    called: list[str] = []

    async def _one(cid):
        called.append(cid)
        return {"success": True, "controller_id": cid}

    class _Ctx:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(discovery, "_discover_devices_for_controller", _one)
    monkeypatch.setattr(discovery, "AsyncSessionLocal", lambda: _Ctx())
    return called


async def test_scheduled_run_skips_auto_sync_off_and_not_yet_due(db_session, monkeypatch):
    _org, rows = await _graph(db_session)
    called = _stub(monkeypatch, db_session)

    await discovery._discover_all_devices()

    mine = {str(c.id): k for k, c in rows.items()}
    assert sorted(mine[c] for c in called if c in mine) == ["due", "never"]


async def test_user_triggered_run_still_covers_every_enabled_controller(db_session, monkeypatch):
    org, rows = await _graph(db_session)
    called = _stub(monkeypatch, db_session)

    await discovery._discover_all_devices(str(org.id))

    assert sorted(called) == sorted(str(c.id) for c in rows.values())


def test_interval_rule():
    now = datetime.now(UTC)
    assert discovery._interval_due(None, 3600, now)
    assert discovery._interval_due(now - timedelta(seconds=280), 300, now)  # 30 s slack
    assert not discovery._interval_due(now - timedelta(seconds=200), 300, now)
    assert discovery._interval_due(now - timedelta(seconds=40), 10, now)  # 60 s floor


async def test_scheduled_run_applies_the_controller_sync_floor(db_session, monkeypatch):
    """A controller asking for 300 s is not rediscovered before the floor."""
    from app.core.config import settings

    _org, rows = await _graph(db_session)
    rows["due"].last_sync = datetime.now(UTC) - timedelta(minutes=6)
    await db_session.flush()
    called = _stub(monkeypatch, db_session)
    monkeypatch.setattr(settings, "CONTROLLER_SYNC_MIN_INTERVAL_SECONDS", 600)

    await discovery._discover_all_devices()

    mine = {str(c.id): k for k, c in rows.items()}
    assert sorted(mine[c] for c in called if c in mine) == ["never"]

    monkeypatch.setattr(settings, "CONTROLLER_SYNC_MIN_INTERVAL_SECONDS", 300)
    called.clear()
    await discovery._discover_all_devices()
    assert sorted(mine[c] for c in called if c in mine) == ["due", "never"]


async def test_scheduled_run_leaves_an_unreachable_controller_to_the_health_check(
    db_session, monkeypatch
):
    from app.core import device_breaker
    from app.core.device_breaker import DeviceBreaker
    from tests.core.test_device_breaker import Clock, RedisDouble

    redis, clock = RedisDouble(), Clock()
    breaker = DeviceBreaker(failure_threshold=1, redis_factory=lambda: redis, clock=clock)
    monkeypatch.setattr(device_breaker, "controller_breaker", breaker)
    org, rows = await _graph(db_session)
    breaker.record_failure(device_breaker.controller_key(rows["never"].id), "ConnectTimeout")
    called = _stub(monkeypatch, db_session)

    await discovery._discover_all_devices()
    mine = {str(c.id): k for k, c in rows.items()}
    assert sorted(mine[c] for c in called if c in mine) == ["due"]

    called.clear()
    await discovery._discover_all_devices(str(org.id))  # an operator's "Sync now"
    assert str(rows["never"].id) in called
