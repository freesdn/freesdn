# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The periodic gateway sync must reach gateways that are not a site's brain.

Found on the 2026-11 soak VM: an OPNsense added from the Gateways page carried
``sync_enabled=true`` and a 300 s interval, was synced once when it was created,
and never again. ``gateway.sync_all_gateways`` ran every five minutes but only
selected gateways assigned the BRAIN role in a site role map, so a gateway
without a role kept its rules, NAT, tunnels, interfaces and leases frozen.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.modules.gateway.tasks import sync_tasks

NOW = datetime(2026, 11, 13, 3, 35, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _private_breakers(monkeypatch):
    """The task consults the shared per-device breakers; keep them off Redis."""
    from app.core import device_breaker
    from tests.core.test_device_breaker import RedisDouble

    redis = RedisDouble()
    for name in ("gateway_breaker", "gateway_sync_breaker"):
        original = getattr(device_breaker, name)
        monkeypatch.setattr(
            device_breaker,
            name,
            device_breaker.DeviceBreaker(
                failure_threshold=original.failure_threshold,
                base_cooldown=original.base_cooldown,
                max_cooldown=original.max_cooldown,
                redis_factory=lambda: redis,
            ),
        )


@pytest.mark.parametrize(
    ("last", "interval", "due"),
    [
        (None, 300, True),
        # The old implicit 300 s is raised to the 30-minute floor (2026-11 soak:
        # a 5-minute full sync helped exhaust the OPNsense PHP pool).
        (NOW - timedelta(seconds=298), 300, False),
        (NOW - timedelta(seconds=1500), 300, False),
        (NOW - timedelta(seconds=1790), 300, True),  # 30 s of beat slack
        (NOW - timedelta(seconds=1500), None, False),  # missing interval -> floor
        # An interval ABOVE the floor is the gateway's own and is respected.
        (NOW - timedelta(seconds=3500), 7200, False),
        (NOW - timedelta(seconds=7180), 7200, True),
    ],
)
def test_a_gateway_is_due_on_its_own_interval(last, interval, due):
    assert sync_tasks._due(last, interval, NOW) is due


def test_the_floor_is_configurable_but_never_below_five_minutes(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "GATEWAY_SYNC_MIN_INTERVAL_SECONDS", 300)
    assert sync_tasks._due(NOW - timedelta(seconds=280), 300, NOW) is True
    monkeypatch.setattr(settings, "GATEWAY_SYNC_MIN_INTERVAL_SECONDS", 10)
    assert sync_tasks._due(NOW - timedelta(seconds=200), 60, NOW) is False


def test_each_gateway_gets_a_stable_offset_within_ten_percent():
    ids = [uuid4() for _ in range(50)]
    offsets = [sync_tasks._jitter_seconds(i, 1800) for i in ids]
    assert all(0 <= o <= 180 for o in offsets)
    assert len(set(offsets)) > 5  # spread out, not all on one beat
    assert offsets == [sync_tasks._jitter_seconds(i, 1800) for i in ids]  # stable


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _FakeSession:
    def __init__(self, brain_rows, enabled_rows):
        self._brain_rows = brain_rows
        self._enabled_rows = enabled_rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def execute(self, stmt):
        if "gw_site_role_assignments" in str(stmt):
            return _Rows(self._brain_rows)
        return _Rows(self._enabled_rows)

    async def commit(self):
        return None


def _run(monkeypatch, brain_rows, enabled_rows):
    import app.modules.gateway.services.sync_service as sync_service

    synced: list = []

    class _FakeSyncService:
        def __init__(self, _session):
            pass

        async def sync_gateway(self, gateway_id):
            synced.append(gateway_id)
            return {"status": "success", "synced": {}}

    monkeypatch.setattr(
        sync_tasks, "AsyncSessionLocal", lambda: _FakeSession(brain_rows, enabled_rows)
    )
    monkeypatch.setattr(sync_service, "SyncService", _FakeSyncService)
    return asyncio.run(sync_tasks._sync_all_brain_gateways()), synced


def test_a_sync_enabled_gateway_without_a_role_is_synced_when_due(monkeypatch):
    opnsense = uuid4()
    long_ago = datetime.now(UTC) - timedelta(minutes=40)
    result, synced = _run(monkeypatch, [], [(opnsense, long_ago, 300)])
    assert synced == [opnsense]
    assert result["total"] == 1 and result["synced"] == 1


def test_a_recently_synced_gateway_is_left_until_its_interval(monkeypatch):
    fresh = datetime.now(UTC) - timedelta(seconds=60)
    result, synced = _run(monkeypatch, [], [(uuid4(), fresh, 300)])
    assert synced == [] and result["synced"] == 0


def test_a_brain_follows_its_interval_like_any_gateway(monkeypatch):
    """A brain used to be synced on EVERY 5-minute beat. It is the site's
    production firewall: it now waits for its interval like any gateway."""
    brain = uuid4()
    fresh = datetime.now(UTC) - timedelta(seconds=60)
    result, synced = _run(monkeypatch, [(brain,)], [(brain, fresh, 300)])
    assert synced == [] and result["synced"] == 0


def test_a_due_brain_is_synced_once(monkeypatch):
    brain = uuid4()
    long_ago = datetime.now(UTC) - timedelta(hours=2)
    result, synced = _run(monkeypatch, [(brain,)], [(brain, long_ago, 300)])
    assert synced == [brain]
    assert result["total"] == 1
