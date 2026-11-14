# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A gateway that failed its sync is not synced again every beat.

Evidence (2026-11 soak): the office OPNsense timed out on every request, and the
periodic task handed it a full sync on every 5-minute beat regardless, because
the only breaker lived inside a client instance that each run rebuilt. These
tests run the real task loop against the shared (Redis) breakers.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from app.core import device_breaker
from app.core.device_breaker import DeviceBreaker
from app.modules.gateway.tasks import sync_tasks
from tests.core.test_device_breaker import Clock, RedisDouble


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _Session:
    def __init__(self, enabled_rows):
        self._results = [_Rows(enabled_rows)]
        self.updates = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def execute(self, _stmt):
        if self._results:
            return self._results.pop(0)
        self.updates += 1  # the skip-reason UPDATE
        return None

    async def commit(self):
        return None

    async def rollback(self):
        return None


@pytest.fixture
def breakers(monkeypatch):
    redis, clock = RedisDouble(), Clock()
    reach = DeviceBreaker(
        failure_threshold=2, base_cooldown=120, redis_factory=lambda: redis, clock=clock
    )
    full = DeviceBreaker(
        failure_threshold=1, base_cooldown=900, redis_factory=lambda: redis, clock=clock
    )
    monkeypatch.setattr(device_breaker, "gateway_breaker", reach)
    monkeypatch.setattr(device_breaker, "gateway_sync_breaker", full)
    return clock


def _run(monkeypatch, gw_id, outcome):
    import app.modules.gateway.services.sync_service as sync_service

    calls: list = []

    class _FakeSyncService:
        def __init__(self, _session):
            pass

        async def sync_gateway(self, gateway_id):
            calls.append(gateway_id)
            return dict(outcome)

    session = _Session([(gw_id, None, 1800)])
    monkeypatch.setattr(sync_tasks, "AsyncSessionLocal", lambda: session)
    monkeypatch.setattr(sync_service, "SyncService", _FakeSyncService)
    result = asyncio.run(sync_tasks._sync_all_brain_gateways())
    return result, calls, session


TIMED_OUT = {"status": "failed", "device_failure": True, "error": "rules: AdapterConnectionError"}
UNREACHABLE = {
    "status": "failed",
    "device_failure": True,
    "error": "connect: AdapterConnectionError",
}


def test_a_failed_sync_is_backed_off_instead_of_repeated_every_beat(monkeypatch, breakers):
    """Fails on the old task: the gateway was synced on all three beats."""
    gw = uuid4()
    attempts = 0
    for _ in range(3):
        result, calls, session = _run(monkeypatch, gw, TIMED_OUT)
        attempts += len(calls)
        breakers.now += 300  # next 5-minute beat
    assert attempts == 1
    assert result["skipped"] == 1 and "backed off" in result["details"][0]["reason"]
    assert session.updates == 1  # the reason is written where the UI shows it


def test_after_the_backoff_one_sync_probes_and_success_resumes(monkeypatch, breakers):
    gw = uuid4()
    _run(monkeypatch, gw, TIMED_OUT)
    breakers.now += 1000  # past the ~15-minute backoff
    result, calls, _ = _run(monkeypatch, gw, {"status": "success", "synced": {}})
    assert calls == [gw] and result["synced"] == 1
    breakers.now += 1  # closed again: due gateways sync normally
    _, calls, _ = _run(monkeypatch, gw, {"status": "success", "synced": {}})
    assert calls == [gw]


def test_an_unreachable_gateway_also_opens_the_reachability_breaker(monkeypatch, breakers):
    gw = uuid4()
    _run(monkeypatch, gw, UNREACHABLE)
    breakers.now += 1000
    _run(monkeypatch, gw, UNREACHABLE)
    reach = device_breaker.gateway_breaker.check(device_breaker.gateway_key(gw))
    assert not reach.allowed and reach.state == "open"
