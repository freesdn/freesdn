# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Uncertain shared state must not authorize an unattended plugin effect."""
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import UUID

import pytest

from app.plugins.scheduler import PluginScheduler, _Key
from app.plugins.schema import PluginSchedule

ORG = UUID("11111111-1111-1111-1111-111111111111")
KEY = _Key("owned-schedule", ORG, "probe")
SCHEDULE = PluginSchedule(name="probe", method="scan", interval_seconds=900)


class SharedClaims:
    def __init__(self):
        self.keys = set()

    async def set(self, key, value, *, nx=False, **kwargs):
        if nx and key in self.keys:
            return None
        self.keys.add(key)
        return True


class Unavailable:
    async def set(self, *args, **kwargs):
        raise ConnectionError("synthetic coordination failure")


@pytest.fixture(autouse=True)
def preserve_health_status():
    from app.core.startup import SUBSYSTEM_STATUS

    before = dict(SUBSYSTEM_STATUS)
    yield
    SUBSYSTEM_STATUS.clear()
    SUBSYSTEM_STATUS.update(before)


@pytest.mark.parametrize("client", [None, Unavailable()])
async def test_two_workers_refuse_the_same_slot_without_shared_coordination(client):
    workers = [PluginScheduler(), PluginScheduler()]
    for worker in workers:
        worker._redis = client
    assert [await worker._claim(KEY, SCHEDULE) for worker in workers] == [False, False]
    for worker in workers:
        status = worker.stats(KEY.plugin_id, ORG)[KEY.name]
        assert status["runs"] == status["failures"] == 0
        assert status["last"] is None
        assert status["blocked"]["reason"] == "coordination_unavailable"
    from app.core.startup import SUBSYSTEM_STATUS

    assert SUBSYSTEM_STATUS["plugin_scheduler"] == "degraded"


async def test_lost_claim_reply_never_authorizes_a_local_fallback():
    class LostReply(SharedClaims):
        async def set(self, *args, **kwargs):
            acquired = await super().set(*args, **kwargs)
            if acquired:
                raise ConnectionError("reply lost after shared write")
            return acquired

    shared = LostReply()
    first, second = PluginScheduler(), PluginScheduler()
    first._redis = second._redis = shared
    assert await first._claim(KEY, SCHEDULE) is False
    assert await second._claim(KEY, SCHEDULE) is False
    assert await first._claim(KEY, SCHEDULE) is False
    assert len(shared.keys) == 1


async def test_coordination_recovery_allows_only_one_worker_and_clears_its_pause():
    first, second = PluginScheduler(), PluginScheduler()
    first._redis = second._redis = Unavailable()
    assert not await first._claim(KEY, SCHEDULE)
    assert not await second._claim(KEY, SCHEDULE)
    first._redis = second._redis = SharedClaims()
    assert await first._claim(KEY, SCHEDULE)
    assert not await second._claim(KEY, SCHEDULE)
    assert all(not worker._blocked for worker in (first, second))


@pytest.mark.parametrize("default", [False, True])
async def test_unreadable_settings_do_not_run_a_scheduled_method(monkeypatch, default):
    from app.plugins import sdk

    class Unreadable:
        async def execute(self, *args, **kwargs):
            raise ConnectionError("synthetic settings outage")

    @asynccontextmanager
    async def scope():
        token = sdk._plugin_session.set(Unreadable())
        try:
            yield None
        finally:
            sdk._plugin_session.reset(token)

    monkeypatch.setattr(sdk, "plugin_session_scope", scope)
    calls = []

    class Runtime:
        async def scan(self):
            calls.append("executed")

    scheduler = PluginScheduler()
    scheduler._redis = SharedClaims()
    schedule = SCHEDULE.model_copy(update={"enabled_by_default": default})
    await scheduler._run(Runtime(), KEY, schedule)
    assert calls == []
    status = scheduler.stats(KEY.plugin_id, ORG)[KEY.name]
    assert status["runs"] == status["failures"] == 0
    assert status["last"] is None
    assert status["blocked"]["reason"] == "settings_unavailable"


async def test_absent_session_is_not_an_authorization_to_use_defaults():
    from app.plugins.sdk import _plugin_session

    scheduler = PluginScheduler()
    token = _plugin_session.set(None)
    try:
        assert await scheduler._is_disabled(KEY, SCHEDULE) is True
    finally:
        _plugin_session.reset(token)


async def test_recovered_settings_respect_the_operators_disabled_row():
    from app.plugins.sdk import _plugin_session

    class Available:
        async def execute(self, *args, **kwargs):
            return SimpleNamespace(first=lambda: (True,))

    scheduler = PluginScheduler()
    scheduler._block(KEY, "settings_unavailable")
    token = _plugin_session.set(Available())
    try:
        assert await scheduler._is_disabled(KEY, SCHEDULE) is True
        assert not scheduler._blocked
    finally:
        _plugin_session.reset(token)


async def test_redis_client_construction_recovers_on_a_later_tick(monkeypatch):
    from app.core import redis_client
    from app.plugins import scheduler as module

    now = [100.0]
    attempts = []
    shared = SharedClaims()

    def factory(**kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise ConnectionError("synthetic initial client failure")
        return shared

    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(redis_client, "get_async_redis", factory)
    scheduler = PluginScheduler()
    assert not await scheduler._claim(KEY, SCHEDULE)
    assert not await scheduler._claim(KEY, SCHEDULE)
    assert len(attempts) == 1
    now[0] += module.TICK_SECONDS
    assert await scheduler._claim(KEY, SCHEDULE)
    assert len(attempts) == 2


@pytest.mark.parametrize("reply", ["OK", 1, {}, []])
async def test_non_boolean_claim_reply_is_not_an_execution_grant(reply):
    class Malformed:
        async def set(self, *args, **kwargs):
            return reply

    scheduler = PluginScheduler()
    scheduler._redis = Malformed()
    assert not await scheduler._claim(KEY, SCHEDULE)
    assert scheduler._blocked[KEY.tuple()]["reason"] == "coordination_unavailable"


async def test_coordination_error_details_do_not_leak_into_diagnostics(caplog):
    class SecretBearingFailure:
        async def set(self, *args, **kwargs):
            raise ConnectionError("private-authentication-material-must-not-appear")

    scheduler = PluginScheduler()
    scheduler._redis = SecretBearingFailure()
    assert not await scheduler._claim(KEY, SCHEDULE)
    assert "private-authentication-material" not in caplog.text
    assert "private-authentication-material" not in str(scheduler.stats(KEY.plugin_id, ORG))


async def test_removed_schedules_do_not_leave_the_scheduler_degraded(monkeypatch):
    from app.core.startup import SUBSYSTEM_STATUS
    from app.plugins.loader import plugin_loader

    scheduler = PluginScheduler()
    scheduler._block(KEY, "coordination_unavailable")
    monkeypatch.setattr(plugin_loader, "get_active", lambda: {})
    await scheduler._tick()
    assert not scheduler._blocked
    assert SUBSYSTEM_STATUS["plugin_scheduler"] == "healthy"
