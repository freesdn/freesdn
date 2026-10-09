# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Properties the plugin scheduler has to hold, because nobody is watching it.

Everything unattended fails differently from everything else. A route that
breaks produces an angry user within minutes; a schedule that breaks produces
silence, and silence from a monitoring plugin reads exactly like good news.
That asymmetry is what these tests are about.

Verified live on the dev instance before they were written -- five
organizations, five runtimes, ~200ms per run, spread across ticks by the jitter,
with ``netbox-sync`` claiming its slots and correctly declining to run because
it ships disabled.
"""

from __future__ import annotations

import asyncio
import inspect
import pathlib
import time
from uuid import UUID, uuid4

import pytest

ORG_A = UUID("11111111-1111-1111-1111-111111111111")
ORG_B = UUID("22222222-2222-2222-2222-222222222222")


@pytest.fixture(autouse=True)
def preserve_scheduler_health():
    from app.core.startup import SUBSYSTEM_STATUS

    previous = dict(SUBSYSTEM_STATUS)
    yield
    SUBSYSTEM_STATUS.clear()
    SUBSYSTEM_STATUS.update(previous)


def _schedule(**kw):
    from app.plugins.schema import PluginSchedule

    return PluginSchedule(
        **{
            "name": "drift_scan",
            "method": "scheduled_scan",
            "interval_seconds": 900,
            **kw,
        }
    )


def _key(org=ORG_A, name="drift_scan"):
    from app.plugins.scheduler import _Key

    return _Key("config-drift-guard", org, name)


# ── the manifest contract ───────────────────────────────────────


def test_a_schedule_cannot_run_more_often_than_the_floor():
    """
    Unattended and fast is how a plugin becomes a self-inflicted denial of
    service on an appliance whose owner is asleep. The 15-second tick also
    cannot pace anything faster, so a smaller number would be a promise the
    scheduler does not keep.
    """
    with pytest.raises(ValueError):
        _schedule(interval_seconds=5)
    with pytest.raises(ValueError):
        _schedule(interval_seconds=59)
    assert _schedule(interval_seconds=60).interval_seconds == 60


def test_a_schedule_cannot_run_less_often_than_a_day():
    """A ceiling keeps the timeout bounded: the run timeout derives from the
    interval, and an unbounded interval would mean an unbounded hold on a
    session and a pooled connection."""
    with pytest.raises(ValueError):
        _schedule(interval_seconds=86_401)


@pytest.mark.parametrize("hook", ["on_start", "on_stop", "on_event", "get_router"])
def test_a_schedule_may_not_target_a_lifecycle_hook(hook: str):
    """
    Calling ``on_start`` on a timer re-runs initialisation against a runtime
    that is already started, quietly duplicating every registration the hook
    performs. It reads like a reasonable thing to declare, which is why it is
    refused rather than documented against.
    """
    from app.plugins.schema import PluginManifest

    with pytest.raises(ValueError, match="lifecycle hook"):
        PluginManifest(
            id="probe",
            name="Probe",
            version="1.0.0",
            class_name="Probe",
            schedules=[{"name": "job", "method": hook, "interval_seconds": 300}],
        )


def test_duplicate_schedule_names_are_refused():
    """
    They collide on the Redis claim key, so two schedules declared 15 minutes
    apart would silently become one -- and the one that vanished would still be
    listed in the UI.
    """
    from app.plugins.schema import PluginManifest

    with pytest.raises(ValueError, match="duplicate schedule name"):
        PluginManifest(
            id="probe",
            name="Probe",
            version="1.0.0",
            class_name="Probe",
            schedules=[
                {"name": "scan", "method": "a", "interval_seconds": 300},
                {"name": "scan", "method": "b", "interval_seconds": 900},
            ],
        )


def test_a_schedule_cannot_call_a_private_method():
    with pytest.raises(ValueError, match="underscore"):
        _schedule(method="_scan")


# ── slot claims: at most once, everywhere ───────────────────────


class _SharedClaims:
    def __init__(self):
        self.keys = set()

    async def set(self, key, value, **kwargs):
        if key in self.keys:
            return None
        self.keys.add(key)
        return True


async def test_a_slot_is_claimed_once_and_then_refused():
    from app.plugins.scheduler import PluginScheduler

    scheduler = PluginScheduler()
    scheduler._redis = _SharedClaims()
    sched = _schedule(interval_seconds=3600)
    assert await scheduler._claim(_key(), sched) is True
    assert await scheduler._claim(_key(), sched) is False
    assert await scheduler._claim(_key(), sched) is False


async def test_a_redis_failure_pauses_without_a_local_authorization():
    from app.plugins.scheduler import PluginScheduler

    class Exploding:
        async def set(self, *a, **kw):
            raise ConnectionError("redis is gone")

    scheduler = PluginScheduler()
    scheduler._redis = Exploding()
    assert await scheduler._claim(_key(), _schedule()) is False
    assert scheduler.stats("config-drift-guard", ORG_A)["drift_scan"]["blocked"][
        "reason"
    ] == "coordination_unavailable"


async def test_the_claim_is_scoped_per_organization():
    """
    A plugin has one runtime per organization and each needs its own run. One
    shared claim would mean whichever organization ticked first got its scan and
    every other tenant got nothing -- a silent, per-tenant outage.
    """
    from app.plugins.scheduler import PluginScheduler

    scheduler = PluginScheduler()
    scheduler._redis = _SharedClaims()
    sched = _schedule(interval_seconds=3600)

    assert await scheduler._claim(_key(ORG_A), sched) is True
    assert await scheduler._claim(_key(ORG_B), sched) is True


# ── jitter ──────────────────────────────────────────────────────


def test_the_offset_is_stable_across_processes():
    """
    Every worker must compute the same slot boundary. Derived from the schedule
    identity rather than ``random`` for exactly this reason: two workers
    disagreeing on where the boundary falls would each claim a different slot,
    and the schedule would run twice.
    """
    from app.plugins.scheduler import PluginScheduler

    first = PluginScheduler._offset(_key(), 900)
    second = PluginScheduler._offset(_key(), 900)
    assert first == second
    assert 0 <= first < 900


def test_organizations_do_not_all_fire_at_once():
    """
    Without an offset, every organization's 15-minute scan lands on the same
    quarter hour: an appliance serving a dozen tenants does a dozen inventory
    sweeps simultaneously and idles the rest of the time.
    """
    from app.plugins.scheduler import PluginScheduler

    offsets = {PluginScheduler._offset(_key(uuid4()), 900) for _ in range(40)}
    # Collisions are fine and expected (40 draws into 900 buckets); what matters
    # is that they are spread rather than identical.
    assert len(offsets) > 30, f"offsets are clustered: {sorted(offsets)[:10]}"


def test_the_next_run_is_within_one_interval():
    from app.plugins.scheduler import PluginScheduler

    scheduler = PluginScheduler()
    sched = _schedule(interval_seconds=900)
    nxt = scheduler.next_run_at("config-drift-guard", ORG_A, sched)
    assert 0 < nxt - time.time() <= 900


# ── enabled_by_default ──────────────────────────────────────────


class _StubResult:
    def __init__(self, row):
        self._row = row

    def first(self):
        return self._row


class _StubSession:
    def __init__(self, row):
        self._row = row

    async def execute(self, _stmt):
        return _StubResult(self._row)


@pytest.fixture
def stub_session(monkeypatch):
    """Make ``_run``'s own session scope bind a stub instead of a real session.

    Setting the ContextVar directly does not work and quietly does the wrong
    thing: ``_run`` opens ``plugin_session_scope()``, which replaces whatever
    was bound. The first version of these tests did exactly that, so the
    enabled-check hit a database that is not there, fell into its except branch,
    and the assertions passed or failed for reasons unrelated to what they name.
    """
    import contextlib as _contextlib

    from app.plugins import sdk as sdk_mod

    def _install(row):
        @_contextlib.asynccontextmanager
        async def _scope():
            token = sdk_mod._plugin_session.set(_StubSession(row))
            try:
                yield None
            finally:
                sdk_mod._plugin_session.reset(token)

        monkeypatch.setattr(sdk_mod, "plugin_session_scope", _scope)

    return _install


async def _disabled_with(row, *, default: bool) -> bool:
    from app.plugins.scheduler import PluginScheduler
    from app.plugins.sdk import _plugin_session

    token = _plugin_session.set(_StubSession(row))
    try:
        return await PluginScheduler()._is_disabled(_key(), _schedule(enabled_by_default=default))
    finally:
        _plugin_session.reset(token)


async def test_no_row_means_what_the_plugin_ships_with():
    """
    The bug this was written against: ``_is_disabled`` treated a missing row as
    "enabled", so ``enabled_by_default: false`` was accepted by the manifest,
    displayed in the UI, and ignored. netbox-sync would have started writing to
    somebody's NetBox unattended on first install.
    """
    assert await _disabled_with(None, default=False) is True
    assert await _disabled_with(None, default=True) is False


async def test_an_operators_choice_beats_the_default():
    assert await _disabled_with(("1",), default=True) is True
    assert await _disabled_with(("",), default=False) is False


async def test_a_failed_lookup_pauses_regardless_of_the_manifest_default():
    """An unreadable operator choice must never authorize a default-on job."""
    from app.plugins.scheduler import PluginScheduler
    from app.plugins.sdk import _plugin_session

    class Exploding:
        async def execute(self, _stmt):
            raise ConnectionError("db is gone")

    token = _plugin_session.set(Exploding())
    try:
        scheduler = PluginScheduler()
        assert await scheduler._is_disabled(_key(), _schedule(enabled_by_default=False)) is True
        assert await scheduler._is_disabled(_key(), _schedule(enabled_by_default=True)) is True
    finally:
        _plugin_session.reset(token)


# ── running ─────────────────────────────────────────────────────


def test_the_supervisor_label_stays_low_cardinality():
    """
    ``operation`` becomes a Prometheus label. ``schedule:{name}`` would put one
    unbounded dimension per plugin author into the metrics backend, which is how
    a metrics backend falls over.
    """
    from app.plugins.scheduler import PluginScheduler

    src = inspect.getsource(PluginScheduler._run)
    assert 'supervisor.guard(key.plugin_id, "schedule"' in src, (
        "the schedule name is being used as a metrics label"
    )


def test_a_run_gets_its_own_session():
    """
    A scheduled run overlaps routes and event handlers by construction, and
    asyncpg permits one operation per connection. Sharing the runtime's session
    is the collision this exists to avoid.
    """
    from app.plugins.scheduler import PluginScheduler

    src = inspect.getsource(PluginScheduler._run)
    assert "plugin_session_scope()" in src


def test_a_slow_run_is_not_stacked_on_top_of_itself():
    """
    A scan that outlives its interval would otherwise get a second copy started
    every interval, turning a struggling plugin into a load test against the
    thing it is supposed to be watching.
    """
    from app.plugins.scheduler import PluginScheduler

    src = inspect.getsource(PluginScheduler._tick)
    assert "in self._running" in src


async def test_a_missing_method_is_reported_as_a_failed_run():
    """
    The manifest validator never imports the plugin class, so it cannot catch a
    typo in ``method``. Logging into the void would leave an operator with a
    schedule that shows as enabled and never produces a run.
    """
    from app.plugins.scheduler import PluginScheduler

    class Runtime:
        pass

    scheduler = PluginScheduler()
    scheduler._redis = None
    await scheduler._run(Runtime(), _key(), _schedule(method="does_not_exist"))

    stat = scheduler._stats[_key().tuple()]
    assert stat.runs == 1
    assert stat.failures == 1
    assert stat.last.status == "missing_method"
    assert "does_not_exist" in (stat.last.error or "")


async def test_a_raising_schedule_is_recorded_not_swallowed(stub_session):
    from app.plugins.scheduler import PluginScheduler

    class Runtime:
        async def scheduled_scan(self):
            raise RuntimeError("the controller said no")

    stub_session(None)  # no toggle row -> enabled by default
    scheduler = PluginScheduler()
    scheduler._redis = None
    await scheduler._run(Runtime(), _key(), _schedule())

    last = scheduler._stats[_key().tuple()].last
    assert last.status == "error"
    assert "the controller said no" in (last.error or "")


async def test_a_disabled_schedule_leaves_no_run_record(stub_session):
    """
    ``enabled: false`` with ``last_run: null`` is unambiguous. Recording a
    "disabled" run would make the health view read as though something happened.
    """
    from app.plugins.scheduler import PluginScheduler

    ran = []

    class Runtime:
        async def scheduled_scan(self):
            ran.append(1)

    stub_session(("1",))  # an operator turned it off
    scheduler = PluginScheduler()
    scheduler._redis = None
    await scheduler._run(Runtime(), _key(), _schedule())

    assert not ran, "a disabled schedule ran anyway"
    assert _key().tuple() not in scheduler._stats


async def test_one_bad_tick_does_not_end_the_scheduler():
    """
    A scheduler that dies silently is worse than one that never existed: the UI
    keeps listing schedules, and every one of them has quietly stopped.
    """
    from app.plugins import scheduler as scheduler_mod

    scheduler = scheduler_mod.PluginScheduler()
    calls = []

    async def _boom():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("bad tick")

    scheduler._tick = _boom
    original, scheduler_mod.TICK_SECONDS = scheduler_mod.TICK_SECONDS, 0.01
    try:
        await scheduler.start()
        await asyncio.sleep(0.2)
        await scheduler.stop()
    finally:
        scheduler_mod.TICK_SECONDS = original

    assert len(calls) > 1, "the loop stopped after one failing tick"


# ── wiring ──────────────────────────────────────────────────────


def test_the_scheduler_stops_before_plugins_do():
    """
    The other order lets an in-flight run call into a runtime whose ``on_stop``
    has already torn down its context, so the last thing in the log before a
    clean shutdown is a plugin crash.
    """
    root = pathlib.Path(__file__).resolve().parents[2]
    src = (root / "app" / "main.py").read_text(encoding="utf-8")
    shutdown = src.split("    # Shutdown", 1)[1]
    assert "plugin_scheduler.stop()" in shutdown
    assert shutdown.index("plugin_scheduler.stop()") < shutdown.index("plugin_loader.get_active()")


def test_the_scheduler_is_its_own_subsystem():
    """
    Folding it into "plugins" would let a scheduler that failed to start leave
    every plugin reporting healthy while nothing periodic runs -- the failure an
    operator is least likely to notice unaided.
    """
    root = pathlib.Path(__file__).resolve().parents[2]
    src = (root / "app" / "main.py").read_text(encoding="utf-8")
    assert 'SUBSYSTEM_STATUS["plugin_scheduler"]' in src


# ── operator settings are not plugin state ──────────────────────


def test_reserved_settings_are_hidden_and_unwritable():
    """
    The schedule toggle lives in the plugin settings table. Without the reserved
    prefix it would render in the operator's configuration form as an editable
    field, inviting someone to "fix" a value the platform depends on.
    """
    root = pathlib.Path(__file__).resolve().parents[2]
    endpoints = (root / "app" / "api" / "v1" / "endpoints" / "plugins.py").read_text(
        encoding="utf-8"
    )
    get_block = endpoints.split("async def get_plugin_settings", 1)[1].split("@router", 1)[0]
    put_block = endpoints.split("async def update_plugin_settings", 1)[1].split("@router", 1)[0]
    assert 'key.startswith("__")' in get_block, "internal state is shown as configuration"
    assert 'k.startswith("__")' in put_block, "an operator can overwrite platform state"


def test_the_toggle_uses_the_reserved_prefix():
    from app.plugins.scheduler import DISABLED_SETTING_PREFIX

    assert DISABLED_SETTING_PREFIX.startswith("__")
