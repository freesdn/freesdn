# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Six ways scheduled work reported itself as done without having happened.

1. A FAILED PoE PUSH WAS RECORDED AS DONE AND NEVER RETRIED
   ``evaluate_poe_schedules`` discarded the ``AdapterResult`` from
   ``configure_switch_port``. A refused write comes back as
   ``success=False`` and does NOT raise, so ``any_device_succeeded`` was set on
   a switch that was never touched -- and with it ``last_action``, which the
   guard at the top of the loop uses to skip a schedule already in the desired
   state. So the failure was not just unreported: it stopped the task retrying
   for the rest of the window. Cameras and APs scheduled to power down at 22:00
   stayed powered all night while the PoE Schedules card showed a fresh "last
   action" timestamp.

   Both interactive PoE endpoints already called ``raise_for_adapter_result``
   for exactly this, with a comment naming the bug class (CONV2-001). The
   scheduled path was the miss.

2. A FAILED ZTP ADOPTION WENT BACK INTO THE WORK QUEUE, FOREVER
   ``AdoptionOrchestrator._fail_job`` sets FAILED and ``flush()``es; the caller
   then rolled the transaction back, which is right for the pipeline's partial
   device writes and wrong for the verdict. The row stayed PENDING -- and
   PENDING is a work queue: ``sync_controller`` selects every PENDING job for
   its controller and dispatches ``execute_adoption``. So a failed adoption
   re-ran the entire pipeline against real hardware on every sync cycle, and
   bypassed ``MAX_RETRY_COUNT`` completely, since ``retry_failed_adoptions``
   only counts jobs that reach FAILED.

3. FIRMWARE SCHEDULES HAD NEVER RUN, EVER
   Nothing in the codebase wrote ``FirmwareSchedule.next_run_at``. Not create,
   not update, not ``run_schedule_now``. The column was NULL on every row ever
   made, and the beat task selects ``next_run_at <= now`` -- which NULL never
   satisfies. Not late, not partial: never. The five-minute checker ran on time
   and matched zero rows every time.

4. VPN ALERTS NEVER LEFT THE PUBLISHING PROCESS
   ``Event`` is a plain dataclass, so ``category`` is annotated
   ``EventCategory`` and never checked. ``Event(category="vpn")`` stored a raw
   string -- and there was no VPN member on the enum anyway -- so every
   ``category.value`` raised. The failure was shaped to hide: local dispatch
   runs BEFORE the Redis branch, so a single-process dev run looked perfect,
   while in any real deployment the publish raised on the channel name and no
   other worker ever saw a VPN alert. ``_publish`` swallows it at debug level.

5. A DISCONNECTED AGENT STAYED "CONNECTED" FOREVER
   ``_receiver_loop`` broke out when the peer went away but never cleared
   ``_running``, and the WebSocket endpoint parks on
   ``while connection._running``. So the endpoint coroutine never returned, its
   cleanup ``finally`` never ran, and the registry kept a connection whose
   socket was closed -- which matters because the registry is deliberately
   trusted over the DB status column when dispatching scans.
"""

from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.core.events import Event, EventCategory
from app.services.firmware import PersistentFirmwareService
from app.services.remote_agent import AgentConnection, AgentStatus


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. the PoE schedule ──────────────────────────────────────────


def test_the_poe_schedule_checks_the_adapter_result() -> None:
    """
    ``configure_switch_port`` returns AdapterResult and a refusal does not
    raise, so an unchecked call cannot tell success from failure.
    """
    from app.tasks import poe

    code = _code(poe)
    assert "raise_for_adapter_result" in code, (
        "the scheduled PoE push still discards the adapter's verdict"
    )
    assert "await adapter.configure_switch_port(" not in code.replace(
        "port_result = await adapter.configure_switch_port(", ""
    ), "an unchecked configure_switch_port call remains"


def test_the_result_is_checked_before_the_schedule_is_marked_done() -> None:
    """
    Ordering is the whole bug. Marking last_action first means the guard at the
    top of the loop skips the schedule for the rest of the window, so the
    failure is permanent for that window rather than retried next tick.
    """
    from app.tasks import poe

    code = _code(poe)
    assert code.index("raise_for_adapter_result") < code.index("any_device_succeeded = True")
    # The ASSIGNMENT, not the comparison at the top of the loop -- the two read
    # almost identically and matching the wrong one would make this vacuous.
    assert code.index("any_device_succeeded = True") < code.index(
        "schedule.last_action = desired_action"
    )


def test_the_skip_guard_that_makes_it_permanent_is_still_there() -> None:
    """
    Premise check. If this guard ever goes away the severity drops -- the task
    would retry on the next tick. Pin it so the two stay coupled.
    """
    from app.tasks import poe

    code = _code(poe)
    assert "if schedule.last_action == desired_action:" in code


def test_the_interactive_poe_paths_still_check_too() -> None:
    """Guard the class: all three PoE write paths, not just the one that broke."""
    from app.api.v1.endpoints import poe as poe_api

    code = _code(poe_api)
    assert code.count("raise_for_adapter_result") >= 2


# ── 2. the adoption job that never left PENDING ──────────────────


def test_a_failed_adoption_is_recorded_as_failed() -> None:
    """
    The rollback is correct for the pipeline's partial writes. The verdict has
    to survive it, or the job goes straight back into the PENDING work queue.
    """
    from app.tasks import adoption

    code = _code(adoption._execute_adoption)
    assert "_record_terminal_failure" in code
    assert code.index("await session.rollback()") < code.index(
        "_record_terminal_failure(job_id, str(result"
    ), "the failure must be recorded AFTER the rollback or it is rolled back too"


def test_the_terminal_write_uses_its_own_transaction() -> None:
    """
    Reusing the rolled-back session would put the write in a dead transaction.
    """
    from app.tasks import adoption

    code = _code(adoption._record_terminal_failure)
    assert "AsyncSessionLocal()" in code
    assert "await session.commit()" in code


def test_the_terminal_write_only_touches_a_still_pending_job() -> None:
    """
    Guarded so it cannot clobber a job another worker has claimed, nor re-fail
    one the "not in pending state" branch already declined to touch.
    """
    from app.tasks import adoption

    code = _code(adoption._record_terminal_failure)
    assert "AdoptionJobStatus.PENDING" in code


def test_the_bookkeeping_write_cannot_mask_the_real_failure() -> None:
    """An error while recording the failure must not replace the failure."""
    from app.tasks import adoption

    code = _code(adoption._record_terminal_failure)
    assert "except Exception:" in code

    exec_code = _code(adoption._execute_adoption)
    tail = exec_code[exec_code.index("except Exception as exc:") :]
    assert "raise" in tail, "the original exception must still propagate"


def test_pending_really_is_a_work_queue() -> None:
    """
    Premise. If sync_controller ever stops dispatching PENDING jobs, this stops
    being an infinite re-run and becomes merely a lost status.
    """
    from app.tasks import discovery

    code = _code(discovery)
    assert "AdoptionJobStatus.PENDING" in code
    assert "execute_adoption" in code


def test_the_retry_cap_only_counts_failed_jobs() -> None:
    """The cap the bug bypassed. Both halves pinned together."""
    from app.tasks import adoption

    code = _code(adoption._retry_failed_adoptions)
    assert "AdoptionJobStatus.FAILED" in code
    assert "MAX_RETRY_COUNT" in code


# ── 3. firmware schedules that never fired ───────────────────────


def _schedule(**kw):
    base = {
        "frequency": "weekly",
        "time_of_day": "02:00",
        "day_of_week": 6,
        "day_of_month": None,
        "timezone": "UTC",
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_a_weekly_schedule_gets_a_next_run() -> None:
    """The regression in one assertion: the column was NULL on every row."""
    after = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)  # a Wednesday
    nxt = PersistentFirmwareService.compute_next_run(_schedule(), after=after)

    assert nxt is not None
    assert nxt > after
    assert nxt.weekday() == 6  # Sunday
    assert (nxt.hour, nxt.minute) == (2, 0)


def test_the_next_run_is_strictly_in_the_future() -> None:
    """
    A next_run_at at or before now would fire immediately and then, if it were
    not advanced, on every five-minute tick after that.
    """
    now = datetime(2026, 8, 23, 2, 0, tzinfo=UTC)  # exactly a Sunday 02:00
    nxt = PersistentFirmwareService.compute_next_run(_schedule(), after=now)
    assert nxt > now
    assert (nxt - now).days == 7


def test_a_monthly_schedule_lands_on_its_day() -> None:
    after = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
    nxt = PersistentFirmwareService.compute_next_run(
        _schedule(frequency="monthly", day_of_month=5), after=after
    )
    assert nxt.day == 5
    assert nxt > after


def test_a_monthly_day_is_clamped_to_a_day_every_month_has() -> None:
    """Day 31 would be invalid in February and raise on the replace()."""
    after = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    nxt = PersistentFirmwareService.compute_next_run(
        _schedule(frequency="monthly", day_of_month=31), after=after
    )
    assert nxt is not None and nxt.day <= 28


def test_a_monthly_schedule_rolls_over_a_year_boundary() -> None:
    after = datetime(2026, 12, 20, 12, 0, tzinfo=UTC)
    nxt = PersistentFirmwareService.compute_next_run(
        _schedule(frequency="monthly", day_of_month=5), after=after
    )
    assert (nxt.year, nxt.month, nxt.day) == (2027, 1, 5)


def test_a_local_timezone_is_honoured() -> None:
    """
    "02:00" means 02:00 where the gear is. Treating it as UTC would run the
    upgrade in the middle of the working day for a US site.
    """
    after = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
    nxt = PersistentFirmwareService.compute_next_run(
        _schedule(timezone="America/New_York"), after=after
    )
    from zoneinfo import ZoneInfo

    assert nxt.astimezone(ZoneInfo("America/New_York")).hour == 2


def test_an_unknown_timezone_does_not_make_the_schedule_unrunnable() -> None:
    """Late by a few hours is recoverable; None is the bug being fixed."""
    after = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
    assert (
        PersistentFirmwareService.compute_next_run(
            _schedule(timezone="Mars/Olympus_Mons"), after=after
        )
        is not None
    )


@pytest.mark.parametrize("bad", ["", "notatime", "99:99", None, "2"])
def test_a_malformed_time_of_day_still_schedules(bad) -> None:
    after = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
    nxt = PersistentFirmwareService.compute_next_run(_schedule(time_of_day=bad), after=after)
    assert nxt is not None and nxt > after


def test_an_on_release_schedule_has_no_clock_time() -> None:
    """
    Deliberate. Those fire when a release appears, so a wall-clock next_run_at
    would be wrong rather than merely absent.
    """
    assert PersistentFirmwareService.compute_next_run(_schedule(frequency="on_release")) is None


def test_running_a_schedule_advances_its_clock() -> None:
    """
    Without this a schedule that DID have a next_run_at would re-fire on every
    five-minute tick -- a firmware upgrade every five minutes, which is the
    opposite failure and much worse.
    """
    code = _code(PersistentFirmwareService.run_schedule_now)
    assert "next_run_at" in code
    assert code.index("schedule.last_run_at") < code.index("schedule.next_run_at")


def test_creating_and_editing_a_schedule_sets_the_clock() -> None:
    assert "compute_next_run" in _code(PersistentFirmwareService.create_schedule)
    update = _code(PersistentFirmwareService.update_schedule)
    assert "compute_next_run" in update
    assert "timing_fields" in update, "moving a schedule must move its next fire time"


def test_existing_null_rows_are_healed_by_the_beat_task() -> None:
    """
    Every row that already exists has next_run_at NULL, and no migration
    touches them. The checker backfills so an operator's existing schedules
    start working without anyone having to notice.
    """
    from app.tasks import firmware

    code = _code(firmware.check_scheduled_upgrades)
    assert "next_run_at.is_(None)" in code
    assert "compute_next_run" in code


# ── 4. the VPN event category ────────────────────────────────────


def test_the_event_category_enum_has_a_vpn_member() -> None:
    assert EventCategory("vpn") is EventCategory.VPN


def test_a_string_category_is_coerced_to_the_enum() -> None:
    """
    The dataclass never validated it, so ``Event(category="vpn")`` stored a str
    and every ``category.value`` downstream raised.
    """
    event = Event(event_type="vpn.tunnel.down", category="vpn")
    assert event.category is EventCategory.VPN
    assert event.to_dict()["category"] == "vpn"


def test_the_event_serialises_at_all() -> None:
    """``to_dict`` raised AttributeError, which is what broke the Redis publish."""
    payload = Event(event_type="vpn.tunnel.down", category="vpn", payload={"a": 1}).to_dict()
    assert payload["event_type"] == "vpn.tunnel.down"
    assert payload["payload"] == {"a": 1}


def test_an_unknown_category_still_publishes(caplog) -> None:
    """
    Falls back to system with a warning rather than raising: an event under the
    wrong category is recoverable, one that never publishes is not.
    """
    event = Event(event_type="x.y", category="not-a-real-category")
    assert event.category is EventCategory.SYSTEM
    assert event.to_dict()["category"] == "system"


def test_a_real_enum_category_is_left_alone() -> None:
    assert Event(event_type="x.y", category=EventCategory.DEVICE).category is EventCategory.DEVICE


def test_the_vpn_alert_service_uses_the_enum() -> None:
    from app.services import vpn_alerts

    code = _code(vpn_alerts)
    assert 'category="vpn"' not in code
    assert "EventCategory.VPN" in code


async def test_a_vpn_event_reaches_the_redis_channel() -> None:
    """
    The behaviour that was broken. Local dispatch always worked, which is why
    a single-process dev run looked fine; the Redis fanout is what every other
    worker depends on.
    """
    from app.core.events import EventBus

    bus = EventBus()
    published: list[tuple[str, str]] = []

    class _Redis:
        async def publish(self, channel, message):
            published.append((channel, message))

    bus._redis = _Redis()
    await bus.publish(Event(event_type="vpn.tunnel.down", category="vpn", payload={"t": 1}))

    assert published, "the VPN event never reached Redis, so no other worker sees it"
    assert published[0][0].startswith("freesdn:events:vpn:")


async def test_the_publisher_swallows_errors_at_debug_level() -> None:
    """
    Premise, and why this went unnoticed for so long: there was nothing in the
    logs to find.
    """
    from app.services import vpn_alerts

    code = _code(vpn_alerts.VPNAlertService._publish)
    assert "except Exception:" in code
    assert "logger.debug" in code


# ── 5. the agent connection that never closed ────────────────────


def _connection() -> AgentConnection:
    conn = AgentConnection.__new__(AgentConnection)
    conn.info = SimpleNamespace(
        agent_id=str(uuid4()), site_id=uuid4(), last_heartbeat=None, status=AgentStatus.OFFLINE
    )
    conn._pending_commands = {}
    conn._report_handlers = {}
    conn._running = True
    conn._max_frame_bytes = 1_000_000
    conn._rate_limiter = SimpleNamespace(check=lambda: True)
    return conn


async def test_a_disconnect_releases_the_endpoints_wait_loop() -> None:
    """
    The regression. The endpoint parks on ``while connection._running``, so a
    receiver that exits without clearing the flag hangs it forever -- the
    cleanup ``finally`` never runs and the registry keeps a dead connection.
    """
    conn = _connection()
    conn.websocket = MagicMock()
    conn.websocket.receive_text = AsyncMock(side_effect=RuntimeError("client disconnected"))

    await asyncio.wait_for(conn._receiver_loop(), timeout=5)
    assert conn._running is False


async def test_a_rate_limited_agent_also_releases_it() -> None:
    """The other way out of that loop, and it had the same problem."""
    conn = _connection()
    conn._rate_limiter = SimpleNamespace(check=lambda: False)
    conn.websocket = MagicMock()
    conn.websocket.receive_text = AsyncMock(return_value="{}")

    await asyncio.wait_for(conn._receiver_loop(), timeout=5)
    assert conn._running is False


async def test_cancellation_also_clears_the_flag() -> None:
    """``stop()`` cancels the task; the flag must not survive that either."""
    conn = _connection()
    conn.websocket = MagicMock()
    conn.websocket.receive_text = AsyncMock(side_effect=asyncio.CancelledError())

    await asyncio.wait_for(conn._receiver_loop(), timeout=5)
    assert conn._running is False


async def test_the_endpoint_wait_loop_would_now_exit() -> None:
    """
    End to end for the symptom: run the endpoint's actual wait expression
    against a connection whose peer just went away.
    """
    conn = _connection()
    conn.websocket = MagicMock()
    conn.websocket.receive_text = AsyncMock(side_effect=RuntimeError("gone"))

    receiver = asyncio.create_task(conn._receiver_loop())

    async def _endpoint_wait() -> None:
        while conn._running:
            await asyncio.sleep(0.01)

    await asyncio.wait_for(_endpoint_wait(), timeout=5)
    await receiver


def test_the_endpoint_still_waits_on_that_flag() -> None:
    """Premise. If the endpoint stops reading _running, this fix moves."""
    from app.api.v1.endpoints import agents

    code = _code(agents)
    assert "while connection._running:" in code
