# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Running plugin work on a timer, per organization.

Until this existed, a plugin acted only when an event arrived or an operator
pressed a button. Three of the four first-party plugins are periodic by nature
and all three were shipped without a way to be periodic:

  * ``config-drift-guard`` scanned when someone clicked ``POST /scan``. A drift
    guard that runs on demand is a report generator; the drift it exists to
    catch happens while nobody is looking.
  * ``netbox-sync`` synced on a button, so the external inventory was stale by
    construction.
  * ``new-device-watch`` saw devices through events, with no sweep to find what
    the events missed.

The design, and why each part is the way it is:

SLOT CLAIMS, NOT TIMERS
    A worker does not remember when it last ran something. Each tick computes
    the current slot -- ``floor((now + offset) / interval)`` -- and claims
    ``SET NX EX`` on a key naming that slot. Whoever wins runs it. This is
    duplicate suppression while the shared claim remains present. Redis loss,
    eviction or restoring an older Redis snapshot can lose that protection;
    external effects still need their own idempotency. A failed or uncertain
    claim never authorizes a local fallback. Missed slots are not caught up.

    It also disposes of catch-up. If the platform was down for six hours, only
    the CURRENT slot can be claimed, so a 15-minute scan runs once on return
    rather than twenty-four times. Catch-up on a monitoring scan is worthless --
    the answer it would have given six hours ago is not the answer anyone wants.

DETERMINISTIC JITTER
    Without an offset, every organization's 15-minute scan fires on the same
    quarter hour, so an appliance serving twelve organizations does twelve
    inventory sweeps simultaneously and idles for the rest. The offset is
    derived from the schedule's identity, so it is stable across restarts and
    identical on every worker (which matters -- workers must agree on where the
    slot boundary is, or they claim different slots and both run).

ITS OWN SESSION
    Runs concurrently with routes and event handlers by definition, and asyncpg
    permits one operation per connection. See ``plugin_session_scope``.

SUPERVISED LIKE EVERYTHING ELSE
    A scheduled run counts against the plugin's error budget, and a quarantined
    plugin is skipped rather than run every interval. A plugin failing
    unattended every 60 seconds forever is the exact thing the budget exists to
    stop, and scheduling is the feature most likely to produce it.

    The supervisor's ``operation`` label is a Prometheus label, so it stays
    ``schedule`` -- not ``schedule:{name}``, which would put unbounded
    cardinality into the metrics backend.

WHAT IT DOES NOT DO
    No cron expressions. An interval is unambiguous; a cron field is not,
    and a half-built cron parser with unstated timezone behaviour would give an
    operator a schedule they misread -- one that runs at the wrong hour and
    looks correct. Interval only, until someone needs more and can say what the
    timezone rules should be.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:  # pragma: no cover
    from app.plugins.schema import PluginSchedule
    from app.plugins.sdk import FreeSDNPlugin

logger = logging.getLogger(__name__)

#: How often the loop looks for work. A schedule fires within this of its slot
#: boundary, which is why the interval floor is 60s -- a 15s tick cannot
#: meaningfully pace anything faster.
TICK_SECONDS = 15.0

#: Ceiling on a single run, on top of the schedule's own interval. A run that
#: outlives its interval can never keep up, so the interval is the natural
#: timeout; this caps the long ones, because a 24-hour schedule should not be
#: able to hold a session and a connection open for 24 hours.
MAX_RUN_SECONDS = 3600.0

#: How long a run record survives in Redis. Long enough that an operator
#: returning on Monday can see Friday's failure.
RUN_RECORD_TTL = 7 * 24 * 3600

#: Prefix for the per-organization setting that turns one schedule off. Settings
#: whose key starts with ``__`` are platform-internal: the settings API hides
#: them from the operator's config form and refuses to write them, so a plugin's
#: own bookkeeping cannot be edited as though it were configuration.
DISABLED_SETTING_PREFIX = "__schedule_disabled__"

_REDIS_UNSET = object()


@dataclass
class ScheduleRun:
    """What happened the last time a schedule ran."""

    status: str  # ok | error | timeout | quarantined | missing_method
    started_at: float
    duration_ms: float
    error: str | None = None
    worker: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScheduleStats:
    """Cumulative, per worker. The last run is shared through Redis; these are
    not -- they describe what THIS process has seen, and say so."""

    runs: int = 0
    failures: int = 0
    last: ScheduleRun | None = None


@dataclass
class _Key:
    plugin_id: str
    organization_id: UUID
    name: str

    def redis_suffix(self) -> str:
        return f"{self.plugin_id}:{self.organization_id}:{self.name}"

    def tuple(self) -> tuple[str, UUID, str]:
        return (self.plugin_id, self.organization_id, self.name)


class PluginScheduler:
    """Run current schedule slots only after a confirmed shared claim."""

    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None
        self._running: set[tuple[str, UUID, str]] = set()
        self._stats: dict[tuple[str, UUID, str], ScheduleStats] = {}
        self._redis: Any = _REDIS_UNSET
        # Diagnostics are worker-local and are NOT execution records. A refused
        # attempt must not increment the count of scheduled methods that ran.
        self._blocked: dict[tuple[str, UUID, str], dict[str, Any]] = {}
        self._redis_retry_at = 0.0
        self._inflight: set[asyncio.Task[None]] = set()

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop(), name="plugin-scheduler")
        logger.info("Plugin scheduler started (tick %.0fs)", TICK_SECONDS)

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        # Let in-flight runs finish rather than tearing a plugin's work in half
        # mid-transaction. Bounded, because shutdown cannot block forever.
        if self._inflight:
            _, pending = await asyncio.wait(self._inflight, timeout=10.0)
            if pending:
                logger.warning(
                    "Plugin scheduler stopping with %d run(s) still in flight", len(pending)
                )
                for t in pending:
                    t.cancel()
        logger.info("Plugin scheduler stopped")

    # ── observability ────────────────────────────────────────────────────

    def stats(self, plugin_id: str, organization_id: UUID) -> dict[str, dict[str, Any]]:
        """Per-schedule counters this process has observed."""
        out: dict[str, dict[str, Any]] = {}
        for (pid, org, name), stat in self._stats.items():
            if pid == plugin_id and org == organization_id:
                out[name] = {
                    "runs": stat.runs,
                    "failures": stat.failures,
                    "last": stat.last.to_dict() if stat.last else None,
                }
        for (pid, org, name), blocked in self._blocked.items():
            if pid == plugin_id and org == organization_id:
                out.setdefault(name, {"runs": 0, "failures": 0, "last": None})["blocked"] = dict(
                    blocked
                )
        return out

    def _block(self, key: _Key, reason: str) -> None:
        from app.core.startup import SUBSYSTEM_STATUS

        previous = self._blocked.get(key.tuple())
        if previous is None or previous["reason"] != reason:
            self._blocked[key.tuple()] = {"reason": reason, "since": time.time()}
            logger.warning("Plugin schedule %s paused: %s", key.redis_suffix(), reason)
        SUBSYSTEM_STATUS["plugin_scheduler"] = "degraded"

    def _unblock(self, key: _Key, *, reason: str | None = None) -> None:
        from app.core.startup import SUBSYSTEM_STATUS

        previous = self._blocked.get(key.tuple())
        if previous is not None and (reason is None or previous["reason"] == reason):
            self._blocked.pop(key.tuple())
        if not self._blocked:
            SUBSYSTEM_STATUS["plugin_scheduler"] = "healthy"

    async def last_run(self, plugin_id: str, organization_id: UUID, name: str) -> dict | None:
        """The last run recorded by ANY worker, or this one's if Redis is down.

        Worth the round trip: without it, an operator on a two-worker deployment
        sees "never run" half the time they refresh, for a schedule running
        perfectly well on the other worker.
        """
        key = _Key(plugin_id, organization_id, name)
        r = await self._get_redis()
        if r is not None:
            try:
                raw = await r.get(f"plugin:sched:last:{key.redis_suffix()}")
                if raw:
                    return dict(json.loads(raw))
            except Exception:
                logger.debug("Plugin scheduler: last-run read failed for %s", key.redis_suffix())
        stat = self._stats.get(key.tuple())
        return stat.last.to_dict() if stat and stat.last else None

    def next_run_at(self, plugin_id: str, organization_id: UUID, sched: PluginSchedule) -> float:
        """Epoch seconds of the next slot boundary. Same on every worker."""
        key = _Key(plugin_id, organization_id, sched.name)
        offset = self._offset(key, sched.interval_seconds)
        now = time.time()
        slot = int((now + offset) // sched.interval_seconds)
        return (slot + 1) * sched.interval_seconds - offset

    # ── the loop ─────────────────────────────────────────────────────────

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(TICK_SECONDS)
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                # One bad tick must never end the scheduler. A scheduler that
                # dies silently is worse than one that never existed, because
                # the UI keeps showing schedules that no longer run.
                logger.exception("Plugin scheduler tick failed; continuing")

    async def _tick(self) -> None:
        from app.plugins.loader import plugin_loader

        active_keys = set()
        for (plugin_id, org_id), runtime in list(plugin_loader.get_active().items()):
            for sched in self._schedules_of(runtime):
                key = _Key(plugin_id, org_id, sched.name)
                active_keys.add(key.tuple())
                if key.tuple() in self._running:
                    # Still running from a previous slot. Skipping is right:
                    # stacking a second scan on top of a slow one turns a
                    # struggling plugin into a self-inflicted load test.
                    continue
                if not await self._claim(key, sched):
                    continue
                task = asyncio.create_task(
                    self._run(runtime, key, sched),
                    name=f"plugin-schedule:{plugin_id}:{sched.name}",
                )
                self._inflight.add(task)
                task.add_done_callback(self._inflight.discard)
        for identity in set(self._blocked) - active_keys:
            self._unblock(_Key(*identity))

    @staticmethod
    def _schedules_of(runtime: FreeSDNPlugin) -> list[PluginSchedule]:
        manifest = getattr(runtime, "_plugin_manifest_data", None)
        return list(getattr(manifest, "schedules", None) or [])

    # ── claiming ─────────────────────────────────────────────────────────

    @staticmethod
    def _offset(key: _Key, interval: int) -> int:
        """A stable per-schedule position inside the interval.

        Hash rather than ``random``: every worker must compute the same slot
        boundary or they claim different slots and the schedule runs twice.
        """
        digest = hashlib.sha256(key.redis_suffix().encode()).digest()
        return int.from_bytes(digest[:4], "big") % max(1, interval)

    async def _claim(self, key: _Key, sched: PluginSchedule) -> bool:
        interval = sched.interval_seconds
        slot = int((time.time() + self._offset(key, interval)) // interval)

        r = await self._get_redis()
        if r is not None:
            try:
                acquired = await r.set(
                    f"plugin:sched:slot:{key.redis_suffix()}:{slot}",
                    "1",
                    nx=True,
                    ex=interval,
                )
                if acquired is not True and acquired is not False and acquired is not None:
                    self._block(key, "coordination_unavailable")
                    return False
                self._unblock(key, reason="coordination_unavailable")
                return acquired is True
            except Exception:
                # SET may have committed even when its reply was lost. An
                # uncertain reply never authorizes a per-process fallback.
                self._block(key, "coordination_unavailable")
                return False

        self._block(key, "coordination_unavailable")
        return False

    async def _get_redis(self) -> Any:
        if self._redis is _REDIS_UNSET:
            if time.monotonic() < self._redis_retry_at:
                return None
            try:
                from app.core.redis_client import get_async_redis

                self._redis = get_async_redis(decode_responses=True)
            except Exception:
                # Retry client construction on a later tick, not for each
                # schedule in this tick. Do not cache an outage forever.
                self._redis_retry_at = time.monotonic() + TICK_SECONDS
                return None
        return self._redis

    # ── running ──────────────────────────────────────────────────────────

    async def _run(self, runtime: FreeSDNPlugin, key: _Key, sched: PluginSchedule) -> None:
        from app.plugins.sdk import plugin_session_scope
        from app.plugins.supervision import PluginQuarantined, supervisor

        self._running.add(key.tuple())
        started = time.time()
        monotonic_start = time.monotonic()
        status = "ok"
        error: str | None = None
        try:
            method = getattr(runtime, sched.method, None)
            if not callable(method):
                # The manifest validator cannot catch this: it never imports the
                # plugin class. Report it as a failed run rather than logging
                # into the void, so an operator sees WHY nothing is happening.
                status = "missing_method"
                error = f"plugin has no method {sched.method!r}"
                logger.error(
                    "Plugin %s schedule %s: no method %r", key.plugin_id, sched.name, sched.method
                )
                return

            timeout = min(float(sched.interval_seconds), MAX_RUN_SECONDS)
            async with plugin_session_scope():
                if await self._is_disabled(key, sched):
                    status = "disabled"
                    return
                async with supervisor.guard(key.plugin_id, "schedule", timeout=timeout):
                    await method()
        except PluginQuarantined:
            status = "quarantined"
            error = "plugin is quarantined"
        except TimeoutError:
            status = "timeout"
            error = f"exceeded {min(float(sched.interval_seconds), MAX_RUN_SECONDS):.0f}s"
        except asyncio.CancelledError:
            status = "cancelled"
            error = "shutdown"
            raise
        except Exception as exc:
            status = "error"
            error = f"{type(exc).__name__}: {exc}"
            logger.exception("Plugin %s schedule %s failed", key.plugin_id, sched.name)
        finally:
            self._running.discard(key.tuple())
            if status != "disabled":
                await self._record(
                    key,
                    ScheduleRun(
                        status=status,
                        started_at=started,
                        duration_ms=(time.monotonic() - monotonic_start) * 1000,
                        error=error,
                    ),
                )

    async def _is_disabled(self, key: _Key, sched: PluginSchedule) -> bool:
        """Has an operator turned this schedule off for this organization?

        Checked here, after the claim, rather than every tick: a claim happens
        once per interval, so this costs one query per interval instead of one
        every 15 seconds per schedule per organization -- and it is always
        current, which a cache would not be.

        NO ROW is not the same as a row saying "enabled". A schedule that ships
        ``enabled_by_default: false`` -- netbox-sync's, because it writes to
        somebody else's system of record -- has no row until an operator makes a
        choice, and treating that as enabled would start it unattended on first
        install, which is exactly what the flag exists to prevent.
        """
        from sqlalchemy import select

        from app.models.plugins import PluginSetting
        from app.plugins.sdk import _plugin_session

        session = _plugin_session.get()
        if session is None:
            self._block(key, "settings_unavailable")
            return True
        try:
            result = await session.execute(
                select(PluginSetting.value).where(
                    PluginSetting.plugin_id == key.plugin_id,
                    PluginSetting.organization_id == key.organization_id,
                    PluginSetting.key == f"{DISABLED_SETTING_PREFIX}{key.name}",
                )
            )
            row = result.first()
            self._unblock(key, reason="settings_unavailable")
            if row is None:
                return not sched.enabled_by_default
            return bool(row[0])
        except Exception:
            # An unreadable row is not proof that no operator choice exists.
            # In particular it must not re-enable a default-on schedule which
            # an operator disabled. Surface the pause without recording a run.
            self._block(key, "settings_unavailable")
            return True

    async def _record(self, key: _Key, run: ScheduleRun) -> None:
        stat = self._stats.setdefault(key.tuple(), ScheduleStats())
        stat.runs += 1
        if run.status != "ok":
            stat.failures += 1
        stat.last = run

        level = logging.INFO if run.status == "ok" else logging.WARNING
        logger.log(
            level,
            "Plugin %s schedule %s for org %s: %s in %.0fms%s",
            key.plugin_id,
            key.name,
            key.organization_id,
            run.status,
            run.duration_ms,
            f" ({run.error})" if run.error else "",
        )

        r = await self._get_redis()
        if r is None:
            return
        with contextlib.suppress(Exception):
            await r.set(
                f"plugin:sched:last:{key.redis_suffix()}",
                json.dumps(run.to_dict()),
                ex=RUN_RECORD_TTL,
            )


plugin_scheduler = PluginScheduler()
