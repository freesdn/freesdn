# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Supervision for third-party plugin code: attribution, budgets, quarantine.

Plugins run in-process. The loader is explicit that this is import hygiene and
not a sandbox, which is a defensible position -- but it only holds if a plugin
that misbehaves is *contained and visible*. Neither was true:

  * A plugin whose ``on_event`` raised on every single event logged
    ``Error in event handler for device.updated`` forever, with no plugin name
    in it. The bus swallows handler exceptions by design, so nothing surfaced,
    nothing degraded, and nobody could tell which plugin was responsible.
  * ``freesdn_plugin_operations_total`` was declared in metrics.py and
    incremented from nowhere. There was no plugin observability of any kind: no
    call counts, no error rate, no latency, no way to answer "is this plugin
    healthy" other than reading logs.
  * Nothing ever stopped calling a plugin. A handler that times out on every
    event burns its 10s budget on every event, forever.

This module adds the missing half. Every entry into plugin-authored code goes
through :func:`guard`, which:

  * records duration and outcome against per-plugin Prometheus series, so the
    question "which plugin is slow / failing" has an answer;
  * keeps a rolling error budget per (plugin, operation);
  * QUARANTINES a plugin that trips the budget -- subsequent calls are refused
    immediately for a cooldown, instead of being attempted and failing;
  * half-opens after the cooldown so a plugin that recovers comes back on its
    own, exactly like the adapter breaker.

Deliberately NOT a security boundary. A plugin determined to hang the process
can still do so with a tight synchronous loop; this bounds *accidental* damage
and makes the source obvious, which is the realistic threat for trusted-author
code. Real isolation means a separate process, which is a different project.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class PluginState(StrEnum):
    """Where a plugin sits with respect to its error budget."""

    HEALTHY = "healthy"
    #: Failing, but still under the budget. Calls still go through.
    DEGRADED = "degraded"
    #: Budget tripped. Calls are refused until the cooldown elapses.
    QUARANTINED = "quarantined"
    #: Waiting on something outside the plugin: an unreachable NetBox, an
    #: expired token, a controller mid-reboot. Not a fault, and not counted as
    #: one -- the platform retries with backoff and says what it is waiting for.
    NOT_READY = "not_ready"


class PluginNotReady(RuntimeError):
    """The plugin is fine; the thing it talks to is not.

    Borrowed from Home Assistant's ``ConfigEntryNotReady``, and the distinction
    it draws is the one FreeSDN was missing: supervision could tell that a
    plugin had failed five times, and could not tell whether the plugin was
    broken or somebody had rebooted their NetBox for ten minutes.

    Both looked identical, so both were punished identically: a perfectly good
    integration was quarantined for an outage in a system it does not own, and
    then sat out an exponential cooldown after the outage ended.

    Raise this and the failure is recorded, surfaced, and RETRIED with backoff.
    It never counts toward quarantine, because there is no failure here to
    protect the platform from.

        if not await self._reachable():
            raise PluginNotReady("NetBox at netbox.lan is not responding")

    Anything else raising is still treated as a fault, which is the right
    default: a plugin that does not know why it failed should not be able to
    claim it was somebody else's problem.
    """

    def __init__(self, reason: str, *, retry_after: float | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        #: Hint for the next attempt. Left to the caller's backoff when None.
        self.retry_after = retry_after


class PluginQuarantined(RuntimeError):
    """Raised instead of calling a plugin that is currently quarantined."""

    def __init__(self, plugin_id: str, until: float, reason: str) -> None:
        self.plugin_id = plugin_id
        self.until = until
        self.reason = reason
        remaining = max(0, int(until - time.monotonic()))
        super().__init__(
            f"Plugin '{plugin_id}' is quarantined for another {remaining}s after "
            f"repeated failures ({reason})."
        )


@dataclass
class OperationHealth:
    """Rolling health for one (plugin, operation) pair."""

    calls: int = 0
    errors: int = 0
    timeouts: int = 0
    consecutive_errors: int = 0
    last_error: str | None = None
    last_error_at: float | None = None
    #: Durations of the most recent calls, for a p95 that does not need a TSDB.
    recent_durations: deque[float] = field(default_factory=lambda: deque(maxlen=50))

    @property
    def error_rate(self) -> float:
        return (self.errors / self.calls) if self.calls else 0.0

    def snapshot(self) -> dict[str, Any]:
        durations = sorted(self.recent_durations)
        p95 = durations[int(len(durations) * 0.95)] if durations else None
        return {
            "calls": self.calls,
            "errors": self.errors,
            "timeouts": self.timeouts,
            "consecutive_errors": self.consecutive_errors,
            "error_rate": round(self.error_rate, 4),
            "p95_seconds": round(p95, 4) if p95 is not None else None,
            "last_error": self.last_error,
        }


@dataclass
class PluginHealth:
    """Everything supervision knows about one plugin."""

    plugin_id: str
    operations: dict[str, OperationHealth] = field(default_factory=dict)
    quarantined_until: float = 0.0
    quarantine_reason: str = ""
    quarantine_count: int = 0

    #: Set while the plugin is waiting on something outside itself. Kept apart
    #: from the quarantine fields on purpose: "broken" and "blocked" are
    #: different states and an operator needs to be told which one they have.
    not_ready_reason: str | None = None
    not_ready_since: float | None = None
    not_ready_attempts: int = 0
    retry_after: float | None = None

    def op(self, operation: str) -> OperationHealth:
        return self.operations.setdefault(operation, OperationHealth())

    @property
    def state(self) -> PluginState:
        if self.quarantined_until > time.monotonic():
            return PluginState.QUARANTINED
        # Ranked above DEGRADED deliberately. A plugin whose NetBox is down is
        # not degraded code; reporting it as such sends an operator to read a
        # plugin that is working correctly.
        if self.not_ready_reason is not None:
            return PluginState.NOT_READY
        if any(o.consecutive_errors > 0 for o in self.operations.values()):
            return PluginState.DEGRADED
        return PluginState.HEALTHY

    def snapshot(self) -> dict[str, Any]:
        remaining = max(0.0, self.quarantined_until - time.monotonic())
        blocked_for = (
            max(0.0, time.monotonic() - self.not_ready_since)
            if self.not_ready_since is not None
            else 0.0
        )
        return {
            "not_ready_reason": self.not_ready_reason,
            "not_ready_for_seconds": round(blocked_for, 1),
            "not_ready_attempts": self.not_ready_attempts,
            "retry_after_seconds": self.retry_after,
            "plugin_id": self.plugin_id,
            "state": str(self.state),
            "quarantined_for_seconds": round(remaining, 1) if remaining else 0,
            "quarantine_reason": self.quarantine_reason or None,
            "quarantine_count": self.quarantine_count,
            "operations": {name: op.snapshot() for name, op in self.operations.items()},
            "totals": {
                "calls": sum(o.calls for o in self.operations.values()),
                "errors": sum(o.errors for o in self.operations.values()),
            },
        }


class PluginSupervisor:
    """Error budgets and quarantine for plugin-authored code."""

    #: Consecutive failures of one operation before the plugin is quarantined.
    #: Deliberately not 1: a transient upstream blip should not quarantine a
    #: plugin whose only fault was being downstream of it.
    FAILURE_THRESHOLD = 5
    #: How long a quarantine lasts before the plugin gets another chance.
    COOLDOWN_SECONDS = 120.0
    #: Each repeat quarantine doubles the cooldown, up to this. A plugin that is
    #: simply broken should stop consuming resources at a growing interval
    #: rather than retrying every two minutes forever.
    MAX_COOLDOWN_SECONDS = 3600.0

    #: Backoff for a plugin waiting on something outside itself. Doubles per
    #: attempt. Deliberately gentler than quarantine: nothing is wrong with
    #: the plugin, so the platform is being patient, not defensive.
    NOT_READY_BASE_SECONDS = 30.0
    NOT_READY_MAX_SECONDS = 900.0
    #: Ceiling on any single call into plugin code. The event bus has its own
    #: 10s budget; this covers routes, lifecycle hooks and AI tools, which had
    #: none at all.
    DEFAULT_TIMEOUT_SECONDS = 30.0

    def __init__(self) -> None:
        self._health: dict[str, PluginHealth] = {}

    # ── State ───────────────────────────────────────────────────────

    def health(self, plugin_id: str) -> PluginHealth:
        return self._health.setdefault(plugin_id, PluginHealth(plugin_id=plugin_id))

    def mark_not_ready(self, plugin_id: str, reason: str, retry_after: float | None) -> None:
        """Record that a plugin is waiting on something outside itself."""
        health = self.health(plugin_id)
        health.not_ready_reason = reason[:300]
        health.not_ready_since = health.not_ready_since or time.monotonic()
        health.not_ready_attempts += 1
        health.retry_after = retry_after or min(
            self.NOT_READY_BASE_SECONDS * (2 ** min(health.not_ready_attempts - 1, 6)),
            self.NOT_READY_MAX_SECONDS,
        )
        logger.info(
            "Plugin %s is not ready (attempt %d): %s. Retrying in ~%.0fs",
            plugin_id,
            health.not_ready_attempts,
            reason[:200],
            health.retry_after,
        )

    def mark_ready(self, plugin_id: str) -> None:
        """Whatever it was waiting for has come back."""
        health = self.health(plugin_id)
        if health.not_ready_reason is None:
            return
        logger.info(
            "Plugin %s is ready again after %d attempt(s)",
            plugin_id,
            health.not_ready_attempts,
        )
        health.not_ready_reason = None
        health.not_ready_since = None
        health.not_ready_attempts = 0
        health.retry_after = None

    def snapshot(self, plugin_id: str | None = None) -> dict[str, Any]:
        if plugin_id is not None:
            return self.health(plugin_id).snapshot()
        return {pid: h.snapshot() for pid, h in self._health.items()}

    def quarantined_plugins(self) -> list[str]:
        return [pid for pid, h in self._health.items() if h.state is PluginState.QUARANTINED]

    def reset(self, plugin_id: str) -> None:
        """Clear a plugin's health. Used on uninstall, and by an operator who
        has fixed the cause and wants the plugin back without waiting."""
        self._health.pop(plugin_id, None)

    # ── The guard ───────────────────────────────────────────────────

    @contextlib.asynccontextmanager
    async def guard(
        self,
        plugin_id: str,
        operation: str,
        *,
        timeout: float | None = None,
        record_only: bool = False,
    ) -> AsyncIterator[None]:
        """Wrap one call into plugin-authored code.

        Args:
            plugin_id: whose code is about to run.
            operation: what kind of call -- ``event``, ``route``, ``ai_tool``,
                ``lifecycle``. Kept low-cardinality on purpose: it becomes a
                Prometheus label, and a label with unbounded values is how a
                metrics backend falls over.
            timeout: overrides the default ceiling.
            record_only: count and time the call but never quarantine. Used for
                lifecycle hooks, where refusing to run ``on_uninstall`` because
                ``on_install`` failed would trap a broken plugin in place.

        Raises:
            PluginQuarantined: before running anything, when the plugin is
                currently quarantined and ``record_only`` is not set.
        """
        health = self.health(plugin_id)
        if not record_only and health.state is PluginState.QUARANTINED:
            _record_metric(plugin_id, operation, "quarantined", None)
            raise PluginQuarantined(plugin_id, health.quarantined_until, health.quarantine_reason)

        op = health.op(operation)
        op.calls += 1
        started = time.monotonic()
        outcome = "ok"
        try:
            if timeout is None:
                timeout = self.DEFAULT_TIMEOUT_SECONDS
            # An asyncio timeout only interrupts at an await point. Plugin code
            # that never yields is not stopped by this, which is the honest
            # limit of in-process supervision.
            async with asyncio.timeout(timeout):
                yield
        except TimeoutError:
            outcome = "timeout"
            op.timeouts += 1
            self._failure(health, op, operation, f"timed out after {timeout}s", record_only)
            raise
        except PluginQuarantined:
            raise
        except PluginNotReady as exc:
            # NOT a failure. The plugin is telling us the thing it depends on is
            # unavailable, which is information, not a fault -- and counting it
            # would quarantine a working integration for somebody else's
            # outage, then make it sit out a cooldown after the outage ended.
            outcome = "not_ready"
            self.mark_not_ready(health.plugin_id, exc.reason, exc.retry_after)
            raise
        except Exception as exc:
            outcome = "error"
            self._failure(health, op, operation, f"{type(exc).__name__}: {exc}", record_only)
            raise
        else:
            # A success resets the streak but NOT the totals: the error rate
            # stays visible, while the breaker stops counting toward a trip.
            op.consecutive_errors = 0
            # And it clears a not-ready state: whatever the plugin was waiting
            # for has answered. Without this the plugin reads as blocked
            # forever after one transient outage.
            self.mark_ready(health.plugin_id)
        finally:
            elapsed = time.monotonic() - started
            op.recent_durations.append(elapsed)
            _record_metric(plugin_id, operation, outcome, elapsed)

    def _failure(
        self,
        health: PluginHealth,
        op: OperationHealth,
        operation: str,
        reason: str,
        record_only: bool,
    ) -> None:
        op.errors += 1
        op.consecutive_errors += 1
        op.last_error = reason[:500]
        op.last_error_at = time.monotonic()

        # Attribution is half the value here. The bus logged "Error in event
        # handler for device.updated" with no plugin in it, so a failing plugin
        # was invisible in a log full of them.
        logger.warning(
            "Plugin %s failed during %s (%d consecutive): %s",
            health.plugin_id,
            operation,
            op.consecutive_errors,
            reason[:200],
        )

        if record_only or op.consecutive_errors < self.FAILURE_THRESHOLD:
            return

        cooldown = min(
            self.COOLDOWN_SECONDS * (2**health.quarantine_count),
            self.MAX_COOLDOWN_SECONDS,
        )
        health.quarantined_until = time.monotonic() + cooldown
        health.quarantine_reason = f"{operation}: {reason[:200]}"
        health.quarantine_count += 1
        op.consecutive_errors = 0  # start the next window clean
        logger.error(
            "Plugin %s QUARANTINED for %.0fs after %d consecutive %s failures. Last: %s",
            health.plugin_id,
            cooldown,
            self.FAILURE_THRESHOLD,
            operation,
            reason[:200],
        )
        _set_quarantine_metric(health.plugin_id, True)


def _record_metric(plugin_id: str, operation: str, outcome: str, elapsed: float | None) -> None:
    """Best-effort metrics. Never let instrumentation break the thing it measures."""
    try:
        from app.core import metrics

        metrics.plugin_operations_total.labels(
            plugin_id=plugin_id, operation=operation, status=outcome
        ).inc()
        if elapsed is not None:
            metrics.plugin_operation_duration.labels(
                plugin_id=plugin_id, operation=operation
            ).observe(elapsed)
    except Exception:  # pragma: no cover - metrics must never be load-bearing
        logger.debug("plugin metric record failed", exc_info=True)


def _set_quarantine_metric(plugin_id: str, quarantined: bool) -> None:
    try:
        from app.core import metrics

        metrics.plugin_quarantined.labels(plugin_id=plugin_id).set(1 if quarantined else 0)
    except Exception:  # pragma: no cover
        logger.debug("plugin quarantine metric failed", exc_info=True)


#: Process-wide supervisor. One per process, like the plugin loader itself.
supervisor = PluginSupervisor()
