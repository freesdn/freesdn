# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Vendor-agnostic circuit breaker for adapter clients
==============================================================

Three-state circuit breaker around vendor API calls. After
``failure_threshold`` consecutive failures the breaker trips ``open``
and rejects calls immediately for ``cooldown_seconds``; one probe
("half-open") then either restores ``closed`` on success or returns
to ``open`` on failure.

Why every adapter needs this:

* **Failing fast** prevents wasting timeout budget on a downed
  controller — a single bad controller can otherwise queue requests
  until the worker pool is exhausted.
* **Backoff** lets the controller recover instead of being hammered
  during a transient outage.
* **Operational signal** — the breaker exposes its state via the
  ``adapter_circuit_state`` Prometheus gauge, so dashboards can
  graph which controllers are unhealthy.

The breaker is intentionally simple: monotonic timestamps, no async
locks (calls are short and ordering doesn't matter for the counter).
Each adapter instance owns its own breaker; do NOT share across
controllers.

Usage::

    breaker = CircuitBreaker(
        name="omada",
        host=base_url,
        failure_threshold=5,
        cooldown_seconds=30,
    )

    breaker.before_call()        # raises CircuitOpenError if open
    try:
        result = await call_vendor()
        breaker.on_success()
    except Exception:
        breaker.on_failure()
        raise
"""

from __future__ import annotations

import time
from enum import Enum

from app.core.metrics import adapter_circuit_state


class CircuitState(Enum):
    CLOSED = 0  # normal — requests pass through
    OPEN = 1  # tripped — requests rejected fast
    HALF_OPEN = 2  # probing — one request allowed


class CircuitOpenError(Exception):
    """Raised by ``before_call`` when the circuit is open.

    Adapters should translate this to their own connection-style
    exception so callers see a consistent error class.
    """

    def __init__(self, name: str, retry_after_s: float) -> None:
        super().__init__(f"circuit breaker for {name!r} is open; retry after ~{retry_after_s:.1f}s")
        self.name = name
        self.retry_after_s = retry_after_s


class CircuitBreaker:
    """Three-state breaker. One instance per (adapter, host)."""

    def __init__(
        self,
        *,
        name: str,
        host: str,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self.name = name
        self.host = host
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = max(1.0, cooldown_seconds)
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float = 0.0
        self._sync_metric()

    # ── State queries ────────────────────────────────────────────

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def is_open(self) -> bool:
        return self._state is CircuitState.OPEN

    # ── Lifecycle ────────────────────────────────────────────────

    def before_call(self) -> None:
        """Check if a call is allowed.

        Transitions OPEN → HALF_OPEN once the cooldown elapses, so
        the next call probes the upstream. Raises
        :class:`CircuitOpenError` while still in OPEN.
        """
        if self._state is CircuitState.OPEN:
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self.cooldown_seconds:
                self._transition(CircuitState.HALF_OPEN)
            else:
                raise CircuitOpenError(self.name, self.cooldown_seconds - elapsed)

    def on_success(self) -> None:
        """Record a successful call.

        From HALF_OPEN → CLOSED restores normal operation.
        From CLOSED resets the consecutive-failure counter.
        """
        if self._state is CircuitState.HALF_OPEN:
            self._transition(CircuitState.CLOSED)
        self._consecutive_failures = 0

    def on_failure(self) -> None:
        """Record a failed call.

        Trips to OPEN once the consecutive-failure threshold is hit
        (or immediately if a HALF_OPEN probe fails).
        """
        if self._state is CircuitState.HALF_OPEN:
            self._transition(CircuitState.OPEN)
            return
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.failure_threshold:
            self._transition(CircuitState.OPEN)

    # ── Internal ─────────────────────────────────────────────────

    def _transition(self, new_state: CircuitState) -> None:
        self._state = new_state
        if new_state is CircuitState.OPEN:
            self._opened_at = time.monotonic()
        if new_state is CircuitState.CLOSED:
            self._consecutive_failures = 0
        self._sync_metric()

    def _sync_metric(self) -> None:
        try:
            adapter_circuit_state.labels(adapter=self.name, host=self.host).set(self._state.value)
        except Exception:
            # Never fail the call path because of a metric write.
            pass
