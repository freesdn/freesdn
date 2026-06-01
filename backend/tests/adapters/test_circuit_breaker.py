# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the vendor-agnostic CircuitBreaker.

The breaker sits between the adapter and a vendor controller. If
the vendor is down, the breaker fails-fast for a cooldown so the
caller doesn't burn the timeout budget on every queued request.
"""

from __future__ import annotations

import pytest

from app.adapters.circuit_breaker import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
)


def _breaker(threshold: int = 3, cooldown: float = 0.05) -> CircuitBreaker:
    return CircuitBreaker(
        name="test",
        host="https://10.0.0.1",
        failure_threshold=threshold,
        cooldown_seconds=cooldown,
    )


class TestCircuitBreaker:
    def test_starts_closed(self) -> None:
        b = _breaker()
        assert b.state is CircuitState.CLOSED
        b.before_call()  # does not raise

    def test_failures_below_threshold_keep_closed(self) -> None:
        b = _breaker(threshold=3)
        b.on_failure()
        b.on_failure()
        assert b.state is CircuitState.CLOSED

    def test_threshold_failures_open_breaker(self) -> None:
        b = _breaker(threshold=3)
        for _ in range(3):
            b.on_failure()
        assert b.state is CircuitState.OPEN

    def test_open_breaker_rejects_calls(self) -> None:
        b = _breaker(threshold=2)
        b.on_failure()
        b.on_failure()
        assert b.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            b.before_call()

    def test_success_resets_failure_count(self) -> None:
        """A success in CLOSED state resets the consecutive-failure
        counter so transient blips don't accumulate forever."""
        b = _breaker(threshold=3)
        b.on_failure()
        b.on_failure()
        b.on_success()
        # We've cleared. Now N-1 more failures should NOT open the
        # breaker (would have if the counter had stayed at 2).
        b.on_failure()
        b.on_failure()
        assert b.state is CircuitState.CLOSED

    def test_cooldown_transitions_to_half_open(self, monkeypatch) -> None:
        # The breaker clamps cooldown to a 1.0-second minimum for
        # production safety, so we monkey-patch the monotonic clock
        # rather than actually sleep — keeps tests fast and
        # deterministic.
        from app.adapters import circuit_breaker as cb

        clock = [1000.0]
        monkeypatch.setattr(cb.time, "monotonic", lambda: clock[0])

        b = _breaker(threshold=1, cooldown=1.0)
        b.on_failure()
        assert b.state is CircuitState.OPEN
        # Right after tripping, before_call should still raise.
        with pytest.raises(CircuitOpenError):
            b.before_call()
        # Advance the clock past the cooldown.
        clock[0] += 2.0
        b.before_call()
        assert b.state is CircuitState.HALF_OPEN

    def test_half_open_success_closes_breaker(self, monkeypatch) -> None:
        from app.adapters import circuit_breaker as cb

        clock = [1000.0]
        monkeypatch.setattr(cb.time, "monotonic", lambda: clock[0])

        b = _breaker(threshold=1, cooldown=1.0)
        b.on_failure()
        clock[0] += 2.0
        b.before_call()  # → HALF_OPEN
        b.on_success()
        assert b.state is CircuitState.CLOSED

    def test_half_open_failure_reopens_breaker(self, monkeypatch) -> None:
        from app.adapters import circuit_breaker as cb

        clock = [1000.0]
        monkeypatch.setattr(cb.time, "monotonic", lambda: clock[0])

        b = _breaker(threshold=1, cooldown=1.0)
        b.on_failure()
        clock[0] += 2.0
        b.before_call()  # → HALF_OPEN
        b.on_failure()
        assert b.state is CircuitState.OPEN

    def test_threshold_clamped_to_minimum_1(self) -> None:
        """A misconfigured threshold of 0 must not disable the breaker."""
        b = CircuitBreaker(
            name="test",
            host="x",
            failure_threshold=0,
            cooldown_seconds=0.01,
        )
        b.on_failure()
        assert b.state is CircuitState.OPEN

    def test_cooldown_clamped_to_minimum(self) -> None:
        """A 0-second cooldown would defeat the breaker."""
        b = CircuitBreaker(
            name="test",
            host="x",
            failure_threshold=1,
            cooldown_seconds=0.0,
        )
        # Construction succeeded; cooldown is bumped to 1.0s minimum
        # internally.
        assert b.cooldown_seconds >= 1.0

    def test_circuit_open_error_carries_retry_after(self) -> None:
        b = _breaker(threshold=1, cooldown=0.5)
        b.on_failure()
        with pytest.raises(CircuitOpenError) as exc:
            b.before_call()
        assert exc.value.retry_after_s > 0
        assert exc.value.name == "test"
