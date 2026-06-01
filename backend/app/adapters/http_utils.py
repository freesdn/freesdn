# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Shared HTTP Adapter Utilities
==========================================

Reusable infrastructure for all vendor adapter HTTP clients:
  - CircuitBreaker  — Three-state (CLOSED/OPEN/HALF_OPEN) fault isolator.
  - AdapterRateLimiter — Async token-bucket + concurrency semaphore.
  - request_with_retry  — Exponential-backoff retry helper.

These are extracted from the OPNsense client so every adapter
(pfSense, MikroTik, OpenWRT) can reuse the same resilience patterns
without duplication.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from app.adapters.exceptions import AdapterRateLimitError

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Circuit Breaker
# ═══════════════════════════════════════════════════════════════════════════════


class CircuitBreaker:
    """
    Lightweight async circuit breaker.

    States:
      CLOSED  — requests flow normally.
      OPEN    — immediately fail for ``reset_timeout`` seconds.
      HALF    — allow a single probe; success closes, failure re-opens.

    Each instance can be tagged with ``name`` (adapter id, e.g.
    ``"opnsense"``) and ``host`` (the controller URL). When set, the
    breaker emits state transitions to the
    ``freesdn_adapter_circuit_state{adapter,host}`` Prometheus gauge —
    same metric the Omada-side breaker uses, so dashboards work
    uniformly across adapters.
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    # Numeric values mirror app.adapters.circuit_breaker.CircuitState:
    # 0=closed, 1=open, 2=half-open. Keeping them aligned means a
    # single Grafana panel covers both implementations.
    _STATE_VALUES = {CLOSED: 0, OPEN: 1, HALF_OPEN: 2}

    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        *,
        name: str | None = None,
        host: str | None = None,
    ):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.name = name
        self.host = host
        self._state = self.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._sync_metric()

    @property
    def state(self) -> str:
        if self._state == self.OPEN:
            if time.monotonic() - self._last_failure_time >= self.reset_timeout:
                self._state = self.HALF_OPEN
                self._sync_metric()
        return self._state

    def record_success(self) -> None:
        self._failure_count = 0
        if self._state != self.CLOSED:
            self._state = self.CLOSED
            self._sync_metric()
        else:
            self._state = self.CLOSED

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._failure_count >= self.failure_threshold:
            if self._state != self.OPEN:
                self._state = self.OPEN
                self._sync_metric()

    def allow_request(self) -> bool:
        s = self.state
        if s == self.CLOSED:
            return True
        if s == self.HALF_OPEN:
            return True  # allow probe
        return False  # OPEN

    def reset(self) -> None:
        """Force-reset to CLOSED state."""
        self._state = self.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._sync_metric()

    def _sync_metric(self) -> None:
        """Emit the current state to the shared Prometheus gauge.

        Best-effort — never raises into the caller. Skips when the
        breaker is unlabeled (legacy callers that don't pass
        ``name``/``host``) so we don't pollute the metric with
        anonymous series.
        """
        if not self.name or not self.host:
            return
        try:
            from app.core.metrics import adapter_circuit_state

            adapter_circuit_state.labels(adapter=self.name, host=self.host).set(
                self._STATE_VALUES.get(self._state, 0)
            )
        except Exception:
            # Never let a metric write block the call path.
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# Rate Limiter
# ═══════════════════════════════════════════════════════════════════════════════


class AdapterRateLimiter:
    """
    Per-adapter async rate limiter using token bucket + concurrency semaphore.

    Parameters come from the adapter manifest:
      - ``calls_per_minute`` maps to ``rate_limit_calls_per_minute``
      - ``max_concurrent`` maps to ``rate_limit_concurrent``
    """

    def __init__(
        self,
        calls_per_minute: int = 60,
        max_concurrent: int = 5,
    ):
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._max_tokens = float(calls_per_minute)
        self._tokens = float(calls_per_minute)
        self._refill_rate = calls_per_minute / 60.0  # tokens per second
        self._last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._max_tokens, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now

    async def acquire(self) -> None:
        """
        Wait until both a concurrency slot and a rate-limit token are available.

        Raises ``AdapterRateLimitError`` if the wait exceeds 30 seconds.
        """
        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=30.0)
        except TimeoutError:
            raise AdapterRateLimitError("Concurrency limit exceeded — all slots busy for 30s")
        try:
            deadline = time.monotonic() + 30.0
            while True:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Wait for roughly one token to refill
                wait = 1.0 / self._refill_rate if self._refill_rate > 0 else 1.0
                if time.monotonic() + wait > deadline:
                    self._semaphore.release()
                    raise AdapterRateLimitError(
                        "Rate limit exceeded — could not acquire token within 30s"
                    )
                await asyncio.sleep(min(wait, 1.0))
        except AdapterRateLimitError:
            raise
        except Exception:
            self._semaphore.release()
            raise

    def release(self) -> None:
        """Release the concurrency slot (call after request completes)."""
        self._semaphore.release()


# ═══════════════════════════════════════════════════════════════════════════════
# Retry Helper
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class RetryConfig:
    """Configuration for exponential-backoff retries."""

    max_retries: int = 3
    backoff_base: float = 1.0
    backoff_cap: float = 30.0
    retryable_status_codes: set[int] = field(default_factory=lambda: {502, 503, 504, 429})

    def delay_for_attempt(self, attempt: int) -> float:
        """Return the sleep duration (seconds) for a given attempt (0-based)."""
        delay = self.backoff_base * (2**attempt)
        return float(min(delay, self.backoff_cap))


def is_retryable_status(status_code: int, config: RetryConfig | None = None) -> bool:
    """Return True if the HTTP status code warrants a retry."""
    if config is None:
        return status_code in {502, 503, 504, 429}
    return status_code in config.retryable_status_codes


def is_auth_error(status_code: int) -> bool:
    """Return True if the status code indicates an authentication failure."""
    return status_code in {401, 403}
