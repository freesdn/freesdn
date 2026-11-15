# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - device I/O retry policy
=================================

One answer, for every adapter transport, to "may this failed request be sent
again?".

1. **A timeout is never retried.** A device that did not answer within the read
   timeout is slow or wedged. Asking again adds load at exactly the moment it can
   least absorb it, and multiplies the caller's wait. Observed on the 2026-11 soak
   against a struggling OPNsense: every 60 s ``ReadTimeout`` was retried three
   times, so one read held the poll for over three minutes while each retry woke
   another PHP worker on the firewall.
2. **A connect failure is not retried.** Refused, unreachable or a connect
   timeout will not recover in the seconds a retry waits; the next poll is the
   retry.
3. **Only a reset or a gateway-class 5xx is retried, and only for an idempotent
   read.** A connection the peer dropped mid-request (keep-alive race, proxy
   restart) and 502/503/504 (a reverse proxy in front of a restarting service)
   are the transient cases a quick second attempt fixes. 500/501 mean the API
   itself failed and will fail the same way again.
4. **A write is transmitted once.** Its failure is surfaced, never replayed: the
   device may already have applied it (see
   ``tests/adapters/test_retry_idempotency_ratchet.py``).
5. **Retries back off with full jitter and never outlive the request deadline.**

Adapters keep their own loop bounds (the ratchet pins them) and their own
vendor-specific delays; they ask this module *whether* to go round again.
"""

from __future__ import annotations

import random
import time
from enum import StrEnum

import httpx

try:  # aiohttp is a hard dependency today; stay importable without it.
    import aiohttp as _aiohttp
except ImportError:  # pragma: no cover
    _aiohttp = None  # type: ignore[assignment]


class Failure(StrEnum):
    """Why a request to a device failed, as far as retrying is concerned."""

    TIMEOUT = "timeout"
    CONNECT = "connect"
    RESET = "reset"
    SERVER_ERROR = "server_error"
    OTHER = "other"


#: Gateway-class statuses: an intermediary in front of a restarting service.
RETRYABLE_STATUSES: frozenset[int] = frozenset({502, 503, 504})

#: Failure kinds a second attempt can plausibly fix.
_RETRYABLE: frozenset[Failure] = frozenset({Failure.RESET, Failure.SERVER_ERROR})


def classify(exc: BaseException) -> Failure:
    """Classify a transport exception from httpx, aiohttp or the socket layer."""
    # Timeouts first: aiohttp.ServerTimeoutError is ALSO a ServerConnectionError,
    # and httpx.ConnectTimeout is a TimeoutException, not a ConnectError.
    if isinstance(exc, httpx.TimeoutException | TimeoutError):
        return Failure.TIMEOUT
    if isinstance(exc, httpx.ConnectError):
        return Failure.CONNECT
    if isinstance(exc, httpx.RemoteProtocolError | httpx.ReadError | httpx.WriteError):
        return Failure.RESET
    if _aiohttp is not None:
        if isinstance(exc, _aiohttp.ClientConnectorError):
            return Failure.CONNECT
        if isinstance(
            exc,
            _aiohttp.ServerDisconnectedError | _aiohttp.ClientPayloadError | _aiohttp.ClientOSError,
        ):
            return Failure.RESET
    if isinstance(exc, ConnectionRefusedError):
        return Failure.CONNECT
    if isinstance(exc, ConnectionError):  # reset, aborted, broken pipe
        return Failure.RESET
    return Failure.OTHER


def may_retry(failure: Failure, *, idempotent: bool) -> bool:
    """True when a request that failed this way may be sent once more."""
    return idempotent and failure in _RETRYABLE


def may_retry_exception(exc: BaseException, *, idempotent: bool) -> bool:
    return may_retry(classify(exc), idempotent=idempotent)


def may_retry_status(status_code: int, *, idempotent: bool) -> bool:
    """True when an HTTP status is worth one more attempt of an idempotent read."""
    return idempotent and status_code in RETRYABLE_STATUSES


def backoff_delay(attempt: int, *, base: float = 0.5, cap: float = 8.0) -> float:
    """Full-jitter exponential backoff for retry number ``attempt`` (1-based).

    ``uniform(0, min(cap, base * 2**(attempt-1)))``: callers that all failed at
    the same instant (every worker polling one recovering controller) spread out
    instead of retrying in lockstep.
    """
    ceiling = min(cap, base * (2 ** max(0, attempt - 1)))
    return random.uniform(0.0, ceiling)


class Deadline:
    """A wall-clock budget for one logical request, retries included."""

    __slots__ = ("_expires",)

    def __init__(self, seconds: float) -> None:
        self._expires = time.monotonic() + max(0.0, float(seconds))

    def remaining(self) -> float:
        return max(0.0, self._expires - time.monotonic())

    def allows(self, delay: float, *, then_needs: float = 1.0) -> bool:
        """Is there room to sleep ``delay`` and still make a meaningful attempt?"""
        return self.remaining() > delay + then_needs


#: Adapters report a failed read as ``AdapterResult.fail(type(exc).__name__)``.
#: These names mean the DEVICE did not answer, not that it refused the request.
_DEVICE_FAILURE_NAMES = (
    "AdapterConnectionError",
    "AdapterTimeoutError",
    "Timeout",
    "ConnectError",
    "RemoteProtocolError",
    "ReadError",
    "CircuitOpenError",
)


def is_device_failure_text(error: str | None) -> bool:
    """Does a failed ``AdapterResult.error`` say the device did not answer?"""
    return bool(error) and any(name in str(error) for name in _DEVICE_FAILURE_NAMES)


def is_device_failure(exc: BaseException) -> bool:
    """Did this exception come from a device that did not answer?

    True for a timeout, a refused or dropped connection, and the adapters' own
    connection/timeout errors (which also wrap an open client-side breaker). A
    4xx, an auth error or a parse error means the device DID answer.
    """
    from app.adapters.exceptions import AdapterConnectionError, AdapterTimeoutError

    if isinstance(exc, AdapterConnectionError | AdapterTimeoutError):
        return True
    return classify(exc) in (Failure.TIMEOUT, Failure.CONNECT, Failure.RESET)
