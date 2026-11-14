# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - per-device circuit breaker shared by every worker process
===================================================================

The adapter breakers (``app/adapters/circuit_breaker.py`` and
``http_utils.CircuitBreaker``) live inside one client instance. Every poll
builds a fresh adapter, usually in a different Celery process, so their failure
count starts at zero each cycle and they never open ACROSS polls. That is how
the 2026-11 soak's struggling OPNsense kept receiving a full gateway sync every
5 minutes and a health poll every 2 minutes while every request timed out:
nothing remembered that the last cycle had failed.

This breaker keeps that memory in Redis, keyed by device, so every worker sees
the same state:

* **closed** -- polls run. Each failed cycle counts; a success resets it.
* **open** -- after ``failure_threshold`` consecutive failed cycles. Polls are
  SKIPPED (callers record a clear "paused" status) until the cooldown ends. The
  cooldown doubles on every consecutive trip, from ``base_cooldown`` to
  ``max_cooldown``, with +/-10 % jitter so many devices do not re-probe in step.
* **half-open** -- once the cooldown ends, exactly ONE caller (a Redis ``SET NX``
  lease) is let through as the probe. Its success closes the breaker; its
  failure re-opens it for the next, longer, cooldown.

Redis trouble never blocks a poll: every operation fails OPEN (allows), because
an unavailable state store is its own incident, not a reason to stop managing
the fleet.

A failure here is a *device* failure -- timeout, refused or reset connection,
5xx, or every read of the cycle failing. A 4xx or an auth error means the
device answered; callers do not count it.
"""

from __future__ import annotations

import json
import logging
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

_PREFIX = "freesdn:devbreaker:"
#: State is transient. A device nobody polls for a day starts clean.
_STATE_TTL = 24 * 3600

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


@dataclass(frozen=True)
class BreakerDecision:
    allowed: bool
    state: str
    #: Seconds until the next probe may run (0 when ``allowed``).
    retry_after: float = 0.0
    #: True when this caller holds the half-open probe lease.
    probe: bool = False
    consecutive_failures: int = 0
    last_error: str | None = None

    def skip_message(self) -> str:
        """Operator-facing reason a poll was skipped."""
        when = f"next probe in ~{int(self.retry_after)}s" if self.retry_after else "probe in flight"
        cause = f" (last error: {self.last_error})" if self.last_error else ""
        return (
            f"Polling paused after {self.consecutive_failures} consecutive failed "
            f"cycle(s); {when}{cause}"
        )


def _default_redis() -> Any:
    from app.core.celery_app import _get_solo_redis

    return _get_solo_redis()


class DeviceBreaker:
    """A cross-process circuit breaker for one class of device polls."""

    def __init__(
        self,
        *,
        failure_threshold: int = 2,
        base_cooldown: float = 120.0,
        max_cooldown: float = 900.0,
        probe_lease: float = 300.0,
        redis_factory: Callable[[], Any] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.failure_threshold = max(1, int(failure_threshold))
        self.base_cooldown = max(1.0, float(base_cooldown))
        self.max_cooldown = max(self.base_cooldown, float(max_cooldown))
        self.probe_lease = max(1.0, float(probe_lease))
        self._redis_factory = redis_factory or _default_redis
        self._clock = clock

    # ── storage ──────────────────────────────────────────────────────────

    def _redis(self) -> Any:
        return self._redis_factory()

    @staticmethod
    def _key(device: str) -> str:
        return f"{_PREFIX}{device}"

    def _load(self, device: str) -> dict[str, Any]:
        raw = self._redis().get(self._key(device))
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _store(self, device: str, data: dict[str, Any]) -> None:
        self._redis().set(self._key(device), json.dumps(data), ex=_STATE_TTL)

    # ── API ──────────────────────────────────────────────────────────────

    def check(self, device: str) -> BreakerDecision:
        """May a poll of ``device`` run now?"""
        try:
            data = self._load(device)
            failures = int(data.get("failures", 0))
            opened_until = float(data.get("opened_until", 0.0))
            last_error = data.get("last_error")
            if failures < self.failure_threshold or not opened_until:
                return BreakerDecision(True, CLOSED, consecutive_failures=failures)
            now = self._clock()
            if now < opened_until:
                return BreakerDecision(
                    False,
                    OPEN,
                    retry_after=opened_until - now,
                    consecutive_failures=failures,
                    last_error=last_error,
                )
            # Cooldown over: one caller probes, everyone else waits for it.
            got = self._redis().set(
                self._key(device) + ":probe", "1", nx=True, ex=int(self.probe_lease)
            )
            if got:
                return BreakerDecision(True, HALF_OPEN, probe=True, consecutive_failures=failures)
            return BreakerDecision(
                False, HALF_OPEN, consecutive_failures=failures, last_error=last_error
            )
        except Exception:  # noqa: BLE001 - fail open, see module docstring
            logger.warning("device breaker unavailable for %s; allowing the poll", device)
            return BreakerDecision(True, CLOSED)

    def record_success(self, device: str) -> None:
        """The device answered: close the breaker."""
        try:
            r = self._redis()
            r.delete(self._key(device), self._key(device) + ":probe")
        except Exception:  # noqa: BLE001
            logger.warning("device breaker unavailable for %s (success not recorded)", device)

    def record_failure(self, device: str, error: str | None = None) -> BreakerDecision:
        """A poll cycle failed at the device. Returns the state it leaves."""
        try:
            data = self._load(device)
            failures = int(data.get("failures", 0)) + 1
            trips = int(data.get("trips", 0))
            now = self._clock()
            data.update(
                failures=failures,
                last_error=(error or "")[:200] or None,
                last_failure_at=now,
            )
            state = CLOSED
            retry_after = 0.0
            if failures >= self.failure_threshold:
                trips += 1
                cooldown = min(self.max_cooldown, self.base_cooldown * (2 ** (trips - 1)))
                cooldown *= random.uniform(0.9, 1.1)
                data.update(trips=trips, opened_until=now + cooldown)
                state, retry_after = OPEN, cooldown
            self._store(device, data)
            if state == OPEN:
                self._redis().delete(self._key(device) + ":probe")
                logger.warning(
                    "Device %s: %d consecutive failed poll(s), pausing polls for %.0fs (%s)",
                    device,
                    failures,
                    retry_after,
                    data.get("last_error"),
                )
            return BreakerDecision(
                state == CLOSED,
                state,
                retry_after=retry_after,
                consecutive_failures=failures,
                last_error=data.get("last_error"),
            )
        except Exception:  # noqa: BLE001
            logger.warning("device breaker unavailable for %s (failure not recorded)", device)
            return BreakerDecision(True, CLOSED)

    def peek(self, device: str) -> str:
        """The breaker's state WITHOUT taking the half-open probe lease.

        For opportunistic callers (drift checks) that should only contact a
        device whose breaker is plainly closed and leave probing to the poller.
        Fails open (CLOSED) like every other operation.
        """
        try:
            data = self._load(device)
            failures = int(data.get("failures", 0))
            opened_until = float(data.get("opened_until", 0.0))
            if failures < self.failure_threshold or not opened_until:
                return CLOSED
            return OPEN if self._clock() < opened_until else HALF_OPEN
        except Exception:  # noqa: BLE001
            return CLOSED

    def release_probe(self, device: str) -> None:
        """Give back a half-open probe lease this caller will not use."""
        try:
            self._redis().delete(self._key(device) + ":probe")
        except Exception:  # noqa: BLE001
            pass

    def status(self, device: str) -> dict[str, Any]:
        """Raw state for diagnostics (``{}`` when closed and clean)."""
        try:
            return self._load(device)
        except Exception:  # noqa: BLE001
            return {}


#: Gateway REACHABILITY (OPNsense/pfSense/...), fed by the 2-minute health poll
#: and by a full sync that could not connect. Two failed cycles open it; a
#: wedged firewall is then probed at most every ~2, 4, 8, then 15 minutes, by
#: one lightweight request, until it answers again. While it is open NOTHING
#: periodic contacts the box.
gateway_breaker = DeviceBreaker(failure_threshold=2, base_cooldown=120.0, max_cooldown=900.0)

#: The heavy FULL SYNC of one gateway (rules, NAT, VPN, interfaces, leases: a
#: dozen API calls). One failed or partial sync backs it off 15 minutes, then
#: 30, 60, up to 2 hours, even while the light poll still gets answers: a box
#: that answers its status page but times out on rule exports (the 2026-11
#: soak's PHP pool exhaustion) must not get the heavy sync every beat.
gateway_sync_breaker = DeviceBreaker(
    failure_threshold=1, base_cooldown=900.0, max_cooldown=7200.0, probe_lease=900.0
)


#: Controller REACHABILITY (Omada, UniFi, Proxmox, TrueNAS, MikroTik, ...), fed
#: by the controller health check and by the Omada, Proxmox and storage
#: monitors, which all poll the controller row. Two failed cycles open it; the
#: controller is then probed by ONE of them at ~2, 4, 8, then 10 minutes (10,
#: not 15: a recovered controller should read CONNECTED soon after it answers).
#: Discovery and device-status sync peek it and leave an open controller alone.
controller_breaker = DeviceBreaker(failure_threshold=2, base_cooldown=120.0, max_cooldown=600.0)

#: An NVR, fed by the camera health poll and the alert ingest. Three failed
#: cycles, because the alert ingest runs every 30 s and one dropped read is not
#: an outage.
nvr_breaker = DeviceBreaker(failure_threshold=3, base_cooldown=120.0, max_cooldown=900.0)

#: A desk phone, fed by the 5-minute phone health check. A phone that does not
#: answer twice is probed every 10, 20, then 60 minutes, not every cycle.
phone_breaker = DeviceBreaker(
    failure_threshold=2, base_cooldown=600.0, max_cooldown=3600.0, probe_lease=600.0
)


def controller_key(controller_id: Any) -> str:
    return f"controller:{controller_id}"


def nvr_key(nvr_id: Any) -> str:
    return f"nvr:{nvr_id}"


def phone_key(phone_id: Any) -> str:
    return f"phone:{phone_id}"


def gateway_key(gateway_id: Any) -> str:
    return f"gateway:{gateway_id}"


def gateway_sync_key(gateway_id: Any) -> str:
    return f"gateway-sync:{gateway_id}"
