# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - the gate every scheduled device poll goes through
===========================================================

``device_poll`` combines the two cross-process guards a poller needs before it
sends a byte to a device:

1. the device's shared **breaker** (``app/core/device_breaker.py``): a device
   that stopped answering is not contacted until its cooldown ends, and then
   by exactly one prober;
2. the device's **slot** (``app/core/device_slot.py``): one in-flight request
   group per device across every poller and process.

Usage::

    async with device_poll(
        slot_key=controller_slot_key(ctrl),
        breaker=controller_breaker,
        breaker_key=controller_key(ctrl.id),
        holder="Omada monitor",
    ) as turn:
        if turn.skipped:
            ...record turn.reason, move on...
        else:
            try:
                ...talk to the device...
            except Exception as exc:
                turn.failed(exc)

On exit the slot is released and the outcome recorded: a failure that means
the device did not answer (timeout, refused or dropped connection, see
``app/adapters/io_policy.py``) counts against the breaker; anything else (it
answered, perhaps with a 4xx or an auth error) closes it. A skipped turn
records nothing and gives back any half-open probe lease it was handed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from app.core.device_breaker import DeviceBreaker
from app.core.device_slot import SlotLease, device_slots

#: Why a turn was skipped (the slot and breaker reasons differ in wording).
BUSY = "busy"
BREAKER_OPEN = "breaker_open"


@dataclass
class PollTurn:
    """One poller's turn at one device."""

    skipped: bool = False
    #: ``BUSY`` or ``BREAKER_OPEN`` when skipped.
    skip_kind: str | None = None
    #: Operator-facing reason when skipped.
    reason: str | None = None
    #: The breaker's half-open probe: this turn decides whether polling resumes.
    probe: bool = False
    _failure: str | None = None
    _no_verdict: bool = False

    def failed(self, error: BaseException | str) -> None:
        """The poll failed. Counts against the breaker only if the device did
        not answer; a refused or unsupported request is the device answering."""
        from app.adapters import io_policy

        if isinstance(error, BaseException):
            if io_policy.is_device_failure(error):
                self._failure = f"{type(error).__name__}"
        elif io_policy.is_device_failure_text(error) or error.startswith("connect:"):
            self._failure = error[:200]

    def unreachable(self, error: str) -> None:
        """The device did not answer, whatever the error looked like."""
        self._failure = (error or "unreachable")[:200]

    def no_verdict(self) -> None:
        """Nothing was learned about the device (e.g. no credentials to try)."""
        self._no_verdict = True

    @property
    def failure(self) -> str | None:
        return self._failure


@asynccontextmanager
async def device_poll(
    *,
    slot_key: str,
    breaker: DeviceBreaker | None,
    breaker_key: str | None,
    holder: str,
    ttl: float | None = None,
) -> AsyncIterator[PollTurn]:
    """Gate one scheduled poll of one device (see the module docstring)."""
    turn = PollTurn()
    if breaker is not None and breaker_key is not None:
        decision = breaker.check(breaker_key)
        if not decision.allowed:
            turn.skipped, turn.skip_kind, turn.reason = (
                True,
                BREAKER_OPEN,
                decision.skip_message(),
            )
            yield turn
            return
        turn.probe = decision.probe
    lease: SlotLease | None = await device_slots.acquire(slot_key, holder, ttl=ttl)
    if lease is None:
        if turn.probe and breaker is not None and breaker_key is not None:
            breaker.release_probe(breaker_key)
        turn.skipped, turn.skip_kind = True, BUSY
        turn.reason = await device_slots.abusy_reason(slot_key)
        turn.probe = False
        yield turn
        return
    try:
        yield turn
    except Exception as exc:
        if turn.failure is None:
            turn.failed(exc)
        raise
    except BaseException:  # cancelled or interrupted: nothing learned
        turn.no_verdict()
        raise
    finally:
        await device_slots.arelease(lease)
        if breaker is not None and breaker_key is not None:
            if turn.failure is not None:
                breaker.record_failure(breaker_key, turn.failure)
            elif turn._no_verdict:
                if turn.probe:
                    breaker.release_probe(breaker_key)
            else:
                breaker.record_success(breaker_key)


def describe_skip(turn: PollTurn) -> dict[str, Any]:
    """A uniform result entry for a skipped device."""
    return {"skipped": True, "skip_kind": turn.skip_kind, "reason": turn.reason}
