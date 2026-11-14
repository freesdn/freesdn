# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The poll gate (breaker + device slot) on real Valkey.

Both the breaker state and the slot leases live in the same Valkey the workers
use; two clients stand in for two worker processes.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.core import device_slot
from app.core.device_breaker import CLOSED, OPEN, DeviceBreaker
from app.core.device_poll import BREAKER_OPEN, BUSY, device_poll
from app.core.device_slot import DeviceSlots

_SCRATCH_DB = 11


@pytest.fixture
def valkey(monkeypatch):
    from app.core.redis_client import get_sync_redis

    client = get_sync_redis(db=_SCRATCH_DB, decode_responses=True)
    slots = DeviceSlots(redis_factory=lambda: client, shared_cap=lambda: 2)
    monkeypatch.setattr(device_slot, "device_slots", slots)
    import app.core.device_poll as device_poll_module

    monkeypatch.setattr(device_poll_module, "device_slots", slots)
    prefix = device_slot._PREFIX
    try:
        yield client, slots
    finally:
        for key in client.scan_iter(match=f"{prefix}*"):
            client.delete(key)
        for key in client.scan_iter(match="freesdn:devbreaker:test-*"):
            client.delete(key)
        client.close()


def _breaker(client, **kw) -> DeviceBreaker:
    return DeviceBreaker(redis_factory=lambda: client, **kw)


def _key() -> str:
    import uuid

    return f"test-{uuid.uuid4().hex}"


def _run(coro):
    return asyncio.run(coro)


def test_a_device_that_did_not_answer_opens_the_breaker_for_every_process(valkey) -> None:
    client, _ = valkey
    worker_a, worker_b = (
        _breaker(client, failure_threshold=2),
        _breaker(client, failure_threshold=2),
    )
    bkey = _key()

    async def one_poll(breaker):
        async with device_poll(
            slot_key="host:192.0.2.1", breaker=breaker, breaker_key=bkey, holder="poll"
        ) as turn:
            if turn.skipped:
                return turn
            turn.failed(httpx.ConnectTimeout("no answer"))
            return turn

    assert not _run(one_poll(worker_a)).skipped
    assert not _run(one_poll(worker_b)).skipped
    third = _run(one_poll(worker_a))
    assert third.skipped and third.skip_kind == BREAKER_OPEN
    assert "paused" in (third.reason or "")
    assert worker_b.peek(bkey) == OPEN


def test_a_refusal_is_the_device_answering(valkey) -> None:
    client, _ = valkey
    breaker = _breaker(client, failure_threshold=1)
    bkey = _key()

    async def poll():
        async with device_poll(
            slot_key="host:192.0.2.1", breaker=breaker, breaker_key=bkey, holder="poll"
        ) as turn:
            turn.failed(PermissionError("401 Unauthorized"))

    _run(poll())
    assert breaker.peek(bkey) == CLOSED


def test_an_exception_out_of_the_body_still_counts_and_frees_the_slot(valkey) -> None:
    client, slots = valkey
    breaker = _breaker(client, failure_threshold=1)
    bkey = _key()

    async def poll():
        async with device_poll(
            slot_key="host:192.0.2.1", breaker=breaker, breaker_key=bkey, holder="poll"
        ):
            raise httpx.ReadTimeout("stalled")

    with pytest.raises(httpx.ReadTimeout):
        _run(poll())
    assert breaker.peek(bkey) == OPEN
    assert slots.try_acquire("host:192.0.2.1", "next", ttl=30) is not None


def test_a_busy_device_is_skipped_and_the_probe_lease_given_back(valkey) -> None:
    """A half-open probe that finds the device busy must not burn the probe."""
    client, slots = valkey
    breaker = _breaker(client, failure_threshold=1, base_cooldown=1.0)
    bkey = _key()
    breaker.record_failure(bkey, "ConnectTimeout")
    import time

    time.sleep(1.2)  # cooldown over: the next check is the probe
    held = slots.try_acquire("host:192.0.2.1", "gateway full sync", ttl=30)
    assert held is not None

    async def poll():
        async with device_poll(
            slot_key="host:192.0.2.1", breaker=breaker, breaker_key=bkey, holder="health"
        ) as turn:
            return turn

    turn = _run(poll())
    assert turn.skipped and turn.skip_kind == BUSY
    assert turn.reason.startswith("Device busy: gateway full sync")
    slots.release(held)
    # The probe lease was returned, so the next poll can probe straight away.
    assert breaker.check(bkey).probe


def test_a_skipped_turn_records_nothing(valkey) -> None:
    client, slots = valkey
    breaker = _breaker(client, failure_threshold=1)
    bkey = _key()
    held = slots.try_acquire("host:192.0.2.1", "discovery", ttl=30)

    async def poll():
        async with device_poll(
            slot_key="host:192.0.2.1", breaker=breaker, breaker_key=bkey, holder="health"
        ) as turn:
            return turn

    assert _run(poll()).skipped
    assert breaker.status(bkey) == {}
    slots.release(held)
