# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""One in-flight request group per device, across processes, on real Valkey.

Two ``DeviceSlots`` instances over one Valkey stand in for two worker
processes. Nothing here is mocked except the clock-free waits: the leases, the
compare-and-delete release, the TTL and the shared/exclusive rules all run in
the server's Lua.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from app.core import device_slot
from app.core.device_slot import (
    EXCLUSIVE,
    SHARED,
    DeviceSlots,
    controller_slot_key,
    gateway_slot_key,
    normalize_host,
)

_SCRATCH_DB = 11


@pytest.fixture
def valkey():
    from app.core.redis_client import get_sync_redis

    client = get_sync_redis(db=_SCRATCH_DB, decode_responses=True)
    try:
        yield client
    finally:
        for key in client.scan_iter(match=f"{device_slot._PREFIX}*"):
            client.delete(key)
        client.close()


@pytest.fixture
def two_processes(valkey):
    """Two independent slot clients sharing one Valkey, like two workers."""

    def make(cap: int = 2) -> DeviceSlots:
        return DeviceSlots(redis_factory=lambda: valkey, shared_cap=lambda: cap)

    return make(), make()


def test_a_device_held_by_one_poller_is_refused_to_another(two_processes) -> None:
    a, b = two_processes
    held = a.try_acquire("host:192.0.2.1", "gateway sync", ttl=30)
    assert held is not None and held.guarded
    assert b.try_acquire("host:192.0.2.1", "firewall health", ttl=30) is None
    # A different device is unaffected.
    assert b.try_acquire("host:192.0.2.2", "firewall health", ttl=30) is not None
    a.release(held)
    assert b.try_acquire("host:192.0.2.1", "firewall health", ttl=30) is not None


def test_the_skip_reason_names_the_holder(two_processes) -> None:
    a, b = two_processes
    a.try_acquire("host:192.0.2.1", "gateway sync", ttl=30)
    reason = b.busy_reason("host:192.0.2.1")
    assert reason.startswith("Device busy: gateway sync since ") and "UTC" in reason


def test_a_crashed_holder_frees_the_device_when_its_lease_expires(two_processes) -> None:
    a, b = two_processes
    assert a.try_acquire("host:192.0.2.1", "dies without releasing", ttl=1) is not None
    assert b.try_acquire("host:192.0.2.1", "next poll", ttl=30) is None
    time.sleep(1.3)
    assert b.try_acquire("host:192.0.2.1", "next poll", ttl=30) is not None


def test_a_late_release_never_frees_the_next_holder(two_processes) -> None:
    """Compare-and-delete: an expired lease's release is a no-op."""
    a, b = two_processes
    stale = a.try_acquire("host:192.0.2.1", "slow poll", ttl=1)
    time.sleep(1.3)
    current = b.try_acquire("host:192.0.2.1", "next poll", ttl=30)
    assert current is not None
    a.release(stale)  # the slow poll finally finishes
    assert a.try_acquire("host:192.0.2.1", "third", ttl=30) is None
    assert b.holders("host:192.0.2.1")[0]["holder"] == "next poll"


def test_ui_reads_share_up_to_the_cap_and_never_alongside_a_poller(two_processes) -> None:
    a, b = two_processes  # cap 2
    r1 = a.try_acquire("host:192.0.2.1", "ui", ttl=30, mode=SHARED)
    r2 = b.try_acquire("host:192.0.2.1", "ui", ttl=30, mode=SHARED)
    assert r1 is not None and r2 is not None
    assert a.try_acquire("host:192.0.2.1", "ui", ttl=30, mode=SHARED) is None  # cap reached
    assert a.try_acquire("host:192.0.2.1", "gateway sync", ttl=30, mode=EXCLUSIVE) is None
    a.release(r1)
    b.release(r2)
    poll = a.try_acquire("host:192.0.2.1", "gateway sync", ttl=30, mode=EXCLUSIVE)
    assert poll is not None
    assert b.try_acquire("host:192.0.2.1", "ui", ttl=30, mode=SHARED) is None


def test_an_expired_shared_reader_does_not_block_the_device(two_processes) -> None:
    a, b = two_processes
    assert a.try_acquire("host:192.0.2.1", "ui", ttl=1, mode=SHARED) is not None
    assert b.try_acquire("host:192.0.2.1", "poll", ttl=30) is None
    time.sleep(1.3)
    assert b.try_acquire("host:192.0.2.1", "poll", ttl=30) is not None


def test_a_waiting_reader_gets_the_slot_as_soon_as_it_frees(two_processes) -> None:
    a, b = two_processes

    async def scenario():
        poll = await a.acquire("host:192.0.2.1", "gateway sync", ttl=30)

        async def finish_poll():
            await asyncio.sleep(0.4)
            await a.arelease(poll)

        releaser = asyncio.create_task(finish_poll())
        started = time.monotonic()
        lease = await b.acquire("host:192.0.2.1", "ui", ttl=30, mode=SHARED, wait=3.0)
        waited = time.monotonic() - started
        await releaser
        return lease, waited

    lease, waited = asyncio.run(scenario())
    assert lease is not None
    assert 0.3 <= waited < 2.0


def test_a_background_poller_does_not_wait(two_processes) -> None:
    a, b = two_processes
    a.try_acquire("host:192.0.2.1", "gateway sync", ttl=30)

    async def scenario():
        started = time.monotonic()
        lease = await b.acquire("host:192.0.2.1", "firewall health", ttl=30)
        return lease, time.monotonic() - started

    lease, took = asyncio.run(scenario())
    assert lease is None and took < 0.5


def test_hold_releases_on_exception(two_processes) -> None:
    a, b = two_processes

    async def scenario():
        with pytest.raises(RuntimeError):
            async with a.hold("host:192.0.2.1", "poll", ttl=30) as lease:
                assert lease is not None
                raise RuntimeError("device answered garbage")
        return b.try_acquire("host:192.0.2.1", "next", ttl=30)

    assert asyncio.run(scenario()) is not None


def test_a_lease_left_by_a_finished_task_is_released_at_task_postrun(two_processes) -> None:
    """The safety net when a poller's own finally never ran."""
    a, b = two_processes
    original = device_slot.device_slots
    device_slot.device_slots = a
    try:
        leaked = a.try_acquire("host:192.0.2.1", "poll", ttl=30, task_id="task-123")
        assert leaked is not None
        assert b.try_acquire("host:192.0.2.1", "next", ttl=30) is None
        from celery.signals import task_postrun

        import app.core.celery_app  # noqa: F401  (connects the postrun handler)

        task_postrun.send(sender=None, task_id="task-123", task=None, args=(), kwargs={})
        assert b.try_acquire("host:192.0.2.1", "next", ttl=30) is not None
    finally:
        device_slot.device_slots = original


def test_an_unavailable_store_lets_the_poll_through_unguarded() -> None:
    def broken():
        raise ConnectionError("valkey down")

    slots = DeviceSlots(redis_factory=broken)
    lease = slots.try_acquire("host:192.0.2.1", "poll", ttl=30)
    assert lease is not None and lease.guarded is False
    slots.release(lease)  # no error


def test_default_ttl_outlives_the_running_tasks_hard_limit(monkeypatch) -> None:
    from types import SimpleNamespace

    task = SimpleNamespace(request=SimpleNamespace(id="t1", timelimit=(None, None)), time_limit=660)
    monkeypatch.setattr(device_slot, "_current_task", lambda: task)
    assert device_slot.default_ttl() > 660
    task.request.timelimit = (900, 840)  # a per-message override wins
    assert device_slot.default_ttl() > 900
    monkeypatch.setattr(device_slot, "_current_task", lambda: None)
    assert device_slot.default_ttl() == device_slot.API_TTL_SECONDS


def test_the_lease_lasts_what_was_asked_and_valkey_keeps_it_one_heartbeat_ahead(
    two_processes, valkey
) -> None:
    """Changed with the heartbeat: what was asked is the lease's
    deadline; Valkey holds it LEASE_HEARTBEAT_SECONDS ahead and the holder's
    process renews it, so a killed holder frees the device within a heartbeat
    (tests/core/test_device_slot_heartbeat.py)."""
    a, _ = two_processes
    lease = a.try_acquire("host:192.0.2.1", "poll", ttl=720)
    assert lease is not None
    assert 715 < lease.deadline - time.time() <= 720
    pttl = valkey.pttl(f"{device_slot._PREFIX}host:192.0.2.1")
    beat = device_slot.LEASE_HEARTBEAT_SECONDS * 1000
    assert beat - 5_000 < pttl <= beat
    a.release(lease)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.168.1.1", "192.168.1.1"),
        ("https://192.168.1.1:770/api", "192.168.1.1"),
        ("192.168.1.1:443", "192.168.1.1"),
        ("OPNsense.LAN.", "opnsense.lan"),
        ("[fe80::1]:443", "fe80::1"),
        ("fe80::1", "fe80::1"),
        ("admin@10.0.0.5", "10.0.0.5"),
        ("", None),
        (None, None),
    ],
)
def test_one_box_is_one_key_however_its_address_was_typed(raw, expected) -> None:
    assert normalize_host(raw) == expected


def test_a_gateway_and_a_controller_row_for_one_box_share_its_slot() -> None:
    from types import SimpleNamespace

    gw = SimpleNamespace(id="g1", host="192.168.1.1")
    ctrl = SimpleNamespace(id="c1", host="https://192.168.1.1:770", connection_mode="local")
    assert gateway_slot_key(gw) == controller_slot_key(ctrl) == "host:192.168.1.1"
    cloud = SimpleNamespace(id="c2", host="aps1-omada.example.com", connection_mode="cloud")
    assert controller_slot_key(cloud) == "controller:c2"
