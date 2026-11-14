# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A killed slot holder frees its device within one heartbeat, not its TTL.

Evidence: a lease lived as long as its holder's Celery hard time limit plus a
minute, so a discovery worker killed by the OOM killer or a container restart
kept its controller "busy" for up to about 16 minutes: every poller and page
read skipped or waited on a device nobody was talking to.

Now Valkey keeps a lease only one heartbeat ahead and a thread in the holder's
process renews it until the lease's deadline. These run against real Valkey;
the killed holder is a real process that receives SIGKILL.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest

from app.core import device_slot
from app.core.device_slot import SHARED, DeviceSlots

KEY = "host:192.0.2.120"


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def _taken(slots: DeviceSlots, holder: str) -> bool:
    """Whether ``slots`` can take KEY now (and give it straight back)."""
    lease = slots.try_acquire(KEY, holder, ttl=30)
    if lease is None:
        return False
    slots.release(lease)
    return True


def test_a_sigkilled_holder_frees_the_device_within_a_heartbeat():
    """Fails on the old lease: it outlived the kill by the whole TTL (600 s here)."""
    child = textwrap.dedent(
        """
        import sys, time
        from app.core import device_slot
        device_slot._PREFIX = sys.argv[1]
        slots = device_slot.DeviceSlots(heartbeat=2.0)
        lease = slots.try_acquire(sys.argv[2], "controller discovery", ttl=600)
        print("held" if lease is not None and lease.guarded else "not held", flush=True)
        time.sleep(600)
        """
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", child, device_slot._PREFIX, KEY],
        stdout=subprocess.PIPE,
        text=True,
        cwd=os.getcwd(),
    )
    slots = DeviceSlots(heartbeat=2.0)
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "held", "the holder needs real Valkey"
        # Alive, it keeps the device past more than two heartbeats.
        time.sleep(5.0)
        assert not _taken(slots, "health check")
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)
        started = time.monotonic()
        assert _wait_for(lambda: _taken(slots, "health check"), 10.0)
        # About one heartbeat (2 s here, 90 s in production), with room for a
        # loaded runner; the old lease stayed for its whole 600 s.
        assert time.monotonic() - started < 6.0, "freed within about one heartbeat"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        if proc.stdout is not None:
            proc.stdout.close()


def test_a_live_holder_keeps_its_lease_across_many_heartbeats():
    holder, other = DeviceSlots(heartbeat=2.0), DeviceSlots(heartbeat=2.0)
    lease = holder.try_acquire(KEY, "gateway full sync", ttl=60)
    assert lease is not None and lease.guarded
    try:
        time.sleep(5.0)  # two and a half heartbeats
        assert not _taken(other, "health poll")
    finally:
        holder.release(lease)
    assert _taken(other, "health poll")


def test_a_shared_reader_is_renewed_the_same_way():
    reader, poller = DeviceSlots(heartbeat=2.0), DeviceSlots(heartbeat=2.0)
    lease = reader.try_acquire(KEY, "UI read", ttl=60, mode=SHARED)
    assert lease is not None
    try:
        time.sleep(5.0)
        assert not _taken(poller, "health poll")
    finally:
        reader.release(lease)


def test_a_lease_that_is_never_released_still_ends_at_its_deadline():
    """A leak in a live process must not hold a device forever: renewals stop
    at the deadline the lease was taken with."""
    leaky, other = DeviceSlots(heartbeat=0.4), DeviceSlots(heartbeat=0.4)
    lease = leaky.try_acquire(KEY, "leaked", ttl=1.2)
    assert lease is not None
    assert not _taken(other, "poll")
    assert _wait_for(lambda: _taken(other, "poll"), 3.0)


def test_a_renewal_never_extends_somebody_elses_lease(monkeypatch):
    """Compare-and-renew: after an expiry and a new holder, a late beat of the
    old holder is refused."""
    old, new = DeviceSlots(heartbeat=0.3), DeviceSlots(heartbeat=30)
    stale = old.try_acquire(KEY, "old holder", ttl=0.3)
    assert stale is not None
    time.sleep(0.5)
    fresh = new.try_acquire(KEY, "new holder", ttl=30)
    assert fresh is not None
    try:
        assert old._renew(stale, 30) is False
        assert not _taken(old, "old holder again")
    finally:
        new.release(fresh)
        old.release(stale)


def test_a_lost_lease_is_given_up_after_one_refused_renewal():
    slots = DeviceSlots(heartbeat=30)
    lease = slots.try_acquire(KEY, "holder", ttl=60)
    assert lease is not None and lease in device_slot.held_leases()
    slots._redis_factory().delete(*lease.redis_keys)  # expired under it
    lease.renewed_at = 0.0  # due now
    device_slot._heartbeat.renew_once()
    assert lease not in device_slot.held_leases()
    slots.release(lease)  # still harmless


def test_a_forked_child_holds_none_of_its_parents_leases():
    if not hasattr(os, "fork"):
        pytest.skip("needs fork")
    slots = DeviceSlots(heartbeat=30)
    lease = slots.try_acquire(KEY, "parent", ttl=60)
    assert lease is not None
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the child
        os.close(read)
        os.write(write, str(len(device_slot.held_leases())).encode())
        os._exit(0)
    os.close(write)
    try:
        assert os.read(read, 16) == b"0"
    finally:
        os.close(read)
        os.waitpid(pid, 0)
        slots.release(lease)
