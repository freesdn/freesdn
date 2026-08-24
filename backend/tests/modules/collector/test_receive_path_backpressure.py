# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A UDP burst turned straight into memory, and unauthorised packets cost the same.

``datagram_received`` is synchronous -- asyncio hands it a packet and expects it
to return immediately -- so both receivers spawned a Task per datagram and moved
on. Nothing bounded that. Measured before the fix: a single 20,000-packet burst
created 20,000 pending Tasks, each holding a coroutine, a parsed record and,
shortly, a database session.

The second half is worse. The allowlist was checked INSIDE the task. UDP source
addresses are trivially spoofable and the port is open to anyone who can route
to it, so the case entirely under an attacker's control -- a flood from an
address that is not permitted -- paid exactly the same price as a legitimate
one. ``_handle`` even carried a note saying the allowlist runs first "so an
unauthorised source never consumes CPU on BER decoding", which was true of the
decoding and not of the Task that wrapped it.

Both checks now run before the task exists:

    authorised 20k burst    20,000 tasks  ->    256 tasks, 19,744 shed
    unauthorised 20k burst  20,000 tasks  ->      0 tasks, 20,000 rejected

Shedding is correct here. Syslog over UDP is lossy by contract and every device
on the network knows it; exhausting the collector's memory is not lossy, it
takes down the fleet's logging. What would not be correct is shedding silently,
because a collector quietly discarding half a fleet's logs looks identical to a
fleet that went quiet -- so the drops are counted and periodically logged.
"""

from __future__ import annotations

import asyncio
import ipaddress

import pytest

from app.modules.collector.services.snmp_trap import SNMPTrapReceiver, _SNMPProtocol
from app.modules.collector.services.syslog import SyslogReceiver, _SyslogProtocol

ALLOWED = [ipaddress.ip_network("192.168.10.0/24")]
GOOD_IP = "192.168.10.1"
BAD_IP = "10.0.0.9"
LINE = b"<27>Oct 11 22:14:15 fw-edge kernel: power supply 2 failed"


def _syslog(**kw):
    receiver = SyslogReceiver(allowlist=ALLOWED, **kw)
    return receiver, _SyslogProtocol(receiver)


def _trap(**kw):
    receiver = SNMPTrapReceiver(allowlist=ALLOWED, **kw)
    return receiver, _SNMPProtocol(receiver)


async def _task_delta(fn) -> int:
    before = len(asyncio.all_tasks())
    fn()
    delta = len(asyncio.all_tasks()) - before
    await asyncio.sleep(0)
    return delta


# ── the unauthorised case, which is the one an attacker controls ──


async def test_an_unauthorised_flood_creates_no_tasks():
    """
    The allowlist is a pure function of the source IP. There is no reason for
    it to cost a Task, and while it did, the cheapest packet to send was the
    one we most wanted to be cheap to refuse.
    """
    receiver, proto = _syslog()

    created = await _task_delta(
        lambda: [proto.datagram_received(LINE, (BAD_IP, 514)) for _ in range(5000)]
    )

    assert created == 0, f"{created} tasks spawned for packets we refuse anyway"
    assert receiver._rejected_packets == 5000


async def test_an_unauthorised_trap_flood_creates_no_tasks():
    """
    More acute for traps: BER decoding an unauthorised packet is strictly more
    expensive than discarding it.
    """
    receiver, proto = _trap()

    created = await _task_delta(
        lambda: [proto.datagram_received(b"\x30\x00", (BAD_IP, 162)) for _ in range(5000)]
    )

    assert created == 0
    assert receiver._rejected_packets == 5000


# ── the authorised case, which still has to be bounded ──


async def test_an_authorised_flood_is_capped():
    receiver, proto = _syslog(max_inflight=64)

    created = await _task_delta(
        lambda: [proto.datagram_received(LINE, (GOOD_IP, 514)) for _ in range(5000)]
    )

    assert created <= 64, f"in-flight work reached {created}; the ceiling is 64"
    assert receiver._dropped_overload == 5000 - created


async def test_shedding_is_counted_not_silent():
    """
    A collector discarding a fleet's logs looks exactly like a fleet that went
    quiet. The counter is the only thing that tells those apart.
    """
    receiver, proto = _syslog(max_inflight=8)

    for _ in range(100):
        proto.datagram_received(LINE, (GOOD_IP, 514))

    assert receiver._dropped_overload > 0
    assert receiver._rejected_packets == 0, "these were authorised; they were shed, not refused"


async def test_capacity_is_returned_when_work_finishes():
    """
    ``release`` is wired as a done-callback. Without it the counter only ever
    rises, and the receiver stops accepting anything the moment it has seen
    ``max_inflight`` packets in total -- a collector that works for a minute
    and then goes deaf for ever.
    """
    receiver, proto = _syslog(max_inflight=4)

    for _ in range(4):
        proto.datagram_received(LINE, (GOOD_IP, 514))
    assert receiver._inflight == 4

    proto.datagram_received(LINE, (GOOD_IP, 514))
    assert receiver._dropped_overload == 1

    await asyncio.sleep(0.05)  # let the tasks run and their callbacks fire

    assert receiver._inflight == 0, "capacity was never returned"

    proto.datagram_received(LINE, (GOOD_IP, 514))
    assert receiver._dropped_overload == 1, "still refusing after the queue drained"


async def test_a_burst_within_the_ceiling_is_not_shed():
    """Guards the cap from being so eager that normal traffic is dropped."""
    receiver, proto = _syslog(max_inflight=256)

    for _ in range(200):
        proto.datagram_received(LINE, (GOOD_IP, 514))

    assert receiver._dropped_overload == 0
    await asyncio.sleep(0.05)


# ── the guard itself ──


@pytest.mark.parametrize("factory", [_syslog, _trap])
async def test_admission_refuses_before_it_reserves(factory):
    """
    Order matters: reserving capacity and then refusing on the allowlist would
    leak a slot per unauthorised packet, and the receiver would throttle itself
    into silence under exactly the flood the allowlist exists to ignore.
    """
    receiver, _ = factory(max_inflight=4)

    for _ in range(50):
        receiver.admit(BAD_IP)

    assert receiver._inflight == 0, "unauthorised packets consumed capacity"
    assert receiver._rejected_packets == 50


@pytest.mark.parametrize("factory", [_syslog, _trap])
async def test_admission_is_synchronous(factory):
    """
    ``datagram_received`` is a plain callback; asyncio expects it to return at
    once. An await in the admission path could not be honoured there, and the
    check would have to move back inside the task -- which is the defect.
    """
    import ast
    import inspect
    import textwrap

    receiver, _ = factory()
    src = textwrap.dedent(inspect.getsource(type(receiver).admit))

    assert not [
        n for n in ast.walk(ast.parse(src)) if isinstance(n, (ast.Await, ast.AsyncFor, ast.AsyncWith))
    ]
