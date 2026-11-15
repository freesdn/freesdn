# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Gateway pollers never talk to one firewall at once.

Evidence (2026-11 soak): the office OPNsense got the full sync, the 2-minute
health poll and drift reads at the same moments, each holding a PHP worker,
and nothing coordinated them. These tests run the real poll bodies against
synthetic devices; the device slots and the breakers they consult live in the
real Valkey of the test run.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.core.device_slot import device_slots, gateway_slot_key
from app.tasks import firewall_monitor
from tests.tasks.test_firewall_poll_gentle import _Firewall
from tests.tasks.test_firewall_poll_gentle import env as env  # noqa: F401


def _hold(key: str, holder: str = "another poller"):
    lease = device_slots.try_acquire(key, holder, ttl=60)
    assert lease is not None and lease.guarded, "the test needs real Valkey"
    return lease


def test_the_health_poll_leaves_a_gateway_the_full_sync_is_talking_to(env):
    """Fails on the old poll: it connected regardless."""
    world, _, install = env
    fw = _Firewall(world)
    install(fw)
    held = _hold(gateway_slot_key(world.gateway), "gateway full sync")
    result = asyncio.run(firewall_monitor._poll_firewall_health())
    assert fw.calls == []
    assert result["busy"] == 1 and result["polled"] == 0
    device_slots.release(held)
    asyncio.run(firewall_monitor._poll_firewall_health())
    assert fw.calls == ["connect", "gateway_status", "ids"]


def test_the_health_poll_and_a_drift_check_never_overlap_on_one_box(env, monkeypatch):
    """Fails on the old code: both connected to the firewall at once."""
    from app.modules.gateway.services import drift_service

    world, _, install = env
    in_flight = {"now": 0, "max": 0}

    class _Slow(_Firewall):
        async def connect(self):
            self._note("connect")
            in_flight["now"] += 1
            in_flight["max"] = max(in_flight["max"], in_flight["now"])
            await asyncio.sleep(0.3)
            in_flight["now"] -= 1

    fw = _Slow(world)
    install(fw)
    drift_adapter = _Slow(world)

    class _Ctx:
        async def __aenter__(self):
            await drift_adapter.connect()
            return drift_adapter

        async def __aexit__(self, *_exc):
            return False

    gw_row = SimpleNamespace(id=world.gateway.id, host=world.gateway.host)

    async def drift():
        async with drift_service._contact(gw_row, _Ctx(), "drift check (VLANs)") as adapter:
            if adapter is not None:
                await asyncio.sleep(0.3)
            return adapter is not None

    async def scenario():
        return await asyncio.gather(firewall_monitor._poll_firewall_health(), drift())

    poll, drift_ran = asyncio.run(scenario())
    assert in_flight["max"] == 1
    # Exactly one of the two got the box; the other skipped this cycle.
    assert (poll["polled"] == 1) != drift_ran
