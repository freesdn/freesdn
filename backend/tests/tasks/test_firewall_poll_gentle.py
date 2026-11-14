# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The 2-minute firewall health poll is a gentle neighbour.

Evidence (2026-11 soak, office OPNsense with a wedged PHP/configd backend): the
poll kept connecting every 2 minutes, sent the gateway-status and IDS reads
after a probe that had already timed out, held its DB session open across all
of it, and nothing stopped it. These tests run the real poll body against a
synthetic gateway, a fake session and the shared breaker on a Redis double.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core import device_breaker
from app.core.device_breaker import DeviceBreaker
from app.tasks import firewall_monitor
from tests.core.test_device_breaker import Clock, RedisDouble


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))


class _World:
    """The gateway table, and whether a DB session is open right now."""

    def __init__(self, gateway):
        self.gateway = gateway
        self.session_open = False
        self.commits = 0

    def session(self):
        world = self

        class _Session:
            async def __aenter__(self):
                world.session_open = True
                return self

            async def __aexit__(self, *_exc):
                world.session_open = False
                return False

            async def execute(self, _stmt):
                return _Result([world.gateway])

            async def commit(self):
                world.commits += 1

        return _Session()


class _Firewall:
    def __init__(self, world, *, connect=None, status=None):
        self.world = world
        self.connect_exc = connect
        self.status_exc = status
        self.calls: list[str] = []
        self.open_tx: list[str] = []

    def _note(self, name):
        self.calls.append(name)
        if self.world.session_open:
            self.open_tx.append(name)

    async def connect(self):
        self._note("connect")
        if self.connect_exc:
            raise self.connect_exc

    async def disconnect(self):
        return None

    async def get_gateway_status(self):
        self._note("gateway_status")
        if self.status_exc:
            raise self.status_exc
        return SimpleNamespace(success=True, data={"gateways": [{"name": "WAN", "status": "up"}]})

    async def get_ids_alerts(self):
        self._note("ids")
        return SimpleNamespace(success=True, data={"alerts": []})


@pytest.fixture
def env(monkeypatch):
    redis, clock = RedisDouble(), Clock()
    breaker = DeviceBreaker(
        failure_threshold=2, base_cooldown=120, redis_factory=lambda: redis, clock=clock
    )
    monkeypatch.setattr(device_breaker, "gateway_breaker", breaker)
    gw = SimpleNamespace(
        id=uuid4(),
        name="opnsense",
        vendor="opnsense",
        host="192.0.2.1",
        org_id=uuid4(),
        fabric_health=None,
    )
    world = _World(gw)
    monkeypatch.setattr(firewall_monitor, "CelerySessionLocal", world.session)
    monkeypatch.setattr(firewall_monitor, "flag_modified", lambda *_a: None)

    def install(firewall):
        from app.modules.firewall import gateway_service

        monkeypatch.setattr(
            gateway_service.GatewayService, "_build_adapter", lambda _self, _gw: firewall
        )

    return world, clock, install


def _poll():
    return asyncio.run(firewall_monitor._poll_firewall_health())


def test_no_db_session_is_open_while_the_firewall_is_polled(env):
    """Fails on the old poll: every device call ran inside the session."""
    world, _, install = env
    fw = _Firewall(world)
    install(fw)
    result = _poll()
    assert fw.calls == ["connect", "gateway_status", "ids"]
    assert fw.open_tx == [], f"DB session open during device I/O: {fw.open_tx}"
    assert result["polled"] == 1 and world.commits == 1
    assert world.gateway.fabric_health["reachable"] is True


def test_a_firewall_that_stops_answering_is_left_alone_until_the_cooldown(env):
    """Fails on the old poll: it connected on every one of the five cycles."""
    world, clock, install = env
    fw = _Firewall(world, connect=TimeoutError())
    install(fw)
    results = []
    for _ in range(5):
        results.append(_poll())
        clock.now += 30  # well inside the first ~2-minute cooldown
    assert fw.calls == ["connect", "connect"]
    assert [r["skipped"] for r in results] == [0, 0, 1, 1, 1]

    clock.now += 200  # cooldown over: exactly one probe
    fw.connect_exc = None
    _poll()
    _poll()
    assert fw.calls.count("connect") == 4  # the probe, then normal polling again


def test_a_read_the_firewall_did_not_answer_stops_the_rest(env):
    """Fails on the old poll: the IDS read followed a timed-out status read."""
    world, _, install = env
    fw = _Firewall(world, status=TimeoutError())
    install(fw)
    _poll()
    assert fw.calls == ["connect", "gateway_status"]
    state = device_breaker.gateway_breaker.status(device_breaker.gateway_key(world.gateway.id))
    assert state.get("failures") == 1 and "gateway_status" in state.get("last_error", "")


def test_a_refused_read_is_not_held_against_the_firewall(env):
    world, _, install = env
    fw = _Firewall(world)

    async def refused():
        fw._note("gateway_status")
        return SimpleNamespace(success=False, data=None, error="OPNsenseAPIError")

    fw.get_gateway_status = refused
    install(fw)
    _poll()
    assert fw.calls == ["connect", "gateway_status", "ids"]
    assert device_breaker.gateway_breaker.status(device_breaker.gateway_key(world.gateway.id)) == {}
