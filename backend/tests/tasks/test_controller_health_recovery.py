# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A controller that answers again is CONNECTED on the next health check.

Evidence (2026-11 soak): after a 2-minute upstream outage the Omada controller
stayed "unreachable" for ~10 minutes after it answered again. The check probed
with ``adapter.get_devices()`` -- a full device discovery -- one controller after
another, with no deadline, inside one DB transaction, on the I/O queue behind
minutes-long syncs. These tests run the real check body against synthetic
controllers and a fake session.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.db.models import ControllerStatus
from app.tasks import sync as sync_tasks


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))


class _World:
    def __init__(self, controllers):
        self.controllers = controllers
        self.session_open = False

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
                return _Result(world.controllers)

            async def commit(self):
                return None

        return _Session()


class _Controller:
    def __init__(self, world, *, hang=0.0, fail=None):
        self.world, self.hang, self.fail = world, hang, fail
        self.calls: list[str] = []
        self.open_tx: list[str] = []

    def _note(self, name):
        self.calls.append(name)
        if self.world.session_open:
            self.open_tx.append(name)

    async def connect(self):
        self._note("connect")
        if self.hang:
            await asyncio.sleep(self.hang)
        if self.fail:
            raise self.fail
        return True

    async def disconnect(self):
        return None

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *_exc):
        return False

    async def get_devices(self):
        self._note("discovery")
        return []


def _row(status, name="omada"):
    return SimpleNamespace(
        id=uuid4(),
        name=name,
        host="192.0.2.10",
        status=status,
        last_error="was down" if status == ControllerStatus.UNREACHABLE else None,
        last_sync=None,
        controller_type="omada",
        connection_mode="local",
        username="u",
        password="p",
        port=443,
        use_ssl=True,
        verify_ssl=False,
        client_id=None,
        client_secret=None,
        omada_id=None,
        cloud_region=None,
    )


@pytest.fixture
def env(monkeypatch):
    def install(rows_and_adapters):
        rows = [r for r, _ in rows_and_adapters]
        world = _World(rows)
        by_id = {}
        for row, make in rows_and_adapters:
            by_id[row.id] = make(world)

        import app.services.adapter_factory as factory

        monkeypatch.setattr(factory, "build_adapter_for_controller", lambda c: by_id[c.id])
        monkeypatch.setattr(sync_tasks, "AsyncSessionLocal", world.session)
        return world, by_id

    return install


def test_a_recovered_controller_is_connected_on_the_next_check(env):
    row = _row(ControllerStatus.UNREACHABLE)
    _, adapters = env([(row, lambda w: _Controller(w))])
    asyncio.run(sync_tasks._check_controller_health())
    assert row.status == ControllerStatus.CONNECTED
    assert row.last_error is None
    # A reachability probe is not a sync: it must not stamp last_sync.
    assert row.last_sync is None


def test_the_probe_is_a_login_not_a_discovery_and_holds_no_transaction(env):
    """Fails on the old check: it ran get_devices() inside the session."""
    row = _row(ControllerStatus.CONNECTED)
    _, adapters = env([(row, lambda w: _Controller(w))])
    asyncio.run(sync_tasks._check_controller_health())
    ad = adapters[row.id]
    assert "discovery" not in ad.calls, ad.calls
    assert ad.open_tx == [], f"DB session open during the probe: {ad.open_tx}"


def test_a_hung_controller_does_not_hold_up_the_others(env, monkeypatch):
    """Fails on the old check: probes ran one after another with no deadline."""
    monkeypatch.setattr(sync_tasks, "_HEALTH_PROBE_TIMEOUT", 0.2)
    hung = _row(ControllerStatus.CONNECTED, name="proxmox")
    back = _row(ControllerStatus.UNREACHABLE, name="omada")
    env([(hung, lambda w: _Controller(w, hang=3.0)), (back, lambda w: _Controller(w))])
    started = time.monotonic()
    asyncio.run(sync_tasks._check_controller_health())
    assert time.monotonic() - started < 2.0
    assert back.status == ControllerStatus.CONNECTED
    assert hung.status == ControllerStatus.UNREACHABLE
    assert hung.last_error == "TimeoutError"


def test_discovery_owned_states_are_left_to_discovery(env):
    """A probe proves reachability, not that discovery works: ERROR stays."""
    row = _row(ControllerStatus.ERROR)
    row.last_error = "discovery failed"
    env([(row, lambda w: _Controller(w))])
    asyncio.run(sync_tasks._check_controller_health())
    assert row.status == ControllerStatus.ERROR and row.last_error == "discovery failed"


def test_an_unreachable_controller_records_why(env):
    from app.adapters.exceptions import AdapterConnectionError

    row = _row(ControllerStatus.CONNECTED)
    env(
        [
            (
                row,
                lambda w: _Controller(
                    w, fail=AdapterConnectionError("refused", adapter_id="omada")
                ),
            )
        ]
    )
    asyncio.run(sync_tasks._check_controller_health())
    assert row.status == ControllerStatus.UNREACHABLE
    assert "refused" in row.last_error
