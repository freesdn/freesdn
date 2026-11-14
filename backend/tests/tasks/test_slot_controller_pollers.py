# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Controller pollers share one turn per box and leave an unreachable one alone.

Evidence (2026-11 soak): the office OPNsense got the full sync, the 2-minute
health poll and drift reads at the same moments, each holding a PHP worker,
and nothing coordinated them. These tests run the real poll bodies against
synthetic devices; the device slots and the breakers they consult live in the
real Valkey of the test run.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx

from app.core.device_breaker import controller_key
from app.core.device_slot import controller_slot_key, device_slots
from app.db.models import ControllerStatus
from app.tasks import sync as sync_tasks
from tests.tasks.test_controller_health_recovery import _Controller, _row
from tests.tasks.test_controller_health_recovery import env as env  # noqa: F401


def _hold(key: str, holder: str = "another poller"):
    lease = device_slots.try_acquire(key, holder, ttl=60)
    assert lease is not None and lease.guarded, "the test needs real Valkey"
    return lease


def test_two_controllers_on_one_box_are_probed_one_after_another(env):
    in_flight = {"now": 0, "max": 0}

    class _Counted(_Controller):
        async def connect(self):
            in_flight["now"] += 1
            in_flight["max"] = max(in_flight["max"], in_flight["now"])
            await asyncio.sleep(0.2)
            in_flight["now"] -= 1
            return True

    a = _row(ControllerStatus.UNREACHABLE, name="omada")
    b = _row(ControllerStatus.UNREACHABLE, name="unifi")  # same host, other service
    env([(a, lambda w: _Counted(w)), (b, lambda w: _Counted(w))])
    asyncio.run(sync_tasks._check_controller_health())
    assert in_flight["max"] == 1
    assert a.status == b.status == ControllerStatus.CONNECTED


def test_a_controller_discovery_is_talking_to_is_not_probed_or_marked(env):
    row = _row(ControllerStatus.CONNECTED)
    _, adapters = env([(row, lambda w: _Controller(w))])
    held = _hold(controller_slot_key(row), "controller discovery")
    result = asyncio.run(sync_tasks._check_controller_health())
    device_slots.release(held)
    assert adapters[row.id].calls == []
    assert row.status == ControllerStatus.CONNECTED
    assert result["skipped"] == 1


def test_an_unreachable_controller_is_left_alone_after_two_failed_checks(env):
    """Fails on the old check: it logged in on every run."""
    row = _row(ControllerStatus.CONNECTED)
    _, adapters = env([(row, lambda w: _Controller(w, fail=httpx.ConnectTimeout("no answer")))])
    for _ in range(4):
        asyncio.run(sync_tasks._check_controller_health())
    assert adapters[row.id].calls == ["connect", "connect"]
    assert row.status == ControllerStatus.UNREACHABLE


def test_a_refused_login_does_not_pause_the_controller(env):
    from app.adapters.exceptions import AdapterAuthenticationError

    row = _row(ControllerStatus.CONNECTED)
    _, adapters = env(
        [
            (
                row,
                lambda w: _Controller(w, fail=AdapterAuthenticationError("bad password")),
            )
        ]
    )
    for _ in range(3):
        asyncio.run(sync_tasks._check_controller_health())
    # The controller answered (it refused the login): keep checking it.
    assert adapters[row.id].calls == ["connect"] * 3


class _DeviceResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))


def _status_world(monkeypatch, ctrl):
    devices = [
        SimpleNamespace(
            id=uuid4(),
            controller=ctrl,
            controller_id=ctrl.id,
            mac_address=f"AA:BB:CC:00:00:0{i}",
            external_id=None,
            site_id=None,
        )
        for i in range(2)
    ]

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

        async def execute(self, _stmt):
            return _DeviceResult(devices)

    built: list = []
    monkeypatch.setattr(sync_tasks, "AsyncSessionLocal", _Session)
    monkeypatch.setattr(
        sync_tasks, "build_adapter_for_controller", lambda c: built.append(c) or object()
    )
    return built


def test_device_status_sync_skips_a_busy_controller(monkeypatch):
    ctrl = SimpleNamespace(id=uuid4(), host="192.0.2.40", connection_mode="local")
    built = _status_world(monkeypatch, ctrl)
    held = _hold(controller_slot_key(ctrl), "controller discovery")
    result = asyncio.run(sync_tasks._sync_all_device_statuses())
    device_slots.release(held)
    assert built == []
    assert result["devices_skipped"] == 2 and result["devices_failed"] == 0


def test_device_status_sync_leaves_an_unreachable_controller_to_the_health_check(monkeypatch):
    from app.core.device_breaker import controller_breaker

    ctrl = SimpleNamespace(id=uuid4(), host="192.0.2.41", connection_mode="local")
    built = _status_world(monkeypatch, ctrl)
    for _ in range(controller_breaker.failure_threshold):
        controller_breaker.record_failure(controller_key(ctrl.id), "ConnectTimeout")
    result = asyncio.run(sync_tasks._sync_all_device_statuses())
    assert built == [] and result["devices_skipped"] == 2
