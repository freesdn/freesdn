# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Discovery and the deep sync hold no database transaction while the
controller is talking.

Evidence: a deep sync of a large Omada site takes minutes, and its sections
interleaved their adapter reads with their writes inside one transaction, so
every slow controller held a transaction (and, behind PgBouncer, a server
connection) the whole time. Discovery likewise kept the transaction from its
first read open across ``discover_devices()``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.models.devices import Device, DeviceType
from app.services import controller_sync
from tests.tasks.test_discovery_tenant_device_authority import inventory as inventory  # noqa: F401


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))

    def scalar_one_or_none(self):
        return None

    def all(self):
        return []


class _Session:
    """Tracks whether a transaction is open, the way SQLAlchemy autobegins."""

    def __init__(self, devices):
        self.devices = devices
        self.in_tx = False
        self.added: list = []

    async def execute(self, stmt, *_a, **_k):
        self.in_tx = True
        try:
            entity = stmt.column_descriptions[0].get("entity")
        except Exception:  # noqa: BLE001 - delete/update statements
            entity = None
        return _Result(self.devices if entity is Device else [])

    def add(self, obj):
        self.in_tx = True
        self.added.append(obj)

    async def flush(self):
        self.in_tx = True

    async def commit(self):
        self.in_tx = False

    async def rollback(self):
        self.in_tx = False

    @asynccontextmanager
    async def begin_nested(self):
        self.in_tx = True
        yield


class _Controller:
    """An Omada-like controller that notes whether a transaction was open."""

    def __init__(self, session):
        self.session = session
        self.calls: list[tuple] = []
        self.in_tx: list[str] = []

    def _note(self, name, *args):
        self.calls.append((name, *args))
        if self.session.in_tx:
            self.in_tx.append(name)

    async def get_ports(self, mac):
        self._note("get_ports", mac)
        return [{"port": 1, "name": "Port 1", "status": "up"}]

    async def get_vlans(self):
        self._note("get_vlans")
        return [{"vlanId": 10, "name": "IoT", "id": "net-10"}]

    async def get_ssids(self):
        self._note("get_ssids")
        return []

    async def get_port_profiles(self):
        self._note("get_port_profiles")
        return []

    async def get_switch_lag_groups(self, mac):
        self._note("get_switch_lag_groups", mac)
        return []

    async def get_clients(self):
        self._note("get_clients")
        return []

    async def get_switch_detail(self, mac):
        self._note("get_switch_detail", mac)
        return {"poe": {"budget": 120}}

    async def get_ap_detail(self, mac):
        self._note("get_ap_detail", mac)
        raise TimeoutError("the AP detail timed out")

    async def get_controller_status(self):
        self._note("get_controller_status")
        return {"cpuUtil": 5}


def _devices():
    ctrl_id = uuid4()
    switch = Device(
        id=uuid4(),
        controller_id=ctrl_id,
        name="core-sw",
        mac_address="AA-BB-CC-00-00-01",
        device_type=DeviceType.SWITCH,
        device_metadata={},
    )
    ap = Device(
        id=uuid4(),
        controller_id=ctrl_id,
        name="ap-1",
        mac_address="AA:BB:CC:00:00:02",
        device_type=DeviceType.ACCESS_POINT,
        device_metadata={},
    )
    controller = SimpleNamespace(id=ctrl_id, config={}, controller_type="omada")
    return controller, [switch, ap]


async def test_the_deep_sync_reads_the_controller_with_no_transaction_open():
    """Fails on the old deep sync: every read ran inside the device-list
    transaction."""
    controller, devices = _devices()
    session = _Session(devices)
    device = _Controller(session)
    await controller_sync.deep_sync_controller(session, device, controller, uuid4())
    assert device.calls, "the deep sync made no reads"
    assert device.in_tx == [], f"transaction open during device I/O: {device.in_tx}"


async def test_the_deep_sync_still_makes_exactly_the_reads_it_always_made():
    """The read phase mirrors the sections' own calls and arguments. A read the
    old code repeated with identical arguments (a switch listed under both its
    raw and normalised MAC) is now made once."""
    controller, devices = _devices()
    session = _Session(devices)
    device = _Controller(session)
    await controller_sync.deep_sync_controller(session, device, controller, uuid4())
    names = sorted(c[0] for c in device.calls)
    assert names == sorted(
        [
            "get_ports",  # the switch, by its stored MAC
            "get_vlans",
            "get_ssids",
            "get_port_profiles",
            "get_switch_lag_groups",
            "get_clients",
            "get_switch_detail",  # normalised and raw-key entries of the switch
            "get_switch_detail",
            "get_ap_detail",
            "get_controller_status",
        ]
    )
    assert ("get_ports", "AA-BB-CC-00-00-01") in device.calls
    # A failed read is replayed to its section exactly as it failed before.
    assert ("get_ap_detail", "AA:BB:CC:00:00:02") in device.calls


async def test_a_write_phase_read_that_was_not_made_fails_loudly_not_silently():
    replay = controller_sync._ReplayAdapter({}, {"get_vlans"})
    with pytest.raises(controller_sync._NotReadAhead):
        await replay.get_vlans()
    assert not hasattr(replay, "get_topology_data"), "hasattr must mirror the real adapter"


async def test_discovery_holds_no_transaction_across_discover_devices(inventory, monkeypatch):
    """Fails on the old discovery: the transaction from the controller read
    stayed open across the controller's whole discovery."""
    from app.db.session import CelerySessionLocal
    from app.tasks import discovery

    f = inventory
    seen: list[bool] = []
    sessions: list = []

    @asynccontextmanager
    async def tracked():
        async with CelerySessionLocal() as db:
            sessions.append(db)
            yield db

    async def check():
        seen.append(sessions[-1].in_transaction())

    f.before_return = check
    monkeypatch.setattr(discovery, "AsyncSessionLocal", tracked)
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is True
    assert seen == [False]


async def test_discovery_of_a_busy_controller_skips_without_contacting_it(inventory):
    from app.core.device_slot import device_slots
    from app.tasks import discovery

    f = inventory
    held = device_slots.try_acquire("host:127.0.0.1", "controller health check", ttl=60)
    assert held is not None and held.guarded
    try:
        outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    finally:
        device_slots.release(held)
    assert outcome["skipped"] is True and outcome["reason"] == "device_busy"
    assert f.adapter_calls == 0
