# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A scheduled PoE on/off goes through the staging chokepoint.

``poe.evaluate_schedules`` switched port power on the switches straight from
the Celery task: no staged row, no record of what it did, and only the adapter
client's own read-only gate in the way. A scheduled on/off sets the port's PoE
administrative state, which the switch keeps until the next window, so it is a
configuration change (STAGING-MIGRATION option 2): refused while read-only mode
is on, and each port write is a ``direct.switch.port.poe.schedule`` ledger row.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload

import app.core.runtime_flags as rf
from app.adapters.base import AdapterResult
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.devices import Device
from app.models.staging import AdapterPendingChange
from app.services import adapter_factory
from app.tasks.poe import _apply_schedule_to_device


class _Switch:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    async def __aenter__(self) -> _Switch:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def configure_switch_port(self, mac: str, port: int, config: Any) -> AdapterResult:
        self.calls.append((mac, port, config))
        return AdapterResult.ok({})


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest.fixture
def switch(monkeypatch: pytest.MonkeyPatch) -> _Switch:
    fake = _Switch()
    monkeypatch.setattr(adapter_factory, "get_adapter", lambda **_k: fake)
    return fake


@pytest_asyncio.fixture
async def device(db_session) -> Any:
    org = Organization(name="poe schedule", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="c", site_id=site.id, controller_type="omada", host="127.0.0.1", port=443
    )
    db_session.add(ctrl)
    await db_session.flush()
    dev = Device(
        name="sw",
        site_id=site.id,
        controller_id=ctrl.id,
        device_type="switch",
        mac_address="aa:bb:cc:00:00:09",
        status="online",
    )
    db_session.add(dev)
    await db_session.commit()
    return (
        await db_session.execute(
            select(Device).options(selectinload(Device.controller)).where(Device.id == dev.id)
        )
    ).scalar_one()


def _schedule() -> Any:
    return SimpleNamespace(id=uuid4(), name="night", port_numbers=[3, 4])


async def _rows(db_session) -> list[AdapterPendingChange]:
    return list(
        (
            await db_session.execute(
                select(AdapterPendingChange).where(
                    AdapterPendingChange.feature == "direct.switch.port.poe.schedule"
                )
            )
        ).scalars()
    )


async def test_a_scheduled_power_off_is_recorded_per_port(
    db_session, device, switch, mode
) -> None:
    schedule = _schedule()
    await _apply_schedule_to_device(db_session, schedule, device, poe_enabled=False)

    assert switch.calls == [
        ("aa:bb:cc:00:00:09", 3, {"poe": {"enable": False}}),
        ("aa:bb:cc:00:00:09", 4, {"poe": {"enable": False}}),
    ]
    rows = await _rows(db_session)
    assert sorted(r.payload["port"] for r in rows) == [3, 4]
    assert all(r.status == "applied" for r in rows)
    assert all(r.payload["schedule_id"] == str(schedule.id) for r in rows)
    assert all(r.payload["enabled"] is False for r in rows)


async def test_read_only_mode_refuses_a_scheduled_change(db_session, device, switch, mode) -> None:
    mode["read_only"] = True
    with pytest.raises(HTTPException) as refused:
        await _apply_schedule_to_device(db_session, _schedule(), device, poe_enabled=False)
    assert refused.value.status_code == 403
    assert switch.calls == []
    assert await _rows(db_session) == []
