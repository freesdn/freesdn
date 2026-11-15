# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A device write waits briefly for the device's slot, then says "device busy".

Pollers take a device's slot (``app/core/device_slot.py``) for their whole
request group, but a write made from a request (``apply_change`` /
``apply_now``) or an audited action did not, so a configuration push could land
in the middle of a gateway full sync. The chokepoint now takes the slot just
before the device is contacted: it waits up to DEVICE_WRITE_SLOT_WAIT_SECONDS,
then refuses with 503 and sends nothing. A caller that already holds the slot
(a scheduled PoE change) is not made to wait for itself.

These run against the test Valkey; nothing is contacted.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select

import app.core.runtime_flags as rf
from app.core.config import settings
from app.core.device_slot import DeviceWriteBusyError, controller_slot_key, device_slots
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.security_audit import AuditLogRecord
from app.models.staging import AdapterPendingChange
from app.services.adapter_staging import AdapterStagingService

_KEY = "host:192.0.2.10"


@pytest.fixture(autouse=True)
def _writable_short_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: False)
    monkeypatch.setattr(settings, "DEVICE_WRITE_SLOT_WAIT_SECONDS", 0.3)


@pytest_asyncio.fixture
async def scope(db_session):
    org = Organization(name="write turn", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="c", site_id=site.id, controller_type="unifi", host="192.0.2.20", port=443
    )
    db_session.add(ctrl)
    await db_session.commit()
    return SimpleNamespace(org=org, site=site, ctrl=ctrl)


def _write(scope, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "organization_id": scope.org.id,
        "controller_id": None,
        "site_id": scope.site.id,
        "feature": "gateway.alias",
        "operation": "update",
        "target_id": "alias-1",
        "payload": {"name": "lan_hosts"},
        "force": True,
        "actor_id": None,
        "slot_key": _KEY,
    }
    base.update(over)
    return base


async def _rows(db_session) -> list[AdapterPendingChange]:
    return list(
        (
            await db_session.execute(
                select(AdapterPendingChange).where(AdapterPendingChange.feature.like("direct.%"))
            )
        ).scalars()
    )


async def test_a_busy_device_refuses_the_write_and_nothing_is_sent(db_session, scope) -> None:
    poller = device_slots.try_acquire(_KEY, "gateway full sync", ttl=30)
    assert poller is not None
    sent: list[str] = []

    async def _perform() -> dict[str, Any]:
        sent.append("write")
        return {"ok": True}

    try:
        with pytest.raises(DeviceWriteBusyError) as busy:
            await AdapterStagingService(db_session).apply_now(**_write(scope), perform=_perform)
    finally:
        device_slots.release(poller)

    assert busy.value.status_code == 503
    assert busy.value.headers == {"Retry-After": "5"}
    assert "Device busy: gateway full sync" in busy.value.detail
    assert "not sent" in busy.value.detail
    assert sent == []
    (row,) = await _rows(db_session)
    assert row.status == "failed"
    assert "refused before the device was contacted" in row.failure_reason
    assert "gateway full sync" in row.failure_reason


async def test_the_write_waits_for_a_poll_that_finishes_in_time(db_session, scope) -> None:
    poller = device_slots.try_acquire(_KEY, "gateway health poll", ttl=30)
    assert poller is not None

    async def _poll_ends() -> None:
        await asyncio.sleep(0.1)
        device_slots.release(poller)

    async def _perform() -> dict[str, Any]:
        return {"ok": True}

    ending = asyncio.create_task(_poll_ends())
    out = await AdapterStagingService(db_session).apply_now(**_write(scope), perform=_perform)
    await ending
    assert out == {"ok": True}
    (row,) = await _rows(db_session)
    assert row.status == "applied"


async def test_a_poller_cannot_start_while_the_write_holds_the_device(db_session, scope) -> None:
    seen: list[Any] = []

    async def _perform() -> dict[str, Any]:
        seen.append(device_slots.try_acquire(_KEY, "gateway full sync", ttl=30))
        return {"ok": True}

    await AdapterStagingService(db_session).apply_now(**_write(scope), perform=_perform)

    assert seen == [None], "a poller got the device while the write was on it"
    after = device_slots.try_acquire(_KEY, "gateway full sync", ttl=30)
    assert after is not None, "the write did not give the device back"
    device_slots.release(after)


async def test_a_caller_that_already_holds_the_slot_is_not_made_to_wait(db_session, scope) -> None:
    """A scheduled PoE change takes the controller's slot, then writes."""
    lease = await device_slots.acquire(_KEY, "PoE schedule", ttl=30)
    assert lease is not None

    async def _perform() -> dict[str, Any]:
        return {"ok": True}

    try:
        out = await AdapterStagingService(db_session).apply_now(**_write(scope), perform=_perform)
    finally:
        await device_slots.arelease(lease)
    assert out == {"ok": True}


async def test_a_controller_write_takes_the_controller_slot(db_session, scope) -> None:
    """No slot_key: the chokepoint derives the device from the change's controller."""
    key = controller_slot_key(scope.ctrl)
    poller = device_slots.try_acquire(key, "controller health check", ttl=30)
    assert poller is not None

    async def _perform() -> dict[str, Any]:
        raise AssertionError("the controller must not be contacted")

    try:
        with pytest.raises(DeviceWriteBusyError):
            await AdapterStagingService(db_session).apply_now(
                **_write(scope, controller_id=scope.ctrl.id, slot_key=None), perform=_perform
            )
    finally:
        device_slots.release(poller)


async def test_a_queued_change_stays_pending_when_the_device_is_busy(db_session, scope) -> None:
    staging = AdapterStagingService(db_session)
    change = await staging.stage_change(
        organization_id=scope.org.id,
        controller_id=scope.ctrl.id,
        site_id=scope.site.id,
        feature="unifi.radios",
        operation="update",
        target_id="ap-1",
        payload={"site": "default", "radio": "ng", "channel": 6},
    )
    key = controller_slot_key(scope.ctrl)
    poller = device_slots.try_acquire(key, "controller discovery", ttl=30)

    async def _applier(_change: Any) -> dict[str, Any]:
        raise AssertionError("the controller must not be contacted")

    try:
        with pytest.raises(HTTPException) as busy:
            await staging.apply_change(change.id, force=True, applier=_applier)
    finally:
        device_slots.release(poller)
    assert busy.value.status_code == 503
    await db_session.refresh(change)
    assert change.status == "pending", "a busy device must not use up the staged change"


async def test_an_audited_action_waits_for_the_device_too(db_session, scope) -> None:
    from app.services.device_writes import audited_device_action

    poller = device_slots.try_acquire(_KEY, "phone health check", ttl=30)
    sent: list[str] = []

    async def _reboot() -> dict[str, Any]:
        sent.append("reboot")
        return {"success": True}

    try:
        with pytest.raises(DeviceWriteBusyError):
            await audited_device_action(
                db_session,
                action="reboot_phone",
                target_type="device",
                target_id=uuid4(),
                target_name="phone 192.0.2.10",
                organization_id=scope.org.id,
                actor_id=None,
                perform=_reboot,
                slot_key=_KEY,
            )
    finally:
        device_slots.release(poller)
    assert sent == []
    records = (
        (
            await db_session.execute(
                select(AuditLogRecord).where(AuditLogRecord.action.like("device_action:%"))
            )
        )
        .scalars()
        .all()
    )
    assert records == []
