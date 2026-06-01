# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""End-to-end discover → sync → DB vertical for controller discovery.

Drives the REAL ``_discover_devices_for_controller_impl`` against a real
(transaction-rolled-back) DB session with a fake adapter, proving the full
vertical: discover_devices() → MAC/MAC-less dedup preload → create/update
decisions → Device rows persisted → a re-sync UPDATES in place (no duplicates,
backed by the uq_devices_mac_alive index). External edges (adapter connect,
events, deep-sync, ZTP) are stubbed so the test is deterministic + offline.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

import app.tasks.discovery as discovery
from app.adapters.base import DiscoveredDevice
from app.models.core import Controller, Organization, Site
from app.models.devices import Device


class _FakeAdapter:
    """Minimal adapter: supports ``async with`` + discover_devices()."""

    def __init__(self, devices):
        self._devices = devices

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def connect(self):
        return None

    async def disconnect(self):
        return None

    async def discover_devices(self):
        return list(self._devices)


def _dev(mac: str, name: str, dtype: str, ip: str) -> DiscoveredDevice:
    return DiscoveredDevice(
        mac_address=mac, ip_address=ip, name=name, vendor="TP-Link",
        model="EAP670" if dtype == "access_point" else "TL-SG3428",
        firmware_version="1.0.0", device_type=dtype, status="online",
    )


@pytest.mark.asyncio
async def test_discover_creates_then_resync_updates_no_dupes(db_session, monkeypatch) -> None:
    # ── arrange: a minimal org → site → omada controller graph ──
    suffix = uuid4().hex[:8]
    org = Organization(name="E2E Org", slug=f"e2e-omada-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="E2E Site", slug=f"e2e-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="E2E Omada", controller_type="omada", host="10.0.0.1", port=8043,
        site_id=site.id, is_active=True, sync_enabled=True, config={},
    )
    db_session.add(ctrl)
    await db_session.flush()
    cid = str(ctrl.id)

    devices = [
        _dev("AA:BB:CC:00:00:01", "AP-1", "access_point", "10.0.0.11"),
        _dev("AA:BB:CC:00:00:02", "SW-1", "switch", "10.0.0.12"),
    ]

    # ── stub the external edges ──
    monkeypatch.setattr(discovery, "get_adapter", lambda *_a, **_k: _FakeAdapter(devices))

    class _Ctx:  # the impl does `async with AsyncSessionLocal() as session`
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False  # never close — the fixture owns the session lifecycle

    monkeypatch.setattr(discovery, "AsyncSessionLocal", lambda: _Ctx())
    # commit → flush so writes stay inside the test transaction (rolled back)
    monkeypatch.setattr(db_session, "commit", db_session.flush)

    async def _noop(*a, **k):
        return None

    async def _deep(*a, **k):
        return {}

    monkeypatch.setattr(discovery, "publish_controller_event", _noop)
    monkeypatch.setattr(discovery, "publish_device_event", _noop)
    monkeypatch.setattr(discovery, "deep_sync_controller", _deep)
    from app.services.ztp import ZTPEngine

    async def _ztp(self, device, session):
        return None

    monkeypatch.setattr(ZTPEngine, "evaluate_device", _ztp)

    async def _devices_for_ctrl():
        rows = (
            await db_session.execute(
                select(Device).where(
                    Device.controller_id == ctrl.id, Device.deleted_at.is_(None)
                )
            )
        ).scalars().all()
        return rows

    # ── act #1: first discovery → CREATE ──
    r1 = await discovery._discover_devices_for_controller_impl(cid)
    assert r1["success"] is True
    assert r1["devices_discovered"] == 2
    assert r1["devices_created"] == 2
    assert r1["devices_updated"] == 0

    rows = await _devices_for_ctrl()
    assert len(rows) == 2
    assert {r.mac_address for r in rows} == {"AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"}
    assert {r.site_id for r in rows} == {site.id}  # resolved to the controller's site

    # ── act #2: re-sync same devices → UPDATE in place, NO duplicates ──
    r2 = await discovery._discover_devices_for_controller_impl(cid)
    assert r2["devices_created"] == 0
    assert r2["devices_updated"] == 2

    rows2 = await _devices_for_ctrl()
    assert len(rows2) == 2  # still 2 — dedup + uq_devices_mac_alive held


@pytest.mark.asyncio
async def test_resync_with_new_device_creates_only_the_new_one(db_session, monkeypatch) -> None:
    suffix = uuid4().hex[:8]
    org = Organization(name="E2E Org2", slug=f"e2e-omada2-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="E2E Site2", slug=f"e2e-site2-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="E2E Omada2", controller_type="omada", host="10.0.0.2", port=8043,
        site_id=site.id, is_active=True, sync_enabled=True, config={},
    )
    db_session.add(ctrl)
    await db_session.flush()
    cid = str(ctrl.id)

    state = {"devices": [_dev("AA:BB:CC:00:00:10", "AP-A", "access_point", "10.0.0.21")]}

    class _Ctx:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(discovery, "get_adapter", lambda *_a, **_k: _FakeAdapter(state["devices"]))
    monkeypatch.setattr(discovery, "AsyncSessionLocal", lambda: _Ctx())
    monkeypatch.setattr(db_session, "commit", db_session.flush)

    async def _noop(*a, **k):
        return None

    async def _deep(*a, **k):
        return {}

    monkeypatch.setattr(discovery, "publish_controller_event", _noop)
    monkeypatch.setattr(discovery, "publish_device_event", _noop)
    monkeypatch.setattr(discovery, "deep_sync_controller", _deep)
    from app.services.ztp import ZTPEngine

    async def _ztp(self, device, session):
        return None

    monkeypatch.setattr(ZTPEngine, "evaluate_device", _ztp)

    r1 = await discovery._discover_devices_for_controller_impl(cid)
    assert r1["devices_created"] == 1

    # second sync: original reappears (update) + one genuinely new device (create)
    state["devices"] = [
        _dev("AA:BB:CC:00:00:10", "AP-A", "access_point", "10.0.0.21"),
        _dev("AA:BB:CC:00:00:11", "AP-B", "access_point", "10.0.0.22"),
    ]
    r2 = await discovery._discover_devices_for_controller_impl(cid)
    assert r2["devices_created"] == 1  # only AP-B
    assert r2["devices_updated"] == 1  # AP-A updated

    rows = (
        await db_session.execute(
            select(Device).where(Device.controller_id == ctrl.id, Device.deleted_at.is_(None))
        )
    ).scalars().all()
    assert len(rows) == 2
