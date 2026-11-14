# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Discovery page's "Discover" buttons must actually discover.

``POST /discovery/controllers/{id}``, ``/discovery/sites/{id}`` and
``/discovery/all`` run ``DiscoveryService``. It used to carry its own copy of
the discovery pipeline that constructed ``Device(vendor=, serial=, mac=, ip=,
hostname=, vendor_data=, discovered_at=)``: none are ``Device`` fields, so every
new device raised ``TypeError``, which was logged and swallowed per device. The
endpoint answered "running" and no device appeared. It also selected controllers
by ``status != "disabled"`` (nothing writes that status), so disabled and
soft-deleted controllers were discovered too.

Found by tests/models/test_orm_constructor_kwargs.py. These run on real
PostgreSQL through the real Omada adapter class with only its network methods
replaced.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

import app.tasks.discovery as tasks_discovery
from app.adapters.base import DiscoveredDevice
from app.adapters.omada import OmadaAdapter
from app.models.core import Controller, Organization, Site
from app.models.devices import Device
from app.services.discovery import DiscoveryService


async def _graph(db_session):
    suffix = uuid4().hex[:8]
    org = Organization(name="Disc Org", slug=f"disc-svc-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="Disc Site", slug=f"disc-svc-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    return org, site


def _controller(site, name, **kw):
    return Controller(
        name=name,
        controller_type="omada",
        host="10.0.0.1",
        port=8043,
        site_id=site.id,
        sync_enabled=True,
        # The adapter is constructed for real (only its network methods are
        # replaced), and a local Omada adapter refuses to exist without a login.
        config={"username": "admin", "password": "not-a-real-secret"},
        **kw,
    )


def _isolate(db_session, monkeypatch, devices):
    async def _connect(self):
        return True

    async def _disconnect(self):
        return None

    async def _discover(self):
        return list(devices)

    monkeypatch.setattr(OmadaAdapter, "connect", _connect)
    monkeypatch.setattr(OmadaAdapter, "disconnect", _disconnect)
    monkeypatch.setattr(OmadaAdapter, "discover_devices", _discover)

    class _Ctx:  # the canonical impl does `async with AsyncSessionLocal() as session`
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(tasks_discovery, "AsyncSessionLocal", lambda: _Ctx())
    monkeypatch.setattr(db_session, "commit", db_session.flush)

    async def _noop(*a, **k):
        return None

    async def _deep(*a, **k):
        return {}

    monkeypatch.setattr(tasks_discovery, "publish_controller_event", _noop)
    monkeypatch.setattr(tasks_discovery, "publish_device_event", _noop)
    monkeypatch.setattr(tasks_discovery, "deep_sync_controller", _deep)
    from app.services.ztp import ZTPEngine

    async def _ztp(self, device, session):
        return None

    monkeypatch.setattr(ZTPEngine, "evaluate_device", _ztp)
    import app.core.celery_app as celery_app

    monkeypatch.setattr(celery_app, "acquire_solo_lock", lambda *_a, **_k: "token")
    monkeypatch.setattr(celery_app, "release_solo_lock", lambda *_a, **_k: None)


async def test_discover_controller_creates_the_discovered_device(db_session, monkeypatch):
    _org, site = await _graph(db_session)
    ctrl = _controller(site, "Disc Omada", is_active=True)
    db_session.add(ctrl)
    await db_session.flush()
    _isolate(
        db_session,
        monkeypatch,
        [
            DiscoveredDevice(
                mac_address="AA:BB:CC:10:00:01",
                ip_address="10.0.0.31",
                name="AP-Disc",
                vendor="TP-Link",
                model="EAP670",
                firmware_version="1.0.0",
                device_type="access_point",
                status="online",
                serial_number="SN-DISC-1",
            )
        ],
    )

    stats = await DiscoveryService(db_session).discover_controller(ctrl.id)

    rows = (
        (await db_session.execute(select(Device).where(Device.controller_id == ctrl.id)))
        .scalars()
        .all()
    )
    assert [(r.mac_address, r.ip_address, r.serial_number) for r in rows] == [
        ("AA:BB:CC:10:00:01", "10.0.0.31", "SN-DISC-1")
    ]
    assert stats["total"] == 1
    assert stats["new"] == 1
    assert stats["errors"] == []


async def test_discover_all_skips_disabled_and_deleted_controllers(db_session, monkeypatch):
    _org, site = await _graph(db_session)
    live = _controller(site, "Live", is_active=True)
    disabled = _controller(site, "Disabled", is_active=False)
    deleted = _controller(site, "Deleted", is_active=True, deleted_at=datetime.now(UTC))
    db_session.add_all([live, disabled, deleted])
    await db_session.flush()

    called = []

    async def _record(self, controller_id):
        called.append(controller_id)
        return {"total": 0, "new": 0, "updated": 0, "unchanged": 0, "errors": []}

    monkeypatch.setattr(DiscoveryService, "discover_controller", _record)

    out = await DiscoveryService(db_session).discover_all(site_id=site.id)

    assert called == [live.id]
    assert out["controllers"] == 1
