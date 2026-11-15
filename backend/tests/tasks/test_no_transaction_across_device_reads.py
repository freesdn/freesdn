# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Proxmox and storage monitors, the camera polls, the phone health check
and the drift checks hold no database transaction while a device answers.

Evidence: each of them opened a session, read the database, then talked to
the device (seconds for a recorder, up to minutes for a slow cluster) with
that transaction still open, and behind PgBouncer a server connection with it.
fixed discovery and the deep sync this way; these are the rest.

The monitors and camera polls run against real PostgreSQL with every session
they open tracked; the device doubles record whether any of them was in a
transaction at the moment of the request.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest_asyncio
from sqlalchemy import delete, select

from app.adapters.base import AdapterResult
from app.core.crypto import encrypt_credential
from app.db.session import CelerySessionLocal
from app.models.core import Controller, Organization, Site


class _Tracked:
    """Every session a task opens, so a device double can ask about them."""

    def __init__(self) -> None:
        self.sessions: list[Any] = []

    def factory(self):
        @asynccontextmanager
        async def open_session():
            async with CelerySessionLocal() as db:
                self.sessions.append(db)
                yield db

        return open_session

    def any_open(self) -> bool:
        return any(s.in_transaction() for s in self.sessions)


@pytest_asyncio.fixture
async def site():
    org_id, site_id = uuid4(), uuid4()
    async with CelerySessionLocal() as db:
        db.add(Organization(id=org_id, name="no tx across io", slug=f"ntx-{org_id.hex}"))
        await db.flush()
        db.add(Site(id=site_id, organization_id=org_id, name="s", slug=f"ntx-{site_id.hex}"))
        await db.commit()
    try:
        yield SimpleNamespace(org=org_id, site=site_id)
    finally:
        from app.modules.cameras.models import NVR, Camera, CameraEvent, CameraHealthSnapshot

        async with CelerySessionLocal() as db:
            cams = select(Camera.id).where(Camera.organization_id == org_id)
            await db.execute(
                delete(CameraHealthSnapshot).where(CameraHealthSnapshot.camera_id.in_(cams))
            )
            await db.execute(delete(CameraEvent).where(CameraEvent.camera_id.in_(cams)))
            await db.execute(delete(Camera).where(Camera.organization_id == org_id))
            await db.execute(delete(NVR).where(NVR.organization_id == org_id))
            await db.execute(delete(Controller).where(Controller.site_id == site_id))
            await db.execute(delete(Site).where(Site.id == site_id))
            await db.execute(delete(Organization).where(Organization.id == org_id))
            await db.commit()


async def _controller(site, kind: str, host: str) -> Controller:
    async with CelerySessionLocal() as db:
        ctrl = Controller(
            name=f"{kind} monitor fixture",
            site_id=site.site,
            controller_type=kind,
            host=host,
            port=443,
            config={"username": "reader", "password": encrypt_credential("synthetic")},
        )
        db.add(ctrl)
        await db.commit()
        return ctrl


async def _operator_saves_a_setting(controller_id) -> None:
    """What an operator editing the controller during the poll does."""
    async with CelerySessionLocal() as db:
        row = await db.get(Controller, controller_id)
        row.config = {**(row.config or {}), "operator_note": "saved during the poll"}
        await db.commit()


async def _config(controller_id) -> dict[str, Any]:
    async with CelerySessionLocal() as db:
        return dict((await db.get(Controller, controller_id)).config or {})


# ── Proxmox monitor ────────────────────────────────────────────────────


async def test_the_proxmox_monitor_reads_a_cluster_with_no_transaction_open(site, monkeypatch):
    """Fails on the old monitor: its controller query's transaction stayed
    open across the cluster read, and the snapshot it wrote afterwards was the
    config read at the start, so a setting saved meanwhile was lost."""
    from app.adapters.proxmox.models import ProxmoxClusterStatus
    from app.services import adapter_proxmox_vm
    from app.tasks import hypervisor

    ctrl = await _controller(site, "proxmox", "192.0.2.81")
    tracked = _Tracked()
    seen: list[bool] = []

    class Cluster:
        async def get_cluster_status(self):
            seen.append(tracked.any_open())
            await _operator_saves_a_setting(ctrl.id)
            return AdapterResult.ok(
                ProxmoxClusterStatus(name="lab", quorate=True, node_count=1, version=2)
            )

        async def disconnect(self):
            return None

    async def build(c):
        return Cluster()

    monkeypatch.setattr(adapter_proxmox_vm, "build_proxmox_adapter", build)
    monkeypatch.setattr(hypervisor, "CelerySessionLocal", tracked.factory())
    out = await hypervisor._poll_hypervisor_health()
    assert out["polled"] >= 1
    assert seen and not any(seen), "no transaction may be open while the cluster answers"
    config = await _config(ctrl.id)
    assert config["operator_note"] == "saved during the poll"
    assert config[hypervisor._SNAP_KEY]["reachable"] is True


# ── storage monitor ────────────────────────────────────────────────────


async def test_the_storage_monitor_reads_an_appliance_with_no_transaction_open(site, monkeypatch):
    from app.modules.storage import providers
    from app.tasks import storage

    ctrl = await _controller(site, "truenas", "192.0.2.82")
    tracked = _Tracked()
    seen: list[bool] = []

    async def read(c):
        seen.append(tracked.any_open())
        if c.id == ctrl.id:
            await _operator_saves_a_setting(ctrl.id)
        return providers.StorageReading(pools=[], alerts=[], disk_temps={})

    monkeypatch.setattr(providers, "read_controller_storage", read)
    monkeypatch.setattr(storage, "CelerySessionLocal", tracked.factory())
    out = await storage._poll_storage_health()
    assert out["polled"] >= 1
    assert seen and not any(seen), "no transaction may be open while the appliance answers"
    config = await _config(ctrl.id)
    assert config["operator_note"] == "saved during the poll"
    assert config[storage._SNAP_KEY]["reachable"] is True


# ── camera polls ───────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def recorder(site, monkeypatch):
    from app.modules.cameras.models import NVR, Camera
    from app.tasks import cameras

    nvr_id, cam_id = uuid4(), uuid4()
    async with CelerySessionLocal() as db:
        db.add(
            NVR(
                id=nvr_id,
                organization_id=site.org,
                site_id=site.site,
                name="nvr",
                ip_address="10.99.0.5",
                port=80,
                vendor="hikvision",
                username="admin",
                password_encrypted=encrypt_credential("synthetic"),
            )
        )
        await db.flush()
        db.add(
            Camera(
                id=cam_id,
                organization_id=site.org,
                site_id=site.site,
                nvr_id=nvr_id,
                name="lobby",
                ip_address="10.99.0.5",
                channel_id=1,
            )
        )
        await db.commit()

    tracked = _Tracked()
    state = SimpleNamespace(seen=[], nvr=nvr_id, camera=cam_id, tracked=tracked)

    class Recorder:
        def __init__(self, **_kw):
            pass

        async def connect(self):
            state.seen.append(tracked.any_open())
            return True

        async def disconnect(self):
            return None

        async def get_channel_status_list(self):
            state.seen.append(tracked.any_open())
            return [{"id": 1, "online": True}]

        async def get_channel_track_info(self, channel):
            state.seen.append(tracked.any_open())
            return {"tracks": [{"bitrate_kbps": 2048, "codec": "H.265"}]}

        async def get_event_state(self):
            state.seen.append(tracked.any_open())
            return {
                "events": [
                    {
                        "channel_id": 1,
                        "event_type": "VMD",
                        "date_time": "2026-11-13T12:00:00+00:00",
                    }
                ]
            }

    monkeypatch.setattr("app.adapters.hikvision.adapter.HikvisionAdapter", Recorder)
    monkeypatch.setattr(cameras, "AsyncSessionLocal", tracked.factory())

    async def no_dispatch(*_a, **_k):
        return None

    monkeypatch.setattr(cameras, "_dispatch_alerts", no_dispatch)
    return state


async def test_the_camera_health_poll_reads_the_recorder_with_no_transaction_open(recorder):
    from app.modules.cameras.models import CameraHealthSnapshot
    from app.tasks import cameras

    out = await cameras._poll_single_nvr_health(recorder.nvr)
    assert out == {"nvr_id": str(recorder.nvr), "saved": 1, "errors": 0}
    assert recorder.seen and not any(recorder.seen)
    async with CelerySessionLocal() as db:
        rows = (
            (
                await db.execute(
                    select(CameraHealthSnapshot).where(
                        CameraHealthSnapshot.camera_id == recorder.camera
                    )
                )
            )
            .scalars()
            .all()
        )
    assert [(r.codec, r.is_online) for r in rows] == [("H.265", True)]


async def test_the_alert_ingest_reads_the_recorder_with_no_transaction_open(recorder):
    from app.modules.cameras.models import CameraEvent
    from app.tasks import cameras

    out = await cameras._ingest_nvr_alerts(recorder.nvr)
    assert out == {"nvr_id": str(recorder.nvr), "ingested": 1}
    assert recorder.seen and not any(recorder.seen)
    async with CelerySessionLocal() as db:
        stored = (
            (await db.execute(select(CameraEvent).where(CameraEvent.camera_id == recorder.camera)))
            .scalars()
            .all()
        )
    assert len(stored) == 1


# ── phone health ───────────────────────────────────────────────────────


class _AutobeginSession:
    """Begins a transaction on the first statement, like SQLAlchemy."""

    def __init__(self) -> None:
        self.in_tx = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def execute(self, _stmt):
        self.in_tx = True
        return SimpleNamespace(all=lambda: [])

    async def commit(self):
        self.in_tx = False


def test_the_phone_health_check_logs_in_with_no_transaction_open(monkeypatch):
    import app.db.session as db_session
    import app.modules.voip.service as voip_service
    from app.modules.voip import tasks
    from tests.modules.test_voip_phone_polling import _FakeService, _phone

    session = _AutobeginSession()
    seen: list[bool] = []

    class Phone:
        def __init__(self, **_kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

        async def get_device_status(self, _mac):
            seen.append(session.in_tx)
            return {"data": {"sip_registered": True}}

    phones = []
    for n in range(2):
        phone = _phone({"web_password": encrypt_credential("pw")}, state="managed")
        phone.ip_address, phone.site_id = f"192.0.2.9{n}", uuid4()
        phones.append(phone)
    _FakeService.by_state, _FakeService.updates = {"managed": phones}, []
    monkeypatch.setattr(db_session, "celery_session_factory", lambda: session)
    monkeypatch.setattr(voip_service, "VoIPService", _FakeService)
    monkeypatch.setattr(tasks, "_get_adapter", lambda _vendor, **kw: Phone(**kw))
    result = tasks.health_check()
    assert result["healthy"] == 2
    assert seen == [False, False], "each phone is read with no transaction open"


# ── drift checks ───────────────────────────────────────────────────────


class _DriftDB:
    """The drift check's session: autobegins on a read, records commits."""

    def __init__(self, *results):
        self._results = list(results)
        self.in_tx = False
        self.new: list[Any] = []
        self.dirty: list[Any] = []
        self.deleted: list[Any] = []

    def in_transaction(self) -> bool:
        return self.in_tx

    async def execute(self, _stmt):
        self.in_tx = True
        rows = self._results.pop(0) if self._results else []
        return SimpleNamespace(
            scalar_one_or_none=lambda: rows[0] if rows else None,
            scalars=lambda: SimpleNamespace(all=lambda: list(rows)),
        )

    async def commit(self):
        self.in_tx = False


async def test_a_drift_check_reads_the_gateway_with_no_transaction_open(monkeypatch):
    """Fails on the old check: the transaction of its gateway and canonical
    VLAN reads stayed open across the firewall's answer."""
    from app.modules.gateway.models import NetworkRole
    from app.modules.gateway.services import drift_service
    from app.modules.gateway.services.drift_service import DriftService

    gw = SimpleNamespace(id=uuid4(), host="192.0.2.95", deleted_at=None, sync_enabled=True)
    role_map = SimpleNamespace(
        organization_id=uuid4(),
        site_id=uuid4(),
        assignments=[SimpleNamespace(role=NetworkRole.BRAIN, gateway_id=gw.id)],
    )
    db = _DriftDB([gw], [SimpleNamespace(vlan_id=10, organization_id=uuid4(), site_id=uuid4())])
    seen: list[bool] = []

    class Firewall:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

        async def get_vlan_devices(self):
            seen.append(db.in_tx)
            return AdapterResult.ok({"vlans": [{"tag": 10}]})

    monkeypatch.setattr(drift_service, "build_adapter", lambda _gw: Firewall())
    assert await DriftService(db)._check_brain_vlans(role_map) == []
    assert seen == [False]


async def test_a_drift_check_never_commits_someone_elses_unflushed_changes(monkeypatch):
    from app.modules.gateway.services.drift_service import DriftService

    db = _DriftDB()
    db.in_tx = True
    db.new.append(object())
    await DriftService(db)._end_read_transaction()
    assert db.in_tx is True, "a session with pending changes is left as it is"


def test_tracked_sessions_see_a_real_transaction():
    """The helper itself: a session that has run a statement is in a transaction."""
    tracked = _Tracked()

    async def scenario():
        async with tracked.factory()() as db:
            await db.execute(select(Organization.id).limit(1))
            return tracked.any_open()

    assert asyncio.run(scenario()) is True
