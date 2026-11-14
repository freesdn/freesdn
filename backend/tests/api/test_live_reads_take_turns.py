# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Page reads of controllers, switches, MikroTik, Proxmox, NVRs and phones take
their turn at the device.

Real PostgreSQL, ASGI and Valkey; each device is a double that records every
request. A poller holding the device's slot stands in for a background sync.
On the old code every one of these routes contacted the device while the
poller held it.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import APIRouter, FastAPI
from httpx import ASGITransport, AsyncClient

from app.adapters.base import AdapterResult
from app.core.config import settings
from app.core.crypto import encrypt_credential
from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.device_slot import device_slots
from app.db import get_session
from app.models.core import Controller, Organization, Site, User
from app.services.device_live_read import DeviceReadTurnMiddleware


class Device:
    """A device double: every method is a recorded request."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.calls: list[str] = []
        self.answers = answers
        self._connected = True
        self.client = self

    async def __aenter__(self) -> Device:
        self.calls.append("connect")
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def connect(self) -> bool:
        self.calls.append("connect")
        return True

    async def disconnect(self) -> None:
        return None

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") or name not in self.answers:
            raise AttributeError(name)

        async def call(*_a: Any, **_k: Any) -> Any:
            self.calls.append(name)
            answer = self.answers[name]
            return answer() if callable(answer) else answer

        return call


@pytest.fixture
def quick_waits(monkeypatch):
    monkeypatch.setattr(settings, "DEVICE_UI_READ_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(settings, "DEVICE_UI_READ_MAX_WAIT_SECONDS", 0.6)


@pytest_asyncio.fixture
async def world(db_session):
    org = Organization(name="turns", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="turns", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    user = User(
        id=uuid4(),
        organization_id=org.id,
        email=f"turns-{uuid4().hex[:8]}@example.test",
        hashed_password="synthetic",
        role="super_admin",
        is_active=True,
    )
    return org, site, user


async def _client(db_session, user, router: APIRouter, prefix: str) -> AsyncClient:
    from app.api.v1.deps import get_db

    app = FastAPI()
    app.add_middleware(DeviceReadTurnMiddleware)
    app.include_router(router, prefix=prefix)

    async def session():
        yield db_session

    app.dependency_overrides[get_current_active_user] = lambda: CurrentUser(user, ["*"])
    app.dependency_overrides[get_session] = session
    app.dependency_overrides[get_db] = session
    return AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://ui.test"
    )


async def _controller(db_session, site, kind: str, host: str) -> Controller:
    ctrl = Controller(
        name=f"{kind} box",
        site_id=site.id,
        controller_type=kind,
        host=host,
        port=443,
        config={"username": "reader", "password": encrypt_credential("synthetic")},
    )
    db_session.add(ctrl)
    await db_session.flush()
    return ctrl


# ── one setup per shared read path ─────────────────────────────────────


async def controller_health(db_session, site, monkeypatch):
    from app.adapters.registry import adapter_registry
    from app.api.v1.endpoints import controllers

    ctrl = await _controller(db_session, site, "omada", "192.0.2.61")
    device = Device({"get_controller_status": lambda: {"state": "healthy"}})
    monkeypatch.setattr(adapter_registry, "create_adapter", lambda **_kw: device)
    return controllers.router, "/controllers", f"/controllers/{ctrl.id}/health", device


async def switch_stp(db_session, site, monkeypatch):
    from app.api.v1.endpoints import switches
    from app.models.devices import Device as DeviceRow

    ctrl = await _controller(db_session, site, "omada", "192.0.2.62")
    row = DeviceRow(
        name="sw1",
        site_id=site.id,
        controller_id=ctrl.id,
        device_type="switch",
        mac_address="aa:bb:cc:00:10:01",
        status="online",
    )
    db_session.add(row)
    await db_session.flush()
    device = Device({"get_switch_stp_config": lambda: {"mode": "rstp", "priority": 32768}})
    monkeypatch.setattr(switches, "get_adapter", lambda **_kw: device)
    return switches.router, "/switches", f"/switches/{row.id}/stp", device


async def mikrotik_dhcp(db_session, site, monkeypatch):
    from app.adapters.pool import adapter_pool
    from app.api.v1.endpoints import adapter_mikrotik_dhcp

    ctrl = await _controller(db_session, site, "mikrotik", "192.0.2.63")
    device = Device({"get_dhcp_servers": lambda: [{"name": "lan", "interface": "bridge"}]})

    async def shared(**_kw: Any) -> Device:
        return device

    monkeypatch.setattr(adapter_pool, "get_or_create_shared", shared)
    return (
        adapter_mikrotik_dhcp.router,
        "",
        f"/gateway-mikrotik-dhcp/{ctrl.id}/servers",
        device,
    )


async def proxmox_cluster(db_session, site, monkeypatch):
    from app.adapters.proxmox.models import ProxmoxClusterStatus
    from app.modules.hypervisor import api as hypervisor_api
    from app.modules.hypervisor import service as hypervisor_service

    ctrl = await _controller(db_session, site, "proxmox", "192.0.2.64")
    status = ProxmoxClusterStatus(name="lab", quorate=True, node_count=1, version=3)
    device = Device({"get_cluster_status": lambda: AdapterResult.ok(status)})
    monkeypatch.setattr(hypervisor_service, "ProxmoxAdapter", lambda **_kw: device)
    return (
        hypervisor_api.router,
        "/hypervisor",
        f"/hypervisor/controllers/{ctrl.id}/cluster/status",
        device,
    )


async def nvr_system_info(db_session, site, monkeypatch):
    from app.modules.cameras import api as cameras_api
    from app.modules.cameras.models import NVR
    from app.modules.cameras.service import NVRDiscoveryService

    nvr = NVR(
        site_id=site.id,
        organization_id=site.organization_id,
        name="nvr1",
        ip_address="192.0.2.65",
        port=80,
        vendor="hikvision",
        username="reader",
        password_encrypted=encrypt_credential("synthetic"),
    )
    db_session.add(nvr)
    await db_session.flush()
    device = Device({"get_full_system_info": lambda: {"model": "DS-7608", "uptime": 5}})
    monkeypatch.setattr(NVRDiscoveryService, "_create_adapter", staticmethod(lambda **_kw: device))
    return cameras_api.nvr_router, "", f"/nvrs/{nvr.id}/system-info", device


async def phone_live_status(db_session, site, monkeypatch):
    from app.adapters.grandstream import client as grandstream_client
    from app.modules.voip import api as voip_api
    from app.modules.voip.models import Phone

    phone = Phone(
        site_id=site.id,
        name="desk",
        ip_address="192.0.2.66",
        settings={"web_username": "admin", "web_password": encrypt_credential("synthetic")},
    )
    db_session.add(phone)
    await db_session.flush()
    device = Device({"_request": lambda: {"body": "available"}})
    monkeypatch.setattr(grandstream_client, "GrandstreamPhoneClient", lambda **_kw: device)
    return voip_api.phones_router, "", f"/phones/{phone.id}/live-status", device


PATHS = {
    "controller health": (controller_health, "host:192.0.2.61"),
    "switch STP": (switch_stp, "host:192.0.2.62"),
    "MikroTik DHCP": (mikrotik_dhcp, "host:192.0.2.63"),
    "Proxmox cluster": (proxmox_cluster, "host:192.0.2.64"),
    "NVR system info": (nvr_system_info, "host:192.0.2.65"),
    "phone live status": (phone_live_status, "host:192.0.2.66"),
}


def _hold(slot: str):
    lease = device_slots.try_acquire(slot, "background sync", ttl=60)
    assert lease is not None and lease.guarded, "the test needs real Valkey"
    return lease


@pytest.mark.parametrize("name", list(PATHS))
async def test_a_busy_device_with_nothing_remembered_is_not_contacted(
    name, world, db_session, monkeypatch, quick_waits
):
    setup, slot = PATHS[name]
    _org, site, user = world
    router, prefix, path, device = await setup(db_session, site, monkeypatch)
    held = _hold(slot)
    try:
        async with await _client(db_session, user, router, prefix) as client:
            response = await client.get(path)
    finally:
        device_slots.release(held)
    assert response.status_code == 503, response.text
    assert response.headers["retry-after"] == "5"
    error = response.json()["error"]
    assert error["type"] == "device_busy" and "background sync" in error["message"]
    assert device.calls == [], f"{name}: nothing may be sent to a device a poller holds"


@pytest.mark.parametrize("name", list(PATHS))
async def test_a_busy_device_is_answered_from_the_last_read(
    name, world, db_session, monkeypatch, quick_waits
):
    setup, slot = PATHS[name]
    _org, site, user = world
    router, prefix, path, device = await setup(db_session, site, monkeypatch)
    async with await _client(db_session, user, router, prefix) as client:
        live = await client.get(path)
        assert live.status_code == 200, live.text
        assert live.headers["x-freesdn-cached"] == "false"
        contacted = list(device.calls)
        assert contacted, f"{name}: the first read is live"
        held = _hold(slot)
        try:
            again = await client.get(path)
        finally:
            device_slots.release(held)
    assert again.status_code == 200, again.text
    assert device.calls == contacted, f"{name}: the busy device was contacted"
    assert again.headers["x-freesdn-cached"] == "true"
    assert again.headers["x-freesdn-cache-reason"] == "device_busy"
    assert again.headers["x-freesdn-as-of"] == live.headers["x-freesdn-as-of"]
    first, second = live.json(), again.json()
    if isinstance(first, dict):
        assert first["cached"] is False and second["cached"] is True
        assert second["as_of"] == first["as_of"]
        assert {
            k: v for k, v in second.items() if k not in ("as_of", "cached", "cache_reason")
        } == {k: v for k, v in first.items() if k not in ("as_of", "cached", "cache_reason")}
    else:
        assert second == first
