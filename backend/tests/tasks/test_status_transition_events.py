# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""State transitions that matter to an operator raise an event, with a tenant.

Three transitions changed a column and told nobody:

* discovery (every 5 min, where a controller-managed device's status is
  refreshed) published ``device.updated`` for every device on every run and
  never ``device.status.changed``, the event alert automations, webhooks and the
  n8n trigger default to;
* ``sync.check_controller_health`` flipped a controller to UNREACHABLE and back
  silently;
* a failed gateway sync published nothing, and the successful one published
  without an organization, so the fail-closed WebSocket and webhook routing
  dropped it.

Real PostgreSQL (rolled back), adapters replaced, the bus calls observed.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

import app.tasks.discovery as discovery
import app.tasks.sync as sync_tasks
from app.adapters.base import DiscoveredDevice
from app.core.crypto import encrypt_dict
from app.models.core import Controller, ControllerStatus, Organization, Site
from app.modules.firewall.models import GatewayConnection
from app.modules.gateway.services import sync_service
from app.modules.gateway.services.sync_service import SyncService


async def _org_site(db):
    org = Organization(name="Transitions", slug="tr-" + uuid4().hex)
    db.add(org)
    await db.flush()
    site = Site(name="site", slug="tr-" + uuid4().hex, organization_id=org.id)
    db.add(site)
    await db.flush()
    return org, site


class _Ctx:
    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *_exc):
        return False


# --------------------------------------------------------------------------
# Discovery: device online <-> offline
# --------------------------------------------------------------------------


def _dev(mac, status):
    return DiscoveredDevice(
        mac_address=mac,
        ip_address="10.0.0.11",
        name="AP-" + mac[-2:],
        vendor="TP-Link",
        model="EAP670",
        firmware_version="1.0.0",
        device_type="access_point",
        status=status,
    )


class _DiscoveryAdapter:
    statuses: dict[str, str] = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def discover_devices(self):
        return [_dev(mac, status) for mac, status in type(self).statuses.items()]


async def test_discovery_announces_a_device_going_offline_and_coming_back(db_session, monkeypatch):
    org, site = await _org_site(db_session)
    ctrl = Controller(
        name="omada",
        controller_type="omada",
        host="10.0.0.1",
        port=8043,
        site_id=site.id,
        is_active=True,
        sync_enabled=True,
        config={},
    )
    db_session.add(ctrl)
    await db_session.flush()

    published: list[tuple[str, dict]] = []

    async def _capture(event_type, **kwargs):
        published.append((str(event_type), kwargs))

    async def _noop(*_a, **_k):
        return {}

    monkeypatch.setattr(
        discovery, "build_adapter_for_controller", lambda *_a, **_k: _DiscoveryAdapter()
    )
    monkeypatch.setattr(discovery, "AsyncSessionLocal", lambda: _Ctx(db_session))
    monkeypatch.setattr(db_session, "commit", db_session.flush)
    monkeypatch.setattr(discovery, "publish_controller_event", _noop)
    monkeypatch.setattr(discovery, "publish_device_event", _capture)
    monkeypatch.setattr(discovery, "deep_sync_controller", _noop)
    from app.services.ztp import ZTPEngine

    async def _ztp(self, device, session):
        return None

    monkeypatch.setattr(ZTPEngine, "evaluate_device", _ztp)

    def changes():
        return [kw for name, kw in published if name == "device.status.changed"]

    _DiscoveryAdapter.statuses = {"AA:BB:CC:00:00:01": "online", "AA:BB:CC:00:00:02": "online"}
    await discovery._discover_devices_for_controller_impl(str(ctrl.id))
    assert changes() == []  # creation is device.discovered, not a status change

    published.clear()
    _DiscoveryAdapter.statuses["AA:BB:CC:00:00:02"] = "offline"
    await discovery._discover_devices_for_controller_impl(str(ctrl.id))
    [change] = changes()
    assert change["data"]["old_status"] == "online"
    assert change["data"]["new_status"] == "offline"
    assert change["organization_id"] == str(org.id)
    assert change["site_id"] == str(site.id)

    published.clear()
    await discovery._discover_devices_for_controller_impl(str(ctrl.id))
    assert changes() == []  # still offline: no repeat

    published.clear()
    _DiscoveryAdapter.statuses["AA:BB:CC:00:00:02"] = "online"
    await discovery._discover_devices_for_controller_impl(str(ctrl.id))
    [back] = changes()
    assert (back["data"]["old_status"], back["data"]["new_status"]) == ("offline", "online")


# --------------------------------------------------------------------------
# Controller reachability
# --------------------------------------------------------------------------


class _ProbeAdapter:
    failing: set[str] = set()

    def __init__(self, host):
        self.host = host

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    # The health check probes with connect() (a login), not a device listing.
    async def connect(self):
        if self.host in type(self).failing:
            raise ConnectionError("connect timeout to https://secret-host.example/api")
        return True

    async def disconnect(self):
        return None


async def test_controller_reachability_transitions_are_announced_once(db_session, monkeypatch):
    org, site = await _org_site(db_session)
    rows = {}
    for key, status in (
        ("recovers", ControllerStatus.UNREACHABLE),
        ("drops", ControllerStatus.CONNECTED),
        ("steady", ControllerStatus.CONNECTED),
        ("still_down", ControllerStatus.UNREACHABLE),
    ):
        ctrl = Controller(
            name=key,
            controller_type="omada",
            host=f"{key}.example.test",
            port=8043,
            site_id=site.id,
            is_active=True,
            sync_enabled=True,
            config={},
            status=status,
        )
        db_session.add(ctrl)
        rows[key] = ctrl
    await db_session.flush()

    _ProbeAdapter.failing = {"drops.example.test", "still_down.example.test"}
    published: list[tuple[str, dict]] = []

    async def _capture(event_type, **kwargs):
        published.append((str(event_type), kwargs))

    monkeypatch.setattr(sync_tasks, "AsyncSessionLocal", lambda: _Ctx(db_session))
    monkeypatch.setattr(db_session, "commit", db_session.flush)
    import app.services.adapter_factory as factory

    monkeypatch.setattr(factory, "build_adapter_for_controller", lambda c: _ProbeAdapter(c.host))
    monkeypatch.setattr(sync_tasks, "publish_controller_event", _capture)

    await sync_tasks._check_controller_health()

    mine = {str(c.id): key for key, c in rows.items()}
    seen = {
        (mine[kw["controller_id"]], name) for name, kw in published if kw["controller_id"] in mine
    }
    assert seen == {("recovers", "controller.recovered"), ("drops", "controller.unreachable")}
    for name, kw in published:
        if kw["controller_id"] in mine:
            assert kw["organization_id"] == str(org.id)
            if name == "controller.unreachable":
                # The class name, not the message (which carried a URL).
                assert kw["error"] == "ConnectionError"

    published.clear()
    await sync_tasks._check_controller_health()
    assert not [kw for _, kw in published if kw["controller_id"] in mine]


# --------------------------------------------------------------------------
# Gateway sync outcome
# --------------------------------------------------------------------------


class _BrokenGateway:
    async def __aenter__(self):
        raise TimeoutError("read timeout from https://opnsense.example.test/api")

    async def __aexit__(self, *_exc):
        return False


@pytest.fixture
def bus_events(monkeypatch):
    events: list = []

    class _Bus:
        async def publish(self, event):
            events.append(event)

    monkeypatch.setattr(sync_service, "get_event_bus", lambda: _Bus())
    return events


async def test_a_failed_gateway_sync_is_announced_with_its_tenant(
    db_session, monkeypatch, bus_events
):
    org, site = await _org_site(db_session)
    gw = GatewayConnection(
        org_id=org.id,
        site_id=site.id,
        name="opnsense",
        vendor="opnsense",
        host="opnsense.example.test",
        credentials=encrypt_dict({"api_key": "k"}),
        settings={},
    )
    db_session.add(gw)
    await db_session.flush()
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: _BrokenGateway())

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert result["status"] == "failed"
    [event] = bus_events
    assert event.event_type == "gateway.sync.failed"
    assert event.organization_id == str(org.id)
    assert event.payload == {
        "gateway_id": str(gw.id),
        "site_id": str(site.id),
        "error": "TimeoutError",
    }


async def test_a_completed_gateway_sync_carries_its_tenant(db_session, monkeypatch, bus_events):
    org, site = await _org_site(db_session)
    gw = GatewayConnection(
        org_id=org.id,
        site_id=site.id,
        name="opnsense",
        vendor="opnsense",
        host="opnsense.example.test",
        credentials=encrypt_dict({"api_key": "k"}),
        settings={},
    )
    db_session.add(gw)
    await db_session.flush()

    empty = SimpleNamespace(success=True, data={})

    class _Quiet:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

        def __getattr__(self, _name):
            async def _read(*_a, **_k):
                return empty

            return _read

    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: _Quiet())

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert result["status"] == "success"
    [event] = [e for e in bus_events if e.event_type == "gateway.sync.completed"]
    assert event.organization_id == str(org.id)


def test_the_new_events_are_named_where_integrations_and_plugins_look():
    from app.api.v1.endpoints.integrations import EVENT_CATEGORIES
    from app.core.events import EventType

    offered = {name for names in EVENT_CATEGORIES.values() for name in names}
    for name in (
        "controller.unreachable",
        "controller.recovered",
        "gateway.sync.completed",
        "gateway.sync.failed",
    ):
        assert name in offered
        assert name in {e.value for e in EventType}
