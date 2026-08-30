# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
``BaseModule.get_event_handlers()`` shipped with zero call sites
==================================================================

Every module could declare a map of {event pattern -> coroutine} and two of
them did (``GatewayModule`` and ``FirewallModule``, both returning
``app.modules.gateway.events.handlers.get_handlers()``), but nothing in the
tree ever read that map.  ``grep -rn '\\.subscribe(' app/`` listed the WS
forwarder, the Fabric runtime, the automation engine and the plugin SDK --
and no module-loader entry.  So the gateway's cross-module reactions never
ran: a VLAN deleted in the network module raised no drift event, and a
finished gateway sync never scheduled the drift check its own publisher
comment promises.

Two further defects only became visible once the handlers were live: both
``_on_network_vlan_created`` and ``_on_device_status_changed`` read payload
keys that their publishers have never sent, so subscribing them alone would
have produced two handlers that log and return.  Those payload shapes are
pinned here against the real publishers.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from app.core.events import Event, EventBus, EventCategory
from app.modules.base import BaseModule
from app.modules.manifest import ModuleManifest
from app.modules.registry import ModuleRegistry

# ── Test doubles ────────────────────────────────────────────────────────────


async def _handler_a(event: Event) -> None:  # pragma: no cover - identity only
    return None


async def _handler_b(event: Event) -> None:  # pragma: no cover - identity only
    return None


class _StubModule(BaseModule):
    """A module that declares two event handlers."""

    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(
            id="stub",
            name="Stub",
            version="1.0.0",
            description="test double",
        )

    def get_router(self):  # type: ignore[no-untyped-def]
        return None

    def get_event_handlers(self):  # type: ignore[no-untyped-def]
        return {"network.vlan.deleted": _handler_a, "gateway.sync.completed": _handler_b}


class _ExplodingModule(_StubModule):
    """A module whose handler map raises -- must not abort its siblings."""

    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(
            id="boom",
            name="Boom",
            version="1.0.0",
            description="test double",
        )

    def get_event_handlers(self):  # type: ignore[no-untyped-def]
        raise RuntimeError("handler map unavailable")


@pytest.fixture
def bus(monkeypatch: pytest.MonkeyPatch) -> EventBus:
    """A private EventBus swapped in for the process-global singleton."""
    import app.core.events as events_mod

    fresh = EventBus(redis_url=None)
    monkeypatch.setattr(events_mod, "_event_bus", fresh)
    return fresh


def _loader_with(*modules: BaseModule):  # type: ignore[no-untyped-def]
    from app.modules.loader import ModuleLoader

    registry = ModuleRegistry()
    for module in modules:
        registry.register(module)
    return ModuleLoader(registry=registry)


def _patterns(bus: EventBus) -> dict[str, list[str]]:
    return {
        pattern: [getattr(sub.handler, "__name__", "?") for sub in subs]
        for pattern, subs in bus._subscriptions.items()
        if subs
    }


# ── 1. the wiring itself ────────────────────────────────────────────────────


def test_loader_subscribes_module_event_handlers(bus: EventBus) -> None:
    """The map a module returns must reach the bus."""
    loader = _loader_with(_StubModule())

    ids = loader.subscribe_event_handlers()

    assert len(ids) == 2
    assert _patterns(bus) == {
        "network.vlan.deleted": ["_handler_a"],
        "gateway.sync.completed": ["_handler_b"],
    }


def test_register_routes_subscribes_too(bus: EventBus) -> None:
    """``register_routes`` is the API-process-only entry point the
    subscription hangs off, so the live app wires handlers without any
    change to main.py."""
    from fastapi import FastAPI

    loader = _loader_with(_StubModule())
    loader.register_routes(FastAPI())

    assert "network.vlan.deleted" in _patterns(bus)


def test_subscribing_twice_does_not_double_fire(bus: EventBus) -> None:
    """A second loader in the same process (``scripts/export_openapi.py``
    builds its own) must not register the same handler again -- a duplicate
    subscription runs the handler twice per event, which for
    ``gateway.sync.completed`` means two ``check_site_drift`` jobs and two
    sets of drift rows."""
    _loader_with(_StubModule()).subscribe_event_handlers()
    second = _loader_with(_StubModule()).subscribe_event_handlers()

    assert second == []
    assert _patterns(bus) == {
        "network.vlan.deleted": ["_handler_a"],
        "gateway.sync.completed": ["_handler_b"],
    }


def test_one_broken_module_does_not_starve_the_rest(bus: EventBus) -> None:
    loader = _loader_with(_ExplodingModule(), _StubModule())

    ids = loader.subscribe_event_handlers()

    assert len(ids) == 2
    assert "gateway.sync.completed" in _patterns(bus)


def test_the_firewall_module_really_declares_the_gateway_handlers() -> None:
    """The production wiring this all exists for. ``gateway`` is in
    ``EXCLUDED_MODULES`` so it never reaches the registry; FirewallModule is
    the module that actually carries the gateway handler map, which is also
    why subscribing the registry cannot double-register them."""
    from app.modules.firewall.module import FirewallModule
    from app.modules.loader import EXCLUDED_MODULES

    assert "gateway" in EXCLUDED_MODULES

    handlers = FirewallModule().get_event_handlers()
    assert set(handlers) == {
        "network.vlan.created",
        "network.vlan.updated",
        "network.vlan.deleted",
        "network.wifi.#",
        "device.status.changed",
        "gateway.sync.completed",
    }


# ── 2. the payload contracts the live handlers depend on ────────────────────


class _FakeResult:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one_or_none(self) -> Any:
        return self._value


class _FakeSession:
    """Minimal stand-in for the fresh AsyncSession the handlers open."""

    def __init__(self, results: list[Any], gets: dict[str, Any]) -> None:
        self._results = list(results)
        self._gets = gets
        self.added: list[Any] = []
        self.committed = False
        self.executed = 0

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def execute(self, _stmt: Any) -> _FakeResult:
        self.executed += 1
        return _FakeResult(self._results.pop(0) if self._results else None)

    async def get(self, model: Any, _pk: Any) -> Any:
        return self._gets.get(model.__name__)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.committed = True


class _Row:
    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)


async def test_vlan_created_handles_the_payload_the_publisher_actually_sends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``VlanService.create`` (app/modules/network/service.py:312) emits
    {vlan_id, vlan_uuid, name, site_id, dhcp_enabled} -- no organization_id,
    no subnet, no gateway_ip.  The handler used to require all three off the
    payload and bailed at its first guard on every real event.
    """
    from app.modules.gateway.events import handlers as gw
    from app.modules.gateway.models import ManagementState

    site_id = uuid4()
    org_id = uuid4()
    vlan_uuid = uuid4()

    session = _FakeSession(
        results=[_Row(id=uuid4()), None],  # SiteRoleMap exists; no CanonicalVLAN yet
        gets={
            "Network": _Row(
                cidr="10.20.0.0/24", subnet="10.20.0.0", gateway="10.20.0.1", name="Lab"
            ),
            "Site": _Row(organization_id=org_id),
        },
    )
    monkeypatch.setattr(gw, "_get_session", lambda: _returns(session))

    await gw._on_network_vlan_created(
        Event(
            event_type="network.vlan.created",
            category=EventCategory.SYSTEM,
            payload={
                "vlan_id": 20,
                "vlan_uuid": str(vlan_uuid),
                "name": "Lab",
                "site_id": str(site_id),
                "dhcp_enabled": True,
            },
        )
    )

    assert session.committed, "no canonical VLAN was created"
    (created,) = session.added
    assert created.vlan_id == 20
    assert created.site_id == site_id
    assert created.organization_id == org_id
    assert created.subnet == "10.20.0.0/24"
    assert created.gateway_ip == "10.20.0.1"
    # MONITORED carries no write authority: drift_service selects MANAGED only.
    assert created.management_state == ManagementState.MONITORED


async def test_vlan_created_still_skips_a_site_without_gateway_orchestration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.modules.gateway.events import handlers as gw

    session = _FakeSession(results=[None], gets={})
    monkeypatch.setattr(gw, "_get_session", lambda: _returns(session))

    await gw._on_network_vlan_created(
        Event(
            event_type="network.vlan.created",
            category=EventCategory.SYSTEM,
            payload={"vlan_id": 20, "site_id": str(uuid4()), "vlan_uuid": str(uuid4())},
        )
    )

    assert not session.added
    assert not session.committed


async def test_device_status_changed_reads_the_nested_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``publish_device_event`` nests the transition under ``data``; all four
    publishers (app/tasks/sync.py:123/152/316/444) pass
    ``data={"name", "old_status", "new_status"}``.  The handler read a flat
    ``payload["status"]`` that no publisher sets, so it returned before ever
    opening a session and the brain-offline alert could not fire.
    """
    from app.modules.gateway.events import handlers as gw

    session = _FakeSession(results=[None], gets={})
    monkeypatch.setattr(gw, "_get_session", lambda: _returns(session))

    await gw._on_device_status_changed(
        Event(
            event_type="device.status.changed",
            category=EventCategory.DEVICE,
            payload={
                "device_id": str(uuid4()),
                "site_id": str(uuid4()),
                "data": {"name": "brain", "old_status": "online", "new_status": "offline"},
            },
        )
    )

    assert session.executed == 1, "handler never looked for a brain assignment"


async def test_device_status_changed_ignores_an_online_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.modules.gateway.events import handlers as gw

    session = _FakeSession(results=[None], gets={})
    monkeypatch.setattr(gw, "_get_session", lambda: _returns(session))

    await gw._on_device_status_changed(
        Event(
            event_type="device.status.changed",
            category=EventCategory.DEVICE,
            payload={
                "device_id": str(uuid4()),
                "data": {"old_status": "offline", "new_status": "online"},
            },
        )
    )

    assert session.executed == 0


async def _returns(value: Any) -> Any:
    return value


# ── 3. a model import that never resolved ───────────────────────────────────


async def test_controller_vlan_lookup_can_import_its_model() -> None:
    """``ReconciliationService._get_controller_vlans`` opened with
    ``from app.models.network import VLAN`` -- a module that has never existed
    in the tree (the network module's VLAN model is
    ``app.modules.network.models.Network``). The import is the first statement
    in the method, so it raised ModuleNotFoundError before touching the DB;
    the caller at reconciliation_service.py:399 catches Exception and files
    ``status="error"``, so every CONTROLLER limb in a reconciliation preview
    reported an adapter failure it never had.

    Reaching the "controller not found" error proves the import resolved.
    """
    from app.modules.gateway.services.reconciliation_service import (
        ReconciliationError,
        ReconciliationService,
    )

    class _NoRows:
        async def get(self, _model: Any, _pk: Any) -> Any:
            return None

    service = ReconciliationService(db=_NoRows())  # type: ignore[arg-type]

    with pytest.raises(ReconciliationError, match="not found"):
        await service._get_controller_vlans(uuid4())
