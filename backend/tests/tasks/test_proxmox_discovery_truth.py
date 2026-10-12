# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Failed Proxmox inventory reads must not become successful empty discovery."""

import logging
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from app.adapters.exceptions import AdapterConnectionError
from app.adapters.proxmox import client as client_module
from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.core.events import EventType
from app.db.session import CelerySessionLocal
from app.models.core import Controller
from app.models.devices import Device
from app.services import adapter_factory
from app.tasks import discovery
from tests.tasks.test_discovery_tenant_device_authority import inventory as inventory
from tests.tasks.test_proxmox_controller_auth import configure

PRIVATE = "owned-provider-internal-value-do-not-publish"
BAD = [
    "http401",
    "http403",
    "http500",
    "invalid-json",
    "missing-data",
    "null",
    "object",
    "text",
    "number",
    "missing-node",
    "empty-node",
    "numeric-node",
    "duplicate-node",
    "non-object-node",
]


def data_for(mode):
    return {
        "null": None,
        "object": {"detail": PRIVATE},
        "text": PRIVATE,
        "number": 123,
        "missing-node": [{}],
        "empty-node": [{"node": "  "}],
        "numeric-node": [{"node": 123}],
        "duplicate-node": [{"node": "owned"}, {"node": "owned"}],
        "non-object-node": [None],
        "empty": [],
        "one": [{"node": "owned", "status": "online"}],
        "optional-fields": [{"node": "owned"}],
        "offline": [{"node": "owned", "status": "offline"}],
    }.get(mode)


@pytest.fixture
def peer(monkeypatch):
    state = SimpleNamespace(mode="one", clients=[], requests=[])

    def respond(request):
        assert request.method == "GET" and request.url.path == "/api2/json/nodes"
        state.requests.append(request)
        if state.mode.startswith("http"):
            return httpx.Response(int(state.mode[4:]), json={"errors": {"detail": PRIVATE}})
        if state.mode == "invalid-json":
            return httpx.Response(200, text=PRIVATE)
        if state.mode == "missing-data":
            return httpx.Response(200, json={"detail": PRIVATE})
        return httpx.Response(200, json={"data": data_for(state.mode)})

    def build(**kwargs):
        client = httpx.AsyncClient(**kwargs, transport=httpx.MockTransport(respond))
        state.clients.append(client)
        return client

    monkeypatch.setattr(client_module, "build_async_client", build)
    monkeypatch.setattr(client_module, "_ticket_cache", client_module._TicketCache())
    monkeypatch.setattr(client_module, "_connection_cache", client_module._ConnectionCache())
    monkeypatch.setattr(client_module, "_reachability", client_module._ReachabilityTracker())
    monkeypatch.setattr(
        discovery, "build_adapter_for_controller", adapter_factory.build_adapter_for_controller
    )
    return state


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", BAD)
async def test_adapter_rejects_unreadable_node_inventory_without_raw_diagnostics(
    peer, caplog, mode
):
    peer.mode = mode
    adapter = ProxmoxAdapter(
        host="192.168.254.254", token_id="owned@pve!monitor", token_secret="owned"
    )
    with caplog.at_level(logging.ERROR):
        with pytest.raises(AdapterConnectionError) as raised:
            async with adapter:
                await adapter.discover_devices()
    assert PRIVATE not in str(raised.value)
    assert PRIVATE not in caplog.text
    assert peer.requests and all(c.is_closed for c in peer.clients)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", BAD)
async def test_failed_inventory_commits_failure_and_never_starts_deep_sync(inventory, peer, mode):
    await configure(inventory, "token", True)
    peer.mode = mode
    result = await discovery._discover_devices_for_controller_impl(str(inventory.controller))
    assert result["success"] is False
    assert result["error"] == "Discovery failed; verify controller connectivity and configuration."
    async with CelerySessionLocal() as observer:
        row = await observer.get(Controller, inventory.controller)
        assert row.status == "error" and row.last_error == result["error"]
        assert row.config["error_history"][0]["error"] == result["error"]
        assert (
            await observer.scalar(select(Device.id).where(Device.controller_id == row.id)) is None
        )
    events = [call.args[0] for call in discovery.publish_controller_event.await_args_list]
    assert EventType.CONTROLLER_SYNC_FAILED in events
    assert EventType.CONTROLLER_SYNC_COMPLETED not in events
    discovery.deep_sync_controller.assert_not_awaited()
    assert all(c.is_closed for c in peer.clients)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["empty", "one", "optional-fields", "offline"])
@pytest.mark.parametrize("path", ["adapter", "discovery"])
async def test_valid_empty_and_node_inventory_remain_success_controls(inventory, peer, mode, path):
    peer.mode = mode
    if path == "adapter":
        adapter = ProxmoxAdapter(
            host="192.168.254.254", token_id="owned@pve!monitor", token_secret="owned"
        )
        async with adapter:
            devices = await adapter.discover_devices()
        assert len(devices) == (0 if mode == "empty" else 1)
        if devices:
            assert devices[0].name == "owned" and devices[0].device_type == "hypervisor"
            assert devices[0].status == ("online" if mode == "one" else "offline")
    else:
        await configure(inventory, "token", True)
        result = await discovery._discover_devices_for_controller_impl(str(inventory.controller))
        assert result["success"] is True
        async with CelerySessionLocal() as observer:
            row = await observer.get(Controller, inventory.controller)
            assert row.status == "connected" and row.last_error is None
            assert (
                await observer.scalar(select(Device.id).where(Device.controller_id == row.id))
                is None
            )
        discovery.deep_sync_controller.assert_awaited_once()
    assert all(c.is_closed for c in peer.clients)
