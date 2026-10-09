# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Stored Proxmox credentials reach actual client authentication on generic paths."""

from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest
from sqlalchemy import select, update

from app.adapters.proxmox import client as proxmox_client
from app.core.crypto import encrypt_credential
from app.db.session import CelerySessionLocal
from app.models.core import Controller
from app.models.devices import Device
from app.services import adapter_factory
from app.tasks import discovery
from tests.tasks.test_discovery_tenant_device_authority import inventory as inventory

SECRET = "owned-proxmox-synthetic-secret"
TOKEN = "owned@pve!monitor"


@pytest.fixture
def peer(monkeypatch):
    state = SimpleNamespace(requests=[], clients=[], realm="pve", token_mode=True)

    def respond(request):
        state.requests.append((request.method, request.url.path))
        if request.method == "POST":
            assert request.url.path == "/api2/json/access/ticket"
            body = parse_qs(request.content.decode())
            accepted = not state.token_mode and body == {
                "username": ["owned@" + state.realm],
                "password": [SECRET],
            }
            return httpx.Response(
                200 if accepted else 401,
                json={"data": {"ticket": "owned-ticket", "CSRFPreventionToken": "owned-csrf"}}
                if accepted
                else {"data": None},
            )
        assert request.method == "GET"
        accepted = (
            request.headers.get("Authorization") == f"PVEAPIToken={TOKEN}={SECRET}"
            if state.token_mode
            else "PVEAuthCookie=owned-ticket" in request.headers.get("Cookie", "")
        )
        if not accepted:
            return httpx.Response(403, json={"data": None})
        assert request.url.path in ["/api2/json/nodes", "/api2/json/cluster/status"]
        return httpx.Response(200, json={"data": [{"node": "owned-node", "status": "online"}]})

    def build(**kwargs):
        assert kwargs["verify"] is True
        client = httpx.AsyncClient(**kwargs, transport=httpx.MockTransport(respond))
        state.clients.append(client)
        return client

    monkeypatch.setattr(proxmox_client, "build_async_client", build)
    monkeypatch.setattr(proxmox_client, "_ticket_cache", proxmox_client._TicketCache())
    monkeypatch.setattr(proxmox_client, "_connection_cache", proxmox_client._ConnectionCache())
    monkeypatch.setattr(proxmox_client, "_reachability", proxmox_client._ReachabilityTracker())
    monkeypatch.setattr(discovery, "get_adapter", adapter_factory.get_adapter)
    return state


async def configure(fixture, mode, encrypted, *, realm="pve"):
    secret = encrypt_credential(SECRET) if encrypted else SECRET
    config = {"realm": realm}
    if mode.startswith("token"):
        config.update(token_id=TOKEN, token_secret=secret)
    if mode in ["password", "token-and-password"]:
        config.update(username="owned", password=secret)
    async with CelerySessionLocal() as db:
        await db.execute(
            update(Controller)
            .where(Controller.id == fixture.controller)
            .values(
                controller_type="proxmox",
                host="192.168.254.254",
                port=8006,
                use_ssl=True,
                verify_ssl=True,
                config=config,
            )
        )
        await db.commit()


async def exercise(fixture, path):
    if path == "factory":
        async with CelerySessionLocal() as db:
            row = await db.get(Controller, fixture.controller)
            adapter = adapter_factory.build_adapter_for_controller(row)
        try:
            result = await adapter.test_connection()
            return result.success
        finally:
            await adapter.disconnect()
    result = await discovery._discover_devices_for_controller_impl(str(fixture.controller))
    async with CelerySessionLocal() as db:
        row = await db.get(Controller, fixture.controller)
        if result["success"]:
            assert row.status == "connected" and row.last_error is None
        # Generic network inventory must not take ownership of hypervisor nodes.
        assert (
            await db.scalar(select(Device.id).where(Device.controller_id == fixture.controller))
            is None
        )
    return result["success"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["factory", "discovery"])
@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("mode", ["token", "password", "token-and-password"])
async def test_stored_credentials_authenticate_on_generic_paths(
    inventory, peer, path, encrypted, mode
):
    peer.token_mode = mode != "password"
    await configure(inventory, mode, encrypted)
    assert await exercise(inventory, path)
    assert peer.clients and all(client.is_closed for client in peer.clients)
    assert any(method == "GET" for method, _ in peer.requests)
    assert any(method == "POST" for method, _ in peer.requests) is (mode == "password")
    if path == "discovery":
        discovery.deep_sync_controller.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["factory", "discovery"])
async def test_default_pam_password_authentication_control(inventory, peer, path):
    peer.token_mode = False
    peer.realm = "pam"
    await configure(inventory, "password", True, realm="pam")
    async with CelerySessionLocal() as db:
        row = await db.get(Controller, inventory.controller)
        row.config = {k: v for k, v in row.config.items() if k != "realm"}
        await db.commit()
    assert await exercise(inventory, path)
    assert peer.clients and all(client.is_closed for client in peer.clients)


@pytest.mark.asyncio
async def test_factory_rejects_wrong_api_key_control(inventory, peer):
    await configure(inventory, "token", True)
    async with CelerySessionLocal() as db:
        row = await db.get(Controller, inventory.controller)
        row.config = {**row.config, "token_secret": encrypt_credential("owned-wrong-key")}
        await db.commit()
    assert not await exercise(inventory, "factory")
    assert peer.clients and all(client.is_closed for client in peer.clients)
