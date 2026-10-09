# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Authentication reuse must preserve credentials, destination and selected mechanism."""

import json
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest

from app.adapters.proxmox import client as module
from app.services.device_reach import AgentHTTPTransport

PASSWORD = "owned-cache-valid-password"
TICKET = "owned-cache-private-ticket"


def config(**kwargs):
    return module.ProxmoxClientConfig(
        host="192.168.254.254",
        username="owned",
        password=PASSWORD,
        verify_ssl=True,
        **kwargs,
    )


@pytest.fixture
def peer(monkeypatch):
    state = SimpleNamespace(requests=[], clients=[], reject_cookie_once=False, logins=0)

    def respond(request):
        state.requests.append(request)
        if request.method == "POST":
            assert request.url.path == "/api2/json/access/ticket"
            accepted = parse_qs(request.content.decode()) == {
                "username": ["owned@pam"],
                "password": [PASSWORD],
            }
            state.logins += 1
            return httpx.Response(
                200 if accepted else 401,
                json={
                    "data": {"ticket": TICKET, "CSRFPreventionToken": "owned-csrf"}
                    if accepted
                    else None,
                },
            )
        assert request.method == "GET" and request.url.path == "/api2/json/nodes"
        accepted = f"PVEAuthCookie={TICKET}" in request.headers.get("cookie", "")
        if state.reject_cookie_once and accepted:
            state.reject_cookie_once = False
            accepted = False
        return httpx.Response(200 if accepted else 401, json={"data": []})

    def build(**kwargs):
        client = httpx.AsyncClient(
            **kwargs,
            **({} if "transport" in kwargs else {"transport": httpx.MockTransport(respond)}),
        )
        state.clients.append(client)
        return client

    monkeypatch.setattr(module, "build_async_client", build)
    monkeypatch.setattr(module, "_ticket_cache", module._TicketCache())
    monkeypatch.setattr(module, "_connection_cache", module._ConnectionCache())
    monkeypatch.setattr(module, "_reachability", module._ReachabilityTracker())
    return state


async def warm():
    client = module.ProxmoxClient(config())
    async with client:
        assert await client.get("/nodes") == []


@pytest.mark.asyncio
async def test_changed_password_cannot_authenticate_using_cached_ticket(peer):
    await warm()
    changed = module.ProxmoxClient(replace(config(), password="owned-invalid-password"))
    try:
        with pytest.raises(module.ProxmoxApiError):
            await changed.connect()
            await changed.get("/nodes")
        assert peer.logins == 2
    finally:
        await changed.close()
    assert all(client.is_closed for client in peer.clients)


@pytest.mark.asyncio
@pytest.mark.parametrize("setting", ["HTTPS_PROXY", "SSL_CERT_FILE", "overlay"])
async def test_direct_routing_or_trust_change_requires_fresh_authentication(
    peer, monkeypatch, setting
):
    await warm()
    if setting == "overlay":
        monkeypatch.setattr(
            "app.core.http_client.overlay_socks_proxy", lambda: "socks5://owned-proxy.invalid:1080"
        )
    else:
        monkeypatch.setenv(setting, "owned-changed-route-or-trust")
    await warm()
    assert peer.logins == 2


@pytest.mark.asyncio
async def test_changed_live_client_configuration_is_not_reused_as_old_identity(peer):
    client = module.ProxmoxClient(config())
    try:
        await client.connect()
        client.config.password = "owned-changed-password"
        assert (
            module.ProxmoxClient.get_cached(
                "192.168.254.254", username="owned", password=PASSWORD, verify_ssl=True
            )
            is None
        )
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"password": "owned-invalid-password"},
        {"realm": "other-realm"},
        {"token_id": "owned@pam!other", "token_secret": "owned-other-token"},
        {"verify_ssl": False},
        {"use_ssl": False},
        {"port": 8007},
    ],
)
async def test_live_cache_does_not_return_other_authentication_context(peer, changes):
    client = module.ProxmoxClient(config())
    try:
        await client.connect()
        args = {"username": "owned", "password": PASSWORD, "verify_ssl": True, **changes}
        assert module.ProxmoxClient.get_cached("192.168.254.254", **args) is None
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_matching_direct_context_can_reuse_ticket_and_live_client(peer):
    first = module.ProxmoxClient(config())
    try:
        await first.connect()
        assert (
            module.ProxmoxClient.get_cached(
                "192.168.254.254", username="owned", password=PASSWORD, verify_ssl=True
            )
            is first
        )
    finally:
        await first.close()
    await warm()
    assert peer.logins == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["verify_ssl", "use_ssl", "realm"])
async def test_ticket_cache_does_not_cross_endpoint_authentication_settings(peer, changed):
    await warm()
    values = {"verify_ssl": False, "use_ssl": False, "realm": "other-realm"}
    second = module.ProxmoxClient(replace(config(), **{changed: values[changed]}))
    try:
        try:
            await second.connect()
        except module.ProxmoxApiError:
            pass
        assert peer.logins == 2
    finally:
        await second.close()


@pytest.mark.asyncio
async def test_older_live_client_close_preserves_newer_cached_client(peer):
    first, second = module.ProxmoxClient(config()), module.ProxmoxClient(config())
    try:
        await first.connect()
        await second.connect()
        await first.close()
        assert (
            module.ProxmoxClient.get_cached(
                "192.168.254.254", username="owned", password=PASSWORD, verify_ssl=True
            )
            is second
        )
    finally:
        await first.close()
        await second.close()


@pytest.mark.asyncio
async def test_rejected_token_never_switches_to_password_login(peer):
    client = module.ProxmoxClient(config(token_id="owned@pam!revoked", token_secret="owned-bad"))
    try:
        await client.connect()
        with pytest.raises(module.ProxmoxApiError):
            await client.get("/nodes")
        assert peer.logins == 0
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "partial", [{"token_id": "owned@pam!token"}, {"token_secret": "owned-token"}]
)
async def test_incomplete_token_configuration_does_not_fall_back_to_password(peer, partial):
    client = module.ProxmoxClient(config(**partial))
    try:
        with pytest.raises(module.ProxmoxApiError):
            await client.connect()
        assert peer.logins == 0
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_password_401_still_reauthenticates_once(peer):
    client = module.ProxmoxClient(config())
    try:
        await client.connect()
        peer.reject_cookie_once = True
        assert await client.get("/nodes") == []
        assert peer.logins == 2
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["agent-agent", "direct-agent", "agent-direct"])
async def test_agent_routing_never_receives_another_destinations_ticket(peer, direction):
    a, b = uuid4(), uuid4()
    seen = {a: [], b: []}

    class Registry:
        async def proxy_http_via_site(self, site_id, **kwargs):
            seen[site_id].append(kwargs)
            body = (
                {"data": {"ticket": f"owned-{site_id}-ticket", "CSRFPreventionToken": "owned-csrf"}}
                if kwargs["method"] == "POST"
                else {"data": []}
            )
            return SimpleNamespace(
                success=True,
                result={
                    "status_code": 200,
                    "headers": {},
                    "body": json.dumps(body),
                },
            )

    registry = Registry()
    first_transport = (
        None if direction == "direct-agent" else AgentHTTPTransport(registry, a, verify_ssl=True)
    )
    second_transport = (
        None if direction == "agent-direct" else AgentHTTPTransport(registry, b, verify_ssl=True)
    )
    first = module.ProxmoxClient(config(), transport=first_transport)
    second = module.ProxmoxClient(config(), transport=second_transport)
    async with first:
        assert await first.get("/nodes") == []
    async with second:
        assert await second.get("/nodes") == []
    if second_transport is None:
        assert peer.logins == 1
        assert all(
            f"owned-{a}-ticket" not in request.headers.get("cookie", "")
            for request in peer.requests
        )
    else:
        assert seen[b][0]["method"] == "POST"
        assert all(
            f"owned-{a}-ticket" not in call["headers"].get("cookie", "")
            and TICKET not in call["headers"].get("cookie", "")
            for call in seen[b]
        )
    assert all(client.is_closed for client in peer.clients)
