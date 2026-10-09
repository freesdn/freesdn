# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Incomplete Proxmox logins cannot retain pools or reusable authentication state."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio

from app.adapters.proxmox import client as module

MARKER = "owned-private-authentication-diagnostic"
TICKET = "owned-valid-ticket"
INVALID = [
    "invalid-json",
    None,
    [],
    "owned-envelope",
    {"data": None},
    {"data": []},
    {"data": "owned-data"},
    {"data": {}},
    {"data": {"ticket": ""}},
    {"data": {"ticket": " "}},
    {"data": {"ticket": True}},
    {"data": {"ticket": 123}},
    {"data": {"ticket": []}},
    {"data": {"ticket": "owned\r\ninjected"}},
    {"data": {"ticket": TICKET, "CSRFPreventionToken": 1}},
    {"data": {"ticket": TICKET, "CSRFPreventionToken": []}},
    {"data": {"ticket": TICKET, "CSRFPreventionToken": "owned\r\ninjected"}},
]


@pytest_asyncio.fixture
async def peer(monkeypatch):
    f = SimpleNamespace(
        body={"data": {"ticket": TICKET, "CSRFPreventionToken": "owned-csrf"}},
        error=None,
        wait=None,
        requests=[],
        clients=[],
        closers=[],
        entered=asyncio.Event(),
    )

    async def respond(request):
        assert request.url.path == "/api2/json/access/ticket" and request.method == "POST"
        f.requests.append(request)
        f.entered.set()
        if f.wait is not None:
            await f.wait.wait()
        if f.error is not None:
            raise f.error(MARKER)
        return (
            httpx.Response(200, content=b"owned-invalid-json")
            if f.body == "invalid-json"
            else httpx.Response(200, json=f.body)
        )

    def build(**kwargs):
        pool = httpx.AsyncClient(**kwargs, transport=httpx.MockTransport(respond))
        f.clients.append(pool)
        f.closers.append(pool.aclose)
        return pool

    monkeypatch.setattr(module, "build_async_client", build)
    monkeypatch.setattr(module, "_ticket_cache", module._TicketCache())
    monkeypatch.setattr(module, "_connection_cache", module._ConnectionCache())
    monkeypatch.setattr(module, "_reachability", module._ReachabilityTracker())
    f.config = module.ProxmoxClientConfig(
        host="192.168.254.254", username="owned", password="owned-password"
    )
    f.client = module.ProxmoxClient(f.config)
    yield f
    for close in f.closers:
        await close()


def assert_reset(f):
    assert f.client._http is None
    assert not f.client.is_connected and not f.client._authenticated
    assert f.client._authentication_mode is None and f.client._cache_identity is None
    assert f.client._ticket is None and f.client._csrf_token is None
    assert (
        module.ProxmoxClient.get_cached(
            f.config.host, username=f.config.username, password=f.config.password
        )
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("body", INVALID)
async def test_malformed_login_is_refused_and_allocated_pool_is_closed(peer, body):
    f = peer
    f.body = body
    with pytest.raises(module.ProxmoxApiError):
        await f.client.connect()
    assert f.clients and all(pool.is_closed for pool in f.clients)
    assert_reset(f)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        httpx.ReadError,
        httpx.WriteError,
        httpx.RemoteProtocolError,
        httpx.DecodingError,
        RuntimeError,
        httpx.ConnectError,
        httpx.ReadTimeout,
    ],
)
async def test_every_failed_login_releases_transport_and_preserves_error_class(peer, failure):
    f = peer
    f.error = failure
    expected = (
        module.ProxmoxApiError if failure in [httpx.ConnectError, httpx.ReadTimeout] else failure
    )
    with pytest.raises(expected):
        await f.client.connect()
    assert all(pool.is_closed for pool in f.clients)
    assert_reset(f)


@pytest.mark.asyncio
async def test_cancelled_login_closes_pool_and_does_not_authenticate(peer):
    f = peer
    f.wait = asyncio.Event()
    task = asyncio.create_task(f.client.connect())
    try:
        await asyncio.wait_for(f.entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert all(pool.is_closed for pool in f.clients)
        assert_reset(f)
    finally:
        f.wait.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_same_instance_can_reauthenticate_after_unexpected_login_failure(peer):
    f = peer
    f.error = httpx.ReadError
    with pytest.raises(httpx.ReadError):
        await f.client.connect()
    f.error = None
    await f.client.connect()
    assert f.client.is_connected and len(f.requests) == 2 and len(f.clients) == 2
    assert f.clients[0].is_closed


@pytest.mark.asyncio
async def test_open_unauthenticated_pool_is_not_a_successful_connection(peer):
    f = peer
    f.client._http = module.build_async_client(base_url=f.client.base_url)
    orphan = f.client._http
    await f.client.connect()
    assert f.client.is_connected and len(f.requests) == 1 and len(f.clients) == 2
    assert orphan.is_closed


@pytest.mark.asyncio
async def test_close_failure_still_clears_authentication_and_cache_identity(peer, monkeypatch):
    f = peer
    await f.client.connect()
    monkeypatch.setattr(f.clients[0], "aclose", AsyncMock(side_effect=RuntimeError(MARKER)))
    with pytest.raises(RuntimeError):
        await f.client.close()
    assert_reset(f)


@pytest.mark.asyncio
async def test_cleanup_failure_does_not_replace_login_error_or_log_private_detail(
    peer, monkeypatch, caplog
):
    f = peer
    original = module.build_async_client

    def broken_close(**kwargs):
        pool = original(**kwargs)
        monkeypatch.setattr(pool, "aclose", AsyncMock(side_effect=RuntimeError(MARKER)))
        return pool

    monkeypatch.setattr(module, "build_async_client", broken_close)
    f.error = httpx.ReadError
    with pytest.raises(httpx.ReadError):
        await f.client.connect()
    assert_reset(f)
    assert MARKER not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("csrf", [None, "", "owned-csrf"])
async def test_valid_ticket_and_optional_csrf_remain_compatible(peer, csrf):
    f = peer
    f.body = {"data": {"ticket": TICKET, "CSRFPreventionToken": csrf}}
    await f.client.connect()
    assert f.client.is_connected and f.client._http.cookies.get("PVEAuthCookie") == TICKET
    await f.client.close()
    assert_reset(f)


@pytest.mark.asyncio
async def test_token_authentication_does_not_attempt_password_login(peer):
    f = peer
    f.config.token_id = "owned@pam!test"
    f.config.token_secret = "owned-token"
    await f.client.connect()
    assert f.client.is_connected and not f.requests
    assert f.client._http.headers["Authorization"] == "PVEAPIToken=owned@pam!test=owned-token"


@pytest.mark.asyncio
async def test_already_authenticated_connection_keeps_its_existing_pool(peer):
    f = peer
    await f.client.connect()
    await f.client.connect()
    assert f.client.is_connected and len(f.clients) == len(f.requests) == 1
