# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Outbound connections go only to checked addresses (26.11.3 review)."""

from __future__ import annotations

import socket
from types import SimpleNamespace as NS

import httpcore
import httpx
import pytest

from app.core import http_client


def _addrinfo(*ips: str):
    async def fake(_host, port, **_kwargs):
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (ip, port),
            )
            for ip in ips
        ]

    return fake


@pytest.mark.parametrize(
    "host",
    [
        "x@127.0.0.1",
        "http://x@127.0.0.1/",
        "admin:pw@10.0.0.5",
        "nvr.lan?x=1",
        "a b",
        "nvr\\lan",
        "",
    ],
)
def test_the_host_check_refuses_text_that_is_not_a_host(host):
    """Fails on candidate 10: "x@127.0.0.1" passed (its lookup failed) and the
    URL parser then connected to 127.0.0.1 with "x" as a login."""
    from app.adapters.base import validate_host

    with pytest.raises(ValueError, match="Blocked host"):
        validate_host(host)


async def test_a_session_cookie_stays_with_the_host_name(loopback_devices_allowed):
    """Fails on candidate 10: the request URL was rewritten to the IP, so a
    login cookie was stored for the IP and never sent back to the name."""
    from aiohttp import web

    async def login(_request):
        response = web.Response(text="ok")
        response.set_cookie("SESSION", "s1")
        return response

    async def whoami(request):
        return web.Response(text=request.cookies.get("SESSION", "none"))

    app = web.Application()
    app.router.add_get("/login", login)
    app.router.add_get("/whoami", whoami)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        async with http_client.build_async_client(timeout=5.0) as client:
            await client.get(f"http://localhost:{port}/login")
            answer = await client.get(f"http://localhost:{port}/whoami")
        assert answer.text == "s1"
    finally:
        await runner.cleanup()


async def test_an_ip_literal_is_checked_at_connect_time():
    async with http_client.build_async_client(timeout=2.0) as client:
        with pytest.raises(httpx.ConnectError, match="refused"):
            await client.get("http://169.254.169.254/latest/meta-data/")
        with pytest.raises(httpx.ConnectError, match="refused"):
            await client.get("http://[::ffff:127.0.0.1]:9/")


async def test_the_network_backend_connects_to_the_checked_address(monkeypatch):
    seen = []

    class Inner(httpcore.AsyncNetworkBackend):
        async def connect_tcp(self, host, port, **_kwargs):
            seen.append(host)
            raise httpcore.ConnectError("closed")

        async def sleep(self, seconds):
            return None

    loop = __import__("asyncio").get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", _addrinfo("192.168.7.10", "192.168.7.11"))
    backend = http_client._CheckedNetworkBackend(Inner(), allow_loopback=False)
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("nvr.example.test", 443)
    assert seen == ["192.168.7.10", "192.168.7.11"]  # each checked address, never the name

    monkeypatch.setattr(loop, "getaddrinfo", _addrinfo("192.168.7.10", "169.254.169.254"))
    seen.clear()
    with pytest.raises(httpcore.ConnectError, match="does not connect to"):
        await backend.connect_tcp("nvr.example.test", 443)
    assert seen == []


def test_the_loopback_exception_is_only_loopback():
    """Fails on candidate 10: allow_loopback switched the whole check off, so a
    model-server name could resolve to a cloud-metadata address."""
    assert http_client._refused("127.0.0.1", allow_loopback=True) is False
    assert http_client._refused("::1", allow_loopback=True) is False
    assert http_client._refused("169.254.169.254", allow_loopback=True) is True
    assert http_client._refused("100.100.100.200", allow_loopback=True) is True
    assert http_client._refused("127.0.0.1") is True


async def test_a_model_server_client_still_refuses_metadata():
    async with http_client.build_async_client(allow_loopback=True, timeout=2.0) as client:
        with pytest.raises(httpx.ConnectError, match="refused"):
            await client.get("http://169.254.169.254/")


async def test_aiohttp_checks_ip_literals_too():
    """Fails on candidate 10: aiohttp does not call its resolver for an IP
    literal, so a redirect to a numeric address skipped the check."""
    import aiohttp

    async with aiohttp.ClientSession(connector=http_client.checked_connector()) as session:
        for url in ("http://169.254.169.254/", "http://127.0.0.1:9/", "http://[::1]:9/"):
            with pytest.raises((aiohttp.ClientError, OSError)) as caught:
                async with session.get(url):
                    pass
            err = caught.value
            assert "does not connect to" in f"{err} {getattr(err, 'os_error', '')}"


@pytest.mark.parametrize(
    ("start", "location", "allowed"),
    [
        ("http://192.168.1.5/", "/login", True),
        ("http://192.168.1.5/", "https://192.168.1.5/login", True),  # upgrade
        ("https://192.168.1.5/", "http://192.168.1.5/login", False),  # downgrade
        ("https://192.168.1.5/", "https://192.168.1.5:8443/login", False),  # other port
        ("http://192.168.1.5/", "http://169.254.169.254/latest", False),
    ],
)
async def test_a_redirect_must_stay_on_the_same_origin(start, location, allowed):
    """Fails on candidate 10 for the downgrade and the port change: only the
    host was compared, so a 307 could carry a login to plain HTTP."""
    import aiohttp
    from yarl import URL

    hook = http_client._same_host_redirects_only().on_request_redirect[0]
    params = NS(url=URL(start), response=NS(headers={"Location": location}))
    if allowed:
        await hook(None, None, params)
    else:
        with pytest.raises(aiohttp.ClientError):
            await hook(None, None, params)


class _Recorder(httpx.AsyncBaseTransport):
    def __init__(self):
        self.requests = []

    async def handle_async_request(self, request):
        self.requests.append(request)
        return httpx.Response(200)


async def test_the_overlay_proxy_is_asked_for_the_checked_address(monkeypatch):
    """Fails on candidate 10: with the userspace overlay the proxy resolved the
    name itself, unchecked."""
    loop = __import__("asyncio").get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", _addrinfo("192.168.7.10"))
    transport = http_client._CheckedProxyTransport(
        proxy="socks5://127.0.0.1:1055", pin=True, allow_loopback=False
    )
    recorder = _Recorder()
    monkeypatch.setattr(transport, "_inner", lambda _host: recorder)
    request = httpx.Request(
        "GET", "https://nvr.example.test/api", headers={"Host": "nvr.example.test"}
    )
    await transport.handle_async_request(request)
    sent = recorder.requests[0]
    assert sent.url.host == "192.168.7.10"
    assert sent.headers["Host"] == "nvr.example.test"
    assert sent.extensions["sni_hostname"] == "nvr.example.test"
    assert request.url.host == "nvr.example.test"  # the caller's request is untouched

    monkeypatch.setattr(loop, "getaddrinfo", _addrinfo("127.0.0.1"))
    with pytest.raises(httpx.ConnectError, match="does not connect to"):
        await transport.handle_async_request(httpx.Request("GET", "https://nvr.example.test/"))


async def test_only_an_overlay_name_may_skip_the_local_lookup(monkeypatch):
    async def unknown(*_args, **_kwargs):
        raise socket.gaierror("no such name")

    loop = __import__("asyncio").get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", unknown)
    transport = http_client._CheckedProxyTransport(
        proxy="socks5://127.0.0.1:1055", pin=True, allow_loopback=False
    )
    recorder = _Recorder()
    monkeypatch.setattr(transport, "_inner", lambda _host: recorder)
    await transport.handle_async_request(
        httpx.Request("GET", "https://nvr.tailnet-example.ts.net/")
    )
    assert recorder.requests[0].url.host == "nvr.tailnet-example.ts.net"
    with pytest.raises(httpx.ConnectError):
        await transport.handle_async_request(httpx.Request("GET", "https://nvr.corp.example/"))


async def test_environment_proxies_are_still_used(monkeypatch):
    """Fails on candidate 10: the checked transport turned httpx's
    HTTP(S)_PROXY support off, so a site behind a proxy lost cloud sign-in."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
    monkeypatch.setenv("NO_PROXY", "192.168.1.5")
    client = http_client.build_async_client(timeout=2.0)
    try:
        transport = client._transport_for_url(httpx.URL("https://login.example.test/"))
        assert isinstance(transport, http_client._CheckedProxyTransport)
        direct = client._transport_for_url(httpx.URL("https://192.168.1.5/"))
        assert isinstance(direct, http_client._CheckedHostTransport)
    finally:
        await client.aclose()


async def test_a_raw_connection_helper_refuses_a_rebound_name(monkeypatch):
    loop = __import__("asyncio").get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", _addrinfo("127.0.0.1"))
    with pytest.raises(OSError, match="does not connect to"):
        await http_client.checked_address("pbx.example.test", 5038)
    monkeypatch.setattr(loop, "getaddrinfo", _addrinfo("192.168.7.20"))
    assert await http_client.checked_address("pbx.example.test", 5038) == "192.168.7.20"
