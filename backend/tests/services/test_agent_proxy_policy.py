# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The edge agent's HTTP proxy reaches only allowed device hosts and carries no FreeSDN secrets.

``proxy_http_via_site`` / ``reach_device_http`` / ``AgentHTTPTransport`` have no
production caller yet. A security review required a host allow-list and header
scrubbing before anything wires them up, because the agent sits on a LAN the
controller cannot reach: an unchecked URL reads the agent host's loopback
services or cloud metadata, and forwarded headers hand FreeSDN's own session to
a device. Nothing here contacts a network: the agent connection is replaced.
"""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.site_access import current_user_var
from app.services import device_reach
from app.services.agent_proxy_policy import (
    AgentProxyRefused,
    check_proxy_target,
    scrub_request_headers,
    scrub_response_headers,
)
from app.services.remote_agent import AgentRegistryService

DEVICE = "10.20.30.40"


def _jwt(claims: dict) -> str:
    def seg(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'HS256'})}.{seg(claims)}.c2ln"


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:9000/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://0.0.0.0/",
        "http://100.100.100.200/",  # Alibaba metadata
        "http://localhost/",
        "http://agent.localhost/",
        "http://metadata.google.internal/",
        "http://2130706433/",  # 127.0.0.1 as one number
        "http://0x7f.1/",
        "http://127.1/",
        f"http://admin:pw@{DEVICE}/",
        f"http://{DEVICE}@169.254.169.254/",
        f"http://{DEVICE}\\@169.254.169.254/",
        f"file:///{DEVICE}/etc/passwd",
        f"gopher://{DEVICE}:70/",
        f"http://{DEVICE}:0/",
        f"http://{DEVICE}:99999/",
        "http://10.20.30.41/",  # a private host, but not the device asked for
        "http:///nohost",
    ],
)
def test_the_policy_refuses(url: str) -> None:
    allowed = {DEVICE, "127.0.0.1", "169.254.169.254", "localhost", "2130706433", "::1"}
    with pytest.raises(AgentProxyRefused):
        check_proxy_target(url, allowed)


def test_no_allow_list_refuses_everything() -> None:
    for allowed in (None, [], {""}):
        with pytest.raises(AgentProxyRefused, match="no allowed hosts"):
            check_proxy_target(f"http://{DEVICE}/", allowed)


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        (f"http://{DEVICE}/ISAPI/System/deviceInfo", {DEVICE}),
        (f"https://{DEVICE}:8443/api?x=1", {DEVICE}),
        ("https://cam-1.lan/api", {"CAM-1.LAN."}),
        ("http://[fd12::5]/", {"fd12::5"}),
    ],
)
def test_the_policy_allows_the_named_device(url: str, allowed: set[str]) -> None:
    assert check_proxy_target(url, allowed) == url


def test_request_headers_lose_freesdn_credentials_and_hop_by_hop() -> None:
    headers = {
        "Cookie": "freesdn_access=abc; JSESSIONID=device-session; freesdn_csrf=x",
        "X-CSRF-Token": "freesdn-csrf",
        "X-API-Key": "fsd_" + "a" * 64,
        "Authorization": "Bearer " + _jwt({"iss": "freesdn", "sub": "user"}),
        "Connection": "close",
        "Host": "169.254.169.254",
        "Proxy-Authorization": "Basic eA==",
        "Content-Length": "9999",
        "X-Device-Header": "kept",
    }
    assert scrub_request_headers(headers) == {
        "Cookie": "JSESSIONID=device-session",
        "X-Device-Header": "kept",
    }
    # The device's own credentials pass: that is what the adapter is for.
    device_auth = {
        "Authorization": "Bearer " + _jwt({"iss": "truenas"}),
        "X-API-KEY": "unifi-integration-key",
    }
    assert scrub_request_headers(device_auth) == device_auth
    assert scrub_request_headers({"Authorization": "Digest username=admin"}) == {
        "Authorization": "Digest username=admin"
    }


def test_response_headers_lose_session_and_token_headers() -> None:
    assert scrub_response_headers(
        {
            "Set-Cookie": "session=device",
            "X-Auth-Token": "t",
            "Authorization": "Basic eA==",
            "Content-Type": "application/json",
            "Transfer-Encoding": "chunked",
        }
    ) == {"Content-Type": "application/json"}


class _Sent:
    def __init__(self) -> None:
        self.commands: list = []

    async def __call__(self, site_id, command, wait_result=True):
        self.commands.append(command)
        return SimpleNamespace(success=True, result={"status_code": 200, "headers": {}, "body": ""})


@pytest.fixture
def registry(monkeypatch):
    reg = AgentRegistryService(db=None)
    sent = _Sent()
    monkeypatch.setattr(reg, "send_command_to_site", sent)
    reg.sent = sent
    return reg


async def test_the_registry_sends_nothing_for_a_refused_url(registry) -> None:
    for url, allowed in (
        ("http://169.254.169.254/latest/meta-data/iam/", {"169.254.169.254"}),
        (f"http://{DEVICE}/", None),
        ("http://10.0.0.9/", {DEVICE}),
    ):
        with pytest.raises(AgentProxyRefused):
            await registry.proxy_http_via_site(
                uuid4(), url=url, allowed_hosts=allowed, username="admin", password="secret"
            )
    assert registry.sent.commands == []


async def test_the_registry_forwards_only_scrubbed_headers(registry) -> None:
    await registry.proxy_http_via_site(
        uuid4(),
        url=f"http://{DEVICE}/api",
        allowed_hosts=[DEVICE],
        headers={"Cookie": "freesdn_refresh=r", "X-CSRF-Token": "c", "Accept": "json"},
    )
    (command,) = registry.sent.commands
    assert command.payload["headers"] == {"Accept": "json"}
    assert command.payload["url"] == f"http://{DEVICE}/api"


async def test_a_site_limited_caller_cannot_proxy_into_another_site(registry) -> None:
    granted, other = uuid4(), uuid4()
    user = SimpleNamespace(can_access_site=lambda site_id: site_id == granted)
    token = current_user_var.set(user)
    try:
        with pytest.raises(HTTPException) as exc:
            await registry.proxy_http_via_site(
                other, url=f"http://{DEVICE}/", allowed_hosts=[DEVICE]
            )
        assert exc.value.status_code == 404
        await registry.proxy_http_via_site(granted, url=f"http://{DEVICE}/", allowed_hosts=[DEVICE])
    finally:
        current_user_var.reset(token)
    assert len(registry.sent.commands) == 1


async def test_reach_device_http_refuses_before_choosing_a_transport(monkeypatch) -> None:
    def _no_client(**_kw):
        raise AssertionError("no client may be built for a refused URL")

    monkeypatch.setattr(device_reach, "build_async_client", _no_client)
    with pytest.raises(device_reach.DeviceUnreachableError, match="refused"):
        await device_reach.reach_device_http(
            uuid4(), "http://169.254.169.254/", allowed_hosts=[DEVICE]
        )
    with pytest.raises(device_reach.DeviceUnreachableError, match="refused"):
        await device_reach.reach_device_http(uuid4(), f"http://{DEVICE}/")


async def test_reach_device_http_strips_session_headers_from_the_agent_response() -> None:
    class _Registry:
        def get_connection_for_site(self, _site_id):
            return object()

        async def proxy_http_via_site(self, _site_id, **kwargs):
            self.kwargs = kwargs
            return SimpleNamespace(
                success=True,
                result={
                    "status_code": 200,
                    "headers": {"Set-Cookie": "sid=device", "Content-Type": "text/html"},
                    "body": "ok",
                },
            )

    reg = _Registry()
    out = await device_reach.reach_device_http(
        uuid4(), f"http://{DEVICE}/", allowed_hosts=[DEVICE], registry=reg, prefer_agent=True
    )
    assert out["headers"] == {"Content-Type": "text/html"}
    assert reg.kwargs["allowed_hosts"] == (DEVICE,)


async def test_the_transport_passes_its_allowed_hosts_to_the_registry() -> None:
    from app.core.http_client import build_async_client

    class _Registry:
        async def proxy_http_via_site(self, _site_id, **kwargs):
            self.kwargs = kwargs
            return SimpleNamespace(
                success=True,
                result={"status_code": 200, "headers": {"Set-Cookie": "sid=1"}, "body": "{}"},
            )

    reg = _Registry()
    transport = device_reach.AgentHTTPTransport(reg, uuid4(), allowed_hosts=[DEVICE])
    async with build_async_client(transport=transport, base_url=f"http://{DEVICE}") as client:
        resp = await client.get("/x")
    assert reg.kwargs["allowed_hosts"] == (DEVICE,)
    # Kept inside the adapter's own client: its cookie jar needs the session.
    assert resp.headers["set-cookie"] == "sid=1"
