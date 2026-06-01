# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for device-reach transport selection (P4 integration seam)."""

from uuid import uuid4

import pytest

from app.core.http_client import build_async_client
from app.services import device_reach


class _FakeResult:
    def __init__(self, success, result=None, error=None):
        self.success = success
        self.result = result
        self.error = error


class _FakeRegistry:
    def __init__(self, connected, proxy_result):
        self._connected = connected
        self._pr = proxy_result
        self.proxy_kwargs = None

    def get_connection_for_site(self, site_id):
        return object() if self._connected else None

    async def proxy_http_via_site(self, site_id, **kwargs):
        self.proxy_kwargs = kwargs
        return self._pr


class _FakeResp:
    status_code = 200
    headers = {"X": "1"}
    text = "direct-body"


class _FakeClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def request(self, *_a, **_k):
        return _FakeResp()


@pytest.mark.asyncio
async def test_reach_uses_agent_when_preferred_and_connected():
    reg = _FakeRegistry(
        connected=True,
        proxy_result=_FakeResult(
            True, {"status_code": 201, "headers": {"A": "b"}, "body": "agent-body"}
        ),
    )
    out = await device_reach.reach_device_http(
        uuid4(),
        "http://cam.lan/api",
        registry=reg,
        prefer_agent=True,
        username="u",
        password="p",
    )
    assert out["via"] == "agent"
    assert out["status_code"] == 201
    assert out["body"] == "agent-body"
    assert reg.proxy_kwargs["url"] == "http://cam.lan/api"


@pytest.mark.asyncio
async def test_reach_falls_to_direct_when_no_agent(monkeypatch):
    reg = _FakeRegistry(connected=False, proxy_result=None)
    monkeypatch.setattr(device_reach, "build_async_client", lambda **_k: _FakeClient())
    out = await device_reach.reach_device_http(uuid4(), "http://x", registry=reg, prefer_agent=True)
    assert out["via"] == "direct"
    assert out["status_code"] == 200


@pytest.mark.asyncio
async def test_reach_direct_by_default(monkeypatch):
    monkeypatch.setattr(device_reach, "build_async_client", lambda **_k: _FakeClient())
    out = await device_reach.reach_device_http(uuid4(), "http://x")
    assert out["via"] == "direct"
    assert out["body"] == "direct-body"


@pytest.mark.asyncio
async def test_reach_raises_when_agent_proxy_fails():
    reg = _FakeRegistry(connected=True, proxy_result=_FakeResult(False, error="boom"))
    with pytest.raises(device_reach.DeviceUnreachableError):
        await device_reach.reach_device_http(uuid4(), "http://x", registry=reg, prefer_agent=True)


@pytest.mark.asyncio
async def test_agent_http_transport_routes_every_request_through_agent():
    # the real httpx client + AgentHTTPTransport: a normal client call reaches the
    # device via the agent, and a stale Content-Length is stripped.
    reg = _FakeRegistry(
        connected=True,
        proxy_result=_FakeResult(
            True,
            {
                "status_code": 200,
                "headers": {"Content-Type": "application/json", "Content-Length": "999"},
                "body": '{"ok": true}',
            },
        ),
    )
    transport = device_reach.AgentHTTPTransport(reg, uuid4())
    async with build_async_client(transport=transport, base_url="http://cam.lan") as client:
        resp = await client.get("/api/system")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert resp.headers["content-type"] == "application/json"
    assert reg.proxy_kwargs["url"].endswith("/api/system")
    assert reg.proxy_kwargs["method"] == "GET"


@pytest.mark.asyncio
async def test_agent_http_transport_raises_connecterror_when_agent_fails():
    import httpx

    reg = _FakeRegistry(connected=True, proxy_result=_FakeResult(False, error="down"))
    transport = device_reach.AgentHTTPTransport(reg, uuid4())
    async with build_async_client(transport=transport, base_url="http://cam.lan") as client:
        with pytest.raises(httpx.ConnectError):
            await client.get("/x")


class _FakeSite:
    def __init__(self, site_id, settings):
        self.id = site_id
        self.settings = settings


def test_site_prefers_agent_reads_settings():
    assert device_reach.site_prefers_agent(_FakeSite(uuid4(), {"reach_mode": "agent"})) is True
    assert device_reach.site_prefers_agent(_FakeSite(uuid4(), {"reach_mode": "AGENT"})) is True
    assert device_reach.site_prefers_agent(_FakeSite(uuid4(), {"reach_mode": "direct"})) is False
    assert device_reach.site_prefers_agent(_FakeSite(uuid4(), {})) is False
    assert device_reach.site_prefers_agent(_FakeSite(uuid4(), None)) is False


def test_agent_transport_for_site_policy():
    site_id = uuid4()
    agent_site = _FakeSite(site_id, {"reach_mode": "agent"})
    direct_site = _FakeSite(site_id, {})
    reg_connected = _FakeRegistry(connected=True, proxy_result=None)
    reg_no_agent = _FakeRegistry(connected=False, proxy_result=None)

    # agent-preferred + an agent connected -> a transport
    assert isinstance(
        device_reach.agent_transport_for_site(reg_connected, agent_site),
        device_reach.AgentHTTPTransport,
    )
    # agent-preferred but no agent connected -> None (fall through to direct)
    assert device_reach.agent_transport_for_site(reg_no_agent, agent_site) is None
    # not agent-preferred -> None
    assert device_reach.agent_transport_for_site(reg_connected, direct_site) is None
    # no registry -> None
    assert device_reach.agent_transport_for_site(None, agent_site) is None
