# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Device I/O policy: a timeout is never retried; only resets and 502/503/504 on reads.

Evidence (2026-11 soak, office OPNsense): every 60 s ``ReadTimeout`` was sent
three times, so a single read held the poll for over three minutes while each
retry woke another PHP worker on a firewall that was already wedged. These tests
count transmissions on a synthetic transport.
"""

from __future__ import annotations

import aiohttp
import httpx
import pytest

from app.adapters import io_policy
from app.adapters.exceptions import AdapterConnectionError
from app.adapters.io_policy import Failure
from app.adapters.opnsense.client import OPNsenseAPIError, OPNsenseClient


@pytest.mark.parametrize(
    "exc,expected",
    [
        (httpx.ReadTimeout("x"), Failure.TIMEOUT),
        (httpx.ConnectTimeout("x"), Failure.TIMEOUT),
        (httpx.PoolTimeout("x"), Failure.TIMEOUT),
        (TimeoutError(), Failure.TIMEOUT),
        (aiohttp.ServerTimeoutError(), Failure.TIMEOUT),
        (httpx.ConnectError("refused"), Failure.CONNECT),
        (ConnectionRefusedError(), Failure.CONNECT),
        (httpx.RemoteProtocolError("dropped"), Failure.RESET),
        (httpx.ReadError("reset"), Failure.RESET),
        (aiohttp.ServerDisconnectedError(), Failure.RESET),
        (ConnectionResetError(), Failure.RESET),
        (ValueError("x"), Failure.OTHER),
    ],
)
def test_classify(exc: BaseException, expected: Failure) -> None:
    assert io_policy.classify(exc) is expected


def test_only_resets_and_gateway_statuses_are_retryable_and_only_for_reads() -> None:
    for failure in Failure:
        assert io_policy.may_retry(failure, idempotent=False) is False
    assert io_policy.may_retry(Failure.RESET, idempotent=True)
    assert io_policy.may_retry(Failure.SERVER_ERROR, idempotent=True)
    assert not io_policy.may_retry(Failure.TIMEOUT, idempotent=True)
    assert not io_policy.may_retry(Failure.CONNECT, idempotent=True)
    assert [s for s in range(400, 600) if io_policy.may_retry_status(s, idempotent=True)] == [
        502,
        503,
        504,
    ]
    assert not io_policy.may_retry_status(503, idempotent=False)


def test_backoff_is_jittered_and_capped() -> None:
    samples = {round(io_policy.backoff_delay(4, base=1.0, cap=3.0), 6) for _ in range(50)}
    assert len(samples) > 1
    assert all(0.0 <= s <= 3.0 for s in samples)


def test_deadline() -> None:
    assert io_policy.Deadline(10).allows(1.0)
    assert not io_policy.Deadline(1).allows(1.0)


async def _nosleep(*_a, **_k) -> None:
    return None


def _client(monkeypatch, handler) -> tuple[OPNsenseClient, list[httpx.Request]]:
    monkeypatch.setattr("app.adapters.opnsense.client.asyncio.sleep", _nosleep)
    calls: list[httpx.Request] = []

    def peer(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request, len(calls))

    client = OPNsenseClient("192.0.2.9", "owned", "synthetic", verify_ssl=True)
    client._client = httpx.AsyncClient(
        base_url=client.base_url, transport=httpx.MockTransport(peer)
    )
    return client, calls


@pytest.mark.parametrize(
    "exc", [httpx.ReadTimeout("slow"), httpx.ConnectTimeout("slow"), httpx.ConnectError("down")]
)
async def test_opnsense_read_is_sent_once_on_timeout_or_connect_failure(monkeypatch, exc) -> None:
    """Fails on the old client: a ReadTimeout was transmitted 3 times."""

    def handler(request, n):
        raise exc

    client, calls = _client(monkeypatch, handler)
    with pytest.raises(AdapterConnectionError):
        await client.get("/api/core/system/status")
    assert len(calls) == 1, f"{type(exc).__name__} was sent {len(calls)} times"


async def test_opnsense_read_is_retried_after_a_dropped_connection(monkeypatch) -> None:
    def handler(request, n):
        if n == 1:
            raise httpx.RemoteProtocolError("server disconnected", request=request)
        return httpx.Response(200, json={"ok": True})

    client, calls = _client(monkeypatch, handler)
    assert await client.get("/api/core/system/status") == {"ok": True}
    assert len(calls) == 2


@pytest.mark.parametrize("status,expected_calls", [(500, 1), (501, 1), (503, 3), (504, 3)])
async def test_opnsense_read_retries_only_gateway_statuses(
    monkeypatch, status, expected_calls
) -> None:
    """Fails on the old client: a 500 was retried 3 times like a 503."""

    def handler(request, n):
        return httpx.Response(status, text="err")

    client, calls = _client(monkeypatch, handler)
    with pytest.raises(OPNsenseAPIError):
        await client.get("/api/core/system/status")
    assert len(calls) == expected_calls


async def test_opnsense_reads_get_the_short_read_timeout(monkeypatch) -> None:
    """Fails on the old client: a read inherited the 60 s write timeout."""

    def handler(request, n):
        if request.url.path.endswith("/download/this"):
            return httpx.Response(200, text="<opnsense/>")
        return httpx.Response(200, json={})

    client, calls = _client(monkeypatch, handler)
    await client.get("/api/core/system/status")
    await client.post("/api/firewall/filter/searchRule", {})
    await client.download_config_xml()
    for request in calls:
        timeout = request.extensions["timeout"]
        assert timeout["read"] == 30.0, (request.url.path, timeout)
        assert timeout["connect"] <= 8.0


# ── The same policy in every adapter transport that retried ─────────────────


def _omada_client():
    from unittest.mock import AsyncMock, MagicMock

    from app.adapters.omada.client import OmadaApiClient, OmadaClientConfig

    client = OmadaApiClient(
        OmadaClientConfig(
            host="omada.invalid",
            username="u",
            password="p",
            verify_ssl=False,
            max_retries=3,
            retry_backoff=0.0,
        )
    )
    http = MagicMock()
    http.is_closed = False
    http.request = AsyncMock()
    client._http = http
    client._logged_in = True
    client._controller_id = "ctrl"
    client._csrf_token = "csrf"
    client._rate_limiter.acquire = AsyncMock(return_value=True)
    return client, http


async def test_omada_read_is_sent_once_on_timeout() -> None:
    """Fails on the old client: a ReadTimeout on GET was transmitted 3 times."""
    from app.adapters.omada.exceptions import OmadaTimeoutError

    client, http = _omada_client()
    http.request.side_effect = httpx.ReadTimeout("slow")
    with pytest.raises(OmadaTimeoutError):
        await client._request("GET", "/sites")
    assert http.request.await_count == 1


async def test_omada_read_is_sent_once_on_connect_failure_but_retried_on_reset() -> None:
    from app.adapters.omada.exceptions import OmadaConnectionError

    client, http = _omada_client()
    http.request.side_effect = httpx.ConnectError("refused")
    with pytest.raises(OmadaConnectionError):
        await client._request("GET", "/sites")
    assert http.request.await_count == 1

    client, http = _omada_client()
    http.request.side_effect = httpx.RemoteProtocolError("dropped")
    with pytest.raises(OmadaConnectionError):
        await client._request("GET", "/sites")
    assert http.request.await_count == 3


def _proxmox(handler):
    from app.adapters.proxmox.client import ProxmoxClient, ProxmoxClientConfig

    client = ProxmoxClient(ProxmoxClientConfig(host="192.0.2.1"))
    client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://pve.invalid"
    )
    client._authenticated = True
    return client


async def test_proxmox_read_is_sent_once_on_timeout(monkeypatch) -> None:
    """Fails on the old client: a ReadTimeout on GET was transmitted 3 times."""
    from app.adapters.proxmox.client import ProxmoxApiError

    monkeypatch.setattr("app.adapters.proxmox.client.asyncio.sleep", _nosleep)
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("slow", request=request)

    client = _proxmox(handler)
    try:
        with pytest.raises(ProxmoxApiError):
            await client.get("/nodes")
    finally:
        await client._http.aclose()
    assert len(calls) == 1


async def test_proxmox_read_is_retried_after_a_dropped_connection(monkeypatch) -> None:
    monkeypatch.setattr("app.adapters.proxmox.client.asyncio.sleep", _nosleep)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.RemoteProtocolError("dropped", request=request)
        return httpx.Response(200, json={"data": [{"node": "pve1"}]})

    client = _proxmox(handler)
    try:
        assert await client.get("/nodes") == [{"node": "pve1"}]
    finally:
        await client._http.aclose()
    assert len(calls) == 2


class _RaisingCM:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def __aenter__(self):
        raise self._exc

    async def __aexit__(self, *exc):
        return False


class _Session:
    def __init__(self, exc: BaseException) -> None:
        self.calls = 0
        self._exc = exc

    def request(self, method, url, **_kw):
        self.calls += 1
        return _RaisingCM(self._exc)


@pytest.mark.parametrize(
    "exc,expected_calls",
    [
        (aiohttp.ServerTimeoutError("slow"), 1),
        (aiohttp.ServerDisconnectedError(), 2),
    ],
)
async def test_grandstream_read_retries_only_a_dropped_connection(
    monkeypatch, exc, expected_calls
) -> None:
    """Fails on the old client: a sock_read timeout on GET was sent twice."""
    from app.adapters.grandstream.client import GrandstreamPhoneClient
    from app.adapters.grandstream.exceptions import GrandstreamConnectionError

    monkeypatch.setattr("app.adapters.grandstream.client.asyncio.sleep", _nosleep)
    client = GrandstreamPhoneClient(host="phone.invalid", password="x")
    session = _Session(exc)
    client._session = session
    with pytest.raises(GrandstreamConnectionError):
        await client._request("GET", "/cgi-bin/api-get_phone_status")
    assert session.calls == expected_calls


@pytest.mark.parametrize("legacy_fallback,expected_paths", [(True, 2), (False, 1)])
async def test_opnsense_rules_fall_back_to_config_xml_only_when_asked(
    monkeypatch, legacy_fallback, expected_paths
) -> None:
    from app.adapters.opnsense.adapter import OPNsenseAdapter

    monkeypatch.setattr("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    adapter = OPNsenseAdapter(host="192.0.2.9", username="k", password="s", verify_ssl=True)
    calls: list[str] = []

    def peer(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/download/this"):
            return httpx.Response(200, text="<opnsense><filter/></opnsense>")
        return httpx.Response(200, json={"rows": [], "total": 0})

    adapter._api._client = httpx.AsyncClient(
        base_url=adapter._api.base_url, transport=httpx.MockTransport(peer)
    )
    result = await adapter.get_firewall_rules(legacy_fallback=legacy_fallback)
    assert result.success
    assert len(calls) == expected_paths, calls
    assert result.data.get("legacy_skipped", False) is (not legacy_fallback)
