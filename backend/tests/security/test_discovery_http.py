# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest

from app.core import discovery_http as probes


class Body(httpx.AsyncByteStream):
    def __init__(self, chunks=(), delay=0):
        self.chunks = chunks
        self.delay = delay
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            yield chunk

    async def aclose(self):
        self.closed = True


def transport(monkeypatch, handler):
    captured = []
    factory = probes.build_async_client

    def build(**kwargs):
        captured.append(kwargs)
        return factory(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(probes, "build_async_client", build)
    return captured


async def test_pins_hostname_sends_no_credentials_cookies_or_environment_proxy(monkeypatch):
    monkeypatch.setattr(probes, "resolve_and_pin_host", lambda _host: "192.168.10.20")
    monkeypatch.setenv("HTTP_PROXY", "http://bad:secret@127.0.0.1:99")
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200, headers={"Set-Cookie": "session=untrusted"}, stream=Body([b"ok"])
        )

    configs = transport(monkeypatch, handler)
    async with probes.DiscoveryProbe("lab.example") as client:
        for port in (80, 8080):
            response = await client.get(f"http://lab.example:{port}/")
            assert response.text == "ok"
    assert len(seen) == 2
    for request in seen:
        assert request.url.host == "192.168.10.20"
        assert not {"authorization", "cookie", "proxy-authorization"} & set(request.headers)
        assert request.headers["accept-encoding"] == "identity"
    assert all(
        c["trust_env"] is False and c["follow_redirects"] is False and c["verify"] is False
        for c in configs
    )


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "::1", "100.100.100.200"])
async def test_forbidden_targets_never_create_client(monkeypatch, host):
    called = transport(monkeypatch, lambda _request: pytest.fail("network dispatched"))
    with pytest.raises(ValueError):
        async with probes.DiscoveryProbe(host):
            pass
    assert not called


@pytest.mark.parametrize(
    "url", ["http://other.example/", "file:///etc/passwd", "http://user:secret@192.168.10.20/"]
)
async def test_origin_and_credentials_are_rejected(monkeypatch, url):
    called = transport(monkeypatch, lambda _request: pytest.fail("network dispatched"))
    async with probes.DiscoveryProbe("192.168.10.20") as client:
        with pytest.raises(ValueError):
            await client.get(url)
    assert not called


@pytest.mark.parametrize(
    "headers,chunks",
    [
        ({"Content-Length": "262145"}, []),
        ({"Content-Length": "bad"}, []),
        ({"Content-Encoding": "gzip"}, [b"compressed bomb"]),
        ({}, [b"a" * 131072, b"b" * 131073]),
    ],
)
async def test_response_budget_rejects_oversize_or_compression_and_closes(
    monkeypatch, headers, chunks
):
    body = Body(chunks)
    transport(monkeypatch, lambda _request: httpx.Response(200, headers=headers, stream=body))
    async with probes.DiscoveryProbe("192.168.10.20") as client:
        with pytest.raises(probes.ProbeLimitError):
            await client.get("http://192.168.10.20/")
        assert client.limited
    assert body.closed


async def test_drip_feed_hits_wall_clock_deadline_and_closes(monkeypatch):
    body = Body([b"x"] * 100, delay=0.01)
    transport(monkeypatch, lambda _request: httpx.Response(200, stream=body))
    async with probes.DiscoveryProbe("192.168.10.20") as client:
        with pytest.raises(probes.ProbeLimitError):
            await client.get("http://192.168.10.20/", timeout=0.025)
    assert body.closed


async def test_redirect_is_observed_without_following(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"}, stream=Body())

    transport(monkeypatch, handler)
    async with probes.DiscoveryProbe("192.168.10.20") as client:
        assert (await client.get("http://192.168.10.20/")).status_code == 302
    assert len(seen) == 1


async def test_total_request_and_time_limits_prevent_dispatch(monkeypatch):
    seen = transport(monkeypatch, lambda _request: httpx.Response(200, stream=Body([b"ok"])))
    async with probes.DiscoveryProbe("192.168.10.20") as client:
        for _ in range(probes.MAX_REQUESTS):
            await client.get("http://192.168.10.20/")
        with pytest.raises(probes.ProbeLimitError):
            await client.get("http://192.168.10.20/")
        client.requests = 0
        client.deadline = 0
        with pytest.raises(probes.ProbeLimitError):
            await client.get("http://192.168.10.20/")
    assert len(seen) == probes.MAX_REQUESTS


async def test_fingerprint_does_not_use_submitted_credentials(monkeypatch):
    from app.api.v1.endpoints.discovery import fingerprint_device
    from app.schemas.discovery import FingerprintRequestSchema

    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, stream=Body([b"MikroTik RouterOS"]))

    transport(monkeypatch, handler)
    result = await fingerprint_device(
        FingerprintRequestSchema(
            ip_address="192.168.10.20", ports=[80], credentials={"password": "DO_NOT_SEND"}
        ),
        current_user=object(),
    )
    assert result.vendor == "mikrotik"
    assert (
        result.raw_data["identity_verified"] is False
        and result.raw_data["credentials_used"] is False
    )
    assert all("DO_NOT_SEND" not in str(r.headers) for r in seen)


async def test_scanner_failure_does_not_echo_remote_diagnostic(monkeypatch):
    from app.services.scanner import ScanConfig, ServiceProber

    monkeypatch.setattr(
        probes.DiscoveryProbe, "get", AsyncMock(side_effect=RuntimeError("SECRET_FIXTURE"))
    )
    result = await ServiceProber(ScanConfig(targets=[])).probe_http("192.168.10.20", 80)
    assert result["error"] == "http_probe_unavailable_or_limited" and "SECRET_FIXTURE" not in str(
        result
    )
