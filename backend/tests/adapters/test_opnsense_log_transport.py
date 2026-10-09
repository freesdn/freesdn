"""Exact read-only LogController POST paths; synthetic HTTP transport only."""

import json

import httpx
import pytest

from app.adapters.exceptions import AdapterError
from app.adapters.opnsense.client import OPNsenseClient


@pytest.mark.parametrize("kind", ["system", "firewall"])
@pytest.mark.parametrize("limit, expected", [(-1, 1), (25, 25), (999999, 5000)])
async def test_logs_use_bounded_read_post_in_read_only_mode(monkeypatch, kind, limit, expected):
    monkeypatch.setattr("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    calls = []
    path = "/api/diagnostics/log/core/" + ("filter" if kind == "firewall" else "system")

    def peer(request):
        calls.append(request)
        assert request.method == "POST" and request.url.path == path
        assert json.loads(request.content) == {"current": 1, "rowCount": expected}
        return httpx.Response(200, json={"rows": [{"message": "owned-log"}]})

    client = OPNsenseClient("192.0.2.1", "owned", "synthetic", verify_ssl=True)
    async with httpx.AsyncClient(
        base_url="https://192.0.2.1", transport=httpx.MockTransport(peer)
    ) as transport:
        client._client = transport
        result = await getattr(client, "get_" + kind + "_log")(limit)
    assert result == {"rows": [{"message": "owned-log"}]} and len(calls) == 1


@pytest.mark.parametrize(
    "suffix",
    ["/clear", "/clear/", "/restart", "/123", "-clear", "/clear/status", "/clear/searchRows"],
)
@pytest.mark.parametrize("kind", ["system", "filter"])
async def test_adjacent_mutating_log_paths_still_refused(monkeypatch, kind, suffix):
    monkeypatch.setattr("app.adapters.opnsense.client._is_adapter_read_only", lambda: True)
    client = OPNsenseClient("192.0.2.1", "owned", "synthetic", verify_ssl=True)
    calls = []

    def peer(request):
        calls.append(request)
        return httpx.Response(200, json={"status": "ok"})

    async with httpx.AsyncClient(
        base_url="https://192.0.2.1", transport=httpx.MockTransport(peer)
    ) as transport:
        client._client = transport
        with pytest.raises(AdapterError, match="ADAPTER_READ_ONLY"):
            await client.post("/api/diagnostics/log/core/" + kind + suffix, {})
    assert not calls
