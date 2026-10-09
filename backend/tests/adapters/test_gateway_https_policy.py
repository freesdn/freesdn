"""Certificate policy must govern actual outgoing gateway request schemes."""

import json

import httpx
import pytest

from app.adapters.mikrotik import client as mikrotik
from app.adapters.openwrt import client as openwrt
from app.adapters.opnsense import client as opnsense
from app.adapters.pfsense import client as pfsense
from app.modules.firewall.gateway_service import GatewayService, adapter_registry

MODULES = {
    "opnsense": opnsense,
    "pfsense": pfsense,
    "mikrotik": mikrotik,
    "openwrt": openwrt,
}


@pytest.fixture
def transport_capture(monkeypatch):
    requests = []
    clients = []
    adapters = []
    original_create = adapter_registry.create_adapter

    def respond(request):
        requests.append(request)
        path = request.url.path
        if path == "/ubus":
            body = json.loads(request.content)
            _, obj, action, _ = body["params"]
            data = {
                ("session", "login"): {"ubus_rpc_session": "owned-session"},
                ("system", "board"): {
                    "hostname": "owned-openwrt",
                    "release": {"version": "fixture"},
                },
                ("system", "info"): {"uptime": 1},
                ("rpc-sys", "packagelist"): {"packages": {}},
            }[(obj, action)]
            payload = {"jsonrpc": "2.0", "id": body["id"], "result": [0, data]}
        else:
            payload = {
                "/api/core/system/status": {
                    "name": "owned-opnsense",
                    "product_version": "fixture",
                },
                "/api/v2/system/version": {
                    "code": 200,
                    "status": "ok",
                    "data": {"version": "fixture"},
                },
                "/rest/system/resource": [{"version": "fixture"}],
                "/rest/system/identity": [{"name": "owned-mikrotik"}],
            }[path]
        return httpx.Response(200, json=payload)

    def build(**kwargs):
        client = httpx.AsyncClient(**kwargs, transport=httpx.MockTransport(respond))
        clients.append(client)
        return client

    def create(*args, **kwargs):
        adapter = original_create(*args, **kwargs)
        adapters.append(adapter)
        return adapter

    for module in MODULES.values():
        monkeypatch.setattr(module, "build_async_client", build)
    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    return requests, clients, adapters


async def exercise(vendor, port, verify_ssl, entry, capture, **extra):
    requests, clients, adapters = capture
    credentials = {
        "api_key": "owned-key",
        "api_secret": "owned-secret",
        "username": "owned-user",
        "password": "owned-secret",
    }
    try:
        if entry == "service":
            result = await GatewayService(None).test_connection(
                vendor, "192.168.77.77", port, verify_ssl, **credentials, **extra
            )
            assert result["success"]
        else:
            adapter = adapter_registry.create_adapter(
                vendor,
                host="192.168.77.77",
                port=port,
                verify_ssl=verify_ssl,
                **credentials,
                **extra,
            )
            assert (await adapter.test_connection()).success
        assert requests
        first = requests[0]
        if vendor == "openwrt":
            assert json.loads(first.content)["params"][3]["password"] == "owned-secret"
        else:
            assert first.headers.get("authorization")
        return requests
    finally:
        # These tests own cleanup; service-level lifetime is qualified separately.
        for adapter in adapters:
            await adapter.disconnect()
        for client in clients:
            await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", list(MODULES))
@pytest.mark.parametrize("port", [80, 8443])
@pytest.mark.parametrize("verify_ssl", [True, False])
@pytest.mark.parametrize("entry", ["service", "adapter"])
async def test_custom_port_credentials_follow_verification_policy(
    vendor, port, verify_ssl, entry, transport_capture
):
    requests = await exercise(vendor, port, verify_ssl, entry, transport_capture)
    expected_scheme = "https" if verify_ssl or vendor in {"opnsense", "pfsense"} else "http"
    assert all(request.url.scheme == expected_scheme for request in requests)
    assert all(
        (request.url.port or (443 if request.url.scheme == "https" else 80)) == port
        for request in requests
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", ["mikrotik", "pfsense"])
@pytest.mark.parametrize("port", [80, 8443])
@pytest.mark.parametrize("entry", ["service", "adapter"])
async def test_contradictory_verified_cleartext_refused_before_transport(
    vendor, port, entry, transport_capture
):
    if entry == "service":
        result = await GatewayService(None).test_connection(
            vendor,
            "192.168.77.77",
            port,
            True,
            api_key="owned-key",
            api_secret="owned-secret",
            username="owned-user",
            password="owned-secret",
            use_ssl=False,
        )
        assert result["success"] is False
        assert result["message"] == "An unexpected error occurred"
        assert result["vendor"] == vendor
    else:
        with pytest.raises(ValueError, match="Certificate verification requires HTTPS"):
            await exercise(vendor, port, True, entry, transport_capture, use_ssl=False)
    requests, clients, adapters = transport_capture
    assert not requests and not clients and not adapters


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", ["mikrotik", "pfsense"])
@pytest.mark.parametrize("port", [80, 8443])
@pytest.mark.parametrize("entry", ["service", "adapter"])
async def test_deliberate_unverified_cleartext_compatibility(
    vendor, port, entry, transport_capture
):
    requests = await exercise(vendor, port, False, entry, transport_capture, use_ssl=False)
    assert all(request.url.scheme == "http" for request in requests)
