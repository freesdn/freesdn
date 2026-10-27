"""Standalone gateway checks own their adapter lifetime, including cancellation."""

import asyncio
import json

import httpx
import pytest
import pytest_asyncio

from app.adapters.base import AdapterResult
from app.adapters.mikrotik import client as mikrotik
from app.adapters.openwrt import client as openwrt
from app.adapters.opnsense import client as opnsense
from app.adapters.pfsense import client as pfsense
from app.modules.firewall.gateway_service import GatewayService, adapter_registry
from tests.harness_wait import HARNESS_WAIT_SECONDS

MODULES = {"opnsense": opnsense, "pfsense": pfsense, "mikrotik": mikrotik, "openwrt": openwrt}


@pytest_asyncio.fixture
async def owned_clients(monkeypatch):
    state = {
        "scenario": "success",
        "clients": [],
        "adapters": [],
        "ready": asyncio.Event(),
        "disconnects": 0,
        "cleanup_raises": False,
    }
    original_create = adapter_registry.create_adapter

    async def respond(request):
        if state["scenario"] == "cancel":
            state["ready"].set()
            await asyncio.Event().wait()
        path = request.url.path
        rpc = json.loads(request.content) if path == "/ubus" else None
        login = rpc is not None and rpc["params"][1:3] == ["session", "login"]
        if not login:
            if state["scenario"] == "auth-refused":
                return httpx.Response(401, json={"error": "owned-auth-refused"})
            if state["scenario"] == "transport-error":
                raise httpx.ReadError("owned-transport-error", request=request)
        if rpc:
            _, obj, action, _ = rpc["params"]
            data = {
                ("session", "login"): {"ubus_rpc_session": "owned-session"},
                ("system", "board"): {
                    "hostname": "owned-openwrt",
                    "release": {"version": "fixture"},
                },
                ("system", "info"): {"uptime": 1},
                ("rpc-sys", "packagelist"): {"packages": {}},
            }[(obj, action)]
            payload = {"jsonrpc": "2.0", "id": rpc["id"], "result": [0, data]}
        else:
            payload = {
                "/api/core/system/status": {"name": "owned-opnsense", "product_version": "fixture"},
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
        state["clients"].append(client)
        return client

    def create(*args, **kwargs):
        adapter = original_create(*args, **kwargs)
        state["adapters"].append(adapter)
        if state["scenario"] in {"exception", "malformed"}:

            async def substitute():
                await adapter._api.connect()
                if state["scenario"] == "exception":
                    raise RuntimeError("owned-test-exception")
                return AdapterResult.ok(data={"identity": []})

            adapter.test_connection = substitute
        if state["cleanup_raises"]:
            disconnect = adapter.disconnect

            async def broken_cleanup():
                state["disconnects"] += 1
                await disconnect()
                raise OSError("owned-cleanup-diagnostic-not-for-service-log")

            adapter.disconnect = broken_cleanup
        return adapter

    for module in MODULES.values():
        monkeypatch.setattr(module, "build_async_client", build)
    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    try:
        yield state
    finally:
        # Assertions happen before this fallback cleanup of old-code failures.
        for client in state["clients"]:
            await client.aclose()


async def check_gateway(vendor):
    return await GatewayService(None).test_connection(
        vendor,
        "192.168.77.77",
        8443,
        True,
        api_key="owned-key",
        api_secret="owned-secret",
        username="owned-user",
        password="owned-secret",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", list(MODULES))
@pytest.mark.parametrize(
    "scenario", ["success", "auth-refused", "transport-error", "exception", "malformed"]
)
async def test_standalone_gateway_closes_owned_clients(vendor, scenario, owned_clients):
    owned_clients["scenario"] = scenario
    result = await check_gateway(vendor)
    assert result["success"] is (scenario == "success")
    assert owned_clients["clients"]
    assert all(client.is_closed for client in owned_clients["clients"])


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", list(MODULES))
async def test_cancelled_gateway_check_closes_client_and_preserves_cancellation(
    vendor, owned_clients
):
    owned_clients["scenario"] = "cancel"
    task = asyncio.create_task(check_gateway(vendor))
    try:
        await asyncio.wait_for(owned_clients["ready"].wait(), HARNESS_WAIT_SECONDS)
        task.cancel("owned-cancel")
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled()
        assert owned_clients["clients"]
        assert all(client.is_closed for client in owned_clients["clients"])
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", list(MODULES))
@pytest.mark.parametrize("cancelled", [False, True])
async def test_cleanup_exception_does_not_replace_original_outcome(
    vendor, cancelled, owned_clients, caplog
):
    owned_clients["cleanup_raises"] = True
    owned_clients["scenario"] = "cancel" if cancelled else "success"
    task = asyncio.create_task(check_gateway(vendor))
    try:
        if cancelled:
            await asyncio.wait_for(owned_clients["ready"].wait(), HARNESS_WAIT_SECONDS)
            task.cancel("owned-cancel")
            with pytest.raises(asyncio.CancelledError):
                await task
            assert task.cancelled()
        else:
            assert (await task)["success"]
        assert owned_clients["disconnects"] == 1
        assert all(client.is_closed for client in owned_clients["clients"])
        assert "owned-cleanup-diagnostic-not-for-service-log" not in caplog.text
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
