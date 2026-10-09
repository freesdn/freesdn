"""Fresh PostgreSQL/ASGI reads with synthetic identity and vendor HTTP responses."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio

from app.adapters.base import AdapterResult
from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.modules.firewall.gateway_service import adapter_registry
from tests.adapters import test_opnsense_system_health_contracts as vendor
from tests.modules import test_gateway_aggregate_availability as helpers

trigger = helpers.trigger
ROUTES = {"firmware": "get_firmware_info", "health": "get_gateway_status"}
SECRET = "owned-system-health-private-error"


@pytest_asyncio.fixture
async def system_wire(trigger, monkeypatch):
    trigger.permissions.append("firewall.view")
    state = {"wire": vendor.wire(), "faults": {}, "requests": [], "constructs": 0, "results": {}}
    adapters = []

    async def respond(request):
        path = request.url.path
        state["requests"].append((request.method, path))
        assert request.method == "GET"
        fault = state["faults"].get(path)
        if fault == "transport":
            raise httpx.ReadTimeout(SECRET)
        if fault == "cancelled":
            raise asyncio.CancelledError(SECRET)
        if fault == "provider":
            return httpx.Response(200, json={"status": "error", "message": SECRET})
        if path not in state["wire"]:
            return httpx.Response(404, json={"message": "unsupported fixture route"})
        return httpx.Response(200, json=state["wire"][path])

    def create(**_kwargs):
        state["constructs"] += 1
        adapter = OPNsenseAdapter(host="192.0.2.99", username="owned", password="owned")
        adapter._api.max_retries = 1
        adapter._api._client = httpx.AsyncClient(
            base_url=adapter._api.base_url, transport=httpx.MockTransport(respond)
        )
        adapter.connect = AsyncMock(return_value=True)
        for method, value in state["results"].items():
            setattr(adapter, method, AsyncMock(return_value=value))
        adapters.append(adapter)
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    try:
        yield state
    finally:
        for adapter in adapters:
            await adapter.disconnect()


async def unchanged_request(trigger, route):
    before = await helpers.snapshot(trigger)
    result = await helpers.request(trigger, route)
    assert await helpers.snapshot(trigger) == before
    return result


@pytest.mark.parametrize("route", ROUTES)
async def test_real_parser_envelope_reaches_the_selected_gateway(trigger, system_wire, route):
    system_wire["wire"][vendor.HEALTH]["items"][0]["status"] = "none"
    response = await unchanged_request(trigger, route)
    assert response.status_code == 200
    body = response.json()
    assert body["gateway_id"] == str(trigger.gateway.id) and body["vendor"] == "opnsense"
    if route == "firmware":
        assert body["firmware"]["current_version"] == "26.7"
        assert body["firmware"].get("update_available") is None
    else:
        row = body["gateways"][0]
        assert row["status"] == "online" and row["default_gateway"] is True
        assert row["loss_pct"] == row["delay_ms"] == 0


@pytest.mark.parametrize(
    "route,path",
    [("firmware", vendor.FIRMWARE), ("health", vendor.HEALTH), ("health", vendor.ROUTING)],
)
@pytest.mark.parametrize("fault", ["provider", "transport"])
async def test_component_failure_is_unavailable_and_not_leaked(
    trigger, system_wire, route, path, fault, caplog
):
    system_wire["faults"][path] = fault
    response = await unchanged_request(trigger, route)
    assert response.status_code == 502 and response.json() == {
        "detail": "Gateway status is unavailable"
    }
    assert SECRET not in response.text and SECRET not in caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.parametrize(
    "route,path",
    [("firmware", vendor.FIRMWARE), ("health", vendor.HEALTH), ("health", vendor.ROUTING)],
)
async def test_read_cancellation_propagates_without_database_changes(
    trigger, system_wire, route, path
):
    system_wire["faults"][path] = "cancelled"
    before = await helpers.snapshot(trigger)
    with pytest.raises(asyncio.CancelledError):
        await helpers.request(trigger, route)
    assert await helpers.snapshot(trigger) == before


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("code", ["NOT_SUPPORTED", "NOT_IMPLEMENTED"])
async def test_explicit_unsupported_reads_have_a_generic_501(trigger, system_wire, route, code):
    system_wire["results"][ROUTES[route]] = AdapterResult.fail(SECRET, error_code=code)
    response = await unchanged_request(trigger, route)
    assert response.status_code == 501
    assert response.json() == {"detail": "This gateway read is not supported"}
    assert SECRET not in response.text


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("data", [{}, None, [], {"count": 0}, {"gateways": [], "count": False}])
async def test_incomplete_normalized_envelope_cannot_be_empty_success(
    trigger, system_wire, route, data
):
    system_wire["results"][ROUTES[route]] = AdapterResult.ok(data)
    response = await unchanged_request(trigger, route)
    assert response.status_code == 502


async def test_firmware_refresh_reads_again_and_does_not_serve_previous_success(
    trigger, system_wire
):
    first = await unchanged_request(trigger, "firmware")
    assert first.status_code == 200
    system_wire["faults"][vendor.FIRMWARE] = "provider"
    second = await unchanged_request(trigger, "firmware")
    assert second.status_code == 502 and "26.7" not in second.text
    assert system_wire["constructs"] == 2
    del system_wire["faults"][vendor.FIRMWARE]
    system_wire["wire"][vendor.FIRMWARE]["status"] = "update"
    third = await unchanged_request(trigger, "firmware")
    assert third.status_code == 200 and third.json()["firmware"]["update_available"] is True
    assert system_wire["constructs"] == 3


@pytest.mark.parametrize("route", ROUTES)
async def test_live_scope_is_rechecked_after_success(trigger, system_wire, route):
    assert (await unchanged_request(trigger, route)).status_code == 200
    trigger.gateway.deleted_at = datetime.now(UTC)
    await trigger.db.flush()
    before = system_wire["constructs"]
    response = await unchanged_request(trigger, route)
    assert response.status_code == 404 and system_wire["constructs"] == before
