"""Vendor HTTP normalization through real PostgreSQL/ASGI with no device writes."""

import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio

from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.modules.firewall.gateway_service import adapter_registry
from tests.adapters import test_opnsense_remaining_inventory_contracts as vendor
from tests.modules import test_gateway_aggregate_availability as helpers

trigger = helpers.trigger
SUMMARY = vendor.FIXTURE["device_summary"]
SUMMARY_PATHS = tuple(SUMMARY)
ROUTING = "/api/routing/settings/search_gateway"
GATEWAYS = "/api/routes/gateway/status"
INTERFACES = "/api/interfaces/overview/export"
FIRMWARE = "/api/core/firmware/status"
SECRET = "owned-private-inventory-diagnostic"


@pytest_asyncio.fixture
async def remaining_wire(trigger, monkeypatch):
    trigger.permissions.append("firewall.view")
    adapter = OPNsenseAdapter(host="192.0.2.99", username="owned", password="owned")
    adapter._api.max_retries = 1
    state = {"wire": {}, "faults": {}, "requests": []}

    async def respond(request):
        path = request.url.path
        state["requests"].append((request.method, path))
        assert request.method == "GET" or "/search" in path
        fault = state["faults"].get(path)
        if fault == "transport":
            raise httpx.ReadTimeout(SECRET)
        if fault == "cancelled":
            raise asyncio.CancelledError(SECRET)
        if fault == "provider":
            return httpx.Response(200, json={"status": "failed", "message": SECRET})
        if path not in state["wire"]:
            return httpx.Response(404, json={"message": "unsupported fixture route"})
        return httpx.Response(200, json=state["wire"][path])

    adapter._api._client = httpx.AsyncClient(
        base_url=adapter._api.base_url, transport=httpx.MockTransport(respond)
    )
    adapter.connect = AsyncMock(return_value=True)
    monkeypatch.setattr(adapter_registry, "create_adapter", lambda **_kwargs: adapter)
    try:
        yield state
    finally:
        await adapter.disconnect()


async def request_unchanged(trigger, route):
    before = await helpers.snapshot(trigger)
    response = await helpers.request(trigger, route)
    assert await helpers.snapshot(trigger) == before
    return response


@pytest.mark.parametrize(
    "route", ["haproxy", "haproxy/servers", "haproxy/backends", "haproxy/frontends", "vpn"]
)
async def test_complete_vendor_inventory_survives_API(trigger, remaining_wire, route):
    state = remaining_wire
    state["wire"] = vendor.vpn_wire(aliases=False) if route == "vpn" else vendor.haproxy_wire()
    response = await request_unchanged(trigger, route)
    assert response.status_code == 200
    data = response.json()
    assert data["gateway_id"] == str(trigger.gateway.id) and data["vendor"] == "opnsense"
    if route == "vpn":
        assert "owned-private-secret" not in response.text
        assert data["tunnels"]["wireguard"]["peers"]["total"] == 1
    elif route == "haproxy":
        assert all(data["haproxy"][name][0]["uuid"] for name in vendor.FAMILIES)
    else:
        assert data["count"] == len(data[route.split("/")[1]]) == 1


@pytest.mark.parametrize(
    "scenario",
    [
        "observed",
        "unknown-interface",
        "unmonitored",
        "missing-samples",
        "no-default",
        "disabled-default",
        "ambiguous-default",
        "ipv6-default",
        "checked-current",
        "update",
        "firmware-error",
    ],
)
async def test_summary_observations_survive_API(trigger, remaining_wire, scenario):
    wire = remaining_wire["wire"] = vendor.summary_wire()
    if scenario == "unknown-interface":
        wire[INTERFACES][1]["status"] = "unknown"
    elif scenario == "unmonitored":
        wire[GATEWAYS]["items"][1].update(
            status="none", status_translated="Online", loss="~", delay="~"
        )
    elif scenario == "missing-samples":
        for key in ["loss", "delay"]:
            wire[GATEWAYS]["items"][1].pop(key)
    elif scenario == "no-default":
        wire[ROUTING]["rows"][0]["defaultgw"] = False
    elif scenario == "disabled-default":
        wire[ROUTING]["rows"][0]["disabled"] = True
    elif scenario == "ambiguous-default":
        extra = {**wire[ROUTING]["rows"][0], "uuid": "owned-other", "name": "OTHER_GW"}
        wire[ROUTING] = vendor.recordset([*wire[ROUTING]["rows"], extra])
    elif scenario == "ipv6-default":
        wire[ROUTING]["rows"][0].update(ipprotocol="inet6", gateway="2001:db8::1")
        wire[INTERFACES][0]["addr6"] = "2001:db8::20/64"
    elif scenario == "checked-current":
        wire[FIRMWARE]["product"]["product_check"] = {"version": "26.7"}
    elif scenario == "update":
        wire[FIRMWARE]["status"] = "update"
    elif scenario == "firmware-error":
        wire[FIRMWARE]["status"] = "error"
    response = await request_unchanged(trigger, "device-summary")
    assert response.status_code == 200
    data = response.json()["summary"]
    assert data["hostname"] == "owned-fw.example.test" and data["version"] == "26.7"
    assert data["interface_count"] == 2
    assert data["interfaces_up"] + data["interfaces_down"] + data["interfaces_unknown"] == 2
    assert data["interfaces_unknown"] == int(scenario == "unknown-interface")
    if scenario in {"no-default", "disabled-default", "ambiguous-default"}:
        assert data["wan_selection"] == ("ambiguous" if scenario == "ambiguous-default" else "none")
        assert data["wan_status"] == "unknown"
        assert data.get("wan_ip") is None and data.get("wan_gateway") is None
    else:
        assert data["wan_selection"] == "active_default"
        assert data["wan_ip"] == ("2001:db8::20" if scenario == "ipv6-default" else "192.0.2.20")
    if scenario in {
        "unmonitored",
        "missing-samples",
        "no-default",
        "disabled-default",
        "ambiguous-default",
    }:
        assert data.get("wan_loss_pct") is None and data.get("wan_delay_ms") is None
    else:
        assert data["wan_loss_pct"] == data["wan_delay_ms"] == 0
    if scenario == "unmonitored":
        assert data["wan_status"] == "none"
    expected_update = (
        False if scenario == "checked-current" else True if scenario == "update" else None
    )
    assert data.get("firmware_update_available") is expected_update
    assert all(
        data.get(field) is None
        for field in ["services_running", "services_stopped", "vpn_tunnels_up", "vpn_tunnels_total"]
    )


COMPONENTS = [("device-summary", path) for path in SUMMARY_PATHS]
COMPONENTS += [("haproxy", path) for path in vendor.haproxy_wire()]
COMPONENTS += [("vpn", path) for path in vendor.vpn_wire(aliases=False) if "/spd/" not in path]


@pytest.mark.parametrize("route,path", COMPONENTS)
@pytest.mark.parametrize("fault", ["transport", "provider"])
async def test_required_read_failure_is_generic_and_does_not_mutate_DB(
    trigger, remaining_wire, route, path, fault, caplog
):
    state = remaining_wire
    state["wire"] = (
        vendor.summary_wire()
        if route == "device-summary"
        else vendor.haproxy_wire()
        if route == "haproxy"
        else vendor.vpn_wire()
    )
    state["faults"][path] = fault
    response = await request_unchanged(trigger, route)
    assert response.status_code == 502
    assert response.json() == {"detail": "Gateway status is unavailable"}
    assert SECRET not in response.text and SECRET not in caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.parametrize("path", SUMMARY_PATHS)
async def test_summary_required_component_cancellation_is_not_swallowed(
    trigger, remaining_wire, path
):
    state = remaining_wire
    state["wire"] = vendor.summary_wire()
    state["faults"][path] = "cancelled"
    before = await helpers.snapshot(trigger)
    with pytest.raises(asyncio.CancelledError):
        await helpers.request(trigger, "device-summary")
    assert await helpers.snapshot(trigger) == before


@pytest.mark.parametrize("path", [*vendor.VPN_INVENTORIES, *vendor.haproxy_wire()])
async def test_truncated_inventory_is_not_published_as_complete(trigger, remaining_wire, path):
    route = "haproxy" if "/haproxy/" in path else "vpn"
    state = remaining_wire
    state["wire"] = vendor.haproxy_wire() if route == "haproxy" else vendor.vpn_wire()
    state["wire"][path]["total"] += 1
    response = await request_unchanged(trigger, route)
    assert response.status_code == 502
    assert response.json() == {"detail": "Gateway status is unavailable"}
