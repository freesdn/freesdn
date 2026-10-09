"""Aggregate failure truth with the real OPNsense client and synthetic HTTP IO.

All controls use reviewed upstream response contracts. These cases do not establish
physical firmware compatibility.
"""

import asyncio
import json
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from app.adapters.opnsense.adapter import OPNsenseAdapter

PATHS = {
    "get_crowdsec_status": [
        "/api/crowdsec/service/status",
        "/api/crowdsec/alerts/searchAlert",
        "/api/crowdsec/decisions/searchDecision",
    ],
    "get_device_summary": [
        "/api/core/system/status",
        "/api/core/firmware/status",
        "/api/routes/gateway/status",
        "/api/interfaces/overview/export",
    ],
    "get_haproxy_status": [
        "/api/haproxy/settings/searchServers",
        "/api/haproxy/settings/searchBackends",
        "/api/haproxy/settings/searchFrontends",
        "/api/haproxy/settings/searchAcls",
        "/api/haproxy/settings/searchActions",
    ],
    "get_monit_status": [
        "/api/monit/settings/searchService",
        "/api/monit/settings/searchTest",
        "/api/monit/settings/searchAlert",
        "/api/monit/service/status",
    ],
    "get_netflow_status": ["/api/netflow/settings/get", "/api/netflow/service/status"],
    "get_proxy_settings": ["/api/proxy/settings/get", "/api/proxy/service/status"],
    "get_tailscale_status": ["/api/tailscale/settings/get", "/api/tailscale/service/status"],
    "get_telegraf_status": ["/api/telegraf/settings/get", "/api/telegraf/service/status"],
    "get_vpn_status": [
        "/api/wireguard/general/get",
        "/api/wireguard/client/searchClient",
        "/api/wireguard/server/searchServer",
        "/api/openvpn/export/providers",
        "/api/openvpn/instances/search",
        "/api/ipsec/sessions/searchSad",
    ],
}
WIRE_CONTRACTS = json.loads(
    (Path(__file__).parents[1] / "fixtures/opnsense_plugin_read_contracts.json").read_text()
)
WIRE = {path: body for fixture in WIRE_CONTRACTS.values() for path, body in fixture["wire"].items()}
for fixture in WIRE_CONTRACTS.values():
    PATHS[fixture["method"]] = list(fixture["wire"])

REMAINING = json.loads(
    (Path(__file__).parents[1] / "fixtures/opnsense_remaining_inventory_contracts.json").read_text()
)
WIRE.update(REMAINING["device_summary"])
PATHS["get_device_summary"] = list(REMAINING["device_summary"])
WIRE.update(REMAINING["vpn"])
PATHS["get_vpn_status"] = [path for path in REMAINING["vpn"] if path != "/api/ipsec/spd/search"]
PATHS["get_ipsec_status"] = ["/api/ipsec/sad/search", "/api/ipsec/spd/search"]
for family, suffix in {
    "servers": "Servers",
    "backends": "Backends",
    "frontends": "Frontends",
    "acls": "Acls",
    "actions": "Actions",
}.items():
    WIRE[f"/api/haproxy/settings/search{suffix}"] = {
        "rows": [REMAINING["haproxy_rows"][family]],
        "total": 1,
        "rowCount": 1,
        "current": 1,
    }

MARKER = "owned-synthetic-aggregate-provider-private-diagnostic"


@pytest_asyncio.fixture
async def wire():
    adapter = OPNsenseAdapter(
        host="192.0.2.99", username="owned", password="owned", verify_ssl=True
    )
    adapter._api.max_retries = 1
    state = {"faults": {}, "requests": []}

    async def response(request):
        path = request.url.path
        state["requests"].append(path)
        fault = state["faults"].get(path)
        if fault == "cancelled":
            raise asyncio.CancelledError(MARKER)
        if fault == "timeout":
            raise httpx.ReadTimeout(MARKER)
        if isinstance(fault, int):
            return httpx.Response(fault, json={"message": MARKER})
        return httpx.Response(200, json=WIRE.get(path, {}))

    adapter._api._client = httpx.AsyncClient(
        base_url=adapter._api.base_url, transport=httpx.MockTransport(response)
    )
    try:
        yield adapter, state
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("method", PATHS)
async def test_successful_components_keep_existing_parser_behavior(wire, method):
    adapter, state = wire
    result = await getattr(adapter, method)()
    assert result.success is True
    assert sorted(state["requests"]) == sorted(PATHS[method])


@pytest.mark.parametrize("method", PATHS)
@pytest.mark.parametrize("fault", [403, 503, "timeout", "cancelled"])
async def test_all_failed_reads_never_report_success_and_cancellation_propagates(
    wire, method, fault
):
    adapter, state = wire
    state["faults"] = dict.fromkeys(PATHS[method], fault)
    if fault == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            await getattr(adapter, method)()
    else:
        result = await getattr(adapter, method)()
        assert result.success is False and result.data is None
        assert MARKER not in str(result)


@pytest.mark.parametrize("method,path", [(m, p) for m, paths in PATHS.items() for p in paths])
@pytest.mark.parametrize("fault", [503, "cancelled"])
async def test_one_failed_required_component_is_not_replaced_by_empty_success(
    wire, method, path, fault
):
    adapter, state = wire
    state["faults"] = {path: fault}
    if fault == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            await getattr(adapter, method)()
    else:
        result = await getattr(adapter, method)()
        assert result.success is False and result.data is None
        assert MARKER not in str(result)
    assert sorted(state["requests"]) == sorted(PATHS[method])


@pytest.mark.parametrize("method", PATHS)
@pytest.mark.parametrize("reverse", [False, True])
async def test_cancellation_wins_over_another_component_failure_in_either_order(
    wire, method, reverse
):
    adapter, state = wire
    first, second = PATHS[method][:2]
    state["faults"] = {
        first: 503 if reverse else "cancelled",
        second: "cancelled" if reverse else 503,
    }
    with pytest.raises(asyncio.CancelledError):
        await getattr(adapter, method)()


@pytest.mark.parametrize("method", PATHS)
async def test_failed_aggregate_does_not_log_provider_body_or_traceback(wire, method, caplog):
    adapter, state = wire
    state["faults"] = dict.fromkeys(PATHS[method], "timeout")
    result = await getattr(adapter, method)()
    assert result.success is False and result.data is None
    assert MARKER not in caplog.text and "Traceback" not in caplog.text
