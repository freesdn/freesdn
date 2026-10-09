"""Actual client read contracts with synthetic, pinned-upstream-shaped payloads."""

import copy
import json
from pathlib import Path

import httpx
import pytest

from app.adapters.opnsense.adapter import OPNsenseAdapter

FIXTURE = json.loads(
    (Path(__file__).parents[1] / "fixtures/opnsense_remaining_inventory_contracts.json").read_text()
)
FAMILIES = {
    "servers": "Servers",
    "backends": "Backends",
    "frontends": "Frontends",
    "acls": "Acls",
    "actions": "Actions",
}


def recordset(rows):
    return {"rows": rows, "total": len(rows), "rowCount": len(rows), "current": 1}


def haproxy_wire():
    return {
        f"/api/haproxy/settings/search{suffix}": recordset(
            [copy.deepcopy(FIXTURE["haproxy_rows"][name])]
        )
        for name, suffix in FAMILIES.items()
    }


def vpn_wire(*, aliases=True):
    wire = copy.deepcopy(FIXTURE["vpn"])
    if aliases:
        # This explicit synthetic alias isolates schema regressions from the
        # separately tested endpoint defect; it is not an upstream support claim.
        wire["/api/ipsec/sessions/searchSad"] = copy.deepcopy(wire["/api/ipsec/sad/search"])
        wire["/api/ipsec/sessions/searchSpd"] = copy.deepcopy(wire["/api/ipsec/spd/search"])
    return wire


def summary_wire():
    wire = copy.deepcopy(FIXTURE["device_summary"])
    # Isolate semantic summary failures without hiding the endpoint regression.
    wire["/api/core/system/status"] = {"name": "legacy-wrong-endpoint", "uptime": "legacy-time"}
    return wire


async def read(method, wire):
    adapter = OPNsenseAdapter(
        host="192.0.2.99", username="owned", password="owned", verify_ssl=True
    )
    adapter._api.max_retries = 1
    requests = []

    async def respond(request):
        path = request.url.path
        requests.append((request.method, path))
        assert request.method == "GET" or "/search" in path, "No write route is permitted"
        if path not in wire:
            return httpx.Response(404, json={"message": "unsupported fixture endpoint"})
        body = wire[path]
        if isinstance(body, BaseException):
            raise body
        return httpx.Response(200, json=body)

    adapter._api._client = httpx.AsyncClient(
        base_url=adapter._api.base_url, transport=httpx.MockTransport(respond)
    )
    try:
        return await getattr(adapter, method)(), requests
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
@pytest.mark.parametrize("family", FAMILIES)
async def test_haproxy_complete_empty_and_populated_inventories(family):
    wire = haproxy_wire()
    result, _ = await read(f"get_haproxy_{family}", wire)
    assert result.success
    assert len(result.data[family]) == result.data["count"] == 1
    assert result.data[family][0]["uuid"] == FIXTURE["haproxy_rows"][family]["uuid"]
    wire[f"/api/haproxy/settings/search{FAMILIES[family]}"] = recordset([])
    empty, _ = await read(f"get_haproxy_{family}", wire)
    assert empty.success and empty.data[family] == [] and empty.data["count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        [],
        {"rows": []},
        {"rows": [], "total": 2, "rowCount": 0, "current": 1},
        {"rows": [None], "total": 1, "rowCount": 1, "current": 1},
        {"rows": [{}], "total": 1, "rowCount": 1, "current": 1},
        {"rows": [], "total": 0, "rowCount": 0, "current": 2},
    ],
)
async def test_haproxy_invalid_component_cannot_be_successful_empty_inventory(family, bad):
    wire = haproxy_wire()
    wire[f"/api/haproxy/settings/search{FAMILIES[family]}"] = copy.deepcopy(bad)
    direct, _ = await read(f"get_haproxy_{family}", wire)
    aggregate, _ = await read("get_haproxy_status", wire)
    assert not direct.success and not aggregate.success


@pytest.mark.asyncio
@pytest.mark.parametrize("family", FAMILIES)
async def test_haproxy_duplicate_identity_is_unavailable(family):
    wire = haproxy_wire()
    row = FIXTURE["haproxy_rows"][family]
    wire[f"/api/haproxy/settings/search{FAMILIES[family]}"] = recordset(
        [copy.deepcopy(row), copy.deepcopy(row)]
    )
    result, _ = await read("get_haproxy_status", wire)
    assert not result.success


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "family,key",
    [
        ("servers", "ssl"),
        ("servers", "sslVerify"),
        ("backends", "enabled"),
        ("backends", "healthCheckEnabled"),
        ("backends", "basicAuthEnabled"),
        ("frontends", "enabled"),
        ("frontends", "ssl_enabled"),
        ("frontends", "forwardFor"),
        ("acls", "negate"),
    ],
)
@pytest.mark.parametrize("bad", ["unknown", None, {}, 2])
async def test_haproxy_unknown_flag_does_not_become_false(family, key, bad):
    wire = haproxy_wire()
    wire[f"/api/haproxy/settings/search{FAMILIES[family]}"]["rows"][0][key] = bad
    result, _ = await read(f"get_haproxy_{family}", wire)
    assert not result.success


VPN_INVENTORIES = [
    "/api/wireguard/client/searchClient",
    "/api/wireguard/server/searchServer",
    "/api/openvpn/instances/search",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", VPN_INVENTORIES)
@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"rows": []},
        {"rows": [], "total": 1001, "rowCount": 1000, "current": 1},
        {"rows": [None], "total": 1, "rowCount": 1, "current": 1},
        {"rows": [], "total": 0, "rowCount": 0, "current": 2},
    ],
)
async def test_vpn_incomplete_inventories_are_unavailable(endpoint, bad):
    wire = vpn_wire()
    wire[endpoint] = copy.deepcopy(bad)
    result, _ = await read("get_vpn_status", wire)
    assert not result.success


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,expected",
    [
        ("get_vpn_status", {"/api/ipsec/sad/search"}),
        ("get_ipsec_status", {"/api/ipsec/sad/search", "/api/ipsec/spd/search"}),
    ],
)
async def test_current_ipsec_read_endpoints(method, expected):
    result, calls = await read(method, vpn_wire(aliases=False))
    assert result.success
    paths = {path for _, path in calls}
    assert expected <= paths
    assert not any("/sessions/search" in path for path in paths)


@pytest.mark.asyncio
async def test_vpn_success_does_not_return_private_key_material():
    result, _ = await read("get_vpn_status", vpn_wire())
    assert result.success
    assert "owned-private-secret" not in json.dumps(result.data)


@pytest.mark.asyncio
async def test_summary_uses_documented_identity_time_version_and_interface_list():
    result, calls = await read("get_device_summary", copy.deepcopy(FIXTURE["device_summary"]))
    assert result.success
    assert result.data["hostname"] == "owned-fw.example.test"
    assert result.data["uptime_text"] == "1 day"
    assert result.data["version"] == "26.7"
    assert result.data["interface_count"] == 2
    assert result.data["interfaces_up"] == 1
    assert result.data["interfaces_down"] == 1
    assert ("GET", "/api/core/system/status") not in calls


@pytest.mark.asyncio
async def test_summary_reports_firewall_address_and_active_default_gateway_not_first_router():
    result, _ = await read("get_device_summary", summary_wire())
    assert result.success
    assert result.data["wan_ip"] == "192.0.2.20"
    assert result.data["wan_gateway"] == "192.0.2.1"
    assert result.data["wan_status"] == "online"
    assert result.data["wan_loss_pct"] == result.data["wan_delay_ms"] == 0


@pytest.mark.asyncio
async def test_summary_does_not_invent_uncollected_counts_or_unchecked_update_state():
    result, _ = await read("get_device_summary", summary_wire())
    assert result.success
    for name in [
        "services_running",
        "services_stopped",
        "vpn_tunnels_up",
        "vpn_tunnels_total",
        "firewall_rule_count",
        "ids_alerts_24h",
        "firmware_update_available",
    ]:
        assert result.data.get(name) is None, name


@pytest.mark.asyncio
async def test_summary_unmonitored_status_and_measurements_are_not_online_zero():
    wire = summary_wire()
    wire["/api/routes/gateway/status"]["items"][1].update(
        status="none", status_translated="Online", loss="~", delay="~"
    )
    result, _ = await read("get_device_summary", wire)
    assert result.success
    assert result.data["wan_status"] == "none"
    assert result.data.get("wan_loss_pct") is None
    assert result.data.get("wan_delay_ms") is None


@pytest.mark.asyncio
async def test_summary_unknown_interface_state_is_not_counted_down():
    wire = summary_wire()
    wire["/api/interfaces/overview/export"][1]["status"] = "owned-unknown-state"
    result, _ = await read("get_device_summary", wire)
    assert result.success
    assert result.data["interfaces_up"] == 1 and result.data["interfaces_down"] == 0
    assert result.data["interfaces_unknown"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad", [None, {}, "invalid", [None], [{"identifier": "wan", "status": None}]]
)
async def test_summary_malformed_interface_data_is_unavailable(bad):
    wire = summary_wire()
    wire["/api/interfaces/overview/export"] = bad
    result, _ = await read("get_device_summary", wire)
    assert not result.success


@pytest.mark.asyncio
async def test_summary_reported_gateway_failure_is_unavailable():
    wire = summary_wire()
    wire["/api/routes/gateway/status"] = {"status": "failed", "items": []}
    result, _ = await read("get_device_summary", wire)
    assert not result.success
