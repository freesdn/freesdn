"""Read contracts from pinned upstream controllers, with synthetic HTTP only.

These fixtures establish parser behavior, not deployed firmware acceptance.
"""

import asyncio
import copy
import json
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from app.adapters.opnsense.adapter import OPNsenseAdapter

FIXTURES = json.loads(
    (Path(__file__).parents[1] / "fixtures/opnsense_plugin_read_contracts.json").read_text()
)
COMPONENTS = [(kind, path) for kind, fixture in FIXTURES.items() for path in fixture["wire"]]
MARKER = "owned-private-wire-diagnostic"


@pytest_asyncio.fixture
async def wire():
    adapter = OPNsenseAdapter(
        host="192.0.2.99", username="owned", password="owned", verify_ssl=True
    )
    adapter._api.max_retries = 1
    state = {"wire": {}, "faults": {}, "requests": []}

    async def response(request):
        path = request.url.path
        state["requests"].append((request.method, path))
        fault = state["faults"].get(path)
        if fault == "cancelled":
            raise asyncio.CancelledError(MARKER)
        if fault == "unavailable":
            return httpx.Response(503, json={"message": MARKER})
        if path not in state["wire"]:
            return httpx.Response(404, json={"message": "Unknown fixture endpoint"})
        return httpx.Response(200, json=state["wire"][path])

    adapter._api._client = httpx.AsyncClient(
        base_url=adapter._api.base_url, transport=httpx.MockTransport(response)
    )
    try:
        yield adapter, state
    finally:
        await adapter.disconnect()


def configure(state, kind):
    state["wire"] = copy.deepcopy(FIXTURES[kind]["wire"])


async def call(wire, kind):
    return await getattr(wire[0], FIXTURES[kind]["method"])()


@pytest.mark.parametrize("kind", FIXTURES)
@pytest.mark.parametrize("running", [True, False])
async def test_documented_wire_data_and_service_states(wire, kind, running):
    _, state = wire
    configure(state, kind)
    status = next(path for path in state["wire"] if path.endswith("/status"))
    state["wire"][status] = {
        "status": ("active" if running else "inactive")
        if kind == "netflow"
        else ("running" if running else "stopped")
    }
    result = await call(wire, kind)
    assert result.success is True
    body = result.data[kind]
    for key, value in FIXTURES[kind]["expected"].items():
        assert body[key] == (running if key == "running" else value)
    assert sorted(path for _, path in state["requests"]) == sorted(state["wire"])
    assert all(
        method == ("POST" if "/search" in path else "GET") for method, path in state["requests"]
    )


@pytest.mark.parametrize("kind", FIXTURES)
@pytest.mark.parametrize("status", [None, {}, [], "unknown", "unkown", "starting", True, 1])
async def test_unknown_service_state_is_unavailable_not_stopped(wire, kind, status):
    _, state = wire
    configure(state, kind)
    path = next(path for path in state["wire"] if path.endswith("/status"))
    state["wire"][path] = {"status": status}
    result = await call(wire, kind)
    assert result.success is False and result.data is None


@pytest.mark.parametrize("kind,path", COMPONENTS)
@pytest.mark.parametrize("body", [None, {}, []])
async def test_required_component_schema_is_not_invented(wire, kind, path, body):
    _, state = wire
    configure(state, kind)
    state["wire"][path] = body
    result = await call(wire, kind)
    assert result.success is False and result.data is None


@pytest.mark.parametrize("kind,path", COMPONENTS)
@pytest.mark.parametrize("fault", ["unavailable", "cancelled"])
async def test_each_required_read_fails_safely_and_cancellation_propagates(
    wire, kind, path, fault, caplog
):
    _, state = wire
    configure(state, kind)
    state["faults"][path] = fault
    if fault == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            await call(wire, kind)
    else:
        result = await call(wire, kind)
        assert result.success is False and result.data is None
    assert MARKER not in caplog.text and "Traceback" not in caplog.text
    assert sorted(path for _, path in state["requests"]) == sorted(state["wire"])


@pytest.mark.parametrize("selected", [0, "0", 1, "1"])
async def test_tailscale_only_selected_exit_nodes_are_reported(wire, selected):
    _, state = wire
    configure(state, "tailscale")
    settings = state["wire"]["/api/tailscale/settings/get"]["settings"]
    settings["useExitNode"] = {"100.64.0.8": {"value": "Owned exit", "selected": selected}}
    result = await call(wire, "tailscale")
    assert result.success
    assert result.data["tailscale"]["settings"]["use_exit_node"] == (
        ["Owned exit"] if str(selected) == "1" else []
    )


@pytest.mark.parametrize("version", ["v5", "v9"])
async def test_netflow_selected_interfaces_and_version(wire, version):
    _, state = wire
    configure(state, "netflow")
    capture = state["wire"]["/api/diagnostics/netflow/getconfig"]["netflow"]["capture"]
    capture["interfaces"] = {
        "em0": {"value": "WAN", "selected": 0},
        "em1": {"value": "LAN", "selected": 1},
    }
    capture["version"] = {
        key: {"value": "NetFlow " + key, "selected": int(key == version)} for key in ["v5", "v9"]
    }
    capture["egress_only"] = {"em1": {"value": "LAN", "selected": 1}}
    result = await call(wire, "netflow")
    assert result.success
    body = result.data["netflow"]
    assert body["interfaces"] == "em1" and body["version"] == version[1:]
    assert body["egress_interfaces"] == "em1" and body["egress_only"] is True


@pytest.mark.parametrize("field", ["interfaces", "targets"])
async def test_netflow_enabled_requires_target_and_selected_interface(wire, field):
    _, state = wire
    configure(state, "netflow")
    capture = state["wire"]["/api/diagnostics/netflow/getconfig"]["netflow"]["capture"]
    capture[field] = {} if field == "interfaces" else ""
    result = await call(wire, "netflow")
    assert result.success and result.data["netflow"]["enabled"] is False


async def test_crowdsec_documented_alert_and_decision_fields(wire):
    _, state = wire
    configure(state, "crowdsec")
    state["wire"]["/api/crowdsec/alerts/search"] = {
        "rows": [{"id": 17, "value": "Ip:2001:db8::1", "reason": "owned", "created": "2026-09-26"}],
        "current": 1,
        "rowCount": 50,
        "total": 1,
    }
    result = await call(wire, "crowdsec")
    assert result.success
    body = result.data["crowdsec"]
    assert body["alerts"][0] == {
        "id": 17,
        "scope": "Ip",
        "value": "2001:db8::1",
        "scenario": "owned",
        "created_at": "2026-09-26",
    }
    assert body["decisions"][0] == {
        "id": "owned",
        "scope": "Ip",
        "value": "192.0.2.15",
        "type": "ban",
        "origin": "crowdsec",
        "duration": "4h",
    }


@pytest.mark.parametrize("field", ["alerts", "decisions"])
async def test_crowdsec_bounded_window_exposes_total_and_truncation(wire, field):
    _, state = wire
    configure(state, "crowdsec")
    path = "/api/crowdsec/" + field + "/search"
    template = (
        {"id": 1, "value": "Ip:192.0.2.1", "reason": "owned", "created": "today"}
        if field == "alerts"
        else state["wire"][path]["rows"][0]
    )
    state["wire"][path] = {
        "rows": [{**template, "id": i} for i in range(50)],
        "total": 75,
        "current": 1,
        "rowCount": 50,
    }
    result = await call(wire, "crowdsec")
    assert result.success
    body = result.data["crowdsec"]
    key = "alert" if field == "alerts" else "decision"
    assert body[key + "_count"] == 50 and body[key + "_total"] == 75
    assert body[key + "_truncated"] is True


@pytest.mark.parametrize("field", ["services", "tests", "alerts"])
async def test_monit_incomplete_inventory_never_reports_complete(wire, field):
    _, state = wire
    configure(state, "monit")
    suffix = {"services": "Service", "tests": "Test", "alerts": "Alert"}[field]
    state["wire"]["/api/monit/settings/search" + suffix]["total"] = 42
    result = await call(wire, "monit")
    assert result.success is False and result.data is None


@pytest.mark.parametrize("enabled", ["0", "1"])
async def test_monit_alert_enabled_is_boolean(wire, enabled):
    _, state = wire
    configure(state, "monit")
    state["wire"]["/api/monit/settings/searchAlert"] = {
        "rows": [
            {
                "uuid": "owned-alert",
                "enabled": enabled,
                "recipient": "owned@example.test",
                "events": "",
                "description": "owned",
            }
        ],
        "total": 1,
        "current": 1,
        "rowCount": -1,
    }
    result = await call(wire, "monit")
    assert result.success
    assert result.data["monit"]["alerts"][0]["enabled"] is (enabled == "1")


async def test_telegraf_influx_v2_and_url_credentials(wire):
    _, state = wire
    configure(state, "telegraf")
    output = state["wire"]["/api/telegraf/output/get"]["output"]
    output.update(
        influx_enable="0",
        influx_v2_enable="1",
        influx_v2_url="https://owned:private@example.test/metrics?token=private#private",
        influx_v2_token="private",
    )
    result = await call(wire, "telegraf")
    assert result.success
    body = result.data["telegraf"]
    assert body["output_influxdb"] is True and body["output_influxdb_v2"] is True
    assert body["influx_v2_url"] == "https://example.test/metrics" and "private" not in json.dumps(
        body
    )
