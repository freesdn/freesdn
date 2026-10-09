"""Actual vendor parser through real PostgreSQL/ASGI, with synthetic identity/HTTP."""

from unittest.mock import AsyncMock

import pytest

from app.modules.firewall.gateway_service import adapter_registry
from tests.adapters import test_opnsense_plugin_read_contracts as vendor
from tests.modules import test_gateway_aggregate_availability as helpers

trigger = helpers.trigger
wire = vendor.wire


def install(trigger, wire, monkeypatch, kind):
    trigger.permissions.append("firewall.view")
    adapter, state = wire
    vendor.configure(state, kind)
    adapter.connect = AsyncMock(return_value=True)
    monkeypatch.setattr(adapter_registry, "create_adapter", lambda **_kwargs: adapter)
    return state


@pytest.mark.parametrize("kind", vendor.FIXTURES)
@pytest.mark.parametrize("running", [True, False])
async def test_vendor_wire_data_survives_API_validation(trigger, wire, monkeypatch, kind, running):
    state = install(trigger, wire, monkeypatch, kind)
    path = next(path for path in state["wire"] if path.endswith("/status"))
    state["wire"][path] = {
        "status": ("active" if running else "inactive")
        if kind == "netflow"
        else ("running" if running else "stopped")
    }
    before = await helpers.snapshot(trigger)
    response = await helpers.request(trigger, kind)
    assert response.status_code == 200
    body = response.json()
    assert body["gateway_id"] == str(trigger.gateway.id) and body["vendor"] == "opnsense"
    for key, value in vendor.FIXTURES[kind]["expected"].items():
        assert body[kind][key] == (running if key == "running" else value)
    assert await helpers.snapshot(trigger) == before


@pytest.mark.parametrize("kind", vendor.FIXTURES)
async def test_unknown_service_state_is_API_unavailable(trigger, wire, monkeypatch, kind):
    state = install(trigger, wire, monkeypatch, kind)
    path = next(path for path in state["wire"] if path.endswith("/status"))
    state["wire"][path] = {"status": "unknown"}
    before = await helpers.snapshot(trigger)
    response = await helpers.request(trigger, kind)
    assert response.status_code == 502
    assert response.json() == {"detail": "Gateway status is unavailable"}
    assert await helpers.snapshot(trigger) == before


@pytest.mark.parametrize("kind,path", vendor.COMPONENTS)
@pytest.mark.parametrize("fault", ["schema", "unavailable"])
async def test_each_required_wire_component_fails_closed_through_API(
    trigger, wire, monkeypatch, kind, path, fault
):
    state = install(trigger, wire, monkeypatch, kind)
    if fault == "schema":
        state["wire"][path] = {}
    else:
        state["faults"][path] = "unavailable"
    before = await helpers.snapshot(trigger)
    response = await helpers.request(trigger, kind)
    assert response.status_code == 502
    assert response.json() == {"detail": "Gateway status is unavailable"}
    assert await helpers.snapshot(trigger) == before
