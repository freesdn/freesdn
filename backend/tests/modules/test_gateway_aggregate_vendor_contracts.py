"""Preserve OpenWrt's existing summary contract through real PostgreSQL/ASGI.

The successful controls use the actual OpenWrt parser with synthetic ubus I/O.
Authentication is the explicit identity fixture; these are not firmware tests.
"""

from unittest.mock import AsyncMock

import pytest

from app.adapters.base import AdapterResult
from app.adapters.openwrt.adapter import OpenWRTAdapter
from app.modules.firewall.gateway_service import adapter_registry
from tests.modules import test_gateway_aggregate_availability as helpers

trigger = helpers.trigger
aggregate_inventory = helpers.aggregate_inventory
snapshot = helpers.snapshot
request = helpers.request


def openwrt_summary():
    return {
        "hostname": "owned-openwrt",
        "model": "owned-model",
        "version": "owned-version",
        "uptime": 120,
        "interfaces_total": 2,
        "interfaces_up": 1,
        "memory_total": 1024,
        "memory_free": 512,
        "services_total": 3,
        "capabilities": {"wireguard": True},
    }


@pytest.mark.parametrize(
    "interfaces,capabilities", [(0, {}), (2, {"wireguard": True}), (2, {"wireguard": False})]
)
async def test_actual_openwrt_summary_is_not_rejected(
    trigger, monkeypatch, interfaces, capabilities
):
    f = trigger
    f.permissions.append("firewall.view")
    f.gateway.vendor = "openwrt"
    adapter = OpenWRTAdapter(host="owned.invalid", username="owned", password="synthetic")
    adapter._capabilities = capabilities
    adapter._api.get_board_info = AsyncMock(
        return_value={
            "hostname": "owned-openwrt",
            "model": "owned-model",
            "release": {"version": "owned-version"},
        }
    )
    adapter._api.get_system_info = AsyncMock(
        return_value={"uptime": 120, "memory": {"total": 1024, "free": 512}}
    )
    adapter._api.get_network_interfaces = AsyncMock(
        return_value={"interface": [{"up": True}] * interfaces}
    )
    adapter._api.get_services = AsyncMock(return_value={"owned-service": {}})
    adapter.connect = AsyncMock(return_value=True)
    adapter.disconnect = AsyncMock()
    monkeypatch.setattr(adapter_registry, "create_adapter", lambda **_kwargs: adapter)
    before = await snapshot(f)
    response = await request(f, "device-summary")
    assert response.status_code == 200
    assert response.json() == {
        "gateway_id": str(f.gateway.id),
        "vendor": "openwrt",
        "summary": {
            **openwrt_summary(),
            "interfaces_total": interfaces,
            "interfaces_up": interfaces,
            "services_total": 1,
            "capabilities": capabilities,
        },
    }
    adapter._api.get_board_info.assert_awaited_once()
    adapter._api.get_system_info.assert_awaited_once()
    adapter._api.get_network_interfaces.assert_awaited_once()
    adapter._api.get_services.assert_awaited_once()
    adapter.disconnect.assert_awaited_once()
    assert await snapshot(f) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("interfaces_total", -1),
        ("interfaces_up", 3),
        ("interfaces_total", True),
        ("uptime", {"nested": 120}),
        ("memory_total", "1024"),
        ("services_total", -1),
        ("capabilities", {"wireguard": "yes"}),
        ("memory_free", 2048),
    ],
)
async def test_malformed_openwrt_summary_is_unavailable(aggregate_inventory, field, value):
    f = aggregate_inventory
    f.gateway.vendor = "openwrt"
    f.inventory_result = AdapterResult.ok({**openwrt_summary(), field: value})
    before = await snapshot(f)
    response = await request(f, "device-summary")
    assert response.status_code == 502
    assert response.json() == {"detail": "Gateway status is unavailable"}
    assert await snapshot(f) == before


async def test_adapter_cannot_select_another_vendors_summary_contract(aggregate_inventory):
    f = aggregate_inventory
    assert f.gateway.vendor == "opnsense"
    f.inventory_result = AdapterResult.ok({**openwrt_summary(), "vendor": "openwrt"})
    before = await snapshot(f)
    response = await request(f, "device-summary")
    assert response.status_code == 502
    assert await snapshot(f) == before
