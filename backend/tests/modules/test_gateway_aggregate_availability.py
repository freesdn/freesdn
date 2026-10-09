"""Read-only aggregate status routes over real PostgreSQL/ASGI; device/identity are doubles."""

import asyncio
from uuid import uuid4

import pytest
import pytest_asyncio

from app.adapters.base import AdapterResult
from app.modules.firewall.gateway_service import adapter_registry
from tests.modules import test_gateway_backup_trigger_honesty as helpers

trigger = helpers.trigger
snapshot = helpers.snapshot
SECRET = "owned-private-aggregate-error"
ROUTES = {
    "vpn": "get_vpn_status",
    "device-summary": "get_device_summary",
    "tailscale": "get_tailscale_status",
    "haproxy": "get_haproxy_status",
    "haproxy/servers": "get_haproxy_servers",
    "haproxy/backends": "get_haproxy_backends",
    "haproxy/frontends": "get_haproxy_frontends",
    "proxy": "get_proxy_settings",
    "crowdsec": "get_crowdsec_status",
    "telegraf": "get_telegraf_status",
    "monit": "get_monit_status",
    "netflow": "get_netflow_status",
}


def inventory(route, active=False):
    rows = [{"uuid": "owned", "name": "Owned"}] if active else []
    if route == "vpn":
        return {
            "wireguard": {"status": {}, "peers": rows, "servers": []},
            "openvpn": {"providers": [], "instances": []},
            "ipsec": {},
        }
    if route == "device-summary":
        return {
            "hostname": "owned",
            "version": "owned",
            "interface_count": int(active),
            "interfaces_up": int(active),
            "interfaces_down": 0,
            "wan_status": "unknown",
        }
    if route == "tailscale":
        return {"tailscale": {"settings": {"enabled": active}, "running": active}}
    if route.startswith("haproxy/"):
        return {route.split("/")[1]: rows, "count": len(rows)}
    if route == "haproxy":
        return {
            "haproxy": {
                "servers": rows,
                "backends": [],
                "frontends": [],
                "acls": [],
                "actions": [],
                "server_count": len(rows),
                "backend_count": 0,
                "frontend_count": 0,
            }
        }
    if route == "proxy":
        return {
            "proxy": {
                "enabled": active,
                "running": active,
                "ssl_inspection": False,
                "transparent_mode": False,
                "cache_enabled": False,
                "logging": True,
                "port": "3128",
            }
        }
    if route == "crowdsec":
        return {
            "crowdsec": {
                "running": active,
                "alerts": rows,
                "decisions": [],
                "alert_count": len(rows),
                "decision_count": 0,
            }
        }
    if route == "telegraf":
        return {
            "telegraf": {
                "enabled": active,
                "running": active,
                "output_influxdb": False,
                "output_graphite": False,
                "output_prometheus": active,
            }
        }
    if route == "monit":
        return {
            "monit": {
                "running": active,
                "services": rows,
                "tests": [],
                "alerts": [],
                "service_count": len(rows),
                "test_count": 0,
                "alert_count": 0,
            }
        }
    return {"netflow": {"enabled": active, "collect_enabled": active, "running": active}}


def expected_payload(route, data):
    if route == "vpn":
        return {"tunnels": data}
    if route == "device-summary":
        return {"summary": data}
    return data


@pytest_asyncio.fixture
async def aggregate_inventory(trigger, monkeypatch):
    f = trigger
    f.permissions.append("firewall.view")
    f.inventory_result = AdapterResult.ok()
    original = adapter_registry.create_adapter

    def create(**kwargs):
        adapter = original(**kwargs)
        for name in ROUTES.values():

            async def read(name=name):
                f.calls.append(name)
                if isinstance(f.inventory_result, BaseException):
                    raise f.inventory_result
                return f.inventory_result

            setattr(adapter, name, read)
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    yield f


async def request(f, route, gateway_id=None):
    return await f.client.get(f"/firewall/gateways/{gateway_id or f.gateway.id}/{route}")


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("kind", ["failure", "exception", "none", "missing", "bad-data", "truthy"])
async def test_unavailable_reads_never_look_empty(aggregate_inventory, route, kind, caplog):
    f = aggregate_inventory
    data = inventory(route)
    f.inventory_result = {
        "failure": AdapterResult.fail(SECRET),
        "exception": RuntimeError(SECRET),
        "none": None,
        "missing": AdapterResult.ok({}),
        "bad-data": AdapterResult.ok(SECRET),
        "truthy": AdapterResult(success="yes", data=data),
    }.get(kind, AdapterResult.ok(data))
    before = await snapshot(f)
    response = await request(f, route)
    assert response.status_code == 502
    assert SECRET not in response.text and SECRET not in caplog.text
    assert "Traceback" not in caplog.text
    assert f.calls == ["construct", "connect", ROUTES[route], "disconnect"]
    assert await snapshot(f) == before


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("code", ["NOT_SUPPORTED", "NOT_IMPLEMENTED"])
async def test_unsupported_is_explicit(aggregate_inventory, route, code):
    f = aggregate_inventory
    f.inventory_result = AdapterResult.fail(SECRET, error_code=code)
    response = await request(f, route)
    assert response.status_code == 501 and SECRET not in response.text


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("active", [False, True])
async def test_complete_empty_and_nonempty_controls(aggregate_inventory, route, active):
    f = aggregate_inventory
    data = inventory(route, active)
    # Adapter metadata cannot replace the admitted gateway identity.
    f.inventory_result = AdapterResult.ok({**data, "gateway_id": "wrong", "vendor": "wrong"})
    before = await snapshot(f)
    response = await request(f, route)
    assert response.status_code == 200
    assert response.json() == {
        "gateway_id": str(f.gateway.id),
        "vendor": "opnsense",
        **expected_payload(route, data),
    }
    assert await snapshot(f) == before


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("denial", ["anonymous", "permission", "site", "organization", "missing"])
async def test_admission_stays_opaque_without_device_io(aggregate_inventory, route, denial):
    f = aggregate_inventory
    gateway_id = None
    if denial == "anonymous":
        f.anonymous = True
    elif denial == "permission":
        f.permissions = []
        f.scoped = True
    elif denial == "site":
        f.user.role = "viewer"
        f.scoped = True
        f.site_ids = {f.sites[1].id}
    elif denial == "organization":
        f.user.organization_id = uuid4()
    else:
        gateway_id = uuid4()
    response = await request(f, route, gateway_id)
    assert response.status_code == (
        401 if denial == "anonymous" else 403 if denial == "permission" else 404
    )
    assert not f.calls


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("stage", ["construct", "connect"])
async def test_connection_failure_is_safe(aggregate_inventory, route, stage, caplog):
    f = aggregate_inventory
    f.failure = stage
    response = await request(f, route)
    assert response.status_code == 502
    assert helpers.SECRET not in response.text and helpers.SECRET not in caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.parametrize("route", ROUTES)
async def test_cancellation_propagates(aggregate_inventory, route):
    f = aggregate_inventory
    f.inventory_result = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await request(f, route)
    assert f.calls[-1] == "disconnect"
