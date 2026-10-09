"""Read-only trust/ACME routes over real PostgreSQL/ASGI; device/identity are doubles."""

import asyncio
from uuid import uuid4

import pytest
import pytest_asyncio

from app.adapters.base import AdapterResult
from app.modules.firewall.gateway_service import adapter_registry
from tests.modules import test_gateway_backup_trigger_honesty as helpers

trigger = helpers.trigger
snapshot = helpers.snapshot
SECRET = "owned-private-trust-acme-error"
ROUTES = {
    "certificates": "get_trust_overview",
    "certificates/cas": "get_certificate_authorities",
    "acme": "get_acme_overview",
    "acme/certificates": "get_acme_certificates",
}


def inventory(route, rows=None):
    rows = [] if rows is None else rows
    if route == "certificates":
        return {
            "trust": {
                "certificates": rows,
                "certificate_authorities": rows,
                "crls": rows,
                "cert_count": len(rows),
                "ca_count": len(rows),
                "crl_count": len(rows),
            }
        }
    if route == "acme":
        return {
            "acme": {
                "settings": {"enabled": False, "auto_renewal": True},
                "certificates": rows,
                "accounts": rows,
                "validations": rows,
                "actions": rows,
                "cert_count": len(rows),
                "account_count": len(rows),
            }
        }
    key = "certificate_authorities" if route == "certificates/cas" else "acme_certificates"
    return {key: rows, "count": len(rows)}


@pytest_asyncio.fixture
async def trust_inventory(trigger, monkeypatch):
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
@pytest.mark.parametrize(
    "kind",
    [
        "failure",
        "exception",
        "none",
        "missing",
        "bad-data",
        "truthy",
        "bad-row",
        "partial",
        "bool-count",
    ],
)
async def test_unavailable_reads_never_look_empty(trust_inventory, route, kind, caplog):
    f = trust_inventory
    data = inventory(route)
    body = data.get("trust", data.get("acme", data))
    count_key = "cert_count" if route in {"certificates", "acme"} else "count"
    if kind == "bad-row":
        data = inventory(route, [None])
    elif kind in {"partial", "bool-count"}:
        body[count_key] = 1 if kind == "partial" else False
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
async def test_unsupported_is_explicit(trust_inventory, route, code):
    f = trust_inventory
    f.inventory_result = AdapterResult.fail(SECRET, error_code=code)
    response = await request(f, route)
    assert response.status_code == 501 and SECRET not in response.text


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("rows", [[], [{"uuid": "owned", "name": "Owned", "descr": "Owned"}]])
async def test_complete_empty_and_nonempty_controls(trust_inventory, route, rows):
    f = trust_inventory
    data = inventory(route, rows)
    # Adapter metadata cannot replace the admitted gateway identity.
    f.inventory_result = AdapterResult.ok({**data, "gateway_id": "wrong", "vendor": "wrong"})
    before = await snapshot(f)
    response = await request(f, route)
    assert response.status_code == 200
    assert response.json() == {"gateway_id": str(f.gateway.id), "vendor": "opnsense", **data}
    assert await snapshot(f) == before


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("denial", ["anonymous", "permission", "site", "organization", "missing"])
async def test_admission_stays_opaque_without_device_io(trust_inventory, route, denial):
    f = trust_inventory
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
async def test_connection_failure_is_safe(trust_inventory, route, stage, caplog):
    f = trust_inventory
    f.failure = stage
    response = await request(f, route)
    assert response.status_code == 502
    assert helpers.SECRET not in response.text and helpers.SECRET not in caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.parametrize("route", ROUTES)
async def test_cancellation_propagates(trust_inventory, route):
    f = trust_inventory
    f.inventory_result = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await request(f, route)
    assert f.calls[-1] == "disconnect"
