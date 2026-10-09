"""Inventory admission and truthful failures over PostgreSQL/ASGI, vendor I/O doubled."""

import asyncio
import logging

import pytest
import pytest_asyncio

from app.adapters.base import AdapterResult
from app.modules.firewall.gateway_service import GatewayService, adapter_registry
from tests.modules import test_gateway_backup_trigger_honesty as trigger_helpers

trigger = trigger_helpers.trigger
snapshot = trigger_helpers.snapshot

SECRET = "owned-inventory-service-private-diagnostic"
ITEM = {
    "filename": "config-1720000000.xml",
    "timestamp": "2024-07-03T09:46:40+00:00",
    "size_bytes": 128,
    "description": "Owned revision",
}
UNAVAILABLE = "Backup inventory could not be retrieved"


@pytest_asyncio.fixture
async def inventory(trigger, monkeypatch):
    f = trigger
    f.result = AdapterResult.ok({"backups": [ITEM]})
    f.permissions += ["firewall.view"]
    original = adapter_registry.create_adapter

    def create(**kwargs):
        adapter = original(**kwargs)

        async def backups():
            f.calls.append("list")
            if isinstance(f.result, BaseException):
                raise f.result
            return f.result

        if f.failure != "unsupported-method":
            adapter.get_backup_list = backups
        if f.failure == "disconnect":

            async def disconnect():
                f.calls.append("disconnect")
                raise RuntimeError(SECRET)

            adapter.disconnect = disconnect
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    yield f


async def request(f):
    return await f.client.get(f"/firewall/gateways/{f.gateway.id}/backups")


@pytest.mark.parametrize(
    "kind",
    [
        "failed",
        "exception",
        "none",
        "envelope",
        "empty",
        "no-data",
        "not-list",
        "bad-row",
        "bad-filename",
        "bad-size",
        "duplicates",
    ],
)
async def test_failed_inventory_is_not_empty_success(inventory, kind, caplog):
    f = inventory
    f.result = {
        "failed": AdapterResult.fail(SECRET),
        "exception": RuntimeError(SECRET),
        "none": None,
        "envelope": {"success": True, "data": {"backups": []}},
        "empty": AdapterResult.ok({}),
        "no-data": AdapterResult.ok(),
        "not-list": AdapterResult.ok({"backups": SECRET}),
        "bad-row": AdapterResult.ok({"backups": [SECRET]}),
        "bad-filename": AdapterResult.ok({"backups": [{**ITEM, "filename": "../private"}]}),
        "bad-size": AdapterResult.ok({"backups": [{**ITEM, "size_bytes": True}]}),
        "duplicates": AdapterResult.ok({"backups": [ITEM, ITEM]}),
    }[kind]
    before = await snapshot(f)
    response = await request(f)
    assert response.status_code == 502 and response.json() == {"detail": UNAVAILABLE}
    assert f.calls == ["construct", "connect", "list", "disconnect"]
    assert SECRET not in response.text and SECRET not in caplog.text
    assert await snapshot(f) == before


@pytest.mark.parametrize("kind", ["NOT_SUPPORTED", "NOT_IMPLEMENTED", "unsupported-method"])
async def test_unsupported_inventory_is_explicit(inventory, kind):
    f = inventory
    if kind == "unsupported-method":
        f.failure = kind
    else:
        f.result = AdapterResult.fail(SECRET, error_code=kind)
    response = await request(f)
    assert response.status_code == 501
    assert response.json() == {"detail": "Backup inventory is not supported by this gateway"}
    assert SECRET not in response.text and f.calls[-1] == "disconnect"


@pytest.mark.parametrize("rows", [[], [ITEM]])
async def test_confirmed_empty_and_valid_inventory_remain_distinct_successes(inventory, rows):
    f = inventory
    f.result = AdapterResult.ok({"backups": rows})
    before = await snapshot(f)
    response = await request(f)
    assert response.status_code == 200
    assert response.json() == {
        "gateway_id": str(f.gateway.id),
        "vendor": "opnsense",
        "backups": rows,
        "count": len(rows),
    }
    assert await snapshot(f) == before


async def test_only_normalized_metadata_is_returned(inventory):
    f = inventory
    f.result = AdapterResult.ok(
        {"backups": [{**ITEM, "config_xml": SECRET, "diagnostics": SECRET}]}
    )
    response = await request(f)
    assert response.status_code == 200 and response.json()["backups"] == [ITEM]
    assert SECRET not in response.text


@pytest.mark.parametrize("kind", ["construct", "connect"])
async def test_connection_errors_are_generic(inventory, kind, caplog):
    f = inventory
    f.failure = kind
    response = await request(f)
    assert response.status_code == 502 and response.json() == {"detail": UNAVAILABLE}
    assert SECRET not in response.text and SECRET not in caplog.text
    assert "list" not in f.calls
    assert f.calls.count("disconnect") == int(kind == "connect")


async def test_disconnect_diagnostics_do_not_leak_into_logs(inventory, caplog):
    f = inventory
    f.failure = "disconnect"
    caplog.set_level(logging.DEBUG, logger="app.modules.firewall.gateway_service")
    response = await request(f)
    assert response.status_code == 200
    assert SECRET not in response.text and SECRET not in caplog.text
    assert f.calls == ["construct", "connect", "list", "disconnect"]


async def test_cancellation_propagates_and_adapter_closes(inventory):
    f = inventory
    f.result = asyncio.CancelledError("owned")
    with pytest.raises(asyncio.CancelledError):
        await GatewayService(f.db).get_live_backups(f.gateway.id, f.org.id)
    assert f.calls == ["construct", "connect", "list", "disconnect"]


@pytest.mark.parametrize("denial", ["organization", "permission", "site"])
async def test_existing_inventory_admission_never_contacts_device(inventory, denial):
    f = inventory
    if denial == "organization":
        f.user.organization_id = f.sites[1].id
    elif denial == "permission":
        f.permissions = []
        f.scoped = True
    else:
        f.user.role = "viewer"
        f.site_ids = {f.sites[1].id}
    response = await request(f)
    assert response.status_code == (403 if denial == "permission" else 404)
    assert not f.calls
