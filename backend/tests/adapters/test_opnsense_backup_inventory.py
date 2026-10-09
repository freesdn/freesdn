"""Vendor backup contract through real HTTPX parsing with an explicit mock transport."""

import asyncio

import httpx
import pytest
import pytest_asyncio

from app.adapters.opnsense.adapter import OPNsenseAdapter

SECRET = "owned-backup-inventory-private-diagnostic"
ITEM = {
    "id": "config-1720000000.xml",
    "time": "1720000000",
    "time_iso": "2024-07-03T09:46:40+00:00",
    "filesize": 128,
    "description": "Owned revision α",
    "username": "owned-administrator",
}
NORMAL = {
    "filename": ITEM["id"],
    "timestamp": ITEM["time_iso"],
    "size_bytes": 128,
    "description": ITEM["description"],
}


@pytest_asyncio.fixture
async def wire():
    adapter = OPNsenseAdapter(
        host="192.0.2.55", username="owned-key", password="owned-secret", verify_ssl=True
    )
    client = adapter._api
    client.max_retries = 1
    state = {"body": {"items": [ITEM]}, "status": 200, "error": None, "requests": []}

    async def response(request):
        state["requests"].append((request.method, request.url.path))
        if state["error"]:
            raise state["error"]
        return httpx.Response(state["status"], json=state["body"])

    client._client = httpx.AsyncClient(
        base_url=client.base_url, transport=httpx.MockTransport(response)
    )
    try:
        yield adapter, client, state
    finally:
        await adapter.disconnect()


async def test_client_selects_only_this_firewall_inventory(wire):
    _, client, state = wire
    assert await client.get_backup_list() == state["body"]
    assert state["requests"] == [("GET", "/api/core/backup/backups/this")]


@pytest.mark.parametrize("variant", ["empty", "one", "two-zero-size"])
async def test_upstream_items_are_losslessly_normalized(wire, variant):
    adapter, _, state = wire
    items = [] if variant == "empty" else [ITEM]
    wanted = [] if variant == "empty" else [NORMAL]
    if variant == "two-zero-size":
        items = [ITEM, {**ITEM, "id": "config-1720000001.xml", "filesize": 0}]
        wanted = [NORMAL, {**NORMAL, "filename": "config-1720000001.xml", "size_bytes": 0}]
    state["body"] = {"items": items, "diagnostics": SECRET}
    result = await adapter.get_backup_list()
    assert result.success is True and result.data == {"backups": wanted}
    assert state["requests"] == [("GET", "/api/core/backup/backups/this")]
    assert SECRET not in str(result.data) and "username" not in str(result.data)


def malformed(kind):
    if kind == "missing":
        return {}
    if kind == "old-envelope":
        return {"backups": [{"filename": SECRET}]}
    if kind in ["null", "text", "object"]:
        return {"items": {"null": None, "text": SECRET, "object": {"secret": SECRET}}[kind]}
    item = dict(ITEM)
    if kind == "row-text":
        return {"items": [SECRET]}
    if kind == "duplicate":
        return {"items": [item, item]}
    field, value = {
        "missing-id": ("id", None),
        "empty-id": ("id", ""),
        "unsafe-id": ("id", "../config.xml"),
        "negative-size": ("filesize", -1),
        "bool-size": ("filesize", True),
        "text-size": ("filesize", "128"),
        "missing-size": ("filesize", None),
        "bad-time": ("time_iso", {"secret": SECRET}),
        "bad-description": ("description", [SECRET]),
    }[kind]
    item[field] = value
    return {"items": [item]}


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "old-envelope",
        "null",
        "text",
        "object",
        "row-text",
        "duplicate",
        "missing-id",
        "empty-id",
        "unsafe-id",
        "negative-size",
        "bool-size",
        "text-size",
        "missing-size",
        "bad-time",
        "bad-description",
    ],
)
async def test_malformed_inventory_is_not_a_successful_empty_list(wire, kind, caplog):
    adapter, _, state = wire
    state["body"] = malformed(kind)
    result = await adapter.get_backup_list()
    assert result.success is False and result.data is None
    assert result.error == "Backup inventory could not be retrieved"
    assert result.error_code == "BACKUP_LIST_FAILED"
    assert SECRET not in caplog.text and "Traceback" not in caplog.text


@pytest.mark.parametrize("failure", [401, 403, 503, "connection", "timeout"])
async def test_adapter_transport_failures_are_safe(wire, failure, caplog):
    adapter, _, state = wire
    state["body"] = {"message": SECRET}
    if isinstance(failure, int):
        state["status"] = failure
    else:
        state["error"] = (httpx.ConnectError if failure == "connection" else httpx.ReadTimeout)(
            SECRET
        )
    result = await adapter.get_backup_list()
    assert result.success is False and result.data is None
    assert (
        result.error == "Backup inventory could not be retrieved"
        and result.error_code == "BACKUP_LIST_FAILED"
    )
    assert SECRET not in caplog.text and "Traceback" not in caplog.text


async def test_adapter_cancellation_is_not_a_success_or_failure_result(wire):
    adapter, _, state = wire
    state["error"] = asyncio.CancelledError("owned")
    with pytest.raises(asyncio.CancelledError):
        await adapter.get_backup_list()
