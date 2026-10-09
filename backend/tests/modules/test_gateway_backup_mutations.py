"""Actual API/DB/OPNsense adapter; vendor HTTPX transport and identity are doubles."""

from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio

from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.core.config import settings
from app.core.middleware import setup_exception_handlers
from app.modules.firewall.gateway_service import adapter_registry
from tests.modules import test_gateway_backup_trigger_honesty as trigger_helpers

trigger = trigger_helpers.trigger
snapshot = trigger_helpers.snapshot
FILENAME = "config-1720000000.xml"
SECRET = "owned-backup-mutation-private-diagnostic"


@pytest_asyncio.fixture
async def mutation(trigger, monkeypatch):
    f = trigger
    f.body = {}
    f.requests = []
    f.adapters = []
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", False)
    setup_exception_handlers(f.client._transport.app)

    async def response(request):
        f.requests.append((request.method, request.url.path))
        return httpx.Response(200, json=f.body)

    def create(**kwargs):
        f.calls.append("construct")
        kwargs.pop("adapter_id")
        adapter = OPNsenseAdapter(**kwargs)
        adapter._api._client = httpx.AsyncClient(
            base_url=adapter._api.base_url, transport=httpx.MockTransport(response)
        )

        async def connect():
            f.calls.append("connect")
            return True

        adapter.connect = connect
        f.adapters.append(adapter)
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    try:
        yield f
    finally:
        for adapter in f.adapters:
            await adapter.disconnect()


async def request(f, operation):
    path = f"/firewall/gateways/{f.gateway.id}/backups/{FILENAME}"
    return (
        await f.client.delete(path)
        if operation == "delete"
        else await f.client.post(path + "/revert")
    )


@pytest.mark.parametrize("operation", ["delete", "revert"])
@pytest.mark.parametrize(
    "outcome, expected", [("success", 200), ("not_found", 404), ("failed", 502), ("missing", 502)]
)
async def test_gateway_write_status_reflects_actual_vendor_outcome(
    mutation, operation, outcome, expected, caplog
):
    f = mutation
    status = (
        ("deleted" if operation == "delete" else "reverted") if outcome == "success" else outcome
    )
    f.body = (
        {"status": status, "message": SECRET, "private": SECRET} if outcome != "missing" else {}
    )
    before = await snapshot(f)
    response = await request(f, operation)
    assert response.status_code == expected
    if outcome == "success":
        assert response.json()["success"] is True
        assert response.json()["data"] == {"status": status, "filename": FILENAME}
    else:
        assert response.json()["error"]["message"] == (
            "Backup not found"
            if outcome == "not_found"
            else "Backup operation could not be confirmed"
        )
    assert f.requests == [("POST", f"/api/core/backup/{operation}Backup/{FILENAME}")]
    assert SECRET not in response.text and SECRET not in caplog.text
    assert await snapshot(f) == before
    assert all(
        adapter._api._client is None or adapter._api._client.is_closed for adapter in f.adapters
    )


@pytest.mark.parametrize("operation", ["delete", "revert"])
@pytest.mark.parametrize(
    "denial, expected", [("permission", 403), ("site", 404), ("deleted", 404), ("read-only", 502)]
)
async def test_permission_scope_and_read_only_do_not_dispatch_backup_writes(
    mutation, operation, denial, expected, monkeypatch
):
    f = mutation
    if denial == "permission":
        f.user.role = "viewer"
        f.permissions = []
    elif denial == "site":
        f.user.role = "viewer"
        f.site_ids = {f.sites[1].id}
    elif denial == "deleted":
        f.gateway.deleted_at = datetime.now(UTC)
    else:
        monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", True)
    before = await snapshot(f)
    response = await request(f, operation)
    assert response.status_code == expected and not f.requests
    if denial != "read-only":
        assert not f.calls
    assert await snapshot(f) == before
