"""Real gateway API/database/adapters; identity and vendor transport are explicit doubles."""

from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio

from app.adapters.openwrt.adapter import OpenWRTAdapter
from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.core.config import settings
from app.core.middleware import setup_exception_handlers
from app.modules.firewall.gateway_service import adapter_registry
from tests.modules import test_gateway_backup_trigger_honesty as trigger_helpers

trigger = trigger_helpers.trigger
snapshot = trigger_helpers.snapshot
CREATE_UNAVAILABLE = "OPNsense backup creation is not supported by this API; no backup was created"
INVENTORY_UNAVAILABLE = "Backup inventory is not supported by this gateway"
SECRET = "owned-capability-private-diagnostic"


@pytest_asyncio.fixture
async def capability(trigger, monkeypatch):
    f = trigger
    f.permissions += ["firewall.view"]
    f.requests = []
    f.adapters = []
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", False)
    setup_exception_handlers(f.client._transport.app)

    async def response(request):
        f.requests.append((request.method, request.url.path))
        return httpx.Response(200, json={"status": "ok", "private": SECRET})

    def create(**kwargs):
        f.calls.append("construct")
        vendor = kwargs.pop("adapter_id")
        adapter = (OpenWRTAdapter if vendor == "openwrt" else OPNsenseAdapter)(**kwargs)
        if vendor == "opnsense":
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


async def request(f, operation, gateway_id=None):
    path = f"/firewall/gateways/{gateway_id or f.gateway.id}/backups"
    return await f.client.post(path) if operation == "create" else await f.client.get(path)


@pytest.mark.parametrize("operation", ["create", "inventory"])
@pytest.mark.parametrize("read_only", [False, True])
async def test_unsupported_backup_capability_is_explicit_without_operation_io(
    capability, operation, read_only, monkeypatch, caplog
):
    f = capability
    f.gateway.vendor = "opnsense" if operation == "create" else "openwrt"
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    before = await snapshot(f)
    response = await request(f, operation)
    assert response.status_code == 501
    assert response.json() == {
        "error": {
            "code": 501,
            "message": CREATE_UNAVAILABLE if operation == "create" else INVENTORY_UNAVAILABLE,
            "request_id": None,
        }
    }
    assert not f.requests and f.calls == ["construct", "connect"]
    assert SECRET not in response.text and SECRET not in caplog.text
    assert await snapshot(f) == before
    assert all(
        adapter._api._client is None or adapter._api._client.is_closed for adapter in f.adapters
    )


@pytest.mark.parametrize("operation", ["create", "inventory"])
@pytest.mark.parametrize(
    "denial",
    [
        "missing",
        "organization",
        "deleted",
        "site",
        "null-site",
        "permission",
        "scoped",
        "anonymous",
    ],
)
async def test_unsupported_capability_preserves_access_control_before_adapter_creation(
    capability, operation, denial
):
    f = capability
    f.gateway.vendor = "opnsense" if operation == "create" else "openwrt"
    gateway_id = f.gateway.id
    expected = 404
    if denial == "missing":
        gateway_id = uuid4()
    elif denial == "organization":
        f.user.organization_id = uuid4()
    elif denial == "deleted":
        f.gateway.deleted_at = datetime.now(UTC)
    elif denial in ["site", "null-site"]:
        f.user.role = "viewer"
        f.site_ids = {f.sites[1].id}
        if denial == "null-site":
            f.gateway.site_id = None
    elif denial in ["permission", "scoped"]:
        f.permissions = []
        f.scoped = denial == "scoped"
        if denial == "permission":
            f.user.role = "viewer"
        expected = 403
    else:
        f.anonymous = True
        expected = 401
    before = await snapshot(f)
    response = await request(f, operation, gateway_id)
    assert response.status_code == expected and not f.calls and not f.requests
    assert "not supported" not in response.text
    assert await snapshot(f) == before
