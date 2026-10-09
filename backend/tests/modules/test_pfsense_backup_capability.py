"""pfSense backup creation must not invent success or return arbitrary configuration payloads."""

from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio

from app.adapters.exceptions import CapabilityNotSupportedError
from app.adapters.pfsense.adapter import PfSenseAdapter
from app.core.config import settings
from app.core.middleware import setup_exception_handlers
from app.modules.firewall.gateway_service import adapter_registry
from tests.modules import test_gateway_backup_trigger_honesty as helpers

trigger = helpers.trigger
snapshot = helpers.snapshot
UNSUPPORTED = "pfSense backup creation is not supported by this adapter; no backup was created"
PRIVATE = "owned-pf-backup-confidential"


@pytest_asyncio.fixture
async def wire():
    adapters = []
    requests = []

    def make(version="v2"):
        adapter = PfSenseAdapter(
            host="192.0.2.55", username="owned", password="owned", api_version=version
        )

        async def response(request):
            requests.append((request.method, request.url.path))
            return httpx.Response(200, json={"data": {"config_xml": PRIVATE}})

        adapter._api._client = httpx.AsyncClient(
            base_url=adapter._api.base_url, transport=httpx.MockTransport(response)
        )
        adapters.append(adapter)
        return adapter

    try:
        yield make, requests
    finally:
        for adapter in adapters:
            await adapter.disconnect()


@pytest.mark.parametrize("version", ["v1", "v2"])
@pytest.mark.parametrize("read_only", [False, True])
async def test_direct_client_refuses_unsupported_backup_before_http(
    wire, monkeypatch, version, read_only
):
    make, requests = wire
    adapter = make(version)
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    with pytest.raises(CapabilityNotSupportedError, match=UNSUPPORTED) as error:
        await adapter._api.create_backup()
    assert error.value.adapter_id == "pfsense" and error.value.capability == "create_backup"
    assert not requests


@pytest.mark.parametrize("version", ["v1", "v2"])
@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("force", [False, True])
async def test_adapter_never_claims_creation_or_returns_provider_payload(
    wire, monkeypatch, version, read_only, force
):
    make, requests = wire
    adapter = make(version)
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    adapter._direct_write_force = force
    result = await adapter.create_backup(name="owned", force=force)
    assert result.success is False and result.error_code == "NOT_SUPPORTED"
    assert result.error == UNSUPPORTED and result.data is None and not requests


@pytest.mark.parametrize("version", ["v1", "v2"])
@pytest.mark.parametrize("read_only", [False, True])
async def test_existing_low_level_reads_keep_their_contract(wire, monkeypatch, version, read_only):
    make, requests = wire
    adapter = make(version)
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    result = await adapter._api.get("/system/version")
    assert result == {"config_xml": PRIVATE}
    assert requests == [("GET", f"/api/{version}/system/version")]


@pytest_asyncio.fixture
async def capability(trigger, monkeypatch):
    f = trigger
    f.gateway.vendor = "pfsense"
    f.requests = []
    f.adapters = []
    f.http_status = 200
    f.body = {"data": {"config_xml": PRIVATE}}
    setup_exception_handlers(f.client._transport.app)

    async def response(request):
        f.requests.append((request.method, request.url.path))
        return httpx.Response(f.http_status, json=f.body)

    def create(**kwargs):
        f.calls.append("construct")
        kwargs.pop("adapter_id")
        adapter = PfSenseAdapter(**kwargs)
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


@pytest.mark.parametrize("role", ["super_admin", "viewer"])
@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("kind", ["configuration", "empty", "http404"])
async def test_api_reports_unsupported_without_contacting_assumed_backup_endpoint(
    capability, monkeypatch, role, read_only, kind, caplog
):
    f = capability
    f.user.role = role
    f.permissions = ["firewall.manage_rules"]
    f.site_ids = {f.gateway.site_id}
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    if kind == "empty":
        f.body = {"data": {}}
    if kind == "http404":
        f.http_status = 404
        f.body = {"message": PRIVATE}
    before = await snapshot(f)
    response = await f.client.post(f"/firewall/gateways/{f.gateway.id}/backups")
    assert response.status_code == 501
    assert response.json() == {"error": {"code": 501, "message": UNSUPPORTED, "request_id": None}}
    assert f.calls == ["construct", "connect"] and not f.requests
    assert PRIVATE not in response.text and PRIVATE not in caplog.text
    assert await snapshot(f) == before
    assert all(
        adapter._api._client is None or adapter._api._client.is_closed for adapter in f.adapters
    )


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
async def test_existing_backup_authority_checks_precede_capability_disclosure(capability, denial):
    f = capability
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
    response = await f.client.post(f"/firewall/gateways/{gateway_id}/backups")
    assert response.status_code == expected
    assert not f.calls and not f.requests and "not supported" not in response.text
    assert await snapshot(f) == before
