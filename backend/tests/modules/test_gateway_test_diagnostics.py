"""Gateway test HTTP responses and service logs exclude raw adapter diagnostics.

Database, encryption, service and routes are real. Authentication and adapter
results are synthetic; arbitrary returned device metadata is not sanitized here.
"""

import logging
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterConnectionError
from app.core.crypto import encrypt_dict
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import Organization, User
from app.modules.firewall.gateway_api import router
from app.modules.firewall.gateway_service import adapter_registry
from app.modules.firewall.models import GatewayConnection

VENDORS = ["opnsense", "pfsense", "mikrotik", "openwrt"]
DIAGNOSTIC = "owned-opaque-secret-marker https://owned-user:owned-password@provider.invalid/path?token=owned-token"


@pytest_asyncio.fixture
async def diagnostic_http(db_session):
    org = Organization(name="Owned diagnostics", slug="owned-diag-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    user = User(
        id=uuid4(),
        email="gateway-diag@example.test",
        hashed_password="synthetic",
        role="org_admin",
        is_active=True,
        organization_id=org.id,
    )
    current = CurrentUser(user, ["firewall.view", "firewall.manage_rules"])
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_active_user] = lambda: current

    async def session():
        yield db_session

    app.dependency_overrides[get_session] = session
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://owned-fixture"
    ) as client:
        yield client, org


@pytest.fixture
def service_logs():
    records = []

    class Recorder(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger("app.modules.firewall.gateway_service")
    assert not logger.disabled
    handler = Recorder()
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        handler.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("saved", [False, True])
@pytest.mark.parametrize(
    "outcome", ["success", "failure", "auth", "raised", "empty-control", "error-only-control"]
)
async def test_gateway_diagnostic_boundary(
    diagnostic_http, db_session, monkeypatch, service_logs, vendor, saved, outcome
):
    client, org = diagnostic_http
    adapter = AsyncMock()
    expected_success = outcome in {"success", "empty-control"}
    metadata = {"hostname": "owned-appliance", "version": "fixture-v1", "model": "fixture-model"}
    if outcome == "raised":
        adapter.test_connection.side_effect = AdapterConnectionError(DIAGNOSTIC, adapter_id=vendor)
        expected_message = "Connection failed - check host and port"
    elif expected_success:
        adapter.test_connection.return_value = AdapterResult.ok(
            data=metadata, message=None if outcome == "empty-control" else DIAGNOSTIC
        )
        expected_message = "Connection successful"
    else:
        adapter.test_connection.return_value = AdapterResult.fail(
            DIAGNOSTIC,
            error_code="AUTH_FAILED" if outcome == "auth" else DIAGNOSTIC,
            message=None if outcome == "error-only-control" else DIAGNOSTIC,
        )
        expected_message = (
            "Authentication failed - check credentials"
            if outcome == "auth"
            else "Connection test failed"
        )
    created = []

    def create(**kwargs):
        created.append(kwargs)
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    credentials = (
        {"api_key": "owned-key", "api_secret": "owned-secret"}
        if vendor in {"opnsense", "pfsense"}
        else {"username": "owned-user", "password": "owned-secret"}
    )
    if saved:
        gateway = GatewayConnection(
            org_id=org.id,
            name="Owned diagnostic gateway",
            vendor=vendor,
            host="192.168.77.77",
            port=443,
            verify_ssl=True,
            credentials=encrypt_dict(credentials),
            sync_enabled=False,
        )
        db_session.add(gateway)
        await db_session.flush()
        response = await client.post(f"/gateways/{gateway.id}/test")
    else:
        response = await client.post(
            "/gateways/test",
            json={
                "vendor": vendor,
                "host": "192.168.77.77",
                "port": 443,
                "verify_ssl": True,
                **credentials,
            },
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is expected_success and body["vendor"] == vendor
    assert (
        len(created) == 1
        and created[0]["host"] == "192.168.77.77"
        and created[0]["verify_ssl"] is True
    )
    adapter.test_connection.assert_awaited_once()
    adapter.disconnect.assert_awaited_once()
    assert isinstance(body["latency_ms"], int) and body["latency_ms"] >= 0
    if expected_success:
        assert all(body[name] == value for name, value in metadata.items())
    if saved:
        await db_session.refresh(gateway)
        assert gateway.is_online is expected_success
        if expected_success:
            assert gateway.detected_hostname == metadata["hostname"]
            assert gateway.detected_version == metadata["version"]
            assert gateway.detected_model == metadata["model"]
    service_records = service_logs
    if outcome == "raised":
        assert service_records, "The exact service logger must be observed"
    assert DIAGNOSTIC not in response.text
    assert all(DIAGNOSTIC not in r.getMessage() and r.exc_info is None for r in service_records)
    assert body["message"] == expected_message
