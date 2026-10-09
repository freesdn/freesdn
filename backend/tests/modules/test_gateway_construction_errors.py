"""Construction failures are controlled gateway test results, not unhandled HTTP errors."""

import asyncio
import logging
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.adapters.base import AdapterResult
from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterTimeoutError,
)
from app.adapters.mikrotik import client as mikrotik_client
from app.adapters.pfsense import client as pfsense_client
from app.core.crypto import encrypt_dict
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import Organization, User
from app.modules.firewall.gateway_api import router
from app.modules.firewall.gateway_service import GatewayService, adapter_registry
from app.modules.firewall.models import GatewayConnection

VENDORS = ["opnsense", "pfsense", "mikrotik", "openwrt"]
DIAGNOSTIC = (
    "owned-constructor-secret https://owned-user:owned-password@provider.invalid/?token=owned-token"
)


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
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://owned-fixture",
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


def credentials(vendor):
    return (
        {"api_key": "owned-key", "api_secret": "owned-secret"}
        if vendor in {"opnsense", "pfsense"}
        else {"username": "owned-user", "password": "owned-secret"}
    )


async def request_test(client, db_session, org, vendor, saved, settings=None):
    gateway = None
    if saved:
        gateway = GatewayConnection(
            org_id=org.id,
            name="Owned constructor boundary",
            vendor=vendor,
            host="192.168.77.77",
            port=8443,
            verify_ssl=True,
            credentials=encrypt_dict(credentials(vendor)),
            settings=settings,
            is_online=True,
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
                "port": 8443,
                "verify_ssl": True,
                **credentials(vendor),
            },
        )
    return response, gateway


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("saved", [False, True])
@pytest.mark.parametrize(
    "outcome", ["value", "auth", "connection", "timeout", "runtime", "success-control"]
)
async def test_constructor_HTTP_boundary(
    diagnostic_http, db_session, monkeypatch, service_logs, vendor, saved, outcome
):
    client, org = diagnostic_http
    calls = []
    adapter = AsyncMock()
    adapter.test_connection.return_value = AdapterResult.ok(
        data={"hostname": "owned-constructor-control"}
    )
    errors = {
        "value": ValueError,
        "auth": AdapterAuthenticationError,
        "connection": AdapterConnectionError,
        "timeout": AdapterTimeoutError,
        "runtime": RuntimeError,
    }
    messages = {
        "auth": "Authentication failed - check credentials",
        "connection": "Connection failed - check host and port",
        "timeout": "Connection timed out - device may be unreachable",
        "success-control": "Connection successful",
    }

    def create(**kwargs):
        calls.append(kwargs)
        if outcome in errors:
            raise errors[outcome](DIAGNOSTIC)
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    response, gateway = await request_test(client, db_session, org, vendor, saved)
    assert response.status_code == 200, response.text
    body = response.json()
    success = outcome == "success-control"
    assert body["success"] is success and body["vendor"] == vendor
    assert body["message"] == messages.get(outcome, "An unexpected error occurred")
    assert isinstance(body["latency_ms"], int) and body["latency_ms"] >= 0
    assert (
        len(calls) == 1 and calls[0]["host"] == "192.168.77.77" and calls[0]["verify_ssl"] is True
    )
    if success:
        adapter.test_connection.assert_awaited_once()
        adapter.disconnect.assert_awaited_once()
        assert body["hostname"] == "owned-constructor-control"
    else:
        adapter.test_connection.assert_not_awaited()
        adapter.disconnect.assert_not_awaited()
        assert service_logs, "Observe the exact service logger before asserting diagnostics"
        assert body["hostname"] is None
    assert DIAGNOSTIC not in response.text
    assert all(DIAGNOSTIC not in r.getMessage() and r.exc_info is None for r in service_logs)
    if gateway:
        await db_session.refresh(gateway)
        assert gateway.is_online is success
        assert gateway.host == "192.168.77.77" and gateway.verify_ssl is True


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
async def test_constructor_cancellation_propagates_without_an_owned_adapter(monkeypatch, vendor):
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        raise asyncio.CancelledError()

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    with pytest.raises(asyncio.CancelledError):
        await GatewayService(None).test_connection(
            vendor, "192.168.77.77", 8443, True, **credentials(vendor)
        )
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", ["mikrotik", "pfsense"])
async def test_real_saved_TLS_policy_conflict_is_controlled_and_opens_no_client(
    diagnostic_http, db_session, monkeypatch, service_logs, vendor
):
    client, org = diagnostic_http
    clients = []

    def forbidden_client(**kwargs):
        clients.append(kwargs)
        raise AssertionError("Conflicting transport policy must be rejected before opening HTTPX")

    monkeypatch.setattr(
        mikrotik_client if vendor == "mikrotik" else pfsense_client,
        "build_async_client",
        forbidden_client,
    )
    response, gateway = await request_test(
        client, db_session, org, vendor, True, {"use_ssl": False}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is False and body["message"] == "An unexpected error occurred"
    assert service_logs and all(r.exc_info is None for r in service_logs)
    assert not clients
    await db_session.refresh(gateway)
    assert (
        gateway.settings == {"use_ssl": False}
        and gateway.verify_ssl is True
        and gateway.is_online is False
    )
