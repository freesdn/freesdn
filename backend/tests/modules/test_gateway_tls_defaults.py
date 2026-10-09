# SPDX-License-Identifier: AGPL-3.0-only
"""New gateway certificate policy at HTTP, service and PostgreSQL boundaries.

Authentication and discovery publication are synthetic; the router, request
validation, service, encryption and PostgreSQL writes are real. Device tests
are transport doubles here. Separate TLS peer qualification covers transport.
"""
from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import Organization, User
from app.modules.firewall.gateway_api import router
from app.modules.firewall.gateway_service import GatewayService
from app.modules.firewall.models import GatewayConnection
from app.modules.firewall.schemas import GatewayConnectionUpdate

VENDORS = ["opnsense", "pfsense", "mikrotik", "openwrt"]
POLICIES = ["omitted", True, False]


def payload(vendor: str, choice: str | bool) -> dict:
    body = {"vendor": vendor, "host": "192.168.77.77", "port": 443}
    body.update({"api_key": "synthetic-key", "api_secret": "synthetic-secret"} if vendor in ("opnsense", "pfsense") else {"username": "synthetic-user", "password": "synthetic-secret"})
    if choice != "omitted":
        body["verify_ssl"] = choice
    return body


@pytest_asyncio.fixture
async def owner(db_session: AsyncSession) -> Organization:
    org = Organization(name="Owned TLS fixture", slug="owned-tls-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture
async def gateway_http(db_session: AsyncSession, owner: Organization, monkeypatch):
    app = FastAPI()
    app.include_router(router)
    user = User(id=uuid4(), email="gateway-tls@example.test", hashed_password="synthetic", role="org_admin", is_active=True, organization_id=owner.id)
    current = CurrentUser(user, ["firewall.view", "firewall.manage_rules"])
    app.dependency_overrides[get_current_active_user] = lambda: current

    async def session():
        yield db_session

    app.dependency_overrides[get_session] = session
    monkeypatch.setattr("app.services.device_sync.trigger_device_registry_sync", lambda *_: None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://owned-fixture") as client:
        yield client


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("choice", POLICIES)
async def test_create_http_persists_deliberate_certificate_policy(gateway_http, db_session, owner, vendor, choice):
    body = {**payload(vendor, choice), "name": "Owned gateway", "sync_enabled": False}
    response = await gateway_http.post("/gateways", json=body)
    assert response.status_code == 201, response.text
    expected = choice is not False
    assert response.json()["verify_ssl"] is expected
    saved = await db_session.get(GatewayConnection, UUID(response.json()["id"]))
    await db_session.refresh(saved)
    assert saved.org_id == owner.id and saved.verify_ssl is expected
    assert "synthetic-secret" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("choice", POLICIES)
async def test_unsaved_http_test_passes_deliberate_certificate_policy(gateway_http, monkeypatch, vendor, choice):
    request = AsyncMock(return_value={"success": False, "message": "Synthetic transport response", "vendor": vendor})
    monkeypatch.setattr(GatewayService, "test_connection", request)
    response = await gateway_http.post("/gateways/test", json=payload(vendor, choice))
    assert response.status_code == 200, response.text
    request.assert_awaited_once()
    assert request.await_args.kwargs["verify_ssl"] is (choice is not False)


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
async def test_service_creation_without_policy_inserts_verified_gateway(db_session, owner, vendor):
    saved = await GatewayService(db_session).create_gateway(owner.id, name="Service-owned gateway", sync_enabled=False, **payload(vendor, "omitted"))
    await db_session.refresh(saved)
    assert saved.verify_ssl is True


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
async def test_orm_insert_without_policy_defaults_to_verified_tls(db_session, owner, vendor):
    row = GatewayConnection(org_id=owner.id, name="ORM-owned gateway", vendor=vendor, host="192.168.77.77", credentials=encrypt_dict({"password": "synthetic-secret"}), sync_enabled=False)
    db_session.add(row)
    await db_session.flush()
    stored = (await db_session.execute(select(GatewayConnection.verify_ssl).where(GatewayConnection.id == row.id))).scalar_one()
    assert stored is True


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("saved_policy", [False, True])
async def test_unrelated_update_preserves_saved_certificate_policy(db_session, owner, vendor, saved_policy):
    service = GatewayService(db_session)
    saved = await service.create_gateway(owner.id, name="Existing gateway", sync_enabled=False, **payload(vendor, saved_policy))
    fields = GatewayConnectionUpdate(name="Renamed gateway").model_dump(exclude_unset=True)
    updated = await service.update_gateway(saved.id, owner.id, **fields)
    await db_session.refresh(updated)
    assert updated.name == "Renamed gateway" and updated.verify_ssl is saved_policy


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("saved_policy", [False, True])
@pytest.mark.parametrize("override", POLICIES)
async def test_saved_gateway_test_preserves_stored_policy_or_explicit_override(db_session, owner, monkeypatch, vendor, saved_policy, override):
    service = GatewayService(db_session)
    saved = await service.create_gateway(owner.id, name="Existing gateway", sync_enabled=False, **payload(vendor, saved_policy))
    request = AsyncMock(return_value={"success": False, "message": "Synthetic transport response", "vendor": vendor})
    monkeypatch.setattr(service, "test_connection", request)
    kwargs = {} if override == "omitted" else {"verify_ssl": override}
    await service.test_existing_gateway(saved.id, owner.id, **kwargs)
    expected = saved_policy if override == "omitted" else override
    assert request.await_args.kwargs["verify_ssl"] is expected
    await db_session.refresh(saved)
    assert saved.verify_ssl is saved_policy


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("path", ["/gateways", "/gateways/test"])
async def test_null_policy_is_rejected_without_device_test(gateway_http, monkeypatch, vendor, path):
    request = AsyncMock()
    monkeypatch.setattr(GatewayService, "test_connection", request)
    response = await gateway_http.post(path, json={**payload(vendor, "omitted"), "name": "Owned gateway", "verify_ssl": None})
    assert response.status_code == 422
    request.assert_not_awaited()
