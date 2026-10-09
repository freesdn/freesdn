# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real PostgreSQL and HTTP response serialization; provider/auth edges are synthetic."""

import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy import delete, select

from app.adapters.registry import adapter_registry
from app.api.v1.endpoints import controllers
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db.session import CelerySessionLocal
from app.models.core import Controller, Organization, Site, User

MARKER = "owned-private-legacy-controller-diagnostic"


@pytest_asyncio.fixture
async def database_api(monkeypatch):
    org, other, site_id, foreign_id, controller_id = [uuid4() for _ in range(5)]
    history = [{"timestamp": "2026-09-24T00:00:00+00:00", "error": MARKER, "private": MARKER}]
    async with CelerySessionLocal() as db:
        db.add_all(
            [Organization(id=i, name="Owned diagnostic fixture", slug=i.hex) for i in [org, other]]
        )
        await db.flush()
        db.add_all(
            [
                Site(id=i, name="Owned diagnostic site", slug=i.hex, organization_id=o)
                for i, o in [(site_id, org), (foreign_id, other)]
            ]
        )
        await db.flush()
        db.add(
            Controller(
                id=controller_id,
                site_id=site_id,
                name="Owned controller",
                controller_type="omada",
                host="192.168.254.254",
                port=8043,
                status="error",
                last_error=MARKER,
                config={"error_history": history, "preserve_setting": "owned"},
                is_active=True,
            )
        )
        await db.commit()
    state = SimpleNamespace(
        org=org, other=other, site=site_id, foreign=foreign_id, controller=controller_id
    )

    def user(organization, *, permissions=None, grants=None, role="org_admin"):
        return CurrentUser(
            user=User(
                id=uuid4(),
                email="owned@example.invalid",
                organization_id=organization,
                role=role,
                hashed_password="owned",
                is_active=True,
            ),
            permissions=permissions
            or ["controller:read", "controller:update", "controller:create"],
            accessible_site_ids=set(grants or []),
        )

    state.make_user = user
    state.caller = user(org)
    app = FastAPI()
    app.include_router(controllers.router, prefix="/controllers")
    app.dependency_overrides[get_current_active_user] = lambda: state.caller

    async def session():
        async with CelerySessionLocal() as db:
            yield db

    app.dependency_overrides[controllers.get_session] = session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://owned.invalid"
    ) as client:
        state.client = client
        try:
            yield state
        finally:
            async with CelerySessionLocal() as db:
                await db.execute(
                    delete(Controller).where(Controller.site_id.in_([site_id, foreign_id]))
                )
                await db.execute(delete(Site).where(Site.id.in_([site_id, foreign_id])))
                await db.execute(delete(Organization).where(Organization.id.in_([org, other])))
                await db.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["list", "detail", "metadata"])
async def test_http_legacy_diagnostics_are_projected_without_database_rewrite(database_api, route):
    f = database_api
    async with CelerySessionLocal() as db:
        row = await db.get(Controller, f.controller)
        before = (row.last_error, copy.deepcopy(row.config), row.updated_at)
    path = (
        "/controllers/"
        if route == "list"
        else f"/controllers/{f.controller}" + ("/metadata" if route == "metadata" else "")
    )
    response = await f.client.get(path)
    assert response.status_code == 200, response.text
    assert MARKER not in response.text
    async with CelerySessionLocal() as db:
        row = await db.get(Controller, f.controller)
        assert (row.last_error, row.config, row.updated_at) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["result", "exception"])
async def test_saved_connection_check_persists_only_fixed_failure(
    database_api, monkeypatch, mode, caplog
):
    f = database_api
    adapter = MagicMock()
    adapter.__aenter__ = AsyncMock(return_value=adapter)
    adapter.__aexit__ = AsyncMock(return_value=False)
    adapter.test_connection = AsyncMock(
        return_value=SimpleNamespace(success=False, error=MARKER, message=MARKER, data={})
    )
    if mode == "exception":
        adapter.test_connection.side_effect = RuntimeError(MARKER)
    monkeypatch.setattr(adapter_registry, "create_adapter", lambda **_kwargs: adapter)
    response = await f.client.post(f"/controllers/{f.controller}/test")
    assert response.status_code == 200 and response.json()["success"] is False
    assert MARKER not in response.text + caplog.text
    async with CelerySessionLocal() as db:
        row = await db.get(Controller, f.controller)
        assert row.last_error and MARKER not in row.last_error
    adapter.test_connection.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["result", "exception"])
async def test_initial_background_connection_check_persists_safe_failure(
    database_api, monkeypatch, mode, caplog
):
    import app.db
    from app.services.organization import OrganizationService

    f = database_api
    # This test covers committed creation/background diagnostics, not tier quota policy.
    monkeypatch.setattr(OrganizationService, "_check_quota", AsyncMock())
    monkeypatch.setattr(app.db, "async_session_factory", CelerySessionLocal)
    adapter = MagicMock()
    adapter.__aenter__ = AsyncMock(return_value=adapter)
    adapter.__aexit__ = AsyncMock(return_value=False)
    adapter.test_connection = AsyncMock(
        return_value=SimpleNamespace(success=False, error=MARKER, message=MARKER, data={})
    )
    if mode == "exception":
        adapter.test_connection.side_effect = RuntimeError(MARKER)
    monkeypatch.setattr(adapter_registry, "create_adapter", lambda **_kwargs: adapter)
    response = await f.client.post(
        "/controllers/",
        json={
            "name": "Owned new controller",
            "controller_type": "omada",
            "host": "192.168.254.254",
            "port": 8043,
            "site_id": str(f.site),
            "username": "owned",
            "password": "owned",
        },
    )
    assert response.status_code == 201, response.text
    assert MARKER not in response.text + caplog.text
    async with CelerySessionLocal() as db:
        row = await db.scalar(
            select(Controller).where(
                Controller.name == "Owned new controller", Controller.site_id == f.site
            )
        )
        assert row is not None and row.last_error and MARKER not in row.last_error
    adapter.test_connection.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["detail", "metadata", "test"])
async def test_foreign_tenant_still_cannot_access_controller(database_api, route):
    f = database_api
    f.caller = f.make_user(f.other)
    suffix = "" if route == "detail" else "/" + route
    response = await (f.client.post if route == "test" else f.client.get)(
        f"/controllers/{f.controller}{suffix}"
    )
    assert response.status_code in {403, 404}
    assert MARKER not in response.text
