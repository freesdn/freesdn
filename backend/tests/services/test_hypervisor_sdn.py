# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real database ownership/HTTP endpoint regressions for read-only SDN inspection."""

from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.site_access import current_user_var
from app.models.core import Controller, Site, User
from app.modules.hypervisor import api
from app.services import hypervisor_sdn as control
from tests.adapters.test_proxmox_write_outcomes import connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows


@pytest.mark.parametrize(
    "guard",
    [
        "accepted",
        "viewer",
        "no_permission",
        "foreign_org",
        "site_grant",
        "scoped",
        "scoped_foreign",
        "scoped_no_org",
        "inactive_controller",
        "inactive_site",
        "sync_disabled",
    ],
)
async def test_endpoint_ownership_before_credentials_and_no_direct_write_routes(
    power, monkeypatch, guard
):
    c = power
    user = c.user
    if guard in (
        "viewer",
        "no_permission",
        "foreign_org",
        "site_grant",
        "scoped",
        "scoped_foreign",
        "scoped_no_org",
    ):
        user = CurrentUser(
            User(
                id=c.user.id,
                organization_id=None
                if guard == "scoped_no_org"
                else uuid4()
                if guard in ("foreign_org", "scoped_foreign")
                else c.org,
                role="viewer" if guard in ("viewer", "no_permission") else "site_admin",
            ),
            [] if guard == "no_permission" else ["hypervisor:read"],
            scoped=guard.startswith("scoped"),
            accessible_site_ids={uuid4()} if guard == "site_grant" else set(),
        )
    if guard in ("inactive_controller", "inactive_site", "sync_disabled"):
        async with c.sessions() as db:
            obj = await db.get(
                Site if guard == "inactive_site" else Controller,
                c.site if guard == "inactive_site" else c.controller,
            )
            if guard == "sync_disabled":
                obj.sync_enabled = False
            else:
                obj.is_active = False
            await db.commit()

    async def builder(_):
        c.calls.append("credentials")

        def dispatch(request):
            c.calls.append((request.method, request.url.path))
            data = {"/sdn": {}} if request.url.path == "/access/permissions" else []
            if request.url.path.endswith("/dry-run"):
                data = {"interfaces-diff": None, "frr-diff": None}
            return httpx.Response(200, json={"data": data})

        return connected(dispatch)[0]

    monkeypatch.setattr(control, "build_proxmox_adapter", builder)

    async def auth():
        token = current_user_var.set(user)
        try:
            yield user
        finally:
            current_user_var.reset(token)

    async def session():
        async with c.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(api.router, prefix="/hypervisor")
    app.dependency_overrides[get_current_active_user] = auth
    app.dependency_overrides[api.get_db] = session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        base = f"/hypervisor/controllers/{c.controller}/sdn"
        response = await client.get(base + "/inspection")
        preview = await client.get(base + "/nodes/pve1/dry-run")
        dependencies = await client.get(base + "/dependencies")
        attachments = await client.get(base + "/attachments")
        for method, path in [
            ("POST", "/zones"),
            ("POST", "/vnets"),
            ("DELETE", "/zones/z1"),
            ("DELETE", "/vnets/v1"),
            ("POST", "/apply"),
        ]:
            assert (
                await client.request(method, base + path, json={"force": True})
            ).status_code in (404, 405)
    if guard in ("accepted", "viewer", "scoped"):
        assert response.status_code == preview.status_code == dependencies.status_code == 200
        assert attachments.status_code == 200
        assert attachments.json()["connectivity_verified"] is False
        assert attachments.json()["writes_enabled"] is False
        assert dependencies.json()["dependency_graph_complete"] is False
        assert dependencies.json()["writes_enabled"] is False
        assert response.json()["writes_enabled"] is False
        assert preview.json()["connectivity_verified"] is False
        assert all(call == "credentials" or call[0] == "GET" for call in c.calls)
    else:
        assert response.status_code in (403, 404) and preview.status_code in (403, 404)
        assert dependencies.status_code in (403, 404)
        assert attachments.status_code in (403, 404)
        assert not c.calls
    assert await rows(c) == []
