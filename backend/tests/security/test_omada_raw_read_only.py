# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Omada raw escape hatch is read-only, whole-organization and redacted.

A raw write reached the controller without a staged change, a confirmation or
the device slot, and the upstream site id in the path was never checked
against the caller's FreeSDN site grants. These tests drive the real endpoint
with a fake controller client and prove that no mutating call and no
site-limited call ever reaches it, and that secrets in a read are masked.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints import adapter_omada_raw
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db.session import get_session


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def raw_call(self, method, path, *, params=None, body=None):
        self.calls.append((method, path))
        return {
            "data": [
                {
                    "name": "Office",
                    "pskSetting": {"securityKey": "SECRET-psk", "versionPsk": 2},
                    "radiusSecret": "SECRET-radius",
                    "password": "SECRET-portal",
                }
            ]
        }


@pytest.fixture
def raw(monkeypatch):
    state = SimpleNamespace(client=_FakeClient(), sites=set(), role="site_admin", audits=[])

    async def get_controller(self, controller_id, organization_id):
        return SimpleNamespace(id=controller_id)

    async def get_client(self, ctrl):
        return state.client

    async def audit_log(self, **kwargs):
        state.audits.append(kwargs)

    monkeypatch.setattr(adapter_omada_raw._RawService, "_get_controller", get_controller)
    monkeypatch.setattr(adapter_omada_raw._RawService, "_get_client", get_client)
    from app.services.audit import AuditService

    monkeypatch.setattr(AuditService, "log", audit_log)

    app = FastAPI()
    app.include_router(adapter_omada_raw.router)

    def principal():
        user = SimpleNamespace(
            id=uuid4(),
            email="raw@example.test",
            organization_id=uuid4(),
            role=state.role,
            is_superuser=False,
            is_active=True,
        )
        return CurrentUser(user, ["controller:write"], accessible_site_ids=state.sites)

    async def session():
        yield SimpleNamespace()

    app.dependency_overrides[get_current_active_user] = principal
    app.dependency_overrides[get_session] = session
    state.app = app
    return state


async def _call(state, **body):
    async with AsyncClient(
        transport=ASGITransport(app=state.app, raise_app_exceptions=False), base_url="http://t"
    ) as client:
        return await client.post(f"/gateway-raw/{uuid4()}/call", json=body)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_every_mutating_method_is_refused_even_with_force_and_confirm(raw, method):
    response = await _call(
        raw,
        method=method,
        path="/sites/abc/setting/wlans/x/ssids/y",
        body={"name": "x"},
        force=True,
        confirmed=True,
    )
    assert response.status_code == 403
    assert "stage" in response.json()["detail"]
    assert raw.client.calls == []


async def test_site_limited_caller_is_refused_before_any_controller_call(raw):
    raw.sites = {uuid4()}
    response = await _call(raw, method="GET", path="/sites/other-site/setting/wlans")
    assert response.status_code == 403
    assert "site" in response.json()["detail"]
    assert raw.client.calls == []


async def test_read_is_forwarded_and_secrets_are_redacted(raw):
    response = await _call(raw, method="GET", path="sites/abc/setting/wlans")
    assert response.status_code == 200, response.text
    assert raw.client.calls == [("GET", "/sites/abc/setting/wlans")]
    assert "SECRET" not in response.text
    [row] = response.json()["response"]["data"]
    assert row["name"] == "Office"
    assert [a["extra_metadata"]["method"] for a in raw.audits] == ["GET"]
