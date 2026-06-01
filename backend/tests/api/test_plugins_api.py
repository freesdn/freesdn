# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints import plugins as plugins_endpoint
from app.core.dependencies import get_current_active_user
from app.db import get_session


class _ScalarResult:
    def __init__(self, record: object | None) -> None:
        self._record = record

    def scalar_one_or_none(self) -> object | None:
        return self._record


class _FakePluginsSession:
    def __init__(self, plugin: object | None) -> None:
        self._plugin = plugin
        self.commits = 0

    async def execute(self, _query: object) -> _ScalarResult:
        return _ScalarResult(self._plugin)

    async def commit(self) -> None:
        self.commits += 1


def _fake_current_user(*, organization_id: object | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        email="admin@example.com",
        full_name="Plugin Admin",
        is_org_admin=True,
        is_superuser=False,
        organization_id=organization_id,
        has_permission=lambda _permission: False,
    )


def _build_plugin(*, public_routes: list[dict[str, object]] | None = None, is_active: bool = True, status: str = "installed") -> SimpleNamespace:
    return SimpleNamespace(
        plugin_id="demo-plugin",
        name="Demo Plugin",
        version="1.0.0",
        description="demo",
        author="tests",
        license="Proprietary",
        homepage="https://example.com",
        plugin_dir="/data/plugins/demo-plugin",
        manifest_cache={"public_routes": public_routes or []},
        installed_from=None,
        is_active=is_active,
        status=status,
    )


@pytest.fixture
def plugins_app() -> FastAPI:
    app = FastAPI()
    app.include_router(plugins_endpoint.router, prefix="/plugins")
    yield app
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_public_auth_status_endpoint_returns_routes_and_secret_presence(
    plugins_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = uuid4()
    plugin = _build_plugin(
        public_routes=[{"path": "/webhook", "methods": ["POST"]}],
    )
    session = _FakePluginsSession(plugin)
    plugins_app.dependency_overrides[get_current_active_user] = lambda: _fake_current_user(
        organization_id=org_id
    )
    plugins_app.dependency_overrides[get_session] = lambda: session

    async def _fake_get_public_secret(_session: object, _plugin_id: str, _org_id: object) -> str | None:
        return "configured-secret"

    monkeypatch.setattr(plugins_endpoint, "get_public_webhook_secret", _fake_get_public_secret)

    async with AsyncClient(
        transport=ASGITransport(app=plugins_app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/plugins/demo-plugin/public-auth")

    assert response.status_code == 200
    assert response.json()["has_secret"] is True
    assert response.json()["public_routes"] == [{"path": "/webhook", "methods": ["POST"]}]


@pytest.mark.asyncio
async def test_rotate_public_auth_secret_endpoint_returns_secret_and_commits(
    plugins_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = uuid4()
    plugin = _build_plugin(
        public_routes=[{"path": "/webhook", "methods": ["POST"]}],
    )
    session = _FakePluginsSession(plugin)
    plugins_app.dependency_overrides[get_current_active_user] = lambda: _fake_current_user(
        organization_id=org_id
    )
    plugins_app.dependency_overrides[get_session] = lambda: session

    async def _fake_rotate_secret(_session: object, _plugin_id: str, _org_id: object) -> str:
        return "new-public-secret"

    async def _fake_audit(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(plugins_endpoint, "rotate_public_webhook_secret", _fake_rotate_secret)
    monkeypatch.setattr(plugins_endpoint, "_audit_plugin_lifecycle", _fake_audit)

    async with AsyncClient(
        transport=ASGITransport(app=plugins_app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/plugins/demo-plugin/public-auth/rotate-secret")

    assert response.status_code == 200
    assert response.json()["secret"] == "new-public-secret"
    assert session.commits == 1


@pytest.mark.asyncio
async def test_org_disable_endpoint_stops_runtime_and_returns_disabled(
    plugins_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = uuid4()
    plugin = _build_plugin()
    session = _FakePluginsSession(plugin)
    plugins_app.dependency_overrides[get_current_active_user] = lambda: _fake_current_user(
        organization_id=org_id
    )
    plugins_app.dependency_overrides[get_session] = lambda: session

    calls: dict[str, object] = {}

    async def _fake_set_org_state(
        _session: object,
        plugin_id: str,
        organization_id: object,
        *,
        is_enabled: bool,
    ) -> None:
        calls["set_state"] = (plugin_id, organization_id, is_enabled)

    async def _fake_stop_for_org(plugin_id: str, organization_id: object, _session: object) -> None:
        calls["stop"] = (plugin_id, organization_id)

    async def _fake_audit(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(plugins_endpoint, "_set_org_plugin_enabled", _fake_set_org_state)
    monkeypatch.setattr(plugins_endpoint.plugin_loader, "stop_for_org", _fake_stop_for_org)
    monkeypatch.setattr(plugins_endpoint, "_audit_plugin_lifecycle", _fake_audit)

    async with AsyncClient(
        transport=ASGITransport(app=plugins_app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/plugins/demo-plugin/disable")

    assert response.status_code == 200
    assert response.json()["status"] == "disabled"
    assert calls["set_state"] == ("demo-plugin", org_id, False)
    assert calls["stop"] == ("demo-plugin", org_id)
    assert session.commits == 1


@pytest.mark.asyncio
async def test_org_enable_endpoint_requires_global_plugin_to_be_enabled(
    plugins_app: FastAPI,
) -> None:
    org_id = uuid4()
    plugin = _build_plugin(is_active=False, status="disabled")
    session = _FakePluginsSession(plugin)
    plugins_app.dependency_overrides[get_current_active_user] = lambda: _fake_current_user(
        organization_id=org_id
    )
    plugins_app.dependency_overrides[get_session] = lambda: session

    async with AsyncClient(
        transport=ASGITransport(app=plugins_app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/plugins/demo-plugin/enable")

    assert response.status_code == 409
    assert "globally disabled" in response.json()["detail"]


@pytest.mark.asyncio
async def test_org_enable_endpoint_starts_runtime_when_global_plugin_is_enabled(
    plugins_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = uuid4()
    plugin = _build_plugin()
    session = _FakePluginsSession(plugin)
    plugins_app.dependency_overrides[get_current_active_user] = lambda: _fake_current_user(
        organization_id=org_id
    )
    plugins_app.dependency_overrides[get_session] = lambda: session

    calls: dict[str, object] = {}

    async def _fake_set_org_state(
        _session: object,
        plugin_id: str,
        organization_id: object,
        *,
        is_enabled: bool,
    ) -> None:
        calls["set_state"] = (plugin_id, organization_id, is_enabled)

    async def _fake_start_for_org(
        plugin_id: str,
        organization_id: object,
        _session: object,
        _app: object | None = None,
    ) -> None:
        calls["start"] = (plugin_id, organization_id)

    async def _fake_audit(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(plugins_endpoint, "_set_org_plugin_enabled", _fake_set_org_state)
    monkeypatch.setattr(plugins_endpoint, "_start_plugin_for_org", _fake_start_for_org)
    monkeypatch.setattr(plugins_endpoint, "_audit_plugin_lifecycle", _fake_audit)

    async with AsyncClient(
        transport=ASGITransport(app=plugins_app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/plugins/demo-plugin/enable")

    assert response.status_code == 200
    assert response.json()["status"] == "installed"
    assert calls["set_state"] == ("demo-plugin", org_id, True)
    assert calls["start"] == ("demo-plugin", org_id)
    assert session.commits == 1


@pytest.mark.asyncio
async def test_install_plugin_from_url_is_disabled_by_policy_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = SimpleNamespace(
        id=uuid4(),
        is_superuser=True,
        is_org_admin=False,
        organization_id=uuid4(),
        has_permission=lambda _permission: False,
    )
    request = SimpleNamespace(app=None)
    session = SimpleNamespace()

    monkeypatch.setattr(plugins_endpoint.settings, "PLUGIN_ENABLE_DIRECT_URL_INSTALLS", False)

    with pytest.raises(HTTPException) as exc_info:
        await plugins_endpoint.install_plugin_from_url(
            plugins_endpoint.PluginInstallFromUrl(url="https://plugins.example.com/demo.zip"),
            request,
            user,
            session,
        )

    assert exc_info.value.status_code == 403
    assert "disabled by policy" in str(exc_info.value.detail)
