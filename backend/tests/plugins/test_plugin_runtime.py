# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints.plugins import get_plugin_health
from app.core.dependencies import get_current_user_optional
from app.core.events import Event, event_bus
from app.core.security_utils import encrypt_webhook_secret
from app.db import get_session
from app.plugins.bridges import automation_bridge
from app.plugins.loader import PluginLoader, _load_plugin_class
from app.plugins.public_auth import (
    PLUGIN_PUBLIC_NONCE_HEADER,
    PLUGIN_PUBLIC_ORG_HEADER,
    PLUGIN_PUBLIC_SIGNATURE_HEADER,
    PLUGIN_PUBLIC_TIMESTAMP_HEADER,
    sign_public_plugin_request,
)
from app.plugins.schema import PluginManifest


@pytest.fixture(autouse=True)
def reset_plugin_runtime_state() -> None:
    event_bus._subscriptions.clear()
    event_bus._store.events.clear()
    automation_bridge._plugin_triggers.clear()
    automation_bridge._plugin_actions.clear()


def _build_plugin_dir(
    tmp_path: Path,
    *,
    plugin_id: str,
    class_name: str,
    plugin_code: str,
    permissions: list[str] | None = None,
    event_subscriptions: list[str] | None = None,
    public_routes: list[dict[str, object]] | None = None,
    python_dependencies: list[str] | None = None,
) -> Path:
    plugin_dir = tmp_path / plugin_id
    plugin_dir.mkdir()

    manifest = {
        "id": plugin_id,
        "name": plugin_id,
        "version": "1.0.0",
        "description": "Test plugin",
        "author": "tests",
        "license": "Proprietary",
        "class_name": class_name,
        "entry_point": "plugin.py",
        "permissions": [
            {
                "code": permission,
                "name": permission,
                "description": f"Permission {permission}",
            }
            for permission in (permissions or [])
        ],
        "event_subscriptions": event_subscriptions or [],
        "public_routes": public_routes or [],
        "python_dependencies": python_dependencies or [],
    }
    (plugin_dir / "plugin.yaml").write_text(json.dumps(manifest), encoding="utf-8")
    (plugin_dir / "plugin.py").write_text(plugin_code, encoding="utf-8")
    return plugin_dir


def _load_test_plugin(plugin_dir: Path, plugin_id: str) -> PluginLoader:
    manifest = PluginManifest.from_yaml(str(plugin_dir / "plugin.yaml"))
    template, plugin_cls, added_paths = _load_plugin_class(plugin_dir, manifest)
    loader = PluginLoader()
    loader._loaded[plugin_id] = template
    loader._plugin_classes[plugin_id] = plugin_cls
    loader._plugin_paths[plugin_id] = added_paths
    return loader


@pytest.mark.asyncio
async def test_start_for_org_initializes_context_and_emits_namespaced_event(
    tmp_path: Path,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="echo-plugin",
        class_name="EchoPlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin


class EchoPlugin(FreeSDNPlugin):
    def __init__(self):
        super().__init__()
        self.started_org_ids = []

    async def on_start(self, organization_id, db=None):
        await super().on_start(organization_id, db)
        self.started_org_ids.append(str(organization_id))
""",
    )
    loader = _load_test_plugin(plugin_dir, "echo-plugin")

    org_id = uuid4()
    runtime = await loader.start_for_org("echo-plugin", org_id, SimpleNamespace())

    assert runtime.ctx is not None
    assert runtime.is_started_for(org_id)
    assert runtime.started_org_ids == [str(org_id)]

    await runtime.ctx.events.emit("threshold", {"value": 95})

    recent = await event_bus._store.get_recent(1)
    assert len(recent) == 1
    assert recent[0].event_type == "plugin.echo-plugin.threshold"
    assert recent[0].organization_id == str(org_id)


@pytest.mark.asyncio
async def test_install_plugin_rejects_runtime_python_deps_when_policy_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="deps-plugin",
        class_name="DepsPlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin


class DepsPlugin(FreeSDNPlugin):
    pass
""",
        python_dependencies=["httpx==0.28.1"],
    )
    archive_path = tmp_path / "deps-plugin.zip"

    import zipfile

    with zipfile.ZipFile(archive_path, "w") as archive:
        for path in plugin_dir.iterdir():
            archive.write(path, arcname=f"deps-plugin/{path.name}")

    class _ScalarResult:
        def scalar_one_or_none(self) -> None:
            return None

    class _FakeSession:
        async def execute(self, _query: object) -> _ScalarResult:
            return _ScalarResult()

        def add(self, _record: object) -> None:
            return None

        async def commit(self) -> None:
            return None

        async def refresh(self, _record: object) -> None:
            return None

    install_root = tmp_path / "installed-plugins"
    monkeypatch.setattr("app.plugins.loader.PLUGIN_DIR", install_root)
    monkeypatch.setattr("app.plugins.loader.settings.PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS", False)

    loader = PluginLoader()
    with pytest.raises(Exception, match="runtime dependency installs are disabled by policy"):
        await loader.install_plugin(
            source=archive_path.read_bytes(),
            db=_FakeSession(),
            installed_by_id=uuid4(),
        )


@pytest.mark.asyncio
async def test_event_subscriptions_are_org_scoped_and_removed_on_stop(
    tmp_path: Path,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="sub-plugin",
        class_name="SubscriberPlugin",
        event_subscriptions=["device.offline"],
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin


class SubscriberPlugin(FreeSDNPlugin):
    def __init__(self):
        super().__init__()
        self.received_events = []

    async def on_event(self, event):
        self.received_events.append(
            {
                "event_type": event.event_type,
                "organization_id": event.organization_id,
            }
        )
""",
    )
    loader = _load_test_plugin(plugin_dir, "sub-plugin")

    org_a = uuid4()
    org_b = uuid4()
    runtime_a = await loader.start_for_org("sub-plugin", org_a, SimpleNamespace())
    runtime_b = await loader.start_for_org("sub-plugin", org_b, SimpleNamespace())

    await event_bus.publish(
        Event(
            event_type="device.offline",
            payload={"device_id": "dev-1"},
            organization_id=str(org_a),
        )
    )

    assert runtime_a.received_events == [
        {
            "event_type": "device.offline",
            "organization_id": str(org_a),
        }
    ]
    assert runtime_b.received_events == []

    stopped = await loader.stop_for_org("sub-plugin", org_a, SimpleNamespace())
    assert stopped is True
    assert runtime_a.ctx is None

    await event_bus.publish(
        Event(
            event_type="device.offline",
            payload={"device_id": "dev-2"},
            organization_id=str(org_a),
        )
    )

    assert len(runtime_a.received_events) == 1
    assert runtime_b.received_events == []


@pytest.mark.asyncio
async def test_bridge_registrations_are_deduplicated_and_cleaned_up(
    tmp_path: Path,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="bridge-plugin",
        class_name="BridgePlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin


class BridgePlugin(FreeSDNPlugin):
    async def on_start(self, organization_id, db=None):
        await super().on_start(organization_id, db)
        self.register_automation_trigger(
            "echo_trigger",
            "Echo trigger",
            {"type": "object"},
        )
        self.register_automation_action(
            "echo_action",
            self._run_action,
            "Echo action",
            {"type": "object"},
        )

    async def _run_action(self, **kwargs):
        return kwargs
""",
    )
    loader = _load_test_plugin(plugin_dir, "bridge-plugin")

    org_a = uuid4()
    org_b = uuid4()
    await loader.start_for_org("bridge-plugin", org_a, SimpleNamespace())
    await loader.start_for_org("bridge-plugin", org_b, SimpleNamespace())

    assert len(automation_bridge.get_plugin_triggers("bridge-plugin")) == 1
    assert len(automation_bridge.get_plugin_actions("bridge-plugin")) == 1

    await loader.stop_for_org("bridge-plugin", org_a, SimpleNamespace())
    assert len(automation_bridge.get_plugin_triggers("bridge-plugin")) == 1
    assert len(automation_bridge.get_plugin_actions("bridge-plugin")) == 1

    await loader.stop_for_org("bridge-plugin", org_b, SimpleNamespace())
    assert automation_bridge.get_plugin_triggers("bridge-plugin") == []
    assert automation_bridge.get_plugin_actions("bridge-plugin") == []


@pytest.mark.asyncio
async def test_start_failure_does_not_mark_plugin_active(
    tmp_path: Path,
) -> None:
    failing_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="broken-plugin",
        class_name="BrokenPlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin


class BrokenPlugin(FreeSDNPlugin):
    async def on_start(self, organization_id, db=None):
        await super().on_start(organization_id, db)
        self.register_automation_trigger(
            "broken_trigger",
            "Broken trigger",
            {"type": "object"},
        )
        raise RuntimeError("boom")
""",
    )
    healthy_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="healthy-plugin",
        class_name="HealthyPlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin


class HealthyPlugin(FreeSDNPlugin):
    async def on_start(self, organization_id, db=None):
        await super().on_start(organization_id, db)
""",
    )

    loader = PluginLoader()
    for plugin_id, plugin_dir in {
        "broken-plugin": failing_dir,
        "healthy-plugin": healthy_dir,
    }.items():
        manifest = PluginManifest.from_yaml(str(plugin_dir / "plugin.yaml"))
        template, plugin_cls, added_paths = _load_plugin_class(plugin_dir, manifest)
        loader._loaded[plugin_id] = template
        loader._plugin_classes[plugin_id] = plugin_cls
        loader._plugin_paths[plugin_id] = added_paths

    org_id = uuid4()
    with pytest.raises(RuntimeError, match="boom"):
        await loader.start_for_org("broken-plugin", org_id, SimpleNamespace())

    assert not loader.is_active_for_org("broken-plugin", org_id)
    assert automation_bridge.get_plugin_triggers("broken-plugin") == []

    healthy_runtime = await loader.start_for_org("healthy-plugin", org_id, SimpleNamespace())
    assert healthy_runtime.ctx is not None
    assert loader.is_active_for_org("healthy-plugin", org_id)


@pytest.mark.asyncio
async def test_sdk_rejects_undeclared_permissions(
    tmp_path: Path,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="permission-plugin",
        class_name="PermissionPlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin


class PermissionPlugin(FreeSDNPlugin):
    async def on_start(self, organization_id, db=None):
        await super().on_start(organization_id, db)
""",
    )
    loader = _load_test_plugin(plugin_dir, "permission-plugin")

    runtime = await loader.start_for_org("permission-plugin", uuid4(), SimpleNamespace())

    assert runtime.ctx is not None
    with pytest.raises(PermissionError, match="devices.read"):
        await runtime.ctx.devices.list()


@pytest.mark.asyncio
async def test_registered_plugin_route_binds_request_runtime_context(
    tmp_path: Path,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="route-plugin",
        class_name="RoutePlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin
from fastapi import APIRouter


class RoutePlugin(FreeSDNPlugin):
    def get_router(self):
        router = APIRouter()

        @router.get("/context")
        async def context():
            return {
                "organization_id": str(self.ctx.organization_id) if self.ctx else None,
            }

        return router
""",
    )
    loader = _load_test_plugin(plugin_dir, "route-plugin")

    app = FastAPI()
    loader.register_plugin_routes(app, "route-plugin")
    org_id = uuid4()
    await loader.start_for_org("route-plugin", org_id, SimpleNamespace())
    app.dependency_overrides[get_current_user_optional] = lambda: SimpleNamespace(
        organization_id=org_id
    )
    app.dependency_overrides[get_session] = lambda: SimpleNamespace()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/api/v1/route-plugin/context")

    assert response.status_code == 200
    assert response.json() == {"organization_id": str(org_id)}


@pytest.mark.asyncio
async def test_registered_plugin_route_returns_410_for_inactive_org(
    tmp_path: Path,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="guard-plugin",
        class_name="GuardPlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin
from fastapi import APIRouter


class GuardPlugin(FreeSDNPlugin):
    def get_router(self):
        router = APIRouter()

        @router.get("/status")
        async def status():
            return {"ok": True}

        return router
""",
    )
    loader = _load_test_plugin(plugin_dir, "guard-plugin")

    app = FastAPI()
    loader.register_plugin_routes(app, "guard-plugin")
    await loader.start_for_org("guard-plugin", uuid4(), SimpleNamespace())
    app.dependency_overrides[get_current_user_optional] = lambda: SimpleNamespace(
        organization_id=uuid4()
    )
    app.dependency_overrides[get_session] = lambda: SimpleNamespace()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/api/v1/guard-plugin/status")

    assert response.status_code == 410
    assert response.json()["detail"] == "Plugin is not active for this organization"


class _ScalarOneResult:
    def __init__(self, record: object | None) -> None:
        self._record = record

    def scalar_one_or_none(self) -> object | None:
        return self._record


class _FakePluginSession:
    def __init__(self, record: object | None) -> None:
        self._record = record

    async def execute(self, _query: object) -> _ScalarOneResult:
        return _ScalarOneResult(self._record)


class _FakeReplayRedis:
    def __init__(self) -> None:
        self._keys: set[str] = set()

    async def set(self, key: str, value: str, ex: int, nx: bool = False) -> bool:
        if nx and key in self._keys:
            return False
        self._keys.add(key)
        return True


@pytest.mark.asyncio
async def test_plugin_health_endpoint_uses_org_runtime(
    tmp_path: Path,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="health-plugin",
        class_name="HealthPlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin


class HealthPlugin(FreeSDNPlugin):
    async def health_check(self):
        return {
            "status": "ok",
            "ready": self.ctx is not None,
        }
""",
    )
    loader = _load_test_plugin(plugin_dir, "health-plugin")
    org_id = uuid4()
    await loader.start_for_org("health-plugin", org_id, SimpleNamespace())

    from app.api.v1.endpoints import plugins as plugins_endpoint

    original_loader = plugins_endpoint.plugin_loader
    plugins_endpoint.plugin_loader = loader
    try:
        response = await get_plugin_health(
            "health-plugin",
            current_user=SimpleNamespace(
                is_org_admin=True,
                is_superuser=False,
                organization_id=org_id,
                has_permission=lambda _permission: False,
            ),
            session=_FakePluginSession(
                SimpleNamespace(plugin_id="health-plugin", status="installed")
            ),
        )
    finally:
        plugins_endpoint.plugin_loader = original_loader

    assert response.status == "ok"
    assert response.is_active is True
    assert response.organization_id == str(org_id)
    assert response.details["ready"] is True


@pytest.mark.asyncio
async def test_public_plugin_route_requires_signed_hmac_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="public-plugin",
        class_name="PublicPlugin",
        public_routes=[{"path": "/webhook", "methods": ["POST"]}],
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin
from fastapi import APIRouter


class PublicPlugin(FreeSDNPlugin):
    def get_router(self):
        router = APIRouter()

        @router.post("/webhook")
        async def webhook():
            return {
                "organization_id": str(self.ctx.organization_id) if self.ctx else None,
            }

        return router
""",
    )
    loader = _load_test_plugin(plugin_dir, "public-plugin")

    app = FastAPI()
    loader.register_plugin_routes(app, "public-plugin")
    org_id = uuid4()
    await loader.start_for_org("public-plugin", org_id, SimpleNamespace())
    app.dependency_overrides[get_current_user_optional] = lambda: None
    secret = "public-secret-for-tests"
    app.dependency_overrides[get_session] = lambda: _FakePluginSession(
        SimpleNamespace(value=encrypt_webhook_secret(secret))
    )

    from app.plugins import public_auth

    fake_redis = _FakeReplayRedis()

    async def _fake_get_redis() -> _FakeReplayRedis:
        return fake_redis

    monkeypatch.setattr(public_auth, "_get_redis", _fake_get_redis)

    body = b'{"event":"webhook"}'
    timestamp = int(time.time())
    nonce = "n" * 24
    path = "/api/v1/public-plugin/webhook"
    signature = sign_public_plugin_request(
        secret,
        timestamp=timestamp,
        nonce=nonce,
        method="POST",
        path=path,
        query="",
        organization_id=org_id,
        body=body,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            path,
            content=body,
            headers={
                PLUGIN_PUBLIC_ORG_HEADER: str(org_id),
                PLUGIN_PUBLIC_TIMESTAMP_HEADER: str(timestamp),
                PLUGIN_PUBLIC_NONCE_HEADER: nonce,
                PLUGIN_PUBLIC_SIGNATURE_HEADER: signature,
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 200
    assert response.json() == {"organization_id": str(org_id)}


@pytest.mark.asyncio
async def test_public_plugin_route_rejects_replayed_nonce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="replay-plugin",
        class_name="ReplayPlugin",
        public_routes=[{"path": "/webhook", "methods": ["POST"]}],
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin
from fastapi import APIRouter


class ReplayPlugin(FreeSDNPlugin):
    def get_router(self):
        router = APIRouter()

        @router.post("/webhook")
        async def webhook():
            return {"ok": True}

        return router
""",
    )
    loader = _load_test_plugin(plugin_dir, "replay-plugin")

    app = FastAPI()
    loader.register_plugin_routes(app, "replay-plugin")
    org_id = uuid4()
    await loader.start_for_org("replay-plugin", org_id, SimpleNamespace())
    app.dependency_overrides[get_current_user_optional] = lambda: None
    secret = "public-secret-for-replay"
    app.dependency_overrides[get_session] = lambda: _FakePluginSession(
        SimpleNamespace(value=encrypt_webhook_secret(secret))
    )

    from app.plugins import public_auth

    fake_redis = _FakeReplayRedis()

    async def _fake_get_redis() -> _FakeReplayRedis:
        return fake_redis

    monkeypatch.setattr(public_auth, "_get_redis", _fake_get_redis)

    body = b"{}"
    timestamp = int(time.time())
    nonce = "r" * 24
    path = "/api/v1/replay-plugin/webhook"
    headers = {
        PLUGIN_PUBLIC_ORG_HEADER: str(org_id),
        PLUGIN_PUBLIC_TIMESTAMP_HEADER: str(timestamp),
        PLUGIN_PUBLIC_NONCE_HEADER: nonce,
        PLUGIN_PUBLIC_SIGNATURE_HEADER: sign_public_plugin_request(
            secret,
            timestamp=timestamp,
            nonce=nonce,
            method="POST",
            path=path,
            query="",
            organization_id=org_id,
            body=body,
        ),
        "Content-Type": "application/json",
    }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        first = await client.post(path, content=body, headers=headers)
        second = await client.post(path, content=body, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json()["detail"] == "Plugin request replay detected"


@pytest.mark.asyncio
async def test_non_public_plugin_route_rejects_unauthenticated_access(
    tmp_path: Path,
) -> None:
    plugin_dir = _build_plugin_dir(
        tmp_path,
        plugin_id="private-plugin",
        class_name="PrivatePlugin",
        plugin_code="""
from app.plugins.sdk import FreeSDNPlugin
from fastapi import APIRouter


class PrivatePlugin(FreeSDNPlugin):
    def get_router(self):
        router = APIRouter()

        @router.get("/admin")
        async def admin():
            return {"ok": True}

        return router
""",
    )
    loader = _load_test_plugin(plugin_dir, "private-plugin")

    app = FastAPI()
    loader.register_plugin_routes(app, "private-plugin")
    await loader.start_for_org("private-plugin", uuid4(), SimpleNamespace())
    app.dependency_overrides[get_current_user_optional] = lambda: None
    app.dependency_overrides[get_session] = lambda: SimpleNamespace()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/api/v1/private-plugin/admin")

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required for this plugin route"
