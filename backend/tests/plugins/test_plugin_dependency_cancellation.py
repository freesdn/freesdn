# SPDX-License-Identifier: AGPL-3.0-only
"""Cancellation must not restore files while a dependency worker can still write.

Actual authenticated ASGI requests, native committed PostgreSQL, loader and
executor threads are exercised. Only the dependency installer is replaced by
a bounded owned-filesystem worker; this does not qualify uv/network/wheels,
production middleware, process shutdown, or crash recovery.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
import yaml
from fastapi import FastAPI
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import plugins as endpoints
from app.core.security import create_access_token, decode_token, get_password_hash
from app.db.session import create_test_engine, get_session
from app.models.core import Organization, User, UserSession
from app.models.plugins import InstalledPlugin, PluginOrganizationState, PluginSetting
from app.models.security_audit import AuditLogRecord
from app.plugins import loader as loader_module
from app.plugins.loader import PluginLoader, PluginLoadError
from tests.plugins.test_plugin_upgrade_rollback import (
    candidate_archive,
    runtime_state,
    subscription_ids,
)
from tests.plugins.test_ticketing_archive_lifecycle import (
    SLUGS,
    archive,
    disk_files,
    expected_files,
    settings_rows,
)

MARKER = b"Owned dependency worker completed before rollback\n"


def manifest_version(path):
    file = path / "plugin.yaml"
    return yaml.safe_load(file.read_text())["version"] if file.is_file() else None


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("operation", ["install", "upgrade"])
@pytest.mark.parametrize("outcome", ["cancel_once_ok", "cancel_twice_ok", "cancel_once_error", "cancel_twice_error", "valid", "worker_error"])
async def test_dependency_worker_finishes_before_cancelled_install_restores_files(
    monkeypatch, tmp_path, record_property, slug, operation, outcome,
):
    engine = create_test_engine()
    loop = asyncio.get_running_loop()
    started, finished = asyncio.Event(), asyncio.Event()
    release = threading.Event()
    worker_observations = {}
    main_thread = threading.get_ident()
    orgs, users = [uuid4() for _ in range(3)], [uuid4() for _ in range(3)]
    tokens, claims = [], []
    for user in users:
        token = create_access_token(str(user), token_version=17, expires_delta=timedelta(minutes=5))
        claim = await decode_token(token)
        assert claim is not None
        tokens.append(token)
        claims.append(claim)
    loader = PluginLoader()
    dest = tmp_path / "installed"
    monkeypatch.setattr(loader_module, "PLUGIN_DIR", dest)
    monkeypatch.setattr(loader_module.settings, "PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS", False)
    monkeypatch.setattr(loader_module, "plugin_loader", loader)
    monkeypatch.setattr(endpoints, "plugin_loader", loader)
    app = FastAPI()
    app.include_router(endpoints.router, prefix="/api/v1/plugins")

    async def independent_session():
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = independent_session
    original_subscriptions = subscription_ids()
    request_task = None

    def owned_dependency_worker(path, dependencies):
        worker_observations.update(
            different_thread=threading.get_ident() != main_thread,
            expected_destination=path == dest / slug,
            dependencies=dependencies,
            version_at_start=manifest_version(path),
        )
        loop.call_soon_threadsafe(started.set)
        try:
            if not release.wait(timeout=20):
                worker_observations["fixture_release_timeout"] = True
                raise RuntimeError("Owned worker release timed out")
            worker_observations["version_at_write"] = manifest_version(path)
            worker_observations["request_done_at_write"] = request_task.done()
            path.mkdir(parents=True, exist_ok=True)
            (path / ".owned-dependency-write").write_bytes(MARKER)
            worker_observations["write_completed"] = True
            if outcome.endswith("error"):
                raise PluginLoadError("Owned dependency worker refusal")
        finally:
            loop.call_soon_threadsafe(finished.set)

    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            assert not (await seed.scalars(select(Organization.id).where(Organization.is_active.is_(True)))).all()
            assert not (await seed.scalars(select(InstalledPlugin.plugin_id))).all()
            seed.add_all([Organization(id=org, name="Owned cancellation", slug=uuid4().hex, is_active=True) for org in orgs])
            await seed.flush()
            password = get_password_hash("Owned cancellation synthetic password")
            for index, (user, org) in enumerate(zip(users, orgs, strict=True)):
                name = "owned-cancel-" + uuid4().hex
                seed.add(User(id=user, organization_id=org, username=name, email=name + "@example.com",
                              full_name="Owned cancellation operator", hashed_password=password,
                              role="super_admin" if index == 0 else "viewer", is_active=True,
                              is_verified=True, token_version=17))
            await seed.flush()
            seed.add_all([UserSession(user_id=user, access_jti=claim["jti"], created_at=datetime.now(UTC),
                                      expires_at=datetime.now(UTC) + timedelta(minutes=5))
                          for user, claim in zip(users, claims, strict=True)])
            await seed.commit()
            if operation == "upgrade":
                await loader.install_plugin(archive(slug, "1.0.3"), seed, users[0])
            seed.add(PluginOrganizationState(plugin_id=slug, organization_id=orgs[2], is_enabled=False))
            for org in orgs:
                for key, value in {"minimum_severity": "high", "dry_run": True}.items():
                    seed.add(PluginSetting(plugin_id=slug, organization_id=org, key=key, value=value))
            await seed.commit()
            if operation == "upgrade":
                await endpoints._start_plugin_everywhere(slug, seed, app)
                await seed.commit()
        before_files = disk_files(dest)
        async with AsyncSession(engine) as observer:
            before_settings = await settings_rows(observer, slug)
        old_runtime = runtime_state(loader, slug, orgs)
        headers = [{"Authorization": f"Bearer {token}"} for token in tokens]
        raw = candidate_archive(slug, "dependencies")
        monkeypatch.setattr(loader_module, "_install_python_deps", owned_dependency_worker)
        monkeypatch.setattr(loader_module.settings, "PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS", True)
        cancellations = []
        request_cancelled = False
        response = None
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            url = f"/api/v1/plugins/{slug}/upgrade" if operation == "upgrade" else "/api/v1/plugins/install"
            request_task = asyncio.create_task(client.post(url, headers=headers[0], files={"file": ("owned.zip", raw, "application/zip")}))
            await asyncio.wait_for(started.wait(), timeout=5)
            assert worker_observations["different_thread"] and worker_observations["version_at_start"] == "1.0.4"
            if outcome.startswith("cancel_"):
                cancellations.append(request_task.cancel("Owned first cancellation"))
                # wait() observes without cancelling the request a second time.
                # The worker remains blocked at its explicit release barrier.
                await asyncio.wait({request_task}, timeout=1)
                if "twice" in outcome:
                    cancellations.append(request_task.cancel("Owned repeated cancellation"))
                    await asyncio.wait({request_task}, timeout=0.1)
            done_while_blocked = request_task.done()
            release.set()
            await asyncio.wait_for(finished.wait(), timeout=5)
            done, _ = await asyncio.wait({request_task}, timeout=5)
            assert done, "Owned request did not terminate after worker completed"
            try:
                response = request_task.result()
            except asyncio.CancelledError:
                request_cancelled = True
            routes = [await client.get(f"/api/v1/{slug}/", headers=h) for h in headers]
        async with AsyncSession(engine) as observer:
            rows = (await observer.scalars(select(InstalledPlugin).where(InstalledPlugin.plugin_id.in_(SLUGS)))).all()
            actual_rows = sorted((row.plugin_id, row.version, row.status, row.is_active) for row in rows)
            current_settings = await settings_rows(observer, slug)
            fresh = PluginLoader()
            loaded = await fresh.load_all_plugins(observer)
            fresh_versions = sorted((plugin.manifest.id, plugin._plugin_manifest_data.version) for plugin in loaded)
            disabled = (await observer.scalars(select(PluginOrganizationState).where(PluginOrganizationState.organization_id.in_(orgs)))).all()
        actual = {"operation": operation, "outcome": outcome, "worker": worker_observations,
                  "cancellations_requested": cancellations, "request_done_while_worker_blocked": done_while_blocked,
                  "request_cancelled": request_cancelled, "http_status": response.status_code if response else None,
                  "route_statuses": [r.status_code for r in routes], "rows": actual_rows,
                  "runtime": runtime_state(loader, slug, orgs), "files_unchanged": disk_files(dest) == before_files,
                  "destination_files": disk_files(dest / slug), "settings_unchanged": current_settings == before_settings,
                  "fresh_versions": fresh_versions, "missing_on_disk": fresh.missing_on_disk,
                  "disabled_states": [(orgs.index(row.organization_id), row.is_enabled) for row in disabled],
                  "owned_subscription_delta": len(subscription_ids() - original_subscriptions),
                  "preexisting_subscriptions_preserved": original_subscriptions <= subscription_ids(),
                  "rollback_directories": [x.name for x in dest.glob(f".{slug}-rollback-*")]}
        record_property("actual_dependency_cancellation", json.dumps(actual, sort_keys=True))
        assert not worker_observations.get("fixture_release_timeout"), actual
        assert worker_observations["expected_destination"] and worker_observations["dependencies"] == ["httpx==0.28.1"]
        assert worker_observations["write_completed"] and finished.is_set()
        assert not done_while_blocked and not worker_observations["request_done_at_write"], actual
        assert worker_observations["version_at_write"] == "1.0.4", actual
        cancelled = outcome.startswith("cancel_")
        valid = outcome == "valid"
        assert request_cancelled == cancelled
        if cancelled:
            assert all(cancellations) and len(cancellations) == (2 if "twice" in outcome else 1)
        else:
            assert response.status_code == ((201 if operation == "install" else 200) if valid else 400), actual
        version = "1.0.4" if valid else "1.0.3"
        installed = valid or operation == "upgrade"
        assert actual_rows == ([(slug, version, "installed", True)] if installed else []), actual
        assert fresh_versions == ([(slug, version)] if installed else []) and not fresh.missing_on_disk
        assert actual["settings_unchanged"] and actual["disabled_states"] == [(2, False)]
        assert actual["preexisting_subscriptions_preserved"] and not actual["rollback_directories"]
        if valid:
            expected = {**expected_files(raw), ".owned-dependency-write": hashlib.sha256(MARKER).hexdigest()}
            assert actual["destination_files"] == expected
        else:
            assert actual["files_unchanged"], actual
            assert actual["runtime"] == old_runtime
        if installed:
            assert actual["route_statuses"] == [200, 200, 410]
            assert actual["runtime"] == [{"active": True, "subscriptions": 2, "version": version}] * 2 + [
                {"active": False, "subscriptions": 0, "version": None},
            ]
            assert actual["owned_subscription_delta"] == 4
        else:
            assert actual["route_statuses"] == [404, 404, 404] and actual["owned_subscription_delta"] == 0
    finally:
        release.set()
        if started.is_set():
            await asyncio.wait_for(finished.wait(), timeout=5)
        if request_task is not None:
            done, _ = await asyncio.wait({request_task}, timeout=5)
            assert done, "Owned request leaked"
            if not request_task.cancelled():
                request_task.exception()
        async with AsyncSession(engine) as cleanup:
            await loader.stop_plugin_everywhere(slug, cleanup)
            await cleanup.execute(delete(PluginSetting).where(PluginSetting.organization_id.in_(orgs)))
            await cleanup.execute(delete(PluginOrganizationState).where(PluginOrganizationState.organization_id.in_(orgs)))
            await cleanup.execute(delete(InstalledPlugin).where(InstalledPlugin.installed_by.in_(users)))
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.actor_id.in_([str(user) for user in users])))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id.in_(users)))
            await cleanup.execute(delete(User).where(User.id.in_(users)))
            await cleanup.execute(delete(Organization).where(Organization.id.in_(orgs)))
            await cleanup.commit()
        await engine.dispose()
        from app.db.session import engine as sdk_engine
        await sdk_engine.dispose()
        assert subscription_ids() == original_subscriptions
