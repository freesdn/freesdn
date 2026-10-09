# SPDX-License-Identifier: AGPL-3.0-only
"""Real authenticated upload, archive loader, runtime routes, and committed PG rows.

The ASGI app contains actual plugin management and dynamically mounted plugin
routes; it does not substitute for production middleware, marketplace transport,
worker coordination, external ticket services, or a process restart.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import plugins as endpoints
from app.core.events import event_bus
from app.core.security import create_access_token, decode_token, get_password_hash
from app.db.session import create_test_engine, get_session
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, User, UserSession
from app.models.plugins import InstalledPlugin, PluginOrganizationState, PluginSetting
from app.models.security_audit import AuditLogRecord
from app.plugins import loader as loader_module
from app.plugins.loader import PluginLoader
from tests.plugins.test_ticketing_archive_lifecycle import (
    SLUGS,
    archive,
    disk_files,
    expected_files,
    settings_rows,
)


def subscription_ids():
    return {s.id for subscriptions in event_bus._subscriptions.values() for s in subscriptions}


def runtime_state(loader, slug, orgs):
    return [{"active": (runtime := loader.get_active_for_org(slug, org)) is not None,
             "subscriptions": len(runtime._event_subscription_ids) if runtime else 0,
             "version": runtime._plugin_manifest_data.version if runtime else None}
            for org in orgs]


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("outcome", ["corrupt", "wrong-plugin", "valid", "denied"])
async def test_authenticated_upload_preserves_running_plugin(
    monkeypatch, tmp_path, record_property, slug, credential, outcome,
):
    engine = create_test_engine()
    orgs, users = [uuid4() for _ in range(3)], [uuid4() for _ in range(3)]
    raw_key, prefix, key_hash = generate_api_key()
    tokens, claims = [], []
    for user_id in users:
        token = create_access_token(str(user_id), token_version=17, expires_delta=timedelta(minutes=5))
        decoded = await decode_token(token)
        assert decoded is not None
        tokens.append(token)
        claims.append(decoded)
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
    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            assert not (await seed.scalars(select(Organization.id).where(Organization.is_active.is_(True)))).all()
            assert not (await seed.scalars(select(InstalledPlugin.plugin_id))).all()
            seed.add_all([Organization(id=org, name="Owned plugin recovery", slug=uuid4().hex, is_active=True) for org in orgs])
            await seed.flush()
            password = get_password_hash("Owned plugin recovery synthetic password")
            for index, (user_id, org) in enumerate(zip(users, orgs, strict=True)):
                name = "owned-plugin-recovery-" + uuid4().hex
                role = "super_admin" if index == 0 and not (outcome == "denied" and credential == "jwt") else "viewer"
                seed.add(User(id=user_id, organization_id=org, username=name, email=name + "@example.com",
                              full_name="Owned plugin operator", hashed_password=password, role=role,
                              is_active=True, is_verified=True, token_version=17))
            await seed.flush()
            seed.add_all([UserSession(user_id=user_id, access_jti=claim["jti"], created_at=datetime.now(UTC),
                                      expires_at=datetime.now(UTC) + timedelta(minutes=5))
                          for user_id, claim in zip(users, claims, strict=True)])
            seed.add(APIKey(user_id=users[0], name="Owned plugin recovery key", key_prefix=prefix,
                            key_hash=key_hash, scopes=["network:read"] if outcome == "denied" else [], is_active=True))
            await seed.commit()
            await loader.install_plugin(archive(slug, "1.0.3"), seed, users[0])
            seed.add(PluginOrganizationState(plugin_id=slug, organization_id=orgs[2], is_enabled=False))
            for index, org in enumerate(orgs):
                for key, value in {"minimum_severity": "high", "dry_run": True, "__retained_ticket__": f"owned-{index}"}.items():
                    seed.add(PluginSetting(plugin_id=slug, organization_id=org, key=key, value=value))
                if slug == "servicenow-incidents":
                    seed.add(PluginSetting(plugin_id=slug, organization_id=org, key="urgency_map", value="critical=1,high=2,medium=2,low=3"))
            await seed.commit()
            await endpoints._start_plugin_everywhere(slug, seed, app)
            await seed.commit()
        before_files = disk_files(dest)
        async with AsyncSession(engine) as observer:
            before_settings = await settings_rows(observer, slug)
        subscriptions_per_org = len(loader._loaded[slug]._plugin_manifest_data.event_subscriptions)
        assert subscriptions_per_org > 0
        expected_old = [{"active": True, "subscriptions": subscriptions_per_org, "version": "1.0.3"}] * 2 + [
            {"active": False, "subscriptions": 0, "version": None},
        ]
        assert runtime_state(loader, slug, orgs) == expected_old
        read_headers = [{"Authorization": f"Bearer {token}"} for token in tokens]
        upgrade_headers = read_headers[0] if credential == "jwt" else {"X-API-Key": raw_key}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            before_routes = [await client.get(f"/api/v1/{slug}/", headers=headers) for headers in read_headers]
            record_property("before_route_statuses", json.dumps([r.status_code for r in before_routes]))
            assert [r.status_code for r in before_routes] == [200, 200, 410]
            for response in before_routes[:2]:
                assert response.json()["minimum_severity"] == "high"
            other = next(s for s in SLUGS if s != slug)
            raw = b"owned-invalid-zip" if outcome == "corrupt" else archive(other if outcome == "wrong-plugin" else slug, "1.0.4")
            response = await client.post(f"/api/v1/plugins/{slug}/upgrade", headers=upgrade_headers,
                                         files={"file": ("candidate.zip", raw, "application/zip")})
            after_routes = [await client.get(f"/api/v1/{slug}/", headers=headers) for headers in read_headers]
        async with AsyncSession(engine) as observer:
            rows = (await observer.scalars(select(InstalledPlugin).where(InstalledPlugin.plugin_id.in_(SLUGS)))).all()
            actual_rows = sorted((r.plugin_id, r.version, r.status, r.is_active) for r in rows)
            after_settings = await settings_rows(observer, slug)
            disabled = (await observer.scalars(select(PluginOrganizationState).where(PluginOrganizationState.organization_id.in_(orgs)))).all()
            actual_disabled = [(orgs.index(row.organization_id), row.is_enabled) for row in disabled]
        actual = {"http_status": response.status_code, "route_statuses": [r.status_code for r in after_routes],
                  "runtime": runtime_state(loader, slug, orgs), "installed_rows": actual_rows,
                  "files_unchanged": disk_files(dest) == before_files, "settings_unchanged": before_settings == after_settings,
                  "disabled_states": actual_disabled, "event_subscription_delta": len(subscription_ids() - original_subscriptions),
                  "preexisting_subscriptions_preserved": original_subscriptions <= subscription_ids()}
        record_property("actual_upgrade_runtime", json.dumps(actual, sort_keys=True))
        assert response.status_code == (200 if outcome == "valid" else 403 if outcome == "denied" else 400), actual
        # Both durable state and runtime observations are recorded before this regression assertion.
        assert actual["route_statuses"] == [200, 200, 410], actual
        version = "1.0.4" if outcome == "valid" else "1.0.3"
        assert actual_rows == [(slug, version, "installed", True)]
        assert actual["settings_unchanged"] and actual_disabled == [(2, False)]
        assert actual["runtime"] == [{"active": True, "subscriptions": subscriptions_per_org, "version": version}] * 2 + [
            {"active": False, "subscriptions": 0, "version": None},
        ]
        assert actual["event_subscription_delta"] == 2 * subscriptions_per_org and actual["preexisting_subscriptions_preserved"]
        assert disk_files(dest / slug) == expected_files(archive(slug, version))
        if outcome != "valid":
            assert actual["files_unchanged"]
        for r in after_routes[:2]:
            assert r.json()["minimum_severity"] == "high"
    finally:
        async with AsyncSession(engine) as cleanup:
            await loader.stop_plugin_everywhere(slug, cleanup)
            await cleanup.execute(delete(PluginSetting).where(PluginSetting.organization_id.in_(orgs)))
            await cleanup.execute(delete(PluginOrganizationState).where(PluginOrganizationState.organization_id.in_(orgs)))
            await cleanup.execute(delete(InstalledPlugin).where(InstalledPlugin.installed_by.in_(users)))
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.actor_id.in_([str(u) for u in users])))
            await cleanup.execute(delete(APIKey).where(APIKey.user_id.in_(users)))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id.in_(users)))
            await cleanup.execute(delete(User).where(User.id.in_(users)))
            await cleanup.execute(delete(Organization).where(Organization.id.in_(orgs)))
            await cleanup.commit()
        await engine.dispose()
        from app.db.session import engine as sdk_engine
        await sdk_engine.dispose()
        assert subscription_ids() == original_subscriptions
