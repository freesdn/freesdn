# SPDX-License-Identifier: AGPL-3.0-only
"""Owned filesystem permission failures and explicit hook failure with HTTP retry.

The kernel denies actual unlink/rename operations on owned directories. The
restart hook raises an explicit controlled error. Real auth, PostgreSQL, loader,
routes and operator retry are used; no crash or external hook effects are proved.
"""
from __future__ import annotations

import errno
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
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
from app.plugins.loader import PluginLoader
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


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("fault_kind", ["remove_denied", "rename_denied", "restart_refused", "cleanup_denied", "valid"])
async def test_recovery_fault_is_visible_and_operator_retry_restores_service(
    monkeypatch, tmp_path, caplog, record_property, slug, fault_kind,
):
    assert os.geteuid() != 0, "The permission fixture must run unprivileged"
    engine = create_test_engine()
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
    changed_permissions = {}
    fault = {"enabled": False, "load_calls": 0, "restart_attempts": 0}
    original_load = loader_module._load_plugin_class

    def deny_write(path):
        assert path.is_dir() and path.is_relative_to(dest) and not path.is_symlink()
        changed_permissions[path] = path.stat().st_mode & 0o777
        path.chmod(0o500)

    def remove_fault():
        fault["enabled"] = False
        for path, mode in changed_permissions.items():
            if path.exists():
                path.chmod(mode)

    def load_with_owned_permissions(path, manifest):
        if fault["enabled"] and manifest.id == slug and manifest.version == "1.0.4":
            fault["load_calls"] += 1
            roots = list(dest.glob(f".{slug}-rollback-*"))
            assert len(roots) == 1 and (roots[0] / "previous").is_dir()
            if fault_kind == "remove_denied":
                deny_write(path)
            elif fault_kind == "rename_denied":
                deny_write(roots[0])
            elif fault_kind == "cleanup_denied":
                deny_write(roots[0] / "previous")
        return original_load(path, manifest)

    async def observe(client, headers):
        routes = [await client.get(f"/api/v1/{slug}/", headers=h) for h in headers]
        async with AsyncSession(engine) as session:
            rows = (await session.scalars(select(InstalledPlugin).where(InstalledPlugin.plugin_id == slug))).all()
            values = [(row.plugin_id, row.version, row.status, row.is_active) for row in rows]
            settings = await settings_rows(session, slug)
            disabled = (await session.scalars(select(PluginOrganizationState).where(PluginOrganizationState.organization_id.in_(orgs)))).all()
            fresh = PluginLoader()
            loaded = await fresh.load_all_plugins(session)
        roots = list(dest.glob(f".{slug}-rollback-*"))
        return {"rows": values, "route_statuses": [r.status_code for r in routes],
                "route_settings": [r.json().get("minimum_severity") for r in routes],
                "runtime": runtime_state(loader, slug, orgs), "settings": settings,
                "disabled": [(orgs.index(row.organization_id), row.is_enabled) for row in disabled],
                "fresh_versions": sorted((p.manifest.id, p._plugin_manifest_data.version) for p in loaded),
                "fresh_missing": fresh.missing_on_disk,
                "files": disk_files(dest / slug),
                "retained": [{"name": root.name, "mode": root.stat().st_mode & 0o777,
                              "previous_files": disk_files(root / "previous")} for root in roots],
                "subscription_delta": len(subscription_ids() - original_subscriptions),
                "preexisting_subscriptions_preserved": original_subscriptions <= subscription_ids()}

    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            assert not (await seed.scalars(select(Organization.id).where(Organization.is_active.is_(True)))).all()
            assert not (await seed.scalars(select(InstalledPlugin.plugin_id))).all()
            seed.add_all([Organization(id=org, name="Owned recovery failure", slug=uuid4().hex, is_active=True) for org in orgs])
            await seed.flush()
            password = get_password_hash("Owned recovery failure synthetic password")
            for index, (user, org) in enumerate(zip(users, orgs, strict=True)):
                name = "owned-recovery-" + uuid4().hex
                seed.add(User(id=user, organization_id=org, username=name, email=name + "@example.com",
                              full_name="Owned recovery operator", hashed_password=password,
                              role="super_admin" if index == 0 else "viewer", is_active=True,
                              is_verified=True, token_version=17))
            await seed.flush()
            seed.add_all([UserSession(user_id=user, access_jti=claim["jti"], created_at=datetime.now(UTC),
                                      expires_at=datetime.now(UTC) + timedelta(minutes=5))
                          for user, claim in zip(users, claims, strict=True)])
            await seed.commit()
            await loader.install_plugin(archive(slug, "1.0.3"), seed, users[0])
            seed.add(PluginOrganizationState(plugin_id=slug, organization_id=orgs[2], is_enabled=False))
            for org in orgs:
                for key, value in {"minimum_severity": "high", "dry_run": True}.items():
                    seed.add(PluginSetting(plugin_id=slug, organization_id=org, key=key, value=value))
            await seed.commit()
            await endpoints._start_plugin_everywhere(slug, seed, app)
            await seed.commit()
            before_settings = await settings_rows(seed, slug)
        previous_runtime = loader.get_active_for_org(slug, orgs[0])
        original_start = previous_runtime.on_start

        async def controlled_restart(org, session):
            fault["restart_attempts"] += 1
            if fault["enabled"]:
                raise RuntimeError("Owned plugin restart refusal")
            await original_start(org, session)

        if fault_kind == "restart_refused":
            monkeypatch.setattr(previous_runtime, "on_start", controlled_restart)
        monkeypatch.setattr(loader_module, "_load_plugin_class", load_with_owned_permissions)
        failed = fault_kind in {"remove_denied", "rename_denied", "restart_refused"}
        raw = candidate_archive(slug, "constructor" if failed else "valid")
        headers = [{"Authorization": f"Bearer {token}"} for token in tokens]
        fault["enabled"] = fault_kind != "valid"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            response = await client.post(f"/api/v1/plugins/{slug}/upgrade", headers=headers[0],
                                         files={"file": ("owned.zip", raw, "application/zip")})
            # Do not reinject a fault while merely inspecting committed state.
            fault["enabled"] = False
            first = await observe(client, headers)
            errors = [record.exc_info[1] for record in caplog.records if record.exc_info]
            os_errors = [{"type": type(exc).__name__, "errno": getattr(exc, "errno", None),
                          "filename": str(exc.filename) if exc.filename is not None else None} for exc in errors if isinstance(exc, OSError)]
            remove_fault()
            retry = await client.post(f"/api/v1/plugins/{slug}/upgrade", headers=headers[0],
                                      files={"file": ("retry.zip", candidate_archive(slug, "valid"), "application/zip")})
            after_retry = await observe(client, headers)
        actual = {"fault_kind": fault_kind, "first_status": response.status_code, "retry_status": retry.status_code,
                  "fault": fault, "native_os_errors": os_errors, "first": first, "after_retry": after_retry,
                  "first_settings_unchanged": first["settings"] == before_settings,
                  "retry_settings_unchanged": after_retry["settings"] == before_settings,
                  "retained_packages_preserved_by_retry": {r["name"]: r["previous_files"] for r in first["retained"]}
                      == {r["name"]: r["previous_files"] for r in after_retry["retained"]}}
        record_property("actual_recovery_failure_and_retry", json.dumps(actual, sort_keys=True))
        assert response.status_code == (400 if failed else 200), actual
        if fault_kind in {"remove_denied", "rename_denied", "cleanup_denied"}:
            assert fault["load_calls"] == 1 and any(e["type"] == "PermissionError" and e["errno"] == errno.EACCES for e in os_errors), actual
        if fault_kind == "restart_refused":
            assert fault["restart_attempts"] == 1, actual
        expected_row = (slug, "1.0.3", "error", False) if failed else (slug, "1.0.4", "installed", True)
        assert first["rows"] == [expected_row], actual
        assert first["route_statuses"] == ([410, 410, 410] if failed else [200, 200, 410]), actual
        assert first["fresh_versions"] == ([] if failed else [(slug, "1.0.4")]) and not first["fresh_missing"]
        assert first["subscription_delta"] == (0 if failed else 4), actual
        assert len(first["retained"]) == (0 if fault_kind == "valid" else 1), actual
        assert all(not row["mode"] & 0o077 for row in first["retained"])
        if fault_kind in {"remove_denied", "rename_denied", "cleanup_denied"}:
            assert first["retained"][0]["previous_files"] == expected_files(archive(slug, "1.0.3")), actual
        elif fault_kind == "restart_refused":
            assert first["files"] == expected_files(archive(slug, "1.0.3")), actual
        assert actual["first_settings_unchanged"] and actual["retry_settings_unchanged"]
        assert actual["retained_packages_preserved_by_retry"], actual
        assert retry.status_code == 200 and after_retry["rows"] == [(slug, "1.0.4", "installed", True)], actual
        assert after_retry["route_statuses"] == [200, 200, 410] and after_retry["route_settings"][:2] == ["high", "high"]
        assert after_retry["files"] == expected_files(candidate_archive(slug, "valid"))
        assert after_retry["fresh_versions"] == [(slug, "1.0.4")] and not after_retry["fresh_missing"]
        assert after_retry["runtime"] == [{"active": True, "subscriptions": 2, "version": "1.0.4"}] * 2 + [
            {"active": False, "subscriptions": 0, "version": None},
        ]
        assert after_retry["subscription_delta"] == 4
        assert first["disabled"] == after_retry["disabled"] == [(2, False)]
        assert first["preexisting_subscriptions_preserved"] and after_retry["preexisting_subscriptions_preserved"]
    finally:
        remove_fault()
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
