# SPDX-License-Identifier: AGPL-3.0-only
"""Real authenticated plugin mutations waiting on their actual lifecycle mutex.

Independent PostgreSQL commits change the initiating principal after a verified
Lock.acquire wait. No auth, session, loader, lock or clock implementation is
mocked. Organization/password changes additionally test conservative initiating
context binding; do not label every such refusal contract a proven privilege gain.
"""
from __future__ import annotations

import asyncio
import json
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
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, User, UserSession
from app.models.plugins import InstalledPlugin, PluginOrganizationState, PluginSetting
from app.models.security_audit import AuditLogRecord
from app.plugins import loader as loader_module
from app.plugins.loader import PluginLoader
from tests.plugins.test_plugin_upgrade_rollback import runtime_state, subscription_ids
from tests.plugins.test_ticketing_archive_lifecycle import SLUGS, archive, disk_files, settings_rows

COMMON = ["account_disabled", "soft_deleted", "role_downgrade", "organization_changed", "password_changed"]
CASES = [(credential, change) for credential in ["jwt", "api_key"]
         for change in COMMON + (["jwt_version", "session_revoked", "expired"] if credential == "jwt"
                                 else ["key_revoked", "key_scoped", "expired"]) + ["valid"]]
OPERATIONS = ["install", "upgrade", "uninstall", "enable", "disable"]


def lock_wait_proof(task, lock):
    current = task.get_coro()
    stack = []
    actual_acquire = False
    for _ in range(150):
        frame = getattr(current, "cr_frame", None) or getattr(current, "gi_frame", None)
        if frame is not None:
            name = frame.f_code.co_name
            stack.append(name)
            if name == "acquire" and frame.f_locals.get("self") is lock:
                actual_acquire = True
        current = getattr(current, "cr_await", None) or getattr(current, "gi_yieldfrom", None)
        if current is None:
            break
    waiters = list(lock._waiters or ())
    return {"task_pending": not task.done(), "lock_held": lock.locked(),
            "pending_waiters": sum(not future.done() for future in waiters),
            "actual_lock_acquire_in_coroutine_chain": actual_acquire, "coroutine_chain": stack}


async def wait_for_actual_lock(task, lock):
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        proof = lock_wait_proof(task, lock)
        if proof["actual_lock_acquire_in_coroutine_chain"] and proof["pending_waiters"] == 1 and proof["task_pending"]:
            return proof
        if task.done():
            response = task.result()
            raise AssertionError(f"Request ended before the actual lock wait: HTTP {response.status_code}")
        await asyncio.sleep(0.01)
    raise AssertionError("Request never reached the owned lifecycle lock")


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("credential, transition", CASES)
async def test_queued_plugin_mutation_rechecks_initiating_authority(
    monkeypatch, tmp_path, record_property, slug, operation, credential, transition,
):
    engine = create_test_engine()
    orgs, users = [uuid4() for _ in range(3)], [uuid4() for _ in range(3)]
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
    raw_key, prefix, key_hash = generate_api_key()
    key_id = uuid4()
    original_subscriptions = subscription_ids()
    request_task = None
    lock = loader.lifecycle_lock(slug)
    lock_owned = False
    tokens, claims = [], []
    expiration = datetime.now(UTC) + timedelta(seconds=5 if transition == "expired" else 300)
    for index, user in enumerate(users):
        token = create_access_token(str(user), token_version=17,
                                    expires_delta=timedelta(seconds=5 if transition == "expired" and credential == "jwt" and index == 0 else 300))
        claim = await decode_token(token)
        assert claim is not None
        tokens.append(token)
        claims.append(claim)

    async def observe(client):
        # The two observers are unaffected by the initiating actor's revocation.
        responses = [await client.get(f"/api/v1/{slug}/", headers={"Authorization": f"Bearer {tokens[i]}"}) for i in [1, 2]]
        async with AsyncSession(engine) as session:
            rows = (await session.scalars(select(InstalledPlugin).where(InstalledPlugin.plugin_id == slug))).all()
            settings = await settings_rows(session, slug)
            states = (await session.scalars(select(PluginOrganizationState).where(PluginOrganizationState.organization_id.in_(orgs)))).all()
            fresh = PluginLoader()
            loaded = await fresh.load_all_plugins(session)
        return {"rows": [(row.plugin_id, row.version, row.status, row.is_active) for row in rows],
                "files": disk_files(dest), "settings": settings,
                "disabled": [(orgs.index(row.organization_id), row.is_enabled) for row in states],
                "runtime": runtime_state(loader, slug, orgs), "observer_route_statuses": [r.status_code for r in responses],
                "fresh_versions": sorted((p.manifest.id, p._plugin_manifest_data.version) for p in loaded),
                "fresh_missing": fresh.missing_on_disk,
                "subscription_delta": len(subscription_ids() - original_subscriptions),
                "preexisting_subscriptions_preserved": original_subscriptions <= subscription_ids()}

    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            assert not (await seed.scalars(select(Organization.id).where(Organization.is_active.is_(True)))).all()
            assert not (await seed.scalars(select(InstalledPlugin.plugin_id))).all()
            seed.add_all([Organization(id=org, name="Owned queued authority", slug=uuid4().hex, is_active=True) for org in orgs])
            await seed.flush()
            password = get_password_hash("Owned queued authority synthetic password")
            for index, (user, org) in enumerate(zip(users, orgs, strict=True)):
                name = "owned-queued-" + uuid4().hex
                seed.add(User(id=user, organization_id=None if index == 0 and operation in {"enable", "disable"} else org,
                              username=name, email=name + "@example.com",
                              full_name="Owned queued operator", hashed_password=password,
                              role="super_admin" if index == 0 else "viewer", is_active=True,
                              is_verified=True, token_version=17))
            await seed.flush()
            seed.add_all([UserSession(user_id=user, access_jti=claim["jti"], created_at=datetime.now(UTC),
                                      expires_at=datetime.fromtimestamp(claim["exp"], UTC))
                          for user, claim in zip(users, claims, strict=True)])
            seed.add(APIKey(id=key_id, user_id=users[0], name="Owned queued authority key", key_prefix=prefix,
                            key_hash=key_hash, scopes=[], is_active=True,
                            expires_at=expiration if transition == "expired" and credential == "api_key" else None))
            await seed.commit()
            if operation != "install":
                await loader.install_plugin(archive(slug, "1.0.3"), seed, users[0])
            seed.add(PluginOrganizationState(plugin_id=slug, organization_id=orgs[2], is_enabled=False))
            for org in orgs:
                for key, value in {"minimum_severity": "high", "dry_run": True}.items():
                    seed.add(PluginSetting(plugin_id=slug, organization_id=org, key=key, value=value))
            await seed.commit()
            if operation != "install":
                await endpoints._start_plugin_everywhere(slug, seed, app)
                await seed.commit()
            if operation == "enable":
                await loader.stop_plugin_everywhere(slug, seed)
                row = (await seed.scalars(select(InstalledPlugin).where(InstalledPlugin.plugin_id == slug))).one()
                row.is_active = False
                row.status = "disabled"
                await seed.commit()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            before = await observe(client)
            await lock.acquire()
            lock_owned = True
            headers = {"Authorization": f"Bearer {tokens[0]}"} if credential == "jwt" else {"X-API-Key": raw_key}
            if operation == "uninstall":
                request_task = asyncio.create_task(client.delete(f"/api/v1/plugins/{slug}", headers=headers))
            elif operation in {"install", "upgrade"}:
                url = "/api/v1/plugins/install" if operation == "install" else f"/api/v1/plugins/{slug}/upgrade"
                request_task = asyncio.create_task(client.post(url, headers=headers,
                                            files={"file": ("owned.zip", archive(slug, "1.0.4"), "application/zip")}))
            else:
                request_task = asyncio.create_task(client.post(f"/api/v1/plugins/{slug}/{operation}", headers=headers))
            proof = await wait_for_actual_lock(request_task, lock)
            async with AsyncSession(engine, expire_on_commit=False) as change:
                actor = await change.get(User, users[0])
                if transition == "account_disabled":
                    actor.is_active = False
                elif transition == "soft_deleted":
                    actor.deleted_at = datetime.now(UTC)
                elif transition == "role_downgrade":
                    actor.role = "viewer"
                elif transition == "organization_changed":
                    actor.organization_id = orgs[1]
                elif transition == "password_changed":
                    actor.hashed_password = get_password_hash("Owned replacement synthetic password")
                elif transition == "jwt_version":
                    actor.token_version = 18
                elif transition == "session_revoked":
                    session_row = (await change.scalars(select(UserSession).where(UserSession.access_jti == claims[0]["jti"]))).one()
                    session_row.is_revoked = True
                    session_row.revoked_at = datetime.now(UTC)
                elif transition in {"key_revoked", "key_scoped"}:
                    key = await change.get(APIKey, key_id)
                    if transition == "key_revoked":
                        key.is_active = False
                    else:
                        key.scopes = ["network:read"]
                await change.commit()
                waiting_rows = (await change.execute(select(InstalledPlugin.version, InstalledPlugin.status, InstalledPlugin.is_active)
                                                     .where(InstalledPlugin.plugin_id == slug))).all()
            if transition == "expired":
                deadline = claims[0]["exp"] if credential == "jwt" else expiration.timestamp()
                await asyncio.sleep(max(0, deadline - datetime.now(UTC).timestamp()) + 0.1)
                assert datetime.now(UTC).timestamp() > deadline
            proof_after = lock_wait_proof(request_task, lock)
            lock.release()
            lock_owned = False
            done, _ = await asyncio.wait({request_task}, timeout=15)
            assert done, "Owned plugin request did not leave its released lock"
            response = request_task.result()
            after = await observe(client)
        actual = {"operation": operation, "credential": credential, "transition": transition,
                  "before_wait_proof": proof, "after_change_wait_proof": proof_after,
                  "rows_while_waiting": [list(row) for row in waiting_rows],
                  "http_status": response.status_code,
                  "before": before, "after": after,
                  "unchanged": before == after,
                  "initiating_context_contract": transition in {"organization_changed", "password_changed"}}
        record_property("actual_queued_plugin_authority", json.dumps(actual, sort_keys=True))
        assert proof_after["task_pending"] and proof_after["actual_lock_acquire_in_coroutine_chain"] and proof_after["pending_waiters"] == 1, actual
        if transition != "valid":
            assert response.status_code in {401, 403}, actual
            assert actual["unchanged"], actual
        else:
            assert response.status_code == (201 if operation == "install" else 204 if operation == "uninstall" else 200), actual
            assert not actual["unchanged"] and before["settings"] == after["settings"], actual
            assert after["disabled"] == [(2, False)]
            assert after["observer_route_statuses"] == ([410, 410] if operation in {"disable", "uninstall"} else [200, 410])
            assert after["subscription_delta"] == (0 if operation in {"disable", "uninstall"} else 4)
            if operation == "uninstall":
                assert after["rows"] == [(slug, "1.0.3", "uninstalled", False)] and after["files"] == {}
            elif operation == "disable":
                assert after["rows"] == [(slug, "1.0.3", "disabled", False)] and after["files"] == before["files"]
            else:
                version = "1.0.3" if operation == "enable" else "1.0.4"
                assert after["rows"] == [(slug, version, "installed", True)]
                assert after["fresh_versions"] == [(slug, version)]
        assert after["preexisting_subscriptions_preserved"]
    finally:
        if lock_owned:
            lock.release()
        if request_task is not None:
            done, _ = await asyncio.wait({request_task}, timeout=15)
            assert done, "Owned request leaked"
            if not request_task.cancelled():
                request_task.exception()
        async with AsyncSession(engine) as cleanup:
            await loader.stop_plugin_everywhere(slug, cleanup)
            await cleanup.execute(delete(PluginSetting).where(PluginSetting.organization_id.in_(orgs)))
            await cleanup.execute(delete(PluginOrganizationState).where(PluginOrganizationState.organization_id.in_(orgs)))
            await cleanup.execute(delete(InstalledPlugin).where(InstalledPlugin.installed_by.in_(users)))
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.actor_id.in_([str(user) for user in users])))
            await cleanup.execute(delete(APIKey).where(APIKey.user_id.in_(users)))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id.in_(users)))
            await cleanup.execute(delete(User).where(User.id.in_(users)))
            await cleanup.execute(delete(Organization).where(Organization.id.in_(orgs)))
            await cleanup.commit()
        await engine.dispose()
        from app.db.session import engine as sdk_engine
        await sdk_engine.dispose()
        assert subscription_ids() == original_subscriptions
