# SPDX-License-Identifier: AGPL-3.0-only
"""Signed catalog expiry and committed withdrawal during actual lifecycle waits.

Catalogs are signed by an ephemeral test key and ingested via authenticated HTTP
and PostgreSQL. Transport bytes are controlled; actual signature/checksum,
clock, authentication and lifecycle implementations are unchanged. Expiry is
real wall time. This does not qualify a public registry or cross-worker locks.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import marketplace as marketplace
from app.api.v1.endpoints import plugins as endpoints
from app.core.security import create_access_token, decode_token, get_password_hash
from app.db.session import create_test_engine, get_session
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, User, UserSession
from app.models.marketplace import MarketplaceCatalogState, MarketplacePlugin
from app.models.plugins import InstalledPlugin, PluginOrganizationState, PluginSetting
from app.models.security_audit import AuditLogRecord
from app.plugins import loader as loader_module
from app.plugins.loader import PluginLoader
from tests.plugins.test_plugin_upgrade_rollback import runtime_state, subscription_ids
from tests.plugins.test_ticketing_archive_lifecycle import SLUGS, archive, disk_files, settings_rows

CASES = [("marketplace_install", "catalog_expired"), ("marketplace_install", "valid"),
         ("marketplace_upgrade", "catalog_expired"), ("marketplace_upgrade", "catalog_withdrawn"),
         ("marketplace_upgrade", "valid")]


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


def download_wait_proof(task, event):
    current = task.get_coro()
    actual_wait = False
    for _ in range(150):
        frame = getattr(current, "cr_frame", None)
        if frame is not None and frame.f_code.co_name == "wait" and frame.f_locals.get("self") is event:
            actual_wait = True
        current = getattr(current, "cr_await", None)
        if current is None:
            break
    return {"task_pending": not task.done(), "event_unset": not event.is_set(),
            "actual_owned_event_wait": actual_wait,
            "pending_waiters": sum(not future.done() for future in event._waiters)}


async def wait_for_download(task, event):
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        proof = download_wait_proof(task, event)
        if proof["actual_owned_event_wait"] and proof["pending_waiters"] == 1 and proof["task_pending"]:
            return proof
        if task.done():
            raise AssertionError(f"Request ended before controlled download wait: {task.result().status_code}")
        await asyncio.sleep(.01)
    raise AssertionError("Request did not reach controlled download wait")


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("surface, transition", CASES)
@pytest.mark.parametrize("credential", ["jwt", "api_key"])
async def test_signed_catalog_still_authorizes_plugin_after_lifecycle_wait(
    monkeypatch, tmp_path, record_property, slug, surface, credential, transition,
):
    wait_point = "lifecycle"
    withdrawal = None
    operation = "upgrade" if surface == "marketplace_upgrade" else "install"
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
    app.include_router(marketplace.router, prefix="/api/v1/marketplace")
    raw_archive = archive(slug, "1.0.4")
    archive_url = f"https://owned.example.invalid/{slug}.zip"
    gate = asyncio.Event()
    download_calls = []
    if wait_point == "lifecycle":
        gate.set()

    async def controlled_download(url):
        assert url == archive_url
        download_calls.append(url)
        await gate.wait()
        return raw_archive

    monkeypatch.setattr(endpoints, "_download_plugin_archive", controlled_download)
    monkeypatch.setattr(endpoints.settings, "PLUGIN_ENABLE_DIRECT_URL_INSTALLS", True)
    monkeypatch.setattr(endpoints, "PLUGIN_ALLOWED_DOMAINS", ["owned.example.invalid"])
    signing_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(marketplace, "MARKETPLACE_PUBLISHER_PUBLIC_KEY", signing_key.public_key().public_bytes_raw().hex())
    monkeypatch.setattr(marketplace, "MARKETPLACE_ALLOW_UNSIGNED", False)
    monkeypatch.setattr(marketplace, "MARKETPLACE_MIN_SERIAL", "0")
    monkeypatch.setattr(marketplace, "MARKETPLACE_REGISTRY_URL", "https://owned.example.invalid/plugins.json")
    now = datetime.now(UTC)
    catalog = {"catalog_version": 1, "serial": 1,
               "generated_at": (now - timedelta(minutes=1)).isoformat(),
               "expires_at": (now + timedelta(seconds=5 if transition == "catalog_expired" else 900)).isoformat(),
               "plugins": [{"plugin_id": slug, "slug": slug, "name": slug,
                            "short_description": "Owned download fixture", "author_name": "Owned fixture",
                            "category": "monitoring", "latest_version": "1.0.4", "min_core_version": "0.1.0",
                            "download_url": archive_url, "checksum_sha256": hashlib.sha256(raw_archive).hexdigest()}]}
    catalog["signature"] = signing_key.sign(marketplace._canonical_catalog_bytes(catalog)).hex()

    async def controlled_catalog(url):
        assert url == marketplace.MARKETPLACE_REGISTRY_URL
        return deepcopy(catalog)

    monkeypatch.setattr(marketplace, "_fetch_registry_catalog", controlled_catalog)
    owned_catalog = False

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
    expiration = datetime.now(UTC) + timedelta(seconds=300)
    for user in users:
        token = create_access_token(str(user), token_version=17,
                                    expires_delta=timedelta(seconds=300))
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
            catalog_rows = (await session.execute(select(
                MarketplacePlugin.plugin_id, MarketplacePlugin.status, MarketplacePlugin.catalog_serial,
                MarketplacePlugin.download_count,
            ).where(MarketplacePlugin.plugin_id == slug))).all()
            fresh = PluginLoader()
            loaded = await fresh.load_all_plugins(session)
        return {"catalog_rows": [list(row) for row in catalog_rows],
                "rows": [(row.plugin_id, row.version, row.status, row.is_active) for row in rows],
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
            assert not (await seed.scalars(select(MarketplacePlugin.id))).all()
            assert not (await seed.scalars(select(MarketplaceCatalogState.scope))).all()
            owned_catalog = True
            seed.add_all([Organization(id=org, name="Owned queued authority", slug=uuid4().hex, is_active=True) for org in orgs])
            await seed.flush()
            password = get_password_hash("Owned queued authority synthetic password")
            for index, (user, org) in enumerate(zip(users, orgs, strict=True)):
                name = "owned-queued-" + uuid4().hex
                seed.add(User(id=user, organization_id=None if index == 0 else org,
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
                            expires_at=expiration))
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
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            if surface.startswith("marketplace"):
                synced = await asyncio.wait_for(client.post("/api/v1/marketplace/sync", headers={"Authorization": f"Bearer {tokens[0]}"}), timeout=10)
                assert synced.status_code == 200, synced.text
                assert synced.json()["catalog_serial"] == 1 and not synced.json()["used_seed"]
                async with AsyncSession(engine) as verified:
                    state = await verified.get(MarketplaceCatalogState, "global")
                    assert state.identity == marketplace._catalog_identity() and state.serial == 1
            before = await observe(client)
            if wait_point == "lifecycle":
                await lock.acquire()
                lock_owned = True
            headers = {"Authorization": f"Bearer {tokens[0]}"} if credential == "jwt" else {"X-API-Key": raw_key}
            if surface == "direct_url_install":
                request_task = asyncio.create_task(client.post("/api/v1/plugins/install-url", headers=headers,
                                                               json={"url": archive_url}))
            else:
                request_task = asyncio.create_task(client.post(f"/api/v1/marketplace/{slug}/{operation}", headers=headers))
            proof = (await wait_for_actual_lock(request_task, lock) if wait_point == "lifecycle"
                     else await wait_for_download(request_task, gate))
            async with AsyncSession(engine, expire_on_commit=False) as change:
                waiting_rows = (await change.execute(select(InstalledPlugin.version, InstalledPlugin.status, InstalledPlugin.is_active)
                                                     .where(InstalledPlugin.plugin_id == slug))).all()
            if transition == "catalog_withdrawn":
                catalog = {**catalog, "serial": 2, "plugins": []}
                catalog.pop("signature")
                catalog["signature"] = signing_key.sign(marketplace._canonical_catalog_bytes(catalog)).hex()
                synced = await asyncio.wait_for(client.post("/api/v1/marketplace/sync", headers={"Authorization": f"Bearer {tokens[0]}"}), timeout=10)
                assert synced.status_code == 200, synced.text
                withdrawal = synced.json()
                assert withdrawal["catalog_serial"] == 2 and withdrawal["withdrawn"] == [slug]
            elif transition == "catalog_expired":
                deadline = datetime.fromisoformat(catalog["expires_at"]).timestamp()
                await asyncio.sleep(max(0, deadline - datetime.now(UTC).timestamp()) + 0.1)
                assert datetime.now(UTC).timestamp() > deadline
            proof_after = (lock_wait_proof(request_task, lock) if wait_point == "lifecycle"
                           else download_wait_proof(request_task, gate))
            if lock_owned:
                lock.release()
                lock_owned = False
            gate.set()
            done, _ = await asyncio.wait({request_task}, timeout=15)
            assert done, "Owned plugin request did not leave its released lock"
            response = request_task.result()
            after = await observe(client)
        actual = {"surface": surface, "wait_point": wait_point, "controlled_transport_calls": len(download_calls),
                  "real_network_qualified": False, "operation": operation, "credential": credential, "transition": transition,
                  "before_wait_proof": proof, "after_change_wait_proof": proof_after,
                  "rows_while_waiting": [list(row) for row in waiting_rows],
                  "http_status": response.status_code,
                  "before": before, "after": after,
                  "unchanged": {k: v for k, v in before.items() if k != "catalog_rows"}
                  == {k: v for k, v in after.items() if k != "catalog_rows"},
                  "withdrawal": withdrawal, "catalog_expiry": catalog["expires_at"],
                  "catalog_signature_and_ingestion_real": surface.startswith("marketplace")}
        record_property("actual_catalog_after_lifecycle_wait", json.dumps(actual, sort_keys=True))
        assert len(download_calls) == 1, actual
        assert proof_after["task_pending"] and proof_after["pending_waiters"] == 1, actual
        assert proof_after["actual_lock_acquire_in_coroutine_chain" if wait_point == "lifecycle" else "actual_owned_event_wait"], actual
        if transition != "valid":
            assert response.status_code == 409, actual
            assert actual["unchanged"], actual
            assert after["catalog_rows"] == [[slug, "withdrawn" if transition == "catalog_withdrawn" else "published", 1, 0]]
        else:
            assert response.status_code == (201 if operation == "install" else 200), actual
            assert not actual["unchanged"] and before["settings"] == after["settings"], actual
            assert after["disabled"] == [(2, False)]
            assert after["observer_route_statuses"] == [200, 410]
            assert after["subscription_delta"] == 4
            assert after["rows"] == [(slug, "1.0.4", "installed", True)]
            assert after["fresh_versions"] == [(slug, "1.0.4")]
            assert after["catalog_rows"] == ([] if surface == "direct_url_install" else
                                              [[slug, "published", 1, 1 if operation == "install" else 0]])
        assert after["preexisting_subscriptions_preserved"]
    finally:
        gate.set()
        if lock_owned:
            lock.release()
        if request_task is not None:
            done, _ = await asyncio.wait({request_task}, timeout=15)
            assert done, "Owned request leaked"
            if not request_task.cancelled():
                request_task.exception()
        async with AsyncSession(engine) as cleanup:
            await loader.stop_plugin_everywhere(slug, cleanup)
            if owned_catalog:
                await cleanup.execute(delete(MarketplacePlugin).where(
                    MarketplacePlugin.plugin_id == slug,
                    MarketplacePlugin.catalog_identity == marketplace._catalog_identity(),
                ))
                await cleanup.execute(delete(MarketplaceCatalogState).where(
                    MarketplaceCatalogState.scope == "global",
                    MarketplaceCatalogState.identity == marketplace._catalog_identity(),
                ))
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
