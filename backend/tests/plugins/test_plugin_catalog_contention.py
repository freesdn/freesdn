# SPDX-License-Identifier: AGPL-3.0-only
"""Real HTTP/PG catalog writer versus two actual plugin mutex waiters.

Only catalog/archive transport is controlled with an ephemeral publisher key.
Signature, checksum, authentication, SQL, lifecycle and clocks remain real.
The final retry archive changes only the owned manifest version to 1.0.5; this
is not a released plugin package or public-registry network qualification.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from io import BytesIO
from uuid import uuid4
from zipfile import ZipFile

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request
from sqlalchemy import delete, select, text
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
from tests.plugins.test_plugin_catalog_lifecycle_wait import lock_wait_proof
from tests.plugins.test_plugin_upgrade_rollback import runtime_state, subscription_ids
from tests.plugins.test_ticketing_archive_lifecycle import SLUGS, archive, disk_files, settings_rows


def next_owned_archive(raw):
    """Synthetic retry version only; executable bytes remain the actual 1.0.4."""
    out = BytesIO()
    with ZipFile(BytesIO(raw)) as source, ZipFile(out, "w") as dest:
        assert set(source.namelist()) == {"plugin.py", "plugin.yaml"}
        for info in source.infolist():
            data = source.read(info)
            if info.filename == "plugin.yaml":
                assert data.count(b"1.0.4") == 1
                data = data.replace(b"1.0.4", b"1.0.5")
            dest.writestr(info, data)
    return out.getvalue()


async def wait_for_mutex(task, lock, count):
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        proof = lock_wait_proof(task, lock)
        if proof["actual_lock_acquire_in_coroutine_chain"] and proof["pending_waiters"] == count and proof["task_pending"]:
            return proof
        if task.done():
            raise AssertionError(f"Request ended before actual mutex wait: {task.result().status_code}")
        await asyncio.sleep(.01)
    raise AssertionError(f"Actual mutex wait never reached with {count} waiters")


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("pending_writer", [False, True], ids=["no_writer", "withdrawal"])
async def test_marketplace_catalog_contention_completes_and_allows_operator_retry(
    monkeypatch, tmp_path, record_property, slug, credential, pending_writer,
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
    app.include_router(marketplace.router, prefix="/api/v1/marketplace")
    raw_archive = archive(slug, "1.0.4")
    retry_archive = next_owned_archive(raw_archive)
    archive_url = f"https://owned.example.invalid/{slug}-1.0.4.zip"
    retry_url = f"https://owned.example.invalid/{slug}-1.0.5.zip"
    download_calls = []

    async def controlled_download(url):
        assert url in {archive_url, retry_url}
        download_calls.append(url)
        return {archive_url: raw_archive, retry_url: retry_archive}[url]

    monkeypatch.setattr(endpoints, "_download_plugin_archive", controlled_download)
    signing_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(marketplace, "MARKETPLACE_PUBLISHER_PUBLIC_KEY", signing_key.public_key().public_bytes_raw().hex())
    monkeypatch.setattr(marketplace, "MARKETPLACE_ALLOW_UNSIGNED", False)
    monkeypatch.setattr(marketplace, "MARKETPLACE_MIN_SERIAL", "0")
    monkeypatch.setattr(marketplace, "MARKETPLACE_REGISTRY_URL", "https://owned.example.invalid/plugins.json")

    def signed_catalog(serial, version):
        now = datetime.now(UTC)
        catalog = {"catalog_version": 1, "serial": serial,
                   "generated_at": (now - timedelta(minutes=1)).isoformat(),
                   "expires_at": (now + timedelta(minutes=15)).isoformat(), "plugins": []}
        if version is not None:
            raw = raw_archive if version == "1.0.4" else retry_archive
            url = archive_url if version == "1.0.4" else retry_url
            catalog["plugins"].append({"plugin_id": slug, "slug": slug, "name": slug,
                "short_description": "Owned contention fixture", "author_name": "Owned fixture",
                "category": "monitoring", "latest_version": version, "min_core_version": "0.1.0",
                "download_url": url, "checksum_sha256": hashlib.sha256(raw).hexdigest()})
        catalog["signature"] = signing_key.sign(marketplace._canonical_catalog_bytes(catalog)).hex()
        return catalog

    catalog = signed_catalog(1, "1.0.4")

    async def controlled_catalog(url):
        assert url == marketplace.MARKETPLACE_REGISTRY_URL
        return deepcopy(catalog)

    monkeypatch.setattr(marketplace, "_fetch_registry_catalog", controlled_catalog)
    owned_catalog = False
    pids = {}

    async def independent_session(request: Request):
        # Keep the physical connection across the real API-key/upgrade commits.
        async with engine.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                label = request.headers.get("X-Owned-Request")
                if label:
                    assert label not in pids
                    pids[label] = await session.scalar(text("SELECT pg_backend_pid()"))
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
    tasks = {}
    lock = loader.lifecycle_lock(slug)
    lock_owned = False
    tokens, claims = [], []
    expiration = datetime.now(UTC) + timedelta(minutes=10)
    for user in users:
        token = create_access_token(str(user), token_version=17, expires_delta=timedelta(minutes=10))
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
            state = await session.get(MarketplaceCatalogState, "global")
            serial = state.serial if state else None
            fresh = PluginLoader()
            loaded = await fresh.load_all_plugins(session)
        return {"catalog_serial": serial, "catalog_rows": [list(row) for row in catalog_rows],
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
            await loader.install_plugin(archive(slug, "1.0.3"), seed, users[0])
            seed.add(PluginOrganizationState(plugin_id=slug, organization_id=orgs[2], is_enabled=False))
            for org in orgs:
                for key, value in {"minimum_severity": "high", "dry_run": True}.items():
                    seed.add(PluginSetting(plugin_id=slug, organization_id=org, key=key, value=value))
            await seed.commit()
            await endpoints._start_plugin_everywhere(slug, seed, app)
            await seed.commit()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            headers = {"Authorization": f"Bearer {tokens[0]}"} if credential == "jwt" else {"X-API-Key": raw_key}
            synced = await asyncio.wait_for(client.post("/api/v1/marketplace/sync", headers=headers), timeout=10)
            assert synced.status_code == 200 and synced.json()["catalog_serial"] == 1, synced.text
            assert not synced.json()["used_seed"]
            before = await observe(client)
            await lock.acquire()
            lock_owned = True
            tasks["upgrade"] = asyncio.create_task(client.post(
                f"/api/v1/marketplace/{slug}/upgrade", headers={**headers, "X-Owned-Request": "upgrade"}))
            upgrade_wait = await wait_for_mutex(tasks["upgrade"], lock, 1)
            async with AsyncSession(engine) as observer:
                waiting_rows = [list(row) for row in (await observer.execute(select(
                    InstalledPlugin.version, InstalledPlugin.status, InstalledPlugin.is_active,
                ).where(InstalledPlugin.plugin_id == slug))).all()]
            assert waiting_rows == [["1.0.3", "upgrading", True]], waiting_rows
            tasks["install"] = asyncio.create_task(client.post(
                f"/api/v1/marketplace/{slug}/install", headers={**headers, "X-Owned-Request": "install"}))
            install_wait = await wait_for_mutex(tasks["install"], lock, 2)
            writer_wait = None
            async with engine.connect() as observer:
                observer_pid = await observer.scalar(text("SELECT pg_backend_pid()"))
                if pending_writer:
                    catalog = signed_catalog(2, None)
                    tasks["withdrawal"] = asyncio.create_task(client.post(
                        "/api/v1/marketplace/sync", headers={**headers, "X-Owned-Request": "withdrawal"}))
                    deadline = asyncio.get_running_loop().time() + 10
                    while asyncio.get_running_loop().time() < deadline:
                        if "withdrawal" in pids:
                            blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": pids["withdrawal"]})
                            if pids["install"] in blockers and pids["upgrade"] not in blockers:
                                writer_wait = {"backend_pids": dict(pids), "observer_pid": observer_pid,
                                    "blockers": blockers, "writer_pending": not tasks["withdrawal"].done(),
                                    "install_mutex": lock_wait_proof(tasks["install"], lock),
                                    "upgrade_mutex": lock_wait_proof(tasks["upgrade"], lock)}
                                break
                        if tasks["withdrawal"].done():
                            raise AssertionError(f"Catalog writer did not wait: {tasks['withdrawal'].result().status_code}")
                        await asyncio.sleep(.01)
                    assert writer_wait is not None, {"pids": pids}
                assert len(set(pids.values()) | {observer_pid}) == len(pids) + 1, pids
            lock.release()
            lock_owned = False
            _, waiting = await asyncio.wait(set(tasks.values()), timeout=15)
            if waiting:
                async with engine.connect() as observer:
                    blocking = {name: await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": pid})
                                for name, pid in pids.items()}
                record_property("actual_catalog_contention_timeout", json.dumps({
                    "blocking": blocking, "pids": pids,
                    "tasks": {name: lock_wait_proof(task, lock) for name, task in tasks.items()},
                }, sort_keys=True))
                pytest.fail("Owned catalog/lifecycle contention did not complete within 15 seconds")
            responses = {name: task.result() for name, task in tasks.items()}
            after = await observe(client)
            actual = {"credential": credential, "pending_writer": pending_writer,
                      "upgrade_wait": upgrade_wait, "install_wait": install_wait, "writer_wait": writer_wait,
                      "rows_while_waiting": waiting_rows, "request_pids": dict(pids),
                      "http_statuses": {name: response.status_code for name, response in responses.items()},
                      "response_bodies": {name: response.text for name, response in responses.items()},
                      "before": before, "after": after, "download_calls": list(download_calls),
                      "real_network_qualified": False, "retry_archive_is_synthetic_manifest_version": True}
            # Observe durable SQL/files/routes before checking any outcome contract.
            record_property("actual_catalog_contention", json.dumps(actual, sort_keys=True))
            assert actual["http_statuses"] == {"upgrade": 200, "install": 400, **({"withdrawal": 200} if pending_writer else {})}, actual
            assert "already installed" in responses["install"].text, actual
            assert after["rows"] == [(slug, "1.0.4", "installed", True)] and after["fresh_versions"] == [(slug, "1.0.4")], actual
            assert before["settings"] == after["settings"] and after["disabled"] == [(2, False)], actual
            assert after["observer_route_statuses"] == [200, 410] and after["subscription_delta"] == 4, actual
            assert after["catalog_serial"] == (2 if pending_writer else 1), actual
            assert after["catalog_rows"] == [[slug, "withdrawn" if pending_writer else "published", 1, 0]], actual
            assert after["preexisting_subscriptions_preserved"] and not after["fresh_missing"], actual
            if pending_writer:
                assert responses["withdrawal"].json()["withdrawn"] == [slug], actual
            catalog = signed_catalog(3, "1.0.5")
            republished = await asyncio.wait_for(client.post("/api/v1/marketplace/sync", headers=headers), timeout=10)
            assert republished.status_code == 200 and republished.json()["catalog_serial"] == 3, republished.text
            retry = await asyncio.wait_for(client.post(f"/api/v1/marketplace/{slug}/upgrade", headers=headers), timeout=15)
            retried = await observe(client)
            retry_actual = {"status": retry.status_code, "response": retry.text, "after": retried,
                            "settings_unchanged": before["settings"] == retried["settings"]}
            record_property("actual_catalog_contention_retry", json.dumps(retry_actual, sort_keys=True))
            assert retry.status_code == 200 and retry_actual["settings_unchanged"], retry_actual
            assert retried["rows"] == [(slug, "1.0.5", "installed", True)], retry_actual
            assert retried["fresh_versions"] == [(slug, "1.0.5")] and not retried["fresh_missing"], retry_actual
            assert retried["observer_route_statuses"] == [200, 410] and retried["disabled"] == [(2, False)], retry_actual
            assert retried["subscription_delta"] == 4 and retried["preexisting_subscriptions_preserved"], retry_actual
            assert retried["catalog_serial"] == 3 and retried["catalog_rows"] == [[slug, "published", 3, 0]], retry_actual
    finally:
        # Cancel only our requests, writer first, so a failed probe cannot leave
        # a catalog lock cycle behind. No test retry follows a failed outcome.
        for name in ["withdrawal", "install", "upgrade"]:
            task = tasks.get(name)
            if task is not None and not task.done():
                task.cancel()
                done, _ = await asyncio.wait({task}, timeout=15)
                assert done, f"Owned {name} task did not drain after cancellation"
            if task is not None and not task.cancelled():
                task.exception()
        if lock_owned:
            lock.release()
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
