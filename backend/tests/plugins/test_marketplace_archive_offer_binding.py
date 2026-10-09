# SPDX-License-Identifier: AGPL-3.0-only
"""Signed offer versus exact downloaded archive identity and manifest version.

Only transport is controlled, with an ephemeral publisher key and exact owned
old/new plugin ZIPs. Real signature, checksum, auth, HTTP, PostgreSQL, loader and
routes execute unchanged. No real registry, vendor or publisher-key use.
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


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("operation", ["install", "upgrade"])
@pytest.mark.parametrize("offer_case", ["different_id", "different_version", "valid"])
async def test_marketplace_archive_matches_signed_offer(
    monkeypatch, tmp_path, record_property, slug, credential, operation, offer_case,
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
    other_slug = next(value for value in SLUGS if value != slug)
    archive_slug = other_slug if offer_case == "different_id" else slug
    archive_version = "1.0.3" if offer_case == "different_version" else "1.0.4"
    raw_archive = archive(archive_slug, archive_version)
    archive_url = f"https://owned.example.invalid/{slug}.zip"
    download_calls = []

    async def controlled_download(url):
        assert url == archive_url
        download_calls.append(url)
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
               "expires_at": (now + timedelta(minutes=15)).isoformat(),
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
        responses = {name: [await client.get(f"/api/v1/{name}/", headers={"Authorization": f"Bearer {tokens[i]}"}) for i in [1, 2]] for name in SLUGS}
        async with AsyncSession(engine) as session:
            rows = (await session.scalars(select(InstalledPlugin).where(InstalledPlugin.plugin_id.in_(SLUGS)))).all()
            settings = {name: await settings_rows(session, name) for name in SLUGS}
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
                "runtime": {name: runtime_state(loader, name, orgs) for name in SLUGS},
                "observer_route_statuses": {name: [r.status_code for r in values] for name, values in responses.items()},
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
            headers = {"Authorization": f"Bearer {tokens[0]}"} if credential == "jwt" else {"X-API-Key": raw_key}
            synced = await asyncio.wait_for(client.post("/api/v1/marketplace/sync", headers=headers), timeout=10)
            assert synced.status_code == 200 and synced.json()["catalog_serial"] == 1, synced.text
            assert not synced.json()["used_seed"]
            before = await observe(client)
            response = await asyncio.wait_for(client.post(f"/api/v1/marketplace/{slug}/{operation}", headers=headers), timeout=15)
            after = await observe(client)
            actual = {"credential": credential, "operation": operation, "offer_case": offer_case,
                "offer_plugin_id": slug, "offer_version": "1.0.4", "archive_plugin_id": archive_slug,
                "archive_version": archive_version, "checksum_matches_download": True,
                "ephemeral_signature_and_ingestion_real": True, "real_network_qualified": False,
                "archive_sha256": hashlib.sha256(raw_archive).hexdigest(), "download_calls": download_calls,
                "http_status": response.status_code, "response_body": response.text,
                "before": before, "after": after, "all_observed_state_unchanged": before == after}
            # Always capture complete durable plugin/files/runtime/catalog state
            # before the proposed refusal assertion, including the other ID.
            record_property("actual_marketplace_archive_binding", json.dumps(actual, sort_keys=True))
            assert download_calls == [archive_url], actual
            if offer_case != "valid":
                assert response.status_code == 400, actual
                assert actual["all_observed_state_unchanged"], actual
            else:
                assert response.status_code == (201 if operation == "install" else 200), actual
                assert after["rows"] == [(slug, "1.0.4", "installed", True)], actual
                assert after["fresh_versions"] == [(slug, "1.0.4")] and not after["fresh_missing"], actual
                assert after["settings"] == before["settings"] and after["disabled"] == [(2, False)], actual
                assert after["observer_route_statuses"][slug] == [200, 410], actual
                assert after["observer_route_statuses"][other_slug] == [404, 404], actual
                assert after["subscription_delta"] == 4, actual
                assert after["catalog_rows"] == [[slug, "published", 1, 1 if operation == "install" else 0]], actual
            assert after["preexisting_subscriptions_preserved"], actual
    finally:
        async with AsyncSession(engine) as cleanup:
            for name in SLUGS:
                await loader.stop_plugin_everywhere(name, cleanup)
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
