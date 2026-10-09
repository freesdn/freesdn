# SPDX-License-Identifier: AGPL-3.0-only
"""Real initiator authority after catalog network and PostgreSQL writer waits.

Only catalog transport is controlled with an ephemeral publisher key. Actual
signature validation, HTTP/authentication, clocks and committed SQL remain real.
Both ticketing entries share one catalog; no per-plugin duplicate matrix.
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
from fastapi import FastAPI, Request
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import marketplace
from app.core.security import create_access_token, decode_token, get_password_hash
from app.db.session import create_test_engine, get_session
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import User, UserSession
from app.models.marketplace import MarketplaceCatalogState, MarketplacePlugin
from tests.plugins.test_plugin_catalog_lifecycle_wait import download_wait_proof
from tests.plugins.test_ticketing_archive_lifecycle import SLUGS, archive


@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("transition", ["revoked", "role_changed", "expired", "valid"])
@pytest.mark.parametrize("wait_point", ["fetch", "catalog_lock"])
async def test_catalog_sync_rechecks_initiator_after_actual_wait(
    monkeypatch, record_property, credential, transition, wait_point,
):
    engine = create_test_engine()
    user_id, key_id = uuid4(), uuid4()
    raw_key, prefix, key_hash = generate_api_key()
    signing_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(marketplace, "MARKETPLACE_PUBLISHER_PUBLIC_KEY", signing_key.public_key().public_bytes_raw().hex())
    monkeypatch.setattr(marketplace, "MARKETPLACE_ALLOW_UNSIGNED", False)
    monkeypatch.setattr(marketplace, "MARKETPLACE_MIN_SERIAL", "0")
    monkeypatch.setattr(marketplace, "MARKETPLACE_REGISTRY_URL", "https://owned.example.invalid/plugins.json")
    gate = asyncio.Event()
    gate.set()
    payloads = []
    now = datetime.now(UTC)
    first = {"catalog_version": 1, "serial": 1,
             "generated_at": (now - timedelta(minutes=1)).isoformat(),
             "expires_at": (now + timedelta(minutes=15)).isoformat(), "plugins": []}
    for slug in SLUGS:
        first["plugins"].append({"plugin_id": slug, "slug": slug, "name": slug,
            "short_description": "Owned sync authority", "author_name": "Owned fixture",
            "category": "monitoring", "latest_version": "1.0.4", "min_core_version": "0.1.0",
            "download_url": f"https://owned.example.invalid/{slug}-1.0.4.zip",
            "checksum_sha256": hashlib.sha256(archive(slug, "1.0.4")).hexdigest()})
    second = {**first, "serial": 2, "plugins": []}
    for value in [first, second]:
        value["signature"] = signing_key.sign(marketplace._canonical_catalog_bytes(value)).hex()
        payloads.append(value)
    fetch_calls = 0

    async def controlled_catalog(url):
        nonlocal fetch_calls
        assert url == marketplace.MARKETPLACE_REGISTRY_URL
        index = fetch_calls
        fetch_calls += 1
        assert index in (0, 1)
        await gate.wait()
        return deepcopy(payloads[index])

    monkeypatch.setattr(marketplace, "_fetch_registry_catalog", controlled_catalog)
    app = FastAPI()
    app.include_router(marketplace.router, prefix="/api/v1/marketplace")
    request_pid = None

    async def independent_session(request: Request):
        nonlocal request_pid
        # API-key auth commits last_used: keep the physical connection stable.
        async with engine.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                if request.headers.get("X-Owned-Probe"):
                    assert request_pid is None
                    request_pid = await session.scalar(text("SELECT pg_backend_pid()"))
                try:
                    yield session
                    await session.commit()
                except BaseException:
                    await session.rollback()
                    raise

    app.dependency_overrides[get_session] = independent_session
    lifetime = 5 if transition == "expired" else 300
    token = create_access_token(str(user_id), token_version=17, expires_delta=timedelta(seconds=lifetime))
    claims = await decode_token(token)
    assert claims is not None
    expiry = datetime.now(UTC) + timedelta(seconds=lifetime)
    task = None
    owner_session = None
    owner_connection = None
    owned_catalog = False

    async def snapshot():
        async with AsyncSession(engine) as session:
            state = await session.get(MarketplaceCatalogState, "global")
            rows = (await session.execute(select(
                MarketplacePlugin.plugin_id, MarketplacePlugin.latest_version,
                MarketplacePlugin.catalog_identity, MarketplacePlugin.catalog_serial,
                MarketplacePlugin.status, MarketplacePlugin.download_count,
                MarketplacePlugin.download_url, MarketplacePlugin.checksum_sha256,
            ).order_by(MarketplacePlugin.plugin_id))).all()
            return {"state": {"identity": state.identity, "serial": state.serial,
                    "digest": state.payload_sha256, "generated_at": state.generated_at.isoformat(),
                    "expires_at": state.expires_at.isoformat()}, "rows": [list(row) for row in rows]}

    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            assert not (await seed.scalars(select(MarketplacePlugin.id))).all()
            assert not (await seed.scalars(select(MarketplaceCatalogState.scope))).all()
            owned_catalog = True
            name = "owned-sync-" + uuid4().hex
            seed.add(User(id=user_id, username=name, email=name + "@example.com", organization_id=None,
                          full_name="Owned sync operator", hashed_password=get_password_hash("Owned synthetic catalog password"),
                          role="super_admin", is_active=True, is_verified=True, token_version=17))
            await seed.flush()
            seed.add(UserSession(user_id=user_id, access_jti=claims["jti"], created_at=datetime.now(UTC),
                                 expires_at=datetime.fromtimestamp(claims["exp"], UTC)))
            seed.add(APIKey(id=key_id, user_id=user_id, name="Owned sync key", key_prefix=prefix,
                            key_hash=key_hash, scopes=[], is_active=True, expires_at=expiry))
            await seed.commit()
        headers = {"Authorization": f"Bearer {token}"} if credential == "jwt" else {"X-API-Key": raw_key}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            initial = await asyncio.wait_for(client.post("/api/v1/marketplace/sync", headers=headers), timeout=10)
            assert initial.status_code == 200 and initial.json()["catalog_serial"] == 1, initial.text
            assert not initial.json()["used_seed"] and initial.json()["synced"] == 2
            before = await snapshot()
            owner_pid = None
            if wait_point == "fetch":
                gate.clear()
            else:
                owner_connection = await engine.connect()
                owner_session = AsyncSession(bind=owner_connection, expire_on_commit=False, autoflush=False)
                owner_pid = await owner_session.scalar(text("SELECT pg_backend_pid()"))
                await owner_session.execute(select(MarketplaceCatalogState).where(
                    MarketplaceCatalogState.scope == "global").with_for_update())
            task = asyncio.create_task(client.post("/api/v1/marketplace/sync", headers={**headers, "X-Owned-Probe": "true"}))
            proof = None
            async with engine.connect() as observer:
                observer_pid = await observer.scalar(text("SELECT pg_backend_pid()"))
                deadline = asyncio.get_running_loop().time() + 10
                while asyncio.get_running_loop().time() < deadline:
                    if wait_point == "fetch":
                        candidate = download_wait_proof(task, gate)
                        if candidate["actual_owned_event_wait"] and candidate["task_pending"] and candidate["pending_waiters"] == 1:
                            proof = candidate
                            break
                    elif request_pid is not None:
                        blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": request_pid})
                        if owner_pid in blockers:
                            proof = {"owner_pid": owner_pid, "request_pid": request_pid,
                                     "observer_pid": observer_pid, "blockers": blockers,
                                     "request_pending": not task.done()}
                            assert len({owner_pid, request_pid, observer_pid}) == 3
                            break
                    if task.done():
                        raise AssertionError(f"Sync ended before actual owned wait: HTTP{task.result().status_code}")
                    await asyncio.sleep(.01)
            assert proof is not None, {"wait_point": wait_point, "request_pid": request_pid}
            if transition == "expired":
                deadline = claims["exp"] if credential == "jwt" else expiry.timestamp()
                await asyncio.sleep(max(0, deadline - datetime.now(UTC).timestamp()) + .1)
                assert datetime.now(UTC).timestamp() > deadline
            elif transition != "valid":
                async with AsyncSession(engine) as change:
                    if transition == "role_changed":
                        await change.execute(update(User).where(User.id == user_id).values(role="viewer"))
                    elif credential == "jwt":
                        await change.execute(update(User).where(User.id == user_id).values(token_version=18))
                    else:
                        await change.execute(update(APIKey).where(APIKey.id == key_id).values(is_active=False))
                    await change.commit()
            assert not task.done()
            if owner_session is not None:
                await owner_session.rollback()
            gate.set()
            done, _ = await asyncio.wait({task}, timeout=15)
            assert done, "Owned sync did not leave the released wait"
            response = task.result()
            after = await snapshot()
            actual = {"credential": credential, "transition": transition, "wait_point": wait_point,
                      "genuine_wait": proof, "fetch_calls": fetch_calls,
                      "http_status": response.status_code, "response": response.text,
                      "before": before, "after": after, "unchanged": before == after,
                      "real_signature_authentication_SQL": True, "real_network_qualified": False}
            record_property("actual_marketplace_sync_authority", json.dumps(actual, sort_keys=True))
            assert fetch_calls == 2, actual
            if transition == "valid":
                assert response.status_code == 200 and after["state"]["serial"] == 2, actual
                assert sorted(response.json()["withdrawn"]) == sorted(SLUGS), actual
                assert len(after["rows"]) == 2 and all(row[4] == "withdrawn" for row in after["rows"]), actual
            else:
                assert response.status_code == 401, actual
                assert actual["unchanged"], actual
    finally:
        gate.set()
        if owner_session is not None:
            await owner_session.rollback()
            await owner_session.close()
        if owner_connection is not None:
            await owner_connection.close()
        if task is not None:
            if not task.done():
                task.cancel()
                done, _ = await asyncio.wait({task}, timeout=15)
                assert done, "Owned catalog sync task leaked"
            if not task.cancelled():
                task.exception()
        async with AsyncSession(engine) as cleanup:
            if owned_catalog:
                await cleanup.execute(delete(MarketplacePlugin).where(
                    MarketplacePlugin.plugin_id.in_(SLUGS), MarketplacePlugin.catalog_identity == marketplace._catalog_identity()))
                await cleanup.execute(delete(MarketplaceCatalogState).where(
                    MarketplaceCatalogState.scope == "global", MarketplaceCatalogState.identity == marketplace._catalog_identity()))
            await cleanup.execute(delete(APIKey).where(APIKey.user_id == user_id))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.commit()
        await engine.dispose()
