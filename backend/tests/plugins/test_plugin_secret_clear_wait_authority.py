# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit secret clearing after an actual plaintext-row wait, with revocation controls.

The installed-plugin record is synthetic and has no executing plugin. Encryption,
permissions, expiry, SQL upserts and transaction rollback are not mocked. This
does not qualify plugin installation, vendor validation or external transport.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, Request
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import plugins
from app.core.security import create_access_token, decode_token, get_password_hash
from app.core.security_utils import decrypt_webhook_secret, encrypt_webhook_secret
from app.db.session import create_test_engine, get_session
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, User, UserSession
from app.models.plugins import InstalledPlugin, PluginSetting

TRANSITIONS = [(credential, transition) for credential in ("jwt", "api_key")
               for transition in ("revoked", "valid")]


@pytest.mark.parametrize("credential,transition", TRANSITIONS)
@pytest.mark.parametrize("setting_kind", ["secret"])
async def test_secret_clear_rechecks_initiator_after_plaintext_row_wait(
    record_property, credential, transition, setting_kind,
):
    engine = create_test_engine()
    user_id, key_id, org_id, other_org_id = (uuid4() for _ in range(4))
    slug = "owned-settings-" + uuid4().hex
    raw_key, prefix, key_hash = generate_api_key()
    original_secret = "Owned synthetic prior setting " + uuid4().hex
    replacement_secret = ""
    original_ciphertext = encrypt_webhook_secret(original_secret)
    old_plaintext = "owned legacy plaintext twin"
    app = FastAPI()
    app.include_router(plugins.router, prefix="/api/v1/plugins")
    request_pid = None

    async def independent_session(request: Request):
        nonlocal request_pid
        # API-key last_used commits must not change the observed physical PID.
        async with engine.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                assert request.headers.get("X-Owned-Probe") and request_pid is None
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

    async def snapshot():
        async with AsyncSession(engine) as session:
            rows = (await session.execute(select(
                PluginSetting.organization_id, PluginSetting.key, PluginSetting.value,
            ).where(PluginSetting.plugin_id == slug))).all()
            settings = {str(org): {} for org in (org_id, other_org_id)}
            for org, key, value in rows:
                settings[str(org)][key] = value
            own = settings[str(org_id)]
            encrypted = own.get("api_token:encrypted")
            # Retain equality proof without logging raw synthetic secrets/ciphertext.
            return {
                "plain": own["region"], "sentinel": own["sentinel"],
                "plaintext_twin_is_original": own.get("api_token") == old_plaintext,
                "plaintext_twin_blank": own.get("api_token") in (None, ""),
                "ciphertext_sha256": hashlib.sha256(encrypted.encode()).hexdigest() if encrypted else None,
                "decrypted_is_original": bool(encrypted) and decrypt_webhook_secret(encrypted) == original_secret,
                "decrypted_is_empty": not encrypted or decrypt_webhook_secret(encrypted) == "",
                "other_org_unchanged": settings[str(other_org_id)] == {"sentinel": "other-org-original"},
                "row_count": len(rows),
            }

    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            seed.add_all([
                Organization(id=org_id, name="Owned settings organization", slug=slug + "-org"),
                Organization(id=other_org_id, name="Owned other organization", slug=slug + "-other"),
            ])
            await seed.flush()
            seed.add(User(id=user_id, username=slug, email=slug + "@example.com", organization_id=org_id,
                          full_name="Owned settings administrator", hashed_password=get_password_hash("Owned settings password"),
                          role="org_admin", is_active=True, is_verified=True, token_version=17))
            await seed.flush()
            seed.add(UserSession(user_id=user_id, access_jti=claims["jti"], created_at=datetime.now(UTC),
                                 expires_at=datetime.fromtimestamp(claims["exp"], UTC)))
            seed.add(APIKey(id=key_id, user_id=user_id, name="Owned settings key", key_prefix=prefix,
                            key_hash=key_hash, scopes=[], is_active=True, expires_at=expiry))
            seed.add(InstalledPlugin(plugin_id=slug, name="Owned settings fixture", version="1.0.0",
                                     plugin_dir="/owned-not-executed", is_active=False, status="disabled",
                                     manifest_cache={"settings_schema": {"properties": {
                                         "region": {"type": "string"},
                                         "api_token": {"type": "string", "secret": True},
                                     }}}))
            for key, value in {"region": "original-region", "sentinel": "own-original",
                               "api_token": old_plaintext, "api_token:encrypted": original_ciphertext}.items():
                seed.add(PluginSetting(plugin_id=slug, organization_id=org_id, key=key, value=value))
            seed.add(PluginSetting(plugin_id=slug, organization_id=other_org_id, key="sentinel", value="other-org-original"))
            await seed.commit()
        before = await snapshot()
        headers = {"Authorization": f"Bearer {token}"} if credential == "jwt" else {"X-API-Key": raw_key}
        target_key = "api_token"
        body = {"api_token": replacement_secret}
        owner_connection = await engine.connect()
        owner_session = AsyncSession(bind=owner_connection, expire_on_commit=False, autoflush=False)
        owner_pid = await owner_session.scalar(text("SELECT pg_backend_pid()"))
        await owner_session.execute(select(PluginSetting).where(
            PluginSetting.plugin_id == slug, PluginSetting.organization_id == org_id,
            PluginSetting.key == target_key,
        ).with_for_update())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            task = asyncio.create_task(client.put(f"/api/v1/plugins/{slug}/settings",
                headers={**headers, "X-Owned-Probe": "true"}, json={"settings": body}))
            proof = None
            async with engine.connect() as observer:
                observer_pid = await observer.scalar(text("SELECT pg_backend_pid()"))
                deadline = asyncio.get_running_loop().time() + 10
                while asyncio.get_running_loop().time() < deadline:
                    if request_pid is not None:
                        blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": request_pid})
                        if owner_pid in blockers:
                            proof = {"owner_pid": owner_pid, "request_pid": request_pid,
                                     "observer_pid": observer_pid, "blockers": blockers,
                                     "request_pending": not task.done(), "blocked_key": target_key}
                            assert len({owner_pid, request_pid, observer_pid}) == 3
                            break
                    if task.done():
                        raise AssertionError(f"Settings ended before actual owned row wait: HTTP{task.result().status_code}")
                    await asyncio.sleep(.01)
            assert proof is not None, {"request_pid": request_pid, "blocked_key": target_key}
            if transition == "expired":
                deadline = claims["exp"] if credential == "jwt" else expiry.timestamp()
                await asyncio.sleep(max(0, deadline - datetime.now(UTC).timestamp()) + .1)
                assert datetime.now(UTC).timestamp() > deadline
            elif transition != "valid":
                async with AsyncSession(engine) as change:
                    if transition == "scoped":
                        await change.execute(update(APIKey).where(APIKey.id == key_id).values(scopes=["plugins.view"]))
                    elif transition == "revoked" and credential == "api_key":
                        await change.execute(update(APIKey).where(APIKey.id == key_id).values(is_active=False))
                    else:
                        values = {
                            "revoked": {"token_version": 18}, "disabled": {"is_active": False},
                            "deleted": {"deleted_at": datetime.now(UTC)}, "role_changed": {"role": "viewer"},
                            "org_changed": {"organization_id": other_org_id},
                        }[transition]
                        await change.execute(update(User).where(User.id == user_id).values(**values))
                    await change.commit()
            assert not task.done()
            while_waiting = await snapshot()
            await owner_session.rollback()
            done, _ = await asyncio.wait({task}, timeout=15)
            assert done, "Settings request did not leave released row wait"
            response = task.result()
            after = await snapshot()
            observation = {
                "credential": credential, "transition": transition, "setting_kind": setting_kind,
                "genuine_wait": proof, "http_status": response.status_code,
                "response_contains_secret": original_secret in response.text,
                "before": before, "while_waiting": while_waiting, "after": after,
                "unchanged": before == after, "real_authentication_SQL_encryption": True,
                "plugin_runtime_or_vendor_validation_qualified": False,
                "initiating_organization_contract": transition == "org_changed",
            }
            record_property("actual_plugin_secret_clear_wait_authority", json.dumps(observation, sort_keys=True))
            assert while_waiting == before, observation
            assert not observation["response_contains_secret"] and after["other_org_unchanged"], observation
            if transition == "valid":
                assert response.status_code == 200, observation
                assert after["sentinel"] == before["sentinel"] and after["row_count"] <= before["row_count"], observation
                assert after["plaintext_twin_blank"] and not after["plaintext_twin_is_original"], observation
                assert after["decrypted_is_empty"] and not after["decrypted_is_original"], observation
                assert after["ciphertext_sha256"] != before["ciphertext_sha256"] and after["plain"] == before["plain"], observation
                assert response.json() == {"settings": {"api_token": ""}}, observation
            else:
                assert response.status_code == 401, observation
                assert observation["unchanged"], observation
    finally:
        if owner_session is not None:
            await owner_session.rollback()
            await owner_session.close()
        if owner_connection is not None:
            await owner_connection.close()
        if task is not None:
            if not task.done():
                task.cancel()
                done, _ = await asyncio.wait({task}, timeout=15)
                assert done, "Owned settings task leaked"
            if not task.cancelled():
                task.exception()
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(PluginSetting).where(PluginSetting.plugin_id == slug,
                PluginSetting.organization_id.in_([org_id, other_org_id])))
            await cleanup.execute(delete(InstalledPlugin).where(InstalledPlugin.plugin_id == slug))
            await cleanup.execute(delete(APIKey).where(APIKey.user_id == user_id))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.execute(delete(Organization).where(Organization.id.in_([org_id, other_org_id])))
            await cleanup.commit()
        await engine.dispose()
