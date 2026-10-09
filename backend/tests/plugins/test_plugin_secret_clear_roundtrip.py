# SPDX-License-Identifier: AGPL-3.0-only
"""Actual settings HTTP/SDK secret roundtrips; no running plugin or vendor calls."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import plugins
from app.core.security import create_access_token, decode_token, get_password_hash
from app.core.security_utils import encrypt_webhook_secret
from app.db.session import create_test_engine, get_session
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, User, UserSession
from app.models.plugins import InstalledPlugin, PluginSetting
from app.plugins.sdk import PluginSettingsSDK


@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("declaration", ["secret", "password"])
@pytest.mark.parametrize("storage", ["encrypted", "legacy_and_encrypted", "legacy_only"])
@pytest.mark.parametrize("action", ["clear", "mask", "omit", "replace"])
async def test_plugin_secret_roundtrip_preserves_operator_intent(
    record_property, credential, declaration, storage, action,
):
    engine = create_test_engine()
    user_id, key_id, org_id, other_org_id = (uuid4() for _ in range(4))
    slug = "owned-secret-" + uuid4().hex
    other_plugin = slug + "-other"
    original_secret = "Owned synthetic original " + uuid4().hex
    replacement_secret = "Owned synthetic replacement " + uuid4().hex
    original_ciphertext = encrypt_webhook_secret(original_secret)
    raw_key, prefix, key_hash = generate_api_key()
    token = create_access_token(str(user_id), token_version=17, expires_delta=timedelta(minutes=5))
    claims = await decode_token(token)
    assert claims is not None
    app = FastAPI()
    app.include_router(plugins.router, prefix="/api/v1/plugins")

    async def independent_session():
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = independent_session

    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    async def snapshot():
        async with AsyncSession(engine) as session:
            rows = (await session.execute(select(
                PluginSetting.plugin_id, PluginSetting.organization_id,
                PluginSetting.key, PluginSetting.value,
            ).where(PluginSetting.plugin_id.in_([slug, other_plugin])))).all()
            owned = {key: value for plugin, org, key, value in rows if plugin == slug and org == org_id}
            sdk = PluginSettingsSDK(slug, org_id, session)
            ordinary = await sdk.get("api_token")
            explicit = await sdk.get_secret("api_token")
            other_org = {key: value for plugin, org, key, value in rows if plugin == slug and org == other_org_id}
            other_scope = {key: value for plugin, org, key, value in rows if plugin == other_plugin and org == org_id}
            # Only equality/digest evidence, never raw secret/ciphertext in JUnit.
            return {
                "own_row_digests": {key: digest(value) for key, value in sorted(owned.items())},
                "plaintext_present": "api_token" in owned,
                "plaintext_empty": owned.get("api_token") in (None, ""),
                "ciphertext_present": "api_token:encrypted" in owned,
                "ciphertext_usable": bool(owned.get("api_token:encrypted")),
                "sdk_get_is_original": ordinary == original_secret,
                "sdk_get_is_replacement": ordinary == replacement_secret,
                "sdk_get_empty": ordinary in (None, ""),
                "sdk_secret_is_original": explicit == original_secret,
                "sdk_secret_is_replacement": explicit == replacement_secret,
                "sdk_secret_empty": explicit in (None, ""),
                "other_org_unchanged": other_org == {"api_token": original_secret, "api_token:encrypted": original_ciphertext},
                "other_plugin_unchanged": other_scope == {"api_token": original_secret, "api_token:encrypted": original_ciphertext},
            }

    def response_settings(reply):
        try:
            data = reply.json()
        except ValueError:
            return {}
        if not isinstance(data, dict) or not isinstance(data.get("settings"), dict):
            return {}
        return data["settings"]

    try:
        async with AsyncSession(engine) as seed:
            seed.add_all([
                Organization(id=org_id, name="Owned secret organization", slug=slug + "-org"),
                Organization(id=other_org_id, name="Owned other organization", slug=slug + "-other-org"),
            ])
            await seed.flush()
            seed.add(User(id=user_id, username=slug, email=slug + "@example.com", organization_id=org_id,
                          full_name="Owned secret operator", hashed_password=get_password_hash("Owned secret password"),
                          role="org_admin", is_active=True, is_verified=True, token_version=17))
            await seed.flush()
            seed.add(UserSession(user_id=user_id, access_jti=claims["jti"], created_at=datetime.now(UTC),
                                 expires_at=datetime.fromtimestamp(claims["exp"], UTC)))
            seed.add(APIKey(id=key_id, user_id=user_id, name="Owned secret key", key_prefix=prefix,
                            key_hash=key_hash, scopes=[], is_active=True, expires_at=datetime.fromtimestamp(claims["exp"], UTC)))
            marker = {"secret": True} if declaration == "secret" else {"format": "password"}
            seed.add(InstalledPlugin(plugin_id=slug, name="Owned secret fixture", version="1.0.0",
                                     plugin_dir="/owned-not-executed", is_active=False, status="disabled",
                                     manifest_cache={"settings_schema": {"properties": {
                                         "api_token": {"type": "string", **marker},
                                         "region": {"type": "string"},
                                     }}}))
            values = {"region": "unchanged-region", "api_token": "" if storage == "encrypted" else original_secret}
            if storage != "legacy_only":
                values["api_token:encrypted"] = original_ciphertext
            for key, value in values.items():
                seed.add(PluginSetting(plugin_id=slug, organization_id=org_id, key=key, value=value))
            for plugin, org in ((slug, other_org_id), (other_plugin, org_id)):
                for key, value in {"api_token": original_secret, "api_token:encrypted": original_ciphertext}.items():
                    seed.add(PluginSetting(plugin_id=plugin, organization_id=org, key=key, value=value))
            await seed.commit()
        before = await snapshot()
        headers = {"Authorization": f"Bearer {token}"} if credential == "jwt" else {"X-API-Key": raw_key}
        submitted = {"clear": {"api_token": ""}, "mask": {"api_token": plugins.SECRET_MASK},
                     "omit": {"region": "unchanged-region"}, "replace": {"api_token": replacement_secret}}[action]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://owned.test") as client:
            initial = await client.get(f"/api/v1/plugins/{slug}/settings", headers=headers)
            response = await client.put(f"/api/v1/plugins/{slug}/settings", headers=headers, json={"settings": submitted})
            reread = await client.get(f"/api/v1/plugins/{slug}/settings", headers=headers)
        after = await snapshot()
        observation = {
            "credential": credential, "declaration": declaration, "storage": storage, "action": action,
            "initial_status": initial.status_code, "put_status": response.status_code, "reread_status": reread.status_code,
            "initial_reports_configured": response_settings(initial).get("api_token") == plugins.SECRET_MASK,
            "reread_reports_configured": response_settings(reread).get("api_token") == plugins.SECRET_MASK,
            "reread_reports_empty": response_settings(reread).get("api_token") == "",
            "put_reports_mask": response_settings(response).get("api_token") == plugins.SECRET_MASK,
            "put_reports_empty": response_settings(response).get("api_token") == "",
            "secret_or_ciphertext_in_response": any(value in reply.text for value in
                (original_secret, replacement_secret, original_ciphertext) for reply in (initial, response, reread)),
            "before": before, "after": after, "unchanged": before == after,
            "real_HTTP_authentication_SQL_encryption_SDK": True, "UI_or_vendor_runtime_qualified": False,
        }
        record_property("actual_plugin_secret_roundtrip", json.dumps(observation, sort_keys=True))
        assert observation["initial_status"] == observation["put_status"] == observation["reread_status"] == 200, observation
        assert observation["initial_reports_configured"] and not observation["secret_or_ciphertext_in_response"], observation
        assert before["sdk_get_is_original"] and after["other_org_unchanged"] and after["other_plugin_unchanged"], observation
        assert before["own_row_digests"]["region"] == after["own_row_digests"]["region"], observation
        if action == "clear":
            assert after["sdk_get_empty"] and after["sdk_secret_empty"], observation
            assert after["plaintext_empty"] and not after["ciphertext_usable"], observation
            assert observation["put_reports_empty"] and observation["reread_reports_empty"], observation
        elif action in ("mask", "omit"):
            assert observation["unchanged"] and observation["reread_reports_configured"], observation
            assert after["sdk_get_is_original"] and after["sdk_secret_is_original"] == (storage != "legacy_only"), observation
        else:
            assert after["sdk_get_is_replacement"] and after["sdk_secret_is_replacement"], observation
            assert after["plaintext_empty"] and after["ciphertext_usable"], observation
            assert observation["put_reports_mask"] and observation["reread_reports_configured"], observation
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(PluginSetting).where(PluginSetting.plugin_id.in_([slug, other_plugin]),
                PluginSetting.organization_id.in_([org_id, other_org_id])))
            await cleanup.execute(delete(InstalledPlugin).where(InstalledPlugin.plugin_id == slug))
            await cleanup.execute(delete(APIKey).where(APIKey.user_id == user_id))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.execute(delete(Organization).where(Organization.id.in_([org_id, other_org_id])))
            await cleanup.commit()
        await engine.dispose()
