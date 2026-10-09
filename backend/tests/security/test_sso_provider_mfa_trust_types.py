# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unrun provider trust probes after the external-verification boundary.

Real management HTTP, committed PostgreSQL, provisioner/issuer, protected HTTP
and local TOTP exchange. No external IdP, TLS, signature or MFA attestation is
simulated as acceptance. Type-refusal is a proposed management contract; only
observed protected access without local MFA establishes a local-gate failure.
"""

import json
from copy import deepcopy
from uuid import uuid4

import httpx
import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import User
from app.models.sso import SSOProvider
from app.services.sso import SSOService
from tests.security.test_sso_existing_account_binding import account_binding
from tests.services.test_backup_vault_security_roundtrip import remember_owned_token, source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db

CASES = {
    "absent": {}, "boolean_false": {"trust_idp_mfa": False},
    "boolean_true": {"trust_idp_mfa": True},
    "string_false": {"trust_idp_mfa": "false"},
    "string_true": {"trust_idp_mfa": "true"},
    "integer_zero": {"trust_idp_mfa": 0},
    "integer_one": {"trust_idp_mfa": 1},
    "null": {"trust_idp_mfa": None},
    "empty_list": {"trust_idp_mfa": []},
    "nonempty_list": {"trust_idp_mfa": [False]},
    "object": {"trust_idp_mfa": {"enabled": False}},
}
VALID = {"absent", "boolean_false", "boolean_true"}


def same_settings(left, right):
    # Python treats True == 1; preserve JSON types in durable-state evidence.
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def transport():
    peer = uuid4().int
    return httpx.ASGITransport(app=app, raise_app_exceptions=False,
                              client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45220))


async def actor_headers(f, credential):
    f.user.role = "org_admin"
    if credential == "jwt":
        headers = {"Authorization": "Bearer " + create_access_token(
            subject=str(f.user.id), token_version=f.user.token_version,
        )}
    else:
        raw, prefix, digest = generate_api_key()
        f.db.add(APIKey(id=uuid4(), user_id=f.user.id, name="Owned trust-setting key",
                        key_prefix=prefix, key_hash=digest, scopes=[], is_active=True))
        headers = {"X-API-Key": raw}
    await f.db.commit()
    return headers


def provider_body(f, slug, extra):
    return {
        "name": "Owned typed trust provider", "slug": slug,
        "organization_id": str(f.org.id), "protocol": "oidc", "status": "active",
        "oidc_issuer": "https://owned-trust.example.invalid", "oidc_client_id": "owned-client",
        "jit_provisioning": True, "default_role": "viewer", "extra_settings": deepcopy(extra),
    }


async def add_bound_mfa_user(f, provider_id):
    identity = uuid4().hex
    user = User(id=uuid4(), organization_id=f.org.id, username=identity,
                email=identity + "@example.com", role="viewer", hashed_password="!SSO_MANAGED",
                auth_provider="oidc", external_id="owned-trust-subject", sso_provider_id=provider_id,
                token_version=17, is_active=True, is_verified=True,
                mfa_enabled=True, mfa_secret=f.user.mfa_secret,
                mfa_backup_codes=f.user.mfa_backup_codes, mfa_last_totp_step=123456)
    f.db.add(user)
    f.db.info["owned_user_ids"].append(user.id)
    await f.db.commit()
    return user.id


async def observe_sign_in(f, client, provider_id, target_id):
    async with AsyncSession(f.db.bind, expire_on_commit=False) as session:
        provider = await session.get(SSOProvider, provider_id)
        target = await session.get(User, target_id)
        svc = SSOService(session)
        user = await svc._provision_or_update_user(
            provider, {"email": target.email}, {"sub": "owned-trust-subject"},
        )
        result = await svc._issue_tokens(user, provider)
        await session.commit()
    accepted = False
    accepted_id = None
    challenge_accepted = False
    completed = False
    if result.access_token:
        me = await client.get("/api/v1/auth/me", headers={
            "Authorization": "Bearer " + result.access_token,
        })
        accepted = me.status_code == 200
        accepted_id = me.json().get("id") if accepted else None
    if result.mfa_token:
        remember_owned_token(f.db, result.mfa_token, audience="freesdn-mfa")
        probe = await client.get("/api/v1/auth/me", headers={
            "Authorization": "Bearer " + result.mfa_token,
        })
        challenge_accepted = probe.status_code == 200
        response = await client.post("/api/v1/auth/login/mfa", json={
            "mfa_token": result.mfa_token, "code": pyotp.TOTP(f.seed).now(),
        })
        me = await client.get("/api/v1/auth/me")
        completed = response.status_code == 200 and me.status_code == 200 and me.json().get("id") == str(target_id)
        client.cookies.clear()
    return {
        "ordinary_access_accepted": accepted, "accepted_id": accepted_id,
        "mfa_challenge": bool(result.require_mfa),
        "challenge_accepted_as_ordinary_bearer": challenge_accepted,
        "local_TOTP_exchange_and_protected_HTTP_succeeded": completed,
    }


def assert_sign_in(observed, target_id, *, trusted):
    assert observed["challenge_accepted_as_ordinary_bearer"] is False
    if trusted:
        assert observed["ordinary_access_accepted"] is True
        assert observed["accepted_id"] == str(target_id)
        assert observed["mfa_challenge"] is False
    else:
        assert observed["ordinary_access_accepted"] is False
        assert observed["mfa_challenge"] is True
        assert observed["local_TOTP_exchange_and_protected_HTTP_succeeded"] is True


@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("operation", ["create", "patch"])
@pytest.mark.parametrize("case", list(CASES))
async def test_provider_management_requires_explicit_boolean_MFA_trust(
    vault_db, tmp_path, monkeypatch, request, credential, operation, case,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    headers = await actor_headers(f, credential)
    slug = uuid4().hex
    target_id = None
    before = None
    async with httpx.AsyncClient(transport=transport(), base_url="http://test") as client:
        if operation == "patch":
            setup = await client.post("/api/v1/auth/sso/providers", headers=headers,
                                      json=provider_body(f, slug, CASES["boolean_false"]))
            assert setup.status_code == 201, setup.text
            async with AsyncSession(f.db.bind) as observer:
                provider_id = await observer.scalar(select(SSOProvider.id).where(SSOProvider.slug == slug))
            target_id = await add_bound_mfa_user(f, provider_id)
            before = await account_binding(f.db, target_id)
            await f.db.rollback()
            response = await client.patch(f"/api/v1/auth/sso/providers/{provider_id}", headers=headers,
                                          json={"extra_settings": deepcopy(CASES[case])})
        else:
            response = await client.post("/api/v1/auth/sso/providers", headers=headers,
                                         json=provider_body(f, slug, CASES[case]))
        async with AsyncSession(f.db.bind) as observer:
            stored = (await observer.execute(select(SSOProvider.id, SSOProvider.extra_settings).where(
                SSOProvider.slug == slug,
            ))).one_or_none()
        observed = None
        after = None
        if stored is not None:
            if target_id is None:
                target_id = await add_bound_mfa_user(f, stored.id)
                before = await account_binding(f.db, target_id)
                await f.db.rollback()
            # Observe account security BEFORE the optional TOTP completion,
            # which legitimately advances mfa_last_totp_step.
            async with AsyncSession(f.db.bind) as observer:
                after = await account_binding(observer, target_id)
            observed = await observe_sign_in(f, client, stored.id, target_id)
        request.node.user_properties.extend([
            ("management_HTTP_status", response.status_code),
            ("provider_row_exists", stored is not None),
            ("provider_settings_equal_requested", stored is not None and same_settings(stored.extra_settings, CASES[case])),
            ("target_security_unchanged_before_TOTP", before == after),
            ("post_verification_sign_in_observed", observed is not None),
            *[(key, value) for key, value in (observed or {}).items() if key != "accepted_id"],
        ])
        # Record all durable state and sign-in observations before asserting
        # the proposed management contract; failed status != proven MFA bypass.
        if case in VALID:
            assert response.status_code == (201 if operation == "create" else 200)
            assert stored is not None and same_settings(stored.extra_settings, CASES[case])
            assert before == after
            assert_sign_in(observed, target_id, trusted=case == "boolean_true")
        else:
            assert response.status_code in {400, 422}
            if operation == "create":
                assert stored is None
            else:
                assert same_settings(stored.extra_settings, CASES["boolean_false"])
                assert before == after
                assert_sign_in(observed, target_id, trusted=False)


@pytest.mark.parametrize("case", list(CASES))
async def test_stored_legacy_nonboolean_trust_never_skips_local_MFA(
    vault_db, tmp_path, monkeypatch, request, case,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    headers = await actor_headers(f, "jwt")
    slug = uuid4().hex
    async with httpx.AsyncClient(transport=transport(), base_url="http://test") as client:
        setup = await client.post("/api/v1/auth/sso/providers", headers=headers,
                                  json=provider_body(f, slug, CASES["boolean_false"]))
        assert setup.status_code == 201, setup.text
        provider = await f.db.scalar(select(SSOProvider).where(SSOProvider.slug == slug))
        provider_id = provider.id
        # An owned database fixture models old stored JSON; this is not an
        # unauthenticated route or a claim that a DB writer lacks authority.
        provider.extra_settings = deepcopy(CASES[case])
        await f.db.commit()
        target_id = await add_bound_mfa_user(f, provider_id)
        observed = await observe_sign_in(f, client, provider_id, target_id)
        request.node.user_properties.extend([
            ("stored_legacy_JSON_fixture_not_HTTP_exploit", True),
            *[(key, value) for key, value in observed.items() if key != "accepted_id"],
        ])
        assert_sign_in(observed, target_id, trusted=case == "boolean_true")
