# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unrun existing-account SSO binding probes, separate from provider wait cases.

The real administrator HTTP route creates the provider. The real provisioner
is then entered after the identity-provider verification boundary, followed by
real token issuance and HTTP /auth/me validation. This does not test an external
IdP exchange, discovery, network transport or signature verification.
"""

from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import User
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus
from app.services.sso import SSOAuthError, SSOService
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db

PROFILES = [
    "local_super_admin", "local_org_admin", "local_viewer",
    "other_provider", "other_subject", "matching_binding", "new_jit",
    "local_super_admin_mfa_trusted_idp",
]


async def account_binding(session, user_id):
    if user_id is None:
        return None
    row = (await session.execute(select(
        User.role, User.organization_id, User.auth_provider, User.external_id,
        User.sso_provider_id, User.hashed_password, User.mfa_enabled, User.mfa_secret,
        User.mfa_backup_codes, User.token_version, User.is_active, User.is_verified,
    ).where(User.id == user_id))).one_or_none()
    return tuple(row) if row is not None else None


@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("profile", PROFILES)
async def test_sso_does_not_silently_rebind_existing_account(
    vault_db, tmp_path, monkeypatch, request, credential, profile,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    f.user.role = "org_admin"
    if credential == "jwt":
        headers = {"Authorization": "Bearer " + create_access_token(
            subject=str(f.user.id), token_version=f.user.token_version,
        )}
    else:
        raw, prefix, key_hash = generate_api_key()
        f.db.add(APIKey(
            id=uuid4(), user_id=f.user.id, name="Owned provider-creation key",
            key_prefix=prefix, key_hash=key_hash, scopes=[], is_active=True,
        ))
        headers = {"X-API-Key": raw}
    await f.db.commit()
    peer = uuid4().int
    transport = httpx.ASGITransport(
        app=app, raise_app_exceptions=False,
        client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45125),
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        creation = await client.post("/api/v1/auth/sso/providers", headers=headers, json={
            "name": "Owned account-binding provider", "slug": uuid4().hex,
            "organization_id": str(f.org.id), "protocol": "oidc", "status": "active",
            "oidc_issuer": "https://owned-binding.example.invalid", "oidc_client_id": "owned-client",
            "jit_provisioning": True, "default_role": "viewer",
            "extra_settings": {"trust_idp_mfa": profile == "local_super_admin_mfa_trusted_idp"},
        })
        assert creation.status_code == 201, creation.text
        provider_id = UUID(creation.json()["id"])
        provider = await f.db.get(SSOProvider, provider_id)
        assert provider is not None and provider.created_by == f.user.id
        identity = uuid4().hex
        email = identity + "@example.com"
        user_id = None
        if profile != "new_jit":
            user_id = uuid4()
            bound = profile in {"other_provider", "other_subject", "matching_binding"}
            target_provider_id = provider_id if bound else None
            if profile == "other_provider":
                previous_provider = SSOProvider(
                    id=uuid4(), organization_id=f.org.id, name="Owned previous binding",
                    slug=uuid4().hex, protocol=SSOProtocol.OIDC, status=SSOProviderStatus.ACTIVE,
                    oidc_issuer="https://previous-binding.example.invalid",
                    oidc_client_id="owned-previous-client", default_role="viewer",
                )
                f.db.add(previous_provider)
                await f.db.flush()
                target_provider_id = previous_provider.id
            role = "viewer" if profile == "local_viewer" else (
                "org_admin" if profile == "local_org_admin" else "super_admin"
            )
            mfa = profile == "local_super_admin_mfa_trusted_idp"
            f.db.add(User(
                id=user_id, organization_id=f.org.id, username=identity, email=email,
                role=role, hashed_password="!SSO_MANAGED" if bound else f.user.hashed_password,
                auth_provider="oidc" if bound else None,
                external_id=("different-subject" if profile == "other_subject" else "asserted-subject")
                if bound else None,
                sso_provider_id=target_provider_id, token_version=17, is_active=True, is_verified=True,
                mfa_enabled=mfa, mfa_secret=f.user.mfa_secret if mfa else None,
                mfa_backup_codes=f.user.mfa_backup_codes if mfa else None,
                mfa_last_totp_step=f.user.mfa_last_totp_step if mfa else None,
            ))
            f.db.info["owned_user_ids"].append(user_id)
        await f.db.commit()
        before = await account_binding(f.db, user_id)
        await f.db.rollback()
        refused = False
        result = None
        returned_id = None
        async with AsyncSession(f.db.bind, expire_on_commit=False) as service_session:
            live_provider = await service_session.get(SSOProvider, provider_id)
            svc = SSOService(service_session)
            try:
                user = await svc._provision_or_update_user(
                    live_provider, {"email": email, "username": identity},
                    {"sub": "asserted-subject", "email": email, "email_verified": True},
                )
                returned_id = user.id
                if user.id not in f.db.info["owned_user_ids"]:
                    f.db.info["owned_user_ids"].append(user.id)
                result = await svc._issue_tokens(user, live_provider)
                await service_session.commit()
            except SSOAuthError:
                refused = True
                await service_session.rollback()
        async with AsyncSession(f.db.bind) as observer:
            after = await account_binding(observer, user_id or returned_id)
        accepted_identity = None
        accepted_role = None
        access_accepted = False
        if result is not None and result.access_token:
            me = await client.get("/api/v1/auth/me", headers={
                "Authorization": "Bearer " + result.access_token,
            })
            access_accepted = me.status_code == 200
            if access_accepted:
                accepted_identity = me.json()["id"]
                accepted_role = me.json()["role"]
        request.node.user_properties.extend([
            ("provider_created_by_org_admin_through_HTTP", True),
            ("provision_or_issue_refused", refused),
            ("existing_account_security_unchanged", before == after),
            ("ordinary_access_accepted_by_real_HTTP", access_accepted),
            ("accepted_role", accepted_role or "none"),
            ("MFA_challenge_returned", bool(result is not None and result.require_mfa)),
        ])
        if profile in {"matching_binding", "new_jit"}:
            assert not refused and access_accepted
            assert accepted_identity == str(user_id or returned_id)
            assert accepted_role == ("super_admin" if profile == "matching_binding" else "viewer")
            if profile == "matching_binding":
                assert before == after
        else:
            # Observe real issuance, HTTP acceptance and committed security
            # fields before asserting refusal. No external-IdP claim follows.
            assert (refused, before == after, access_accepted) == (True, True, False)
