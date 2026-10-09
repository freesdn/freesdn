# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unrun OIDC callback identity probes with real signatures, DB and issued JWTs.

Only upstream HTTP transport is replaced by owned response documents. Discovery,
JWKS parsing, signature/claim/nonce verification, provisioning and token issuance
use production code. This does not qualify external IdP or TLS/network behavior.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models.core import User
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus, SSOSession
from app.services import sso as sso_module
from app.services.sso import SSOAuthError, SSOCallbackError, SSOService
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


@pytest.fixture(scope="module")
def owned_signing_keys():
    return (rsa.generate_private_key(public_exponent=65537, key_size=2048),
            rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.mark.parametrize("scenario", [
    "id_token_only", "userinfo_matching", "userinfo_unavailable",
    "userinfo_mismatched_subject", "userinfo_missing_subject",
    "id_token_missing_subject", "id_token_empty_subject", "id_token_missing",
    "wrong_signature", "wrong_nonce",
])
async def test_oidc_identity_and_enrichment_remain_bound_to_validated_subject(
    vault_db, tmp_path, monkeypatch, request, owned_signing_keys, scenario,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    identity = uuid4().hex
    email = identity + "@example.com"
    issuer = "https://owned-oidc.example.invalid/" + identity
    provider = SSOProvider(
        id=uuid4(), organization_id=f.org.id, name="Owned OIDC identity probe", slug=identity,
        protocol=SSOProtocol.OIDC, status=SSOProviderStatus.ACTIVE,
        oidc_issuer=issuer, oidc_client_id="owned-client", jit_provisioning=True,
        default_role="viewer", role_mapping={"org_admin": "owned-administrators"},
        attribute_mapping={"email": "email", "username": "preferred_username", "full_name": "name"},
    )
    f.db.add(provider)
    await f.db.flush()
    state, nonce = uuid4().hex, uuid4().hex
    now = datetime.now(UTC)
    flow = SSOSession(
        id=uuid4(), provider_id=provider.id, state=state, nonce=nonce,
        created_at=now, expires_at=now + timedelta(minutes=5), redirect_uri="http://test/auth/sso/callback",
    )
    f.db.add(flow)
    await f.db.commit()
    provider_id, flow_id = provider.id, flow.id
    signing_key, other_key = owned_signing_keys
    claims = {
        "iss": issuer, "sub": "owned-subject", "aud": "owned-client", "iat": now,
        "exp": now + timedelta(minutes=5), "nonce": nonce,
        "email": email, "email_verified": True, "preferred_username": identity,
        "name": "Owned ID token profile",
    }
    if scenario == "id_token_missing_subject":
        claims.pop("sub")
    elif scenario == "id_token_empty_subject":
        claims["sub"] = ""
    elif scenario == "wrong_nonce":
        claims["nonce"] = uuid4().hex
    token_data = {"access_token": "owned-disposable-external-access", "token_type": "Bearer"}
    if scenario != "id_token_missing":
        token_data["id_token"] = jwt.encode(
            claims, other_key if scenario == "wrong_signature" else signing_key,
            algorithm="RS256", headers={"kid": "owned-key"},
        )
    public_jwk = json.loads(RSAAlgorithm.to_jwk(signing_key.public_key()))
    public_jwk.update(kid="owned-key", use="sig", alg="RS256")
    endpoints = {
        "issuer": issuer, "authorization_endpoint": issuer + "/authorize",
        "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
    }
    if scenario != "id_token_only":
        endpoints["userinfo_endpoint"] = issuer + "/userinfo"
    userinfo = {"sub": "owned-subject", "email": email, "groups": ["owned-administrators"],
                "name": "Owned UserInfo profile"}
    if scenario == "userinfo_mismatched_subject":
        userinfo["sub"] = "different-subject"
    elif scenario == "userinfo_missing_subject":
        userinfo.pop("sub")
    observed_calls = []

    async def owned_upstream_transport(method, url, **kwargs):
        observed_calls.append((method, url))
        assert kwargs.get("allow_hosts") == frozenset({"owned-oidc.example.invalid"})
        if url == issuer + "/.well-known/openid-configuration":
            assert method == "GET"
            return httpx.Response(200, json=endpoints)
        if url == issuer + "/token":
            assert method == "POST" and kwargs["data"]["code"] == "owned-authorization-code"
            return httpx.Response(200, json=token_data)
        if url == issuer + "/jwks":
            assert method == "GET"
            return httpx.Response(200, json={"keys": [public_jwk]})
        if url == issuer + "/userinfo":
            assert method == "GET"
            return httpx.Response(503 if scenario == "userinfo_unavailable" else 200, json=userinfo)
        raise AssertionError("Unexpected upstream request in owned OIDC probe")

    monkeypatch.setattr(sso_module, "safe_http_request", owned_upstream_transport)
    result = None
    refused = False
    async with AsyncSession(f.db.bind, expire_on_commit=False) as callback_session:
        try:
            result = await SSOService(callback_session).oidc_callback(state, "owned-authorization-code")
            assert result.user is not None
            f.db.info["owned_user_ids"].append(result.user.id)
            await callback_session.commit()
        except (SSOAuthError, SSOCallbackError):
            refused = True
            await callback_session.rollback()
    async with AsyncSession(f.db.bind) as observer:
        account = (await observer.execute(select(
            User.id, User.role, User.external_id, User.sso_provider_id, User.full_name,
        ).where(User.email == email, User.organization_id == f.org.id))).one_or_none()
        completion = await observer.scalar(select(SSOSession.completed_at).where(SSOSession.id == flow_id))
    # Retain any actual inserted row for precise owned cleanup even if the
    # production response unexpectedly omits it; never erase committed evidence.
    if account is not None and account.id not in f.db.info["owned_user_ids"]:
        f.db.info["owned_user_ids"].append(account.id)
    access_accepted = False
    if result is not None and result.access_token:
        peer = uuid4().int
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                       client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45127))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + result.access_token})
        access_accepted = response.status_code == 200
    request.node.user_properties.extend([
        ("upstream_transport_documents_stubbed", True),
        ("production_signature_claim_nonce_verifiers_unmocked", True),
        ("provision_or_callback_refused", refused),
        ("new_account_committed", account is not None),
        ("actual_account_role", account.role if account is not None else "none"),
        ("actual_subject_matches_ID_token", account is not None and account.external_id == "owned-subject"),
        ("actual_provider_binding_matches", account is not None and account.sso_provider_id == provider_id),
        ("ordinary_access_accepted_by_real_HTTP", access_accepted),
        ("flow_completion_committed", completion is not None),
        ("upstream_calls", len(observed_calls)),
    ])
    if scenario in {"id_token_missing", "id_token_missing_subject", "id_token_empty_subject", "wrong_signature", "wrong_nonce"}:
        assert (refused, account is None, access_accepted) == (True, True, False)
    elif scenario in {"userinfo_mismatched_subject", "userinfo_missing_subject"}:
        # OIDC permits discarding unusable enrichment. Rejecting the callback
        # is also safe; do not demand a blanket refusal of an otherwise valid
        # signed identity when the offending UserInfo is entirely ignored.
        if refused:
            assert account is None and not access_accepted
        else:
            assert account is not None and access_accepted
            assert account.role == "viewer" and account.external_id == "owned-subject"
            assert account.sso_provider_id == provider_id and account.full_name == claims["name"]
    else:
        assert not refused and account is not None and access_accepted
        assert account.role == ("org_admin" if scenario == "userinfo_matching" else "viewer")
        assert account.external_id == "owned-subject" and account.sso_provider_id == provider_id
        assert completion is not None
