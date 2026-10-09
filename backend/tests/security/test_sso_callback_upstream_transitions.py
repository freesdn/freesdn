# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Actual callback revalidation across owned upstream transport suspension.

Only transport documents are replaced. Signature, nonce, persistence, issuance
and protected HTTP authentication remain real. This is not external IdP proof.
"""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import jwt
import pytest
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models.core import User
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus, SSOSession
from app.services import sso as sso_module
from app.services.sso import SSOAuthError, SSOCallbackError, SSOService
from tests.security.test_sso_oidc_identity_validation import (
    owned_signing_keys as owned_signing_keys,
)
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


@pytest.mark.parametrize("transition", [
    "unchanged", "presentation", "provider_disabled", "client_changed",
    "trust_changed", "role_mapping_changed", "provider_soft_deleted", "callback_expired",
])
async def test_callback_retains_verified_provider_and_expiry_across_upstream_wait(
    vault_db, tmp_path, monkeypatch, request, owned_signing_keys, transition,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    identity = uuid4().hex
    issuer = "https://transition.example.invalid/" + identity
    email = identity + "@example.com"
    provider = SSOProvider(
        id=uuid4(), organization_id=f.org.id, name="Owned suspended callback",
        slug=identity, protocol=SSOProtocol.OIDC, status=SSOProviderStatus.ACTIVE,
        oidc_issuer=issuer, oidc_client_id="owned-client", jit_provisioning=True,
        default_role="viewer", role_mapping={}, extra_settings={},
        attribute_mapping={"email": "email", "username": "preferred_username", "full_name": "name"},
    )
    f.db.add(provider)
    await f.db.flush()
    now = datetime.now(UTC)
    expires = now + (timedelta(seconds=5) if transition == "callback_expired" else timedelta(minutes=5))
    state, nonce = uuid4().hex, uuid4().hex
    flow = SSOSession(
        id=uuid4(), provider_id=provider.id, state=state, nonce=nonce, created_at=now,
        expires_at=expires, redirect_uri="http://test/auth/sso/callback",
    )
    f.db.add(flow)
    await f.db.commit()
    provider_id, flow_id = provider.id, flow.id
    signing_key, _ = owned_signing_keys
    claims = {
        "iss": issuer, "sub": "owned-suspended-subject", "aud": "owned-client", "iat": now,
        "exp": now + timedelta(minutes=5), "nonce": nonce, "email": email,
        "email_verified": True, "preferred_username": identity, "name": "Owned profile",
    }
    encoded = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "owned-key"})
    jwk = json.loads(RSAAlgorithm.to_jwk(signing_key.public_key()))
    jwk.update(kid="owned-key", use="sig", alg="RS256")
    entered, released = asyncio.Event(), asyncio.Event()
    observed = {"transport_calls": [], "mutation_committed": False}

    async def owned_transport(method, url, **kwargs):
        observed["transport_calls"].append((method, url))
        assert kwargs.get("allow_hosts") == frozenset({"transition.example.invalid"})
        if url == issuer + "/.well-known/openid-configuration":
            assert method == "GET"
            return httpx.Response(200, json={
                "issuer": issuer, "authorization_endpoint": issuer + "/authorize",
                "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
            })
        if url == issuer + "/token":
            assert method == "POST" and kwargs["data"]["client_id"] == "owned-client"
            observed["flow_current_when_token_exchange_started"] = datetime.now(UTC) < expires
            entered.set()
            await asyncio.wait_for(released.wait(), timeout=10)
            return httpx.Response(200, json={"id_token": encoded, "token_type": "Bearer"})
        if url == issuer + "/jwks":
            assert method == "GET"
            return httpx.Response(200, json={"keys": [jwk]})
        raise AssertionError("Unexpected request in owned transport")

    async def transition_during_exchange():
        await asyncio.wait_for(entered.wait(), timeout=5)
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False) as writer:
                observed["writer_pid"] = await writer.scalar(text("select pg_backend_pid()"))
                values = {
                    "presentation": {"name": "Renamed during exchange"},
                    "provider_disabled": {"status": SSOProviderStatus.INACTIVE},
                    "client_changed": {"oidc_client_id": "different-client"},
                    "trust_changed": {"extra_settings": {"trust_idp_mfa": True}},
                    "role_mapping_changed": {"default_role": "org_admin"},
                    "provider_soft_deleted": {"deleted_at": datetime.now(UTC)},
                }.get(transition)
                if values is not None:
                    await writer.execute(update(SSOProvider).where(SSOProvider.id == provider_id).values(**values))
                await writer.commit()
                observed["mutation_committed"] = values is not None
        if transition == "callback_expired":
            await asyncio.sleep(max(0, (expires - datetime.now(UTC)).total_seconds()) + 0.02)
        observed["expired_before_transport_return"] = datetime.now(UTC) >= expires
        released.set()

    monkeypatch.setattr(sso_module, "safe_http_request", owned_transport)
    writer_task = asyncio.create_task(transition_during_exchange())
    refused, result = False, None
    try:
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False) as callback:
                observed["callback_pid"] = await callback.scalar(text("select pg_backend_pid()"))
                try:
                    result = await SSOService(callback).oidc_callback(state, "owned-authorization-code")
                    assert result.user is not None
                    f.db.info["owned_user_ids"].append(result.user.id)
                    await callback.commit()
                except (SSOAuthError, SSOCallbackError):
                    refused = True
                    await callback.rollback()
        await writer_task
    finally:
        released.set()
        if not writer_task.done():
            writer_task.cancel()
        await asyncio.gather(writer_task, return_exceptions=True)
    async with AsyncSession(f.db.bind) as observer:
        account = (await observer.execute(select(User.id, User.role).where(User.email == email))).one_or_none()
        completion = await observer.scalar(select(SSOSession.completed_at).where(SSOSession.id == flow_id))
        current_provider = await observer.get(SSOProvider, provider_id)
        assert current_provider is not None
        current_name = current_provider.name
    if account is not None and account.id not in f.db.info["owned_user_ids"]:
        f.db.info["owned_user_ids"].append(account.id)
    accepted = False
    if result is not None and result.access_token:
        peer = uuid4().int
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                       client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45131))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + result.access_token})
        accepted = response.status_code == 200
    request.node.user_properties.extend([
        ("real_verifiers_unmocked_transport_documents_stubbed", True),
        ("actual_upstream_transport_suspension", entered.is_set() and released.is_set()),
        ("distinct_callback_and_committed_writer_connections", observed["writer_pid"] != observed["callback_pid"]),
        ("flow_current_when_token_exchange_started", observed["flow_current_when_token_exchange_started"]),
        ("provider_mutation_committed", observed["mutation_committed"]),
        ("flow_expired_before_transport_return", observed["expired_before_transport_return"]),
        ("refused", refused), ("account_committed", account is not None),
        ("account_role", account.role if account else "none"),
        ("protected_access_accepted", accepted), ("flow_completion_committed", completion is not None),
        ("presentation_change_retained", current_name == "Renamed during exchange"),
    ])
    assert observed["flow_current_when_token_exchange_started"]
    assert observed["writer_pid"] != observed["callback_pid"]
    if transition in {"unchanged", "presentation"}:
        assert not refused and account is not None and accepted and completion is not None
        assert account.role == "viewer"
        if transition == "presentation":
            assert current_name == "Renamed during exchange"
    else:
        assert refused and account is None and not accepted and completion is None
        if transition == "callback_expired":
            assert observed["expired_before_transport_return"]
        else:
            assert observed["mutation_committed"]
