# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unrun policy probes: provider deletion must preserve live security references.

These are separate from the original forty frozen-later wait probes. They use
real HTTP administration and the account-security collector, not an IdP login.
The proposed conflict refusal still needs baseline and product-policy review.
"""

from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import User
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus
from app.services.backup_contributors.account_security import (
    AccountSecurityFormatError,
    collect_snapshot,
)
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


async def provider_and_account_state(session, provider_id, user_id):
    provider = (await session.execute(select(
        SSOProvider.organization_id, SSOProvider.protocol, SSOProvider.deleted_at,
    ).where(SSOProvider.id == provider_id))).one_or_none()
    account = None
    if user_id is not None:
        account = (await session.execute(select(
            User.organization_id, User.auth_provider, User.sso_provider_id,
            User.is_active, User.deleted_at,
        ).where(User.id == user_id))).one_or_none()
    return (tuple(provider) if provider is not None else None,
            tuple(account) if account is not None else None)


@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("profile", ["active", "disabled", "deleted", "unbound"])
async def test_provider_delete_keeps_remaining_accounts_collectable(
    vault_db, tmp_path, monkeypatch, request, credential, profile,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    f.user.role = "org_admin"
    provider = SSOProvider(
        id=uuid4(), organization_id=f.org.id, name="Owned provider reference probe",
        slug=uuid4().hex, protocol=SSOProtocol.OIDC, status=SSOProviderStatus.ACTIVE,
        oidc_issuer="https://owned-provider.example.invalid", oidc_client_id="owned-client",
        jit_provisioning=False, default_role="viewer",
    )
    f.db.add(provider)
    await f.db.flush()
    user_id = None
    if profile != "unbound":
        user_id = uuid4()
        name = uuid4().hex
        f.db.add(User(
            id=user_id, organization_id=f.org.id, username=name, email=name + "@example.invalid",
            role="viewer", hashed_password="!SSO_MANAGED", auth_provider="oidc",
            external_id="owned-subject-" + name, sso_provider_id=provider.id,
            is_active=profile != "disabled", is_verified=True,
            deleted_at=datetime.now(UTC) if profile == "deleted" else None,
        ))
        f.db.info["owned_user_ids"].append(user_id)
    if credential == "jwt":
        headers = {"Authorization": "Bearer " + create_access_token(
            subject=str(f.user.id), token_version=f.user.token_version,
        )}
    else:
        raw, prefix, key_hash = generate_api_key()
        f.db.add(APIKey(
            id=uuid4(), user_id=f.user.id, name="Owned provider reference key",
            key_prefix=prefix, key_hash=key_hash, scopes=[], is_active=True,
        ))
        headers = {"X-API-Key": raw}
    await f.db.commit()
    org_id, provider_id = f.org.id, provider.id
    async with AsyncSession(f.db.bind) as observer:
        before = await provider_and_account_state(observer, provider_id, user_id)
        before_snapshot = await collect_snapshot(observer, org_id)
    assert any(row["id"] == str(provider_id) for row in before_snapshot["sso_providers"])
    assert (any(row["id"] == str(user_id) for row in before_snapshot["users"])) == (
        profile in {"active", "disabled"}
    )
    peer = uuid4().int
    transport = httpx.ASGITransport(
        app=app, raise_app_exceptions=False,
        client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45124),
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers=headers) as client:
        response = await client.delete(f"/api/v1/auth/sso/providers/{provider_id}")
    async with AsyncSession(f.db.bind) as observer:
        after = await provider_and_account_state(observer, provider_id, user_id)
        try:
            await collect_snapshot(observer, org_id)
        except AccountSecurityFormatError:
            collectable_after = False
        else:
            collectable_after = True
    request.node.user_properties.extend([
        ("provider_delete_response_status", response.status_code),
        ("bound_account_state_unchanged", after[1] == before[1]),
        ("provider_state_unchanged", after[0] == before[0]),
        ("valid_security_snapshot_before", True),
        ("valid_security_snapshot_after", collectable_after),
    ])
    # Record durable state and actual collector outcome before any response
    # assertion. Never turn unexpected fixture exceptions into product results.
    assert after[1] == before[1]
    if profile in {"active", "disabled"}:
        assert (response.status_code, after[0] == before[0], collectable_after) == (409, True, True)
    else:
        assert response.status_code == 204, response.text
        assert after[0] is not None and after[0][2] is not None
        assert collectable_after
