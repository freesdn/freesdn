# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private, unrun provisioner-boundary probes; no external IdP acceptance.

Exercise stable binding and malformed identity handling with real PostgreSQL,
the real issuer and protected HTTP. SAML cases start after verification and do
not enable or qualify the deliberately unsupported external SAML callback.
"""

from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import create_test_engine
from app.main import app
from app.models.core import User
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus
from app.services.sso import SSOAuthError, SSOService
from tests.security.test_sso_existing_account_binding import account_binding
from tests.services.sso_legacy_fixture import legacy_vault_database
from tests.services.test_backup_vault_security_roundtrip import owned_vault_database, source_fixture


@pytest_asyncio.fixture
async def vault_db(monkeypatch, profile, request):
    # Ambiguity remains a supported refusal case on already-deployed schemas.
    # Restore the frozen old dump and run actual migrations only through 021;
    # never drop the new index from a current database to force the test through.
    if profile != "duplicate_binding":
        async with owned_vault_database(monkeypatch, create_test_engine()) as db:
            yield db
        return
    async with legacy_vault_database(monkeypatch, request) as db:
        yield db


@pytest.mark.parametrize("protocol", ["oidc", "saml", "ldap"])
@pytest.mark.parametrize("profile", [
    "changed_email", "missing_email", "email_collision", "disabled",
    "duplicate_binding", "missing_subject", "empty_subject", "wrong_protocol_key",
])
async def test_existing_external_subject_controls_account_selection(
    vault_db, tmp_path, monkeypatch, request, protocol, profile,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    provider = SSOProvider(
        id=uuid4(), organization_id=f.org.id, name="Owned subject invariant provider",
        slug=uuid4().hex, protocol=SSOProtocol(protocol), status=SSOProviderStatus.ACTIVE,
        jit_provisioning=True, default_role="viewer", extra_settings={},
    )
    f.db.add(provider)
    await f.db.flush()
    target_id, other_id = uuid4(), uuid4()
    target_name, other_name = uuid4().hex, uuid4().hex
    target_email, other_email = target_name + "@example.com", other_name + "@example.com"
    subject = "owned-external-subject"
    f.db.add(User(
        id=target_id, organization_id=f.org.id, username=target_name, email=target_email,
        role="viewer", hashed_password="!SSO_MANAGED", auth_provider=protocol,
        external_id=subject, sso_provider_id=provider.id, token_version=17,
        is_active=profile != "disabled", is_verified=True, mfa_enabled=False,
    ))
    f.db.info["owned_user_ids"].append(target_id)
    if profile in {"email_collision", "duplicate_binding"}:
        duplicate = profile == "duplicate_binding"
        f.db.add(User(
            id=other_id, organization_id=f.org.id, username=other_name, email=other_email,
            role="org_admin", hashed_password="!SSO_MANAGED" if duplicate else f.user.hashed_password,
            auth_provider=protocol if duplicate else None,
            external_id=subject if duplicate else None,
            sso_provider_id=provider.id if duplicate else None,
            token_version=29, is_active=True, is_verified=True, mfa_enabled=False,
        ))
        f.db.info["owned_user_ids"].append(other_id)
    await f.db.commit()
    provider_id = provider.id
    before = await account_binding(f.db, target_id)
    other_before = await account_binding(f.db, other_id)
    before_ids = set((await f.db.scalars(select(User.id).where(
        User.organization_id == f.org.id,
    ))).all())
    await f.db.rollback()

    key = {"oidc": "sub", "saml": "NameID", "ldap": "dn"}[protocol]
    claims = {key: subject}
    attrs = {"email": target_email, "username": target_name}
    if profile == "changed_email":
        attrs = {"email": uuid4().hex + "@example.com", "username": uuid4().hex}
    elif profile == "missing_email":
        attrs = {"username": target_name}
    elif profile == "email_collision":
        attrs = {"email": other_email, "username": other_name}
    elif profile == "missing_subject":
        claims = {}
    elif profile == "empty_subject":
        claims = {key: ""}
    elif profile == "wrong_protocol_key":
        claims = {"dn" if protocol == "oidc" else "sub": subject}

    refused, result, returned_id = False, None, None
    async with AsyncSession(f.db.bind, expire_on_commit=False) as session:
        live = await session.get(SSOProvider, provider_id)
        svc = SSOService(session)
        try:
            user = await svc._provision_or_update_user(live, attrs, claims)
            returned_id = user.id
            if returned_id not in f.db.info["owned_user_ids"]:
                f.db.info["owned_user_ids"].append(returned_id)
            result = await svc._issue_tokens(user, live)
            await session.commit()
        except SSOAuthError:
            refused = True
            await session.rollback()
    async with AsyncSession(f.db.bind) as observer:
        after = await account_binding(observer, target_id)
        other_after = await account_binding(observer, other_id)
        after_ids = set((await observer.scalars(select(User.id).where(
            User.organization_id == before[1],
        ))).all())

    accepted_id = None
    if result is not None and result.access_token:
        peer = uuid4().int
        transport = httpx.ASGITransport(
            app=app, raise_app_exceptions=False,
            client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45127),
        )
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/auth/me", headers={
                "Authorization": "Bearer " + result.access_token,
            })
        if response.status_code == 200:
            accepted_id = response.json()["id"]
    request.node.user_properties.extend([
        ("entered_after_external_verification_boundary", True),
        ("refused_by_real_provisioner", refused),
        ("protected_HTTP_accepted_original_identity", accepted_id == str(target_id)),
        ("target_security_unchanged", before == after),
        ("other_account_security_unchanged", other_before == other_after),
        ("organization_account_IDs_unchanged", before_ids == after_ids),
    ])
    if profile in {"changed_email", "missing_email", "email_collision"}:
        assert not refused and accepted_id == str(target_id)
        assert returned_id == target_id
    else:
        assert refused and accepted_id is None and returned_id is None
    assert before == after and other_before == other_after
    assert before_ids == after_ids
