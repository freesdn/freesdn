"""Real current-auth/SQL/factor probes for the private external-confirmation flow.

Owned harness endpoints are not public backup routes. LDAP uses actual loopback
TLS/messages with explicit test admission; OIDC uses the earlier owned signed
HTTP transport. No factor/current-authority/claim verifier is replaced.
"""

import asyncio
import hashlib
import hmac
import json
import secrets
import time
from datetime import UTC, datetime

import anyio
import jwt
import pyotp
import pytest
import pytest_asyncio
from fastapi import Depends, HTTPException, Request
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.core.security_utils import encrypt_field
from app.core.vault_export_proof import bind_export_value
from app.core.vault_identity_proof import InvalidIdentityConfirmation
from app.core.vault_ldap_reauthentication import LDAPConfirmationError
from app.core.vault_oidc_reauthentication import OIDCConfirmationError
from app.models.api_keys import APIKey
from app.models.core import TokenRevocation, User, UserSession
from app.models.sso import SSOProtocol, SSOProvider, SSOSession
from app.services.vault_export_authority import VaultExportAuthority
from app.services.vault_export_factors import (
    complete_external_factors,
    complete_oidc_identity,
    confirm_ldap_identity,
)
from tests.security.test_vault_export_authority import credentials, mutate, real_wait, state
from tests.security.test_vault_export_authority import owned_export as owned_export
from tests.security.test_vault_export_ldap_protocol import certificates as certificates
from tests.security.test_vault_export_ldap_protocol import owned as owned
from tests.security.test_vault_export_oidc_authority import oidc_export as oidc_export
from tests.security.test_vault_export_oidc_authority import (
    owned_oidc_signing_key as owned_oidc_signing_key,
)
from tests.security.test_vault_export_oidc_authority import start as start_oidc


def add_factor_route(f):
    app = f.client._transport.app

    @app.post("/owned/factors/complete")
    async def complete(request: Request, user: CurrentUser = Depends(get_current_user)):
        authority = await VaultExportAuthority.capture(
            request, user, action="create", secret_key=f.secret
        )
        body = await request.json()
        try:
            result = await complete_external_factors(
                authority,
                request_binding=f.operation,
                identity_token=body["identity_token"],
                code=body.get("code"),
            )
        except InvalidIdentityConfirmation:
            raise HTTPException(401, "Fresh identity confirmation refused") from None
        return {
            "actor": str(result.authority.actor_id),
            "authenticated_at": result.authenticated_at,
            "expires_at": result.expires_at,
        }


def remember_identity(f, authority, token):
    key = hmac.digest(authority.secret_key, b"FreeSDN/vault-identity/v1", "sha256")
    claims = jwt.decode(
        token,
        key,
        algorithms=["HS256"],
        issuer="freesdn",
        audience="freesdn-vault-identity-confirmation",
    )
    f.identity_key = key
    f.identity_claims = claims
    f.identity_hash = hashlib.sha256(claims["jti"].encode()).hexdigest()
    f.token_hashes.add(f.identity_hash)


@pytest.fixture
def ldap_protocol():
    return "ldaps"


@pytest_asyncio.fixture
async def ldap_factors(owned_export, owned, ldap_protocol):
    f, peer = owned_export, owned
    f.peer = peer
    f.operation = bind_export_value(
        {"owned": secrets.token_hex(16)}, key=f.secret, domain="request"
    )
    await mutate(
        f,
        {
            "auth_provider": "ldap",
            "sso_provider_id": f.provider,
            "external_id": "cn=existing,dc=example,dc=invalid",
            "hashed_password": "!SSO_MANAGED",
        },
    )
    async with peer.server(ldap_protocol) as prototype:
        async with AsyncSession(f.engine) as db:
            await db.execute(
                update(SSOProvider)
                .where(SSOProvider.id == f.provider)
                .values(
                    protocol=SSOProtocol.LDAP,
                    ldap_url=prototype.binding.url,
                    ldap_use_tls=True,
                    ldap_tls_ca_cert=prototype.binding.ca_pem,
                    ldap_base_dn="dc=example,dc=invalid",
                )
            )
            await db.commit()
        app = f.client._transport.app

        @app.post("/owned/ldap/identity")
        async def identity(request: Request, user: CurrentUser = Depends(get_current_user)):
            authority = await VaultExportAuthority.capture(
                request, user, action="create", secret_key=f.secret
            )
            body = await request.json()
            try:
                token = await confirm_ldap_identity(
                    authority, request_binding=f.operation, password=body["password"]
                )
            except (LDAPConfirmationError, InvalidIdentityConfirmation):
                raise HTTPException(401, "Fresh identity confirmation refused") from None
            remember_identity(f, authority, token)
            return {"identity_token": token}

        add_factor_route(f)
        yield f


@pytest_asyncio.fixture
async def oidc_factors(oidc_export):
    f = oidc_export
    app = f.client._transport.app

    @app.post("/owned/oidc/identity")
    async def identity(request: Request, user: CurrentUser = Depends(get_current_user)):
        authority = await VaultExportAuthority.capture(
            request, user, action="create", secret_key=f.secret
        )
        body = await request.json()
        try:
            token = await complete_oidc_identity(
                authority,
                request_binding=f.operation,
                redirect_uri=f.redirect,
                allowed_redirect_uris=(f.redirect,),
                state=body["state"],
                code=body["code"],
            )
        except (OIDCConfirmationError, InvalidIdentityConfirmation):
            raise HTTPException(401, "Fresh identity confirmation refused") from None
        remember_identity(f, authority, token)
        return {"identity_token": token}

    add_factor_route(f)
    yield f


async def configure_factor(f, factor):
    if factor == "none":
        return None
    await mutate(
        f,
        {
            "mfa_enabled": True,
            "mfa_secret": encrypt_field(f.seed),
            "mfa_backup_codes": json.dumps([f.recovery_hash]),
            "mfa_last_totp_step": None,
        },
    )
    return pyotp.TOTP(f.seed).now() if factor == "totp" else f.recovery


async def ldap_identity(f, headers):
    response = await f.client.post(
        "/owned/ldap/identity", headers=headers, json={"password": "Owned directory password"}
    )
    assert response.status_code == 200, response.text
    return response.json()["identity_token"]


async def complete(f, headers, token, code=None):
    return await f.client.post(
        "/owned/factors/complete", headers=headers, json={"identity_token": token, "code": code}
    )


async def consumed(f, identity_hash=None):
    async with AsyncSession(f.engine) as db:
        return await db.scalar(
            select(func.count())
            .select_from(TokenRevocation)
            .where(TokenRevocation.jti_hash == (identity_hash or f.identity_hash))
        )


async def no_login_or_jit(f):
    async with AsyncSession(f.engine) as db:
        assert (
            await db.scalar(
                select(func.count()).select_from(User).where(User.organization_id.in_([f.org, f.other_org]))
            )
            == 1
        )
        assert (
            await db.scalar(
                select(func.count()).select_from(UserSession).where(UserSession.user_id == f.user)
            )
            == 0
        )
        assert (
            await db.scalar(
                select(func.count())
                .select_from(SSOSession)
                .where(SSOSession.provider_id == f.provider)
            )
            == 0
        )


def assert_consumed_factor(row, factor):
    if factor == "totp":
        assert row["mfa_last_totp_step"] is not None
    elif factor == "recovery":
        assert json.loads(row["mfa_backup_codes"]) == []
    assert row["failed_login_attempts"] == 0


@pytest.mark.parametrize("ldap_protocol", ["ldaps", "ldap"])
@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("factor", ["none", "totp", "recovery"])
@pytest.mark.asyncio
async def test_real_ldap_then_mfa_and_one_use(ldap_factors, kind, factor):
    f = ldap_factors
    code = await configure_factor(f, factor)
    headers, _ = credentials(f, kind)
    token = await ldap_identity(f, headers)
    before = await state(f)
    assert before["mfa_last_totp_step"] is None
    response = await complete(f, headers, token, code)
    after = await state(f)
    assert response.status_code == 200, response.text
    assert response.json()["expires_at"] == f.identity_claims["exp"]
    assert response.json()["authenticated_at"] == f.identity_claims["auth_time"]
    assert_consumed_factor(after, factor)
    assert await consumed(f) == 1
    assert (await complete(f, headers, token, code)).status_code == 401
    assert await state(f) == after
    await no_login_or_jit(f)
    assert len(f.peer.passwords) == 1


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("factor", ["none", "totp", "recovery"])
@pytest.mark.asyncio
async def test_real_signed_oidc_then_mfa_and_one_use(oidc_factors, kind, factor):
    f = oidc_factors
    code = await configure_factor(f, factor)
    raw = await start_oidc(f, kind)
    response = await f.client.post(
        "/owned/oidc/identity", headers=f.headers, json={"state": raw, "code": "owned-code"}
    )
    assert response.status_code == 200, response.text
    token = response.json()["identity_token"]
    response = await complete(f, f.headers, token, code)
    after = await state(f)
    assert response.status_code == 200, response.text
    assert_consumed_factor(after, factor)
    assert await consumed(f) == 1
    assert (await complete(f, f.headers, token, code)).status_code == 401
    assert await state(f) == after
    assert f.requests.count("/token") == 1
    await no_login_or_jit(f)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize(
    "change",
    [
        "active",
        "verified",
        "deleted",
        "org",
        "role",
        "version",
        "subject",
        "provider",
        "key",
        "unchanged",
    ],
)
@pytest.mark.asyncio
async def test_real_authority_change_during_ldap_bind(ldap_factors, kind, change):
    f = ldap_factors
    f.peer.mode = "pause-bind"
    headers, _ = credentials(f, kind)
    task = asyncio.create_task(
        f.client.post(
            "/owned/ldap/identity", headers=headers, json={"password": "Owned directory password"}
        )
    )
    await asyncio.wait_for(f.peer.entered.wait(), 5)
    values = {
        "active": {"is_active": False},
        "verified": {"is_verified": False},
        "deleted": {"deleted_at": datetime.now(UTC)},
        "org": {"organization_id": f.other_org},
        "role": {"role": "viewer"},
        "version": {"token_version": 18},
        "subject": {"external_id": "cn=changed,dc=example,dc=invalid"},
    }
    if change in values:
        await mutate(f, values[change])
    elif change in {"provider", "key"}:
        async with AsyncSession(f.engine) as db:
            if change == "provider":
                await db.execute(
                    update(SSOProvider)
                    .where(SSOProvider.id == f.provider)
                    .values(ldap_url="ldaps://changed.example.invalid")
                )
            else:
                await db.execute(
                    update(APIKey).where(APIKey.id == f.key_id).values(is_active=False)
                )
            await db.commit()
    f.peer.release.set()
    response = await task
    valid = change == "unchanged" or (kind == "jwt" and change == "key")
    assert response.status_code == (200 if valid else 401), response.text
    assert ("identity_token" in response.json()) is valid
    assert len(f.peer.passwords) == 1
    await no_login_or_jit(f)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize(
    "change", ["active", "version", "mfa", "seed", "step", "code", "provider", "key", "unchanged"]
)
@pytest.mark.asyncio
async def test_current_authority_after_real_mfa_row_wait(
    ldap_factors, kind, change, record_property
):
    f = ldap_factors
    code = await configure_factor(f, "totp")
    headers, _ = credentials(f, kind)
    token = await ldap_identity(f, headers)
    async with AsyncSession(f.engine) as holder:
        await holder.begin()
        holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(select(User.id).where(User.id == f.user).with_for_update())
        task = asyncio.create_task(complete(f, headers, token, code))
        await real_wait(f, task, holder_pid)
        record_property("actual_User_wait", True)
        changes = {
            "active": {"is_active": False},
            "version": {"token_version": 18},
            "mfa": {"mfa_enabled": False},
            "seed": {"mfa_secret": encrypt_field(pyotp.random_base32())},
            "step": {"mfa_last_totp_step": int(time.time()) // 30},
            "code": {"mfa_backup_codes": "[]"},
        }
        if change in changes:
            await holder.execute(update(User).where(User.id == f.user).values(**changes[change]))
        elif change == "provider":
            await holder.execute(
                update(SSOProvider)
                .where(SSOProvider.id == f.provider)
                .values(ldap_url="ldaps://changed.example.invalid")
            )
        elif change == "key":
            await holder.execute(
                update(APIKey).where(APIKey.id == f.key_id).values(is_active=False)
            )
        await holder.commit()
        response = await task
    valid = change == "unchanged" or (kind == "jwt" and change == "key")
    assert response.status_code == (200 if valid else 401), response.text
    assert await consumed(f) == 1
    if valid:
        assert (await state(f))["mfa_last_totp_step"] is not None


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("factor", ["totp", "recovery"])
@pytest.mark.asyncio
async def test_two_real_claim_waiters_have_one_winner(ldap_factors, kind, factor, record_property):
    f = ldap_factors
    code = await configure_factor(f, factor)
    headers, _ = credentials(f, kind)
    token = await ldap_identity(f, headers)
    async with AsyncSession(f.engine) as holder:
        await holder.begin()
        holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(
            insert(TokenRevocation).values(
                jti_hash=f.identity_hash,
                expires_at=datetime.fromtimestamp(f.identity_claims["exp"], UTC),
            )
        )
        tasks = [asyncio.create_task(complete(f, headers, token, code)) for _ in range(2)]
        combined = asyncio.gather(*tasks)
        await real_wait(f, combined, holder_pid, count=2)
        record_property("two_actual_claim_waiters", True)
        await holder.rollback()
        responses = await combined
    assert sorted(r.status_code for r in responses) == [200, 401]
    assert await consumed(f) == 1
    assert_consumed_factor(await state(f), factor)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("factor", ["totp", "recovery"])
@pytest.mark.asyncio
async def test_distinct_identity_tokens_cannot_reuse_same_local_factor(
    ldap_factors, kind, factor, record_property
):
    f = ldap_factors
    code = await configure_factor(f, factor)
    headers, _ = credentials(f, kind)
    tokens = [await ldap_identity(f, headers), await ldap_identity(f, headers)]
    async with AsyncSession(f.engine) as holder:
        await holder.begin()
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(select(User.id).where(User.id == f.user).with_for_update())
        tasks = [asyncio.create_task(complete(f, headers, token, code)) for token in tokens]
        combined = asyncio.gather(*tasks)
        await real_wait(f, combined, pid, count=2)
        record_property("two_actual_MFA_waiters", True)
        await holder.commit()
        responses = await combined
    assert sorted(r.status_code for r in responses) == [200, 401]
    assert_consumed_factor(await state(f), factor)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.asyncio
async def test_five_failed_mfa_attempts_persist_and_lock(ldap_factors, kind):
    f = ldap_factors
    await configure_factor(f, "recovery")
    headers, _ = credentials(f, kind)
    for attempt in range(1, 6):
        token = await ldap_identity(f, headers)
        response = await complete(f, headers, token, "BAD0BAD0XX")
        row = await state(f)
        assert response.status_code == 401, response.text
        assert await consumed(f) == 1
        assert row["failed_login_attempts"] == attempt
        assert json.loads(row["mfa_backup_codes"]) == [f.recovery_hash]
        assert (row["locked_until"] is not None) == (attempt == 5)
    response = await f.client.post(
        "/owned/ldap/identity", headers=headers, json={"password": "Owned directory password"}
    )
    assert response.status_code in {401, 403}
    assert len(f.peer.passwords) == 5


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.asyncio
async def test_actual_identity_expiry_during_mfa_wait(ldap_factors, kind, record_property):
    f = ldap_factors
    code = await configure_factor(f, "recovery")
    headers, _ = credentials(f, kind)
    await ldap_identity(f, headers)
    body = dict(f.identity_claims)
    body["exp"] = int(time.time()) + 2
    token = jwt.encode(body, f.identity_key, algorithm="HS256")
    async with AsyncSession(f.engine) as holder:
        await holder.begin()
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(select(User.id).where(User.id == f.user).with_for_update())
        task = asyncio.create_task(complete(f, headers, token, code))
        await real_wait(f, task, pid)
        record_property("actual_expiry_User_wait", True)
        await asyncio.sleep(max(0, body["exp"] - time.time()) + 0.05)
        await holder.commit()
        response = await task
    assert response.status_code == 401, response.text
    assert await consumed(f) == 1
    row = await state(f)
    assert json.loads(row["mfa_backup_codes"]) == [f.recovery_hash]
    assert row["failed_login_attempts"] == 0


@pytest.mark.parametrize("cancellation", ["asyncio", "anyio"])
@pytest.mark.asyncio
async def test_cancellation_during_owned_factor_wait_keeps_consumption(
    ldap_factors, cancellation, record_property
):
    f = ldap_factors
    code = await configure_factor(f, "recovery")
    headers, _ = credentials(f, "jwt")
    token = await ldap_identity(f, headers)
    scopes, delivered = [], []

    async def run():
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            delivered.append(await complete(f, headers, token, code))

    async with AsyncSession(f.engine) as holder:
        await holder.begin()
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(select(User.id).where(User.id == f.user).with_for_update())
        task = asyncio.create_task(run())
        await real_wait(f, task, pid)
        record_property("actual_cancelled_User_wait", True)
        if cancellation == "asyncio":
            task.cancel()
        else:
            scopes[0].cancel()
        await asyncio.sleep(0.03)
        assert not task.done()
        await holder.commit()
        if cancellation == "asyncio":
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await task
    assert not delivered
    assert await consumed(f) == 1
    assert json.loads((await state(f))["mfa_backup_codes"]) == []
    assert (await complete(f, headers, token, code)).status_code == 401
