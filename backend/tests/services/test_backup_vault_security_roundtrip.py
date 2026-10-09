# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real sealed vault recovery must preserve account security under a new field key.

Disposable PostgreSQL, actual collector/archive/dispatcher and synthetic keys.
These cases do not represent a customer identity-provider or packaged deployment.
"""

import gzip
import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import jwt
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security_utils
from app.core.config import settings
from app.core.cookies import ACCESS_COOKIE, REFRESH_COOKIE
from app.core.security import get_password_hash, verify_password
from app.core.security_utils import decrypt_field, encrypt_field
from app.db.session import create_test_engine, get_session
from app.main import app
from app.models.api_keys import APIKey
from app.models.core import Organization, TokenRevocation, User, UserSession
from app.models.security_audit import AuditLogRecord
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus
from app.modules.backup.models import Backup, BackupStatus, StorageLocation
from app.services.backup import BackupEncryption, BackupService, LocalStorageBackend
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    CoreBackupContributor,
)

ACCOUNT_FIELDS = [
    "mfa_enabled", "mfa_secret", "mfa_backup_codes", "mfa_pending_secret",
    "mfa_pending_backup_codes", "mfa_last_totp_step", "token_version", "is_verified",
    "failed_login_attempts", "locked_until", "last_login", "auth_provider", "external_id",
    "sso_provider_id", "is_active", "hashed_password",
]


@asynccontextmanager
async def owned_vault_database(monkeypatch, engine):
    # Real independent commits make source rows visible to a separately
    # acquired consistent-snapshot connection. No outer test rollback masks it.
    org_ids, user_ids, token_hashes = [], [], set()

    async def independent_session():
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    monkeypatch.setitem(app.dependency_overrides, get_session, independent_session)
    try:
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as db:
            db.info.update(owned_org_ids=org_ids, owned_user_ids=user_ids, owned_token_hashes=token_hashes)
            try:
                yield db
            finally:
                await db.rollback()
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.organization_id.in_(org_ids)))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id.in_(user_ids)))
            await cleanup.execute(delete(APIKey).where(APIKey.user_id.in_(user_ids)))
            await cleanup.execute(delete(User).where(User.id.in_(user_ids)))
            await cleanup.execute(delete(SSOProvider).where(SSOProvider.organization_id.in_(org_ids)))
            await cleanup.execute(delete(Backup).where(Backup.organization_id.in_(org_ids)))
            await cleanup.execute(delete(StorageLocation).where(StorageLocation.organization_id.in_(org_ids)))
            await cleanup.execute(delete(Organization).where(Organization.id.in_(org_ids)))
            await cleanup.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash.in_(token_hashes)))
            await cleanup.commit()
        await engine.dispose()
        # Override callables may remain classified after fixture cleanup.
        # All owned requests and database cleanup have finished.
        engine = None


@pytest_asyncio.fixture
async def vault_db(monkeypatch):
    async with owned_vault_database(monkeypatch, create_test_engine()) as db:
        yield db


def remember_owned_token(db, token, *, audience="freesdn-api"):
    # Verify this freshly minted synthetic token before retaining ONLY its
    # durable-revocation identifier for precise fixture cleanup.
    claims = jwt.decode(token, settings.jwt_signing_key, algorithms=[settings.ALGORITHM],
                        audience=audience, issuer="freesdn", options={"require": ["exp", "iat", "sub", "jti"]})
    db.info["owned_token_hashes"].add(hashlib.sha256(claims["jti"].encode()).hexdigest())


@pytest_asyncio.fixture
async def vault_auth_client(vault_db):
    identity = uuid4().int
    peer = f"198.19.{(identity >> 8) & 255}.{identity & 255}"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(peer, 45123)),
                                 base_url="http://test") as client:
        yield client


async def source_fixture(db, tmp_path, monkeypatch, *, field=None, protocol=None):
    import pyotp

    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    monkeypatch.setattr(security_utils, "_fernet_instance", Fernet(Fernet.generate_key()))
    org = Organization(name="Owned vault security", slug=uuid4().hex)
    db.add(org)
    await db.flush()
    db.info["owned_org_ids"].append(org.id)
    identity = uuid4().hex
    seed = pyotp.random_base32()
    pending_seed = pyotp.random_base32()
    password = "Owned vault security password"
    retained_code = "AB12CD34EF"
    codes = json.dumps([get_password_hash(retained_code)])
    pending = field in {"mfa_pending_secret", "mfa_pending_backup_codes"}
    user = User(
        organization_id=org.id, username=identity, email=identity + "@example.com",
        role="super_admin", hashed_password=get_password_hash(password),
        mfa_enabled=not pending, mfa_secret=None if pending else encrypt_field(seed),
        mfa_backup_codes=None if pending else codes,
        mfa_pending_secret=encrypt_field(pending_seed) if pending else None,
        mfa_pending_backup_codes=codes if pending else None,
        mfa_last_totp_step=123456,
        token_version=17, is_verified=True, is_active=field != "is_active",
        failed_login_attempts=4 if field == "failed_login_attempts" else 0,
        locked_until=datetime(2099, 1, 1, tzinfo=UTC) if field == "locked_until" else None,
        last_login=datetime(2026, 1, 1, tzinfo=UTC),
    )
    provider = None
    provider_secret = "Owned disposable provider credential"
    if protocol or field in {"auth_provider", "external_id", "sso_provider_id"}:
        protocol = protocol or "oidc"
        provider = SSOProvider(
            organization_id=org.id, name="Owned identity provider", slug=uuid4().hex,
            protocol=SSOProtocol(protocol), status=SSOProviderStatus.ACTIVE,
            oidc_issuer="https://identity.example.invalid", oidc_client_id="owned-client",
            oidc_client_secret=encrypt_field(provider_secret) if protocol == "oidc" else None,
            saml_entity_id="owned-entity", saml_sso_url="https://identity.example.invalid/sso",
            saml_signing_key=encrypt_field(provider_secret) if protocol == "saml" else None,
            ldap_url="ldaps://identity.example.invalid", ldap_base_dn="dc=example,dc=invalid",
            ldap_bind_password=encrypt_field(provider_secret) if protocol == "ldap" else None,
            attribute_mapping={"email": "mail"}, role_mapping={"operators": "operator"},
            jit_provisioning=False, default_role="viewer",
        )
        db.add(provider)
        await db.flush()
        user.auth_provider = protocol
        user.external_id = "owned-external-subject"
        user.sso_provider_id = provider.id
    db.add(user)
    storage = StorageLocation(organization_id=org.id, name="Owned local vault", storage_type="local",
                             config={"path": str(tmp_path)}, is_active=True)
    db.add(storage)
    await db.flush()
    db.info["owned_user_ids"].append(user.id)
    await db.commit()
    return SimpleNamespace(db=db, org=org, user=user, provider=provider, storage=storage,
                           seed=seed, pending_seed=pending_seed, password=password, retained_code=retained_code,
                           provider_secret=provider_secret, phrase="Owned field-key recovery archive passphrase")


async def export_vault(f):
    await f.db.commit()
    service = BackupService(f.db)
    backup = await service.create_backup(
        name="Owned security vault", organization_id=f.org.id, include_devices=False,
        include_users=True, include_automation=False, include_secrets=True, passphrase=f.phrase,
        storage_location_id=f.storage.id, is_encrypted=True,
    )
    assert backup.status == BackupStatus.COMPLETED and not backup.error_message
    await f.db.commit()
    blob = await LocalStorageBackend(f.storage.config).load(backup.storage_path)
    size = int.from_bytes(blob[:4], "big")
    header, body = json.loads(blob[4:4 + size]), blob[4 + size:]
    assert header["secrets"] is True and header["encrypted"] is True
    assert hashlib.sha256(body).hexdigest() == header["checksum"]
    for secret in (f.seed, f.pending_seed, f.password, f.provider_secret, f.user.hashed_password):
        assert secret.encode() not in blob
    archive = BackupArchive.model_validate_json(gzip.decompress(
        BackupEncryption(master_key=f.phrase).decrypt(body, header["key_id"]),
    ))
    return archive


async def recover_under_new_key(f, archive, monkeypatch):
    user_id, org_id = f.user.id, f.org.id
    provider_id = f.provider.id if f.provider is not None else None
    await f.db.delete(f.user)
    await f.db.flush()
    if f.provider is not None:
        await f.db.delete(f.provider)
        await f.db.flush()
    await f.db.commit()
    monkeypatch.setattr(security_utils, "_fernet_instance", Fernet(Fernet.generate_key()))
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=False,
        restore_options={"overwrite_existing": True, "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )
    assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
    await f.db.commit()
    restored = await f.db.get(User, user_id, populate_existing=True)
    assert restored is not None
    return restored, provider_id


@pytest.mark.parametrize("field", ACCOUNT_FIELDS)
async def test_sealed_vault_preserves_account_security_field(vault_db, tmp_path, monkeypatch, field):
    f = await source_fixture(vault_db, tmp_path, monkeypatch, field=field)
    expected = getattr(f.user, field)
    if field in {"mfa_secret", "mfa_pending_secret"}:
        original_ciphertext = expected
        expected = decrypt_field(expected)
    archive = await export_vault(f)
    restored, _ = await recover_under_new_key(f, archive, monkeypatch)
    actual = getattr(restored, field)
    if field in {"mfa_secret", "mfa_pending_secret"}:
        assert actual and actual.startswith("fernet:") and actual != original_ciphertext
        actual = decrypt_field(actual)
    if field == "token_version":
        # Even when an operator retains the JWT signing key, a recovery must
        # not reactivate any token already minted at the snapshot boundary.
        assert actual > expected
    else:
        assert actual == expected
    assert verify_password(f.password, restored.hashed_password)


@pytest.mark.parametrize("protocol,secret_field", [
    ("oidc", "oidc_client_secret"), ("saml", "saml_signing_key"), ("ldap", "ldap_bind_password"),
])
async def test_sealed_vault_restores_provider_before_external_identity(vault_db, tmp_path, monkeypatch, protocol, secret_field):
    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol=protocol)
    original_ciphertext = getattr(f.provider, secret_field)
    archive = await export_vault(f)
    restored, provider_id = await recover_under_new_key(f, archive, monkeypatch)
    provider = await f.db.get(SSOProvider, provider_id, populate_existing=True)
    assert provider is not None and provider.organization_id == restored.organization_id
    assert restored.auth_provider == protocol and restored.external_id == "owned-external-subject"
    assert restored.sso_provider_id == provider.id
    assert str(provider.protocol) == protocol and provider.status == SSOProviderStatus.ACTIVE
    assert provider.attribute_mapping == {"email": "mail"} and provider.role_mapping == {"operators": "operator"}
    assert provider.jit_provisioning is False and provider.default_role == "viewer"
    ciphertext = getattr(provider, secret_field)
    assert ciphertext.startswith("fernet:") and ciphertext != original_ciphertext
    assert decrypt_field(ciphertext) == f.provider_secret


async def test_restored_mfa_login_still_requires_challenge(vault_db, vault_auth_client, tmp_path, monkeypatch):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    archive = await export_vault(f)
    restored, _ = await recover_under_new_key(f, archive, monkeypatch)
    response = await vault_auth_client.post("/api/v1/auth/login", json={"login": restored.username, "password": f.password})
    assert response.status_code == 200
    assert response.json().get("require_mfa") is True and response.json().get("mfa_token")
    assert not any(name in response.cookies for name in (ACCESS_COOKIE, REFRESH_COOKIE))


async def test_restored_mfa_recovery_code_remains_single_use(vault_db, vault_auth_client, tmp_path, monkeypatch):
    from app.core.security import create_access_token

    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    archive = await export_vault(f)
    restored, _ = await recover_under_new_key(f, archive, monkeypatch)

    async def redeem():
        # Real signed challenge, actual route, Redis and locked PostgreSQL row;
        # no authorization, verification, single-use or session mock.
        challenge = create_access_token(subject=str(restored.id), expires_delta=timedelta(minutes=5),
                                        extra_claims={"type": "mfa_pending", "aud": "freesdn-mfa"},
                                        token_version=restored.token_version)
        remember_owned_token(f.db, challenge, audience="freesdn-mfa")
        return await vault_auth_client.post("/api/v1/auth/login/mfa", json={"mfa_token": challenge, "code": f.retained_code})

    first = await redeem()
    assert first.status_code == 200
    await f.db.refresh(restored)
    assert json.loads(restored.mfa_backup_codes) == []
    vault_auth_client.cookies.clear()
    second = await redeem()
    assert second.status_code == 401


@pytest.mark.parametrize("kind", ["access", "refresh", "mfa-pending"])
@pytest.mark.parametrize("old_version", [0, 17])
async def test_recovery_refuses_previously_minted_tokens(vault_db, vault_auth_client, tmp_path, monkeypatch, kind, old_version):
    from app.core.security import create_access_token, create_refresh_token

    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    if kind == "refresh":
        token = create_refresh_token(subject=str(f.user.id), token_version=old_version)
    else:
        claims = {"type": "mfa_pending", "aud": "freesdn-mfa"} if kind == "mfa-pending" else {}
        token = create_access_token(subject=str(f.user.id), token_version=old_version, extra_claims=claims)
    remember_owned_token(f.db, token, audience="freesdn-mfa" if kind == "mfa-pending" else "freesdn-api")
    archive = await export_vault(f)
    await recover_under_new_key(f, archive, monkeypatch)
    if kind == "access":
        response = await vault_auth_client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + token})
    elif kind == "refresh":
        response = await vault_auth_client.post("/api/v1/auth/refresh", json={"refresh_token": token})
    else:
        response = await vault_auth_client.post("/api/v1/auth/login/mfa", json={"mfa_token": token, "code": f.retained_code})
    assert response.status_code == 401
    assert not any(name in response.cookies for name in (ACCESS_COOKIE, REFRESH_COOKIE))


async def test_recovery_keeps_consumed_totp_step_but_allows_remaining_backup_code(vault_db, vault_auth_client, tmp_path, monkeypatch):
    import pyotp

    from app.core import security
    from app.core.security import create_access_token

    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    # Fix only the TOTP verifier clock to remove window-boundary flakiness;
    # signing, verification, Redis single-use checks and database writes stay real.
    fixed = datetime.now(UTC)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed.replace(tzinfo=None) if tz is None else fixed.astimezone(tz)

    monkeypatch.setattr(security, "datetime", FixedDateTime)
    f.user.mfa_last_totp_step = pyotp.TOTP(f.seed).timecode(fixed)
    await f.db.flush()
    archive = await export_vault(f)
    restored, _ = await recover_under_new_key(f, archive, monkeypatch)

    async def complete(code):
        token = create_access_token(subject=str(restored.id), token_version=restored.token_version,
                                    extra_claims={"type": "mfa_pending", "aud": "freesdn-mfa"})
        remember_owned_token(f.db, token, audience="freesdn-mfa")
        return await vault_auth_client.post("/api/v1/auth/login/mfa", json={"mfa_token": token, "code": code})

    replay = await complete(pyotp.TOTP(f.seed).at(fixed))
    assert replay.status_code == 401
    legitimate = await complete(f.retained_code)
    assert legitimate.status_code == 200


@pytest.mark.parametrize("protocol", ["oidc", "saml", "ldap"])
async def test_provider_recovery_never_recreates_transient_login_exchange(vault_db, tmp_path, monkeypatch, protocol):
    from app.models.sso import SSOSession

    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol=protocol)
    transient = SSOSession(provider_id=f.provider.id, user_id=f.user.id,
                           state=uuid4().hex, nonce=uuid4().hex,
                           expires_at=datetime.now(UTC) + timedelta(minutes=10),
                           idp_response={"owned-transient-response": uuid4().hex})
    f.db.add(transient)
    await f.db.flush()
    identity, state, nonce = transient.id, transient.state, transient.nonce
    archive = await export_vault(f)
    decoded = archive.model_dump_json()
    assert state not in decoded and nonce not in decoded
    _, provider_id = await recover_under_new_key(f, archive, monkeypatch)
    assert await f.db.get(SSOProvider, provider_id, populate_existing=True) is not None
    # The provider's database deletion cascaded its original exchange. The
    # restore must not reconstruct it as usable login state.
    if transient in f.db:
        f.db.expunge(transient)
    assert await f.db.get(SSOSession, identity, populate_existing=True) is None
