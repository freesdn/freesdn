# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Account-secret archives require the same authority as full recovery.

Actual HTTP authorization, PostgreSQL, local encrypted storage and generated
credentials; only the fixture-owned database dependency replaces production DB.
"""

from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, event, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import create_access_token, get_password_hash
from app.db.session import create_test_engine, get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, TokenRevocation, User, UserSession
from app.modules.backup.models import Backup, BackupStatus, RestoreJob, StorageLocation
from app.services.backup import BackupService, LocalStorageBackend
from app.services.backup_contributors import BackupContributorRegistry, CoreBackupContributor
from tests.services.test_backup_artifact_integrity_contract import authorize_owned_vault

PRINCIPALS = ["org_admin", "site_admin", "viewer", "super_admin", "super_scoped_key", "super_unscoped_key"]



@pytest_asyncio.fixture
async def db_session():
    """Committed owned rows are visible to the real independent checkpoint."""
    engine = create_test_engine()
    owned_orgs = set()
    try:
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as session:
            session.info["vault_claim_hashes"] = set()
            def remember_owned_orgs(sync_session, _flush_context):
                owned_orgs.update(row.id for row in sync_session.new if isinstance(row, Organization))

            event.listen(session.sync_session, "after_flush", remember_owned_orgs)
            try:
                yield session
            finally:
                await session.rollback()
                event.remove(session.sync_session, "after_flush", remember_owned_orgs)
                if session.info["vault_claim_hashes"]:
                    await session.execute(delete(TokenRevocation).where(
                        TokenRevocation.jti_hash.in_(session.info["vault_claim_hashes"])))
                if owned_orgs:
                    users = select(User.id).where(User.organization_id.in_(owned_orgs))
                    backups = select(Backup.id).where(Backup.organization_id.in_(owned_orgs))
                    await session.execute(delete(RestoreJob).where(RestoreJob.backup_id.in_(backups)))
                    await session.execute(delete(Backup).where(Backup.organization_id.in_(owned_orgs)))
                    await session.execute(delete(APIKey).where(APIKey.user_id.in_(users)))
                    await session.execute(delete(UserSession).where(UserSession.user_id.in_(users)))
                    await session.execute(delete(StorageLocation).where(StorageLocation.organization_id.in_(owned_orgs)))
                    await session.execute(delete(User).where(User.organization_id.in_(owned_orgs)))
                    await session.execute(delete(Organization).where(Organization.id.in_(owned_orgs)))
                    await session.commit()
    finally:
        await engine.dispose()
        engine = None
        from app.db.session import engine as global_engine

        await global_engine.dispose()


@pytest_asyncio.fixture
async def async_client(db_session):
    async def request_session():
        yield db_session

    app.dependency_overrides[get_session] = request_session
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_session, None)
        # All requests ended; do not retain the disposed engine in the callable.
        db_session = None


async def fixture(db, tmp_path, monkeypatch, principal):
    import app.services.backup_contributors as contributors

    # Exercise the real disk-backed pool without requiring access to the
    # production /data/backups mount. Keep transfer state outside the archive.
    monkeypatch.setattr(
        get_settings(), "BACKUP_DOWNLOAD_SPOOL", str(tmp_path.with_name(tmp_path.name + "-transfers")),
    )
    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    org = Organization(name="Owned vault authorization", slug=uuid4().hex)
    db.add(org)
    await db.flush()
    identity = uuid4().hex
    source_admin = User(organization_id=org.id, username=identity, email=identity + "@example.com",
                        hashed_password=get_password_hash("Owned source administrator password"),
                        role="super_admin", is_active=True, is_verified=True)
    role = "super_admin" if principal.startswith("super_") else principal
    actor_identity = uuid4().hex
    actor = User(organization_id=org.id, username=actor_identity,
                 email=actor_identity + "@example.com",
                 hashed_password=get_password_hash("Owned actor authorization password"),
                 role=role, is_active=True, is_verified=True)
    storage = StorageLocation(organization_id=org.id, name="Owned authorization storage",
                             storage_type="local", config={"path": str(tmp_path)}, is_active=True)
    db.add_all([source_admin, actor, storage])
    await db.flush()
    db_key = None
    if principal.endswith("_key"):
        key, prefix, digest = generate_api_key()
        db_key = APIKey(user_id=actor.id, name="Owned authorization credential",
                      key_prefix=prefix, key_hash=digest, is_active=True,
                      scopes=["backup.create", "backup.view"] if principal == "super_scoped_key" else [])
        db.add(db_key)
        await db.flush()
        headers = {"X-API-Key": key}
    else:
        headers = {"Authorization": "Bearer " + create_access_token(subject=str(actor.id), token_version=actor.token_version)}
    await db.commit()
    return SimpleNamespace(db=db, org=org, actor=actor, storage=storage, headers=headers, api_key=db_key,
                           phrase="Owned authorization archive passphrase",
                           password="Owned actor authorization password", client=None,
                           claim_hashes=db.info["vault_claim_hashes"])


@pytest.mark.parametrize("principal", PRINCIPALS)
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("operation", ["create", "download"])
async def test_full_vault_access_obeys_role_and_credential_ceiling(
    db_session, async_client, tmp_path, monkeypatch, principal, secrets, operation
):
    f = await fixture(db_session, tmp_path, monkeypatch, principal)
    f.client = async_client
    # Prove even refused callers authenticated with real credentials. Auth/me
    # accepts JWT sessions only; the backup stats route uses the same canonical
    # JWT/API-key dependency as create/download. Last-used proves key lookup and
    # hash verification; a corrupted key must fail on that very same endpoint.
    if f.api_key is not None:
        identity = await async_client.get("/api/v1/backups/stats", headers=f.headers)
        assert identity.status_code == 200 and f.api_key.last_used is not None
        invalid = await async_client.get(
            "/api/v1/backups/stats", headers={"X-API-Key": f.headers["X-API-Key"] + "corrupted"}
        )
        assert invalid.status_code == 401
    else:
        identity = await async_client.get("/api/v1/auth/me", headers=f.headers)
        assert identity.status_code == 200 and identity.json()["id"] == str(f.actor.id)
    unrestricted_admin = principal in {"org_admin", "super_admin", "super_unscoped_key"}
    full_authority = principal in {"super_admin", "super_unscoped_key"}
    permitted = unrestricted_admin and (not secrets or full_authority)
    if operation == "create":
        before = await f.db.scalar(select(func.count()).select_from(Backup))
        original_files = {p.relative_to(tmp_path) for p in tmp_path.rglob("*") if p.is_file()}
        data = {
            "name": "Owned role boundary archive", "storage_location_id": str(f.storage.id),
            "include_devices": False, "include_users": True, "include_automation": False,
            "include_secrets": secrets, "passphrase": f.phrase if secrets else None,
        }
        headers = dict(f.headers)
        if permitted and secrets:
            proof = await authorize_owned_vault(f, {"kind": "create", "backup": data}, headers=f.headers)
            headers["X-FreeSDN-Vault-Proof"] = proof
        response = await async_client.post("/api/v1/backups/", headers=headers, json=data)
        count = await f.db.scalar(select(func.count()).select_from(Backup))
        assert (response.status_code, count) == (201 if permitted else 403, before + int(permitted))
        if permitted:
            assert response.json()["status"] == "completed"
        else:
            assert {p.relative_to(tmp_path) for p in tmp_path.rglob("*") if p.is_file()} == original_files
    else:
        backup = await BackupService(f.db).create_backup(
            name="Owned prepared archive", organization_id=f.org.id, include_devices=False,
            include_users=True, include_automation=False, include_secrets=secrets,
            passphrase=f.phrase if secrets else None, storage_location_id=f.storage.id, is_encrypted=True,
        )
        assert backup.status == BackupStatus.COMPLETED
        expected = await LocalStorageBackend(f.storage.config).load(backup.storage_path)
        headers = dict(f.headers)
        if permitted and secrets:
            proof = await authorize_owned_vault(f, {
                "kind": "download_recorded", "backup_id": str(backup.id),
            }, headers=f.headers)
            headers["X-FreeSDN-Vault-Proof"] = proof
        response = await async_client.get(f"/api/v1/backups/{backup.id}/download", headers=headers)
        assert response.status_code == (200 if permitted else 403)
        if permitted:
            assert response.headers["content-type"] == "application/octet-stream"
            assert response.content == expected
        else:
            assert response.headers["content-type"] != "application/octet-stream"
