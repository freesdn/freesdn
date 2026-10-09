# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A failed collector must not produce a completed disaster-recovery vault.

Real PostgreSQL, collector reads, HTTP authentication and encrypted local files.
Only the selected collector's failure is injected; no persistence/storage mocks.
"""

import gzip
import hashlib
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.security import create_access_token, get_password_hash
from app.models.core import Organization, User
from app.modules.backup.models import Backup, BackupStatus, StorageLocation
from app.services.backup import BackupEncryption, BackupService, LocalStorageBackend
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    CoreBackupContributor,
)
from app.services.backup_transport import StorageConfigurationError
from tests.services.test_backup_artifact_integrity_contract import authorize_owned_vault
from tests.services.test_backup_vault_secret_authorization import async_client as async_client
from tests.services.test_backup_vault_secret_authorization import db_session as db_session


class FallibleCollector(CoreBackupContributor):
    def __init__(self, identity, failure=None):
        self.contributor_id = identity
        self.depends_on = () if identity == "core" else ("core",)
        self.failure = failure

    async def collect(self, session, organization_id, options):
        payload = await super().collect(session, organization_id, options)
        if self.failure is not None:
            raise self.failure
        return payload


async def fixture(db, tmp_path, monkeypatch, *, failed_id="extension", error_type=None, missing_core=False):
    import app.services.backup_contributors as contributors

    marker = "private-collector-diagnostic-" + uuid4().hex
    registry = BackupContributorRegistry()
    failed = FallibleCollector(failed_id, error_type(marker) if error_type else None)
    if not missing_core:
        registry.register(failed if failed_id == "core" else CoreBackupContributor())
        if failed_id != "core":
            registry.register(failed)
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    org = Organization(name="Owned complete vault", slug=uuid4().hex)
    db.add(org)
    await db.flush()
    identity = uuid4().hex
    user = User(organization_id=org.id, username=identity, email=identity + "@example.com",
                hashed_password=get_password_hash("Owned collector fixture password"),
                role="super_admin", is_active=True, is_verified=True)
    storage = StorageLocation(organization_id=org.id, name="Owned collector storage", storage_type="local",
                              config={"path": str(tmp_path)}, is_active=True)
    db.add_all([user, storage])
    await db.flush()
    headers = {"Authorization": "Bearer " + create_access_token(subject=str(user.id), token_version=user.token_version)}
    # Real independent confirmation/checkpoint sessions must see owned rows.
    # The module's committed-row fixture removes only these owned identities.
    await db.commit()
    return SimpleNamespace(db=db, org=org, user=user, storage=storage, headers=headers, failed=failed,
                           marker=marker, phrase="Owned complete collection vault passphrase", root=tmp_path,
                           password="Owned collector fixture password", client=None,
                           claim_hashes=db.info["vault_claim_hashes"])


def files(f):
    return {str(p.relative_to(f.root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in f.root.rglob("*") if p.is_file()}


async def create(f, client, secrets, path):
    if path == "http":
        identity = await client.get("/api/v1/auth/me", headers=f.headers)
        assert identity.status_code == 200 and identity.json()["id"] == str(f.user.id)
        data = {
            "name": "Owned completeness test", "include_devices": False, "include_users": True,
            "include_automation": False, "include_secrets": secrets,
            "passphrase": f.phrase if secrets else None, "storage_location_id": str(f.storage.id),
        }
        f.client = client
        headers = dict(f.headers)
        if secrets:
            proof = await authorize_owned_vault(f, {"kind": "create", "backup": data}, headers=f.headers)
            headers["X-FreeSDN-Vault-Proof"] = proof
        response = await client.post("/api/v1/backups/", headers=headers, json=data)
        assert f.marker not in response.text
        return response.status_code
    try:
        await BackupService(f.db).create_backup(
            name="Owned completeness test", organization_id=f.org.id, include_devices=False,
            include_users=True, include_automation=False, include_secrets=secrets,
            passphrase=f.phrase if secrets else None, storage_location_id=f.storage.id, is_encrypted=True,
        )
    except Exception as exc:
        # Only actual failures qualify; safe fixed messages must not leak the
        # injected provider/SDK diagnostic through the direct service boundary.
        assert f.marker not in str(exc)
        return 500
    return 201


async def rows(f):
    return list((await f.db.scalars(select(Backup).where(Backup.organization_id == f.org.id))).all())


async def decoded(f, backup):
    blob = await LocalStorageBackend(f.storage.config).load(backup.storage_path)
    size = int.from_bytes(blob[:4], "big")
    header, body = json.loads(blob[4:4 + size]), blob[4 + size:]
    assert header["encrypted"] is True and hashlib.sha256(body).hexdigest() == header["checksum"]
    cipher = BackupEncryption(master_key=f.phrase) if backup.include_secrets else BackupService(f.db).encryption
    return BackupArchive.model_validate_json(gzip.decompress(cipher.decrypt(body, header["key_id"])))


@pytest.mark.parametrize("failed_id", ["core", "extension"])
@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, StorageConfigurationError])
@pytest.mark.parametrize("path", ["http", "service"])
async def test_full_vault_collection_failure_keeps_prior_archive_and_allows_retry(
    db_session, async_client, tmp_path, monkeypatch, failed_id, error_type, path
):
    f = await fixture(db_session, tmp_path, monkeypatch, failed_id=failed_id, error_type=error_type)
    failure = f.failed.failure
    f.failed.failure = None
    assert await create(f, async_client, True, path) == 201
    prior = (await rows(f))[0]
    prior_bytes = files(f)
    assert prior.status == BackupStatus.COMPLETED and prior_bytes
    f.failed.failure = failure
    assert await create(f, async_client, True, path) == 500
    attempts = await rows(f)
    assert len(attempts) == 2
    refused = next(b for b in attempts if b.id != prior.id)
    assert refused.status == BackupStatus.FAILED and refused.storage_path is None
    assert refused.error_message and "collector" in refused.error_message.lower()
    assert f.marker not in refused.error_message
    assert files(f) == prior_bytes
    f.failed.failure = None
    assert await create(f, async_client, True, path) == 201
    completed = [b for b in await rows(f) if b.status == BackupStatus.COMPLETED]
    assert len(completed) == 2
    recovered = next(b for b in completed if b.id != prior.id)
    archive = await decoded(f, recovered)
    assert "core" in archive.contributors
    assert str(f.user.id) in {u["id"] for u in archive.contributors["core"]["users"]}
    assert prior_bytes.items() <= files(f).items()


@pytest.mark.parametrize("failed_id", ["core", "extension"])
@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, StorageConfigurationError])
async def test_configuration_snapshot_retains_explicit_partial_export_warning(
    db_session, async_client, tmp_path, monkeypatch, failed_id, error_type
):
    f = await fixture(db_session, tmp_path, monkeypatch, failed_id=failed_id, error_type=error_type)
    assert await create(f, async_client, False, "http") == 201
    backup, = await rows(f)
    assert backup.status == BackupStatus.COMPLETED and backup.error_message
    assert failed_id in backup.error_message and f.marker not in backup.error_message
    assert files(f)
    archive = await decoded(f, backup)
    assert failed_id not in archive.contributors


@pytest.mark.parametrize("path", ["http", "service"])
async def test_full_vault_refuses_missing_core_collector(db_session, async_client, tmp_path, monkeypatch, path):
    f = await fixture(db_session, tmp_path, monkeypatch, missing_core=True)
    assert await create(f, async_client, True, path) == 500
    backup, = await rows(f)
    assert backup.status == BackupStatus.FAILED and backup.storage_path is None
    assert "core collector" in backup.error_message.lower()
    assert files(f) == {}


@pytest.mark.parametrize("secrets", [False, True])
async def test_complete_collectors_still_store_decryptable_archives(db_session, async_client, tmp_path, monkeypatch, secrets):
    f = await fixture(db_session, tmp_path, monkeypatch)
    assert await create(f, async_client, secrets, "http") == 201
    backup, = await rows(f)
    assert backup.status == BackupStatus.COMPLETED and not backup.error_message
    archive = await decoded(f, backup)
    assert set(archive.contributors) == {"core", "extension"}
    assert str(f.user.id) in {u["id"] for u in archive.contributors["core"]["users"]}
