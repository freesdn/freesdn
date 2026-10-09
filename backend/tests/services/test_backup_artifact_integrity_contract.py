# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private, unrun artifact/HTTP contracts; historical checksums stay ambiguous.

Real PostgreSQL, core collection/encryption/local files and HTTP credentials and
response models. A core-only registry is explicit; no other contributors,
remote storage or external identity are qualified. Full-vault setup uses the
actual registered password-confirmation API and preserves its proof boundary.
"""

import hashlib
import hmac
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import jwt
import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import create_access_token, get_password_hash
from app.db.session import create_test_engine, get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, TokenRevocation, User, UserSession
from app.modules.backup.models import Backup, RestoreJob, StorageLocation
from app.services.backup import BackupService, LocalStorageBackend
from app.services.backup_contributors import BackupContributorRegistry, CoreBackupContributor


@asynccontextmanager
async def owned_actor(monkeypatch, tmp_path, credential="jwt"):
    import app.services.backup_contributors as contributors

    # A native test user cannot write the production /data/backups spool.
    # Keep real disk/ownership/capacity checks, with a private sibling outside
    # the archive root whose contents these cases independently inspect.
    monkeypatch.setattr(
        get_settings(), "BACKUP_DOWNLOAD_SPOOL", str(tmp_path.with_name(tmp_path.name + "-transfers")),
    )
    engine = create_test_engine()
    org_id, actor_id, storage_id = uuid4(), uuid4(), uuid4()
    name = uuid4().hex
    password = "Owned-Artifact!9-" + uuid4().hex
    claim_hashes = set()
    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)

    async def request_session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    monkeypatch.setitem(app.dependency_overrides, get_session, request_session)
    try:
        async with AsyncSession(engine) as db:
            db.add(Organization(id=org_id, name="Owned artifact", slug=name))
            await db.flush()
            db.add(User(id=actor_id, organization_id=org_id, username=name,
                        email=name + "@example.com", role="super_admin",
                        hashed_password=get_password_hash(password),
                        is_active=True, is_verified=True, token_version=17))
            db.add(StorageLocation(id=storage_id, organization_id=org_id,
                                   name="Owned artifact files", storage_type="local",
                                   config={"path": str(tmp_path)}, is_active=True))
            await db.flush()
            if credential == "key":
                key, prefix, digest = generate_api_key()
                db.add(APIKey(user_id=actor_id, name="Owned artifact caller", key_prefix=prefix,
                              key_hash=digest, scopes=[], is_active=True))
                headers = {"X-API-Key": key}
            else:
                headers = {"Authorization": "Bearer " + create_access_token(str(actor_id), token_version=17)}
            await db.commit()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test", headers=headers,
        ) as client:
            yield SimpleNamespace(engine=engine, org_id=org_id, actor_id=actor_id,
                                  storage_id=storage_id, client=client, root=tmp_path,
                                  password=password, claim_hashes=claim_hashes,
                                  phrase="Owned archive passphrase!9-" + uuid4().hex)
    finally:
        async with AsyncSession(engine) as db:
            owned = select(Backup.id).where(Backup.organization_id == org_id)
            await db.execute(delete(RestoreJob).where(RestoreJob.backup_id.in_(owned)))
            await db.execute(delete(Backup).where(Backup.organization_id == org_id))
            await db.execute(delete(APIKey).where(APIKey.user_id == actor_id))
            await db.execute(delete(UserSession).where(UserSession.user_id == actor_id))
            if claim_hashes:
                await db.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash.in_(claim_hashes)))
            await db.execute(delete(StorageLocation).where(StorageLocation.id == storage_id))
            await db.execute(delete(User).where(User.id == actor_id))
            await db.execute(delete(Organization).where(Organization.id == org_id))
            await db.commit()
        await engine.dispose()
        # Cached request_session callables outlive this context.
        # All owned requests and cleanup have finished at this point.
        engine = None


def create_request(f, secrets):
    return {
        "name": "Owned artifact", "storage_location_id": str(f.storage_id),
        "include_devices": False, "include_vlans": False, "include_ssids": False,
        "include_users": True, "include_automation": False, "is_encrypted": True,
        "include_secrets": secrets, "passphrase": f.phrase if secrets else None,
    }


def remember_owned_proof(f, token):
    """Verify a returned proof only to track its owned durable claim for cleanup."""
    authority_key = hmac.digest(get_settings().SECRET_KEY.encode(), b"FreeSDN/vault-authority/v1", "sha256")
    signing_key = hmac.digest(authority_key, b"FreeSDN/vault-export/final-signature/v2", "sha256")
    claims = jwt.decode(token, signing_key, algorithms=["HS256"], audience="freesdn-vault-export-v2", issuer="freesdn")
    f.claim_hashes.add(hashlib.sha256(claims["jti"].encode()).hexdigest())
    return claims


async def authorize_owned_vault(f, intent, *, headers=None):
    """Use real registered HTTP/password confirmation, never forge a proof."""
    response = await f.client.post("/api/v1/auth/vault-export/authorize/local", json={
        "intent": intent, "password": f.password,
    }, headers=headers)
    assert response.status_code == 200, "Owned fresh confirmation prerequisite failed"
    token = response.json()["proof"]
    remember_owned_proof(f, token)
    return token


async def recorded_download_headers(f, backup_id, secrets, *, headers=None):
    """Call explicitly before any deliberate catalogue/account/file mutation."""
    if not secrets:
        return {}
    proof = await authorize_owned_vault(f, {"kind": "download_recorded", "backup_id": str(backup_id)}, headers=headers)
    return {"X-FreeSDN-Vault-Proof": proof}


async def acknowledged_legacy_download(f, backup_id):
    """Exercise explicit observation/download; never relabel old metadata."""
    proof = await authorize_owned_vault(f, {
        "kind": "observe_legacy", "backup_id": str(backup_id), "legacy_acknowledged": True,
    })
    headers = {"X-FreeSDN-Vault-Proof": proof}
    refused = await f.client.get(f"/api/v1/backups/{backup_id}/download", headers=headers)
    assert refused.status_code == 409, "Legacy GET must not bypass explicit observation"
    observed = await f.client.post(f"/api/v1/backups/{backup_id}/vault-observation",
                                  json={"legacy_acknowledged": True}, headers=headers)
    assert observed.status_code == 200, "Owned legacy observation prerequisite failed"
    value = observed.json()
    original = remember_owned_proof(f, proof)
    final = remember_owned_proof(f, value["proof"])
    assert final["auth_time"] == original["auth_time"]
    assert final["exp"] <= original["exp"] and final["auth_exp"] <= original["auth_exp"]
    assert value["artifact_integrity"] == "legacy_unverified"
    return await f.client.post(f"/api/v1/backups/{backup_id}/vault-download", json={
        "legacy_acknowledged": True, "observed_identity": value["observed_identity"],
    }, headers={"X-FreeSDN-Vault-Proof": value["proof"]})


async def create_archive(f, secrets):
    data = create_request(f, secrets)
    headers = {}
    if secrets:
        proof = await authorize_owned_vault(f, {"kind": "create", "backup": data})
        headers["X-FreeSDN-Vault-Proof"] = proof
    response = await f.client.post("/api/v1/backups/", json=data, headers=headers)
    assert response.status_code == 201, "Owned archive creation prerequisite failed"
    assert response.json()["status"] == "completed"
    async with AsyncSession(f.engine) as db:
        backup = await db.get(Backup, UUID(response.json()["id"]))
        assert backup is not None
        path = f.root / backup.storage_path
        return backup, path, path.read_bytes()


def identity(raw):
    return {"version": 1, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


async def set_identity(f, backup_id, value, *, legacy=False, checksum=None):
    async with AsyncSession(f.engine) as db:
        backup = await db.get(Backup, backup_id)
        backup.metadata_json = {} if legacy else {"artifact_identity": value}
        backup.checksum = checksum
        await db.commit()


async def actor_state(f):
    async with AsyncSession(f.engine) as db:
        row = await db.get(User, f.actor_id)
        return (row.hashed_password, row.token_version, row.role, row.is_active, row.mfa_enabled)


async def invoke(f, backup_id, operation, *, headers=None):
    if operation == "restore":
        return await f.client.post("/api/v1/backups/restore", json={
            "backup_id": str(backup_id), "dry_run": True, "passphrase": f.phrase,
        })
    endpoint = "manifest" if operation == "manifest" else "download"
    return await f.client.get(f"/api/v1/backups/{backup_id}/{endpoint}", headers=headers)


@pytest.mark.parametrize("secrets", [False, True])
async def test_new_archive_records_a_separate_whole_file_identity(monkeypatch, tmp_path, request, secrets):
    async with owned_actor(monkeypatch, tmp_path) as f:
        backup, path, raw = await create_archive(f, secrets)
        detail = await f.client.get(f"/api/v1/backups/{backup.id}")
        observed = (backup.metadata_json or {}).get("artifact_identity")
        request.node.user_properties.extend([
            ("creation_status", backup.status), ("file_bytes", len(raw)),
            ("whole_file_identity_matches", observed == identity(raw)),
            ("catalogue_integrity_state", detail.json().get("artifact_integrity")),
        ])
        assert observed == identity(raw)
        assert backup.file_size == len(raw) and path.is_file()
        assert detail.status_code == 200 and detail.json()["artifact_integrity"] == "recorded"


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("operation", ["download", "manifest", "restore"])
@pytest.mark.parametrize("change", ["unchanged", "header", "payload"])
async def test_catalogue_reads_use_recorded_whole_file_identity(
    monkeypatch, tmp_path, request, credential, secrets, operation, change
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        backup, path, raw = await create_archive(f, secrets)
        await set_identity(f, backup.id, identity(raw))
        headers = await recorded_download_headers(f, backup.id, secrets) if operation == "download" else {}
        if change == "header":
            size = int.from_bytes(raw[:4], "big")
            header = json.loads(raw[4:4 + size])
            header["backup_id"] = str(uuid4())
            encoded = json.dumps(header).encode()
            path.write_bytes(len(encoded).to_bytes(4, "big") + encoded + raw[4 + size:])
        elif change == "payload":
            path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        before_state = await actor_state(f)
        reads = []
        original_load = LocalStorageBackend.load

        async def traced_load(self, name):
            reads.append(name)
            return await original_load(self, name)

        monkeypatch.setattr(LocalStorageBackend, "load", traced_load)
        response = await invoke(f, backup.id, operation, headers=headers)
        after_state = await actor_state(f)
        async with AsyncSession(f.engine) as db:
            job_states = list((await db.scalars(
                select(RestoreJob.status).where(RestoreJob.backup_id == backup.id)
            )).all())
        stored_bytes = path.read_bytes()
        is_json = response.headers.get("content-type", "").startswith("application/json")
        body = response.json() if is_json else {}
        observed = {
            "HTTP_status": response.status_code, "storage_reads": len(reads),
            "core_actor_unchanged": before_state == after_state,
            "exact_original_download": response.content == raw,
            "exact_stored_download": response.content == stored_bytes,
            "durable_job_states": str(job_states),
            "restore_status": body.get("status"),
            "requires_passphrase": body.get("requires_passphrase"),
            "integrity_state": body.get("artifact_integrity"),
        }
        request.node.user_properties.extend(observed.items())
        if secrets and operation == "manifest":
            assert response.status_code == 200
            assert body["requires_passphrase"] is True and body["format_version"] is None
            assert body["contributors"] == [] and body["artifact_integrity"] == "recorded"
            assert not reads, "Metadata-only vault preview must not imply a verified file read"
        elif change == "unchanged":
            assert response.status_code == 200
            if operation == "download":
                assert response.content == raw
                assert response.headers["x-freesdn-artifact-integrity"] == "verified"
            elif operation == "restore":
                assert body["status"] == "completed" and job_states == ["completed"]
            else:
                assert body["contributors"] and body["artifact_integrity"] == "verified"
        elif operation == "restore":
            assert response.status_code == 400
            assert job_states == ["failed"]
        else:
            assert response.status_code in {400, 404, 409}
            assert response.content != path.read_bytes()
        assert before_state == after_state
        if operation != "restore":
            assert job_states == [], "Read-only archive routes must not create restore jobs"


MALFORMED = [None, "invalid", {}, {"version": 99}, {"version": True},
             {"version": 1, "sha256": "bad", "bytes": 7},
             {"version": 1, "sha256": "0" * 64, "bytes": True},
             {"version": 1, "sha256": "0" * 64, "bytes": -1},
             {"version": 1, "sha256": "0" * 64, "bytes": 0},
             {"version": 1, "sha256": "A" * 64, "bytes": 7}]


@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("malformed", MALFORMED)
async def test_malformed_identity_is_not_a_legacy_fallback(monkeypatch, tmp_path, request, secrets, malformed):
    async with owned_actor(monkeypatch, tmp_path) as f:
        backup, _path, raw = await create_archive(f, secrets)
        headers = await recorded_download_headers(f, backup.id, secrets)
        await set_identity(f, backup.id, malformed)
        reads = []
        original_load = LocalStorageBackend.load

        async def traced_load(self, name):
            reads.append(name)
            return await original_load(self, name)

        monkeypatch.setattr(LocalStorageBackend, "load", traced_load)
        response = await invoke(f, backup.id, "download", headers=headers)
        request.node.user_properties.extend([
            ("HTTP_status", response.status_code), ("storage_reads", len(reads)),
            ("returned_original_archive", response.content == raw),
        ])
        assert response.status_code in {400, 409}
        assert not reads and response.content != raw


@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("old_checksum", [None, "f" * 64])
async def test_legacy_checksum_is_never_silently_promoted(monkeypatch, tmp_path, request, secrets, old_checksum):
    async with owned_actor(monkeypatch, tmp_path) as f:
        backup, _path, raw = await create_archive(f, secrets)
        await set_identity(f, backup.id, None, legacy=True, checksum=old_checksum)
        response = (await acknowledged_legacy_download(f, backup.id) if secrets
                    else await invoke(f, backup.id, "download"))
        async with AsyncSession(f.engine) as db:
            after = await db.get(Backup, backup.id)
            unchanged = after.checksum == old_checksum and after.metadata_json == {}
        request.node.user_properties.extend([
            ("HTTP_status", response.status_code), ("exact_archive_returned", response.content == raw),
            ("historical_identity_unchanged", unchanged),
            ("integrity_header", response.headers.get("x-freesdn-artifact-integrity")),
        ])
        assert response.status_code == 200 and response.content == raw and unchanged
        assert response.headers["x-freesdn-artifact-integrity"] == "legacy_unverified"


@pytest.mark.parametrize("secrets", [False, True])
async def test_creation_does_not_complete_after_corrupted_storage_ack(monkeypatch, tmp_path, request, secrets):
    async with owned_actor(monkeypatch, tmp_path) as f:
        data = create_request(f, secrets)
        headers = {}
        if secrets:
            proof = await authorize_owned_vault(f, {"kind": "create", "backup": data})
            headers["X-FreeSDN-Vault-Proof"] = proof
        original_save = LocalStorageBackend.save

        async def corrupted_save(self, backup_id, data, filename):
            path = await original_save(self, backup_id, data, filename)
            (self.base_path / path).write_bytes(data + b"owned-corruption")
            return path

        monkeypatch.setattr(LocalStorageBackend, "save", corrupted_save)
        response = await f.client.post("/api/v1/backups/", json=data, headers=headers)
        async with AsyncSession(f.engine) as db:
            backups = list((await db.scalars(select(Backup).where(Backup.organization_id == f.org_id))).all())
            states = [b.status for b in backups]
        request.node.user_properties.extend([
            ("HTTP_status", response.status_code), ("catalogue_states", str(states)),
            ("stored_files", sum(p.is_file() for p in tmp_path.rglob("*"))),
        ])
        assert response.status_code in {400, 409, 500}
        assert states == ["failed"]
        assert backups[0].storage_path, "Failed write verification must retain its cleanup locator"
