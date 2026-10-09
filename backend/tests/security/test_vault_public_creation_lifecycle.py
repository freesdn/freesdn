"""Actual HTTP/factor/PG/local creation probes, not remote/native acceptance.

Confirmation routes are mounted explicitly in an owned application; startup/UI
registration remains separate. Production backup route code, collection,
encryption and local storage run unchanged except the proposed connection.
"""

import asyncio
import gzip
import hashlib
import hmac
import json
from contextlib import asynccontextmanager
from uuid import uuid4

import anyio
import httpx
import jwt
import pyotp
import pytest
from fastapi import FastAPI
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.backups import router as backups_router
from app.api.v1.endpoints.vault_export import (
    VaultConfirmationPolicy,
    create_vault_confirmation_router,
)
from app.core.config import get_settings
from app.core.security import get_password_hash
from app.core.security_utils import encrypt_field
from app.db.session import get_session
from app.main import app as product_app
from app.models.core import TokenRevocation, User
from app.modules.backup.models import Backup, StorageLocation
from app.services.backup import BackupEncryption, BackupService, LocalStorageBackend
from tests.security.test_vault_public_confirmation_contract import catalogue_count, owned_files
from tests.services.test_backup_artifact_integrity_contract import create_request, owned_actor


@asynccontextmanager
async def creation_actor(monkeypatch, tmp_path, credential):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        f.password = "Owned fresh creation!9-" + uuid4().hex
        f.password_hash = get_password_hash(f.password)
        f.claim_hashes = set()
        async with AsyncSession(f.engine) as db:
            await db.execute(update(User).where(User.id == f.actor_id).values(hashed_password=f.password_hash))
            await db.commit()

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False) as db:
                try:
                    yield db
                    await db.commit()
                except BaseException:
                    await db.rollback()
                    raise

        app = FastAPI(exception_handlers=product_app.exception_handlers)
        app.dependency_overrides[get_session] = request_session
        app.include_router(backups_router, prefix="/api/v1/backups")
        app.include_router(create_vault_confirmation_router(VaultConfirmationPolicy()), prefix="/owned/vault")
        original = f.client
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                         base_url="http://test", headers=original.headers) as client:
                f.client = client
                yield f
        finally:
            f.client = original
            async with AsyncSession(f.engine) as db:
                if f.claim_hashes:
                    await db.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash.in_(f.claim_hashes)))
                await db.commit()
            # Cached fixture callbacks must not retain completed request resources.
            f = None


async def proof_for(f, data, *, code=None):
    body = {"intent": {"kind": "create", "backup": data}, "password": f.password}
    if code is not None:
        body["mfa_code"] = code
    response = await f.client.post("/owned/vault/authorize/local", json=body)
    assert response.status_code == 200, response.text
    token = response.json()["proof"]
    authority_key = hmac.digest(get_settings().SECRET_KEY.encode(), b"FreeSDN/vault-authority/v1", "sha256")
    signing_key = hmac.digest(authority_key, b"FreeSDN/vault-export/final-signature/v2", "sha256")
    claims = jwt.decode(token, signing_key, algorithms=["HS256"], audience="freesdn-vault-export-v2", issuer="freesdn")
    f.claim_hashes.add(hashlib.sha256(claims["jti"].encode()).hexdigest())
    return token


async def rows(f):
    async with AsyncSession(f.engine) as db:
        return list((await db.scalars(select(Backup).where(Backup.organization_id == f.org_id))).all())


async def spent(f):
    async with AsyncSession(f.engine) as db:
        return set((await db.scalars(select(TokenRevocation.jti_hash).where(
            TokenRevocation.jti_hash.in_(f.claim_hashes)))).all()) == f.claim_hashes


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("mfa", [False, True])
async def test_real_confirmation_creates_decryptable_vault_and_cannot_replay(monkeypatch, tmp_path, request, credential, mfa):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        code = None
        if mfa:
            seed = pyotp.random_base32()
            async with AsyncSession(f.engine) as db:
                await db.execute(update(User).where(User.id == f.actor_id).values(
                    mfa_enabled=True, mfa_secret=encrypt_field(seed), mfa_last_totp_step=None))
                await db.commit()
            code = pyotp.TOTP(seed).now()
        data = create_request(f, True)
        token = await proof_for(f, data, code=code)
        response = await f.client.post("/api/v1/backups/", json=data, headers={"X-FreeSDN-Vault-Proof": token})
        actual = await rows(f)
        request.node.user_properties.extend([("HTTP_status", response.status_code), ("catalogue_rows", len(actual)), ("proof_spent", await spent(f))])
        assert response.status_code == 201, response.text
        assert len(actual) == 1 and actual[0].status == "completed" and await spent(f)
        raw = (f.root / actual[0].storage_path).read_bytes()
        size = int.from_bytes(raw[:4], "big")
        header = json.loads(raw[4:4 + size])
        payload = BackupEncryption(master_key=f.phrase).decrypt(raw[4 + size:], header["key_id"])
        decoded = gzip.decompress(payload).decode()
        assert f.password_hash in decoded and str(f.actor_id) in decoded
        assert header["encrypted"] and header["secrets"]
        assert actual[0].metadata_json["artifact_identity"] == {"version": 1, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        first_files = owned_files(f)
        replay = await f.client.post("/api/v1/backups/", json=data, headers={"X-FreeSDN-Vault-Proof": token})
        assert replay.status_code == 401 and await catalogue_count(f) == 1 and owned_files(f) == first_files
        request.node.user_properties.extend([("decrypted_own_account", True), ("exact_whole_file_identity", True), ("replay_status", replay.status_code)])


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("change", ["missing", "malformed", "duplicate", "oversize", "empty", "query-only"])
async def test_invalid_proof_has_no_collection_catalogue_or_files(monkeypatch, tmp_path, request, credential, change):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        data = create_request(f, True)
        token = await proof_for(f, data)
        headers = [("X-FreeSDN-Vault-Proof", token)]
        url = "/api/v1/backups/"
        if change == "missing":
            headers = []
        elif change == "malformed":
            headers = [(headers[0][0], "not-a-proof")]
        elif change == "duplicate":
            headers += headers
        elif change == "oversize":
            headers = [(headers[0][0], "x" * 8193)]
        elif change == "empty":
            headers = [(headers[0][0], "")]
        else:
            headers = []
            url += "?proof=not-a-proof"
        calls = []
        original = BackupService._assemble_backup_archive

        async def observe(self, **kwargs):
            calls.append(True)
            return await original(self, **kwargs)

        monkeypatch.setattr(BackupService, "_assemble_backup_archive", observe)
        response = await f.client.post(url, json=data, headers=headers)
        properties = {"HTTP_status": response.status_code, "collection_calls": len(calls), "catalogue_rows": await catalogue_count(f), "files": len(owned_files(f))}
        request.node.user_properties.extend(properties.items())
        assert properties == {"HTTP_status": 401, "collection_calls": 0, "catalogue_rows": 0, "files": 0}
        assert token not in response.text and f.phrase not in response.text


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("change", ["name", "passphrase", "retention", "destination", "actor", "organization"])
async def test_confirmed_input_and_browser_context_cannot_change(monkeypatch, tmp_path, request, credential, change):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        data = create_request(f, True)
        token = await proof_for(f, data)
        headers = {"X-FreeSDN-Vault-Proof": token}
        expected = 401
        if change == "name":
            data["name"] += " changed"
        elif change == "passphrase":
            data["passphrase"] += " changed"
        elif change == "retention":
            data["retention_days"] = 31
        elif change == "destination":
            async with AsyncSession(f.engine) as db:
                await db.execute(update(StorageLocation).where(StorageLocation.id == f.storage_id).values(config={"path": str(tmp_path / "changed")}))
                await db.commit()
        else:
            headers.update({"X-FreeSDN-Vault-Actor": str(f.actor_id), "X-FreeSDN-Vault-Organization": str(f.org_id)})
            headers["X-FreeSDN-Vault-Actor" if change == "actor" else "X-FreeSDN-Vault-Organization"] = str(uuid4())
            expected = 409
        response = await f.client.post("/api/v1/backups/", json=data, headers=headers)
        properties = {"HTTP_status": response.status_code, "catalogue_rows": await catalogue_count(f), "files": len(owned_files(f))}
        request.node.user_properties.extend(properties.items())
        assert properties == {"HTTP_status": expected, "catalogue_rows": 0, "files": 0}


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("phase", ["collect", "save", "load", "commit"])
async def test_revocation_after_actual_work_refuses_and_preserves_acknowledged_locator(monkeypatch, tmp_path, request, credential, phase):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        data = create_request(f, True)
        token = await proof_for(f, data)
        reached, proceed = asyncio.Event(), asyncio.Event()
        paused = False
        target, method = {"collect": (BackupService, "_assemble_backup_archive"),
                          "save": (LocalStorageBackend, "save"), "load": (LocalStorageBackend, "load"),
                          "commit": (AsyncSession, "commit")}[phase]
        original = getattr(target, method)

        async def observe(self, *args, **kwargs):
            nonlocal paused
            relevant = phase != "commit" or any(isinstance(o, Backup) and o.organization_id == f.org_id and o.status == "completed" for o in self.dirty)
            value = await original(self, *args, **kwargs)
            if relevant and not paused:
                paused = True
                reached.set()
                async with asyncio.timeout(10):
                    await proceed.wait()
            return value

        monkeypatch.setattr(target, method, observe)
        task = asyncio.create_task(f.client.post("/api/v1/backups/", json=data, headers={"X-FreeSDN-Vault-Proof": token}))
        try:
            async with asyncio.timeout(10):
                await reached.wait()
            assert not task.done()
            async with AsyncSession(f.engine) as db:
                await db.execute(update(User).where(User.id == f.actor_id).values(is_active=False))
                await db.commit()
        finally:
            proceed.set()
            response = await task
        actual = await rows(f)
        files = owned_files(f)
        props = {"HTTP_status": response.status_code, "catalogue_rows": len(actual), "catalogue_status": actual[0].status if actual else None,
                 "files": len(files), "acknowledged_locator": bool(actual and actual[0].storage_path), "proof_spent": await spent(f), "actual_work_pause": paused}
        request.node.user_properties.extend(props.items())
        assert response.status_code == 401, response.text
        assert len(actual) == 1 and actual[0].status == "failed" and await spent(f)
        if phase == "collect":
            assert not files and not actual[0].storage_path
        else:
            assert len(files) == 1 and actual[0].storage_path in files
            assert actual[0].file_size == (f.root / actual[0].storage_path).stat().st_size


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("mode", ["asyncio", "anyio"])
async def test_cancellation_after_actual_save_drains_catalogue_and_spends_proof(monkeypatch, tmp_path, request, credential, mode):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        data = create_request(f, True)
        token = await proof_for(f, data)
        reached, proceed = asyncio.Event(), asyncio.Event()
        original = LocalStorageBackend.save
        scopes, delivered = [], []

        async def observed_save(self, *args, **kwargs):
            value = await original(self, *args, **kwargs)
            reached.set()
            async with asyncio.timeout(10):
                await proceed.wait()
            return value

        monkeypatch.setattr(LocalStorageBackend, "save", observed_save)

        async def invoke():
            with anyio.CancelScope() as scope:
                scopes.append(scope)
                delivered.append(await f.client.post("/api/v1/backups/", json=data, headers={"X-FreeSDN-Vault-Proof": token}))

        task = asyncio.create_task(invoke())
        try:
            async with asyncio.timeout(10):
                await reached.wait()
            if mode == "asyncio":
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
            else:
                scopes[0].cancel()
            await asyncio.sleep(0)
            assert not task.done()
        finally:
            proceed.set()
            try:
                await task
            except asyncio.CancelledError:
                assert mode == "asyncio"
        actual = await rows(f)
        files = owned_files(f)
        request.node.user_properties.extend([("delivered_responses", len(delivered)), ("catalogue_rows", len(actual)),
                                            ("catalogue_status", actual[0].status if actual else None), ("files", len(files)), ("proof_spent", await spent(f))])
        assert not delivered and len(actual) == 1 and actual[0].status == "completed"
        assert len(files) == 1 and actual[0].storage_path in files and await spent(f)
        assert actual[0].file_size == (f.root / actual[0].storage_path).stat().st_size
