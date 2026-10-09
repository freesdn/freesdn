"""Owned real SQL/auth/proof/file response flow; no public endpoint or hardware."""

import hashlib
import json

import anyio
import jwt
import pyotp
import pytest
import pytest_asyncio
from fastapi import Depends, Request
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.vault_export import (
    VaultConfirmationPolicy,
    create_vault_confirmation_router,
)
from app.core.backup_downloads import DownloadPool
from app.core.config import get_settings
from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.security_utils import encrypt_field
from app.modules.backup.models import Backup, StorageLocation
from app.services.vault_export_authority import VaultExportAuthority
from app.services.vault_export_download import VaultArchiveResponse
from app.services.vault_export_operation_state import ExportIntent
from tests.security.test_vault_export_authority import credentials, mutate
from tests.security.test_vault_export_authority import owned_export as owned_export
from tests.security.test_vault_export_operation_state import operations as operations


def remember_proof(f, token):
    # Decode only for precise test-owned row cleanup, never authorization.
    claims = jwt.decode(token, options={"verify_signature": False})
    f.token_hashes.add(hashlib.sha256(claims["jti"].encode()).hexdigest())


@pytest_asyncio.fixture
async def local_archive(operations, tmp_path):
    f = operations
    f.root = tmp_path / "owned-archives"
    f.root.mkdir(mode=0o700)
    f.payload = b"Owned opaque encrypted-archive test bytes\x00" * 128
    f.path = "owned.fsdnvault"
    f.file = f.root / f.path
    f.file.write_bytes(f.payload)
    f.file.chmod(0o600)
    f.observed = {"version": 1, "bytes": len(f.payload), "sha256": hashlib.sha256(f.payload).hexdigest()}
    f.pool = DownloadPool(tmp_path / "owned-spool", slots=1, limit=2 * 1024**2, free_floor=0)
    f.responses = []
    f.copies = []
    async with AsyncSession(f.engine) as db:
        await db.execute(update(StorageLocation).where(StorageLocation.id == f.location).values(
            storage_type="local", config={"path": str(f.root)}))
        await db.execute(update(Backup).where(Backup.id == f.backup).values(
            storage_type="local", storage_path=f.path, metadata_json={"artifact_identity": f.observed}))
        await db.commit()
    app = f.client._transport.app
    app.include_router(create_vault_confirmation_router(VaultConfirmationPolicy()), prefix="/owned/vault")

    class ObservedResponse(VaultArchiveResponse):
        async def _copy(self, snapshot):
            f.copies.append(True)
            await super()._copy(snapshot)

    @app.post("/owned/archive")
    async def archive(request: Request, user: CurrentUser = Depends(get_current_active_user)):
        body = await request.json()
        authority = await VaultExportAuthority.capture(
            request, user, action="download", secret_key=get_settings().SECRET_KEY.encode())
        intent = ExportIntent.download(
            f.backup, operation=body["operation"],
            legacy_acknowledged=body["operation"] != "download_recorded",
            observed_identity=body.get("observed_identity"))
        response = ObservedResponse(authority, intent, body["proof"], f.pool)
        f.responses.append(response)
        return response

    yield f
    assert all(response.snapshot is None or response.snapshot._fd < 0 for response in f.responses)
    slot = await anyio.to_thread.run_sync(f.pool.acquire)
    slot.close()
    # Cached fixture callbacks must not retain completed request resources.
    f = None


async def authorize(f, headers, *, legacy=False, code=None):
    intent = {"kind": "observe_legacy" if legacy else "download_recorded", "backup_id": str(f.backup)}
    if legacy:
        intent["legacy_acknowledged"] = True
    body = {"intent": intent, "password": f.password}
    if code is not None:
        body["mfa_code"] = code
    response = await f.client.post("/owned/vault/authorize/local", headers=headers, json=body)
    assert response.status_code == 200, response.text
    proof = response.json()["proof"]
    remember_proof(f, proof)
    return proof


async def transfer(f, headers, proof, operation="download_recorded", observed=None):
    body = {"proof": proof, "operation": operation}
    if observed is not None:
        body["observed_identity"] = observed
    return await f.client.post("/owned/archive", headers=headers, json=body)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("factor", ["password", "totp", "recovery"])
async def test_real_confirmation_claim_and_recorded_file_delivery(local_archive, kind, factor):
    f = local_archive
    code = None
    if factor != "password":
        await mutate(f, {"mfa_enabled": True, "mfa_secret": encrypt_field(f.seed),
                         "mfa_backup_codes": json.dumps([f.recovery_hash]), "mfa_last_totp_step": None})
        code = pyotp.TOTP(f.seed).now() if factor == "totp" else f.recovery
    headers, _ = credentials(f, kind)
    proof = await authorize(f, headers, code=code)
    response = await transfer(f, headers, proof)
    assert response.status_code == 200, response.text
    assert response.content == f.payload
    assert response.headers["x-freesdn-artifact-integrity"] == "verified"
    assert response.headers["cache-control"] == "no-store"
    assert f.copies == [True]
    again = await transfer(f, headers, proof)
    assert again.status_code == 401, again.text
    assert f.copies == [True]


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("change,status,reads", [
    ("role", 403, 0), ("storage", 401, 0), ("identity", 401, 0),
    ("symlink", 500, 1), ("tamper", 409, 1), ("missing", 500, 1),
])
async def test_changed_authority_destination_or_file_never_delivers(local_archive, kind, change, status, reads):
    f = local_archive
    headers, _ = credentials(f, kind)
    proof = await authorize(f, headers)
    if change == "role":
        await mutate(f, {"role": "viewer"})
    elif change in {"storage", "identity"}:
        async with AsyncSession(f.engine) as db:
            if change == "storage":
                await db.execute(update(StorageLocation).where(StorageLocation.id == f.location)
                                 .values(config={"path": str(f.root / "different")}))
            else:
                altered = {**f.observed, "sha256": "b" * 64}
                await db.execute(update(Backup).where(Backup.id == f.backup)
                                 .values(metadata_json={"artifact_identity": altered}))
            await db.commit()
    elif change == "symlink":
        other = f.root / "other.fsdnvault"
        other.write_bytes(f.payload)
        other.chmod(0o600)
        f.file.unlink()
        f.file.symlink_to(other)
    elif change == "tamper":
        f.file.write_bytes(b"X" * len(f.payload))
    else:
        f.file.unlink()
    response = await transfer(f, headers, proof)
    assert response.status_code == status, response.text
    assert response.content != f.payload and b"Owned opaque" not in response.content
    assert len(f.copies) == reads
    assert str(f.root) not in response.text and proof not in response.text


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("change_after_observation", [False, True])
async def test_legacy_observation_exchange_keeps_identity_and_consumption(local_archive, kind, change_after_observation):
    f = local_archive
    async with AsyncSession(f.engine) as db:
        await db.execute(update(Backup).where(Backup.id == f.backup).values(metadata_json={}))
        await db.commit()
    headers, _ = credentials(f, kind)
    proof = await authorize(f, headers, legacy=True)
    observed = await transfer(f, headers, proof, "observe_legacy")
    assert observed.status_code == 200, observed.text
    data = observed.json()
    assert data["artifact_integrity"] == "legacy_unverified"
    assert data["observed_identity"] == f.observed
    assert f.copies == [True]
    remember_proof(f, data["proof"])
    again = await transfer(f, headers, proof, "observe_legacy")
    assert again.status_code == 401, again.text
    assert f.copies == [True]
    if change_after_observation:
        f.file.write_bytes(b"Y" * len(f.payload))
    delivered = await transfer(f, headers, data["proof"], "download_legacy", data["observed_identity"])
    assert delivered.status_code == (409 if change_after_observation else 200), delivered.text
    if change_after_observation:
        assert delivered.content != f.payload
    else:
        assert delivered.content == f.payload
        assert delivered.headers["x-freesdn-artifact-integrity"] == "legacy_unverified"
    assert f.copies == [True, True]
    replay = await transfer(f, headers, data["proof"], "download_legacy", data["observed_identity"])
    assert replay.status_code == 401, replay.text
    assert f.copies == [True, True]
