"""Real public-route/PG/factor/local-file tests; no remote or UI acceptance.

Creation uses actual fresh confirmation and encryption. Confirmation factory
registration is explicit in the owned app; full application startup is separate.
"""

import asyncio
import hashlib
import hmac
from uuid import uuid4

import jwt
import pyotp
import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security_utils import encrypt_field
from app.models.api_keys import APIKey
from app.models.core import User
from app.modules.backup.models import Backup, StorageLocation
from app.services.vault_export_download import VaultArchiveResponse
from app.services.vault_snapshot_response import LocalDownloadSource
from tests.security.test_vault_public_creation_lifecycle import (
    creation_actor,
    proof_for,
    rows,
    spent,
)
from tests.services.test_backup_artifact_integrity_contract import (
    create_request,
    identity,
    set_identity,
)


def remember(f, token):
    authority = hmac.digest(get_settings().SECRET_KEY.encode(), b"FreeSDN/vault-authority/v1", "sha256")
    signing = hmac.digest(authority, b"FreeSDN/vault-export/final-signature/v2", "sha256")
    claims = jwt.decode(token, signing, algorithms=["HS256"], audience="freesdn-vault-export-v2", issuer="freesdn")
    f.claim_hashes.add(hashlib.sha256(claims["jti"].encode()).hexdigest())
    return claims


async def actual_archive(f):
    data = create_request(f, True)
    token = await proof_for(f, data)
    response = await f.client.post("/api/v1/backups/", json=data, headers={"X-FreeSDN-Vault-Proof": token})
    assert response.status_code == 201, response.text
    items = await rows(f)
    assert len(items) == 1 and items[0].status == "completed"
    path = f.root / items[0].storage_path
    return items[0], path, path.read_bytes()


async def download_proof(f, backup_id, *, legacy=False, code=None):
    intent = {"kind": "observe_legacy" if legacy else "download_recorded", "backup_id": str(backup_id)}
    if legacy:
        intent["legacy_acknowledged"] = True
    data = {"intent": intent, "password": f.password}
    if code is not None:
        data["mfa_code"] = code
    response = await f.client.post("/owned/vault/authorize/local", json=data)
    assert response.status_code == 200, response.text
    token = response.json()["proof"]
    return token, remember(f, token)


def copies_observer(monkeypatch):
    calls = []
    original = LocalDownloadSource.copy_into

    def observe(source, snapshot):
        calls.append(True)
        return original(source, snapshot)

    monkeypatch.setattr(LocalDownloadSource, "copy_into", observe)
    return calls


async def observation(f, backup_id, token):
    response = await f.client.post(f"/api/v1/backups/{backup_id}/vault-observation",
                                 json={"legacy_acknowledged": True}, headers={"X-FreeSDN-Vault-Proof": token})
    assert response.status_code == 200, response.text
    value = response.json()
    claims = remember(f, value["proof"])
    return response, value, claims


async def legacy_download(f, backup_id, value):
    return await f.client.post(f"/api/v1/backups/{backup_id}/vault-download", json={
        "legacy_acknowledged": True, "observed_identity": value["observed_identity"],
    }, headers={"X-FreeSDN-Vault-Proof": value["proof"]})


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("mfa", [False, True])
async def test_recorded_public_download_consumes_real_confirmation(monkeypatch, tmp_path, request, credential, mfa):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await actual_archive(f)
        code = None
        if mfa:
            seed = pyotp.random_base32()
            async with AsyncSession(f.engine) as db:
                await db.execute(update(User).where(User.id == f.actor_id).values(
                    mfa_enabled=True, mfa_secret=encrypt_field(seed), mfa_last_totp_step=None))
                await db.commit()
            code = pyotp.TOTP(seed).now()
        token, _claims = await download_proof(f, backup.id, code=code)
        copies = copies_observer(monkeypatch)
        response = await f.client.get(f"/api/v1/backups/{backup.id}/download", headers={"X-FreeSDN-Vault-Proof": token})
        replay = await f.client.get(f"/api/v1/backups/{backup.id}/download", headers={"X-FreeSDN-Vault-Proof": token})
        props = {"status": response.status_code, "exact_encrypted_bytes": response.content == raw,
                 "integrity": response.headers.get("x-freesdn-artifact-integrity"), "replay": replay.status_code,
                 "copies": len(copies), "all_proofs_spent": await spent(f)}
        request.node.user_properties.extend(props.items())
        assert props == {"status": 200, "exact_encrypted_bytes": True, "integrity": "verified", "replay": 401,
                         "copies": 1, "all_proofs_spent": True}
        assert response.headers["cache-control"] == "no-store"
        assert "attachment;" in response.headers["content-disposition"]
        assert token.encode() not in response.content


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("change", ["missing", "malformed", "duplicate", "oversize", "empty", "query-only"])
async def test_invalid_download_proof_refuses_before_storage(monkeypatch, tmp_path, request, credential, change):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await actual_archive(f)
        token, _claims = await download_proof(f, backup.id)
        headers = [("X-FreeSDN-Vault-Proof", token)]
        url = f"/api/v1/backups/{backup.id}/download"
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
        copies = copies_observer(monkeypatch)
        response = await f.client.get(url, headers=headers)
        request.node.user_properties.extend([("status", response.status_code), ("copies", len(copies)),
                                             ("archive_returned", response.content == raw)])
        assert response.status_code == 401 and not copies and response.content != raw
        assert token not in response.text and f.phrase not in response.text


@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_legacy_public_flow_is_exact_nonrenewing_and_historically_unverified(monkeypatch, tmp_path, request, credential):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await actual_archive(f)
        checksum = "historical-ambiguous-" + uuid4().hex
        await set_identity(f, backup.id, None, legacy=True, checksum=checksum)
        token, original = await download_proof(f, backup.id, legacy=True)
        copies = copies_observer(monkeypatch)
        seen, value, final = await observation(f, backup.id, token)
        replay_observe = await f.client.post(f"/api/v1/backups/{backup.id}/vault-observation",
                                             json={"legacy_acknowledged": True}, headers={"X-FreeSDN-Vault-Proof": token})
        response = await legacy_download(f, backup.id, value)
        replay_download = await legacy_download(f, backup.id, value)
        async with AsyncSession(f.engine) as db:
            current = await db.get(Backup, backup.id)
            unchanged = current.metadata_json == {} and current.checksum == checksum
        props = {"exact_encrypted_bytes": response.content == raw, "status": response.status_code,
                 "integrity": response.headers.get("x-freesdn-artifact-integrity"), "copies": len(copies),
                 "observation_replay": replay_observe.status_code, "download_replay": replay_download.status_code,
                 "all_proofs_spent": await spent(f), "legacy_metadata_unchanged": unchanged,
                 "original_auth_time": original["auth_time"] == final["auth_time"],
                 "no_freshness_extension": final["exp"] <= original["exp"] and final["auth_exp"] <= original["auth_exp"]}
        request.node.user_properties.extend(props.items())
        assert props == {"exact_encrypted_bytes": True, "status": 200, "integrity": "legacy_unverified", "copies": 2,
                         "observation_replay": 401, "download_replay": 401, "all_proofs_spent": True,
                         "legacy_metadata_unchanged": True, "original_auth_time": True, "no_freshness_extension": True}
        assert value["observed_identity"] == identity(raw)
        assert value["artifact_integrity"] == "legacy_unverified" and value["operation"] == "download_legacy"
        assert value["authentication_expires_at"] <= original["exp"]
        assert "content-disposition" not in seen.headers
        assert seen.headers["cache-control"] == response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_legacy_get_refuses_even_valid_observation_proof(monkeypatch, tmp_path, request, credential):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await actual_archive(f)
        await set_identity(f, backup.id, None, legacy=True)
        token, _claims = await download_proof(f, backup.id, legacy=True)
        copies = copies_observer(monkeypatch)
        response = await f.client.get(f"/api/v1/backups/{backup.id}/download", headers={"X-FreeSDN-Vault-Proof": token})
        request.node.user_properties.extend([("status", response.status_code), ("copies", len(copies))])
        assert response.status_code == 409 and not copies and response.content != raw


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("raw,media,encoding,status", [
    ('{}', "application/json", None, 422),
    ('{"legacy_acknowledged":false}', "application/json", None, 422),
    ('{"legacy_acknowledged":1}', "application/json", None, 422),
    ('{"legacy_acknowledged":true,"extra":true}', "application/json", None, 422),
    ('{"legacy_acknowledged":true,"legacy_acknowledged":true}', "application/json", None, 422),
    ('{"legacy_acknowledged":NaN}', "application/json", None, 422),
    ('[]', "application/json", None, 422),
    (' ' * 2049, "application/json", None, 413),
    ('{"legacy_acknowledged":true}', "text/plain", None, 415),
    ('{"legacy_acknowledged":true}', "application/json", "gzip", 415),
], ids=["missing", "false", "numeric", "extra", "duplicate", "nonfinite", "list", "oversize", "media", "encoding"])
async def test_legacy_commands_bound_and_validate_before_storage(monkeypatch, tmp_path, request, credential, raw, media, encoding, status):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, archive = await actual_archive(f)
        await set_identity(f, backup.id, None, legacy=True)
        token, _claims = await download_proof(f, backup.id, legacy=True)
        headers = {"X-FreeSDN-Vault-Proof": token, "Content-Type": media}
        if encoding:
            headers["Content-Encoding"] = encoding
        copies = copies_observer(monkeypatch)
        response = await f.client.post(f"/api/v1/backups/{backup.id}/vault-observation", content=raw, headers=headers)
        request.node.user_properties.extend([("status", response.status_code), ("copies", len(copies))])
        assert response.status_code == status and not copies and response.content != archive
        assert token not in response.text and f.phrase not in response.text


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("change,status,reads", [
    ("role", 403, 0), ("storage", 401, 0), ("identity", 401, 0),
    ("symlink", 500, 1), ("tamper", 409, 1), ("missing", 500, 1),
])
async def test_changed_public_authority_or_archive_never_delivers(monkeypatch, tmp_path, request, credential, change, status, reads):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, path, raw = await actual_archive(f)
        token, _claims = await download_proof(f, backup.id)
        if change in {"role", "storage", "identity"}:
            async with AsyncSession(f.engine) as db:
                if change == "role":
                    await db.execute(update(User).where(User.id == f.actor_id).values(role="viewer"))
                elif change == "storage":
                    await db.execute(update(StorageLocation).where(StorageLocation.id == f.storage_id).values(config={"path": str(f.root / "other")}))
                else:
                    await db.execute(update(Backup).where(Backup.id == backup.id).values(metadata_json={"artifact_identity": {**identity(raw), "sha256": "b" * 64}}))
                await db.commit()
        elif change == "symlink":
            other = f.root / "other.fsdnvault"
            other.write_bytes(raw)
            path.unlink()
            path.symlink_to(other)
        elif change == "tamper":
            path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        else:
            path.unlink()
        copies = copies_observer(monkeypatch)
        response = await f.client.get(f"/api/v1/backups/{backup.id}/download", headers={"X-FreeSDN-Vault-Proof": token})
        request.node.user_properties.extend([("status", response.status_code), ("copies", len(copies)), ("archive_returned", response.content == raw)])
        assert response.status_code == status and len(copies) == reads and response.content != raw
        assert token not in response.text and f.phrase not in response.text


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("change", ["disable", "credential", "destination", "identity"])
async def test_after_actual_file_read_changes_refuse_before_headers(monkeypatch, tmp_path, request, credential, change):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await actual_archive(f)
        token, _claims = await download_proof(f, backup.id)
        reached, proceed = asyncio.Event(), asyncio.Event()
        original = VaultArchiveResponse._copy_local

        async def wait_after(source, snapshot):
            await original(source, snapshot)
            reached.set()
            async with asyncio.timeout(10):
                await proceed.wait()

        monkeypatch.setattr(VaultArchiveResponse, "_copy_local", staticmethod(wait_after))
        task = asyncio.create_task(f.client.get(f"/api/v1/backups/{backup.id}/download", headers={"X-FreeSDN-Vault-Proof": token}))
        try:
            async with asyncio.timeout(10):
                await reached.wait()
            assert not task.done()
            async with AsyncSession(f.engine) as db:
                if change == "disable":
                    await db.execute(update(User).where(User.id == f.actor_id).values(is_active=False))
                elif change == "credential":
                    if credential == "jwt":
                        await db.execute(update(User).where(User.id == f.actor_id).values(token_version=18))
                    else:
                        await db.execute(update(APIKey).where(APIKey.user_id == f.actor_id).values(is_active=False))
                elif change == "destination":
                    await db.execute(update(StorageLocation).where(StorageLocation.id == f.storage_id).values(config={"path": str(f.root / "other")}))
                else:
                    await db.execute(update(Backup).where(Backup.id == backup.id).values(metadata_json={"artifact_identity": {**identity(raw), "sha256": "b" * 64}}))
                await db.commit()
        finally:
            proceed.set()
            response = await task
        props = {"status": response.status_code, "actual_read_wait": reached.is_set(), "archive_returned": response.content == raw,
                 "all_proofs_spent": await spent(f), "attachment_header": "content-disposition" in response.headers}
        request.node.user_properties.extend(props.items())
        assert response.status_code in {401, 403, 409} and reached.is_set() and response.content != raw
        assert props["all_proofs_spent"] and not props["attachment_header"]


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("change", ["actor", "organization"])
async def test_download_rejects_queued_browser_context_change(monkeypatch, tmp_path, request, credential, change):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await actual_archive(f)
        token, _claims = await download_proof(f, backup.id)
        headers = {"X-FreeSDN-Vault-Proof": token, "X-FreeSDN-Vault-Actor": str(f.actor_id), "X-FreeSDN-Vault-Organization": str(f.org_id)}
        headers["X-FreeSDN-Vault-Actor" if change == "actor" else "X-FreeSDN-Vault-Organization"] = str(uuid4())
        copies = copies_observer(monkeypatch)
        response = await f.client.get(f"/api/v1/backups/{backup.id}/download", headers=headers)
        request.node.user_properties.extend([("status", response.status_code), ("copies", len(copies))])
        assert response.status_code == 409 and not copies and response.content != raw


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("change", ["file", "observation"])
async def test_legacy_final_download_binds_the_observed_bytes(monkeypatch, tmp_path, request, credential, change):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, path, raw = await actual_archive(f)
        await set_identity(f, backup.id, None, legacy=True)
        token, _claims = await download_proof(f, backup.id, legacy=True)
        _response, value, _claims = await observation(f, backup.id, token)
        if change == "file":
            path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        else:
            value["observed_identity"]["sha256"] = "b" * 64
        copies = copies_observer(monkeypatch)
        response = await legacy_download(f, backup.id, value)
        request.node.user_properties.extend([("status", response.status_code), ("copies", len(copies)), ("archive_returned", response.content == raw)])
        assert response.status_code == (409 if change == "file" else 401)
        assert len(copies) == (1 if change == "file" else 0) and response.content != raw


@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_concurrent_public_download_proof_has_one_real_claim_winner(monkeypatch, tmp_path, request, credential):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await actual_archive(f)
        token, _claims = await download_proof(f, backup.id)
        copies = copies_observer(monkeypatch)
        responses = await asyncio.gather(*[f.client.get(f"/api/v1/backups/{backup.id}/download", headers={"X-FreeSDN-Vault-Proof": token}) for _ in range(2)])
        statuses = sorted(r.status_code for r in responses)
        props = {"statuses": statuses, "copies": len(copies), "exact_deliveries": sum(r.content == raw for r in responses), "all_proofs_spent": await spent(f)}
        request.node.user_properties.extend(props.items())
        assert props == {"statuses": [200, 401], "copies": 1, "exact_deliveries": 1, "all_proofs_spent": True}


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("operation", ["creation", "recorded-on-legacy", "observation-as-final"])
async def test_other_export_purposes_do_not_authorize_download(monkeypatch, tmp_path, request, credential, operation):
    async with creation_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await actual_archive(f)
        if operation == "creation":
            token = await proof_for(f, create_request(f, True))
        else:
            if operation == "observation-as-final":
                await set_identity(f, backup.id, None, legacy=True)
            token, _claims = await download_proof(f, backup.id, legacy=operation == "observation-as-final")
        copies = copies_observer(monkeypatch)
        if operation == "creation":
            response = await f.client.get(f"/api/v1/backups/{backup.id}/download", headers={"X-FreeSDN-Vault-Proof": token})
        elif operation == "recorded-on-legacy":
            response = await f.client.post(f"/api/v1/backups/{backup.id}/vault-observation", json={"legacy_acknowledged": True}, headers={"X-FreeSDN-Vault-Proof": token})
        else:
            response = await legacy_download(f, backup.id, {"proof": token, "observed_identity": identity(raw)})
        request.node.user_properties.extend([("status", response.status_code), ("copies", len(copies))])
        assert response.status_code == (409 if operation == "recorded-on-legacy" else 401)
        assert not copies and response.content != raw
