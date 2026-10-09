"""Proposed public fresh-export boundary; private and not runtime-qualified.

Real request authentication and owned SQL/catalogue/local files are intended.
The seeded download file is opaque fixture data, not an encryption or restore
claim. Configuration snapshots remain outside the fresh-vault proof policy.
"""

import hashlib
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_download_response import LocalDownloadSource
from app.modules.backup.models import Backup
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    create_request,
    owned_actor,
)


async def seed_opaque_vault(f):
    """Prepare a recorded owned artifact without using the route under test."""
    backup_id = uuid4()
    raw = b"Owned opaque vault-boundary bytes\x00" * 128
    path = f.root / f"{backup_id}.fsdnvault"
    path.write_bytes(raw)
    path.chmod(0o600)
    identity = {"version": 1, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    async with AsyncSession(f.engine) as db:
        db.add(Backup(id=backup_id, name="Owned public vault boundary", status="completed",
                      organization_id=f.org_id, created_by_id=f.actor_id,
                      storage_location_id=f.storage_id, storage_type="local",
                      storage_path=path.name, file_size=len(raw), include_secrets=True,
                      is_encrypted=True, metadata_json={"artifact_identity": identity}))
        await db.commit()
    return backup_id, raw


async def catalogue_count(f):
    async with AsyncSession(f.engine) as db:
        return await db.scalar(select(func.count()).select_from(Backup).where(
            Backup.organization_id == f.org_id))


def owned_files(f):
    return {str(p.relative_to(f.root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in f.root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("proof", ["missing", "malformed"])
@pytest.mark.parametrize("operation", ["create", "download"])
async def test_public_vault_requires_purpose_bound_fresh_permission(
    monkeypatch, tmp_path, request, credential, proof, operation,
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        backup_id, raw = await seed_opaque_vault(f) if operation == "download" else (None, b"")
        before_count, before_files = await catalogue_count(f), owned_files(f)
        copies = []
        original = LocalDownloadSource.copy_into

        def observe_copy(source, snapshot):
            copies.append(True)
            return original(source, snapshot)

        monkeypatch.setattr(LocalDownloadSource, "copy_into", observe_copy)
        headers = {"X-FreeSDN-Vault-Proof": "not-a-signed-vault-proof"} if proof == "malformed" else {}
        if operation == "create":
            response = await f.client.post("/api/v1/backups/", json=create_request(f, True), headers=headers)
        else:
            response = await f.client.get(f"/api/v1/backups/{backup_id}/download", headers=headers)
        observed = {
            "HTTP_status": response.status_code,
            "catalogue_count_before": before_count,
            "catalogue_count_after": await catalogue_count(f),
            "owned_files_unchanged": before_files == owned_files(f),
            "snapshot_copy_calls": len(copies),
            "opaque_archive_returned": bool(raw) and response.content == raw,
        }
        request.node.user_properties.extend(observed.items())
        # All durable/read observations are recorded BEFORE the contract asserts.
        assert response.status_code == 401
        assert observed["catalogue_count_after"] == before_count
        assert observed["owned_files_unchanged"] and not copies
        assert not observed["opaque_archive_returned"]


@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_configuration_snapshot_still_creates_and_downloads_without_vault_proof(
    monkeypatch, tmp_path, request, credential,
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await create_archive(f, False)
        response = await f.client.get(f"/api/v1/backups/{backup.id}/download")
        request.node.user_properties.extend([
            ("HTTP_status", response.status_code), ("exact_archive", response.content == raw),
            ("integrity", response.headers.get("x-freesdn-artifact-integrity")),
        ])
        assert response.status_code == 200
        assert response.content == raw
        assert response.headers["x-freesdn-artifact-integrity"] == "verified"


def test_owned_file_observation_detects_nested_publication(tmp_path):
    from types import SimpleNamespace

    f = SimpleNamespace(root=tmp_path)
    before = owned_files(f)
    nested = tmp_path / "owned-backup-id"
    nested.mkdir()
    target = nested / "owned.fsdnvault"
    target.write_bytes(b"Owned first archive")
    first = owned_files(f)
    target.write_bytes(b"Owned changed archive")
    second = owned_files(f)
    assert before == {}
    assert first != before and second != first
    assert set(first) == set(second) == {"owned-backup-id/owned.fsdnvault"}
