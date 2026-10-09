# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unfrozen actual HTTP/DB/local-write uncertainty probes; no runtime claim."""

import errno
import os
import stat
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.backup.models import Backup, StorageLocation
from tests.services.test_backup_artifact_integrity_contract import (
    authorize_owned_vault,
    create_request,
    owned_actor,
)


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_uncertain_directory_sync_keeps_failed_catalog_locator_without_identity(
    monkeypatch, tmp_path, request, credential, secrets,
):
    async with owned_actor(monkeypatch, tmp_path, credential) as fixture:
        data = create_request(fixture, secrets)
        headers = {}
        if secrets:
            proof = await authorize_owned_vault(fixture, {"kind": "create", "backup": data})
            headers["X-FreeSDN-Vault-Proof"] = proof
        real_sync = os.fsync
        synced_file = []
        failed_publication = []

        def sync(fd):
            info = os.fstat(fd)
            opened = Path(os.readlink(f"/proc/self/fd/{fd}"))
            if not opened.is_relative_to(tmp_path):
                return real_sync(fd)
            if stat.S_ISREG(info.st_mode) and opened.name.startswith(".freesdn-archive-"):
                synced_file.append((info.st_dev, info.st_ino))
            elif stat.S_ISDIR(info.st_mode) and synced_file:
                failed_publication.append((info.st_dev, info.st_ino))
                raise OSError(errno.EIO, "owned publication sync failure")
            return real_sync(fd)

        with monkeypatch.context() as patch:
            patch.setattr(os, "fsync", sync)
            response = await fixture.client.post("/api/v1/backups/", json=data, headers=headers)
        async with AsyncSession(fixture.engine) as db:
            rows = list((await db.scalars(select(Backup).where(Backup.organization_id == fixture.org_id))).all())
            observed = [{"status": row.status, "locator": row.storage_path,
                         "identity": (row.metadata_json or {}).get("artifact_identity"),
                         "storage": row.storage_location_id == fixture.storage_id,
                         "size": row.file_size} for row in rows]
        stored = [p for p in tmp_path.rglob("*") if p.is_file()]
        locator_matches = len(rows) == len(stored) == 1 and rows[0].storage_path is not None and stored[0] == tmp_path / rows[0].storage_path
        request.node.user_properties.extend([
            ("HTTP_status", response.status_code), ("file_fsync_count", len(synced_file)),
            ("publication_failure_count", len(failed_publication)), ("catalogue", observed),
            ("stored_file_count", len(stored)), ("failed_locator_matches_existing_file", locator_matches),
        ])
        assert synced_file and failed_publication, "The intended post-publication fsync failure must occur"
        assert response.status_code in {400, 409, 500}
        assert len(rows) == 1 and rows[0].status == "failed"
        assert locator_matches and rows[0].storage_location_id == fixture.storage_id
        assert observed[0]["identity"] is None
        assert rows[0].file_size == stored[0].stat().st_size
        assert not list(tmp_path.rglob(".freesdn-archive-*.tmp"))


@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_uncertain_probe_publication_still_attempts_owned_cleanup(
    monkeypatch, tmp_path, request, credential,
):
    async with owned_actor(monkeypatch, tmp_path, credential) as fixture:
        real_sync = os.fsync
        synced = []
        refused = []

        def sync(fd):
            info = os.fstat(fd)
            opened = Path(os.readlink(f"/proc/self/fd/{fd}"))
            if opened.is_relative_to(tmp_path):
                if stat.S_ISREG(info.st_mode) and opened.name.startswith(".freesdn-archive-"):
                    synced.append(True)
                elif stat.S_ISDIR(info.st_mode) and synced and not refused:
                    refused.append(True)
                    raise OSError(errno.EIO, "owned first publication sync failure")
            return real_sync(fd)

        with monkeypatch.context() as patch:
            patch.setattr(os, "fsync", sync)
            response = await fixture.client.post(f"/api/v1/backups/storage-locations/{fixture.storage_id}/test")
        async with AsyncSession(fixture.engine) as db:
            row = await db.get(StorageLocation, fixture.storage_id)
            durable_status = row.last_test_status
        remaining = [p for p in tmp_path.rglob("*") if p.is_file()]
        data = response.json()
        request.node.user_properties.extend([
            ("HTTP_status", response.status_code), ("publication_refusal_count", len(refused)),
            ("response_success", data.get("success")), ("response_cleanup", (data.get("details") or {}).get("cleanup")),
            ("durable_probe_status", durable_status), ("remaining_owned_files", len(remaining)),
        ])
        assert synced and refused
        assert response.status_code == 200 and data["success"] is False
        assert data["details"]["cleanup"] == "acknowledged"
        assert durable_status == "failed" and not remaining
