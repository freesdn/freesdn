# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private unrun catalogue/storage transitions after actual verified copy."""

import asyncio
import copy
import hashlib
import threading
from uuid import uuid4

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_download_response import LocalDownloadSource as ConfigurationDownloadSource
from app.models.core import Organization
from app.modules.backup.models import Backup, StorageLocation
from app.services.vault_snapshot_response import LocalDownloadSource as VaultDownloadSource
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    owned_actor,
    recorded_download_headers,
)

TRANSITIONS = [
    "backup_owner", "backup_status", "backup_deleted", "backup_locator",
    "storage_owner", "storage_disabled", "storage_root", "identity_replaced",
    "unchanged", "backup_renamed", "storage_renamed",
]
CONTROLS = {"unchanged", "backup_renamed", "storage_renamed"}


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("transition", TRANSITIONS)
async def test_prepared_download_checks_current_catalogue_before_first_response(
    tmp_path, monkeypatch, request, credential, secrets, transition
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await create_archive(f, secrets)
        download_headers = await recorded_download_headers(f, backup.id, secrets)
        source_type = VaultDownloadSource if secrets else ConfigurationDownloadSource
        backup_id = backup.id
        expected_digest, expected_bytes = hashlib.sha256(raw).hexdigest(), len(raw)
        del raw
        other_org = uuid4()
        replacement_root = tmp_path / "owned-alternative-root"
        replacement_root.mkdir()
        metadata = copy.deepcopy(backup.metadata_json)
        metadata["artifact_identity"]["sha256"] = "0" * 64
        assert metadata["artifact_identity"]["sha256"] != expected_digest
        backup_change = {
            "backup_owner": {"organization_id": other_org},
            "backup_status": {"status": "failed"},
            "backup_locator": {"storage_path": "owned-alternative.fsdn"},
            "identity_replaced": {"metadata_json": metadata},
            "backup_renamed": {"name": "Owned harmless archive display-name update"},
        }.get(transition, {})
        storage_change = {
            "storage_owner": {"organization_id": other_org},
            "storage_disabled": {"is_active": False},
            "storage_root": {"config": {"path": str(replacement_root)}},
            "storage_renamed": {"name": "Owned harmless storage display-name update"},
        }.get(transition, {})
        entered, release = threading.Event(), threading.Event()
        actual = []
        original = source_type.copy_into

        def wait_after_real_copy(source, snapshot):
            original(source, snapshot)
            if source.files.root == f.root.absolute():
                actual.append({"verified": snapshot.integrity == "verified", "bytes": snapshot.size,
                               "thread": threading.get_ident()})
                entered.set()
                if not release.wait(15):
                    raise TimeoutError("Owned post-copy catalogue fixture was not released")

        monkeypatch.setattr(source_type, "copy_into", wait_after_real_copy)

        async def durable_state_matches():
            async with AsyncSession(f.engine) as db:
                row = await db.get(Backup, backup_id)
                loc = await db.get(StorageLocation, f.storage_id)
                archive_matches = (row is None if transition == "backup_deleted" else
                                   row is not None and all(getattr(row, k) == v for k, v in backup_change.items()))
                return (archive_matches and loc is not None
                        and all(getattr(loc, k) == v for k, v in storage_change.items()))

        task = asyncio.create_task(f.client.get(f"/api/v1/backups/{backup_id}/download", headers=download_headers))
        try:
            for _ in range(1000):
                if entered.is_set() or task.done():
                    break
                await asyncio.sleep(.01)
            assert entered.is_set() and not task.done(), "Actual verified copy wait was not reached"
            assert len(actual) == 1 and actual[0]["verified"] and actual[0]["bytes"] == expected_bytes
            assert actual[0]["thread"] != threading.get_ident()
            async with AsyncSession(f.engine) as db:
                if transition in {"backup_owner", "storage_owner"}:
                    db.add(Organization(id=other_org, name="Owned catalogue transition", slug=uuid4().hex))
                    await db.flush()
                if transition == "backup_deleted":
                    await db.execute(delete(Backup).where(Backup.id == backup_id))
                elif backup_change:
                    await db.execute(update(Backup).where(Backup.id == backup_id).values(**backup_change))
                if storage_change:
                    await db.execute(update(StorageLocation).where(StorageLocation.id == f.storage_id).values(**storage_change))
                await db.commit()
            before_delivery = await durable_state_matches()
            release.set()
            response = await asyncio.wait_for(task, 5)
            after_delivery = await durable_state_matches()
            delivered = (response.status_code == 200 and len(response.content) == expected_bytes
                         and hashlib.sha256(response.content).hexdigest() == expected_digest)
            request.node.user_properties.extend({
                "real_verified_copy_wait": True, "independent_catalogue_state_checked": before_delivery,
                "state_survives_request": after_delivery, "HTTP_status": response.status_code,
                "response_bytes": len(response.content), "exact_archive_delivered": delivered,
                "integrity_header": response.headers.get("x-freesdn-artifact-integrity"),
            }.items())
            assert before_delivery and after_delivery
            if transition in CONTROLS:
                assert response.status_code == 200 and delivered
            else:
                assert response.status_code in (401, 403, 404, 409)
                assert not delivered and "x-freesdn-artifact-integrity" not in response.headers
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            if transition in {"backup_owner", "storage_owner"}:
                async with AsyncSession(f.engine) as db:
                    await db.execute(update(Backup).where(Backup.id == backup_id).values(organization_id=f.org_id))
                    await db.execute(update(StorageLocation).where(StorageLocation.id == f.storage_id).values(organization_id=f.org_id))
                    await db.execute(delete(Organization).where(Organization.id == other_org))
                    await db.commit()
