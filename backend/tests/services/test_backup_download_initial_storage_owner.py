# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private unrun storage ownership checks before any local copy starts."""

import hashlib
from uuid import uuid4

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_download_response import LocalDownloadSource as ConfigurationDownloadSource
from app.models.core import Organization
from app.modules.backup.models import StorageLocation
from app.services.vault_snapshot_response import LocalDownloadSource as VaultDownloadSource
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    owned_actor,
    recorded_download_headers,
)

TRANSITIONS = ["foreign_storage", "unchanged"]


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("transition", TRANSITIONS)
async def test_download_resolves_only_current_organization_storage(
    tmp_path, monkeypatch, request, credential, secrets, transition
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await create_archive(f, secrets)
        download_headers = await recorded_download_headers(f, backup.id, secrets)
        source_type = VaultDownloadSource if secrets else ConfigurationDownloadSource
        expected_digest, expected_bytes = hashlib.sha256(raw).hexdigest(), len(raw)
        del raw
        other_org = uuid4()
        copied = []
        original = source_type.copy_into

        def observe_actual_copy(source, snapshot):
            copied.append(source.files.root == f.root.absolute())
            return original(source, snapshot)

        monkeypatch.setattr(source_type, "copy_into", observe_actual_copy)
        try:
            if transition == "foreign_storage":
                async with AsyncSession(f.engine) as db:
                    db.add(Organization(id=other_org, name="Owned foreign storage", slug=uuid4().hex))
                    await db.flush()
                    await db.execute(update(StorageLocation).where(StorageLocation.id == f.storage_id)
                                     .values(organization_id=other_org))
                    await db.commit()
            async with AsyncSession(f.engine) as db:
                current_owner = (await db.get(StorageLocation, f.storage_id)).organization_id
            expected_owner = other_org if transition == "foreign_storage" else f.org_id
            response = await f.client.get(f"/api/v1/backups/{backup.id}/download", headers=download_headers)
            async with AsyncSession(f.engine) as db:
                final_owner = (await db.get(StorageLocation, f.storage_id)).organization_id
            delivered = (response.status_code == 200 and len(response.content) == expected_bytes
                         and hashlib.sha256(response.content).hexdigest() == expected_digest)
            request.node.user_properties.extend({
                "independent_initial_storage_owner_checked": current_owner == expected_owner,
                "state_survives_request": final_owner == expected_owner,
                "HTTP_status": response.status_code, "copy_count": len(copied),
                "copies_use_owned_fixture_root": all(copied), "exact_archive_delivered": delivered,
                "response_bytes": len(response.content),
            }.items())
            assert current_owner == final_owner == expected_owner
            if transition == "unchanged":
                assert response.status_code == 200 and delivered and copied == [True]
            else:
                assert response.status_code in (403, 404)
                assert copied == [] and not delivered
        finally:
            if transition == "foreign_storage":
                async with AsyncSession(f.engine) as db:
                    await db.execute(update(StorageLocation).where(StorageLocation.id == f.storage_id)
                                     .values(organization_id=f.org_id))
                    await db.execute(delete(Organization).where(Organization.id == other_org))
                    await db.commit()
