"""Actual API/PG catalogue after controlled real remote acknowledgment loss."""

import hashlib
import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_credential
from app.modules.backup.models import Backup, StorageLocation
from app.services.backup import BackupService
from tests.services.test_backup_artifact_integrity_contract import create_request, owned_actor
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer
from tests.services.test_remote_publication_acknowledgment import fixture


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("stage", ["none", "before", "after"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_real_create_catalogue_retains_possible_remote_publication(
    request, monkeypatch, tmp_path, protocol, stage, credential,
):
    remote = fixture(request, monkeypatch, protocol, stage=stage)
    async with owned_actor(monkeypatch, tmp_path, credential) as actor:
        async with AsyncSession(actor.engine) as session:
            loc = await session.get(StorageLocation, actor.storage_id)
            public, secret = BackupService(session)._extract_sensitive(remote.backend.config)
            loc.storage_type = "sftp" if protocol == "sftp" else "ftp"
            loc.config = public
            loc.encrypted_credentials = encrypt_credential(json.dumps(secret))
            await session.commit()
        data = create_request(actor, False)
        data["storage_type"] = "sftp" if protocol == "sftp" else "ftp"
        response = await actor.client.post("/api/v1/backups/", json=data)
        # Independent session observes committed state, not the request identity map.
        async with AsyncSession(actor.engine) as session:
            rows = list((await session.scalars(select(Backup).where(Backup.organization_id == actor.org_id))).all())
        contents = remote.files()
        renames = [e for e in remote.state.events if e[0] == "rename"]
        assert len(rows) == len(renames) == len(contents) == 1, "Actual collection/storage/catalogue boundary prerequisite"
        row = rows[0]
        _, temporary, destination = renames[0]
        actual_path = temporary if stage == "before" else destination
        assert set(contents) == {actual_path}
        blob = contents[actual_path]
        length = int.from_bytes(blob[:4], "big")
        assert 0 < length < len(blob) - 4
        header = json.loads(blob[4:4 + length])
        body = blob[4 + length:]
        detail = await actor.client.get(f"/api/v1/backups/{row.id}")
        detail_data = detail.json()
        candidate = remote.backend._url(destination)
        observed = {
            "protocol": protocol, "drop_stage": stage, "credential": credential,
            "create_HTTP": response.status_code, "detail_HTTP": detail.status_code,
            "durable_rows": len(rows), "durable_status": row.status,
            "durable_locator_retained": row.storage_path == candidate,
            "detail_locator_retained": detail_data.get("storage_path") == candidate,
            "durable_identity_recorded": "artifact_identity" in (row.metadata_json or {}),
            "durable_storage_matches": row.storage_location_id == actor.storage_id,
            "actual_rename_requests": len(renames), "actual_authentications": remote.auths(),
            "actual_final_exists": destination in contents, "actual_temporary_exists": temporary in contents,
            "archive_encrypted": header.get("encrypted") is True,
            "archive_header_matches_row": header.get("backup_id") == str(row.id),
            "archive_body_checksum_valid": hashlib.sha256(body).hexdigest() == header.get("checksum"),
            "raw_catalogue_has_locator": row.storage_path is not None,
            "acknowledgment_dropped": remote.state.dropped,
        }
        request.node.user_properties.extend(observed.items())
        assert observed["archive_encrypted"] and observed["archive_header_matches_row"] and observed["archive_body_checksum_valid"]
        assert detail.status_code == 200 and row.storage_location_id == actor.storage_id
        if stage == "none":
            assert response.status_code == 201 and row.status == "completed"
            assert observed["durable_identity_recorded"] and not remote.state.dropped
            assert row.file_size == len(blob) and remote.auths() == 2
        else:
            assert response.status_code in {400, 409, 500, 503} and row.status == "failed"
            assert remote.state.dropped and remote.auths() == 1
            assert not observed["durable_identity_recorded"]
        assert observed["durable_locator_retained"], "Committed catalogue lost the possible remote destination"
        assert observed["detail_locator_retained"], "Authorized operator cannot inspect the possible destination"
