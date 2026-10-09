"""Actual authenticated storage probes after real remote rename receipt loss."""

import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_credential
from app.models.remote_write_operations import operations
from app.modules.backup.models import StorageLocation
from app.services.backup import BackupService
from tests.services.test_backup_artifact_integrity_contract import owned_actor
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer
from tests.services.test_remote_publication_acknowledgment import fixture


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("stage", ["none", "before", "after"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_storage_probe_retains_uncertain_remote_publication(
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
        response = await actor.client.post(
            f"/api/v1/backups/storage-locations/{actor.storage_id}/test",
        )
        body = response.json()
        # Observe independently committed state and actual peer bytes before
        # asserting the response contract; a failed assertion must not hide them.
        async with AsyncSession(actor.engine) as session:
            loc = await session.get(StorageLocation, actor.storage_id)
            history = list((await session.execute(select(operations).where(
                operations.c.organization_id == actor.org_id,
            ))).all())
        contents = remote.files()
        renames = [event for event in remote.state.events if event[0] == "rename"]
        deletes = [event for event in remote.state.events if event[0] == "delete"]
        assert len(renames) == 1, "Actual storage probe must reach the real rename boundary"
        _, temporary, final = renames[0]
        possible = [remote.backend._url(final), remote.backend._url(temporary)]
        details = body.get("details") or {}
        serialized_details = json.dumps(details)
        retained = b"\n".join(row.intent_bytes for row in history)
        observed = {
            "protocol": protocol, "stage": stage, "credential": credential,
            "HTTP": response.status_code, "success": body.get("success"),
            "cleanup": details.get("cleanup"),
            "round_trip_verified": details.get("round_trip_verified"),
            "committed_status": loc.last_test_status,
            "committed_message_matches": loc.last_test_message == body.get("message"),
            "actual_rename_requests": len(renames), "actual_delete_requests": len(deletes),
            "actual_authentications": remote.auths(), "acknowledgment_dropped": remote.state.dropped,
            "final_exists": final in contents, "temporary_exists": temporary in contents,
            "remaining_objects": len(contents), "history_rows": len(history),
            "response_retains_final": possible[0] in serialized_details,
            "response_retains_temporary": possible[1] in serialized_details,
            "history_retains_final": possible[0].encode() in retained,
            "history_retains_temporary": possible[1].encode() in retained,
        }
        request.node.user_properties.extend(observed.items())
        assert response.status_code == 200 and observed["committed_message_matches"]
        if stage == "none":
            assert body["success"] is True and loc.last_test_status == "success"
            assert details["round_trip_verified"] is True and details["cleanup"] == "acknowledged"
            assert not remote.state.dropped and contents == {} and len(deletes) == 1
        else:
            assert remote.state.dropped and remote.auths() == 1 and not deletes
            assert set(contents) == {temporary if stage == "before" else final}
            assert next(iter(contents.values())).startswith(b"freesdn-connectivity-test-")
            assert body["success"] is False and loc.last_test_status == "failed"
            assert details["cleanup"] != "not_created", "Remote bytes remain but cleanup reports no creation"
            assert observed["response_retains_final"] and observed["response_retains_temporary"], (
                "Operator response must retain both possible remote locations without claiming either exists"
            )
            assert observed["history_retains_final"] and observed["history_retains_temporary"], (
                "Both candidates must survive loss of the HTTP response"
            )
