"""Probe purpose, actual protocol ordering and durable ambiguous receipts."""

import asyncio
import hashlib
import json
from contextlib import contextmanager
from dataclasses import asdict, replace
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncTransaction

import app.services.backup as storage
from app.core.remote_write_intent import InvalidRemoteIntent, RemoteProbeIntent
from tests.services.test_backup_artifact_integrity_contract import owned_actor
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer
from tests.services.test_remote_publication_acknowledgment import fixture
from tests.services.test_remote_write_coordination import configure, history
from tests.services.test_remote_write_journal import intent


def probe():
    original = intent()
    final = original.final_location.replace("_fixture.fsdn", "_connectivity_test.txt")
    return RemoteProbeIntent(**{
        **asdict(original), "final_location": final,
        "temporary_location": final + ".partial-" + original.operation_id.hex,
    })


def test_probe_purpose_is_explicit_and_backup_v1_unchanged():
    original = intent()
    old = original.encoded()
    parsed_old = json.loads(old)
    assert parsed_old["format_version"] == 1 and "purpose" not in parsed_old
    assert parsed_old["backup_id"] == str(original.backup_id)
    value = probe()
    parsed = json.loads(value.encoded())
    assert parsed["format_version"] == 2 and parsed["purpose"] == "connectivity_probe"
    assert parsed["probe_id"] == str(value.backup_id) and "backup_id" not in parsed
    assert parsed["include_secrets"] is False and parsed["schedule_id"] is None
    assert len(value.encoded()) <= 8192
    assert value.digest() == hashlib.sha256(value.encoded()).hexdigest()
    assert original.encoded() == old


@pytest.mark.parametrize("variant", ["secrets", "scheduled", "oversize", "filename", "actor", "bool-size"])
def test_probe_metadata_refuses_wrong_purpose_inputs(variant):
    value = probe()
    if variant == "secrets":
        value = replace(value, include_secrets=True)
    elif variant == "scheduled":
        value = replace(value, requested_by=None, schedule_id=uuid4())
    elif variant == "oversize":
        value = replace(value, payload_size=129)
    elif variant == "filename":
        final = value.final_location.replace("_connectivity_test.txt", "_vault.fsdn")
        value = replace(value, final_location=final,
                        temporary_location=final + ".partial-" + value.operation_id.hex)
    elif variant == "actor":
        value = replace(value, requested_by=None)
    else:
        value = replace(value, payload_size=True)
    with pytest.raises(InvalidRemoteIntent, match="^Invalid remote recovery metadata$"):
        value.encoded()


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("stage", ["none", "before", "after"])
async def test_probe_intent_is_committed_before_actual_remote_connection(
    request, monkeypatch, tmp_path, protocol, stage,
):
    remote = fixture(request, monkeypatch, protocol, stage=stage)
    async with owned_actor(monkeypatch, tmp_path) as actor:
        await configure(actor, remote, protocol)
        name = "sftp_connection" if protocol == "sftp" else "ftps_connection"
        original = getattr(storage, name)
        observed = []
        url = actor.engine.url.set(drivername="postgresql").render_as_string(hide_password=False)

        @contextmanager
        def inspected_connection(*args, **kwargs):
            with psycopg.connect(url, connect_timeout=3) as db:
                rows = db.execute(
                    "SELECT phase, intent_bytes FROM backup.remote_write_operations WHERE organization_id=%s",
                    (actor.org_id,),
                ).fetchall()
            assert len(rows) == 1
            observed.append((rows[0][0], json.loads(bytes(rows[0][1]))))
            with original(*args, **kwargs) as connection:
                yield connection

        monkeypatch.setattr(storage, name, inspected_connection)
        response = await actor.client.post(f"/api/v1/backups/storage-locations/{actor.storage_id}/test")
        rows = await history(actor)
        assert response.status_code == 200 and len(rows) == 1 and observed
        row = rows[0]
        value = json.loads(row.intent_bytes)
        assert observed[0] == ("dispatched", value)
        assert value["format_version"] == 2 and value["purpose"] == "connectivity_probe"
        assert value["requested_by"] == str(actor.actor_id)
        assert value["organization_id"] == str(actor.org_id) and value["storage_location_id"] == str(actor.storage_id)
        assert value["probe_id"] == str(row.backup_id) and "backup_id" not in value
        assert hashlib.sha256(row.intent_bytes).hexdigest() == row.intent_sha256
        renames = [item for item in remote.state.events if item[0] == "rename"]
        assert len(renames) == 1
        _, temporary, final = renames[0]
        assert value["final_location"] == remote.backend._url(final)
        assert value["temporary_location"] == remote.backend._url(temporary)
        details = response.json()["details"]["remote_write"]
        assert details["operation_id"] == str(row.operation_id)
        assert details["automatic_retry_allowed"] is False
        if stage == "none":
            assert response.json()["success"] and not remote.files()
            assert row.phase == "acknowledged" and details["recovery_required"] is False
            assert len(observed) == 4
        else:
            assert not response.json()["success"] and details["recovery_required"]
            assert row.phase == "dispatched" and len(observed) == 1
            blob = remote.files()[temporary if stage == "before" else final]
            assert len(blob) == value["payload_size"]
            assert hashlib.sha256(blob).hexdigest() == value["payload_sha256"]
        request.node.user_properties.extend([
            ("independent_committed_probe_history_before_original_real_connection", True),
            ("explicit_probe_purpose_and_actor_scope_retained", True),
            ("actual_protocol_names_equal_durable_candidates", True),
            ("no_automatic_replay_after_unknown_publication", stage != "none"),
        ])


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("phase", ["reserve", "dispatch"])
async def test_probe_actual_commit_with_lost_receipt_sends_no_remote_bytes(
    request, monkeypatch, tmp_path, protocol, phase,
):
    remote = fixture(request, monkeypatch, protocol)
    async with owned_actor(monkeypatch, tmp_path) as actor:
        await configure(actor, remote, protocol)
        original_exit = AsyncTransaction.__aexit__
        observed = []

        def mark(connection, cursor, statement, parameters, context, many):
            selected = (statement.startswith("INSERT INTO backup.remote_write_operations") if phase == "reserve"
                        else statement.startswith("UPDATE backup.remote_write_operations"))
            if selected:
                connection.info["owned_probe_commit_receipt"] = True

        async def lost_receipt(transaction, *args):
            selected = transaction.connection.info.pop("owned_probe_commit_receipt", False)
            answer = await original_exit(transaction, *args)
            if selected and args[0] is None:
                observed.append(True)
                raise ConnectionError("Owned probe receipt lost after commit")
            return answer

        event.listen(actor.engine.sync_engine, "after_cursor_execute", mark)
        monkeypatch.setattr(AsyncTransaction, "__aexit__", lost_receipt)
        try:
            response = await actor.client.post(f"/api/v1/backups/storage-locations/{actor.storage_id}/test")
        finally:
            event.remove(actor.engine.sync_engine, "after_cursor_execute", mark)
        rows = await history(actor)
        assert response.status_code == 200 and response.json()["success"] is False and observed == [True]
        assert len(rows) == 1 and rows[0].phase == ("reserved" if phase == "reserve" else "dispatched")
        assert response.json()["details"]["remote_write"]["operation_id"] == str(rows[0].operation_id)
        assert remote.auths() == 0 and not remote.files() and not remote.state.events
        request.node.user_properties.extend([
            ("real_commit_precedes_injected_receipt_failure", True),
            ("probe_history_survives_and_no_remote_io_follows", True),
        ])


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("stage", ["before", "after"])
async def test_probe_lost_cleanup_receipt_keeps_recovery_without_reconnect(
    request, monkeypatch, tmp_path, protocol, stage,
):
    remote = fixture(request, monkeypatch, protocol, operation="delete", stage=stage)
    async with owned_actor(monkeypatch, tmp_path) as actor:
        await configure(actor, remote, protocol)
        response = await actor.client.post(f"/api/v1/backups/storage-locations/{actor.storage_id}/test")
        rows = await history(actor)
        assert response.status_code == 200 and response.json()["success"] is False
        assert remote.state.dropped and remote.auths() == 4
        assert len([item for item in remote.state.events if item[0] == "delete"]) == 1
        assert len(remote.files()) == (1 if stage == "before" else 0)
        assert len(rows) == 1 and rows[0].phase == "acknowledged"
        details = response.json()["details"]
        assert details["cleanup"] == "failed" and details["remote_write"]["recovery_required"]
        assert details["remote_write"]["automatic_retry_allowed"] is False
        request.node.user_properties.extend([
            ("actual_delete_acknowledgment_lost", True),
            ("remaining_files", len(remote.files())),
            ("no_speculative_reconnect_or_delete_retry", True),
        ])


async def test_probe_actual_journal_wait_refuses_before_remote_connection(request, monkeypatch, tmp_path):
    remote = fixture(request, monkeypatch, "sftp")
    async with owned_actor(monkeypatch, tmp_path) as actor:
        await configure(actor, remote, "sftp")
        async with actor.engine.connect() as blocker:
            transaction = await blocker.begin()
            holder = await blocker.scalar(text("SELECT pg_backend_pid()"))
            await blocker.execute(text("LOCK TABLE backup.remote_write_operations IN ACCESS EXCLUSIVE MODE"))
            task = asyncio.create_task(actor.client.post(f"/api/v1/backups/storage-locations/{actor.storage_id}/test"))
            waited = False
            try:
                for _ in range(300):
                    async with actor.engine.connect() as observer:
                        count = await observer.scalar(text(
                            "SELECT count(*) FROM pg_stat_activity WHERE :holder = ANY(pg_blocking_pids(pid))"),
                            {"holder": holder},
                        )
                    if count:
                        waited = True
                        break
                    await asyncio.sleep(.01)
                assert waited, "Actual PostgreSQL wait prerequisite"
                response = await asyncio.wait_for(asyncio.shield(task), 12)
            finally:
                await transaction.rollback()
                await asyncio.gather(task, return_exceptions=True)
        assert response.status_code == 200 and response.json()["success"] is False
        assert not await history(actor) and remote.auths() == 0 and not remote.files()
        request.node.user_properties.append(("actual_journal_deadline_prevents_probe_connection", True))
