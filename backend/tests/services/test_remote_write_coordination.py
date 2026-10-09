"""Real API/PG/SSH/TLS pre-dispatch history and uncertain commit boundaries."""

import asyncio
import hashlib
import importlib.util
import json
from contextlib import contextmanager
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import event, select, text
from sqlalchemy.ext.asyncio import AsyncSession, AsyncTransaction

import app.services.backup as storage
from app.core.crypto import encrypt_credential
from app.modules.backup.models import Backup, StorageLocation
from app.services.remote_write_journal import operations
from tests.services.test_backup_artifact_integrity_contract import create_request, owned_actor
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer
from tests.services.test_remote_publication_acknowledgment import fixture


async def configure(actor, remote, protocol):
    async with AsyncSession(actor.engine) as session:
        loc = await session.get(StorageLocation, actor.storage_id)
        public, secret = storage.BackupService(session)._extract_sensitive(remote.backend.config)
        loc.storage_type = "sftp" if protocol == "sftp" else "ftp"
        loc.config = public
        loc.encrypted_credentials = encrypt_credential(json.dumps(secret))
        await session.commit()
    data = create_request(actor, False)
    data["storage_type"] = "sftp" if protocol == "sftp" else "ftp"
    return data


async def history(actor):
    async with actor.engine.connect() as connection:
        return (await connection.execute(select(operations).where(
            operations.c.organization_id == actor.org_id,
        ))).mappings().all()


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("stage", ["none", "before", "after"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_committed_intent_precedes_actual_connection_and_retains_exact_names(
    request, monkeypatch, tmp_path, protocol, stage, credential,
):
    remote = fixture(request, monkeypatch, protocol, stage=stage)
    async with owned_actor(monkeypatch, tmp_path, credential) as actor:
        data = await configure(actor, remote, protocol)
        name = "sftp_connection" if protocol == "sftp" else "ftps_connection"
        original = getattr(storage, name)
        observations = []
        url = actor.engine.url.set(drivername="postgresql").render_as_string(hide_password=False)

        @contextmanager
        def inspected_connection(*args, **kwargs):
            # This opens a distinct real connection from the protocol worker,
            # before calling the original actual SSH/TLS connection function.
            with psycopg.connect(url, connect_timeout=3) as db:
                rows = db.execute(
                    "SELECT phase, intent_bytes FROM backup.remote_write_operations WHERE organization_id=%s",
                    (actor.org_id,),
                ).fetchall()
            assert len(rows) == 1 and rows[0][0] in {"dispatched", "acknowledged"}
            observations.append((rows[0][0], json.loads(bytes(rows[0][1]))))
            with original(*args, **kwargs) as connection:
                yield connection

        monkeypatch.setattr(storage, name, inspected_connection)
        response = await actor.client.post("/api/v1/backups/", json=data)
        retained = await history(actor)
        assert len(retained) == 1 and observations
        row = retained[0]
        intent = json.loads(row.intent_bytes)
        assert observations[0] == ("dispatched", intent)
        assert hashlib.sha256(row.intent_bytes).hexdigest() == row.intent_sha256
        renames = [item for item in remote.state.events if item[0] == "rename"]
        assert len(renames) == 1
        _, temporary, destination = renames[0]
        assert intent["final_location"] == remote.backend._url(destination)
        assert intent["temporary_location"] == remote.backend._url(temporary)
        contents = remote.files()
        blob = contents[temporary if stage == "before" else destination]
        assert len(blob) == intent["payload_size"]
        assert hashlib.sha256(blob).hexdigest() == intent["payload_sha256"]
        async with AsyncSession(actor.engine) as db:
            backup = (await db.scalars(select(Backup).where(Backup.organization_id == actor.org_id))).one()
        detail = await actor.client.get(f"/api/v1/backups/{backup.id}")
        assert detail.status_code == 200
        assert detail.json()["remote_write_operation_id"] == str(row.operation_id)
        if stage == "none":
            assert response.status_code == 201 and row.phase == "acknowledged"
            assert not detail.json()["remote_write_recovery_required"]
        else:
            assert response.status_code == 500 and row.phase == "dispatched"
            assert detail.json()["remote_write_recovery_required"]
            authentications = remote.auths()
            assert (await actor.client.delete(f"/api/v1/backups/{backup.id}")).status_code == 409
            assert (await actor.client.get(f"/api/v1/backups/{backup.id}/download")).status_code == 409
            assert remote.auths() == authentications and remote.files() == contents
            assert len(await history(actor)) == 1
        request.node.user_properties.extend([
            ("real_committed_history_before_first_remote_connection", True),
            ("same_retained_candidate_names_used_by_real_protocol", True),
            ("real_payload_matches_durable_identity", True),
            ("unknown_outcome_blocks_ordinary_delete_download", stage != "none"),
        ])


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("phase", ["reserve", "dispatch"])
async def test_actual_commit_with_lost_caller_receipt_never_starts_remote_io(
    request, monkeypatch, tmp_path, protocol, phase,
):
    remote = fixture(request, monkeypatch, protocol, stage="none")
    async with owned_actor(monkeypatch, tmp_path) as actor:
        data = await configure(actor, remote, protocol)
        original_exit = AsyncTransaction.__aexit__
        observed = []

        def mark(connection, cursor, statement, parameters, context, many):
            selected = (statement.startswith("INSERT INTO backup.remote_write_operations") if phase == "reserve"
                        else statement.startswith("UPDATE backup.remote_write_operations"))
            if selected:
                connection.info["owned_lost_commit_receipt"] = True

        async def lost_after_actual_commit(transaction, *args):
            connection = transaction.connection
            selected = connection.info.pop("owned_lost_commit_receipt", False)
            answer = await original_exit(transaction, *args)
            if selected and args[0] is None:
                observed.append(True)
                raise ConnectionError("Owned client receipt lost after actual commit")
            return answer

        event.listen(actor.engine.sync_engine, "after_cursor_execute", mark)
        monkeypatch.setattr(AsyncTransaction, "__aexit__", lost_after_actual_commit)
        try:
            response = await actor.client.post("/api/v1/backups/", json=data)
        finally:
            event.remove(actor.engine.sync_engine, "after_cursor_execute", mark)
        rows = await history(actor)
        assert response.status_code == 500 and observed == [True]
        assert len(rows) == 1 and rows[0].phase == ("reserved" if phase == "reserve" else "dispatched")
        assert remote.auths() == 0 and not remote.files() and not remote.state.events
        request.node.user_properties.extend([
            ("real_SQL_commit_before_injected_client_receipt_failure", True),
            ("durable_history_independently_observed_after_exception", True),
            ("no_remote_authentication_or_mutation_after_commit_exception", True),
        ])


async def test_actual_journal_lock_timeout_prevents_remote_connection(request, monkeypatch, tmp_path):
    remote = fixture(request, monkeypatch, "sftp", stage="none")
    async with owned_actor(monkeypatch, tmp_path) as actor:
        data = await configure(actor, remote, "sftp")
        async with actor.engine.connect() as blocker:
            transaction = await blocker.begin()
            holder = await blocker.scalar(text("SELECT pg_backend_pid()"))
            await blocker.execute(text("LOCK TABLE backup.remote_write_operations IN ACCESS EXCLUSIVE MODE"))
            task = asyncio.create_task(actor.client.post("/api/v1/backups/", json=data))
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
                # Keep the lock held until the unchanged database deadline
                # refuses the request, instead of releasing it to let it pass.
                response = await asyncio.wait_for(asyncio.shield(task), 12)
            finally:
                await transaction.rollback()
                await asyncio.gather(task, return_exceptions=True)
        assert response.status_code == 500 and not await history(actor)
        assert remote.auths() == 0 and not remote.files()
        request.node.user_properties.append(("real_journal_lock_timeout_before_any_remote_connection", True))


async def test_registered_model_matches_frozen_incremental_definition():
    from app.db.session import create_test_engine

    path = Path(__file__).resolve().parents[2] / "alembic/versions/028_remote_write_history.py"
    spec = importlib.util.spec_from_file_location("remote_history_frozen_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engine = create_test_engine()
    try:
        async with engine.begin() as connection:
            await connection.run_sync(module._verify)
    finally:
        await engine.dispose()
