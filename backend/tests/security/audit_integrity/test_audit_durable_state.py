"""Real local PostgreSQL state/retention/migration contracts, no WORM claim."""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

import app
from app.models.security_audit import AuditChainState, AuditLogRecord
from app.services.audit import AuditService
from app.services.audit_chain import prune_prefix
from app.services.security_audit import PersistentSecurityAuditService


def engine():
    return create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)


async def seed(db, ids, ages=None):
    async with AsyncSession(db, expire_on_commit=False) as session:
        assert await session.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
        for number, identity in enumerate(ids):
            await AuditService(session).persist_record(AuditLogRecord(
                id=identity, timestamp=datetime.now(UTC) - timedelta(days=(ages or [120] * len(ids))[number]),
                action="owned_durable_audit", resource_type="owned_durable_audit",
            ))
        await session.commit()


async def finish(db, ids):
    async with db.begin() as connection:
        await connection.execute(delete(AuditLogRecord).where(AuditLogRecord.id.in_(ids)))
    await db.dispose()


async def raw_state(db):
    async with db.connect() as connection:
        row = (await connection.execute(text(
            "SELECT revision,encode(state_bytes,'hex'),state_hmac FROM audit.audit_chain_state WHERE id=1",
        ))).one()
        return tuple(row)


@pytest.mark.parametrize("operation", ["append", "main_retention", "legacy_retention"])
async def test_rollback_keeps_rows_and_seal_atomic(operation, record_property):
    db = engine()
    ids = [uuid4() for _ in range(4)]
    try:
        await seed(db, ids[:3])
        before = await raw_state(db)
        async with AsyncSession(db) as session:
            if operation == "append":
                await AuditService(session).persist_record(AuditLogRecord(
                    id=ids[3], timestamp=datetime.now(UTC), action="owned_rollback", resource_type="owned_durable_audit",
                ))
            elif operation == "main_retention":
                assert await AuditService(session).cleanup_old_entries(90) == 3
            else:
                assert (await PersistentSecurityAuditService.cleanup_old_entries(session, 90))["audit_logs"] == 3
            own = await AuditService(session).validate_audit_chain()
            assert own["valid"] and own["state_authenticated"]
            await session.rollback()
        after = await raw_state(db)
        async with AsyncSession(db) as reader:
            count = await reader.scalar(select(func.count()).select_from(AuditLogRecord))
            verdict = await AuditService(reader).validate_audit_chain()
        record_property("exact_state_restored", before == after)
        record_property("durable_count", count)
        assert before == after and count == 3
        assert verdict["valid"] and verdict["retained_history_authenticated"]
        assert verdict["history_authenticated"] is False and verdict["external_immutability_proven"] is False
    finally:
        await finish(db, ids)


@pytest.mark.parametrize("mutation", ["head", "middle", "tail", "all", "body", "state_bytes", "state_signature", "missing_state"])
async def test_uncoordinated_tampering_is_not_silently_reinitialized(mutation, record_property):
    db = engine()
    ids = [uuid4() for _ in range(4)]
    try:
        await seed(db, ids[:3])
        async with db.begin() as connection:
            if mutation in ("head", "middle", "tail", "all"):
                target = ids[:3] if mutation == "all" else [ids[{"head": 0, "middle": 1, "tail": 2}[mutation]]]
                await connection.execute(delete(AuditLogRecord).where(AuditLogRecord.id.in_(target)))
            elif mutation == "body":
                await connection.execute(text("UPDATE audit.audit_logs SET action='changed' WHERE id=:id"), {"id": ids[1]})
            elif mutation == "missing_state":
                # Privileged DDL adversary, beyond normal guarded DELETE/TRUNCATE.
                await connection.execute(text("DROP TABLE audit.audit_chain_state"))
                # Empty same-shape table without its seed/triggers emulates missing
                # singleton, while avoiding an undefined-table SQL exception.
                await connection.execute(text("CREATE TABLE audit.audit_chain_state "
                    "(id smallint PRIMARY KEY,revision bigint NOT NULL,state_bytes bytea NOT NULL,state_hmac varchar(64))"))
                assert AuditChainState.__tablename__ == "audit_chain_state"
            elif mutation == "state_bytes":
                await connection.execute(text("UPDATE audit.audit_chain_state SET revision=revision+1,state_bytes=convert_to('{}','UTF8')"))
            else:
                await connection.execute(text("UPDATE audit.audit_chain_state SET revision=revision+1,state_hmac=repeat('0',64)"))
        async with AsyncSession(db) as session:
            verdict = await AuditService(session).validate_audit_chain()
            record_property("actual_verdict", json.dumps(verdict))
            assert not verdict["valid"] and not verdict["retained_history_authenticated"]
            if mutation in ("tail", "all", "state_bytes", "state_signature", "missing_state"):
                with pytest.raises(ValueError):
                    await AuditService(session).persist_record(AuditLogRecord(
                        id=ids[3], timestamp=datetime.now(UTC), action="owned_refused", resource_type="owned_durable_audit",
                    ))
                await session.commit()
                assert await session.get(AuditLogRecord, ids[3]) is None
            if mutation in ("head", "middle", "tail", "all", "body"):
                with pytest.raises(ValueError):
                    await prune_prefix(session, datetime.now(UTC))
                await session.commit()
    finally:
        await finish(db, ids)


@pytest.mark.parametrize("command", ["DELETE FROM audit.audit_chain_state", "TRUNCATE audit.audit_chain_state",
    "UPDATE audit.audit_chain_state SET revision=0", "UPDATE audit.audit_chain_state SET state_hmac=NULL",
    "INSERT INTO audit.audit_chain_state SELECT * FROM audit.audit_chain_state"],
    ids=["delete", "truncate", "rewind", "unsign", "insert"])
async def test_state_reset_commands_are_refused(command):
    db = engine()
    ids = [uuid4()]
    try:
        await seed(db, ids)
        before = await raw_state(db)
        async with db.connect() as connection:
            with pytest.raises(DBAPIError):
                await connection.execute(text(command))
            await connection.rollback()
        assert await raw_state(db) == before
    finally:
        await finish(db, ids)


async def test_bounded_retention_and_continuation_through_empty_history(record_property):
    db = engine()
    ids = [uuid4() for _ in range(6)]
    try:
        await seed(db, ids[:5])
        async with AsyncSession(db, expire_on_commit=False) as session:
            tail = await session.get(AuditLogRecord, ids[4])
            tail_hash = tail.row_hmac
            counts = []
            for _ in range(3):
                counts.append(await prune_prefix(session, datetime.now(UTC), batch_size=2))
                await session.commit()
                verdict = await AuditService(session).validate_audit_chain()
                assert verdict["valid"] and verdict["boundary_verified"]
            assert counts == [2, 2, 1]
            await AuditService(session).persist_record(AuditLogRecord(
                id=ids[5], timestamp=datetime.now(UTC), action="owned_after_empty", resource_type="owned_durable_audit",
            ))
            await session.commit()
        async with AsyncSession(db) as reader:
            row = await reader.get(AuditLogRecord, ids[5])
            verdict = await AuditService(reader).validate_audit_chain()
        record_property("actual_batch_deletions", json.dumps(counts))
        record_property("continued_from_removed_tail", row.prev_hash == tail_hash)
        assert row.prev_hash == tail_hash and verdict["valid"] and verdict["retention_applied"]
    finally:
        await finish(db, ids)


def revision(connection, method):
    path = Path(app.__file__).resolve().parent.parent / "alembic/versions/030_audit_retention_state.py"
    spec = importlib.util.spec_from_file_location("owned_revision_030", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with Operations.context(MigrationContext.configure(connection)):
        getattr(module, method)()


async def test_fresh_metadata_and_repeated_revision_agree():
    db = engine()
    try:
        async with db.begin() as connection:
            await connection.run_sync(lambda c: revision(c, "upgrade"))
            await connection.run_sync(lambda c: revision(c, "upgrade"))
    finally:
        await db.dispose()


async def test_downgrade_refuses_state_loss():
    db = engine()
    ids = [uuid4()]
    try:
        await seed(db, ids)
        before = await raw_state(db)
        async with db.begin() as connection:
            with pytest.raises(RuntimeError, match="Refusing downgrade"):
                await connection.run_sync(lambda c: revision(c, "downgrade"))
        assert await raw_state(db) == before
    finally:
        await finish(db, ids)


async def test_actual_upgrade_keeps_signed_rows_byte_equivalent(record_property):
    db = engine()
    ids = [uuid4(), uuid4()]
    try:
        await seed(db, ids[:1])
        async with db.begin() as connection:
            before = await connection.scalar(text("SELECT to_jsonb(a)::text FROM audit.audit_logs a WHERE id=:id"), {"id": ids[0]})
            await connection.execute(text("DROP TABLE audit.audit_chain_state"))
            await connection.execute(text("DROP FUNCTION audit.guard_audit_chain_state()"))
            await connection.execute(text("DROP INDEX audit.ix_audit_logs_chain_order"))
            await connection.execute(text("ALTER TABLE audit.audit_logs ADD CONSTRAINT owned_previous_org_fk FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL"))
            await connection.execute(text("ALTER TABLE audit.audit_logs ADD CONSTRAINT owned_previous_site_fk FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL"))
            await connection.run_sync(lambda c: revision(c, "upgrade"))
            after = await connection.scalar(text("SELECT to_jsonb(a)::text FROM audit.audit_logs a WHERE id=:id"), {"id": ids[0]})
            record_property("actual_upgrade_preserved_original_row", before == after)
            assert before == after
        async with AsyncSession(db) as session:
            initial = await AuditService(session).validate_audit_chain()
            assert initial["valid"] and not initial["state_authenticated"]
            await AuditService(session).persist_record(AuditLogRecord(
                id=ids[1], timestamp=datetime.now(UTC), action="owned_after_upgrade", resource_type="owned_durable_audit",
            ))
            await session.commit()
        async with AsyncSession(db) as reader:
            verdict = await AuditService(reader).validate_audit_chain()
            assert verdict["valid"] and verdict["retained_history_authenticated"]
    finally:
        await finish(db, ids)


async def test_concurrent_appends_do_not_split_verification_snapshot(record_property):
    db = engine()
    ids = [uuid4() for _ in range(21)]
    ready = asyncio.Event()
    try:
        await seed(db, ids[:1], [0])
        async def write():
            async with AsyncSession(db) as session:
                pid = await session.scalar(text("SELECT pg_backend_pid()"))
                await ready.wait()
                for identity in ids[1:]:
                    await AuditService(session).persist_record(AuditLogRecord(
                        id=identity, timestamp=datetime.now(UTC), action="owned_concurrent", resource_type="owned_durable_audit",
                    ))
                    await session.commit()
                    await asyncio.sleep(0)
                return pid
        async def read():
            counts = set()
            async with AsyncSession(db) as session:
                pid = await session.scalar(text("SELECT pg_backend_pid()"))
                ready.set()
                for _ in range(80):
                    verdict = await AuditService(session).validate_audit_chain()
                    assert verdict["valid"] and verdict["retained_history_authenticated"]
                    counts.add(verdict["checked"])
                    await asyncio.sleep(0)
                return pid, counts
        tasks = [asyncio.create_task(write()), asyncio.create_task(read())]
        try:
            writer, (reader, counts) = await asyncio.gather(*tasks)
        finally:
            # gather propagates the first exception without cancelling siblings.
            # Join them before finally deletes this case's owned rows.
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        record_property("distinct_physical_connections", writer != reader)
        record_property("observed_retained_counts", json.dumps(sorted(counts)))
        assert writer != reader and len(counts) >= 2
    finally:
        await finish(db, ids)
