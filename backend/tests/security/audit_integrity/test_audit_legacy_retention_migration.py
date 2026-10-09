"""Actual029/030 over owned old rows, retaining uncertainty and failed histories.

The predecessor schema is reconstructed in a fresh local database. This is not
an application/OCI/public-version installation or a production-data exercise.
"""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

import app
from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditService, _compute_row_hmac
from app.services.audit_chain import prune_prefix

REVISIONS = {29: "029_audit_append_order.py", 30: "030_audit_retention_state.py"}


def revision(connection, number, method):
    path = Path(app.__file__).resolve().parent.parent / "alembic/versions" / REVISIONS[number]
    spec = importlib.util.spec_from_file_location("owned_revision_" + str(number), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with Operations.context(MigrationContext.configure(connection)):
        getattr(module, method)()


async def old_schema(connection):
    assert await connection.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
    # Owned setup only. Reconstruct the predecessor without invoking the new
    # deliberately refusing downgrade. All subsequent transitions use actual
    # immutable revision029 and revision030 upgrade code.
    await connection.execute(text("DROP TABLE audit.audit_chain_state"))
    await connection.execute(text("DROP FUNCTION audit.guard_audit_chain_state()"))
    await connection.execute(text("DROP INDEX audit.ix_audit_logs_chain_order"))
    await connection.execute(text("ALTER TABLE audit.audit_logs ADD CONSTRAINT owned_previous_org_fk "
        "FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL"))
    await connection.execute(text("ALTER TABLE audit.audit_logs ADD CONSTRAINT owned_previous_site_fk "
        "FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL"))
    await connection.run_sync(lambda c: revision(c, 29, "downgrade"))


def rows_for(kind):
    rows = []
    for number in range(3):
        row = AuditLogRecord(id=uuid4(), timestamp=datetime(2024, 1, 1, tzinfo=UTC) + timedelta(seconds=number),
            action="owned_old_audit", resource_type="owned_old_audit", actor_type="user",
            status="success", tags=[], extra_metadata={})
        row.prev_hash = rows[-1].row_hmac if rows and not (kind == "branch" and number == 1) else None
        row.row_hmac = None if kind == "unsigned" or (kind == "unsigned_late" and number == 1) else _compute_row_hmac(row.prev_hash, row)
        if (kind == "corrupt_middle" and number == 1) or (kind == "corrupt_tail" and number == 2):
            row.action = "owned_altered_after_signing"
        rows.append(row)
    return rows


async def insert_old(connection, rows):
    for row in rows:
        await connection.execute(text(
            "INSERT INTO audit.audit_logs "
            "(id,timestamp,action,resource_type,actor_type,status,tags,metadata,prev_hash,row_hmac) "
            "VALUES (:id,:timestamp,:action,:resource_type,'user','success','[]'::jsonb,'{}'::jsonb,:prev_hash,:row_hmac)"
        ), {n: getattr(row, n) for n in ("id", "timestamp", "action", "resource_type", "prev_hash", "row_hmac")})


async def stored(connection, ids):
    return list((await connection.execute(text(
        "SELECT (to_jsonb(a)-'append_sequence')::text FROM audit.audit_logs a WHERE id=ANY(:ids) ORDER BY id",
    ), {"ids": ids})).scalars())


async def finish(db, ids):
    async with db.begin() as connection:
        await connection.execute(text("DELETE FROM audit.audit_logs WHERE id=ANY(:ids)"), {"ids": ids})
        await connection.run_sync(lambda c: revision(c, 29, "upgrade"))
        await connection.run_sync(lambda c: revision(c, 30, "upgrade"))
    await db.dispose()


@pytest.mark.parametrize("kind", ["valid", "unsigned", "corrupt_middle", "branch", "previously_pruned", "corrupt_tail", "unsigned_late"])
async def test_legacy_upgrade_append_and_retention_never_rewrite_history(kind, record_property):
    db = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    rows = rows_for(kind)
    ids = [row.id for row in rows]
    new_id = uuid4()
    try:
        async with db.begin() as connection:
            await old_schema(connection)
            await insert_old(connection, rows)
            if kind == "previously_pruned":
                await connection.execute(text("DELETE FROM audit.audit_logs WHERE id=:id"), {"id": ids[0]})
            before = await stored(connection, ids)
        async with db.begin() as connection:
            await connection.run_sync(lambda c: revision(c, 29, "upgrade"))
            await connection.run_sync(lambda c: revision(c, 30, "upgrade"))
            after_upgrade = await stored(connection, ids)
            positions = list((await connection.execute(text(
                "SELECT append_sequence FROM audit.audit_logs WHERE id=ANY(:ids)",
            ), {"ids": ids})).scalars())
        async with AsyncSession(db) as session:
            unsealed = await AuditService(session).validate_audit_chain()
            append_error = None
            try:
                await AuditService(session).persist_record(AuditLogRecord(
                    id=new_id, timestamp=datetime.now(UTC), action="owned_new_audit", resource_type="owned_old_audit",
                ))
            except ValueError as exc:
                append_error = str(exc)
            await session.commit()
        async with AsyncSession(db) as reader:
            after_append = await AuditService(reader).validate_audit_chain()
            added = await reader.get(AuditLogRecord, new_id)
            new_properties = None if added is None else {
                "prev_matches_old_tail": added.prev_hash == rows[-1].row_hmac,
                "body_valid": added.row_hmac == _compute_row_hmac(added.prev_hash, added),
                "position_positive": added.append_sequence > 0,
            }
        async with AsyncSession(db) as session:
            prune_error = None
            removed = None
            try:
                removed = await prune_prefix(session, datetime.now(UTC) - timedelta(days=90))
            except ValueError as exc:
                prune_error = str(exc)
            await session.commit()
        async with AsyncSession(db) as reader:
            final = await AuditService(reader).validate_audit_chain()
        async with db.connect() as connection:
            remaining_old = await stored(connection, ids)
        observations = {"unchanged_old_fields": before == after_upgrade,
            "old_positions_null": positions == [None] * len(before),
            "unsealed_verdict": unsealed, "append_error": append_error,
            "new_record": new_properties, "after_append_verdict": after_append,
            "prune_error": prune_error, "removed": removed, "final_verdict": final,
            "remaining_old_count": len(remaining_old), "remaining_old_fields_unchanged": remaining_old == before}
        record_property("actual_legacy_transition", json.dumps(observations))
        assert before == after_upgrade and positions == [None] * len(before)
        assert not unsealed["state_authenticated"] and not unsealed["retained_history_authenticated"]
        assert unsealed["valid"] is (kind in {"valid", "unsigned"})
        if kind == "corrupt_tail":
            assert append_error is not None and added is None
        else:
            assert append_error is None and all(new_properties.values())
        assert after_append["valid"] is (kind in {"valid", "unsigned"})
        if kind in {"valid", "unsigned"}:
            assert prune_error is None and removed == 3 and remaining_old == []
            assert final["valid"]
            assert final["retained_history_authenticated"] is (kind == "valid")
            if kind == "unsigned":
                assert final["unsigned_history_rows"] == 3 and final["legacy_rows"] == 0
        else:
            assert prune_error is not None and removed is None and remaining_old == before
            assert not final["valid"]
        assert not final["external_immutability_proven"] and not final["history_authenticated"]
    finally:
        await finish(db, ids + [new_id])
