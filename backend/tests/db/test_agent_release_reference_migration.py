# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unexecuted real PostgreSQL/reference-fence contracts, not cleanup proof.

Uses the owned database/auth/publication/deletion fixtures without changing their
original tests or migrations. Raw SQL below deliberately exercises independent
writers. Synthetic cleaned journal state does not claim filesystem cleanup.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, insert, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine

from app.db.agent_release_reference_schema import REFERENCE_DDL
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from tests.db.conftest import drop_scratch_database, make_scratch_database, run_alembic
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_preparation as preparation_probes
from tests.services import test_agent_release_publication as publication_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes

OLD = "026_agent_release_size"
NEW = "027_agent_release_references"


@pytest_asyncio.fixture
async def reference_database(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(deletion_probes.remover.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        yield f


async def migrate(f, *, direction="upgrade", revision=NEW, success=True):
    return await asyncio.to_thread(run_alembic, f.engine.url, direction, revision, expect_success=success)


async def schema(f):
    async with f.engine.connect() as db:
        triggers = (await db.execute(text("""
            SELECT c.relname,t.tgname,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,
                   pg_get_triggerdef(t.oid)
            FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
            WHERE t.tgrelid IN ('agents.agent_releases'::regclass,'agents.agent_release_operations'::regclass)
              AND NOT t.tgisinternal ORDER BY c.relname,t.tgname
        """))).all()
        functions = (await db.execute(text("""
            SELECT p.proname,pg_get_functiondef(p.oid) FROM pg_proc p
            JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='agents' AND p.proname IN
              ('guard_release_operation','lock_release_references','assert_release_reference','check_release_references')
            ORDER BY p.proname
        """))).all()
        revision = await db.scalar(text("SELECT version_num FROM alembic_version"))
        indexes = (await db.execute(text("""
            SELECT indexname,indexdef FROM pg_indexes WHERE schemaname='agents'
              AND tablename IN ('agent_releases','agent_release_operations') ORDER BY indexname
        """))).all()
        constraints = (await db.execute(text("""
            SELECT c.conrelid::regclass::text,c.conname,c.convalidated,pg_get_constraintdef(c.oid)
            FROM pg_constraint c WHERE c.conrelid IN
              ('agents.agent_releases'::regclass,'agents.agent_release_operations'::regclass)
            ORDER BY c.conrelid::regclass::text,c.conname
        """))).all()
    return (tuple(map(tuple, triggers)), tuple(map(tuple, functions)), revision,
            tuple(map(tuple, indexes)), tuple(map(tuple, constraints)))


async def owned_target(f):
    credential = await lifecycle_probes.headers(f)
    row = await deletion_probes.target(f, credential, organization=f.org)
    return row, credential


def sqlstate(exc):
    return getattr(exc.orig, "sqlstate", None)


async def refused(f, statement, *, code="23514"):
    before = await deletion_probes.state(f)
    with pytest.raises(DBAPIError) as caught:
        async with f.engine.begin() as db:
            await db.execute(statement)
    assert sqlstate(caught.value) == code
    assert await deletion_probes.state(f) == before


@pytest.mark.parametrize("storage", ["owned", "external", "legacy"])
@pytest.mark.parametrize("credential_kind", ["jwt", "key"])
async def test_actual_publication_and_deletion_preserve_normal_supported_paths(reference_database, storage, credential_kind):
    f = reference_database
    await migrate(f)
    credential = await lifecycle_probes.headers(f, credential_kind)
    await deletion_probes.target(f, credential, storage=storage, organization=f.org)
    files = preparation_probes.files(f)
    response = await deletion_probes.call(f, credential)
    assert response.status_code == 200 and response.json()["decision"] == "deleted"
    assert not response.json()["cleanup_authorized"] and preparation_probes.files(f) == files
    before = await deletion_probes.state(f)
    assert (await deletion_probes.call(f, credential)).status_code == 200
    assert await deletion_probes.state(f) == before


async def test_existing_valid_owned_history_is_preserved_without_adoption_or_rewrite(reference_database):
    f = reference_database
    await owned_target(f)
    before = await deletion_probes.state(f)
    await migrate(f)
    installed = await schema(f)
    assert installed[2] == NEW and len(installed[0]) == 6 and len(installed[1]) == 4
    assert await deletion_probes.state(f) == before
    await migrate(f)
    assert await schema(f) == installed and await deletion_probes.state(f) == before


async def test_empty_fresh_install_and_installed_upgrade_have_exact_same_native_guards(reference_database, maintenance_engine):
    f = reference_database
    await migrate(f)
    expected = await schema(f)
    name = "freesdn_release_references_" + uuid4().hex[:12]
    url = await asyncio.to_thread(make_scratch_database, maintenance_engine, name)
    engine = create_async_engine(url.set(drivername="postgresql+asyncpg"))
    try:
        await asyncio.to_thread(run_alembic, url, "upgrade", NEW)
        assert await schema(SimpleNamespace(engine=engine)) == expected
    finally:
        await engine.dispose()
        await asyncio.to_thread(drop_scratch_database, maintenance_engine, name)


@pytest.mark.parametrize("change", ["missing", "owner", "size", "hash", "url", "filename"])
async def test_upgrade_refuses_inconsistent_retained_history_without_repair(reference_database, change):
    f = reference_database
    row, _ = await owned_target(f)
    async with f.engine.begin() as db:
        if change == "missing":
            await db.execute(delete(AgentRelease).where(AgentRelease.id == row["id"]))
        else:
            values = {"owner": {"organization_id": f.other_org}, "size": {"file_size": 100},
                      "hash": {"checksum_sha256": "f" * 64}, "url": {"download_url": "/other"},
                      "filename": {"filename": None}}[change]
            await db.execute(update(AgentRelease).where(AgentRelease.id == row["id"]).values(**values))
    before, before_schema = await deletion_probes.state(f), await schema(f)
    result = await migrate(f, success=False)
    assert result.returncode != 0 and "Managed release" in result.stderr
    assert await deletion_probes.state(f) == before and await schema(f) == before_schema


@pytest.mark.parametrize("change", ["id", "owner", "size", "hash", "url", "filename-none", "filename-empty"])
async def test_raw_writer_cannot_rebind_a_live_managed_reference(reference_database, change):
    f = reference_database
    await migrate(f)
    row, _ = await owned_target(f)
    values = {"id": {"id": uuid4()}, "owner": {"organization_id": f.other_org},
              "size": {"file_size": 100}, "hash": {"checksum_sha256": "f" * 64},
              "url": {"download_url": "/other"}, "filename-none": {"filename": None},
              "filename-empty": {"filename": ""}}[change]
    await refused(f, update(AgentRelease).where(AgentRelease.id == row["id"]).values(**values))


@pytest.mark.parametrize("change", ["count", "latest", "notes"])
async def test_reference_fence_does_not_claim_authentication_or_block_nonreference_fields(reference_database, change):
    f = reference_database
    await migrate(f)
    row, _ = await owned_target(f)
    values = {"count": {"download_count": 27}, "latest": {"is_latest": False},
              "notes": {"release_notes": "unchanged physical reference"}}[change]
    files = preparation_probes.files(f)
    async with f.engine.begin() as db:
        await db.execute(update(AgentRelease).where(AgentRelease.id == row["id"]).values(**values))
    actual = next(r for r in await publication_probes.releases(f) if r["id"] == row["id"])
    assert actual == {**row, **values} and preparation_probes.files(f) == files


@pytest.mark.parametrize("action", ["delete", "truncate"])
async def test_raw_removal_without_retained_decision_is_refused(reference_database, action):
    f = reference_database
    await migrate(f)
    row, _ = await owned_target(f)
    statement = delete(AgentRelease).where(AgentRelease.id == row["id"]) if action == "delete" else text("TRUNCATE agents.agent_releases")
    await refused(f, statement)


@pytest.mark.parametrize("change", ["artifact", "owner", "size", "hash", "release"])
async def test_raw_owned_deletion_must_match_its_exact_publication(reference_database, change):
    f = reference_database
    await migrate(f)
    row, _ = await owned_target(f)
    history = next(r for r in (await deletion_probes.state(f))[1] if r["kind"] == "publish")
    attempt = {**history, "operation_id": uuid4(), "kind": "delete", "phase": "reserved",
               "decision": None, "transition_sequence": 0, "prepared_at": None, "decided_at": None,
               "cleaned_at": None, "created_at": datetime.now(UTC)}
    attempt.update({"artifact": {"artifact_id": uuid4()}, "owner": {"organization_id": f.other_org},
                    "size": {"expected_size": row["file_size"] + 1}, "hash": {"expected_sha256": "f" * 64},
                    "release": {"release_id": uuid4()}}[change])
    await refused(f, insert(AgentReleaseOperation).values(**attempt))


async def test_deleted_managed_release_cannot_be_resurrected_by_an_independent_insert(reference_database):
    f = reference_database
    await migrate(f)
    row, credential = await owned_target(f)
    assert (await deletion_probes.call(f, credential)).status_code == 200
    await refused(f, insert(AgentRelease).values(**row))


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
async def test_unsupported_stale_snapshot_isolation_is_refused_before_writing(reference_database, isolation):
    f = reference_database
    await migrate(f)
    row, _ = await owned_target(f)
    before = await deletion_probes.state(f)
    with pytest.raises(DBAPIError) as caught:
        async with f.engine.connect() as db:
            db = await db.execution_options(isolation_level=isolation)
            async with db.begin():
                await db.execute(update(AgentRelease).where(AgentRelease.id == row["id"]).values(download_count=9))
    assert sqlstate(caught.value) == "23514" and await deletion_probes.state(f) == before


@pytest.mark.parametrize("committed", [False, True])
async def test_actual_waiting_reinsertion_observes_delete_commit_or_rollback(reference_database, committed, record_property):
    f = reference_database
    await migrate(f)
    row, credential = await owned_target(f)
    f.deletion_action = "reserve"
    assert (await deletion_probes.call(f, credential)).status_code == 200
    before = await deletion_probes.state(f)
    candidate_pid = None
    launched = asyncio.Event()

    async def reinsert():
        nonlocal candidate_pid
        async with f.engine.connect() as db:
            transaction = await db.begin()
            try:
                candidate_pid = await db.scalar(text("SELECT pg_backend_pid()"))
                await db.execute(text("SET LOCAL lock_timeout = '8s'"))
                launched.set()
                await db.execute(insert(AgentRelease).values(**row))
                await transaction.commit()
                return None
            except DBAPIError as exc:
                await transaction.rollback()
                return sqlstate(exc)

    async with f.engine.connect() as db:
        transaction = await db.begin()
        writer_pid = await db.scalar(text("SELECT pg_backend_pid()"))
        operation = f.deletion.operation_id
        # Service reservations use the database clock; avoid ordering against a
        # potentially skewed client wall clock in this raw transition fixture.
        now = await db.scalar(text("SELECT clock_timestamp()"))
        await db.execute(update(AgentReleaseOperation).where(AgentReleaseOperation.operation_id == operation)
                         .values(phase="prepared", transition_sequence=1, prepared_at=now))
        await db.execute(delete(AgentRelease).where(AgentRelease.id == row["id"]))
        await db.execute(update(AgentReleaseOperation).where(AgentReleaseOperation.operation_id == operation)
                         .values(phase="decided", decision="deleted", transition_sequence=2, decided_at=now))
        task = asyncio.create_task(reinsert())
        try:
            await asyncio.wait_for(launched.wait(), 5)
            assert candidate_pid != writer_pid
            observed = False
            async with f.engine.connect() as observer:
                for _ in range(100):
                    blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": candidate_pid})
                    if writer_pid in blockers:
                        observed = True
                        break
                    if task.done():
                        break
                    await asyncio.sleep(.025)
            assert observed, "The original real writer wait must occur"
            record_property("reference_reinsert_actual_table_wait", True)
            record_property("reference_distinct_writer_and_reinsert_connections", True)
            if committed:
                await transaction.commit()
            else:
                await transaction.rollback()
            assert await asyncio.wait_for(task, 8) == ("23514" if committed else "23505")
        finally:
            if transaction.is_active:
                await transaction.rollback()
            if not task.done():
                await asyncio.wait_for(task, 8)
    after = await deletion_probes.state(f)
    assert after[2] == before[2]
    if committed:
        assert after[0] == [] and (await deletion_probes.delete_row(f))["decision"] == "deleted"
    else:
        assert after == before


@pytest.mark.parametrize("committed", [False, True])
async def test_migration_validates_real_writer_result_after_proven_table_wait(reference_database, committed, record_property):
    f = reference_database
    row, _ = await owned_target(f)
    original = await deletion_probes.state(f)
    old_schema = await schema(f)
    async with f.engine.connect() as writer:
        transaction = await writer.begin()
        writer_pid = await writer.scalar(text("SELECT pg_backend_pid()"))
        await writer.execute(update(AgentRelease).where(AgentRelease.id == row["id"]).values(checksum_sha256="f" * 64))
        task = asyncio.create_task(migrate(f, success=False))
        observed = False
        try:
            async with f.engine.connect() as observer:
                for _ in range(400):
                    # pg_stat_activity is cached within an observer transaction.
                    # Refresh only this read-only observer, never the writer.
                    await observer.rollback()
                    matches = (await observer.execute(text("""
                        SELECT pid,pg_blocking_pids(pid) FROM pg_stat_activity
                        WHERE datname=current_database() AND pid<>:writer AND wait_event_type='Lock'
                          AND query LIKE 'LOCK TABLE agents.agent_release_operations, agents.agent_releases%'
                    """), {"writer": writer_pid})).all()
                    if any(writer_pid in blockers for _, blockers in matches):
                        observed = True
                        break
                    if task.done():
                        break
                    await asyncio.sleep(.025)
            assert observed, "Original migration must genuinely wait on the owned writer"
            record_property("reference_migration_actual_table_wait", True)
            if committed:
                await transaction.commit()
            else:
                await transaction.rollback()
            result = await asyncio.wait_for(asyncio.shield(task), 30)
        finally:
            if transaction.is_active:
                await transaction.rollback()
            if not task.done():
                await task
    after = await deletion_probes.state(f)
    assert after[1:] == original[1:]
    if committed:
        assert result.returncode != 0 and "Managed release reference" in result.stderr
        assert await schema(f) == old_schema
        assert after[0] == [{**row, "checksum_sha256": "f" * 64}]
    else:
        assert result.returncode == 0 and (await schema(f))[2] == NEW
        assert after == original


@pytest.mark.parametrize("stage", ["reserved", "prepared", "published", "deleted", "cancelled", "cleaned"])
async def test_downgrade_refuses_every_retained_owned_history_phase(reference_database, stage):
    f = reference_database
    await migrate(f)
    credential = await lifecycle_probes.headers(f)
    publication_probes.configure(f, organization=f.org)
    if stage in ("published", "deleted", "cleaned"):
        await deletion_probes.target(f, credential, organization=f.org)
        if stage != "published":
            assert (await deletion_probes.call(f, credential)).status_code == 200
        if stage == "cleaned":
            async with f.engine.begin() as db:
                await db.execute(update(AgentReleaseOperation).where(AgentReleaseOperation.operation_id == f.deletion.operation_id)
                                 .values(phase="cleaned", transition_sequence=3, cleaned_at=func.clock_timestamp()))
    else:
        # The preparation route establishes a real acknowledged reservation;
        # reserve-only uses the original reservation harness below.
        f.action = "reserve"
        assert (await reservation_probes.call(f, credential)).status_code == 200
        if stage == "prepared":
            assert (await preparation_probes.call(f, credential)).status_code == 200
        elif stage == "cancelled":
            f.action = "cancel"
            assert (await reservation_probes.call(f, credential)).status_code == 200
    before, before_schema = await deletion_probes.state(f), await schema(f)
    result = await migrate(f, direction="downgrade", revision=OLD, success=False)
    assert result.returncode != 0 and "downgrade refused while owned history remains" in result.stderr
    assert await schema(f) == before_schema and await deletion_probes.state(f) == before


async def test_external_and_legacy_history_allow_guard_removal_without_data_changes(reference_database):
    f = reference_database
    await migrate(f)
    credential = await lifecycle_probes.headers(f)
    await deletion_probes.target(f, credential, storage="external", organization=f.org)
    await publication_probes.seed(f, organization=f.other_org)
    before = await deletion_probes.state(f)
    await migrate(f, direction="downgrade", revision=OLD)
    assert await deletion_probes.state(f) == before and (await schema(f))[2] == OLD
    await migrate(f)
    assert await deletion_probes.state(f) == before


@pytest.mark.parametrize("drift", ["disabled", "immediate", "missing", "security-definer", "search-path", "body"])
async def test_native_guard_drift_is_refused_without_overwriting_evidence(reference_database, drift):
    f = reference_database
    await migrate(f)
    statements = {
        "disabled": "ALTER TABLE agents.agent_releases DISABLE TRIGGER release_reference_deferred",
        "missing": "DROP TRIGGER release_reference_deferred ON agents.agent_releases",
        "security-definer": "ALTER FUNCTION agents.check_release_references() SECURITY DEFINER",
        "search-path": "ALTER FUNCTION agents.check_release_references() SET search_path = public",
        "body": "CREATE OR REPLACE FUNCTION agents.check_release_references() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$",
    }
    async with f.engine.begin() as db:
        if drift == "immediate":
            # User constraint triggers cannot use ALTER CONSTRAINT (FK-only).
            await db.execute(text("DROP TRIGGER release_reference_deferred ON agents.agent_releases"))
            await db.execute(text("CREATE CONSTRAINT TRIGGER release_reference_deferred AFTER INSERT OR UPDATE OR DELETE "
                                  "ON agents.agent_releases NOT DEFERRABLE FOR EACH ROW "
                                  "EXECUTE FUNCTION agents.check_release_references()"))
        else:
            await db.execute(text(statements[drift]))
    before, before_schema = await deletion_probes.state(f), await schema(f)
    result = await migrate(f, direction="downgrade", revision=OLD, success=False)
    assert result.returncode != 0 and "Release reference" in result.stderr
    assert await schema(f) == before_schema and await deletion_probes.state(f) == before


@pytest.mark.parametrize("drift", ["disabled-immutability", "function-body", "publish-index", "artifact-index", "phase-check"])
async def test_original_journal_guards_are_required_before_installing_reference_fence(reference_database, drift):
    f = reference_database
    statements = {
        "disabled-immutability": "ALTER TABLE agents.agent_release_operations DISABLE TRIGGER guard_release_operation",
        "function-body": "CREATE OR REPLACE FUNCTION agents.guard_release_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
        "publish-index": "DROP INDEX agents.uq_release_operation_publish_identity",
        "artifact-index": "DROP INDEX agents.uq_release_operation_owned_object",
        "phase-check": "ALTER TABLE agents.agent_release_operations DROP CONSTRAINT ck_agent_release_operations_decision_kind",
    }
    async with f.engine.begin() as db:
        await db.execute(text(statements[drift]))
    before, before_schema = await deletion_probes.state(f), await schema(f)
    result = await migrate(f, success=False)
    assert result.returncode != 0 and "Release operation" in result.stderr
    assert await schema(f) == before_schema and await deletion_probes.state(f) == before


@pytest.mark.parametrize("partial", ["function-only", "overload", "one-trigger"])
async def test_partial_install_is_refused_without_overwrite_or_schema_repair(reference_database, partial):
    f = reference_database
    async with f.engine.begin() as db:
        if partial == "overload":
            await db.execute(text("CREATE FUNCTION agents.lock_release_references(integer) RETURNS integer LANGUAGE sql AS 'SELECT $1'"))
        else:
            for statement in REFERENCE_DDL[:1 if partial == "function-only" else 3]:
                await db.execute(text(statement))
            if partial == "one-trigger":
                await db.execute(text(REFERENCE_DDL[5]))
    before, before_schema = await deletion_probes.state(f), await schema(f)
    result = await migrate(f, success=False)
    assert result.returncode != 0 and "Release reference" in result.stderr
    assert await schema(f) == before_schema and await deletion_probes.state(f) == before


async def test_late_revision_refusal_rolls_back_all_new_guard_DDL(reference_database):
    f = reference_database
    await owned_target(f)
    async with f.engine.begin() as db:
        await db.execute(text("CREATE FUNCTION public.owned_refuse_reference_revision() RETURNS trigger LANGUAGE plpgsql AS $$ "
                              "BEGIN RAISE EXCEPTION 'owned reference revision refusal'; END $$"))
        await db.execute(text("CREATE TRIGGER owned_refuse_reference_revision BEFORE UPDATE ON alembic_version "
                              "FOR EACH ROW EXECUTE FUNCTION public.owned_refuse_reference_revision()"))
    before, before_schema = await deletion_probes.state(f), await schema(f)
    result = await migrate(f, success=False)
    assert result.returncode != 0 and "owned reference revision refusal" in result.stderr
    assert await schema(f) == before_schema and await deletion_probes.state(f) == before
