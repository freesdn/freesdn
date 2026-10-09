# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""AFTER-only journal schema contracts; not endpoint or filesystem acceptance.

Owned scratch PostgreSQL and the actual frozen migration chain. Request bytes
are synthetic public metadata. No real artifact, credential or key is accessed.
"""
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    make_scratch_database,
    run_alembic,
    scratch_engine,
)

OLD = "024_agent_signing_enrollment"
NEW = "025_agent_release_operations"
TABLE = "agents.agent_release_operations"


@pytest.fixture
def operation_database(maintenance_engine):
    name = "freesdn_release_operation_" + uuid4().hex[:12]
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", OLD)
        with engine.connect() as c:
            assert c.scalar(sa.text("SELECT to_regclass(:name)"), {"name": TABLE}) is None
        run_alembic(url, "upgrade", NEW)
        yield engine, url
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


def values(*, kind="publish", storage="owned", organization=None):
    operation = uuid4()
    actor = uuid4()
    request = b'{"synthetic":"owned release intent"}'
    return {"operation_id": operation, "format_version": 1, "kind": kind,
            "release_id": uuid4(), "organization_id": organization, "requested_by": actor,
            "storage_kind": storage, "artifact_id": operation if storage == "owned" else None,
            "request_bytes": request, "request_sha256": hashlib.sha256(request).hexdigest(),
            "expected_sha256": "a" * 64, "expected_size": 5, "phase": "reserved",
            "decision": None, "transition_sequence": 0, "created_at": datetime.now(UTC),
            "prepared_at": None, "decided_at": None, "cleaned_at": None, "last_transition_by": actor}


def table(c):
    return sa.Table("agent_release_operations", sa.MetaData(), schema="agents", autoload_with=c)


def insert(c, value):
    c.execute(table(c).insert().values(**value))


def transition(c, value, phase, decision=None):
    t = table(c)
    current = c.execute(sa.select(t).where(t.c.operation_id == value["operation_id"])).mappings().one()
    data = {"phase": phase, "transition_sequence": current["transition_sequence"] + 1,
            "last_transition_by": value["requested_by"]}
    if phase == "prepared":
        data["prepared_at"] = value["created_at"] + timedelta(seconds=1)
    elif phase == "decided":
        data.update(decision=decision, decided_at=value["created_at"] + timedelta(seconds=2))
    elif phase == "cleaned":
        data["cleaned_at"] = value["created_at"] + timedelta(seconds=3)
    c.execute(t.update().where(t.c.operation_id == value["operation_id"]).values(**data))


def rows(engine):
    with engine.connect() as c:
        t = table(c)
        return [dict(r) for r in c.execute(sa.select(t).order_by(t.c.operation_id)).mappings()]


def shape(engine):
    with engine.connect() as c:
        columns = c.execute(sa.text("""SELECT attname,format_type(atttypid,atttypmod),attnotnull
            FROM pg_attribute WHERE attrelid='agents.agent_release_operations'::regclass
            AND attnum>0 AND NOT attisdropped ORDER BY attnum""")).all()
        constraints = c.execute(sa.text("""SELECT conname,pg_get_constraintdef(oid),convalidated
            FROM pg_constraint WHERE conrelid='agents.agent_release_operations'::regclass ORDER BY conname""")).all()
        indexes = c.execute(sa.text("""SELECT indexname,indexdef FROM pg_indexes
            WHERE schemaname='agents' AND tablename='agent_release_operations' ORDER BY indexname""")).all()
        triggers = c.execute(sa.text("""SELECT tgname,pg_get_triggerdef(oid),tgenabled
            FROM pg_trigger WHERE tgrelid='agents.agent_release_operations'::regclass
            AND NOT tgisinternal ORDER BY tgname""")).all()
        function = c.execute(sa.text("""SELECT prosrc,proconfig,prosecdef FROM pg_proc
            WHERE oid='agents.guard_release_operation()'::regprocedure""")).one()
        policy = c.execute(sa.text("""SELECT relpersistence,relrowsecurity,relforcerowsecurity
            FROM pg_class WHERE oid='agents.agent_release_operations'::regclass""")).one()
    return columns, constraints, indexes, triggers, function, policy


def test_fresh_model_and_incremental_journal_match_without_backfill(operation_database, maintenance_engine):
    engine, _ = operation_database
    assert rows(engine) == []
    name = "freesdn_release_operation_fresh_" + uuid4().hex[:12]
    url = make_scratch_database(maintenance_engine, name)
    fresh = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", NEW)
        assert rows(fresh) == [] and shape(fresh) == shape(engine)
        with fresh.connect() as c:
            assert c.scalar(sa.text("SELECT count(*) FROM agents.agent_releases")) == 0
    finally:
        fresh.dispose()
        drop_scratch_database(maintenance_engine, name)


@pytest.mark.parametrize("kind,storage", [("publish", "owned"), ("publish", "external"), ("delete", "owned"), ("delete", "external"), ("delete", "legacy")])
@pytest.mark.parametrize("cancel", [False, True])
def test_prepared_decision_and_cleanup_keep_original_intent(operation_database, kind, storage, cancel):
    engine, _ = operation_database
    value = values(kind=kind, storage=storage)
    with engine.begin() as c:
        insert(c, value)
    with engine.begin() as c:
        transition(c, value, "prepared")
    decision = "cancelled" if cancel else {"publish": "published", "delete": "deleted"}[kind]
    with engine.begin() as c:
        transition(c, value, "decided", decision)
    if decision != "published":
        with engine.begin() as c:
            transition(c, value, "cleaned")
    row = rows(engine)[0]
    assert row["decision"] == decision and row["request_bytes"] == value["request_bytes"]
    assert row["request_sha256"] == value["request_sha256"] and row["artifact_id"] == value["artifact_id"]
    assert row["phase"] == ("decided" if decision == "published" else "cleaned")


@pytest.mark.parametrize("kind", ["publish", "delete"])
@pytest.mark.parametrize("has_org", [False, True])
def test_cancel_before_storage_retains_scope_and_history(operation_database, kind, has_org):
    engine, _ = operation_database
    value = values(kind=kind, organization=uuid4() if has_org else None)
    with engine.begin() as c:
        insert(c, value)
        transition(c, value, "decided", "cancelled")
        transition(c, value, "cleaned")
    row = rows(engine)[0]
    assert row["prepared_at"] is None and row["transition_sequence"] == 2
    assert row["requested_by"] == value["requested_by"] and row["organization_id"] == value["organization_id"]


@pytest.mark.parametrize("mutation", ["format", "kind", "storage", "legacy_publish", "missing_object", "wrong_object", "external_object", "empty_request", "large_request", "bad_request_hash", "uppercase_digest", "negative_size", "large_owned_size", "large_external_size", "future_phase", "initial_sequence", "initial_actor", "null_actor"])
def test_invalid_reservation_refused_without_retained_partial_row(operation_database, mutation):
    engine, _ = operation_database
    value = values()
    changes = {
        "format": {"format_version": 2}, "kind": {"kind": "replace"}, "storage": {"storage_kind": "unknown"},
        "legacy_publish": {"storage_kind": "legacy", "artifact_id": None},
        "missing_object": {"artifact_id": None}, "wrong_object": {"artifact_id": uuid4()},
        "external_object": {"storage_kind": "external"}, "empty_request": {"request_bytes": b""},
        "large_request": {"request_bytes": b"x" * 65537}, "bad_request_hash": {"request_sha256": "b" * 64},
        "uppercase_digest": {"expected_sha256": "A" * 64}, "negative_size": {"expected_size": -1},
        "large_owned_size": {"expected_size": 524288001},
        "large_external_size": {"storage_kind": "external", "artifact_id": None, "expected_size": 10737418241},
        "future_phase": {"phase": "prepared", "prepared_at": value["created_at"], "transition_sequence": 1},
        "initial_sequence": {"transition_sequence": 1}, "initial_actor": {"last_transition_by": uuid4()},
        "null_actor": {"requested_by": None, "last_transition_by": None},
    }
    value.update(changes[mutation])
    if mutation in {"empty_request", "large_request"}:
        value["request_sha256"] = hashlib.sha256(value["request_bytes"]).hexdigest()
    with pytest.raises(sa.exc.DBAPIError), engine.begin() as c:
        insert(c, value)
    assert rows(engine) == []


@pytest.mark.parametrize("field", ["operation_id", "format_version", "kind", "release_id", "organization_id", "requested_by", "storage_kind", "artifact_id", "request_bytes", "request_sha256", "expected_sha256", "expected_size", "created_at"])
def test_reserved_intent_cannot_be_rebound(operation_database, field):
    engine, _ = operation_database
    value = values()
    with engine.begin() as c:
        insert(c, value)
    before = rows(engine)
    change = {"operation_id": uuid4(), "format_version": 2, "kind": "delete", "release_id": uuid4(),
              "organization_id": uuid4(), "requested_by": uuid4(), "storage_kind": "external", "artifact_id": uuid4(),
              "request_bytes": b"changed", "request_sha256": "b" * 64, "expected_sha256": "b" * 64,
              "expected_size": 6, "created_at": value["created_at"] + timedelta(seconds=1)}[field]
    with pytest.raises(sa.exc.DBAPIError), engine.begin() as c:
        t = table(c)
        c.execute(t.update().where(t.c.operation_id == value["operation_id"]).values(**{field: change}))
    assert rows(engine) == before


@pytest.mark.parametrize("mutation", ["publish_unprepared", "opposite_decision", "published_cleanup", "rewrite_decision", "rewind", "rewrite_prepare", "rewrite_decide", "negative_time", "null_cleaned_decision"])
def test_decision_cannot_skip_rewind_or_become_cleanup_authority(operation_database, mutation):
    engine, _ = operation_database
    value = values()
    with engine.begin() as c:
        insert(c, value)
        if mutation != "publish_unprepared":
            transition(c, value, "prepared")
        if mutation in {"published_cleanup", "rewrite_decision", "rewind", "rewrite_decide"}:
            transition(c, value, "decided", "published")
        if mutation == "null_cleaned_decision":
            transition(c, value, "decided", "cancelled")
    before = rows(engine)
    with pytest.raises(sa.exc.DBAPIError), engine.begin() as c:
        t = table(c)
        data = {
            "publish_unprepared": {"phase": "decided", "decision": "published", "decided_at": value["created_at"], "transition_sequence": 1},
            "opposite_decision": {"phase": "decided", "decision": "deleted", "decided_at": value["created_at"] + timedelta(seconds=2), "transition_sequence": 2},
            "published_cleanup": {"phase": "cleaned", "cleaned_at": value["created_at"] + timedelta(seconds=3), "transition_sequence": 3},
            "rewrite_decision": {"decision": "cancelled", "transition_sequence": 3},
            "rewind": {"phase": "reserved", "decision": None, "decided_at": None, "prepared_at": None, "transition_sequence": 0},
            "rewrite_prepare": {"prepared_at": value["created_at"] + timedelta(seconds=2), "transition_sequence": 2},
            "rewrite_decide": {"decided_at": value["created_at"] + timedelta(seconds=3), "transition_sequence": 3},
            "negative_time": {"phase": "decided", "decision": "cancelled", "decided_at": value["created_at"] - timedelta(seconds=1), "transition_sequence": 2},
            "null_cleaned_decision": {"phase": "cleaned", "decision": None, "cleaned_at": value["created_at"] + timedelta(seconds=3), "transition_sequence": 3},
        }[mutation]
        c.execute(t.update().where(t.c.operation_id == value["operation_id"]).values(**data))
    assert rows(engine) == before


@pytest.mark.parametrize("phase", ["reserved", "prepared", "published", "cancelled", "cleaned"])
@pytest.mark.parametrize("action", ["delete", "truncate", "downgrade"])
def test_history_survives_destructive_requests(operation_database, phase, action):
    engine, url = operation_database
    value = values()
    with engine.begin() as c:
        insert(c, value)
        if phase != "reserved":
            transition(c, value, "prepared")
        if phase in {"published", "cancelled", "cleaned"}:
            transition(c, value, "decided", "published" if phase == "published" else "cancelled")
        if phase == "cleaned":
            transition(c, value, "cleaned")
    before = rows(engine), shape(engine)
    if action == "downgrade":
        result = run_alembic(url, "downgrade", OLD, expect_success=False)
        assert result.returncode != 0 and "history remains" in result.stderr
    else:
        with pytest.raises(sa.exc.DBAPIError), engine.begin() as c:
            c.execute(sa.text("DELETE FROM agents.agent_release_operations" if action == "delete" else "TRUNCATE agents.agent_release_operations"))
    assert (rows(engine), shape(engine)) == before


def test_empty_downgrade_and_reupgrade_does_not_adopt_artifacts(operation_database):
    engine, url = operation_database
    run_alembic(url, "downgrade", OLD)
    with engine.connect() as c:
        assert c.scalar(sa.text("SELECT to_regclass(:name)"), {"name": TABLE}) is None
    run_alembic(url, "upgrade", NEW)
    assert rows(engine) == []


@pytest.mark.parametrize("mutation", ["disable_trigger", "drop_trigger", "drop_check", "request_type", "unexpected_column", "row_security", "unlogged", "guard_body"])
def test_upgrade_refuses_native_drift_without_repair(operation_database, mutation):
    engine, url = operation_database
    statements = {
        "disable_trigger": "ALTER TABLE agents.agent_release_operations DISABLE TRIGGER guard_release_operation",
        "drop_trigger": "DROP TRIGGER guard_release_operation_no_truncate ON agents.agent_release_operations",
        "drop_check": "ALTER TABLE agents.agent_release_operations DROP CONSTRAINT ck_agent_release_operations_request_binding",
        "request_type": "ALTER TABLE agents.agent_release_operations ALTER COLUMN request_sha256 TYPE varchar(128)",
        "unexpected_column": "ALTER TABLE agents.agent_release_operations ADD COLUMN unwanted integer",
        "row_security": "ALTER TABLE agents.agent_release_operations ENABLE ROW LEVEL SECURITY",
        "unlogged": "ALTER TABLE agents.agent_release_operations SET UNLOGGED",
        "guard_body": "CREATE OR REPLACE FUNCTION agents.guard_release_operation() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$BEGIN RETURN NEW; END$$",
    }
    with engine.begin() as c:
        c.execute(sa.text(statements[mutation]))
    run_alembic(url, "stamp", OLD)
    before = shape(engine)
    result = run_alembic(url, "upgrade", NEW, expect_success=False)
    assert result.returncode != 0 and shape(engine) == before
    with engine.connect() as c:
        assert c.scalar(sa.text("SELECT version_num FROM alembic_version")) == OLD


@pytest.mark.parametrize("kind", ["publish", "delete"])
def test_actual_unique_wait_serializes_one_unresolved_release(operation_database, kind, record_property):
    engine, _ = operation_database
    first = values(kind=kind)
    second = values(kind="delete")
    second["release_id"] = first["release_id"]
    pids = []

    def reserve_second():
        try:
            with engine.begin() as c:
                pids.append(c.scalar(sa.text("SELECT pg_backend_pid()")))
                c.execute(sa.text("SET LOCAL statement_timeout='8s'"))
                insert(c, second)
        except sa.exc.IntegrityError:
            return "conflict"
        return "committed"

    with engine.connect() as holder, ThreadPoolExecutor(max_workers=1) as pool:
        transaction = holder.begin()
        pid = holder.scalar(sa.text("SELECT pg_backend_pid()"))
        insert(holder, first)
        task = pool.submit(reserve_second)
        try:
            deadline = time.monotonic() + 5
            with engine.connect() as observer:
                while True:
                    assert not task.done(), "Second reservation did not wait on the actual unique decision"
                    if pids and pid in observer.scalar(sa.text("SELECT pg_blocking_pids(:pid)"), {"pid": pids[0]}):
                        assert pid != pids[0]
                        record_property("genuine_operation_unique_wait", True)
                        break
                    assert time.monotonic() < deadline
                    time.sleep(0.01)
            transaction.commit()
            assert task.result(timeout=8) == "conflict"
        finally:
            if transaction.is_active:
                transaction.rollback()
        assert [r["operation_id"] for r in rows(engine)] == [first["operation_id"]]
