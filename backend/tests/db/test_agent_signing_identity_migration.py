# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""AFTER-only schema contracts on owned scratch PostgreSQL databases.

These do not authenticate initialization or qualify private storage/HTTP/agents.
They must not be treated as baseline defects merely because revision 023 is new.
"""

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    make_scratch_database,
    run_alembic,
    scratch_engine,
)

OLD = "022_sso_binding_unique"
NEW = "023_agent_signing_identity"


@pytest.fixture
def signing_database(maintenance_engine):
    name = "freesdn_signing_schema_" + uuid4().hex[:12]
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", OLD)
        with engine.connect() as c:
            assert c.scalar(sa.text("SELECT to_regclass('agents.agent_signing_intents')")) is None
        yield engine, url
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


def snapshot(engine):
    with engine.connect() as c:
        revision = c.scalar(sa.text("SELECT version_num FROM alembic_version"))
        values = {}
        for table in ("agent_signing_intents", "agent_signing_identities"):
            if c.scalar(sa.text("SELECT to_regclass(:name)"), {"name": "agents." + table}):
                # Only fixed table names above are interpolated, never request data.
                values[table] = c.execute(sa.text(
                    f"SELECT to_jsonb(t) FROM agents.{table} t ORDER BY operation_id",
                )).scalars().all()
            else:
                values[table] = None
        schema = c.execute(sa.text("""
            SELECT c.relname, a.attname, format_type(a.atttypid,a.atttypmod), a.attnotnull
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_attribute a ON a.attrelid=c.oid
            WHERE n.nspname='agents' AND c.relname IN ('agent_signing_intents','agent_signing_identities')
              AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum
        """)).all()
        constraints = c.execute(sa.text("""
            SELECT conname, pg_get_constraintdef(oid), convalidated FROM pg_constraint
            WHERE conrelid IN (to_regclass('agents.agent_signing_intents'),
                               to_regclass('agents.agent_signing_identities')) ORDER BY conname
        """)).all()
        guards = c.execute(sa.text("""
            SELECT tgname, pg_get_triggerdef(oid), tgenabled FROM pg_trigger
            WHERE tgrelid IN (to_regclass('agents.agent_signing_intents'),
                              to_regclass('agents.agent_signing_identities'))
              AND NOT tgisinternal ORDER BY tgname
        """)).all()
    return revision, values, schema, constraints, guards


def intent(*, kind="initialize", crlf=False):
    # New synthetic key only within the future owned test process, never a deployed key.
    pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if crlf:
        pem = pem.replace(b"\n", b"\r\n")
    return {"operation": uuid4(), "installation": uuid4(), "actor": uuid4(),
            "kind": kind, "created": datetime.now(UTC), "pem": pem,
            "fingerprint": hashlib.sha256(pem).hexdigest()}


def pending(c, values):
    c.execute(sa.text("""
        INSERT INTO agents.agent_signing_intents
          (operation_id,singleton_id,installation_id,identity_epoch,kind,expected_public_sha256,state,requested_by,created_at)
        VALUES (:operation,1,:installation,1,:kind,:expected,'pending',:actor,:created)
    """), {**values, "expected": values["fingerprint"] if values["kind"] == "adopt" else None})


def prepared(c, values):
    c.execute(sa.text("""
        UPDATE agents.agent_signing_intents SET state='prepared',public_key_pem=:pem,
          public_key_sha256=:fingerprint,prepared_at=:created WHERE operation_id=:operation
    """), values)


def closed(c, values, state):
    c.execute(sa.text("""
        UPDATE agents.agent_signing_intents SET state=:state,closed_at=:created,closed_by=:actor
        WHERE operation_id=:operation
    """), {**values, "state": state})


def activate(c, values):
    closed(c, values, "activated")
    c.execute(sa.text("""
        INSERT INTO agents.agent_signing_identities
          (singleton_id,format_version,purpose,installation_id,identity_epoch,operation_id,
           public_key_pem,public_key_sha256,activated_by,activated_at)
        VALUES (1,1,'agent-release',:installation,1,:operation,:pem,:fingerprint,:actor,:created)
    """), values)


def test_fresh_and_incremental_schema_match_without_initializing_keys(signing_database, maintenance_engine):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    expected = snapshot(engine)
    assert expected[0] == NEW and all(v == [] for v in expected[1].values())
    fresh_name = "freesdn_signing_fresh_" + uuid4().hex[:12]
    fresh_url = make_scratch_database(maintenance_engine, fresh_name)
    fresh = scratch_engine(fresh_url)
    try:
        run_alembic(fresh_url, "upgrade", NEW)
        assert snapshot(fresh) == expected
    finally:
        fresh.dispose()
        drop_scratch_database(maintenance_engine, fresh_name)


@pytest.mark.parametrize("kind", ["initialize", "adopt"])
@pytest.mark.parametrize("crlf", [False, True])
def test_pending_prepare_activate_retains_exact_public_bytes(signing_database, kind, crlf):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent(kind=kind, crlf=crlf)
    with engine.begin() as c:
        pending(c, value)
    assert snapshot(engine)[1]["agent_signing_identities"] == []
    with engine.begin() as c:
        prepared(c, value)
    assert snapshot(engine)[1]["agent_signing_identities"] == []
    with engine.begin() as c:
        activate(c, value)
    with engine.connect() as c:
        row = c.execute(sa.text("SELECT public_key_pem,public_key_sha256 FROM agents.agent_signing_identities")).one()
    assert bytes(row[0]) == value["pem"] and row[1] == value["fingerprint"]


@pytest.mark.parametrize("phase", ["pending", "prepared", "cancelled", "activated"])
def test_history_blocks_destructive_downgrade(signing_database, phase):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent()
    with engine.begin() as c:
        pending(c, value)
        if phase in {"prepared", "activated"}:
            prepared(c, value)
        if phase == "activated":
            activate(c, value)
        elif phase == "cancelled":
            closed(c, value, phase)
    before = snapshot(engine)
    result = run_alembic(url, "downgrade", OLD, expect_success=False)
    assert result.returncode != 0 and "retained identity or operation history" in result.stderr
    assert snapshot(engine) == before


def test_unused_schema_can_downgrade_and_reupgrade(signing_database):
    engine, url = signing_database
    before = snapshot(engine)
    run_alembic(url, "upgrade", NEW)
    accepted = snapshot(engine)
    run_alembic(url, "downgrade", OLD)
    assert snapshot(engine) == before
    run_alembic(url, "upgrade", NEW)
    assert snapshot(engine) == accepted


def test_deferred_activation_refuses_orphan_and_rolls_back(signing_database):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent()
    with engine.begin() as c:
        pending(c, value)
        prepared(c, value)
    before = snapshot(engine)
    with pytest.raises(sa.exc.IntegrityError, match="matching identity at commit"):
        with engine.begin() as c:
            closed(c, value, "activated")
    assert snapshot(engine) == before


@pytest.mark.parametrize("staged", [False, True])
def test_cancelled_intent_retains_history_and_allows_separate_retry(signing_database, staged):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent()
    with engine.begin() as c:
        pending(c, value)
        if staged:
            prepared(c, value)
        closed(c, value, "cancelled")
    before = snapshot(engine)
    with pytest.raises(sa.exc.IntegrityError, match="rewrite retained history"):
        with engine.begin() as c:
            c.execute(sa.text("UPDATE agents.agent_signing_intents SET state='pending',closed_at=NULL,closed_by=NULL"))
    assert snapshot(engine) == before
    with engine.begin() as c:
        pending(c, intent())
    after = snapshot(engine)[1]
    retained = [row for row in after["agent_signing_intents"] if row["operation_id"] == str(value["operation"])]
    assert retained == before[1]["agent_signing_intents"] and len(after["agent_signing_intents"]) == 2
    assert after["agent_signing_identities"] == []


@pytest.mark.parametrize("assignment", [
    "installation_id=:other", "requested_by=:other", "identity_epoch=2", "kind='adopt'",
    "public_key_pem=:pem,public_key_sha256=:fingerprint",
])
def test_prepared_intent_cannot_rebind_identity_during_close(signing_database, assignment):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent()
    with engine.begin() as c:
        pending(c, value)
        prepared(c, value)
    before = snapshot(engine)
    with pytest.raises(sa.exc.IntegrityError, match="rewrite retained history"):
        with engine.begin() as c:
            c.execute(sa.text("UPDATE agents.agent_signing_intents SET state='cancelled',"
                              "closed_at=:created,closed_by=:actor," + assignment),
                      {**intent(), "created": value["created"], "other": uuid4()})
    assert snapshot(engine) == before


@pytest.mark.parametrize("assignment", [
    "installation_id=:other", "identity_epoch=2", "operation_id=:other",
    "activated_by=:other", "activated_at=activated_at+interval '1 second'",
    "public_key_pem=:pem, public_key_sha256=:fingerprint",
])
def test_active_identity_cannot_be_replaced(signing_database, assignment):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent()
    with engine.begin() as c:
        pending(c, value)
        prepared(c, value)
        activate(c, value)
    before = snapshot(engine)
    replacement = {**intent(), "other": uuid4()}
    with pytest.raises(sa.exc.IntegrityError, match="Active signing identity is immutable"):
        with engine.begin() as c:
            c.execute(sa.text("UPDATE agents.agent_signing_identities SET " + assignment), replacement)
    assert snapshot(engine) == before


@pytest.mark.parametrize("statement", [
    "DELETE FROM agents.agent_signing_identities",
    "DELETE FROM agents.agent_signing_intents",
    "TRUNCATE agents.agent_signing_identities",
    "TRUNCATE agents.agent_signing_intents CASCADE",
])
def test_active_history_cannot_be_deleted(signing_database, statement):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent()
    with engine.begin() as c:
        pending(c, value)
        prepared(c, value)
        activate(c, value)
    before = snapshot(engine)
    with pytest.raises(sa.exc.IntegrityError, match="cannot be deleted"):
        with engine.begin() as c:
            c.execute(sa.text(statement))
    assert snapshot(engine) == before


@pytest.mark.parametrize("case", ["empty", "oversize", "hash", "upper-hash", "null-pem", "null-hash", "past-prepared"])
def test_prepared_public_binding_has_no_null_or_size_escape(signing_database, case):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent()
    with engine.begin() as c:
        pending(c, value)
    before = snapshot(engine)
    changed = dict(value)
    if case in {"empty", "oversize"}:
        changed["pem"] = b"" if case == "empty" else b"x" * 4097
        changed["fingerprint"] = hashlib.sha256(changed["pem"]).hexdigest()
    elif case == "hash":
        changed["fingerprint"] = "0" * 64
    elif case == "upper-hash":
        changed["fingerprint"] = value["fingerprint"].upper()
    elif case == "null-pem":
        changed["pem"] = None
    elif case == "null-hash":
        changed["fingerprint"] = None
    else:
        changed["created"] = value["created"] - timedelta(seconds=1)
    with pytest.raises(sa.exc.IntegrityError):
        with engine.begin() as c:
            prepared(c, changed)
    assert snapshot(engine) == before


@pytest.mark.parametrize("change", [
    "ALTER TABLE agents.agent_signing_intents DROP CONSTRAINT ck_agent_signing_intents_public_binding",
    "ALTER TABLE agents.agent_signing_intents DISABLE TRIGGER signing_intent_guard",
    "ALTER TABLE agents.agent_signing_identities ALTER COLUMN public_key_sha256 TYPE text",
    "ALTER TABLE agents.agent_signing_identities DROP CONSTRAINT fk_agent_signing_identities_operation_id_agent_signing_intents",
    "DROP INDEX agents.ix_signing_one_open_intent",
    "ALTER TABLE agents.agent_signing_identities ENABLE ROW LEVEL SECURITY",
    "CREATE INDEX unreviewed_signing_index ON agents.agent_signing_identities(public_key_sha256)",
])
def test_unexpected_existing_schema_refuses_without_repair(signing_database, change):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    with engine.begin() as c:
        c.execute(sa.text(change))
    run_alembic(url, "stamp", OLD)
    before = snapshot(engine)
    result = run_alembic(url, "upgrade", NEW, expect_success=False)
    assert result.returncode != 0 and "Signing schema refused" in result.stderr
    assert snapshot(engine) == before


@pytest.mark.parametrize("commit", [True, False])
def test_downgrade_waits_for_inflight_initialization_before_deciding(signing_database, commit, record_property):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    with ThreadPoolExecutor(max_workers=1) as pool, engine.connect() as writer:
        transaction = writer.begin()
        pid = writer.scalar(sa.text("SELECT pg_backend_pid()"))
        pending(writer, intent())
        future = pool.submit(run_alembic, url, "downgrade", OLD, expect_success=False)
        observed = None
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with engine.connect() as observer:
                    observed = observer.scalar(sa.text("""
                        SELECT pid FROM pg_stat_activity WHERE datname=current_database()
                        AND :writer=ANY(pg_blocking_pids(pid))
                        AND query LIKE 'LOCK TABLE agents.agent_signing_intents,%'
                    """), {"writer": pid})
                if observed is not None or future.done():
                    break
                time.sleep(0.025)
            assert observed is not None and observed != pid and not future.done()
            record_property("genuine_signing_downgrade_writer_wait", True)
            transaction.commit() if commit else transaction.rollback()
        finally:
            if transaction.is_active:
                transaction.rollback()
        result = future.result(timeout=30)
    state = snapshot(engine)
    if commit:
        assert result.returncode != 0 and "retained identity or operation history" in result.stderr
        assert state[0] == NEW and len(state[1]["agent_signing_intents"]) == 1
    else:
        assert result.returncode == 0 and state[0] == OLD
        assert all(v is None for v in state[1].values())


@pytest.mark.parametrize("kind,expected_case,valid", [
    ("adopt", "valid", True), ("initialize", "none", True),
    ("adopt", "none", False), ("adopt", "empty", False),
    ("adopt", "uppercase", False), ("adopt", "short", False),
    ("adopt", "long", False), ("initialize", "valid", False),
])
def test_pending_adoption_persists_bounded_explicit_expectation(signing_database, kind, expected_case, valid):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent(kind=kind)
    expected = {"valid": value["fingerprint"], "none": None, "empty": "",
                "uppercase": "A" * 64, "short": "a" * 63, "long": "a" * 65}[expected_case]
    statement = sa.text("""
        INSERT INTO agents.agent_signing_intents
          (operation_id,singleton_id,installation_id,identity_epoch,kind,expected_public_sha256,state,requested_by,created_at)
        VALUES (:operation,1,:installation,1,:kind,:expected,'pending',:actor,:created)
    """)
    before = snapshot(engine)
    if valid:
        with engine.begin() as c:
            c.execute(statement, {**value, "expected": expected})
        after = snapshot(engine)[1]
        row = after["agent_signing_intents"][0]
        assert row["expected_public_sha256"] == expected and row["public_key_pem"] is None
        assert row["state"] == "pending" and after["agent_signing_identities"] == []
    else:
        with pytest.raises(sa.exc.DBAPIError):
            with engine.begin() as c:
                c.execute(statement, {**value, "expected": expected})
        assert snapshot(engine) == before


@pytest.mark.parametrize("matching", [True, False])
def test_adoption_cannot_prepare_another_internally_valid_public_key(signing_database, matching):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    original = intent(kind="adopt")
    with engine.begin() as c:
        pending(c, original)
    before = snapshot(engine)
    if matching:
        with engine.begin() as c:
            prepared(c, original)
        row = snapshot(engine)[1]["agent_signing_intents"][0]
        assert row["state"] == "prepared"
        assert row["expected_public_sha256"] == row["public_key_sha256"] == original["fingerprint"]
    else:
        other = {**intent(kind="adopt"), "operation": original["operation"]}
        assert other["fingerprint"] != original["fingerprint"]
        with pytest.raises(sa.exc.IntegrityError, match="public_binding"):
            with engine.begin() as c:
                prepared(c, other)
        assert snapshot(engine) == before


@pytest.mark.parametrize("phase", ["pending", "prepared"])
def test_adoption_expectation_cannot_change_during_a_valid_phase_transition(signing_database, phase):
    engine, url = signing_database
    run_alembic(url, "upgrade", NEW)
    value = intent(kind="adopt")
    with engine.begin() as c:
        pending(c, value)
        if phase == "prepared":
            prepared(c, value)
    before = snapshot(engine)
    transition = (
        "state='prepared',prepared_at=:created,public_key_pem=:pem,public_key_sha256=:fingerprint"
        if phase == "pending" else "state='cancelled',closed_at=:created,closed_by=:actor"
    )
    with pytest.raises(sa.exc.IntegrityError, match="rewrite retained history"):
        with engine.begin() as c:
            c.execute(sa.text("UPDATE agents.agent_signing_intents SET expected_public_sha256=:other," + transition),
                      {**value, "other": "0" * 64})
    assert snapshot(engine) == before
