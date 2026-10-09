# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned PostgreSQL migration contracts; no binaries, signing keys or live APIs.

The installed baseline is an immutable dump, never generated from current models.
All runtime results remain unclaimed until the separately guarded runner executes.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import sqlalchemy as sa
from pydantic import ValidationError

from app.schemas.agent_downloads import AgentReleaseCreate
from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    make_scratch_database,
    run_alembic,
    scratch_engine,
)

OLD = "025_agent_release_operations"
NEW = "026_agent_release_size"


def shape(engine):
    with engine.connect() as c:
        return tuple(c.execute(sa.text("""
            SELECT format_type(a.atttypid,a.atttypmod),a.attnotnull,a.atthasdef,
                   a.attidentity,a.attgenerated,c.relpersistence
            FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
            WHERE a.attrelid='agents.agent_releases'::regclass
              AND a.attname='file_size' AND NOT a.attisdropped
        """)).one())


def state(engine):
    with engine.connect() as c:
        return {
            "rows": c.execute(sa.text("SELECT to_jsonb(r) FROM agents.agent_releases r ORDER BY id")).scalars().all(),
            "revision": c.scalar(sa.text("SELECT version_num FROM alembic_version")),
            "indexes": [tuple(r) for r in c.execute(sa.text("""
                SELECT indexname,indexdef FROM pg_indexes WHERE schemaname='agents'
                AND tablename='agent_releases' ORDER BY indexname
            """))],
            "journal": c.execute(sa.text("SELECT to_jsonb(j) FROM agents.agent_release_operations j ORDER BY operation_id")).scalars().all(),
        }


def insert(c, size, *, latest=False):
    identity = uuid4()
    t = sa.Table("agent_releases", sa.MetaData(), schema="agents", autoload_with=c)
    c.execute(t.insert().values(
        id=identity, version="owned-size-contract", platform="linux", agent_type="daemon",
        download_url="https://owned.invalid/agent", checksum_sha256="a" * 64,
        file_size=size, release_notes="preserve all metadata", min_backend_version="0.1",
        is_latest=latest, is_prerelease=not latest, published_at=datetime.now(UTC),
        download_count=17, signature=None, organization_id=None, filename=None,
    ))
    return identity


@pytest.fixture
def legacy_size_database(maintenance_engine):
    name = "freesdn_release_size_" + uuid4().hex[:12]
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", OLD)
        assert shape(engine) == ("integer", True, False, "", "", "p")
        yield engine, url
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


@pytest.mark.parametrize("size", [2147483648, 4294967296, 10737418240])
def test_frozen_old_column_rejects_metadata_the_actual_API_accepts(legacy_size_database, size):
    engine, _ = legacy_size_database
    parsed = AgentReleaseCreate(
        version="owned", platform="linux", download_url="https://owned.invalid/agent",
        checksum_sha256="a" * 64, file_size=size,
    )
    assert parsed.file_size == size
    before = state(engine)
    with pytest.raises(sa.exc.DataError), engine.begin() as c:
        insert(c, size)
    assert state(engine) == before


def test_upgrade_preserves_all_rows_and_stores_exact_supported_boundaries(legacy_size_database):
    engine, url = legacy_size_database
    with engine.begin() as c:
        for value in [-2147483648, -1, 0, 524288000, 2147483647]:
            insert(c, value)
    before = state(engine)
    run_alembic(url, "upgrade", NEW)
    after = state(engine)
    assert shape(engine) == ("bigint", True, False, "", "", "p")
    assert after == {**before, "revision": NEW}
    with engine.begin() as c:
        for value in [2147483648, 4294967296, 10737418240]:
            insert(c, value, latest=True)
    expected = state(engine)
    assert sorted(r["file_size"] for r in expected["rows"]) == [-2147483648, -1, 0, 524288000, 2147483647, 2147483648, 4294967296, 10737418240]
    run_alembic(url, "upgrade", NEW)
    assert state(engine) == expected


def test_fresh_model_and_frozen_installed_upgrade_have_same_native_column(legacy_size_database, maintenance_engine):
    engine, url = legacy_size_database
    run_alembic(url, "upgrade", NEW)
    name = "freesdn_release_size_fresh_" + uuid4().hex[:12]
    fresh_url = make_scratch_database(maintenance_engine, name)
    fresh = scratch_engine(fresh_url)
    try:
        run_alembic(fresh_url, "upgrade", NEW)
        assert shape(fresh) == shape(engine) == ("bigint", True, False, "", "", "p")
        assert state(fresh) == state(engine)
    finally:
        fresh.dispose()
        drop_scratch_database(maintenance_engine, name)


@pytest.mark.parametrize("value", [-2147483648, -1, 0, 524288000, 2147483647])
def test_representable_downgrade_and_reupgrade_preserve_values(legacy_size_database, value):
    engine, url = legacy_size_database
    run_alembic(url, "upgrade", NEW)
    with engine.begin() as c:
        insert(c, value)
    before = state(engine)
    run_alembic(url, "downgrade", OLD)
    assert shape(engine) == ("integer", True, False, "", "", "p")
    assert state(engine) == {**before, "revision": OLD}
    run_alembic(url, "upgrade", NEW)
    assert shape(engine) == ("bigint", True, False, "", "", "p")
    assert state(engine) == before


@pytest.mark.parametrize("value", [-2147483649, 2147483648, 10737418240, 9223372036854775807])
@pytest.mark.parametrize("latest", [False, True])
def test_nonrepresentable_downgrade_refuses_without_changes(legacy_size_database, value, latest):
    engine, url = legacy_size_database
    run_alembic(url, "upgrade", NEW)
    with engine.begin() as c:
        insert(c, value, latest=latest)
    before = state(engine)
    result = run_alembic(url, "downgrade", OLD, expect_success=False)
    assert result.returncode != 0 and "Agent release size downgrade refused" in result.stderr
    assert state(engine) == before and shape(engine) == ("bigint", True, False, "", "", "p")


@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize("value", [2147483647, 2147483648])
def test_downgrade_observes_real_writer_result_after_proven_table_wait(legacy_size_database, committed, value, request):
    engine, url = legacy_size_database
    run_alembic(url, "upgrade", NEW)
    with engine.begin() as c:
        identity = insert(c, 5)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with engine.connect() as writer:
            transaction = writer.begin()
            writer_pid = writer.scalar(sa.text("SELECT pg_backend_pid()"))
            writer.execute(sa.text("UPDATE agents.agent_releases SET file_size=:value WHERE id=:id"), {"value": value, "id": identity})
            future = executor.submit(run_alembic, url, "downgrade", OLD, expect_success=False)
            waiter = None
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and not future.done():
                    with engine.connect() as observer:
                        waiter = observer.execute(sa.text("""
                            SELECT pid,pg_blocking_pids(pid) FROM pg_stat_activity
                            WHERE datname=current_database() AND wait_event_type='Lock'
                              AND query LIKE 'LOCK TABLE agents.agent_releases%'
                              AND :writer = ANY(pg_blocking_pids(pid))
                        """), {"writer": writer_pid}).first()
                    if waiter is not None:
                        break
                    time.sleep(.025)
                assert waiter is not None and waiter.pid != writer_pid and not future.done()
                if committed:
                    transaction.commit()
                else:
                    transaction.rollback()
            finally:
                if transaction.is_active:
                    transaction.rollback()
        result = future.result(timeout=60)
    unsafe = committed and value > 2147483647
    assert (result.returncode != 0) == unsafe
    if unsafe:
        assert "Agent release size downgrade refused" in result.stderr
    observed = state(engine)
    assert observed["revision"] == (NEW if unsafe else OLD)
    assert observed["rows"][0]["file_size"] == (value if committed else 5)
    assert shape(engine)[0] == ("bigint" if unsafe else "integer")
    request.node.user_properties.extend({
        "release_size_actual_table_wait": True, "release_size_distinct_writer_and_migration": True,
        "release_size_writer_committed": committed, "release_size_unsafe_downgrade_refused": unsafe,
    }.items())


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
@pytest.mark.parametrize("drift", ["smallint", "numeric", "text", "real", "nullable", "default", "generated", "unlogged"])
def test_unexpected_native_shape_is_not_silently_repaired(legacy_size_database, direction, drift):
    engine, url = legacy_size_database
    if direction == "downgrade":
        run_alembic(url, "upgrade", NEW)
    statements = {
        "smallint": "ALTER TABLE agents.agent_releases ALTER COLUMN file_size TYPE smallint",
        "numeric": "ALTER TABLE agents.agent_releases ALTER COLUMN file_size TYPE numeric",
        "text": "ALTER TABLE agents.agent_releases ALTER COLUMN file_size TYPE text USING file_size::text",
        "real": "ALTER TABLE agents.agent_releases ALTER COLUMN file_size TYPE real",
        "nullable": "ALTER TABLE agents.agent_releases ALTER COLUMN file_size DROP NOT NULL",
        "default": "ALTER TABLE agents.agent_releases ALTER COLUMN file_size SET DEFAULT 0",
        "generated": "ALTER TABLE agents.agent_releases DROP COLUMN file_size; ALTER TABLE agents.agent_releases ADD COLUMN file_size bigint GENERATED ALWAYS AS (download_count::bigint) STORED NOT NULL",
        "unlogged": "ALTER TABLE agents.agent_releases SET UNLOGGED",
    }
    with engine.begin() as c:
        for statement in statements[drift].split("; "):
            c.execute(sa.text(statement))
    before, column = state(engine), shape(engine)
    result = run_alembic(url, direction, NEW if direction == "upgrade" else OLD, expect_success=False)
    assert result.returncode != 0 and "Agent release size schema differs" in result.stderr
    assert state(engine) == before and shape(engine) == column


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_failure_after_alter_rolls_back_column_rows_and_revision(legacy_size_database, direction):
    engine, url = legacy_size_database
    if direction == "downgrade":
        run_alembic(url, "upgrade", NEW)
    with engine.begin() as c:
        insert(c, 123)
        c.execute(sa.text("""
            CREATE FUNCTION public.owned_refuse_release_size_revision() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
              RAISE EXCEPTION 'Owned refusal after release size ALTER';
            END $$
        """))
        c.execute(sa.text("""
            CREATE TRIGGER owned_refuse_release_size_revision BEFORE UPDATE ON alembic_version
            FOR EACH ROW EXECUTE FUNCTION public.owned_refuse_release_size_revision()
        """))
    before, column = state(engine), shape(engine)
    result = run_alembic(url, direction, NEW if direction == "upgrade" else OLD, expect_success=False)
    assert result.returncode != 0 and "Owned refusal after release size ALTER" in result.stderr
    assert state(engine) == before and shape(engine) == column


@pytest.mark.parametrize("value", [-1, 10737418241])
def test_wider_storage_does_not_expand_API_policy(value):
    with pytest.raises(ValidationError):
        AgentReleaseCreate(version="owned", platform="linux", download_url="https://owned.invalid/agent",
                           checksum_sha256="a" * 64, file_size=value)
