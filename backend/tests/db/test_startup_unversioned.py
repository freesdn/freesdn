# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real startup must not certify an unversioned, nonempty database as current."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from tests.db.conftest import (
    BACKEND_ROOT,
    _load_baseline_schema,
    drop_scratch_database,
    make_scratch_database,
    scratch_engine,
)


@pytest.fixture
def startup_database(maintenance_engine):
    name = "startup_unversioned_guard"
    url = make_scratch_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        yield url, engine
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


def run_startup(url):
    return subprocess.run(
        [sys.executable, "scripts/migrate.py"],
        cwd=BACKEND_ROOT,
        env={**os.environ, "DATABASE_URL": url.render_as_string(hide_password=False)},
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def catalog_inventory(engine):
    with engine.connect() as conn:
        relations = conn.execute(
            text(
                "SELECT n.nspname,c.relname,c.relkind,c.oid "
                "FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
                "AND left(n.nspname,3)<>'pg_' ORDER BY 1,2,3"
            )
        ).all()
        columns = conn.execute(
            text(
                "SELECT table_schema,table_name,column_name,data_type,column_default "
                "FROM information_schema.columns "
                "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
                "ORDER BY 1,2,3"
            )
        ).all()
    return relations, columns


def assert_current(engine):
    head = ScriptDirectory.from_config(Config(str(BACKEND_ROOT / "alembic.ini"))).get_current_head()
    with engine.connect() as conn:
        assert conn.execute(
            text("SELECT version_num FROM public.alembic_version")
        ).scalars().all() == [head]
        assert conn.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                "WHERE table_schema='analytics' AND table_name='sla_report_schedules' "
                "AND column_name='delivery_enabled')"
            )
        )


def assert_refused_without_ddl(url, engine):
    before = catalog_inventory(engine)
    result = run_startup(url)
    assert result.returncode != 0
    assert "Refusing to initialize a non-empty database without migration metadata" in result.stderr
    assert catalog_inventory(engine) == before
    with engine.connect() as conn:
        assert conn.scalar(text("SELECT to_regclass('public.alembic_version')")) is None


def test_restored_legacy_schema_without_revision_is_preserved(startup_database):
    url, engine = startup_database
    _load_baseline_schema(url)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE public.alembic_version"))
        conn.execute(
            text("CREATE TABLE public.recovery_sentinel (id integer PRIMARY KEY, value text)")
        )
        conn.execute(
            text("INSERT INTO public.recovery_sentinel VALUES (1, 'retain this synthetic row')")
        )
    assert_refused_without_ddl(url, engine)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT id,value FROM public.recovery_sentinel")).all() == [
            (1, "retain this synthetic row")
        ]


@pytest.mark.parametrize("schema", ["public", "core", "separate_application"])
@pytest.mark.parametrize(
    "kind", ["table", "partitioned", "view", "materialized", "sequence", "foreign"]
)
def test_unversioned_user_relations_refuse_before_initialization(startup_database, schema, kind):
    url, engine = startup_database
    # Every identifier is a fixed test parameter. The foreign table has no
    # handler or remote endpoint: this test inspects catalog state only.
    statements = {
        "table": f"CREATE TABLE {schema}.legacy_marker (id integer)",
        "partitioned": f"CREATE TABLE {schema}.legacy_marker (id integer) PARTITION BY RANGE (id)",
        "view": f"CREATE VIEW {schema}.legacy_marker AS SELECT 1 AS id",
        "materialized": f"CREATE MATERIALIZED VIEW {schema}.legacy_marker AS SELECT 1 AS id",
        "sequence": f"CREATE SEQUENCE {schema}.legacy_marker",
        "foreign": f"CREATE FOREIGN TABLE {schema}.legacy_marker (id integer) SERVER inert_server",
    }
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
        if kind == "foreign":
            conn.execute(text("CREATE FOREIGN DATA WRAPPER inert_wrapper NO HANDLER"))
            conn.execute(text("CREATE SERVER inert_server FOREIGN DATA WRAPPER inert_wrapper"))
        conn.execute(text(statements[kind]))
    assert_refused_without_ddl(url, engine)


@pytest.mark.parametrize("precreated_schemas", [False, True])
def test_fresh_database_still_initializes_and_restarts(startup_database, precreated_schemas):
    url, engine = startup_database
    if precreated_schemas:
        with engine.begin() as conn:
            conn.execute(text("CREATE SCHEMA core"))
            conn.execute(text("CREATE SCHEMA analytics"))
    assert run_startup(url).returncode == 0
    assert_current(engine)
    before = catalog_inventory(engine)
    assert run_startup(url).returncode == 0
    assert catalog_inventory(engine) == before


def test_preinstalled_extension_relation_is_not_application_state(startup_database):
    url, engine = startup_database
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE public.extension_marker (id integer PRIMARY KEY)"))
        conn.execute(text("INSERT INTO public.extension_marker VALUES (7)"))
        # Real PostgreSQL extension membership, confined to this disposable DB.
        conn.execute(text("ALTER EXTENSION plpgsql ADD TABLE public.extension_marker"))
    assert run_startup(url).returncode == 0
    assert_current(engine)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT id FROM public.extension_marker")).all() == [(7,)]


def test_known_legacy_revision_still_runs_incremental_upgrades(startup_database):
    url, engine = startup_database
    _load_baseline_schema(url)
    assert run_startup(url).returncode == 0
    assert_current(engine)


@pytest.mark.parametrize("state", ["unknown", "empty", "blank", "multiple"])
def test_ambiguous_existing_revision_is_preserved(startup_database, state):
    url, engine = startup_database
    _load_baseline_schema(url)
    head = ScriptDirectory.from_config(Config(str(BACKEND_ROOT / "alembic.ini"))).get_current_head()
    values = {
        "unknown": ["999_future_unrecognized"],
        "empty": [],
        "blank": [""],
        "multiple": [head, "999_future_unrecognized"],
    }[state]
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM public.alembic_version"))
        for value in values:
            conn.execute(
                text("INSERT INTO public.alembic_version(version_num) VALUES (:value)"),
                {"value": value},
            )
    before = catalog_inventory(engine)
    result = run_startup(url)
    assert result.returncode != 0
    assert "Refusing database migration" in result.stderr
    assert catalog_inventory(engine) == before
    with engine.connect() as conn:
        assert sorted(
            conn.execute(text("SELECT version_num FROM public.alembic_version")).scalars()
        ) == sorted(values)
