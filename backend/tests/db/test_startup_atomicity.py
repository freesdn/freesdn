# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Fresh schema creation and its revision must survive or roll back together."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest
from sqlalchemy import text

from tests.db.conftest import (
    BACKEND_ROOT,
    drop_scratch_database,
    make_scratch_database,
    scratch_engine,
)


@pytest.fixture
def atomic_database(maintenance_engine):
    name = "startup_atomicity_guard"
    url = make_scratch_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        yield url, engine
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


def inventory(engine):
    with engine.connect() as connection:
        schemas = connection.execute(
            text(
                "SELECT oid,nspname FROM pg_catalog.pg_namespace "
                "WHERE left(nspname,3)<>'pg_' AND nspname<>'information_schema' "
                "ORDER BY nspname"
            )
        ).all()
        relations = connection.execute(
            text(
                "SELECT c.oid,n.nspname,c.relname,c.relkind FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' "
                "ORDER BY n.nspname,c.relname,c.relkind"
            )
        ).all()
        return schemas, relations


def environment(url):
    return {**os.environ, "DATABASE_URL": url.render_as_string(hide_password=False)}


def normal_startup(url):
    return subprocess.run(
        [sys.executable, "scripts/migrate.py"],
        cwd=BACKEND_ROOT,
        env=environment(url),
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.mark.parametrize("precreated_schemas", [False, True])
@pytest.mark.parametrize(
    "failure", ["before_stamp_exception", "after_stamp_exception", "process_kill"]
)
def test_interrupted_fresh_startup_rolls_back_complete_schema(
    atomic_database, tmp_path, precreated_schemas, failure
):
    url, engine = atomic_database
    if precreated_schemas:
        with engine.begin() as connection:
            connection.execute(text("CREATE SCHEMA core"))
            connection.execute(text("CREATE SCHEMA analytics"))
    before = inventory(engine)
    ready = tmp_path / "stamp-boundary-ready"
    # Only the interruption point is instrumented. ORM schema creation,
    # PostgreSQL transactions, Alembic stamping and process termination are real.
    code = """import sys,time
from pathlib import Path
from scripts import migrate
original=migrate.command.stamp
failure=sys.argv[1];ready=Path(sys.argv[2])
def stamp(*args,**kwargs):
 if failure=='after_stamp_exception':
  original(*args,**kwargs)
  raise RuntimeError('Injected failure after real revision stamp')
 if failure=='before_stamp_exception':
  raise RuntimeError('Injected failure before revision stamp')
 ready.write_text('schema creation returned; real process ready to terminate')
 while True:time.sleep(.1)
migrate.command.stamp=stamp
migrate.main()
"""
    with (tmp_path / "interrupted-startup.log").open("wb") as log:
        process = subprocess.Popen(
            [sys.executable, "-c", code, failure, str(ready)],
            cwd=BACKEND_ROOT,
            env=environment(url),
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            if failure == "process_kill":
                deadline = time.monotonic() + 120
                while not ready.exists():
                    assert process.poll() is None, "Startup exited before interruption point"
                    assert time.monotonic() < deadline
                    time.sleep(0.05)
                process.kill()
            assert process.wait(timeout=120) != 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
    after = inventory(engine)
    retry = normal_startup(url)
    (tmp_path / "recovery-outcome.json").write_text(
        json.dumps(
            {
                "failure": failure,
                "precreated_schemas": precreated_schemas,
                "state_rolled_back": after == before,
                "retry_exit_code": retry.returncode,
                "retry_refused_missing_history": "Refusing to initialize a non-empty database"
                in retry.stderr,
            }
        )
    )
    assert after == before, "Failed fresh initialization left committed schema or revision state"
    assert retry.returncode == 0, (
        "A clean retry must work without deleting or guessing migration metadata"
    )
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM public.alembic_version")) == 1


@pytest.mark.parametrize("precreated_schemas", [False, True])
def test_successful_fresh_startup_and_restart_preserve_schema(atomic_database, precreated_schemas):
    url, engine = atomic_database
    if precreated_schemas:
        with engine.begin() as connection:
            connection.execute(text("CREATE SCHEMA core"))
            connection.execute(text("CREATE SCHEMA analytics"))
    assert normal_startup(url).returncode == 0
    before = inventory(engine)
    assert normal_startup(url).returncode == 0
    assert inventory(engine) == before
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM public.alembic_version")) == 1
