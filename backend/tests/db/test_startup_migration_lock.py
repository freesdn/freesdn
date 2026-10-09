# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real PostgreSQL checks for serialized, restart-safe startup migrations."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest
from sqlalchemy import text

from scripts.migration_lock import STARTUP_MIGRATION_LOCK, migration_lock
from tests.db.conftest import (
    BACKEND_ROOT,
    drop_scratch_database,
    make_scratch_database,
    scratch_engine,
)


@pytest.fixture
def startup_database(maintenance_engine):
    name = "startup_migration_lock"
    url = make_scratch_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        yield url, engine
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


def test_concurrent_fresh_startups_wait_before_ddl(startup_database):
    url, engine = startup_database
    env = {**os.environ, "DATABASE_URL": url.render_as_string(hide_password=False)}
    processes = []
    try:
        # A deterministic barrier: all real entrypoint scripts must wait on the
        # database lock, not merely survive a race by chance or restart later.
        with migration_lock(engine):
            for _ in range(3):
                processes.append(
                    subprocess.Popen(
                        [sys.executable, "scripts/migrate.py"],
                        cwd=BACKEND_ROOT,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                assert all(p.poll() is None for p in processes)
                with engine.connect() as connection:
                    waiting = connection.scalar(
                        text(
                            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' "
                            "AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) "
                            "AND NOT granted"
                        )
                    )
                    assert (
                        connection.scalar(text("SELECT to_regclass('public.alembic_version')"))
                        is None
                    )
                if waiting == len(processes):
                    break
                time.sleep(0.05)
            else:
                pytest.fail("Concurrent migration scripts did not wait before DDL")
        outputs = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=120)
            assert process.returncode == 0, stderr.replace(env["DATABASE_URL"], "[REDACTED]")
            outputs.append(stdout)
        assert sum("Fresh DB: created all tables" in out for out in outputs) == 1
        assert sum("Schema already at head" in out for out in outputs) == 2
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)


def test_failed_migration_releases_guard(startup_database):
    _, engine = startup_database
    with pytest.raises(RuntimeError, match="injected migration failure"):
        with migration_lock(engine):
            raise RuntimeError("injected migration failure")
    with engine.begin() as connection:
        assert (
            connection.scalar(
                text("SELECT pg_try_advisory_xact_lock(:key)"),
                {"key": STARTUP_MIGRATION_LOCK},
            )
            is True
        )
