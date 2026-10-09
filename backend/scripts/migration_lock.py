# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Serialize startup migrations across API replicas, including pooled clients."""

from contextlib import contextmanager

from sqlalchemy import text

# Stable across processes/releases; advisory locks are scoped to the database.
STARTUP_MIGRATION_LOCK = 0x4652454553444E


@contextmanager
def migration_lock(engine):
    """Hold a separate transaction for the entire multi-connection migration.

    A transaction lock also works through PgBouncer transaction pooling: the
    guard retains its server connection until completion. A session lock could
    be returned to the pool while still held. Migration DDL uses other
    connections because Timescale continuous aggregates require autocommit.
    Errors/process exit release this lock without leaving a persistent flag.
    Operators must still keep manual Alembic commands out of startup windows.
    """
    with engine.begin() as guard:
        guard.execute(text("SET LOCAL lock_timeout = '120s'"))
        guard.execute(
            text("SELECT pg_advisory_xact_lock(:key)"),
            {"key": STARTUP_MIGRATION_LOCK},
        )
        yield
