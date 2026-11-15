# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Serialize startup migrations across API replicas, including pooled clients."""

import threading
from contextlib import contextmanager

from sqlalchemy import text

# Stable across processes/releases; advisory locks are scoped to the database.
STARTUP_MIGRATION_LOCK = 0x4652454553444E


#: How often the idle guard transaction proves it is alive. Well under the
#: idle-in-transaction backstops (PgBouncer 300 s, PostgreSQL 10 min).
KEEPALIVE_SECONDS = 60.0


@contextmanager
def migration_lock(engine, *, keepalive_seconds: float = KEEPALIVE_SECONDS):
    """Hold a separate transaction for the entire multi-connection migration.

    A transaction lock also works through PgBouncer transaction pooling: the
    guard retains its server connection until completion. A session lock could
    be returned to the pool while still held. Migration DDL uses other
    connections because Timescale continuous aggregates require autocommit.
    Errors/process exit release this lock without leaving a persistent flag.
    Operators must still keep manual Alembic commands out of startup windows.

    The guard is idle in its transaction for as long as the migration runs, so
    PgBouncer's ``idle_transaction_timeout`` and PostgreSQL's
    ``idle_in_transaction_session_timeout`` would end it -- releasing the lock
    mid-migration and failing the final commit -- on any migration longer than
    the backstop. A keepalive ``SELECT 1`` every ``keepalive_seconds`` keeps it
    active. Only that thread touches the guard while the caller migrates.
    """
    with engine.begin() as guard:
        guard.execute(text("SET LOCAL lock_timeout = '120s'"))
        guard.execute(
            text("SELECT pg_advisory_xact_lock(:key)"),
            {"key": STARTUP_MIGRATION_LOCK},
        )
        stop = threading.Event()

        def _keepalive() -> None:
            while not stop.wait(keepalive_seconds):
                try:
                    guard.execute(text("SELECT 1"))
                except Exception:  # noqa: BLE001 - the commit below reports it
                    return

        beat = threading.Thread(target=_keepalive, name="migration-lock-keepalive", daemon=True)
        beat.start()
        try:
            yield
        finally:
            stop.set()
            beat.join()
