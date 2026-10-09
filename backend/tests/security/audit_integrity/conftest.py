"""Explicit owned-fixture isolation for the new durable singleton.

Original cases already remove only their owned audit rows. Their assertions and
cleanup are unchanged. A singleton deliberately survives those row deletions;
reset it ONLY between cases in this fresh private database, never in application
code and never before a case's assertions. Refuse reset if any row remains.
"""
import os
import subprocess
import sys
from contextlib import contextmanager

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.models.security_audit import AuditChainState, AuditLogRecord
from tests.db.conftest import (
    BACKEND_ROOT,
    drop_scratch_database,
    make_scratch_database,
)
from tests.db.conftest import (
    maintenance_engine as maintenance_engine,
)


@contextmanager
def owned_empty_audit_database(maintenance_engine, name):
    """Keep an empty-chain contract independent of earlier tests.

    Auth and application-startup tests legitimately commit audit rows through
    separate sessions. Do not delete those records to obtain an empty chain:
    create this process's own database using the normal fresh-schema entrypoint.
    The cases below already take their explicit connections from DATABASE_URL.
    """
    url = make_scratch_database(maintenance_engine, name)
    env = {**os.environ, "DATABASE_URL": url.render_as_string(hide_password=False)}
    env.pop("PYTEST_CURRENT_TEST", None)
    try:
        subprocess.run(
            [sys.executable, "scripts/migrate.py"],
            cwd=BACKEND_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("DATABASE_URL", env["DATABASE_URL"])
            yield
    finally:
        drop_scratch_database(maintenance_engine, name)


@pytest.fixture(scope="package", autouse=True)
def isolated_audit_database(maintenance_engine):
    with owned_empty_audit_database(maintenance_engine, "audit_integrity"):
        yield


@pytest.fixture(scope="module")
def isolated_audit_module_database(maintenance_engine):
    """Imported by standalone service modules that use the same chain reset.

    Module scope restores DATABASE_URL before unrelated service tests execute.
    """
    with owned_empty_audit_database(maintenance_engine, "audit_service_module"):
        yield


@pytest_asyncio.fixture(autouse=True)
async def reset_owned_audit_state_after_case():
    yield
    db = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with db.begin() as connection:
            assert await connection.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
            await connection.execute(text("DROP TABLE IF EXISTS audit.audit_chain_state"))
            await connection.execute(text("DROP FUNCTION IF EXISTS audit.guard_audit_chain_state()"))
            await connection.run_sync(lambda c: AuditChainState.__table__.create(c))
    finally:
        await db.dispose()
