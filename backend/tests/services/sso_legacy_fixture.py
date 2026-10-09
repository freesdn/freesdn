# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned real pre-022 databases, restored from the immutable migration baseline."""

from contextlib import asynccontextmanager
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from tests.db.conftest import (
    build_pre_fix_database,
    configured_url,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)
from tests.services.test_backup_vault_security_roundtrip import owned_vault_database


@asynccontextmanager
async def legacy_vault_database(monkeypatch, request):
    """Never remove a current index or weaken the production auth path."""
    maintenance = sa.create_engine(
        configured_url().set(drivername="postgresql+psycopg", database="postgres"),
        isolation_level="AUTOCOMMIT", poolclass=sa.pool.NullPool,
        connect_args={"connect_timeout": 10},
    )
    name = "freesdn_sso_legacy_" + uuid4().hex[:12]
    try:
        url = build_pre_fix_database(maintenance, name)
        run_alembic(url, "upgrade", "021_credential_snmp_text")
        inspection = scratch_engine(url)
        try:
            with inspection.connect() as connection:
                revision = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
                binding_index = connection.scalar(sa.text(
                    "SELECT to_regclass('core.ix_users_external_binding')",
                ))
                actual_database = connection.scalar(sa.text("SELECT current_database()"))
            assert revision == "021_credential_snmp_text" and binding_index is None
            assert actual_database == url.database != configured_url().database
            request.node.user_properties.extend([
                ("legacy_database_revision", revision),
                ("legacy_binding_index_absent", binding_index is None),
                ("legacy_database_separate_from_suite", True),
            ])
        finally:
            inspection.dispose()
        engine = create_async_engine(
            url.set(drivername="postgresql+asyncpg"), poolclass=sa.pool.NullPool,
            connect_args={"timeout": 10, "command_timeout": 30},
        )
        with monkeypatch.context() as scoped:
            async with owned_vault_database(scoped, engine) as db:
                yield db
    finally:
        try:
            drop_scratch_database(maintenance, name)
        finally:
            maintenance.dispose()
