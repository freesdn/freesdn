# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Alembic Environment Configuration
=================================

Configures Alembic for async SQLAlchemy migrations.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.core.config import settings
from app.db.base import Base

# Import all models to register them with Base.metadata
from app.models import *  # noqa: F401, F403

# Import module models not re-exported by app.models
from app.modules.cameras.models import *  # noqa: F401, F403
from app.modules.firewall.models import *  # noqa: F401, F403
from app.modules.voip.models import *  # noqa: F401, F403
from app.modules.access_control.models import *  # noqa: F401, F403
from app.modules.ai.models import *  # noqa: F401, F403
from app.modules.gateway.models import *  # noqa: F401, F403
from app.modules.hypervisor.models import *  # noqa: F401, F403

# Alembic Config object
config = context.config

# Set the database URL
config.set_main_option("sqlalchemy.url", str(settings.DATABASE_URL))

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine,
    though an Engine is acceptable here as well. By skipping the Engine
    creation we don't even need a DBAPI to be available.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run migrations with the given connection."""
    # Alembic reads target_metadata back out of the migration context when it
    # builds an AutogenContext, so pinning it to None disabled `alembic
    # revision --autogenerate` and `alembic check` entirely -- which is why four
    # schema-changing commits (1e0abdb0, a5dd43f3, 934099b6, 67353ef0) each shipped
    # zero migrations and nothing in the repo could say so. The comment that used to
    # justify None claimed passing Base.metadata during `upgrade` raises
    # "'MappedColumn' object has no attribute 'type'"; that does not reproduce on the
    # pinned alembic 1.19 / SQLAlchemy 2.0 (`alembic upgrade head` and
    # `compare_metadata()` both run clean against Base.metadata).
    #
    # It is not inert during `upgrade`, though: alembic takes its constraint naming
    # convention from target_metadata (operations/schemaobj.py:192), so op.create_*
    # directives now render Base's NAMING_CONVENTION instead of PostgreSQL defaults.
    # That is the intended direction -- it makes a migration-built object match what
    # create_all builds -- and the only migration on the chain with anonymous
    # constructs is 005, whose create_table branch is unreachable because 001_initial
    # already built fabric.* via create_all.
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Retype drift (String(10) -> Boolean) is exactly what went unnoticed here,
        # and alembic does not compare column types unless asked.
        compare_type=True,
        include_schemas=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in async mode."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.
    
    In this scenario we need to create an Engine and associate a
    connection with the context.
    """
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
