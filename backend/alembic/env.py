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
        # target_metadata=None for the same reason as do_run_migrations():
        # autogenerate is never run in offline/deployment mode, and passing
        # Base.metadata triggers MappedColumn.type introspection under SA 2.0.
        target_metadata=None,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run migrations with the given connection."""
    context.configure(
        connection=connection,
        # target_metadata is only required for `alembic revision --autogenerate`.
        # Passing it during `upgrade head` causes Alembic to introspect every
        # mapped column's .type attribute, which fails under SQLAlchemy 2.0
        # mapped_column() with: 'MappedColumn' object has no attribute 'type'.
        # Set to None so the runtime migration runner never touches model metadata.
        target_metadata=None,
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
