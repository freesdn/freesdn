# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Make the five soft-delete identifier indexes partial (``WHERE deleted_at IS NULL``)

``1e0abdb0`` (2026-06-22) converted ``User.email``, ``User.username``,
``Organization.slug``, ``Site.slug`` and ``RemoteAgent.agent_key`` to PARTIAL unique
indexes so an identifier frees up once its row is soft-deleted, and dropped the
column-level ``unique=True`` that had also produced a UNIQUE *constraint*. It shipped no
migration. ``create_all`` skips a table that already exists -- indexes included -- so no
install path ever converted an existing full-unique index, and none ever dropped the
surviving constraints.

The handlers were updated to trust the fix (``users.py:255``, ``organizations.py:144``
narrow their duplicate pre-check to ``deleted_at IS NULL``), so on an upgraded appliance
the pre-check passes exactly where the database refuses:

    DELETE /api/v1/users/{id}   -> soft delete
    POST   /api/v1/users/       -> 409, for an email that appears in no list, no search
                                   and no export, because every read filters deleted_at

Reproduced on a legacy-shaped database:
    ERROR: duplicate key value violates unique constraint "ix_users_email"

Two objects have to go per identifier, not one: the full-unique INDEX and, where
``unique=True`` created one, the column-level UNIQUE CONSTRAINT. Replacing only the index
would leave the constraint enforcing the same block.

The swap is done inside the migration transaction rather than ``CONCURRENTLY``.
``CONCURRENTLY`` cannot run in a transaction, which would leave a window where the
identifier is not unique at all; these are operator-scale tables (users, orgs, sites,
agents) and migrations run from the entrypoint before the app serves traffic, so the
brief ACCESS EXCLUSIVE lock is the cheaper trade.

No duplicate backfill is needed and none is attempted: the partial index covers a strict
SUBSET of the rows the full-unique index already covered, so a database that has been
running with the full index cannot contain a duplicate the partial one would reject. A
pre-check here could never fire.

IDEMPOTENT BY DESIGN (project convention, like 002-008): an index that already carries a
predicate is left alone, so this is a no-op on a fresh ``create_all`` database.

Revision ID: 009_soft_delete_partial_uq
Revises: 008_event_sub_is_active_bool
Create Date: 2026-08-27 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "009_soft_delete_partial_uq"
down_revision: str | Sequence[str] | None = "008_event_sub_is_active_bool"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PREDICATE = "deleted_at IS NULL"

# (schema, table, index name, indexed columns) -- mirrors the ``__table_args__``
# Index(...) declarations in app/models/core.py and app/models/agents.py.
_TARGETS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("core", "users", "ix_users_email", ("email",)),
    ("core", "users", "ix_users_username", ("username",)),
    ("core", "organizations", "ix_organizations_slug", ("slug",)),
    ("core", "sites", "ix_sites_slug", ("organization_id", "slug")),
    ("agents", "remote_agents", "ix_remote_agents_agent_key", ("agent_key",)),
)

# Unique constraints are matched by their COLUMN SET, not by name: the name depends on
# which naming convention was in force when the database was built, and a unique
# constraint on exactly the columns we are replacing is by definition the full-unique
# enforcement this migration exists to remove.
_MATCHING_UNIQUE_CONSTRAINTS = sa.text(
    """
    SELECT con.conname
    FROM pg_constraint con
    JOIN pg_class c ON c.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE con.contype = 'u'
      AND n.nspname = :schema
      AND c.relname = :table
      AND (
        SELECT array_agg(a.attname::text ORDER BY a.attname)
        FROM unnest(con.conkey) AS k(attnum)
        JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
      ) = :columns
    """
)

_INDEX_STATE = sa.text(
    """
    SELECT i.indisunique, i.indpred IS NOT NULL AS is_partial
    FROM pg_index i
    JOIN pg_class ic ON ic.oid = i.indexrelid
    JOIN pg_namespace n ON n.oid = ic.relnamespace
    WHERE n.nspname = :schema AND ic.relname = :index
    """
)


def _swap(schema: str, table: str, index: str, columns: tuple[str, ...], predicate: str) -> None:
    """Drop any full-unique enforcement of ``columns`` and rebuild it with ``predicate``."""
    bind = op.get_bind()
    if not sa.inspect(bind).has_table(table, schema=schema):
        return

    for (conname,) in bind.execute(
        _MATCHING_UNIQUE_CONSTRAINTS,
        {"schema": schema, "table": table, "columns": sorted(columns)},
    ).fetchall():
        # No CASCADE: if something genuinely depends on this constraint we want the
        # upgrade to stop and say so, not to silently drop the dependent object.
        op.execute(f'ALTER TABLE {schema}.{table} DROP CONSTRAINT "{conname}"')

    state = bind.execute(_INDEX_STATE, {"schema": schema, "index": index}).fetchone()
    if state is not None:
        if state.indisunique and state.is_partial:
            return  # already the shape the ORM declares (fresh create_all database)
        op.execute(f'DROP INDEX {schema}."{index}"')

    cols = ", ".join(f'"{c}"' for c in columns)
    op.execute(f'CREATE UNIQUE INDEX "{index}" ON {schema}.{table} ({cols}) WHERE {predicate}')


def upgrade() -> None:
    for schema, table, index, columns in _TARGETS:
        _swap(schema, table, index, columns, _PREDICATE)


def downgrade() -> None:
    """Re-widen to full-unique.

    This can legitimately fail: once identifiers have been reused, live and
    soft-deleted rows share a value that a full-unique index rejects. PostgreSQL
    reports the offending key, which is the information an operator needs; there is
    nothing this migration could do about it that would not destroy data.
    """
    bind = op.get_bind()
    for schema, table, index, columns in _TARGETS:
        if not sa.inspect(bind).has_table(table, schema=schema):
            continue
        state = bind.execute(_INDEX_STATE, {"schema": schema, "index": index}).fetchone()
        if state is not None:
            if state.indisunique and not state.is_partial:
                continue
            op.execute(f'DROP INDEX {schema}."{index}"')
        cols = ", ".join(f'"{c}"' for c in columns)
        op.execute(f'CREATE UNIQUE INDEX "{index}" ON {schema}.{table} ({cols})')
