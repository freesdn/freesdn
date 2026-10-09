# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Represent the release API's existing size range without lossy rollback.

Frozen PostgreSQL migration. The initial migration uses current models, so a
fresh database can already have bigint; the frozen installed baseline has int4.
Both paths require the same verified column shape. No row is clamped or deleted.
"""

import sqlalchemy as sa

from alembic import op

revision = "026_agent_release_size"
down_revision = "025_agent_release_operations"
branch_labels = None
depends_on = None


def _locked_column_type():
    if op.get_context().as_sql:
        raise RuntimeError("Agent release size migration requires online PostgreSQL inspection.")
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("Agent release size migration requires PostgreSQL.")
    # Lock BEFORE both the shape and value checks. Alembic retains the table
    # lock through ALTER and its revision update in the same transaction.
    op.execute("LOCK TABLE agents.agent_releases IN ACCESS EXCLUSIVE MODE")
    row = bind.execute(sa.text("""
        SELECT a.atttypid = 'pg_catalog.int4'::regtype AS is_int4,
               a.atttypid = 'pg_catalog.int8'::regtype AS is_int8,
               a.attnotnull, a.atttypmod, a.atthasdef, a.attidentity::text,
               a.attgenerated::text, a.attislocal, a.attinhcount,
               c.relkind::text, c.relpersistence::text
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
        WHERE a.attrelid = 'agents.agent_releases'::regclass
          AND a.attname = 'file_size' AND a.attnum > 0 AND NOT a.attisdropped
    """)).one_or_none()
    if row is None or tuple(row[2:]) != (True, -1, False, "", "", True, 0, "r", "p"):
        raise RuntimeError("Agent release size schema differs; inspect it without automatic repair.")
    if row.is_int4:
        return "integer"
    if row.is_int8:
        return "bigint"
    raise RuntimeError("Agent release size schema differs; inspect it without automatic repair.")


def upgrade() -> None:
    if _locked_column_type() == "integer":
        op.alter_column(
            "agent_releases", "file_size", schema="agents",
            existing_type=sa.Integer(), type_=sa.BigInteger(), existing_nullable=False,
        )
    if _locked_column_type() != "bigint":
        raise RuntimeError("Agent release size upgrade verification failed.")


def downgrade() -> None:
    current = _locked_column_type()
    # Includes every release: old/global, tenant, non-latest and prerelease.
    # Preserve historical negatives as values too; this migration is a type
    # correction, not a policy repair. The unchanged API rejects negative input.
    unsafe = op.get_bind().scalar(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM agents.agent_releases
            WHERE file_size < -2147483648 OR file_size > 2147483647
        )
    """))
    if unsafe:
        raise RuntimeError(
            "Agent release size downgrade refused: retained values exceed the old "
            "signed 32-bit range. Preserve the current database and release artifacts; "
            "reconcile those releases before downgrading. No values were truncated."
        )
    if current == "bigint":
        op.alter_column(
            "agent_releases", "file_size", schema="agents",
            existing_type=sa.BigInteger(), type_=sa.Integer(), existing_nullable=False,
        )
    if _locked_column_type() != "integer":
        raise RuntimeError("Agent release size downgrade verification failed.")
