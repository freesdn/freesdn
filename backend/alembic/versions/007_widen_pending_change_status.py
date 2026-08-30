# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Widen core.adapter_pending_changes.status to hold ``reconciliation_required``

The staged-change lifecycle gained ``reconciliation_required`` -- the honest state
for an apply that left ``applying`` without reaching a terminal state, where the
outcome on the device is genuinely unknown. The state machine was widened without
widening its storage: the column was ``VARCHAR(16)`` and the new value is 23
characters, so PostgreSQL rejected every write with "value too long for type
character varying(16)".

The consequences were silent. The opportunistic stale-row sweep swallows database
errors by design (it is a maintenance hook riding normal queue traffic), so it
rolled back and reported zero rows recovered while the row stayed ``applying``
forever. In ``apply_change`` the terminal commit itself failed, leaving the
already-committed ``applying`` row behind.

Widened to 32 rather than 24 to leave headroom, so the next lifecycle state does
not need another migration.

IDEMPOTENT BY DESIGN (project convention, like 002-006): a fresh ``create_all``
database already gets 32 from the ORM model, and the inspector guard makes this a
no-op there.

Revision ID: 007_widen_pending_status
Revises: 006_backup_include_secrets
Create Date: 2026-08-25 12:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "007_widen_pending_status"
down_revision: str | Sequence[str] | None = "006_backup_include_secrets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "adapter_pending_changes"
_SCHEMA = "core"
_COLUMN = "status"


def _current_width(inspector) -> int | None:
    for col in inspector.get_columns(_TABLE, schema=_SCHEMA):
        if col["name"] == _COLUMN:
            return getattr(col["type"], "length", None)
    return None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _TABLE not in inspector.get_table_names(schema=_SCHEMA):
        return  # fresh create_all DB already has the widened column
    width = _current_width(inspector)
    if width is not None and width >= 32:
        return  # already wide enough
    op.alter_column(
        _TABLE,
        _COLUMN,
        existing_type=sa.String(length=16),
        type_=sa.String(length=32),
        existing_nullable=False,
        existing_server_default="pending",
        schema=_SCHEMA,
    )


def downgrade() -> None:
    """Narrowing again would truncate any ``reconciliation_required`` row.

    Those rows mark changes whose outcome on a device is unknown and which an
    operator still has to verify, so silently mangling them to fit is not an
    acceptable downgrade. Resolve them first (apply or force-discard), then
    narrow.
    """
    inspector = sa.inspect(op.get_bind())
    if _TABLE not in inspector.get_table_names(schema=_SCHEMA):
        return
    bind = op.get_bind()
    stranded = bind.execute(
        sa.text(
            f"SELECT count(*) FROM {_SCHEMA}.{_TABLE} "  # noqa: S608 - fixed identifiers
            "WHERE status = 'reconciliation_required'"
        )
    ).scalar()
    if stranded:
        raise RuntimeError(
            f"{stranded} change(s) are in 'reconciliation_required' and would be "
            "truncated by narrowing status back to 16 chars. Resolve them first."
        )
    op.alter_column(
        _TABLE,
        _COLUMN,
        existing_type=sa.String(length=32),
        type_=sa.String(length=16),
        existing_nullable=False,
        existing_server_default="pending",
        schema=_SCHEMA,
    )
