# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Retype events.event_subscriptions.is_active from VARCHAR(10) to BOOLEAN

``a5dd43f3`` (2026-06-22) changed the model from ``Column(String(10), default="true")``
to ``Column(Boolean, default=True)`` and shipped no migration. A fresh install gets a
real ``boolean`` because ``scripts/migrate.py`` builds the schema with
``Base.metadata.create_all()``; an upgraded install keeps ``character varying(10)``.
Both end up stamped at the same revision with different schemas.

The operator-visible break is the list filter:
``GET /api/v1/events/subscriptions?is_active=true`` compiles to
``WHERE is_active = true``, which PostgreSQL rejects on the legacy column with
``operator does not exist: character varying = boolean`` -- a 500 on every upgraded
appliance, while the unfiltered listing still works (so it reads as a UI bug).

The retype is done in a single ``ALTER ... USING`` rather than an ``UPDATE`` followed by
a plain cast. PostgreSQL's ``varchar::boolean`` cast raises on any value outside its
literal set, which would abort the upgrade mid-flight; an explicit ``CASE`` cannot.
The app only ever wrote ``'true'``/``'false'``, so the ``ELSE`` arm is reachable only on
a hand-edited or externally-restored database -- it maps to ``true``, which is both the
model's default and what the old ``if sub.is_active:`` truthiness gave any non-empty
string.

IDEMPOTENT BY DESIGN (project convention, like 002-007): the inspector guard makes this
a no-op where ``create_all`` already built a boolean column.

Revision ID: 008_event_sub_is_active_bool
Revises: 007_widen_pending_status
Create Date: 2026-08-27 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "008_event_sub_is_active_bool"
down_revision: str | Sequence[str] | None = "007_widen_pending_status"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA = "events"
_TABLE = "event_subscriptions"
_COLUMN = "is_active"

# The literals PostgreSQL's own text->boolean cast accepts, spelled out so an
# unexpected value degrades to the model default instead of aborting the upgrade.
_TO_BOOLEAN = """
    CASE lower(btrim(is_active))
        WHEN 'true' THEN true
        WHEN 't' THEN true
        WHEN 'yes' THEN true
        WHEN 'y' THEN true
        WHEN 'on' THEN true
        WHEN '1' THEN true
        WHEN 'false' THEN false
        WHEN 'f' THEN false
        WHEN 'no' THEN false
        WHEN 'n' THEN false
        WHEN 'off' THEN false
        WHEN '0' THEN false
        ELSE true
    END
"""

_TO_TEXT = "CASE WHEN is_active THEN 'true' ELSE 'false' END"


def _column_type(inspector: sa.Inspector) -> sa.types.TypeEngine[object] | None:
    for col in inspector.get_columns(_TABLE, schema=_SCHEMA):
        if col["name"] == _COLUMN:
            return col["type"]
    return None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _TABLE not in inspector.get_table_names(schema=_SCHEMA):
        return  # fresh create_all DB builds the boolean column from the ORM model
    current = _column_type(inspector)
    if isinstance(current, sa.Boolean):
        return  # already boolean
    op.alter_column(
        _TABLE,
        _COLUMN,
        existing_type=sa.String(length=10),
        type_=sa.Boolean(),
        existing_nullable=False,
        postgresql_using=_TO_BOOLEAN,
        schema=_SCHEMA,
    )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _TABLE not in inspector.get_table_names(schema=_SCHEMA):
        return
    current = _column_type(inspector)
    if not isinstance(current, sa.Boolean):
        return
    op.alter_column(
        _TABLE,
        _COLUMN,
        existing_type=sa.Boolean(),
        type_=sa.String(length=10),
        existing_nullable=False,
        postgresql_using=_TO_TEXT,
        schema=_SCHEMA,
    )
