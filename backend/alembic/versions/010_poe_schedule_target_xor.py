# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Add the PoE schedule target XOR check constraint to upgraded databases

``67353ef0`` (2026-06-22) added ``CheckConstraint("(device_id IS NOT NULL AND
device_group_id IS NULL) OR (device_id IS NULL AND device_group_id IS NOT NULL)")`` to
``PoESchedule`` and shipped no migration, so the constraint exists only where
``create_all`` built the table.

It is the only enforcement there is. ``PoEScheduleCreateIn`` validates ports, days,
timezone and that the two times differ, but has no validator requiring exactly one
target, and the handler validates ownership of ``device_id``/``device_group_id`` only
``if`` they were supplied. On an upgraded appliance ``POST /api/v1/poe/schedules`` with
both targets null returns 201; the schedule then shows in the UI as enabled and never
fires, because ``app/tasks/poe.py`` resolves ``device_ids`` from one of the two fields
and hits ``if not device_ids: continue``. Lights or APs the operator believes are on a
schedule are silently never switched.

Two repairs are needed before the constraint can hold, and they are deliberately
asymmetric:

* Rows with BOTH targets set are repaired losslessly by clearing ``device_group_id``.
  ``app/tasks/poe.py:106-108`` resolves ``device_id`` first and only falls back to the
  group, so the row keeps firing on exactly the devices it fires on today.
* Rows with NEITHER target set cannot be repaired -- there is no target to infer, and
  deleting an operator's schedule from inside a migration is not this code's call. So
  the constraint is added ``NOT VALID`` when any such row exists: PostgreSQL enforces it
  on every INSERT and UPDATE from that moment (which is what closes the 201), while
  leaving the existing inert rows readable so the operator can see and fix them. Where
  there are none -- the overwhelmingly common case -- it is added validated.

The constraint name carries the table prefix twice because the model's declared name
already starts with ``ck_`` and ``NAMING_CONVENTION["ck"]`` is
``ck_%(table_name)s_%(constraint_name)s``. It is spelled out literally here so this
migration produces the same name ``create_all`` does regardless of what metadata the
Alembic environment is configured with.

IDEMPOTENT BY DESIGN (project convention, like 002-009): a no-op where the constraint
already exists.

Revision ID: 010_poe_schedule_target_xor
Revises: 009_soft_delete_partial_uq
Create Date: 2026-08-27 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "010_poe_schedule_target_xor"
down_revision: str | Sequence[str] | None = "009_soft_delete_partial_uq"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA = "devices"
_TABLE = "poe_schedules"
_CONSTRAINT = "ck_poe_schedules_ck_poe_schedule_xor_target"
_EXPRESSION = (
    "(device_id IS NOT NULL AND device_group_id IS NULL) "
    "OR (device_id IS NULL AND device_group_id IS NOT NULL)"
)

_CONSTRAINT_EXISTS = sa.text(
    """
    SELECT 1
    FROM pg_constraint con
    JOIN pg_class c ON c.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = :schema AND c.relname = :table AND con.conname = :constraint
    """
)


def upgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table(_TABLE, schema=_SCHEMA):
        return  # fresh create_all DB builds the constraint from the ORM model
    already = bind.execute(
        _CONSTRAINT_EXISTS,
        {"schema": _SCHEMA, "table": _TABLE, "constraint": _CONSTRAINT},
    ).fetchone()
    if already is not None:
        return

    op.execute(
        f"UPDATE {_SCHEMA}.{_TABLE} SET device_group_id = NULL "  # noqa: S608 - fixed identifiers
        "WHERE device_id IS NOT NULL AND device_group_id IS NOT NULL"
    )
    targetless = bind.execute(
        sa.text(
            f"SELECT count(*) FROM {_SCHEMA}.{_TABLE} "  # noqa: S608 - fixed identifiers
            "WHERE device_id IS NULL AND device_group_id IS NULL"
        )
    ).scalar_one()

    not_valid = " NOT VALID" if targetless else ""
    op.execute(
        f'ALTER TABLE {_SCHEMA}.{_TABLE} ADD CONSTRAINT "{_CONSTRAINT}" '
        f"CHECK ({_EXPRESSION}){not_valid}"
    )
    if targetless:
        print(
            f"WARNING: {targetless} PoE schedule(s) have no device_id and no "
            "device_group_id. They can never fire and were left in place; the XOR "
            f"constraint was added NOT VALID. Delete or retarget them, then run "
            f'ALTER TABLE {_SCHEMA}.{_TABLE} VALIDATE CONSTRAINT "{_CONSTRAINT}";'
        )


def downgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table(_TABLE, schema=_SCHEMA):
        return
    op.execute(f'ALTER TABLE {_SCHEMA}.{_TABLE} DROP CONSTRAINT IF EXISTS "{_CONSTRAINT}"')
