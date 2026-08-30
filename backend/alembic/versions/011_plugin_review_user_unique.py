# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Add the one-review-per-user-per-plugin UNIQUE constraint to upgraded databases

``934099b6`` (2026-06-21) added ``UniqueConstraint("marketplace_plugin_id", "user_id",
name="uq_plugin_review_user_plugin")`` to ``PluginReview`` and shipped no migration --
the fifth and last of the 2026-06-21/22 drift commits, and the one 008-010 left out. Its
commit message claimed the change "propagates to both alembic and the dev/test
create_all path automatically", which is exactly the false belief that produced the
other four: ``create_all`` skips a table that already exists, so only a database built
from empty ever got it. Confirmed absent on the maintainer's live dev database, which
carries only ``pk_plugin_reviews`` and the two non-unique column indexes.

What it costs. ``app/api/v1/endpoints/marketplace.py`` (``create_plugin_review``) does a
best-effort ``SELECT`` for an existing review and then relies on an
``IntegrityError -> 409`` arm, described on the model as "the authoritative guard the
create-review endpoint relies on ... the SELECT pre-check races on its own". On an
upgraded appliance nothing backs that arm: two concurrent POSTs both pass the SELECT,
both INSERT, and the loser silently writes a second review instead of getting its 409.
The plugin's rating average is then computed over a user's duplicate ballots.

Why this one could not follow 010's pattern. A UNIQUE constraint cannot be added
``NOT VALID`` -- PostgreSQL accepts ``NOT VALID`` only for CHECK and FOREIGN KEY. So
where duplicates exist there are exactly two options, and both are bad: abort the
operator's whole upgrade over a plugin review, or DELETE review text a user wrote. This
migration does neither. It counts duplicate groups first:

* none (the overwhelmingly common case, and the only one on any appliance whose reviews
  were all written through the endpoint) -- the constraint is added, and the 409 arm has
  something behind it from that moment on.
* some -- the constraint is NOT added, the offending ``(plugin, user)`` pairs are
  printed with the exact SQL to inspect and repair them, and the upgrade continues. The
  appliance is left in the state it was already in, which is survivable; deciding which
  of somebody's two reviews to destroy is not this code's call, and an upgrade that
  refuses to run is worse than one that reports honestly.

If you take the second branch, dedupe and then run the printed ``ALTER TABLE``. Nothing
re-attempts it: once this revision is stamped, ``alembic upgrade`` will not run it
again.

IDEMPOTENT BY DESIGN (project convention, like 002-010): a no-op where the constraint
already exists, which is every database built by ``create_all``.

Revision ID: 011_plugin_review_user_uq
Revises: 010_poe_schedule_target_xor
Create Date: 2026-08-27 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "011_plugin_review_user_uq"
down_revision: str | Sequence[str] | None = "010_poe_schedule_target_xor"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA = "core"
_TABLE = "plugin_reviews"
# The model names this constraint explicitly and NAMING_CONVENTION["uq"]
# (``uq_%(table_name)s_%(column_0_name)s``) carries no ``%(constraint_name)s`` token, so
# an explicit name is used verbatim -- unlike the "ck" convention, which is why 010's
# constraint name carries its table prefix twice and this one does not. Spelled out
# literally so this migration produces the same name ``create_all`` does.
_CONSTRAINT = "uq_plugin_review_user_plugin"
_COLUMNS = ("marketplace_plugin_id", "user_id")

_CONSTRAINT_EXISTS = sa.text(
    """
    SELECT 1
    FROM pg_constraint con
    JOIN pg_class c ON c.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = :schema AND c.relname = :table AND con.conname = :constraint
    """
)

_DUPLICATE_GROUPS = sa.text(
    f"""
    SELECT marketplace_plugin_id, user_id, count(*) AS n
    FROM {_SCHEMA}.{_TABLE}
    GROUP BY marketplace_plugin_id, user_id
    HAVING count(*) > 1
    ORDER BY n DESC
    LIMIT 20
    """  # noqa: S608 - fixed identifiers, no interpolated user input
)


def upgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table(_TABLE, schema=_SCHEMA):
        return  # nothing to alter; 001_initial builds it from the ORM model
    already = bind.execute(
        _CONSTRAINT_EXISTS,
        {"schema": _SCHEMA, "table": _TABLE, "constraint": _CONSTRAINT},
    ).fetchone()
    if already is not None:
        return

    duplicates = bind.execute(_DUPLICATE_GROUPS).fetchall()
    if duplicates:
        pairs = ", ".join(f"({row[0]}, {row[1]}) x{row[2]}" for row in duplicates)
        print(
            f"WARNING: {_SCHEMA}.{_TABLE} holds more than one review for the same "
            f"(plugin, user). The one-review-per-user UNIQUE constraint was NOT added, "
            f"so the 409 on a duplicate review stays best-effort. Deleting a review "
            f"someone wrote is your decision, not this migration's.\n"
            f"  offending (marketplace_plugin_id, user_id) pairs: {pairs}\n"
            f"  inspect:  SELECT * FROM {_SCHEMA}.{_TABLE} "
            f"ORDER BY marketplace_plugin_id, user_id, created_at;\n"
            f"  then run: ALTER TABLE {_SCHEMA}.{_TABLE} "
            f'ADD CONSTRAINT "{_CONSTRAINT}" UNIQUE ({", ".join(_COLUMNS)});'
        )
        return

    op.create_unique_constraint(_CONSTRAINT, _TABLE, list(_COLUMNS), schema=_SCHEMA)


def downgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table(_TABLE, schema=_SCHEMA):
        return
    op.execute(f'ALTER TABLE {_SCHEMA}.{_TABLE} DROP CONSTRAINT IF EXISTS "{_CONSTRAINT}"')
