# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Group the staged rows of a change that spans several devices.

A site-to-site tunnel push writes to two gateways, and a VLAN distribution to
several controllers. Each now stages one row per device under one
``group_id``: every side is preflighted before any is applied, and a failed
preflight on any side applies nothing. NULL for a change to one device, which
is every row written before this revision.

Revision ID: 034_change_groups
Revises: 033_platform_settings
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "034_change_groups"
down_revision: str | Sequence[str] | None = "033_platform_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "adapter_pending_changes"
_INDEX = "ix_adapter_pending_group"


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns(_TABLE, schema="core")}
    if "group_id" not in columns:
        op.add_column(
            _TABLE,
            sa.Column("group_id", postgresql.UUID(as_uuid=True), nullable=True),
            schema="core",
        )
    indexes = {i["name"] for i in sa.inspect(op.get_bind()).get_indexes(_TABLE, schema="core")}
    if _INDEX not in indexes:
        op.create_index(_INDEX, _TABLE, ["group_id"], schema="core")


def downgrade() -> None:
    op.drop_index(_INDEX, table_name=_TABLE, schema="core")
    op.drop_column(_TABLE, "group_id", schema="core")
