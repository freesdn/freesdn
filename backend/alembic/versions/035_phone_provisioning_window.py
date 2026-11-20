# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 FreeSDN
"""Serve a phone's config to an unsigned subnet fetch only in a short window.

Any device on a site subnet that knew a phone's MAC address could fetch that
phone's configuration, SIP password included. An unsigned fetch from the
subnet is now served only until ``provisioning_open_until``, which the
Provision actions set a few minutes ahead. NULL (every existing phone) means
closed: a signed URL still works at any time.

Revision ID: 035_phone_provisioning_window
Revises: 034_change_groups
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "035_phone_provisioning_window"
down_revision: str | Sequence[str] | None = "034_change_groups"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "phones"
_COLUMN = "provisioning_open_until"


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns(_TABLE, schema="voip")}
    if _COLUMN not in columns:
        op.add_column(
            _TABLE,
            sa.Column(_COLUMN, sa.DateTime(timezone=True), nullable=True),
            schema="voip",
        )


def downgrade() -> None:
    op.drop_column(_TABLE, _COLUMN, schema="voip")
