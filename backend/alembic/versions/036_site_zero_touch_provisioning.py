# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 FreeSDN
"""Zero-touch phone provisioning becomes a per-site switch.

A phone on a site subnet could fetch its configuration, SIP password
included, without a signed URL. A factory phone cannot prove who it is, so
that trust is now a per-site switch, the column
``core.sites.voip_zero_touch_provisioning``, off for new sites. So that an
upgrade does not stop phones that were being provisioned this way, this
revision turns it on for every live site that has subnets and at least one
live phone. An operator turns it off per site from the VoIP API.

Revision ID: 036_site_zero_touch_provisioning
Revises: 035_phone_provisioning_window
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "036_site_zero_touch_provisioning"
down_revision: str | Sequence[str] | None = "035_phone_provisioning_window"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMN = "voip_zero_touch_provisioning"


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("sites", schema="core")}
    if _COLUMN not in columns:
        op.add_column(
            "sites",
            sa.Column(_COLUMN, sa.Boolean(), server_default=sa.text("false"), nullable=False),
            schema="core",
        )
    if not sa.inspect(bind).has_table("phones", schema="voip"):
        return
    bind.execute(
        sa.text(
            """
            UPDATE core.sites AS s
               SET voip_zero_touch_provisioning = true
             WHERE s.deleted_at IS NULL
               AND jsonb_typeof(s.subnets) = 'array'
               AND jsonb_array_length(s.subnets) > 0
               AND EXISTS (
                     SELECT 1 FROM voip.phones AS p
                      WHERE p.site_id = s.id AND p.deleted_at IS NULL
                   )
            """
        )
    )


def downgrade() -> None:
    op.drop_column("sites", _COLUMN, schema="core")
