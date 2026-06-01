# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Add vpn.vpn_connections.openvpn_config_content

The VPN "Connect" action materializes an OpenVPN connection's config to
/etc/openvpn/client/<name>.conf so the daemon (in the privileged vpn sidecar)
can consume it. Previously a connection stored only openvpn_config_path/_protocol
and no config text, so an app-configured OpenVPN connection had nothing to write
to disk and connect() always failed ("No OpenVPN config found"). This column
holds the full .ovpn text, encrypted at rest (it carries inline private keys).

IDEMPOTENT BY DESIGN: 001_initial's upgrade() runs Base.metadata.create_all()
from the LIVE ORM models, so on the `alembic upgrade head` path against an empty
DB this column is already created by 001 (it now exists on the model). Use
ADD COLUMN IF NOT EXISTS so this revision is a no-op there, while still adding
the column to an existing production DB stamped at 001_initial. Mirror with
DROP COLUMN IF EXISTS on downgrade.

Revision ID: 002_vpn_ovpn_cfg
Revises: 001_initial
Create Date: 2026-06-26 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "002_vpn_ovpn_cfg"
down_revision: str | Sequence[str] | None = "001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE vpn.vpn_connections "
        "ADD COLUMN IF NOT EXISTS openvpn_config_content TEXT"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE vpn.vpn_connections DROP COLUMN IF EXISTS openvpn_config_content"
    )
