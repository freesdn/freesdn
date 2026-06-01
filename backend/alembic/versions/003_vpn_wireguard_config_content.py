# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Add vpn.vpn_connections.wireguard_config_content

Mirror of 002 for WireGuard: the VPN "Connect" action materializes a WireGuard
connection's wg-quick INI to /etc/wireguard/<iface>.conf so the privileged vpn
sidecar can `wg-quick up` it. Previously a connection stored no wg config text,
so a WireGuard connect had nothing to write to disk and `wg-quick up` failed.
Encrypted at rest (carries the interface PrivateKey + PSK).

IDEMPOTENT BY DESIGN (same rationale as 002): 001_initial's create_all() builds
this column from the live ORM model on the `alembic upgrade head` path, so use
ADD COLUMN IF NOT EXISTS to be a no-op there while still adding it to an existing
production DB. Mirror with DROP COLUMN IF EXISTS on downgrade.

Revision ID: 003_vpn_wg_cfg
Revises: 002_vpn_ovpn_cfg
Create Date: 2026-06-26 01:00:00.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "003_vpn_wg_cfg"
down_revision: str | Sequence[str] | None = "002_vpn_ovpn_cfg"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE vpn.vpn_connections "
        "ADD COLUMN IF NOT EXISTS wireguard_config_content TEXT"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE vpn.vpn_connections DROP COLUMN IF EXISTS wireguard_config_content"
    )
