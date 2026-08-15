# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Make core.adapter_pending_changes.controller_id nullable (overlay daemon writes)

VPN/overlay writes (Tailscale/NetBird/WireGuard/OpenVPN connect/disconnect) are
appliance-local DAEMON actions — they have no vendor controller — yet they must
still ride the staging chokepoint (stage → operator sign-off → apply, dual-gated)
to be exposed as Fabric write operations. The staging row's controller_id was
NOT NULL with an FK to core.controllers, which a controllerless daemon write
cannot satisfy.

This drops the NOT NULL so an `overlay.*` change can stage with controller_id=NULL.
The nullability is CONTAINED at the app layer: AdapterStagingService.stage_change
refuses a NULL controller_id for any non-`overlay.` feature, so every existing
controller-bound write keeps the "every staged change targets a controller"
invariant. The FK + index stay (Postgres indexes tolerate NULLs).

IDEMPOTENT BY DESIGN (same rationale as 002/003): 001_initial's create_all()
builds this table from the live ORM model, which after this change declares the
column nullable — so DROP NOT NULL is a no-op there while still relaxing an
existing production DB. Downgrade re-imposes NOT NULL (fails only if overlay rows
with a NULL controller exist — apply or discard them first).

Revision ID: 004_overlay_nullable_ctrl
Revises: 003_vpn_wg_cfg
Create Date: 2026-06-27 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "004_overlay_nullable_ctrl"
down_revision: str | Sequence[str] | None = "003_vpn_wg_cfg"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE core.adapter_pending_changes ALTER COLUMN controller_id DROP NOT NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE core.adapter_pending_changes ALTER COLUMN controller_id SET NOT NULL")
