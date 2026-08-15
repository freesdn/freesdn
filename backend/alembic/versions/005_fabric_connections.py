# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Create the fabric schema + connections/connection_runs (active-chain restore)

The Fabric persistence tables (``fabric.connections`` operator-authored wires +
``fabric.connection_runs`` per-firing audit) live in a dedicated ``fabric`` schema
(app/models/fabric.py). Their original migration (039) was moved to
``alembic/_archive/pre_26.06.1/`` during the 26.06.1 migration reset, and the
squashed ``001_initial`` does not recreate the schema — so a fresh
``alembic upgrade head`` left ``fabric`` absent and any Fabric query failed with
``schema "fabric" does not exist`` (a clean-deploy break of the differentiator
feature; the Backend Integration CI job surfaced it).

This restores the schema + tables in the active chain, ported verbatim from the
archived 039 to match the live ORM model. IDEMPOTENT BY DESIGN (project
convention, like 002/003/004): ``CREATE SCHEMA IF NOT EXISTS`` + per-table
inspector guards + ``CREATE INDEX IF NOT EXISTS`` — a no-op on any DB where
``001_initial``'s create_all already built them, and the missing piece on a fresh
migrate-only DB.

Revision ID: 005_fabric_connections
Revises: 004_overlay_nullable_ctrl
Create Date: 2026-06-27 01:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from alembic import op

revision: str = "005_fabric_connections"
down_revision: str | Sequence[str] | None = "004_overlay_nullable_ctrl"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS fabric")
    inspector = sa.inspect(op.get_bind())

    if "connections" not in inspector.get_table_names(schema="fabric"):
        op.create_table(
            "connections",
            sa.Column("id", PGUUID(as_uuid=True), primary_key=True),
            sa.Column(
                "organization_id",
                PGUUID(as_uuid=True),
                sa.ForeignKey("core.organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("source_event", sa.String(length=255), nullable=False),
            sa.Column("conditions", JSONB(), nullable=True),
            sa.Column("steps", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("cooldown_seconds", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("run_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column(
                "created_by",
                PGUUID(as_uuid=True),
                sa.ForeignKey("core.users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "updated_by",
                PGUUID(as_uuid=True),
                sa.ForeignKey("core.users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            schema="fabric",
        )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_fabric_conn_org ON fabric.connections (organization_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_fabric_conn_org_enabled "
        "ON fabric.connections (organization_id, enabled)"
    )

    if "connection_runs" not in inspector.get_table_names(schema="fabric"):
        op.create_table(
            "connection_runs",
            sa.Column("id", PGUUID(as_uuid=True), primary_key=True),
            sa.Column(
                "connection_id",
                PGUUID(as_uuid=True),
                sa.ForeignKey("fabric.connections.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "organization_id",
                PGUUID(as_uuid=True),
                sa.ForeignKey("core.organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("source_event_type", sa.String(length=255), nullable=False),
            sa.Column(
                "trigger_payload", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
            ),
            sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("steps", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            schema="fabric",
        )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_fabric_run_conn ON fabric.connection_runs (connection_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_fabric_run_org_time "
        "ON fabric.connection_runs (organization_id, created_at)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS fabric.connection_runs")
    op.execute("DROP TABLE IF EXISTS fabric.connections")
    op.execute("DROP SCHEMA IF EXISTS fabric CASCADE")
