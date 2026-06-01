# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Add backups.include_secrets — marks a Full ("vault") backup that carries secrets

The secure backup (``.fsdnvault``) includes decrypted credentials + user logins,
sealed under an operator passphrase (re-keyed onto the target SECRET_KEY at restore)
— distinct from the secret-free config snapshot (``.fsdn``). This boolean lets the
UI badge a backup as Full-vs-Config and lets restore know to expect a passphrase.

IDEMPOTENT BY DESIGN (project convention, like 002/003/004/005): an inspector guard
makes it a no-op where ``001_initial``'s create_all already built the column (the
ORM model carries it) and the additive piece on a migrate-only DB.

Revision ID: 006_backup_include_secrets
Revises: 005_fabric_connections
Create Date: 2026-06-28 05:30:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "006_backup_include_secrets"
down_revision: str | Sequence[str] | None = "005_fabric_connections"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "backups" not in inspector.get_table_names(schema="backup"):
        return  # fresh create_all DB will include the column via the ORM model
    cols = {c["name"] for c in inspector.get_columns("backups", schema="backup")}
    if "include_secrets" not in cols:
        op.add_column(
            "backups",
            sa.Column(
                "include_secrets",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
            schema="backup",
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "backups" in inspector.get_table_names(schema="backup"):
        cols = {c["name"] for c in inspector.get_columns("backups", schema="backup")}
        if "include_secrets" in cols:
            op.drop_column("backups", "include_secrets", schema="backup")
