# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Network device configuration backup: targets + encrypted, versioned snapshots.

``backup.device_config_targets`` holds one row per exported device (schedule,
single-flight lease, last outcome); ``backup.device_config_snapshots`` holds one
row per DISTINCT configuration, Fernet-encrypted under the instance SECRET_KEY.

IDEMPOTENT like 005: a fresh install's create_all may already have built both
tables. Downgrade refuses while any snapshot exists -- it would silently destroy
the only copy of device configuration history.

Revision ID: 031_device_config_backups
Revises: 030_audit_retention_state
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from alembic import op

revision = "031_device_config_backups"
down_revision = "030_audit_retention_state"
branch_labels = None
depends_on = None

_TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS backup")
    tables = set(sa.inspect(op.get_bind()).get_table_names(schema="backup"))

    if "device_config_targets" not in tables:
        op.create_table(
            "device_config_targets",
            sa.Column("id", PGUUID(as_uuid=True), nullable=False),
            sa.Column("organization_id", PGUUID(as_uuid=True), nullable=False),
            sa.Column("site_id", PGUUID(as_uuid=True), nullable=True),
            sa.Column("source_kind", sa.String(length=32), nullable=False),
            sa.Column("source_id", PGUUID(as_uuid=True), nullable=False),
            sa.Column("vendor", sa.String(length=32), nullable=False),
            sa.Column("display_name", sa.String(length=255), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("interval_hours", sa.Integer(), nullable=False),
            sa.Column("retention_versions", sa.Integer(), nullable=False),
            sa.Column("next_due_at", _TZ, nullable=True),
            sa.Column("lease_until", _TZ, nullable=True),
            sa.Column("lease_token", PGUUID(as_uuid=True), nullable=True),
            sa.Column("last_attempt_at", _TZ, nullable=True),
            sa.Column("last_success_at", _TZ, nullable=True),
            sa.Column("last_changed_at", _TZ, nullable=True),
            sa.Column("last_status", sa.String(length=32), nullable=False),
            sa.Column("last_error_code", sa.String(length=64), nullable=True),
            sa.Column("consecutive_failures", sa.Integer(), nullable=False),
            sa.Column("created_at", _TZ, server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", _TZ, server_default=sa.text("now()"), nullable=False),
            sa.PrimaryKeyConstraint("id", name="pk_device_config_targets"),
            sa.ForeignKeyConstraint(
                ["organization_id"],
                ["core.organizations.id"],
                name="fk_device_config_targets_organization_id_organizations",
                ondelete="CASCADE",
            ),
            sa.ForeignKeyConstraint(
                ["site_id"],
                ["core.sites.id"],
                name="fk_device_config_targets_site_id_sites",
                ondelete="SET NULL",
            ),
            sa.UniqueConstraint("source_kind", "source_id", name="uq_bak_cfg_target_source"),
            schema="backup",
        )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_bak_cfg_target_org "
        "ON backup.device_config_targets (organization_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_bak_cfg_target_due "
        "ON backup.device_config_targets (enabled, next_due_at)"
    )

    if "device_config_snapshots" not in tables:
        op.create_table(
            "device_config_snapshots",
            sa.Column("id", PGUUID(as_uuid=True), nullable=False),
            sa.Column("organization_id", PGUUID(as_uuid=True), nullable=False),
            sa.Column("site_id", PGUUID(as_uuid=True), nullable=True),
            sa.Column("target_id", PGUUID(as_uuid=True), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("captured_at", _TZ, server_default=sa.text("now()"), nullable=False),
            sa.Column("format", sa.String(length=32), nullable=False),
            sa.Column("size_bytes", sa.BigInteger(), nullable=False),
            sa.Column("content_digest", sa.String(length=64), nullable=False),
            sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
            sa.Column("trigger", sa.String(length=16), nullable=False),
            sa.Column("created_by_id", PGUUID(as_uuid=True), nullable=True),
            sa.Column("summary", JSONB(), nullable=True),
            sa.PrimaryKeyConstraint("id", name="pk_device_config_snapshots"),
            sa.ForeignKeyConstraint(
                ["organization_id"],
                ["core.organizations.id"],
                name="fk_device_config_snapshots_organization_id_organizations",
                ondelete="CASCADE",
            ),
            sa.ForeignKeyConstraint(
                ["site_id"],
                ["core.sites.id"],
                name="fk_device_config_snapshots_site_id_sites",
                ondelete="SET NULL",
            ),
            sa.ForeignKeyConstraint(
                ["target_id"],
                ["backup.device_config_targets.id"],
                name="fk_device_config_snapshots_target_id_device_config_targets",
                ondelete="CASCADE",
            ),
            sa.ForeignKeyConstraint(
                ["created_by_id"],
                ["core.users.id"],
                name="fk_device_config_snapshots_created_by_id_users",
                ondelete="SET NULL",
            ),
            sa.UniqueConstraint("target_id", "version", name="uq_bak_cfg_snapshot_version"),
            schema="backup",
        )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_bak_cfg_snapshot_org_target "
        "ON backup.device_config_snapshots (organization_id, target_id)"
    )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names(schema="backup"))
    if (
        "device_config_snapshots" in tables
        and bind.execute(
            sa.text("SELECT EXISTS (SELECT 1 FROM backup.device_config_snapshots)")
        ).scalar()
    ):
        raise RuntimeError("Refusing downgrade that discards stored device configuration backups")
    if "device_config_snapshots" in tables:
        op.drop_table("device_config_snapshots", schema="backup")
    if "device_config_targets" in tables:
        op.drop_table("device_config_targets", schema="backup")
