"""Persist token revocations outside the evictable shared cache.

Revision ID: 016_durable_token_revocations
Revises: 015_proxmox_task_tracking

Security cutover invalidates access, refresh, password-reset and pending MFA
tokens through the account token version, and revokes all device sessions.
Stop all old application processes before migration. Keep SECRET_KEY and
ENCRYPTION_SALT unchanged: they also protect encrypted device credentials.
"""

import sqlalchemy as sa

from alembic import op

revision = "016_durable_token_revocations"
down_revision = "015_proxmox_task_tracking"
branch_labels = None
depends_on = None


def _invalidate_sessions() -> None:
    op.execute("UPDATE core.users SET token_version = COALESCE(token_version, 0) + 1")
    op.execute(
        "UPDATE core.user_sessions SET is_revoked = TRUE, "
        "revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)"
    )


def upgrade() -> None:
    # Migration 001 builds current metadata on fresh installs.
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("token_revocations", schema="core"):
        op.create_table(
            "token_revocations",
            sa.Column("jti_hash", sa.String(64), primary_key=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            schema="core",
        )
        op.create_index(
            "ix_token_revocations_expires_at", "token_revocations", ["expires_at"], schema="core"
        )
    _invalidate_sessions()


def downgrade() -> None:
    # Never revive ordinary sessions when removing the durable blacklist.
    _invalidate_sessions()
    op.drop_index("ix_token_revocations_expires_at", table_name="token_revocations", schema="core")
    op.drop_table("token_revocations", schema="core")
