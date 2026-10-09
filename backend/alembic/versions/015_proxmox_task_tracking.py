"""Persist asynchronous provider observations separately from write dispatch.

Revision ID: 015_proxmox_task_tracking
Revises: 014_sla_report_calendar
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "015_proxmox_task_tracking"
down_revision = "014_sla_report_calendar"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("adapter_pending_changes", schema="core")}
    # 001 creates current metadata on fresh installs; deployed installs need
    # these additions. Historical writes are not replayed or certified by this
    # migration: only new acknowledgements have a durable observation record.
    if "provider_task" not in columns:
        op.add_column(
            "adapter_pending_changes",
            sa.Column("provider_task", postgresql.JSONB(), nullable=True),
            schema="core",
        )
    if "provider_task_next_poll_at" not in columns:
        op.add_column(
            "adapter_pending_changes",
            sa.Column("provider_task_next_poll_at", sa.DateTime(timezone=True), nullable=True),
            schema="core",
        )
    indexes = {i["name"] for i in inspector.get_indexes("adapter_pending_changes", schema="core")}
    if "ix_adapter_pending_task_poll" not in indexes:
        op.create_index(
            "ix_adapter_pending_task_poll",
            "adapter_pending_changes",
            ["provider_task_next_poll_at"],
            schema="core",
        )


def downgrade() -> None:
    op.drop_index(
        "ix_adapter_pending_task_poll", table_name="adapter_pending_changes", schema="core"
    )
    op.drop_column("adapter_pending_changes", "provider_task_next_poll_at", schema="core")
    op.drop_column("adapter_pending_changes", "provider_task", schema="core")
