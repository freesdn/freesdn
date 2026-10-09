"""Opt-in report notices and durable SMTP outcomes; no legacy schedule sends mail."""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "017_sla_report_delivery"
down_revision = "016_durable_token_revocations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("sla_report_schedules", schema="analytics")}
    for column in (
        sa.Column("delivery_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "delivery_provider_id",
            UUID(),
            sa.ForeignKey("core.notification_providers.id", ondelete="SET NULL"),
        ),
        sa.Column("delivery_approval", JSONB()),
    ):
        if column.name not in columns:
            op.add_column("sla_report_schedules", column, schema="analytics")
    # Earlier SMTP verification did not require trusted certificates. Reverify
    # existing SMTP providers using the corrected TLS client before opting in.
    op.execute(
        "UPDATE core.notification_providers SET is_verified = FALSE "
        "WHERE provider_type IN ('smtp', 'gmail_smtp')"
    )
    # 001 creates current metadata on fresh installs; do not recreate it.
    if not inspector.has_table("sla_report_deliveries", schema="analytics"):
        op.create_table(
            "sla_report_deliveries",
            sa.Column("id", UUID(), primary_key=True),
            sa.Column(
                "organization_id",
                UUID(),
                sa.ForeignKey("core.organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "schedule_id",
                UUID(),
                sa.ForeignKey("analytics.sla_report_schedules.id", ondelete="SET NULL"),
            ),
            sa.Column(
                "report_id", UUID(), sa.ForeignKey("analytics.sla_reports.id", ondelete="SET NULL")
            ),
            sa.Column("recipient_id", UUID(), sa.ForeignKey("core.users.id", ondelete="SET NULL")),
            sa.Column("recipient_email", sa.String(320), nullable=False),
            sa.Column("approval_revision", sa.String(36), nullable=False),
            sa.Column("state", sa.String(16), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("error_code", sa.String(64)),
            sa.Column(
                "next_attempt_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
            sa.Column("accepted_at", sa.DateTime(timezone=True)),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.UniqueConstraint(
                "report_id", "recipient_id", name="uq_sla_report_delivery_recipient"
            ),
            sa.CheckConstraint(
                "state IN ('pending', 'retry', 'sending', 'accepted', 'failed', 'cancelled', 'unknown', 'skipped')",
                name="state",
            ),
            sa.CheckConstraint("attempts >= 0 AND attempts <= 5", name="attempts"),
            schema="analytics",
        )
        op.create_index(
            "ix_sla_delivery_due",
            "sla_report_deliveries",
            ["state", "next_attempt_at"],
            schema="analytics",
        )
        op.create_index(
            "ix_sla_delivery_org",
            "sla_report_deliveries",
            ["organization_id", "created_at"],
            schema="analytics",
        )


def downgrade() -> None:
    bind = op.get_bind()
    # Removing the outbox would lose unresolved acceptance evidence. Require
    # explicit operator reconciliation and export, never silently discard it.
    count = bind.execute(sa.text("SELECT count(*) FROM analytics.sla_report_deliveries")).scalar()
    if count:
        raise RuntimeError("Export and explicitly clear report delivery history before downgrade")
    op.drop_table("sla_report_deliveries", schema="analytics")
    for column in ("delivery_approval", "delivery_provider_id", "delivery_enabled"):
        op.drop_column("sla_report_schedules", column, schema="analytics")
