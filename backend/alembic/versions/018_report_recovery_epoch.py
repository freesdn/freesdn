"""Bind report-mail notices to an independently managed recovery epoch."""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "018_report_recovery_epoch"
down_revision = "017_sla_report_delivery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 001 creates current metadata on fresh installs. Existing notices must stay
    # NULL: no restored setting can prove that a pending notice was never sent.
    columns = {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns(
            "sla_report_deliveries", schema="analytics"
        )
    }
    if "delivery_epoch" not in columns:
        op.add_column(
            "sla_report_deliveries",
            sa.Column("delivery_epoch", UUID(), nullable=True),
            schema="analytics",
        )


def downgrade() -> None:
    exists = (
        op.get_bind()
        .execute(sa.text("SELECT EXISTS (SELECT 1 FROM analytics.sla_report_deliveries)"))
        .scalar()
    )
    if exists:
        raise RuntimeError(
            "Report recovery downgrade refused: preserve and reconcile delivery history"
        )
    op.drop_column("sla_report_deliveries", "delivery_epoch", schema="analytics")
