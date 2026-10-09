"""Record schedule approval without inventing authority for legacy schedules.

Revision ID: 013_sla_schedule_authorization
Revises: 012_firmware_job_ownership
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "013_sla_schedule_authorization"
down_revision = "012_firmware_job_ownership"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("sla_report_schedules", schema="analytics"):
        return
    columns = {c["name"] for c in inspector.get_columns("sla_report_schedules", schema="analytics")}
    if "execution_scope" not in columns:
        op.add_column(
            "sla_report_schedules",
            sa.Column("execution_scope", postgresql.JSONB(), nullable=True),
            schema="analytics",
        )
    if "execution_error" not in columns:
        op.add_column(
            "sla_report_schedules",
            sa.Column("execution_error", sa.String(64), nullable=True),
            schema="analytics",
        )
    op.execute("""UPDATE analytics.sla_report_schedules
                  SET enabled = false, execution_error = 'approval_required'
                  WHERE execution_scope IS NULL""")


def downgrade() -> None:
    op.drop_column("sla_report_schedules", "execution_error", schema="analytics")
    op.drop_column("sla_report_schedules", "execution_scope", schema="analytics")
