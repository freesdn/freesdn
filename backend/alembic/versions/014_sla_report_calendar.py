"""Persist report calendar settings and require review of changed timing semantics.

Revision ID: 014_sla_report_calendar
Revises: 013_sla_schedule_authorization
"""

import sqlalchemy as sa

from alembic import op

revision = "014_sla_report_calendar"
down_revision = "013_sla_schedule_authorization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("sla_report_schedules", schema="analytics"):
        return
    columns = {c["name"] for c in inspector.get_columns("sla_report_schedules", schema="analytics")}
    if "timezone" not in columns:
        op.add_column(
            "sla_report_schedules",
            sa.Column("timezone", sa.String(128), nullable=False, server_default="UTC"),
            schema="analytics",
        )
    if "time_of_day" not in columns:
        op.add_column(
            "sla_report_schedules",
            sa.Column("time_of_day", sa.String(5), nullable=False, server_default="09:00"),
            schema="analytics",
        )
        # Legacy timestamps have no IANA zone. Preserve their UTC clock time;
        # inventing a local zone would silently change the owner's intent.
        op.execute("""UPDATE analytics.sla_report_schedules
                      SET time_of_day = to_char(next_run_at AT TIME ZONE 'UTC', 'HH24:MI')
                      WHERE next_run_at IS NOT NULL""")
    # The new calendar cadence/reporting periods differ from rolling 30/90 days.
    # Preserve approvals and existing errors, but require an explicit timing
    # review before a previously enabled schedule runs with these semantics.
    op.execute("""UPDATE analytics.sla_report_schedules
                  SET enabled = false, execution_error = 'timing_review_required'
                  WHERE enabled = true""")


def downgrade() -> None:
    # Downgrading does not grant permission to resume paused schedules.
    op.drop_column("sla_report_schedules", "time_of_day", schema="analytics")
    op.drop_column("sla_report_schedules", "timezone", schema="analytics")
