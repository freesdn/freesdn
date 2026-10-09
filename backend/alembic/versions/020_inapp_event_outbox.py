"""Persist pending in-app events in the notification owner's transaction."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "020_inapp_event_outbox"
down_revision = "019_marketplace_catalog_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Fresh 001 installations already create current metadata. Existing bell
    # rows deliberately receive no new events: do not replay historical alerts.
    if sa.inspect(op.get_bind()).has_table("in_app_notification_events", schema="core"):
        return
    op.create_table(
        "in_app_notification_events",
        sa.Column(
            "notification_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("core.in_app_notifications.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("core.users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("core.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("suppressed_at", sa.DateTime(timezone=True)),
        sa.Column("last_failure", sa.String(40)),
        sa.CheckConstraint("status IN ('pending', 'published', 'suppressed')", name="status"),
        sa.CheckConstraint("attempts >= 0", name="attempts"),
        schema="core",
    )
    op.create_index(
        "ix_inapp_event_due",
        "in_app_notification_events",
        ["status", "next_attempt_at"],
        schema="core",
    )


def downgrade() -> None:
    if (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM core.in_app_notification_events WHERE status = 'pending')"
            )
        )
        .scalar()
    ):
        raise RuntimeError(
            "In-app event downgrade refused: pending events must be published or explicitly reconciled before removing their queue"
        )
    op.drop_table("in_app_notification_events", schema="core")
