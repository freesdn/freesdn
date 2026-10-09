"""Store encrypted SNMP communities without truncating their Fernet tokens."""

import sqlalchemy as sa

from alembic import op

revision = "021_credential_snmp_text"
down_revision = "020_inapp_event_outbox"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The request's 512-character plaintext limit does not bound the ciphertext
    # to 255 characters. Keep existing bytes, nullability and encryption intact.
    op.alter_column(
        "credentials",
        "snmp_community",
        existing_type=sa.String(255),
        type_=sa.Text(),
        existing_nullable=True,
        schema="core",
    )


def downgrade() -> None:
    # Block writers BEFORE checking every row, including inactive/deleted rows.
    # Hold this lock through ALTER in Alembic's PostgreSQL transaction so a
    # concurrent write cannot invalidate the check. Never cast-and-truncate a
    # token: that destroys the secret even if the migration reports success.
    op.execute("LOCK TABLE core.credentials IN ACCESS EXCLUSIVE MODE")
    if (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM core.credentials "
                "WHERE char_length(snmp_community) > 255)"
            )
        )
        .scalar()
    ):
        raise RuntimeError(
            "SNMP credential downgrade refused: stored values exceed the old "
            "255-character capacity. Preserve a recoverable vault and reconcile "
            "those credentials before downgrading; no values were truncated."
        )
    op.alter_column(
        "credentials",
        "snmp_community",
        existing_type=sa.Text(),
        type_=sa.String(255),
        existing_nullable=True,
        schema="core",
    )
