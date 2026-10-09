"""Persist marketplace freshness and bind installable rows to accepted snapshots."""

import sqlalchemy as sa

from alembic import op

revision = "019_marketplace_catalog_state"
down_revision = "018_report_recovery_epoch"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("marketplace_plugins", schema="core")}
    for column in (
        sa.Column("catalog_identity", sa.String(64), nullable=True),
        sa.Column("catalog_serial", sa.BigInteger(), nullable=True),
    ):
        if column.name not in columns:
            op.add_column("marketplace_plugins", column, schema="core")
    # Fresh 001 installs create current metadata. Legacy rows deliberately keep
    # NULL provenance: authenticity/freshness cannot be inferred from old data.
    if not inspector.has_table("marketplace_catalog_state", schema="core"):
        op.create_table(
            "marketplace_catalog_state",
            sa.Column("scope", sa.String(16), primary_key=True),
            sa.Column("identity", sa.String(64), nullable=False),
            sa.Column("serial", sa.BigInteger(), nullable=False),
            sa.Column("payload_sha256", sa.String(64), nullable=False),
            sa.Column("generated_at", sa.DateTime(timezone=True)),
            sa.Column("expires_at", sa.DateTime(timezone=True)),
            sa.CheckConstraint("scope = 'global'", name="singleton"),
            sa.CheckConstraint("serial >= 0", name="serial"),
            schema="core",
        )


def downgrade() -> None:
    if (
        op.get_bind()
        .execute(
            sa.text("SELECT EXISTS (SELECT 1 FROM core.marketplace_catalog_state WHERE serial > 0)")
        )
        .scalar()
    ):
        raise RuntimeError(
            "Marketplace downgrade refused: export and reconcile accepted serial history before removing replay protection"
        )
    op.drop_table("marketplace_catalog_state", schema="core")
    op.drop_column("marketplace_plugins", "catalog_serial", schema="core")
    op.drop_column("marketplace_plugins", "catalog_identity", schema="core")
