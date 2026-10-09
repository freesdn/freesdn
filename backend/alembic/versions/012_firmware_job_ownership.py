"""Persist firmware job ownership and target authorization snapshots.

Revision ID: 012_firmware_job_ownership
Revises: 011_plugin_review_user_uq

Historical ownership is inferred only when ALL available evidence agrees.
Conflicting/orphaned rows retain NULL ownership and are inaccessible to tenants.
No device is contacted. Previously fabricated cache flags without a path are reset.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "012_firmware_job_ownership"
down_revision: str | Sequence[str] | None = "011_plugin_review_user_uq"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("firmware_upgrade_jobs", schema="core"):
        return
    columns = {c["name"] for c in inspector.get_columns("firmware_upgrade_jobs", schema="core")}
    if "organization_id" not in columns:
        op.add_column(
            "firmware_upgrade_jobs",
            sa.Column(
                "organization_id",
                sa.UUID(),
                sa.ForeignKey("core.organizations.id", ondelete="CASCADE"),
                nullable=True,
            ),
            schema="core",
        )
        op.create_index(
            "ix_core_firmware_upgrade_jobs_organization_id",
            "firmware_upgrade_jobs",
            ["organization_id"],
            schema="core",
        )
    if "target_site_ids" not in columns:
        op.add_column(
            "firmware_upgrade_jobs",
            sa.Column("target_site_ids", postgresql.JSONB(), nullable=True),
            schema="core",
        )
    op.execute("""
        WITH evidence AS (
            SELECT j.id, s.organization_id, s.id AS site_id
            FROM core.firmware_upgrade_jobs j JOIN core.sites s ON s.id = j.site_id
            UNION ALL
            SELECT j.id, s.organization_id, s.id
            FROM core.firmware_upgrade_jobs j
            JOIN devices.devices d ON j.device_ids @> jsonb_build_array(d.id::text)
            JOIN core.sites s ON s.id = d.site_id
            UNION ALL
            SELECT j.id, u.organization_id, NULL::uuid
            FROM core.firmware_upgrade_jobs j JOIN core.users u ON u.id = j.created_by
            UNION ALL
            SELECT j.id, f.organization_id, NULL::uuid
            FROM core.firmware_upgrade_jobs j JOIN core.firmware_images f ON f.id = j.firmware_id
        ), owners AS (
            SELECT id, min(organization_id::text)::uuid AS org,
                   jsonb_agg(DISTINCT site_id::text) FILTER (WHERE site_id IS NOT NULL) AS sites
            FROM evidence GROUP BY id HAVING count(DISTINCT organization_id) = 1
        )
        UPDATE core.firmware_upgrade_jobs j
        SET organization_id = o.org, target_site_ids = o.sites
        FROM owners o WHERE j.id = o.id AND j.organization_id IS NULL
    """)
    op.execute("""UPDATE core.firmware_images SET is_cached = false, cached_at = NULL
                  WHERE is_cached = true AND file_path IS NULL""")


def downgrade() -> None:
    op.drop_column("firmware_upgrade_jobs", "target_site_ids", schema="core")
    op.drop_column("firmware_upgrade_jobs", "organization_id", schema="core")
