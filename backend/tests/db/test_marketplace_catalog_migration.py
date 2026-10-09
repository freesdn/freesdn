# SPDX-License-Identifier: AGPL-3.0-only
"""Legacy schema cannot acquire invented catalog trust; downgrade retains floors."""

import sqlalchemy as sa

from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)
from tests.db.historical_downgrade import HISTORICAL_HEAD, require_current_audit_protection


def test_catalog_migration_preserves_legacy_row_and_refuses_history_loss(maintenance_engine, record_property):
    name = "freesdn_marketplace_freshness_upgrade"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", "018_report_recovery_epoch")
        with engine.begin() as c:
            assert not sa.inspect(c).has_table("marketplace_catalog_state", schema="core")
            c.execute(
                sa.text("""
                INSERT INTO core.marketplace_plugins
                (id, plugin_id, slug, name, short_description, author_name, category,
                 latest_version, min_core_version, download_url, checksum_sha256,
                 tags, screenshots, download_count, rating, rating_count,
                 is_verified, is_featured, status)
                VALUES (gen_random_uuid(), 'migration-fixture', 'migration-fixture',
                        'Fixture', 'Fixture', 'Fixture', 'monitoring', '1.0.0', '0.1.0',
                        'https://example.invalid/fixture.zip', repeat('a',64), '[]', '[]',
                        4, 0, 0, false, false, 'withdrawn')
            """)
            )
        run_alembic(url, "upgrade", HISTORICAL_HEAD)
        with engine.begin() as c:
            row = c.execute(
                sa.text(
                    "SELECT status, download_count, catalog_identity, catalog_serial FROM core.marketplace_plugins WHERE slug='migration-fixture'"
                )
            ).one()
            assert tuple(row) == ("withdrawn", 4, None, None)
            c.execute(
                sa.text(
                    "INSERT INTO core.marketplace_catalog_state (scope, identity, serial, payload_sha256) VALUES ('global', repeat('a',64), 7, repeat('b',64))"
                )
            )
        refusal = run_alembic(url, "downgrade", "018_report_recovery_epoch", expect_success=False)
        assert refusal.returncode != 0 and "Marketplace downgrade refused" in refusal.stderr
        with engine.connect() as c:
            assert (
                c.execute(sa.text("SELECT serial FROM core.marketplace_catalog_state")).scalar_one()
                == 7
            )
            assert (
                c.execute(
                    sa.text(
                        "SELECT catalog_serial FROM core.marketplace_plugins WHERE slug='migration-fixture'"
                    )
                ).scalar_one()
                is None
            )
        require_current_audit_protection(url, engine, "018_report_recovery_epoch", record_property)
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)
