"""Recover historical ownership only when independent evidence agrees."""

from uuid import uuid4

import sqlalchemy as sa

from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)
from tests.db.test_legacy_upgrade_behaviour import (
    _DELETED_USER_ID,
    _DEVICE_ID,
    _ORG_ID,
    _SEED,
    _SEED_PARAMS,
    _SITE_ID,
)


def test_upgrade_backfills_owned_jobs_and_quarantines_conflicts(maintenance_engine):
    name = "freesdn_firmware_ownership_upgrade"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    owned_id, conflict_id, orphan_id, foreign_org, foreign_user = [uuid4() for _ in range(5)]
    try:
        with engine.begin() as connection:
            for statement in _SEED:
                connection.execute(sa.text(statement), _SEED_PARAMS)
            connection.execute(
                sa.text(
                    "INSERT INTO core.organizations (id, name, slug, is_active, settings) "
                    "VALUES (:id, 'Foreign fixture', 'foreign-fixture', true, '{}'::jsonb)"
                ),
                {"id": foreign_org},
            )
            users = sa.Table("users", sa.MetaData(), schema="core", autoload_with=connection)
            copied = dict(
                connection.execute(sa.select(users).where(users.c.id == _DELETED_USER_ID))
                .mappings()
                .one()
            )
            copied.update(
                id=foreign_user,
                organization_id=foreign_org,
                username="foreign-fixture",
                email="foreign@example.invalid",
            )
            connection.execute(users.insert().values(**copied))
            jobs = sa.Table(
                "firmware_upgrade_jobs", sa.MetaData(), schema="core", autoload_with=connection
            )
            assert "organization_id" not in jobs.c  # Real historical schema, not today's ORM.
            for identifier, creator, devices in [
                (owned_id, _DELETED_USER_ID, [str(_DEVICE_ID)]),
                (conflict_id, foreign_user, [str(_DEVICE_ID)]),
                (orphan_id, None, [str(uuid4())]),
            ]:
                connection.execute(
                    jobs.insert().values(
                        id=identifier,
                        created_by=creator,
                        device_ids=devices,
                        site_id=None,
                        status="pending",
                        backup_before=False,
                        rollback_on_failure=False,
                        batch_size=5,
                        delay_between_batches=30,
                        notify_on_complete=False,
                        notify_on_failure=False,
                        progress=0,
                        total_devices=1,
                        successful=0,
                        failed=0,
                        skipped=0,
                    )
                )
        engine.dispose()
        run_alembic(url.set(drivername="postgresql+asyncpg"), "upgrade", "head")
        with engine.connect() as connection:
            rows = {
                row.id: row
                for row in connection.execute(
                    sa.text(
                        "SELECT id, organization_id, target_site_ids FROM core.firmware_upgrade_jobs"
                    )
                )
            }
            assert rows[owned_id].organization_id == _ORG_ID
            assert rows[owned_id].target_site_ids == [str(_SITE_ID)]
            for identifier in (conflict_id, orphan_id):
                assert rows[identifier].organization_id is None
                assert rows[identifier].target_site_ids is None
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)
