# SPDX-License-Identifier: AGPL-3.0-only
"""Upgrade real legacy rows without granting them invented background authority."""

from uuid import uuid4

import sqlalchemy as sa

from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)
from tests.db.test_legacy_upgrade_behaviour import _ORG_ID, _SEED, _SEED_PARAMS


def test_legacy_schedules_require_explicit_reapproval(maintenance_engine):
    name = "freesdn_sla_schedule_upgrade"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    identifier = uuid4()
    try:
        with engine.begin() as connection:
            for statement in _SEED:
                connection.execute(sa.text(statement), _SEED_PARAMS)
            schedule = sa.Table(
                "sla_report_schedules", sa.MetaData(), schema="analytics", autoload_with=connection
            )
            assert "execution_scope" not in schedule.c
            connection.execute(
                schedule.insert().values(
                    id=identifier,
                    organization_id=_ORG_ID,
                    name="Legacy report",
                    frequency="monthly",
                    enabled=True,
                    recipients=[],
                    sla_policy_ids=[],
                )
            )
        run_alembic(url, "upgrade", "head")
        with engine.connect() as connection:
            row = connection.execute(
                sa.text(
                    "SELECT enabled, execution_scope, execution_error, name "
                    "FROM analytics.sla_report_schedules WHERE id = :id"
                ),
                {"id": identifier},
            ).one()
            assert not row.enabled
            assert row.execution_scope is None
            assert row.execution_error == "approval_required"
            assert row.name == "Legacy report"
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)
