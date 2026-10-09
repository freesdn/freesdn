# SPDX-License-Identifier: AGPL-3.0-only
"""Upgrade frozen legacy schema, preserve intent, and do not resume schedules."""

from datetime import UTC, datetime
from uuid import uuid4

import sqlalchemy as sa

from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)
from tests.db.historical_downgrade import HISTORICAL_HEAD, require_current_audit_protection
from tests.db.test_legacy_upgrade_behaviour import _ORG_ID, _SEED, _SEED_PARAMS


def test_calendar_upgrade_requires_timing_review_without_discarding_approval(maintenance_engine, record_property):
    name = "freesdn_sla_calendar_upgrade"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    approved_id, legacy_id = uuid4(), uuid4()
    due = datetime(2026, 10, 6, 17, 45, tzinfo=UTC)
    approval = {"version": 1, "retained_for_test": True}
    try:
        with engine.begin() as connection:
            for statement in _SEED:
                connection.execute(sa.text(statement), _SEED_PARAMS)
        run_alembic(url, "upgrade", "013_sla_schedule_authorization")
        with engine.begin() as connection:
            table = sa.Table(
                "sla_report_schedules", sa.MetaData(), schema="analytics", autoload_with=connection
            )
            assert "timezone" not in table.c and "time_of_day" not in table.c
            for identifier, enabled, scope, error in [
                (approved_id, True, approval, None),
                (legacy_id, False, None, "approval_required"),
            ]:
                connection.execute(
                    table.insert().values(
                        id=identifier,
                        organization_id=_ORG_ID,
                        name="Preserve timing intent",
                        frequency="monthly",
                        day_of_month=6,
                        enabled=enabled,
                        execution_scope=scope,
                        execution_error=error,
                        next_run_at=due,
                        recipients=[],
                        sla_policy_ids=[],
                    )
                )
        run_alembic(url, "upgrade", HISTORICAL_HEAD)
        with engine.connect() as connection:
            table = sa.Table(
                "sla_report_schedules", sa.MetaData(), schema="analytics", autoload_with=connection
            )
            row = connection.execute(sa.select(table).where(table.c.id == approved_id)).one()
            assert not row.enabled and row.execution_error == "timing_review_required"
            assert row.execution_scope == approval
            assert row.timezone == "UTC" and row.time_of_day == "17:45"
            assert row.day_of_month == 6 and row.next_run_at == due
            legacy = connection.execute(sa.select(table).where(table.c.id == legacy_id)).one()
            assert not legacy.enabled and legacy.execution_error == "approval_required"
            assert legacy.execution_scope is None
        run_alembic(url, "downgrade", "013_sla_schedule_authorization")
        with engine.connect() as connection:
            table = sa.Table(
                "sla_report_schedules", sa.MetaData(), schema="analytics", autoload_with=connection
            )
            assert "timezone" not in table.c and "time_of_day" not in table.c
            row = connection.execute(sa.select(table).where(table.c.id == approved_id)).one()
            assert not row.enabled and row.execution_scope == approval
        require_current_audit_protection(url, engine, "013_sla_schedule_authorization", record_property)
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)
