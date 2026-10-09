# SPDX-License-Identifier: AGPL-3.0-only
"""Frozen legacy schema upgrades cannot silently enable external mail."""

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


def test_upgrade_preserves_reports_and_requires_delivery_opt_in(maintenance_engine, record_property):
    name = "freesdn_sla_delivery_upgrade"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    identifier, provider_id = uuid4(), uuid4()
    try:
        with engine.begin() as connection:
            for statement in _SEED:
                connection.execute(sa.text(statement), _SEED_PARAMS)
        run_alembic(url, "upgrade", "016_durable_token_revocations")
        with engine.begin() as connection:
            schedule = sa.Table(
                "sla_report_schedules", sa.MetaData(), schema="analytics", autoload_with=connection
            )
            assert "delivery_enabled" not in schedule.c
            connection.execute(
                schedule.insert().values(
                    id=identifier,
                    organization_id=_ORG_ID,
                    name="Existing schedule",
                    frequency="monthly",
                    enabled=True,
                    recipients=["external@example.test"],
                    sla_policy_ids=[],
                    timezone="UTC",
                    time_of_day="09:00",
                )
            )
            provider = sa.Table(
                "notification_providers", sa.MetaData(), schema="core", autoload_with=connection
            )
            connection.execute(
                provider.insert().values(
                    id=provider_id,
                    organization_id=_ORG_ID,
                    name="Existing relay",
                    provider_type="smtp",
                    channel="email",
                    is_enabled=True,
                    is_default=False,
                    is_verified=True,
                    config={},
                    rate_limit_per_hour=10,
                    rate_limit_per_day=100,
                )
            )
        run_alembic(url, "upgrade", HISTORICAL_HEAD)
        with engine.connect() as connection:
            row = connection.execute(
                sa.text(
                    "SELECT enabled, recipients, delivery_enabled, delivery_approval FROM analytics.sla_report_schedules WHERE id=:id"
                ),
                {"id": identifier},
            ).one()
            assert row.enabled and row.recipients == ["external@example.test"]
            assert not row.delivery_enabled and row.delivery_approval is None
            assert not connection.execute(
                sa.text("SELECT is_verified FROM core.notification_providers WHERE id=:id"),
                {"id": provider_id},
            ).scalar()
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM analytics.sla_report_deliveries")
                ).scalar()
                == 0
            )
        run_alembic(url, "downgrade", "016_durable_token_revocations")
        run_alembic(url, "upgrade", HISTORICAL_HEAD)
        with engine.connect() as connection:
            assert not connection.execute(
                sa.text("SELECT delivery_enabled FROM analytics.sla_report_schedules WHERE id=:id"),
                {"id": identifier},
            ).scalar()
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO analytics.sla_report_deliveries "
                    "(id, organization_id, recipient_email, approval_revision, state, attempts) "
                    "VALUES (:id, :org, 'synthetic@example.test', :revision, 'unknown', 1)"
                ),
                {"id": uuid4(), "org": _ORG_ID, "revision": str(uuid4())},
            )
        result = run_alembic(
            url, "downgrade", "016_durable_token_revocations", expect_success=False
        )
        assert result.returncode != 0 and "preserve and reconcile delivery history" in result.stderr
        with engine.connect() as connection:
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM analytics.sla_report_deliveries")
                ).scalar()
                == 1
            )
        require_current_audit_protection(url, engine, "016_durable_token_revocations", record_property)
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)
