# SPDX-License-Identifier: AGPL-3.0-only
"""The real 017 schema must preserve history without approving legacy notices."""

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


def test_017_upgrade_leaves_epoch_unapproved_and_preserves_history(maintenance_engine, record_property):
    name = "freesdn_report_recovery_upgrade"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    identifiers = {state: uuid4() for state in ["pending", "sending", "accepted", "unknown"]}
    try:
        with engine.begin() as connection:
            for statement in _SEED:
                connection.execute(sa.text(statement), _SEED_PARAMS)
        run_alembic(url, "upgrade", "017_sla_report_delivery")
        with engine.begin() as connection:
            assert "delivery_epoch" not in {
                c["name"]
                for c in sa.inspect(connection).get_columns(
                    "sla_report_deliveries", schema="analytics"
                )
            }
            for state, identifier in identifiers.items():
                connection.execute(
                    sa.text(
                        "INSERT INTO analytics.sla_report_deliveries "
                        "(id, organization_id, recipient_email, approval_revision, state, attempts) "
                        "VALUES (:id, :org, 'synthetic@example.test', :revision, :state, 1)"
                    ),
                    {"id": identifier, "org": _ORG_ID, "revision": str(uuid4()), "state": state},
                )
        run_alembic(url, "upgrade", HISTORICAL_HEAD)
        with engine.connect() as connection:
            upgraded_revision = connection.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            rows = connection.execute(
                sa.text(
                    "SELECT id, state, attempts, delivery_epoch FROM analytics.sla_report_deliveries"
                )
            ).all()
            assert {r.state: r.id for r in rows} == identifiers
            assert all(r.attempts == 1 and r.delivery_epoch is None for r in rows)
        refused = run_alembic(url, "downgrade", "017_sla_report_delivery", expect_success=False)
        assert refused.returncode != 0
        assert "preserve and reconcile delivery history" in refused.stderr
        with engine.connect() as connection:
            # A refused downgrade must roll back the entire migration chain,
            # including newer revisions traversed before reaching the guard.
            assert (
                connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()
                == upgraded_revision
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM analytics.sla_report_deliveries")
                ).scalar()
                == 4
            )
        require_current_audit_protection(url, engine, "017_sla_report_delivery", record_property)
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)
