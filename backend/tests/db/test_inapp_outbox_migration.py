# SPDX-License-Identifier: AGPL-3.0-only
"""Legacy bells are retained without replay; pending publication survives downgrade."""

import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.models.core import Organization, User
from app.models.notification import InAppNotification
from app.models.notification_outbox import InAppNotificationEvent
from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)
from tests.db.historical_downgrade import HISTORICAL_HEAD, require_current_audit_protection


def test_inapp_outbox_upgrade_preserves_legacy_bells_and_refuses_pending_loss(maintenance_engine, record_property):
    name = "freesdn_inapp_outbox_upgrade"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", "019_marketplace_catalog_state")
        with Session(engine) as db:
            assert not sa.inspect(engine).has_table("in_app_notification_events", schema="core")
            org = Organization(name="Owned migration fixture", slug="owned-outbox-migration")
            db.add(org)
            db.flush()
            user = User(
                organization_id=org.id,
                email="owned-migration@example.invalid",
                username="owned-migration",
                hashed_password="synthetic-not-a-login-password",
            )
            db.add(user)
            db.flush()
            notification = InAppNotification(
                user_id=user.id,
                organization_id=org.id,
                title="Legacy fixture",
                body="Preserve without replay",
            )
            db.add(notification)
            db.flush()
            identity, user_id, org_id = notification.id, user.id, org.id
            db.commit()
        run_alembic(url, "upgrade", HISTORICAL_HEAD)
        with Session(engine) as db:
            assert db.get(InAppNotification, identity).body == "Preserve without replay"
            assert db.scalar(sa.select(sa.func.count()).select_from(InAppNotificationEvent)) == 0
            db.add(
                InAppNotificationEvent(
                    notification_id=identity, user_id=user_id, organization_id=org_id
                )
            )
            db.commit()
        refusal = run_alembic(
            url, "downgrade", "019_marketplace_catalog_state", expect_success=False
        )
        assert refusal.returncode != 0 and "In-app event downgrade refused" in refusal.stderr
        with Session(engine) as db:
            row = db.get(InAppNotificationEvent, identity)
            assert row.status == "pending"
            row.status = "suppressed"
            db.commit()
        run_alembic(url, "downgrade", "019_marketplace_catalog_state")
        run_alembic(url, "upgrade", HISTORICAL_HEAD)
        with Session(engine) as db:
            assert db.get(InAppNotification, identity).body == "Preserve without replay"
            assert db.scalar(sa.select(sa.func.count()).select_from(InAppNotificationEvent)) == 0
        require_current_audit_protection(url, engine, "019_marketplace_catalog_state", record_property)
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)
