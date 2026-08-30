# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""What 008-011 actually fix, asserted as behaviour rather than as schema shape.

The sibling module compares the upgraded schema against ``Base.metadata``. This one
runs the four operations that fail on a pre-2026-06-22 appliance, once BEFORE the
upgrade to prove the fixture really is broken (a precondition this suite has fabricated
before) and once after to prove the migrations fixed it -- plus the three data cases the
migrations have to get right and cannot get from the models.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, Engine

from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)

_SCRATCH_DB = "freesdn_migbehaviour_test"

_ORG_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
_DELETED_USER_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
_REUSED_EMAIL = "reonboard@example.com"
_TARGETLESS_SCHEDULE_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")
_DOUBLE_TARGET_SCHEDULE_ID = uuid.UUID("55555555-5555-5555-5555-555555555555")
_DEVICE_ID = uuid.UUID("66666666-6666-6666-6666-666666666666")
_GROUP_ID = uuid.UUID("77777777-7777-7777-7777-777777777777")
_SITE_ID = uuid.UUID("88888888-8888-8888-8888-888888888888")
_SUBSCRIPTION_ID = uuid.UUID("99999999-9999-9999-9999-999999999999")
_PLUGIN_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_REVIEWER_ID = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
_OTHER_REVIEWER_ID = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
_REVIEW_ID = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")

# One statement per entry: psycopg3 refuses a multi-statement query that carries
# parameters. Column lists are the NOT NULL columns without a server default, so the
# seed does not depend on defaults that could change.
_SEED = (
    """
    INSERT INTO core.organizations (id, name, slug, is_active, settings)
    VALUES (:org_id, 'Seed Org', 'seed-org', true, '{}'::jsonb)
    """,
    """
    INSERT INTO core.sites (id, organization_id, name, slug, timezone, time_format,
                            date_format, subnets, settings, is_active)
    VALUES (:site_id, :org_id, 'Seed Site', 'seed-site', 'UTC', '24h', 'YYYY-MM-DD',
            '[]'::jsonb, '{}'::jsonb, true)
    """,
    # A user the operator soft-deleted, exactly as DELETE /api/v1/users/{id} does.
    """
    INSERT INTO core.users (id, organization_id, email, username, hashed_password, role,
                            mfa_enabled, is_active, is_verified, failed_login_attempts,
                            language, preferences, deleted_at)
    VALUES (:user_id, :org_id, :email, 'reonboard', 'x', 'viewer',
            false, true, true, 0, 'en', '{}'::jsonb, now())
    """,
    # A disabled subscription, stored the way the legacy String(10) column stored it.
    """
    INSERT INTO events.event_subscriptions (id, name, pattern, target_type, target_config,
                                            organization_id, is_active, trigger_count,
                                            retry_count, retry_delay_seconds)
    VALUES (:sub_id, 'seed sub', 'device.*', 'webhook', '{}'::jsonb, :org_id, 'false',
            0, 3, 60)
    """,
    """
    INSERT INTO devices.devices (id, site_id, name, device_type, status, "metadata",
                                 capabilities, lifecycle_state, is_active, is_managed,
                                 is_adopted, discovery_data)
    VALUES (:device_id, :site_id, 'seed-device', 'switch', 'online', '{}'::jsonb,
            '{}'::jsonb, 'active', true, true, true, '{}'::jsonb)
    """,
    """
    INSERT INTO devices.device_groups (id, organization_id, site_id, name, match_rules,
                                       is_active)
    VALUES (:group_id, :org_id, :site_id, 'seed-group', '{}'::jsonb, true)
    """,
    # Only creatable because the XOR constraint is missing: no target at all.
    """
    INSERT INTO devices.poe_schedules (id, organization_id, device_id, device_group_id,
                                       name, enabled, port_numbers, power_off_time,
                                       power_on_time, days_of_week, timezone)
    VALUES (:targetless_id, :org_id, NULL, NULL, 'targetless', true, '[1]'::jsonb,
            '22:00', '06:00', '[0,1,2,3,4,5,6]'::jsonb, 'UTC')
    """,
    # Also only creatable without the constraint: BOTH targets set.
    """
    INSERT INTO devices.poe_schedules (id, organization_id, device_id, device_group_id,
                                       name, enabled, port_numbers, power_off_time,
                                       power_on_time, days_of_week, timezone)
    VALUES (:double_id, :org_id, :device_id, :group_id, 'both-targets', true,
            '[2]'::jsonb, '23:00', '05:00', '[0,1,2,3,4,5,6]'::jsonb, 'UTC')
    """,
    # One ordinary review. The 011 branch that ADDS the constraint has to survive a
    # table that already holds rows; the duplicate case gets its own database below.
    """
    INSERT INTO core.plugin_reviews (id, marketplace_plugin_id, user_id, rating, title,
                                     body)
    VALUES (:review_id, :plugin_id, :reviewer_id, 5, 'works', 'adopted our whole fleet')
    """,
)

_SEED_PARAMS = {
    "org_id": _ORG_ID,
    "site_id": _SITE_ID,
    "user_id": _DELETED_USER_ID,
    "email": _REUSED_EMAIL,
    "sub_id": _SUBSCRIPTION_ID,
    "device_id": _DEVICE_ID,
    "group_id": _GROUP_ID,
    "targetless_id": _TARGETLESS_SCHEDULE_ID,
    "double_id": _DOUBLE_TARGET_SCHEDULE_ID,
    "review_id": _REVIEW_ID,
    "plugin_id": _PLUGIN_ID,
    "reviewer_id": _REVIEWER_ID,
}

# What POST /api/v1/marketplace/plugins/{id}/reviews inserts. The endpoint's
# best-effort SELECT pre-check is skipped here on purpose: this is the loser of the
# race the IntegrityError -> 409 arm is supposed to catch.
_SECOND_REVIEW = sa.text(
    """
    INSERT INTO core.plugin_reviews (id, marketplace_plugin_id, user_id, rating, title,
                                     body, created_at, updated_at)
    VALUES (gen_random_uuid(), :plugin_id, :user_id, :rating, 'again', 'second ballot',
            now(), now())
    """
)

_REONBOARD = sa.text(
    """
    INSERT INTO core.users (id, organization_id, email, username, hashed_password, role,
                            mfa_enabled, is_active, is_verified, failed_login_attempts,
                            language, preferences, created_at, updated_at)
    VALUES (gen_random_uuid(), :org_id, :email, 'reonboard-2', 'x', 'viewer',
            false, true, true, 0, 'en', '{}'::jsonb, now(), now())
    """
)

_TARGETLESS_INSERT = sa.text(
    """
    INSERT INTO devices.poe_schedules (id, organization_id, device_id, device_group_id,
                                       name, enabled, port_numbers, power_off_time,
                                       power_on_time, days_of_week, timezone,
                                       created_at, updated_at)
    VALUES (gen_random_uuid(), :org_id, NULL, NULL, 'new-targetless', true, '[3]'::jsonb,
            '21:00', '07:00', '[0,1,2,3,4,5,6]'::jsonb, 'UTC', now(), now())
    """
)

# What app/services/event_service.py compiles for ?is_active=true.
_ACTIVE_FILTER = sa.text("SELECT count(*) FROM events.event_subscriptions WHERE is_active = true")


@pytest.fixture(scope="module")
def pre_fix_engine(maintenance_engine: sa.Engine) -> Iterator[Engine]:
    """A pre-fix database, seeded, BEFORE 008-010 run."""
    url = build_pre_fix_database(maintenance_engine, _SCRATCH_DB)
    engine = scratch_engine(url)
    with engine.begin() as conn:
        for statement in _SEED:
            conn.execute(sa.text(statement), _SEED_PARAMS)
    try:
        yield engine
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, _SCRATCH_DB)


@pytest.fixture(scope="module")
def upgraded_engine(pre_fix_engine: Engine) -> Iterator[Engine]:
    """The same database after ``alembic upgrade head``.

    Depends on ``pre_fix_engine`` so the broken-state assertions below run first: this
    module proves the precondition instead of assuming it.
    """
    url: URL = pre_fix_engine.url.set(drivername="postgresql+asyncpg")
    pre_fix_engine.dispose()
    run_alembic(url, "upgrade", "head")
    engine = scratch_engine(url)
    yield engine
    engine.dispose()


# --------------------------------------------------------------------------------
# The precondition: all three really are broken before the migrations run.
# --------------------------------------------------------------------------------


def test_before_upgrade_the_is_active_filter_is_a_hard_error(pre_fix_engine: Engine) -> None:
    with pre_fix_engine.connect() as conn, pytest.raises(sa.exc.ProgrammingError) as exc:
        conn.execute(_ACTIVE_FILTER)
    assert "character varying = boolean" in str(exc.value)


def test_before_upgrade_a_soft_deleted_email_cannot_be_reused(pre_fix_engine: Engine) -> None:
    with pre_fix_engine.connect() as conn, pytest.raises(sa.exc.IntegrityError) as exc:
        conn.execute(_REONBOARD, {"org_id": _ORG_ID, "email": _REUSED_EMAIL})
    assert _REUSED_EMAIL in str(exc.value)


def test_before_upgrade_a_targetless_poe_schedule_is_accepted(pre_fix_engine: Engine) -> None:
    with pre_fix_engine.connect() as conn:
        conn.execute(_TARGETLESS_INSERT, {"org_id": _ORG_ID})
        conn.rollback()


def test_before_upgrade_a_second_review_by_the_same_user_is_accepted(
    pre_fix_engine: Engine,
) -> None:
    """The race the endpoint's ``IntegrityError -> 409`` arm is meant to lose.

    Nothing raises here, so that arm never runs and the loser of two concurrent
    POSTs writes a second ballot the plugin's rating average then counts twice.
    """
    with pre_fix_engine.connect() as conn:
        conn.execute(
            _SECOND_REVIEW, {"plugin_id": _PLUGIN_ID, "user_id": _REVIEWER_ID, "rating": 1}
        )
        conn.rollback()


# --------------------------------------------------------------------------------
# After the upgrade.
# --------------------------------------------------------------------------------


def test_upgrade_makes_the_is_active_filter_work(upgraded_engine: Engine) -> None:
    with upgraded_engine.connect() as conn:
        assert conn.execute(_ACTIVE_FILTER).scalar() == 0


def test_upgrade_preserves_the_stored_is_active_value(upgraded_engine: Engine) -> None:
    """``'false'`` must land on ``false``, not on ``bool('false') is True``.

    A retype that mapped every row to the default would look identical to the test
    above (both give count 0 for a single row) but would silently re-enable a
    subscription the operator had disabled.
    """
    with upgraded_engine.connect() as conn:
        value = conn.execute(
            sa.text("SELECT is_active FROM events.event_subscriptions WHERE id = :id"),
            {"id": _SUBSCRIPTION_ID},
        ).scalar()
    assert value is False


def test_upgrade_frees_a_soft_deleted_email(upgraded_engine: Engine) -> None:
    with upgraded_engine.connect() as conn:
        conn.execute(_REONBOARD, {"org_id": _ORG_ID, "email": _REUSED_EMAIL})
        # And the soft-deleted row is still there -- this frees the identifier, it does
        # not purge history.
        assert (
            conn.execute(
                sa.text("SELECT count(*) FROM core.users WHERE id = :id"),
                {"id": _DELETED_USER_ID},
            ).scalar()
            == 1
        )
        conn.rollback()


def test_upgrade_still_blocks_a_duplicate_live_email(upgraded_engine: Engine) -> None:
    """The partial index must keep rejecting a collision among LIVE rows.

    A "fix" that simply dropped the unique enforcement would pass every other
    assertion in this module.
    """
    with upgraded_engine.connect() as conn:
        conn.execute(_REONBOARD, {"org_id": _ORG_ID, "email": "live@example.com"})
        with pytest.raises(sa.exc.IntegrityError):
            conn.execute(_REONBOARD, {"org_id": _ORG_ID, "email": "live@example.com"})
        conn.rollback()


def test_upgrade_rejects_a_new_targetless_poe_schedule(upgraded_engine: Engine) -> None:
    """Even though a targetless row already exists, so the constraint is NOT VALID."""
    with upgraded_engine.connect() as conn, pytest.raises(sa.exc.IntegrityError) as exc:
        conn.execute(_TARGETLESS_INSERT, {"org_id": _ORG_ID})
    assert "ck_poe_schedules_ck_poe_schedule_xor_target" in str(exc.value)


def test_upgrade_keeps_the_existing_targetless_schedule(upgraded_engine: Engine) -> None:
    """The operator's inert row survives; the migration does not delete their data."""
    with upgraded_engine.connect() as conn:
        row = conn.execute(
            sa.text("SELECT device_id, device_group_id FROM devices.poe_schedules WHERE id = :id"),
            {"id": _TARGETLESS_SCHEDULE_ID},
        ).fetchone()
    assert row is not None
    assert row.device_id is None
    assert row.device_group_id is None


def test_upgrade_repairs_a_double_target_schedule_without_changing_what_it_does(
    upgraded_engine: Engine,
) -> None:
    """``app/tasks/poe.py`` resolves ``device_id`` first, so clearing the group is a no-op
    for behaviour -- but clearing ``device_id`` instead would silently retarget the
    schedule at a whole group.
    """
    with upgraded_engine.connect() as conn:
        row = conn.execute(
            sa.text("SELECT device_id, device_group_id FROM devices.poe_schedules WHERE id = :id"),
            {"id": _DOUBLE_TARGET_SCHEDULE_ID},
        ).fetchone()
    assert row is not None
    assert row.device_id == _DEVICE_ID
    assert row.device_group_id is None


def test_upgrade_rejects_a_second_review_by_the_same_user(upgraded_engine: Engine) -> None:
    """011 gives the endpoint's ``IntegrityError -> 409`` arm something to catch."""
    with upgraded_engine.connect() as conn, pytest.raises(sa.exc.IntegrityError) as exc:
        conn.execute(
            _SECOND_REVIEW, {"plugin_id": _PLUGIN_ID, "user_id": _REVIEWER_ID, "rating": 1}
        )
    assert "uq_plugin_review_user_plugin" in str(exc.value)


def test_upgrade_still_admits_a_review_from_a_different_user(upgraded_engine: Engine) -> None:
    """The constraint is per (plugin, USER), not per plugin.

    A "fix" that made the pair unique on ``marketplace_plugin_id`` alone would pass
    the test above and let one review per plugin exist in the entire product.
    """
    with upgraded_engine.connect() as conn:
        conn.execute(
            _SECOND_REVIEW, {"plugin_id": _PLUGIN_ID, "user_id": _OTHER_REVIEWER_ID, "rating": 4}
        )
        conn.rollback()


def test_upgrade_keeps_the_existing_review(upgraded_engine: Engine) -> None:
    """Adding the constraint must not touch review text anybody wrote."""
    with upgraded_engine.connect() as conn:
        body = conn.execute(
            sa.text("SELECT body FROM core.plugin_reviews WHERE id = :id"),
            {"id": _REVIEW_ID},
        ).scalar()
    assert body == "adopted our whole fleet"


def test_upgrade_leaves_the_constraint_not_valid_while_a_bad_row_remains(
    upgraded_engine: Engine,
) -> None:
    """Adding it validated would have aborted the upgrade on the targetless row.

    ``convalidated = false`` is the honest state: enforced from now on, not retroactively
    claimed to hold.
    """
    with upgraded_engine.connect() as conn:
        validated = conn.execute(
            sa.text(
                """
                SELECT con.convalidated
                FROM pg_constraint con
                JOIN pg_class c ON c.oid = con.conrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'devices'
                  AND c.relname = 'poe_schedules'
                  AND con.conname = 'ck_poe_schedules_ck_poe_schedule_xor_target'
                """
            )
        ).scalar()
    assert validated is False


# --------------------------------------------------------------------------------
# 011's other branch: an appliance that already holds duplicate reviews.
# --------------------------------------------------------------------------------
#
# A UNIQUE constraint cannot be added NOT VALID, so 010's "enforce from now on, leave
# the bad rows readable" trick is unavailable here. 011 refuses to choose between
# aborting the operator's upgrade and deleting review text somebody wrote: it skips
# the constraint and reports. That decision is load-bearing and asserted below, on a
# database of its own so the seeded duplicates cannot leak into the module above.

_DUP_SCRATCH_DB = "freesdn_migdupreview_test"

_DUP_SEED = sa.text(
    """
    INSERT INTO core.plugin_reviews (id, marketplace_plugin_id, user_id, rating, title,
                                     body, created_at, updated_at)
    VALUES (gen_random_uuid(), :plugin_id, :user_id, :rating, :title, :body,
            now(), now())
    """
)


@pytest.fixture(scope="module")
def duplicate_review_upgrade(
    maintenance_engine: sa.Engine,
) -> Iterator[tuple[Engine, str]]:
    """A pre-fix database holding two reviews by one user, upgraded to head."""
    url = build_pre_fix_database(maintenance_engine, _DUP_SCRATCH_DB)
    engine = scratch_engine(url)
    with engine.begin() as conn:
        for rating, title, body in ((5, "first", "loved it"), (1, "second", "hated it")):
            conn.execute(
                _DUP_SEED,
                {
                    "plugin_id": _PLUGIN_ID,
                    "user_id": _REVIEWER_ID,
                    "rating": rating,
                    "title": title,
                    "body": body,
                },
            )
    engine.dispose()

    result = run_alembic(url.set(drivername="postgresql+asyncpg"), "upgrade", "head")
    engine = scratch_engine(url)
    try:
        yield engine, result.stdout + result.stderr
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, _DUP_SCRATCH_DB)


def test_duplicates_do_not_abort_the_upgrade(
    duplicate_review_upgrade: tuple[Engine, str],
) -> None:
    """The rest of the chain must still land.

    ``run_alembic`` raises on a non-zero exit, so reaching this assertion at all is
    the result: an appliance is not left unpatchable because of a plugin review.
    """
    engine, _output = duplicate_review_upgrade
    with engine.connect() as conn:
        version = conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()
    assert version == "011_plugin_review_user_uq"


def test_duplicates_are_never_deleted(duplicate_review_upgrade: tuple[Engine, str]) -> None:
    """Both reviews survive, with their text intact.

    The alternative repair -- dedupe so the constraint can be added -- destroys
    something a user wrote, on their production database, to satisfy a constraint
    that has been absent for two months.
    """
    engine, _output = duplicate_review_upgrade
    with engine.connect() as conn:
        bodies = (
            conn.execute(
                sa.text(
                    """
                SELECT body FROM core.plugin_reviews
                WHERE marketplace_plugin_id = :plugin_id AND user_id = :user_id
                ORDER BY rating
                """
                ),
                {"plugin_id": _PLUGIN_ID, "user_id": _REVIEWER_ID},
            )
            .scalars()
            .all()
        )
    assert list(bodies) == ["hated it", "loved it"]


def test_duplicates_leave_the_constraint_off(
    duplicate_review_upgrade: tuple[Engine, str],
) -> None:
    """Skipped, not silently half-applied.

    Asserted so nobody "simplifies" 011 into an unconditional ADD CONSTRAINT, which
    would abort the upgrade of exactly the databases that need the rest of the chain.
    """
    engine, _output = duplicate_review_upgrade
    with engine.connect() as conn:
        present = conn.execute(
            sa.text(
                """
                SELECT 1 FROM pg_constraint con
                JOIN pg_class c ON c.oid = con.conrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'core' AND c.relname = 'plugin_reviews'
                  AND con.conname = 'uq_plugin_review_user_plugin'
                """
            )
        ).scalar()
    assert present is None


def test_duplicates_are_reported_with_the_repair(
    duplicate_review_upgrade: tuple[Engine, str],
) -> None:
    """Skipping silently would be the worst of the three options.

    Once 011 is stamped it never runs again, so the operator's only signal that the
    guard is still missing is this message -- it has to name the pair AND carry the
    statement that finishes the job.
    """
    _engine, output = duplicate_review_upgrade
    assert "WARNING" in output
    assert str(_PLUGIN_ID) in output and str(_REVIEWER_ID) in output
    assert "ADD CONSTRAINT" in output and "uq_plugin_review_user_plugin" in output
