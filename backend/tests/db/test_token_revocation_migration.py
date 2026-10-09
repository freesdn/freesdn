# SPDX-License-Identifier: AGPL-3.0-only
"""Security cutover from a real pre-fix schema, including downgrade refusal to revive sessions."""

import sqlalchemy as sa

from tests.db.conftest import (
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)
from tests.db.historical_downgrade import HISTORICAL_HEAD, require_current_audit_protection
from tests.db.test_legacy_upgrade_behaviour import _DELETED_USER_ID, _SEED, _SEED_PARAMS


def test_revocation_cutover_invalidates_account_tokens_and_preserves_on_downgrade(
    maintenance_engine, record_property,
):
    name = "freesdn_token_revocation_upgrade"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        with engine.begin() as connection:
            for statement in _SEED:
                connection.execute(sa.text(statement), _SEED_PARAMS)
        run_alembic(url, "upgrade", "015_proxmox_task_tracking")
        with engine.begin() as connection:
            connection.execute(
                sa.text("""
                INSERT INTO core.user_sessions (id, user_id, refresh_jti, created_at,
                                                expires_at, is_revoked)
                VALUES (gen_random_uuid(), :id, 'migration-test-session', now(),
                        now() + interval '1 day', false)
            """),
                {"id": _DELETED_USER_ID},
            )
            before = (
                connection.execute(
                    sa.text("SELECT token_version FROM core.users WHERE id=:id"),
                    {"id": _DELETED_USER_ID},
                ).scalar_one()
                or 0
            )
            assert not sa.inspect(connection).has_table("token_revocations", schema="core")
        run_alembic(url, "upgrade", HISTORICAL_HEAD)
        with engine.connect() as connection:
            assert (
                connection.execute(
                    sa.text("SELECT token_version FROM core.users WHERE id=:id"),
                    {"id": _DELETED_USER_ID},
                ).scalar_one()
                == before + 1
            )
            assert (
                connection.execute(
                    sa.text(
                        "SELECT is_revoked AND revoked_at IS NOT NULL FROM core.user_sessions "
                        "WHERE refresh_jti='migration-test-session'"
                    )
                ).scalar_one()
                is True
            )
            assert sa.inspect(connection).has_table("token_revocations", schema="core")
            assert {
                i["name"]
                for i in sa.inspect(connection).get_indexes("token_revocations", schema="core")
            } == {"ix_token_revocations_expires_at"}
        run_alembic(url, "downgrade", "015_proxmox_task_tracking")
        with engine.connect() as connection:
            assert (
                connection.execute(
                    sa.text("SELECT token_version FROM core.users WHERE id=:id"),
                    {"id": _DELETED_USER_ID},
                ).scalar_one()
                == before + 2
            )
            assert (
                connection.execute(
                    sa.text(
                        "SELECT is_revoked AND revoked_at IS NOT NULL FROM core.user_sessions "
                        "WHERE refresh_jti='migration-test-session'"
                    )
                ).scalar_one()
                is True
            )
            assert not sa.inspect(connection).has_table("token_revocations", schema="core")
        require_current_audit_protection(url, engine, "015_proxmox_task_tracking", record_property)
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)
