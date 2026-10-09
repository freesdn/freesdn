# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real legacy upgrade, writer exclusion and external binding ownership checks."""

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.models.core import Organization, User
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus
from tests.db.conftest import (
    BACKEND_ROOT,
    build_pre_fix_database,
    drop_scratch_database,
    make_scratch_database,
    run_alembic,
    scratch_engine,
)

OLD = "021_credential_snmp_text"
NEW = "022_sso_binding_unique"
INDEX = "ix_users_external_binding"


def state(engine):
    with engine.connect() as connection:
        users = connection.execute(sa.text(
            "SELECT to_jsonb(u) FROM core.users u ORDER BY id",
        )).scalars().all()
        revision = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
        index = connection.execute(sa.text(
            "SELECT indexdef FROM pg_indexes WHERE schemaname='core' "
            "AND tablename='users' AND indexname=:name",
        ), {"name": INDEX}).scalar_one_or_none()
    return users, revision, index


@pytest.fixture
def legacy_binding(maintenance_engine):
    name = "freesdn_sso_binding_upgrade"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", OLD)
        assert state(engine)[1:] == (OLD, None)
        with Session(engine) as db:
            orgs = [Organization(name="Owned binding upgrade", slug=uuid4().hex)
                    for _ in range(2)]
            db.add_all(orgs)
            db.flush()
            providers = [SSOProvider(
                organization_id=org.id, name="Owned migration provider", slug=uuid4().hex,
                protocol=SSOProtocol.OIDC, status=SSOProviderStatus.ACTIVE,
                oidc_issuer="https://migration.example.com", oidc_client_id="owned-client",
                jit_provisioning=True, default_role="viewer",
            ) for org in orgs]
            db.add_all(providers)
            db.flush()
            ids = [(org.id, provider.id) for org, provider in zip(orgs, providers, strict=True)]
            db.commit()
        yield engine, url, ids
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


def insert_user(connection, owner, *, subject="owned-unique-subject", active=True, deleted=False):
    identity = uuid4()
    # Bypass application advisory locks to cover old or independent SQL writers.
    connection.execute(sa.insert(User.__table__).values(
        id=identity, organization_id=owner[0], sso_provider_id=owner[1],
        auth_provider="oidc" if owner[1] else None, external_id=subject,
        username=identity.hex, email=identity.hex + "@example.com",
        hashed_password="!SSO_MANAGED" if owner[1] else "!",
        role="viewer", is_active=active, is_verified=True,
        token_version=7, failed_login_attempts=0, mfa_enabled=False,
        language="en", preferences={}, deleted_at=datetime.now(UTC) if deleted else None,
    ))
    return identity


def audit(url):
    env = {**os.environ, "DATABASE_URL": url.render_as_string(hide_password=False)}
    return subprocess.run(
        [sys.executable, "-B", "scripts/audit_sso_bindings.py"],
        cwd=BACKEND_ROOT, env=env, capture_output=True, text=True, timeout=20, check=False,
    )


def test_fresh_and_incremental_binding_index_match_without_rewriting_users(
    legacy_binding, maintenance_engine,
):
    engine, url, owners = legacy_binding
    with engine.begin() as connection:
        insert_user(connection, owners[0])
    before = state(engine)
    run_alembic(url, "upgrade", NEW)
    after = state(engine)
    assert after[0] == before[0] and after[1] == NEW
    assert "UNIQUE INDEX" in after[2]
    fresh_name = "freesdn_sso_binding_fresh"
    fresh_url = make_scratch_database(maintenance_engine, fresh_name)
    fresh = scratch_engine(fresh_url)
    try:
        # 001 builds live models; unlike the legacy fixture, this is explicitly
        # the fresh path. Reaching 022 must accept the exact model-built index.
        run_alembic(fresh_url, "upgrade", NEW)
        assert state(fresh)[1:] == after[1:]
    finally:
        fresh.dispose()
        drop_scratch_database(maintenance_engine, fresh_name)


@pytest.mark.parametrize("case", ["active", "disabled", "foreign-org"])
def test_legacy_duplicates_stop_upgrade_without_changing_accounts_or_revision(legacy_binding, case):
    engine, url, owners = legacy_binding
    with engine.begin() as connection:
        first = insert_user(connection, owners[0])
        second_owner = (owners[1][0], owners[0][1]) if case == "foreign-org" else owners[0]
        second = insert_user(connection, second_owner, active=case != "disabled")
    before = state(engine)
    refusal = run_alembic(url, "upgrade", NEW, expect_success=False)
    report = audit(url)
    observed = state(engine)
    assert refusal.returncode != 0 and "multiple nondeleted accounts" in refusal.stderr
    assert observed == before
    assert report.returncode == 1
    body = json.loads(report.stdout)
    assert body["read_only"] and body["duplicate_groups"] == 1
    assert set(body["groups"][0]["account_ids"]) == {str(first), str(second)}
    assert body["groups"][0]["account_count"] == 2
    assert "owned-unique-subject" not in report.stdout and "@example.com" not in report.stdout
    assert "!SSO_MANAGED" not in report.stdout and not report.stderr


@pytest.mark.parametrize("case", ["deleted", "different-provider", "unbound"])
def test_distinct_or_retired_bindings_upgrade_without_data_changes(legacy_binding, case):
    engine, url, owners = legacy_binding
    with engine.begin() as connection:
        insert_user(connection, owners[0])
        owner = owners[1] if case == "different-provider" else owners[0]
        if case == "unbound":
            owner = (owners[0][0], None)
        insert_user(connection, owner, deleted=case == "deleted", subject=None if case == "unbound" else "owned-unique-subject")
    before = state(engine)
    run_alembic(url, "upgrade", NEW)
    after = state(engine)
    report = audit(url)
    assert after[0] == before[0] and after[1] == NEW and after[2]
    assert report.returncode == 0 and json.loads(report.stdout)["duplicate_groups"] == 0
    assert state(engine) == after


@pytest.mark.parametrize("active", [True, False])
def test_downgrade_does_not_remove_live_or_disabled_binding_guard(legacy_binding, active):
    engine, url, owners = legacy_binding
    with engine.begin() as connection:
        insert_user(connection, owners[0], active=active)
    run_alembic(url, "upgrade", NEW)
    before = state(engine)
    refusal = run_alembic(url, "downgrade", OLD, expect_success=False)
    assert refusal.returncode != 0 and "downgrade refused while nondeleted" in refusal.stderr
    assert state(engine) == before


def test_empty_or_deleted_only_database_can_downgrade_without_deleting_rows(legacy_binding):
    engine, url, owners = legacy_binding
    with engine.begin() as connection:
        insert_user(connection, owners[0], deleted=True)
    before = state(engine)
    run_alembic(url, "upgrade", NEW)
    run_alembic(url, "downgrade", OLD)
    assert state(engine) == before


@pytest.mark.parametrize("definition", [
    "CREATE INDEX ix_users_external_binding ON core.users(sso_provider_id,external_id)",
    "CREATE UNIQUE INDEX ix_users_external_binding ON core.users(username,email)",
    "CREATE UNIQUE INDEX ix_users_external_binding ON core.users(sso_provider_id,external_id) WHERE is_active",
    "CREATE UNIQUE INDEX ix_users_external_binding ON core.users(sso_provider_id,external_id text_pattern_ops) "
    "WHERE deleted_at IS NULL AND sso_provider_id IS NOT NULL AND external_id IS NOT NULL",
    'CREATE UNIQUE INDEX ix_users_external_binding ON core.users(sso_provider_id,external_id COLLATE "C") '
    "WHERE deleted_at IS NULL AND sso_provider_id IS NOT NULL AND external_id IS NOT NULL",
])
def test_upgrade_preserves_and_refuses_unexpected_existing_index(legacy_binding, definition):
    engine, url, owners = legacy_binding
    with engine.begin() as connection:
        insert_user(connection, owners[0])
        connection.execute(sa.text(definition))
    before = state(engine)
    refusal = run_alembic(url, "upgrade", NEW, expect_success=False)
    assert refusal.returncode != 0 and "unexpected definition" in refusal.stderr
    assert state(engine) == before


def wait_for_owned_writer(engine, future, writer_pid, query_prefix):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        with engine.connect() as observer:
            rows = observer.execute(sa.text(
                "SELECT pid, pg_blocking_pids(pid) FROM pg_stat_activity "
                "WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE :prefix",
            ), {"prefix": query_prefix + "%"}).all()
        matches = [pid for pid, blockers in rows if writer_pid in blockers]
        if matches:
            assert not future.done() and len(matches) == 1
            return matches[0]
        if future.done():
            break
        time.sleep(0.025)
    raise AssertionError("Owned SQL operation never blocked behind the pinned writer")


@pytest.mark.parametrize("commit", [True, False])
def test_upgrade_locks_before_duplicate_inspection_of_inflight_old_writer(
    legacy_binding, commit, record_property,
):
    engine, url, owners = legacy_binding
    with engine.begin() as connection:
        insert_user(connection, owners[0])
    with ThreadPoolExecutor(max_workers=1) as pool, engine.connect() as writer:
        transaction = writer.begin()
        writer_pid = writer.scalar(sa.text("SELECT pg_backend_pid()"))
        insert_user(writer, owners[0])
        future = pool.submit(run_alembic, url, "upgrade", NEW, expect_success=False)
        try:
            migration_pid = wait_for_owned_writer(engine, future, writer_pid, "LOCK TABLE core.users")
            record_property("genuine_migration_writer_wait", migration_pid != writer_pid)
            if commit:
                transaction.commit()
            else:
                transaction.rollback()
        finally:
            if transaction.is_active:
                transaction.rollback()
        result = future.result(timeout=30)
    rows, revision, index = state(engine)
    record_property("committed_binding_rows", len(rows))
    if commit:
        assert result.returncode != 0 and "multiple nondeleted accounts" in result.stderr
        assert revision == OLD and index is None and len(rows) == 2
    else:
        assert result.returncode == 0
        assert revision == NEW and index and len(rows) == 1


@pytest.mark.parametrize("commit", [True, False])
def test_independent_writers_cannot_commit_duplicate_bindings(legacy_binding, commit, record_property):
    engine, url, owners = legacy_binding
    run_alembic(url, "upgrade", NEW)

    def contender():
        try:
            with engine.begin() as connection:
                pid = connection.scalar(sa.text("SELECT pg_backend_pid()"))
                identity = insert_user(connection, owners[0], active=False)
            return {"committed": True, "pid": pid, "id": str(identity), "sqlstate": None}
        except sa.exc.IntegrityError as exc:
            return {"committed": False, "pid": pid, "sqlstate": exc.orig.sqlstate,
                    "constraint": exc.orig.diag.constraint_name}

    with ThreadPoolExecutor(max_workers=1) as pool, engine.connect() as writer:
        transaction = writer.begin()
        writer_pid = writer.scalar(sa.text("SELECT pg_backend_pid()"))
        first_id = insert_user(writer, owners[0])
        future = pool.submit(contender)
        try:
            waiting_pid = wait_for_owned_writer(engine, future, writer_pid, "INSERT INTO core.users")
            record_property("genuine_unique_writer_wait", waiting_pid != writer_pid)
            if commit:
                transaction.commit()
            else:
                transaction.rollback()
        finally:
            if transaction.is_active:
                transaction.rollback()
        result = future.result(timeout=15)
    rows, revision, _ = state(engine)
    record_property("contender_committed", result["committed"])
    record_property("contender_sqlstate", result["sqlstate"])
    record_property("durable_binding_count", len(rows))
    assert result["pid"] == waiting_pid and revision == NEW and len(rows) == 1
    if commit:
        assert not result["committed"] and result["sqlstate"] == "23505"
        assert result["constraint"] == INDEX and rows[0]["id"] == str(first_id)
    else:
        assert result["committed"] and rows[0]["id"] == result["id"]


def test_legacy_audit_bounds_every_group_and_does_not_disclose_subjects(legacy_binding):
    engine, url, owners = legacy_binding
    with engine.begin() as connection:
        # Every group is oversized so selection order cannot accidentally hide
        # the per-group boundary case. Values are owned synthetic identities.
        for group in range(101):
            for _ in range(21):
                insert_user(connection, owners[0], subject=f"owned-private-subject-{group}")
    before = state(engine)
    report = audit(url)
    after = state(engine)
    assert report.returncode == 1 and not report.stderr
    body = json.loads(report.stdout)
    assert body["read_only"] and body["duplicate_groups"] == 101
    assert body["groups_truncated"] and len(body["groups"]) == 100
    assert all(row["account_count"] == 21 and row["account_ids_truncated"]
               and len(row["account_ids"]) == 20 for row in body["groups"])
    assert "owned-private-subject-" not in report.stdout
    assert "@example.com" not in report.stdout and "!SSO_MANAGED" not in report.stdout
    assert before == after


def test_audit_configuration_failure_does_not_print_credentials_or_url():
    sensitive = "owned-private-url-credential"
    url = "postgresql+psycopg://audit:" + sensitive + "@127.0.0.1:not_a_port/owned"
    env = {**os.environ, "DATABASE_URL": url}
    result = subprocess.run(
        [sys.executable, "-B", "scripts/audit_sso_bindings.py"],
        cwd=BACKEND_ROOT, env=env, capture_output=True, text=True, timeout=20, check=False,
    )
    assert result.returncode == 2 and not result.stdout
    assert "SSO binding audit failed" in result.stderr
    assert sensitive not in result.stderr and url not in result.stderr and "Traceback" not in result.stderr
