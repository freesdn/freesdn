# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Existing-account vault overwrite invalidates destination authentication.

Actual PostgreSQL, contributor dispatcher, signed tokens and HTTP auth routes.
No customer identity provider, shipped runtime or fresh-account fidelity claim.
"""

import copy
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import event, update

from app.core.security import create_access_token, create_refresh_token, get_password_hash
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, Site, User, UserSession
from app.services.backup import BackupService
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    BackupManifest,
    ContributorEntry,
    CoreBackupContributor,
)


@pytest_asyncio.fixture
async def owned_accounts(db_session, monkeypatch):
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    orgs = [Organization(name="Owned revocation fixture", slug=uuid4().hex) for _ in range(2)]
    db_session.add_all(orgs)
    await db_session.flush()
    users = []
    for org in orgs:
        name = uuid4().hex
        users.append(User(organization_id=org.id, username=name, email=name + "@example.com",
                          full_name="Original account", hashed_password=get_password_hash("Owned existing account password"), role="super_admin",
                          is_active=True, is_verified=True, token_version=17))
    site = Site(organization_id=orgs[0].id, name="Original site", slug=uuid4().hex)
    db_session.add_all([*users, site])
    await db_session.flush()
    now = datetime.now(UTC)
    old_revocation = now - timedelta(days=1)
    sessions = [UserSession(user_id=users[0].id, created_at=now, expires_at=now + timedelta(days=1)),
                UserSession(user_id=users[0].id, created_at=now, revoked_at=old_revocation, is_revoked=True),
                UserSession(user_id=users[1].id, created_at=now, expires_at=now + timedelta(days=1))]
    keys, plaintext = [], []
    for user, active in [(users[0], True), (users[0], False), (users[1], True)]:
        raw, prefix, digest = generate_api_key()
        plaintext.append(raw)
        keys.append(APIKey(user_id=user.id, name="Owned revocation key", key_prefix=prefix,
                           key_hash=digest, is_active=active, scopes=[]))
    db_session.add_all([*sessions, *keys])
    await db_session.flush()
    from app.services.backup_contributors.account_security import collect_snapshot

    snapshot = await collect_snapshot(db_session, orgs[0].id)
    return SimpleNamespace(snapshot=snapshot, db=db_session, org=orgs[0], other_org=orgs[1], user=users[0],
                           other_user=users[1], site=site, sessions=sessions, keys=keys,
                           key=plaintext[0], other_key=plaintext[2], old_revocation=old_revocation)


@pytest_asyncio.fixture
async def owned_auth_client(async_client):
    # Use the shared owned database dependency, but a unique synthetic peer for
    # the real Redis rate limiter. No auth or limiter dependency replacement.
    peer = uuid4().int
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(f"198.19.{peer >> 8 & 255}.{peer & 255}", 45123)),
        base_url="http://test",
    ) as client:
        yield client


async def dispatch(f, *, archived=17, dry_run=False, secrets=True, overwrite=True,
                   users=True, late_failure=False):
    # Snapshot is captured before destination mutations; otherwise malformed
    # live-state and ownership tests could fail in collection instead of restore.
    data = copy.deepcopy(f.snapshot)
    assert [row["id"] for row in data["users"]] == [str(f.user.id)]
    record = data["users"][0]
    record["full_name"] = "Recovered account"
    if archived == "missing":
        record.pop("token_version")
    else:
        record["token_version"] = archived
    data["sites"] = [{"id": str(f.site.id), "name": "Earlier core change"}]
    if late_failure:
        # Complete, well-formed security metadata reaches a real database
        # uniqueness failure after the first account/key/session updates.
        collision = {**copy.deepcopy(f.snapshot["users"][0]), "id": str(uuid4()),
                     "username": f.other_user.username, "email": uuid4().hex + "@example.com",
                     "role": "viewer"}
        data["users"].append(collision)
    archive = BackupArchive(
        manifest=BackupManifest(backup_id=str(uuid4()), created_at=datetime.now(UTC),
                                organization_id=str(f.org.id), contributors=[
                                    ContributorEntry(id="core", schema_version="2.0.0", counts={}),
                                ]), contributors={"core": data},
    )
    observed_updates = set()
    f.actual_late_database_failure = False
    bind = f.db.sync_session.get_bind()

    def after_statement(_connection, _cursor, statement, _parameters, _context, _many):
        normalized = statement.strip().lower().replace('"', '')
        for table in ("core.users", "core.user_sessions", "core.api_keys"):
            if normalized.startswith("update " + table + " "):
                observed_updates.add(table)

    def before_statement(_connection, _cursor, statement, _parameters, _context, _many):
        normalized = statement.strip().lower().replace('"', '')
        if normalized.startswith("insert into core.users "):
            f.actual_late_database_failure = observed_updates == {"core.users", "core.user_sessions", "core.api_keys"}

    if late_failure:
        event.listen(bind, "after_cursor_execute", after_statement)
        event.listen(bind, "before_cursor_execute", before_statement)
    try:
        return await BackupService(f.db)._dispatch_restore_via_contributors(
            archive, organization_id=f.org.id, dry_run=dry_run,
            restore_options={"overwrite_existing": overwrite, "restore_users": users,
                             "restore_devices": False, "include_secrets": secrets},
        )
    finally:
        if late_failure:
            event.remove(bind, "after_cursor_execute", after_statement)
            event.remove(bind, "before_cursor_execute", before_statement)


async def refresh(f):
    for row in (f.user, f.other_user, f.site, *f.sessions, *f.keys):
        await f.db.refresh(row)


def assert_credentials(f, revoked):
    assert f.sessions[0].is_revoked is revoked
    assert (f.sessions[0].revoked_at is not None) is revoked
    assert f.sessions[1].is_revoked and f.sessions[1].revoked_at == f.old_revocation
    assert not f.sessions[2].is_revoked and f.sessions[2].revoked_at is None
    assert f.keys[0].is_active is not revoked and not f.keys[1].is_active
    assert f.keys[2].is_active and f.other_user.token_version == 17


@pytest.mark.parametrize("archived", ["missing", 0, 17, 42])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_overwrite_advances_beyond_live_and_archived_versions(owned_accounts, archived, dry_run):
    f = owned_accounts
    report = await dispatch(f, archived=archived, dry_run=dry_run)
    if archived == "missing":
        assert report["summary"]["contributors_failed"] == 1
        await refresh(f)
        assert f.user.token_version == 17 and f.user.full_name == "Original account"
        assert f.site.name == "Original site"
        assert_credentials(f, False)
        report = await dispatch(f, archived=17, dry_run=dry_run)
    assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
    await refresh(f)
    expected = 17 if dry_run else max(17, 17 if archived == "missing" else archived) + 1
    assert f.user.token_version == expected
    assert f.user.full_name == ("Original account" if dry_run else "Recovered account")
    assert_credentials(f, not dry_run)


@pytest.mark.parametrize("archived", [-1, True, 1.5, "17", None, 2**31 - 1, 2**31])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_invalid_archive_counter_refuses_without_core_or_auth_writes(owned_accounts, archived, dry_run):
    f = owned_accounts
    report = await dispatch(f, archived=archived, dry_run=dry_run)
    assert report["summary"]["contributors_failed"] == 1
    assert report["summary"]["total_errors"] > 0
    await refresh(f)
    assert f.user.token_version == 17 and f.user.full_name == "Original account"
    assert f.site.name == "Original site" and f.db.is_active
    assert_credentials(f, False)


@pytest.mark.parametrize("current", [-1, 2**31 - 1])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_invalid_or_exhausted_live_counter_refuses(owned_accounts, current, dry_run):
    f = owned_accounts
    f.user.token_version = current
    await f.db.flush()
    report = await dispatch(f, archived=0, dry_run=dry_run)
    assert report["summary"]["contributors_failed"] == 1
    await refresh(f)
    assert f.user.token_version == current and f.site.name == "Original site"
    assert_credentials(f, False)


@pytest.mark.parametrize("mode", ["configuration", "no-overwrite", "no-users"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_non_overwritten_accounts_keep_their_sessions(owned_accounts, mode, dry_run):
    f = owned_accounts
    report = await dispatch(f, archived=17 if mode == "no-overwrite" else None, dry_run=dry_run, secrets=mode != "configuration",
                            overwrite=mode != "no-overwrite", users=mode != "no-users")
    assert report["summary"]["contributors_failed"] == 0
    await refresh(f)
    assert f.user.token_version == 17
    assert_credentials(f, False)


@pytest.mark.parametrize("scope", ["foreign", "global", "deleted", "stale-foreign"])
async def test_rejected_account_does_not_revoke_its_credentials(owned_accounts, scope):
    f = owned_accounts
    if scope == "foreign":
        f.user.organization_id = f.other_org.id
    elif scope == "global":
        f.user.organization_id = None
    elif scope == "deleted":
        f.user.deleted_at = datetime.now(UTC)
    await f.db.flush()
    if scope == "stale-foreign":
        await f.db.execute(update(User).where(User.id == f.user.id).values(organization_id=f.other_org.id)
                           .execution_options(synchronize_session=False))
        assert f.user.organization_id == f.org.id
    report = await dispatch(f, archived=0)
    assert report["summary"]["contributors_failed"] == 1
    await refresh(f)
    assert f.site.name == "Original site"
    assert f.user.token_version == 17 and f.user.full_name == "Original account"
    assert_credentials(f, False)


@pytest.mark.parametrize("dry_run", [False, True])
async def test_revocation_uses_refreshed_database_counter(owned_accounts, dry_run):
    f = owned_accounts
    await f.db.execute(update(User).where(User.id == f.user.id).values(token_version=42)
                       .execution_options(synchronize_session=False))
    assert f.user.token_version == 17
    report = await dispatch(f, archived=0, dry_run=dry_run)
    assert report["summary"]["contributors_failed"] == 0
    await refresh(f)
    assert f.user.token_version == (42 if dry_run else 43)
    assert_credentials(f, not dry_run)


@pytest.mark.parametrize("dry_run", [False, True])
async def test_last_representable_version_is_usable_without_wraparound(owned_accounts, dry_run):
    f = owned_accounts
    f.user.token_version = 2**31 - 2
    await f.db.flush()
    report = await dispatch(f, archived=0, dry_run=dry_run)
    assert report["summary"]["contributors_failed"] == 0
    await refresh(f)
    assert f.user.token_version == 2**31 - (2 if dry_run else 1)
    assert_credentials(f, not dry_run)
    if not dry_run:
        refused = await dispatch(f, archived=0)
        assert refused["summary"]["contributors_failed"] == 1
        await refresh(f)
        assert f.user.token_version == 2**31 - 1
        assert_credentials(f, True)


@pytest.mark.parametrize("late_failure", [False, True])
async def test_dispatcher_rolls_back_session_key_and_account_changes_together(owned_accounts, request, late_failure):
    f = owned_accounts
    report = await dispatch(f, late_failure=late_failure)
    assert report["summary"]["contributors_failed"] == int(late_failure)
    if late_failure:
        assert f.actual_late_database_failure
        assert "IntegrityError" in str(report["contributors"][0]["errors"])
        request.node.user_properties.append(("real_database_insert_failure_after_account_session_key_updates", True))
    await refresh(f)
    assert f.db.is_active
    assert f.user.token_version == (17 if late_failure else 18)
    assert f.user.full_name == ("Original account" if late_failure else "Recovered account")
    assert f.site.name == ("Original site" if late_failure else "Earlier core change")
    assert_credentials(f, not late_failure)


@pytest.mark.parametrize("kind", ["access", "refresh", "api-key", "mfa-pending"])
@pytest.mark.parametrize("archived", ["missing", 17])
async def test_existing_credential_stops_authenticating_after_overwrite(
    owned_accounts, owned_auth_client, kind, archived,
):
    f, client = owned_accounts, owned_auth_client
    first_code, second_code = "AB12CD34EF", "AB12CD34FF"
    if kind == "mfa-pending":
        import pyotp

        from app.core.security_utils import encrypt_field

        f.user.mfa_enabled = True
        f.user.mfa_secret = encrypt_field(pyotp.random_base32())
        f.user.mfa_backup_codes = json.dumps([get_password_hash(first_code), get_password_hash(second_code)])
        await f.db.flush()
        from app.services.backup_contributors.account_security import collect_snapshot

        f.snapshot = await collect_snapshot(f.db, f.org.id)

    def token():
        if kind == "refresh":
            return create_refresh_token(subject=str(f.user.id), token_version=17)
        claims = {"type": "mfa_pending", "aud": "freesdn-mfa"} if kind == "mfa-pending" else {}
        return create_access_token(subject=str(f.user.id), token_version=17, extra_claims=claims)

    async def authenticate(value, code):
        client.cookies.clear()
        if kind == "api-key":
            return await client.get("/api/v1/backups/stats", headers={"X-API-Key": f.key})
        if kind == "refresh":
            return await client.post("/api/v1/auth/refresh", json={"refresh_token": value})
        if kind == "mfa-pending":
            return await client.post("/api/v1/auth/login/mfa", json={"mfa_token": value, "code": code})
        return await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + value})

    # Use distinct pre-existing refresh/challenge tokens so a successful control
    # never consumes the token used to test restore revocation.
    old_token = token()
    control = await authenticate(token(), first_code)
    assert control.status_code == 200, control.text
    report = await dispatch(f, archived=archived)
    if archived == "missing":
        assert report["summary"]["contributors_failed"] == 1
        await refresh(f)
        assert f.user.token_version == 17
        assert_credentials(f, False)
        report = await dispatch(f, archived=17)
    assert report["summary"]["contributors_failed"] == 0
    refused = await authenticate(old_token, second_code)
    assert refused.status_code == 401
    await refresh(f)
    assert f.user.token_version == 18
    assert_credentials(f, True)
    # Ordinary newly authenticated requests remain possible after revocation.
    client.cookies.clear()
    current = create_access_token(subject=str(f.user.id), token_version=f.user.token_version)
    legitimate = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + current})
    assert legitimate.status_code == 200 and legitimate.json()["id"] == str(f.user.id)
