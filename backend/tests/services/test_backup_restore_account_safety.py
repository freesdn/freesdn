# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Configuration recovery must not undo account security decisions."""

import copy
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, update

from app.core.security import get_password_hash, verify_password
from app.models.core import Organization, Site, User, UserSiteAccess
from app.services.backup import BackupService


@pytest_asyncio.fixture
async def recovery_accounts(db_session):
    org = Organization(name="Owned account recovery", slug=uuid4().hex)
    other = Organization(name="Owned foreign recovery", slug=uuid4().hex)
    db_session.add_all([org, other])
    await db_session.flush()
    identity = uuid4().hex
    user = User(
        organization_id=org.id,
        email=identity + "@example.invalid",
        username=identity,
        full_name="Existing profile",
        hashed_password=get_password_hash("Owned profile account password"),
        role="site_admin",
    )
    sites = [
        Site(organization_id=org.id, name="Owned recovery site", slug=uuid4().hex)
        for _ in range(2)
    ]
    db_session.add_all([user, *sites])
    await db_session.flush()
    grant = UserSiteAccess(user_id=user.id, site_id=sites[0].id, access_level="read")
    db_session.add(grant)
    await db_session.flush()
    from app.services.backup_contributors.account_security import collect_snapshot

    snapshot = await collect_snapshot(db_session, org.id)
    return SimpleNamespace(snapshot=snapshot, db=db_session, org=org, other=other, user=user, sites=sites, grant=grant)


async def restore(f, data, *, dry_run=False, secrets=False, overwrite=True, users=True):
    service = BackupService(f.db)
    service.org_id = f.org.id
    return await service._restore_data(
        data,
        dry_run=dry_run,
        overwrite_existing=overwrite,
        restore_devices=False,
        restore_users=users,
        include_secrets=secrets,
    )


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize(
    "field,original,archived",
    [
        ("token_version", 17, 0),
        ("mfa_enabled", True, False),
        ("mfa_secret", "owned-live-mfa", "owned-archived-mfa"),
        ("mfa_backup_codes", "owned-live-codes", "owned-archived-codes"),
        ("mfa_pending_secret", "owned-live-pending", None),
        ("mfa_pending_backup_codes", "owned-live-pending-codes", None),
        ("mfa_last_totp_step", 123456, 0),
        ("is_active", False, True),
        ("is_verified", False, True),
        ("failed_login_attempts", 9, 0),
        ("locked_until", datetime(2030, 1, 1, tzinfo=UTC), None),
        ("last_login", datetime(2026, 1, 1, tzinfo=UTC), None),
        ("email", "owned-live@example.invalid", "owned-archive@example.invalid"),
        ("username", "owned-live-identity", "owned-archived-identity"),
        ("auth_provider", "oidc", "local"),
        ("external_id", "owned-live-subject", "owned-archived-subject"),
        ("role", "viewer", "super_admin"),
        ("hashed_password", "owned-live-unusable-hash", "owned-archived-unusable-hash"),
    ],
)
async def test_config_restore_preserves_live_account_state(
    recovery_accounts, field, original, archived, dry_run
):
    f = recovery_accounts
    setattr(f.user, field, original)
    await f.db.flush()
    result = await restore(
        f,
        {"users": [{"id": str(f.user.id), "full_name": "Restored profile", field: archived}]},
        dry_run=dry_run,
    )
    await f.db.refresh(f.user)
    assert getattr(f.user, field) == original
    assert f.user.full_name == ("Existing profile" if dry_run else "Restored profile")
    assert result["users"]["rejected_cross_org"] == 0


@pytest.mark.parametrize("dry_run", [False, True])
async def test_new_config_profile_is_disabled_and_cannot_authenticate(recovery_accounts, dry_run):
    f = recovery_accounts
    identifier = uuid4()
    identity = uuid4().hex
    result = await restore(
        f,
        {
            "users": [
                {
                    "id": str(identifier),
                    "email": identity + "@example.invalid",
                    "username": identity,
                    "full_name": "Restored disabled profile",
                    "hashed_password": "owned-archive-login-must-not-apply",
                    "role": "super_admin",
                    "is_active": True,
                    "is_verified": True,
                    "token_version": 999,
                    "mfa_enabled": True,
                    "auth_provider": "oidc",
                    "external_id": "owned-archive-subject",
                }
            ]
        },
        dry_run=dry_run,
    )
    assert result["users"]["created"] == 1
    user = await f.db.get(User, identifier)
    if dry_run:
        assert user is None and not f.db.new
    else:
        assert user.organization_id == f.org.id
        assert user.full_name == "Restored disabled profile"
        assert not user.is_active and not user.is_verified
        assert user.role == "viewer" and user.token_version == 0
        assert not user.mfa_enabled and user.auth_provider is None and user.external_id is None
        assert not verify_password("!", user.hashed_password)
        assert user.hashed_password != "owned-archive-login-must-not-apply"


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("scope", ["global", "foreign", "deleted", "stale-foreign"])
async def test_account_restore_does_not_touch_out_of_scope_rows(
    recovery_accounts, dry_run, secrets, scope
):
    f = recovery_accounts
    if scope == "global":
        f.user.organization_id = None
    elif scope == "foreign":
        f.user.organization_id = f.other.id
    elif scope == "deleted":
        f.user.deleted_at = datetime.now(UTC)
    await f.db.flush()
    if scope == "stale-foreign":
        # A previously loaded object must not override the database's actual owner.
        await f.db.execute(
            update(User)
            .where(User.id == f.user.id)
            .values(organization_id=f.other.id)
            .execution_options(synchronize_session=False)
        )
        assert f.user.organization_id == f.org.id
    data = {"users": [{"id": str(f.user.id), "organization_id": str(f.org.id),
                       "full_name": "Must not overwrite", "deleted_at": None}]}
    if secrets:
        from app.services.backup_contributors.account_security_codec import (
            AccountSecurityFormatError,
        )

        data = copy.deepcopy(f.snapshot)
        data["users"][0]["full_name"] = "Must not overwrite"
        # The security payload is complete. Its destination owner, not missing
        # metadata or a malformed password fixture, must cause this refusal.
        with pytest.raises(AccountSecurityFormatError, match="destination ownership"):
            await restore(f, data, dry_run=dry_run, secrets=True)
        result = None
    else:
        result = await restore(f, data, dry_run=dry_run, secrets=False)
    await f.db.refresh(f.user)
    assert f.user.full_name == "Existing profile"
    if result is not None:
        assert result["users"] == {
            "created": 0, "updated": 0, "skipped": 1, "rejected_cross_org": 1
        }
    assert f.db.is_active
    await f.db.refresh(f.grant)
    assert (f.grant.site_id, f.grant.access_level) == (f.sites[0].id, "read")
    if scope == "global":
        assert f.user.organization_id is None
    elif scope == "deleted":
        assert f.user.deleted_at is not None
    else:
        assert f.user.organization_id == f.other.id


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("change", ["existing", "new"])
async def test_config_restore_does_not_grant_additional_account_access(
    recovery_accounts, dry_run, change
):
    f = recovery_accounts
    record = {
        "id": str(f.grant.id if change == "existing" else uuid4()),
        "user_id": str(f.user.id),
        "site_id": str(f.sites[0 if change == "existing" else 1].id),
        "access_level": "admin",
    }
    result = await restore(f, {"user_site_access": [record]}, dry_run=dry_run)
    rows = list(
        (
            await f.db.execute(
                select(UserSiteAccess)
                .where(UserSiteAccess.user_id == f.user.id)
                .execution_options(populate_existing=True)
            )
        ).scalars()
    )
    assert [(r.id, r.site_id, r.access_level) for r in rows] == [
        (f.grant.id, f.sites[0].id, "read")
    ]
    assert result["user_site_access"] == {
        "created": 0, "updated": 0, "skipped": 1, "rejected_cross_org": 0
    }


@pytest.mark.parametrize("existing", [False, True])
async def test_vault_restore_retains_explicit_account_and_grant_recovery(
    recovery_accounts, existing
):
    f = recovery_accounts
    identifier = f.user.id if existing else uuid4()
    identity = uuid4().hex
    grant_id = uuid4()
    password = "Owned recovered account password"
    archived_hash = get_password_hash(password)
    data = copy.deepcopy(f.snapshot)
    data["users"][0].update(
        id=str(identifier), username=identity, email=identity + "@example.invalid",
        full_name="Explicit vault account", hashed_password=archived_hash,
        role="site_admin", is_active=True, token_version=11,
    )
    data["user_site_access"] = [{"id": str(grant_id), "user_id": str(identifier),
                                 "site_id": str(f.sites[1].id), "access_level": "read"}]
    if existing:
        from app.services.backup_contributors.account_security_codec import (
            AccountSecurityFormatError,
        )

        with pytest.raises(AccountSecurityFormatError, match="identity or authority"):
            await restore(f, data, secrets=True)
        await f.db.refresh(f.user)
        await f.db.refresh(f.grant)
        assert f.user.full_name == "Existing profile" and f.user.token_version == 0
        assert f.user.hashed_password == f.snapshot["users"][0]["hashed_password"]
        assert (f.grant.site_id, f.grant.access_level) == (f.sites[0].id, "read")
        assert await f.db.get(UserSiteAccess, grant_id) is None
        # A compatible complete archive still performs recovery and advances
        # revocation. Do not change a live account's grants or password implicitly.
        data = copy.deepcopy(f.snapshot)
        data["users"][0].update(full_name="Explicit vault account", token_version=11)
        identity, archived_hash, grant_id = f.user.username, f.user.hashed_password, f.grant.id
        password = "Owned profile account password"
    result = await restore(f, data, secrets=True)
    user = await f.db.get(User, identifier)
    await f.db.refresh(user)
    assert user.username == identity and user.is_active and user.role == "site_admin"
    assert user.full_name == "Explicit vault account" and user.hashed_password == archived_hash
    assert verify_password(password, user.hashed_password)
    # Fresh and existing recovery both invalidate the archive-boundary version.
    assert user.token_version == 12
    grant = await f.db.get(UserSiteAccess, grant_id)
    assert grant.user_id == identifier and grant.site_id == f.sites[0 if existing else 1].id
    assert grant.access_level == "read"
    assert result["users"]["updated" if existing else "created"] == 1
    assert result["user_site_access"]["updated" if existing else "created"] == 1


@pytest.mark.parametrize("overwrite,users", [(False, True), (True, False)])
async def test_account_restore_respects_existing_skip_options(recovery_accounts, overwrite, users):
    f = recovery_accounts
    await restore(
        f,
        {"users": [{"id": str(f.user.id), "full_name": "Must not apply"}]},
        overwrite=overwrite,
        users=users,
    )
    await f.db.refresh(f.user)
    assert f.user.full_name == "Existing profile"


@pytest.mark.parametrize("dry_run", [False, True])
async def test_contributor_reports_disabled_profiles_and_preserved_access(recovery_accounts, dry_run):
    from app.services.backup_contributors import ContributorPayload, CoreBackupContributor

    f = recovery_accounts
    identifier = uuid4()
    identity = uuid4().hex
    payload = ContributorPayload(
        schema_version="1.0.0",
        counts={"users": 1, "user_site_access": 1},
        data={
            "users": [{"id": str(identifier), "username": identity,
                       "email": identity + "@example.invalid"}],
            "user_site_access": [{"id": str(f.grant.id), "user_id": str(f.user.id),
                                  "site_id": str(f.sites[0].id), "access_level": "admin"}],
        },
        metadata={},
    )
    result = await CoreBackupContributor().restore(
        f.db, f.org.id, payload, dry_run=dry_run,
        options={"restore_users": True, "overwrite_existing": True, "include_secrets": False},
    )
    assert result.status == ("dry_run_ok" if dry_run else "ok") and not result.errors
    assert result.created["users"] == 1 and result.skipped["user_site_access"] == 1
    assert any("disabled" in warning and "account setup" in warning for warning in result.warnings)
    assert any("site grants" in warning and "unchanged" in warning for warning in result.warnings)
