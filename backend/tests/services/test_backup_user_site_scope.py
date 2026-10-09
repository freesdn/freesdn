"""Site snapshots cannot turn omitted grants into unrestricted restored users."""

import gzip
import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, select, update

from app.core.dependencies import CurrentUser
from app.core.security import get_password_hash
from app.models.core import Organization, Site, User, UserSiteAccess
from app.modules.backup.models import BackupStatus, StorageLocation
from app.services.backup import BackupEncryption, BackupService, LocalStorageBackend
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    CoreBackupContributor,
)


async def make_users(db):
    org = Organization(name="Owned accounts", slug=uuid4().hex)
    other = Organization(name="Owned foreign accounts", slug=uuid4().hex)
    db.add_all([org, other])
    await db.flush()
    sites = {}
    for name in ["a", "b", "empty", "deleted", "foreign"]:
        site = Site(
            name=name,
            slug=uuid4().hex,
            organization_id=other.id if name == "foreign" else org.id,
            deleted_at=datetime.now(UTC) if name == "deleted" else None,
        )
        db.add(site)
        sites[name] = site
    await db.flush()
    users = {}
    password_hash = get_password_hash("Owned scoped account password")
    for name in [
        "global",
        "a",
        "b",
        "both",
        "foreign-site",
        "deleted-site",
        "foreign-user",
        "deleted-user",
    ]:
        user = User(
            email=uuid4().hex + "@owned.example.test",
            username=uuid4().hex,
            organization_id=other.id if name == "foreign-user" else org.id,
            hashed_password=password_hash,
            role="org_admin" if name == "global" else "site_admin",
            is_active=True,
            deleted_at=datetime.now(UTC) if name == "deleted-user" else None,
        )
        db.add(user)
        users[name] = user
    await db.flush()
    for name, site, cap in [
        ("a", "a", "read"),
        ("b", "b", "write"),
        ("both", "a", "read"),
        ("both", "b", "admin"),
        ("foreign-site", "foreign", "read"),
        ("deleted-site", "deleted", "read"),
        ("foreign-user", "a", "read"),
        ("deleted-user", "a", "read"),
    ]:
        db.add(UserSiteAccess(user_id=users[name].id, site_id=sites[site].id, access_level=cap))
    await db.flush()
    return SimpleNamespace(db=db, org=org, other=other, sites=sites, users=users)


@pytest_asyncio.fixture
async def accounts(db_session):
    return await make_users(db_session)


def selected_site(f, target):
    return f.sites[target].id if target in f.sites else uuid4() if target else None


def expected_user_ids(f, target):
    names = (
        {"global", "a", "b", "both", "foreign-site", "deleted-site"}
        if target is None
        else {target, "both"}
        if target in {"a", "b"}
        else set()
    )
    return {str(f.users[name].id) for name in names}


async def valid_full_security_source(f):
    """Prove invalid source refusal, then explicitly repair only test-owned rows.

    The product must never silently drop invalid grants and export an account
    with broader authority. A distinct valid source state lets the same original
    full-organization positive assertions execute afterward.
    """
    from app.services.backup_contributors.account_security_codec import (
        AccountSecurityFormatError,
    )

    if getattr(f, "security_fixture_repaired", False):
        return
    with pytest.raises(AccountSecurityFormatError, match="invalid portable"):
        await CoreBackupContributor().collect(
            f.db, f.org.id, {"include_users": True, "include_secrets": True,
                             "include_devices": False, "include_automation": False},
        )
    for name, site in [("foreign-site", "a"), ("deleted-site", "b")]:
        result = await f.db.execute(update(UserSiteAccess).where(
            UserSiteAccess.user_id == f.users[name].id,
        ).values(site_id=f.sites[site].id))
        assert result.rowcount == 1
    await f.db.flush()
    f.security_fixture_repaired = True


async def collect_users(f, target, secrets, include_users=True):
    if secrets and include_users and target is None:
        await valid_full_security_source(f)
    return await CoreBackupContributor().collect(
        f.db,
        f.org.id,
        {
            "site_id": selected_site(f, target),
            "include_users": include_users,
            "include_secrets": secrets,
            "include_devices": False,
            "include_automation": False,
        },
    )


@pytest.mark.parametrize("target", ["a", "b", "empty", "deleted", "foreign", "missing", None])
@pytest.mark.parametrize("secrets", [False, True])
async def test_site_users_travel_with_their_explicit_grants(accounts, target, secrets):
    f = accounts
    payload = await collect_users(f, target, secrets)
    users = payload.data["users"]
    assert {r["id"] for r in users} == expected_user_ids(f, target)
    assert payload.counts["users"] == len(users)
    if target is not None:
        grants = payload.data["user_site_access"]
        assert {g["user_id"] for g in grants} == {u["id"] for u in users}
        assert all(g["site_id"] == str(selected_site(f, target)) for g in grants)
    assert all(("hashed_password" in u) is secrets for u in users)
    if secrets:
        seeded_hashes = {str(u.id): u.hashed_password for u in f.users.values()}
        assert all(u["hashed_password"] == seeded_hashes[u["id"]] for u in users)


@pytest.mark.parametrize("target", ["a", None])
async def test_user_exclusion_still_excludes_grants(accounts, target):
    payload = await collect_users(accounts, target, True, include_users=False)
    # Explicit empty lists are required current-format metadata, not identities.
    assert not payload.data.get("users") and not payload.data.get("user_site_access")
    assert not payload.data.get("sso_providers")


async def restore_collected_users(f, payload):
    # Remove only this disposable fixture's own users, then use the real restore.
    ids = [u.id for name, u in f.users.items() if name != "foreign-user"]
    f.db.expunge_all()
    await f.db.execute(delete(UserSiteAccess).where(UserSiteAccess.user_id.in_(ids)))
    await f.db.execute(delete(User).where(User.id.in_(ids)))
    await f.db.flush()
    service = BackupService(f.db)
    service.org_id = f.org.id
    result = await service._restore_data(
        {key: payload.data[key] for key in ("account_security_format", "users", "sso_providers", "user_site_access")},
        dry_run=False,
        overwrite_existing=False,
        restore_devices=False,
        restore_users=True,
        include_secrets=True,
    )
    restored = list(
        (await f.db.execute(select(User).where(User.organization_id == f.org.id))).scalars()
    )
    grants = list(
        (
            await f.db.execute(
                select(UserSiteAccess).where(UserSiteAccess.user_id.in_([u.id for u in restored]))
            )
        ).scalars()
    )
    return result, restored, grants


@pytest.mark.parametrize("target", ["a", "b", None])
async def test_actual_restore_cannot_recreate_unselected_users_without_grants(accounts, target):
    f = accounts
    payload = await collect_users(f, target, True)
    expected = expected_user_ids(f, target)
    result, restored, grants = await restore_collected_users(f, payload)
    assert {str(u.id) for u in restored} == expected
    assert result["users"]["created"] == len(expected)
    for user in restored:
        if user.id == f.users["global"].id:
            continue
        owned = [g for g in grants if g.user_id == user.id]
        principal = CurrentUser(
            user,
            permissions=["devices:read", "devices:write"],
            accessible_site_ids={g.site_id for g in owned},
            site_access_levels={g.site_id: g.access_level for g in owned},
        )
        assert principal.is_site_limited
        if target is not None:
            assert principal.can_access_site(f.sites[target].id)
            assert not principal.can_access_site(f.sites["b" if target == "a" else "a"].id)
        for grant in owned:
            if grant.access_level == "read":
                assert not principal.has_site_permission("devices:write", grant.site_id)


async def create_user_archive(f, root, target, secrets):
    if secrets and target is None:
        await valid_full_security_source(f)
    storage = StorageLocation(
        name="Owned accounts archive",
        organization_id=f.org.id,
        storage_type="local",
        config={"path": str(root)},
        is_active=True,
    )
    f.db.add(storage)
    await f.db.flush()
    service = BackupService(f.db)
    phrase = "owned-disposable-user-snapshot-passphrase"
    backup = await service.create_backup(
        name="Owned account selection",
        organization_id=f.org.id,
        site_id=selected_site(f, target),
        include_users=True,
        include_devices=False,
        include_automation=False,
        include_secrets=secrets,
        passphrase=phrase if secrets else None,
        storage_location_id=storage.id,
        is_encrypted=True,
    )
    assert backup.status == BackupStatus.COMPLETED and not backup.error_message
    raw = await LocalStorageBackend({"path": str(root)}).load(backup.storage_path)
    n = int.from_bytes(raw[:4], "big")
    header = json.loads(raw[4 : 4 + n])
    encrypted = raw[4 + n :]
    assert header["encrypted"] is True and header["secrets"] is secrets
    assert hashlib.sha256(encrypted).hexdigest() == header["checksum"]
    assert all(user.hashed_password.encode() not in raw for user in f.users.values())
    encryption = BackupEncryption(master_key=phrase) if secrets else service.encryption
    archive = BackupArchive.model_validate_json(
        gzip.decompress(encryption.decrypt(encrypted, header["key_id"]))
    )
    return backup, archive


@pytest.mark.parametrize("target", ["a", None])
@pytest.mark.parametrize("secrets", [False, True])
async def test_encrypted_archive_contains_only_selected_users(
    accounts, tmp_path, monkeypatch, target, secrets
):
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    backup, archive = await create_user_archive(accounts, tmp_path, target, secrets)
    users = archive.contributors["core"]["users"]
    assert {u["id"] for u in users} == expected_user_ids(accounts, target)
    assert all(("hashed_password" in u) is secrets for u in users)
    assert archive.manifest.contributors[0].counts["users"] == len(users)
    assert backup.site_id == (accounts.sites[target].id if target else None)


async def restore_core(f, data, *, dry_run=False, secrets=True):
    data = {"account_security_format": "2.0.0", "users": [], "sso_providers": [],
            "user_site_access": [], **data}
    service = BackupService(f.db)
    service.org_id = f.org.id
    return await service._restore_data(
        data,
        dry_run=dry_run,
        overwrite_existing=False,
        restore_devices=False,
        restore_users=True,
        include_secrets=secrets,
    )


@pytest.mark.parametrize("dry_run", [False, True])
async def test_bulk_site_restore_uses_typed_ids(accounts, dry_run):
    from uuid import UUID

    f = accounts
    records = [
        {
            "id": str(uuid4()),
            "organization_id": str(f.org.id),
            "name": "Owned restored site",
            "slug": uuid4().hex,
        }
        for _ in range(2)
    ]
    result = await restore_core(f, {"sites": records}, dry_run=dry_run)
    assert result["sites"]["created"] == 2
    rows = list(
        (await f.db.execute(select(Site).where(Site.id.in_([r["id"] for r in records])))).scalars()
    )
    assert len(rows) == (0 if dry_run else 2)
    assert all(isinstance(row.id, UUID) for row in rows)


@pytest.mark.parametrize("secrets", [False, True])
async def test_bulk_credential_restore_preserves_secret_policy_and_ids(accounts, secrets):
    from uuid import UUID

    from app.core.crypto import decrypt_credential, is_encrypted
    from app.models.core import Credential

    f = accounts
    records = [
        {
            "id": str(uuid4()),
            "organization_id": str(f.org.id),
            "site_id": str(f.sites["a"].id),
            "name": "Owned restored credential",
            "credential_type": "ssh",
            "encrypted_password": "owned-restore-secret",
        }
        for _ in range(2)
    ]
    result = await restore_core(f, {"credentials": records}, secrets=secrets)
    assert result["credentials"]["created"] == 2
    rows = list(
        (
            await f.db.execute(
                select(Credential).where(Credential.id.in_([r["id"] for r in records]))
            )
        ).scalars()
    )
    assert len(rows) == 2
    for row in rows:
        assert isinstance(row.id, UUID) and row.site_id == f.sites["a"].id
        if secrets:
            assert is_encrypted(row.encrypted_password)
            assert decrypt_credential(row.encrypted_password) == "owned-restore-secret"
        else:
            assert row.encrypted_password is None


@pytest.mark.parametrize("bad_id", ["not-a-uuid", 123, True, {"bad": "id"}])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_invalid_uuid_record_is_skipped_without_poisoning_transaction(
    accounts, bad_id, dry_run
):
    f = accounts
    from app.services.backup_contributors.account_security_codec import (
        AccountSecurityFormatError,
    )

    source = await collect_users(f, "a", True)
    record = dict(next(row for row in source.data["users"] if row["id"] == str(f.users["a"].id)))
    record.update(id=bad_id, username=uuid4().hex, email=uuid4().hex + "@owned.example.test", role="viewer")
    data = {"users": [record]}
    # Full security is atomic and refuses the invalid ID before any writes.
    # The configuration-only path retains the original safe skip contract.
    with pytest.raises(AccountSecurityFormatError):
        await restore_core(f, data, dry_run=dry_run, secrets=True)
    assert f.db.is_active and not f.db.new
    result = await restore_core(f, data, dry_run=dry_run, secrets=False)
    assert result["users"] == {"created": 0, "updated": 0, "skipped": 1, "rejected_cross_org": 0}
    assert not f.db.new
    assert await f.db.scalar(select(Organization.id).where(Organization.id == f.org.id)) == f.org.id


async def test_bulk_restore_does_not_convert_uuid_shaped_json_values(accounts):
    from app.models.automation import AutomationRuleRecord

    f = accounts
    reference = str(uuid4())
    records = [
        {
            "id": str(uuid4()),
            "organization_id": str(f.org.id),
            "name": "Owned restore JSON",
            "trigger_type": "manual",
            "trigger_config": {"id": reference},
            "actions": [{"id": reference}],
        }
        for _ in range(2)
    ]
    result = await restore_core(f, {"automation_rules": records})
    assert result["automation_rules"]["created"] == 2
    rows = list(
        (
            await f.db.execute(
                select(AutomationRuleRecord).where(
                    AutomationRuleRecord.id.in_([r["id"] for r in records])
                )
            )
        ).scalars()
    )
    assert len(rows) == 2
    assert all(
        row.trigger_config == {"id": reference} and row.actions == [{"id": reference}]
        for row in rows
    )


async def prune_to_one_unselected_user(f):
    removed = [u.id for name, u in f.users.items() if name not in {"b", "foreign-user"}]
    await f.db.execute(delete(UserSiteAccess).where(UserSiteAccess.user_id.in_(removed)))
    await f.db.execute(delete(User).where(User.id.in_(removed)))
    await f.db.flush()


async def test_single_unselected_account_cannot_restore_as_unrestricted(accounts):
    f = accounts
    await prune_to_one_unselected_user(f)
    payload = await collect_users(f, "a", True)
    _, restored, _ = await restore_collected_users(f, payload)
    assert not restored


@pytest.mark.parametrize("change", ["revoke", "delete-site", "delete-user", "new-grant"])
async def test_site_users_and_grants_remain_aligned_between_collection_queries(
    accounts, monkeypatch, change
):
    from sqlalchemy import update

    f = accounts
    execute = f.db.execute
    triggered = False

    async def mutate_between_reads(query, *args, **kwargs):
        nonlocal triggered
        # Mutate before the actual atomic security SELECT. This hook controls
        # timing within one transaction; separate real concurrent tests prove
        # snapshot isolation. No earlier-query membership must be forced here.
        if not triggered and "vault_security_users" in str(query):
            triggered = True
            if change == "revoke":
                await execute(
                    delete(UserSiteAccess).where(UserSiteAccess.user_id == f.users["a"].id)
                )
            elif change == "delete-site":
                await execute(
                    update(Site)
                    .where(Site.id == f.sites["a"].id)
                    .values(deleted_at=datetime.now(UTC))
                )
            elif change == "delete-user":
                await execute(
                    update(User)
                    .where(User.id == f.users["a"].id)
                    .values(deleted_at=datetime.now(UTC))
                )
            else:
                f.db.add(
                    UserSiteAccess(
                        user_id=f.users["b"].id, site_id=f.sites["a"].id, access_level="read"
                    )
                )
                await f.db.flush()
        return await execute(query, *args, **kwargs)

    monkeypatch.setattr(f.db, "execute", mutate_between_reads)
    payload = await collect_users(f, "a", True)
    assert triggered
    users = {u["id"] for u in payload.data["users"]}
    grants = {g["user_id"] for g in payload.data["user_site_access"]}
    expected = (
        set()
        if change == "delete-site"
        else {str(f.users[name].id) for name in ["a", "b", "both"]}
        if change == "new-grant"
        else {str(f.users["both"].id)}
    )
    assert users == grants == expected
