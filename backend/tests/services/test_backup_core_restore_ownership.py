# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Core restoration must check stored ownership and accepted references."""

import copy
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, update

from app.core.security import get_password_hash
from app.models.core import Controller, Credential, Organization, Site, User, UserSiteAccess
from app.models.devices import Device
from app.services.backup_contributors import (
    ContributorPayload,
    CoreBackupContributor,
    RestoreResult,
)


@pytest_asyncio.fixture
async def owned_core_rows(db_session, monkeypatch):
    org, other = [Organization(name="Owned core recovery", slug=uuid4().hex) for _ in range(2)]
    db_session.add_all([org, other])
    await db_session.flush()
    site, other_site = [Site(organization_id=o.id, name="Original site", slug=uuid4().hex) for o in (org, other)]
    db_session.add_all([site, other_site])
    await db_session.flush()
    controller = Controller(site_id=site.id, name="Original controller", controller_type="omada", host="192.0.2.50", port=443, devices=[])
    credential = Credential(organization_id=org.id, name="Original credential", credential_type="password")
    identity = uuid4().hex
    user = User(organization_id=org.id, email=identity + "@example.invalid", username=identity, hashed_password=get_password_hash("Owned core recovery password"))
    db_session.add_all([controller, credential, user])
    await db_session.flush()
    device = Device(site_id=site.id, controller_id=controller.id, name="Original device", device_type="switch")
    db_session.add(device)
    await db_session.flush()
    from app.services.backup_contributors.account_security import collect_snapshot

    snapshot = await collect_snapshot(db_session, org.id)
    assert [row["id"] for row in snapshot["users"]] == [str(user.id)]
    return SimpleNamespace(db=db_session, org=org, other=other, site=site, other_site=other_site,
                           controller=controller, credential=credential, user=user, device=device,
                           account=snapshot["users"][0], monkeypatch=monkeypatch)


def owned_account(f, identifier, **changes):
    # A new synthetic local fixture is explicitly based on the complete known
    # initial account. This is not a migration of an incomplete real archive.
    return {**copy.deepcopy(f.account), "id": str(identifier), **changes}


def declared_security_payload(data):
    # Infrastructure-only test archives explicitly contain no account records.
    return {"account_security_format": "2.0.0", "users": [], "sso_providers": [],
            "user_site_access": [], **copy.deepcopy(data)}


async def restore(f, data, *, dry_run=False, overwrite=True):
    report = await dispatch(f, data, f.monkeypatch, dry_run=dry_run, overwrite=overwrite)
    assert len(report["contributors"]) == 1
    return RestoreResult(**report["contributors"][0])


def resource(f, kind):
    row = getattr(f, kind)
    if kind in {"site", "credential"}:
        return row, "sites" if kind == "site" else "credentials", "organization_id", f.org.id, f.other.id
    return row, "controllers" if kind == "controller" else "devices", "site_id", f.site.id, f.other_site.id


@pytest.mark.parametrize("kind", ["site", "credential", "controller", "device"])
@pytest.mark.parametrize("scope", ["owned", "foreign", "deleted", "stale-foreign"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_restore_checks_stored_owner_before_uploaded_owner(owned_core_rows, kind, scope, dry_run):
    f = owned_core_rows
    row, key, field, owner, foreign = resource(f, kind)
    original = row.name
    if scope == "foreign":
        setattr(row, field, foreign)
    elif scope == "deleted":
        row.deleted_at = datetime.now(UTC)
    await f.db.flush()
    if scope == "stale-foreign":
        await f.db.execute(update(type(row)).where(type(row).id == row.id).values({field: foreign}).execution_options(synchronize_session=False))
        assert getattr(row, field) == owner
    result = await restore(f, {key: [{"id": str(row.id), field: str(owner), "name": "Archived replacement", "deleted_at": None}]}, dry_run=dry_run)
    assert not result.errors
    await f.db.refresh(row)
    accepted = scope == "owned"
    assert row.name == ("Archived replacement" if accepted and not dry_run else original)
    assert getattr(row, field) == (foreign if scope in {"foreign", "stale-foreign"} else owner)
    assert bool(row.deleted_at) == (scope == "deleted")
    if accepted:
        assert result.updated[key] == (0 if dry_run else 1)
    else:
        assert result.updated[key] == 0 and result.skipped[key] == 1 and result.warnings


@pytest.mark.parametrize("kind", ["controller", "device"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_no_overwrite_does_not_silently_accept_foreign_row(owned_core_rows, kind, dry_run):
    f = owned_core_rows
    row, key, field, owner, foreign = resource(f, kind)
    setattr(row, field, foreign)
    await f.db.flush()
    result = await restore(f, {key: [{"id": str(row.id), field: str(owner)}]}, dry_run=dry_run, overwrite=False)
    assert not result.errors
    assert result.skipped[key] == 1 and result.warnings
    await f.db.refresh(row)
    assert getattr(row, field) == foreign


@pytest.mark.parametrize("kind", ["controller-site", "device-site", "credential-site", "device-controller"])
@pytest.mark.parametrize("scope", ["foreign", "deleted", "stale-foreign"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_refuses_foreign_or_deleted_reference(owned_core_rows, kind, scope, dry_run):
    f = owned_core_rows
    identity = uuid4()
    parent = f.controller if kind == "device-controller" else f.site
    field = "site_id" if kind == "device-controller" else "organization_id"
    foreign = f.other_site.id if kind == "device-controller" else f.other.id
    original = getattr(parent, field)
    if scope == "foreign":
        setattr(parent, field, foreign)
    elif scope == "deleted":
        parent.deleted_at = datetime.now(UTC)
    await f.db.flush()
    if scope == "stale-foreign":
        await f.db.execute(update(type(parent)).where(type(parent).id == parent.id).values({field: foreign}).execution_options(synchronize_session=False))
        assert getattr(parent, field) == original
    if kind == "controller-site":
        key, cls = "controllers", Controller
        record = {"id": str(identity), "site_id": str(parent.id), "name": "Rejected controller", "controller_type": "omada", "host": "192.0.2.51", "port": 443}
    elif kind == "credential-site":
        key, cls = "credentials", Credential
        record = {"id": str(identity), "organization_id": str(f.org.id), "site_id": str(parent.id), "name": "Rejected credential", "credential_type": "password"}
    else:
        key, cls = "devices", Device
        record = {"id": str(identity), "site_id": str(f.site.id), "name": "Rejected device", "device_type": "switch"}
        if kind == "device-controller":
            record["controller_id"] = str(parent.id)
    result = await restore(f, {key: [record]}, dry_run=dry_run)
    assert not result.errors
    assert result.created[key] == 0 and result.skipped[key] == 1 and result.warnings
    assert await f.db.get(cls, identity) is None


@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_cannot_repurpose_an_existing_foreign_site_grant(owned_core_rows, dry_run):
    f = owned_core_rows
    grant = UserSiteAccess(user_id=f.user.id, site_id=f.other_site.id, access_level="read")
    f.db.add(grant)
    await f.db.flush()
    fresh_user = uuid4()
    result = await restore(f, {
        "users": [owned_account(f, fresh_user, username=uuid4().hex, email=uuid4().hex + "@example.com")],
        "user_site_access": [{"id": str(grant.id), "user_id": str(fresh_user),
                              "site_id": str(f.site.id), "access_level": "admin"}],
    }, dry_run=dry_run)
    assert result.status == "error" and result.errors
    await f.db.refresh(grant)
    assert grant.site_id == f.other_site.id and grant.user_id == f.user.id and grant.access_level == "read"
    assert await f.db.get(User, fresh_user) is None


@pytest.mark.parametrize("endpoint", ["site", "user"])
@pytest.mark.parametrize("scope", ["foreign", "deleted", "stale-foreign"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_rejected_archived_parent_cannot_authorize_a_site_grant(owned_core_rows, endpoint, scope, dry_run):
    f = owned_core_rows
    parent = getattr(f, endpoint)
    if scope == "foreign":
        parent.organization_id = f.other.id
    elif scope == "deleted":
        parent.deleted_at = datetime.now(UTC)
    await f.db.flush()
    if scope == "stale-foreign":
        await f.db.execute(update(type(parent)).where(type(parent).id == parent.id).values(organization_id=f.other.id).execution_options(synchronize_session=False))
        assert parent.organization_id == f.org.id
    identity = uuid4()
    # A fresh subject avoids an unrelated existing-account no-overwrite skip
    # masking whether a rejected Site can authorize a new grant.
    subject_id = f.user.id if endpoint == "user" else uuid4()
    account = owned_account(f, subject_id)
    if endpoint == "site":
        account.update(username=uuid4().hex, email=uuid4().hex + "@example.com")
    data = {"users": [account], "user_site_access": [
        {"id": str(identity), "user_id": str(subject_id), "site_id": str(f.site.id), "access_level": "admin"},
    ]}
    if endpoint == "site":
        data["sites"] = [{"id": str(parent.id), "organization_id": str(f.org.id)}]
    result = await restore(f, data, dry_run=dry_run, overwrite=False)
    assert result.status == "error" and result.errors
    assert await f.db.get(UserSiteAccess, identity) is None
    if endpoint == "site":
        assert await f.db.get(User, subject_id) is None


async def test_core_archived_relationship_cannot_delete_controller_devices(owned_core_rows):
    f = owned_core_rows
    identity = f.device.id
    await f.db.refresh(f.controller, ["devices"])
    result = await restore(f, {"controllers": [{"id": str(f.controller.id), "site_id": str(f.site.id), "name": "Restored title", "devices": []}]})
    assert not result.errors
    assert await f.db.scalar(select(Device.id).where(Device.id == identity)) == identity
    await f.db.refresh(f.controller)
    assert f.controller.name == "Restored title"


@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_accepts_fresh_same_archive_dependencies_and_grants(owned_core_rows, dry_run):
    f = owned_core_rows
    site, credential, controller, device, user, grant = [uuid4() for _ in range(6)]
    identity = uuid4().hex
    data = {
        "sites": [{"id": str(site), "organization_id": str(f.org.id), "name": "Fresh restored site", "slug": uuid4().hex}],
        "credentials": [{"id": str(credential), "organization_id": str(f.org.id), "site_id": str(site), "name": "Fresh restored credential", "credential_type": "password"}],
        "controllers": [{"id": str(controller), "site_id": str(site), "credential_id": str(credential), "name": "Fresh restored controller", "controller_type": "omada", "host": "192.0.2.52", "port": 443}],
        "devices": [{"id": str(device), "site_id": str(site), "controller_id": str(controller), "credential_id": str(credential), "name": "Fresh restored device", "device_type": "switch"}],
        "users": [owned_account(f, user, username=identity, email=identity + "@example.invalid", role="site_admin")],
        "user_site_access": [{"id": str(grant), "user_id": str(user), "site_id": str(site), "access_level": "read"}],
    }
    result = await restore(f, data, dry_run=dry_run)
    assert not result.errors and not result.warnings
    assert result.status == ("dry_run_ok" if dry_run else "ok")
    assert all(result.created[key] == 1 and result.skipped[key] == 0 for key in data)
    for cls, pk in [(Site, site), (Credential, credential), (Controller, controller), (Device, device), (User, user), (UserSiteAccess, grant)]:
        row = await f.db.get(cls, pk)
        if dry_run:
            assert row is None
        else:
            assert row is not None
    if not dry_run:
        restored_device = await f.db.get(Device, device)
        restored_grant = await f.db.get(UserSiteAccess, grant)
        assert (restored_device.site_id, restored_device.controller_id, restored_device.credential_id) == (site, controller, credential)
        assert (restored_grant.user_id, restored_grant.site_id, restored_grant.access_level) == (user, site, "read")


async def dispatch(f, data, monkeypatch, *, dry_run, overwrite=True):
    """Use the actual dispatcher and core savepoint, never a fake transaction."""
    from app.services import backup_contributors
    from app.services.backup import BackupService
    from app.services.backup_contributors import BackupArchive, BackupManifest, ContributorEntry
    from app.services.backup_contributors.registry import BackupContributorRegistry

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(backup_contributors, "get_registry", lambda: registry)
    archive = BackupArchive(
        manifest=BackupManifest(backup_id=str(uuid4()), created_at=datetime.now(UTC),
                                organization_id=str(f.org.id), contributors=[
                                    ContributorEntry(id="core", schema_version="2.0.0", counts={}),
                                ]), contributors={"core": declared_security_payload(data)},
    )
    return await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=f.org.id, dry_run=dry_run,
        restore_options={"overwrite_existing": overwrite, "restore_devices": True,
                         "restore_users": True, "include_secrets": True},
    )


@pytest.mark.parametrize("kind", ["controller", "credential-controller", "credential-device"])
@pytest.mark.parametrize("mode", ["stranded", "joint", "detach"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_parent_move_checks_final_retained_graph(owned_core_rows, monkeypatch, kind, mode, dry_run):
    f = owned_core_rows
    destination = Site(organization_id=f.org.id, name="Destination", slug=uuid4().hex)
    f.db.add(destination)
    f.credential.site_id = f.site.id
    if kind == "credential-controller":
        f.controller.credential_id = f.credential.id
    elif kind == "credential-device":
        f.device.credential_id = f.credential.id
    await f.db.flush()
    original_site, destination_id = f.site.id, destination.id
    parent = f.controller if kind == "controller" else f.credential
    parent_id, device_id = parent.id, f.device.id
    key = "controllers" if kind == "controller" else "credentials"
    data = {key: [{"id": str(parent_id), "site_id": str(destination_id)}],
            "sites": [{"id": str(original_site), "name": "Earlier core edit"}]}
    if mode == "joint":
        if kind == "credential-controller":
            data["controllers"] = [{"id": str(f.controller.id), "site_id": str(destination_id)}]
        data["devices"] = [{"id": str(device_id), "site_id": str(destination_id)}]
        if kind == "credential-device":
            data["devices"][0]["controller_id"] = None
    elif mode == "detach":
        if kind == "credential-controller":
            data["controllers"] = [{"id": str(f.controller.id), "credential_id": None}]
        else:
            field = "controller_id" if kind == "controller" else "credential_id"
            data["devices"] = [{"id": str(device_id), field: None}]
    report = await dispatch(f, data, monkeypatch, dry_run=dry_run)
    rejected = mode == "stranded"
    assert report["summary"]["contributors_failed"] == int(rejected)
    assert bool(report["summary"]["total_errors"]) == rejected
    assert f.db.is_active
    for row in (f.site, parent, f.controller, f.device):
        await f.db.refresh(row)
    applied = not dry_run and not rejected
    assert parent.site_id == (destination_id if applied else original_site)
    assert f.site.name == ("Earlier core edit" if applied else "Original site")
    assert f.device.site_id == (destination_id if applied and mode == "joint" else original_site)
    if applied and mode == "detach":
        consumer = f.controller if kind == "credential-controller" else f.device
        field = "controller_id" if kind == "controller" else "credential_id"
        assert getattr(consumer, field) is None


@pytest.mark.parametrize("consumer", ["controller", "device"])
@pytest.mark.parametrize("scope", ["owned-site", "organization-wide", "other-site", "foreign", "deleted", "stale-foreign"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_credential_reference_requires_owned_compatible_scope(owned_core_rows, consumer, scope, dry_run):
    f = owned_core_rows
    f.credential.site_id = f.site.id
    if scope == "organization-wide":
        f.credential.site_id = None
    elif scope == "other-site":
        another = Site(organization_id=f.org.id, name="Another owned site", slug=uuid4().hex)
        f.db.add(another)
        await f.db.flush()
        f.credential.site_id = another.id
    elif scope == "foreign":
        f.credential.organization_id = f.other.id
    elif scope == "deleted":
        f.credential.deleted_at = datetime.now(UTC)
    await f.db.flush()
    if scope == "stale-foreign":
        await f.db.execute(update(Credential).where(Credential.id == f.credential.id)
                           .values(organization_id=f.other.id).execution_options(synchronize_session=False))
        assert f.credential.organization_id == f.org.id
    row = getattr(f, consumer)
    key = "controllers" if consumer == "controller" else "devices"
    result = await restore(f, {key: [{"id": str(row.id), "credential_id": str(f.credential.id)}]}, dry_run=dry_run)
    accepted = scope in {"owned-site", "organization-wide"}
    assert not result.errors and bool(result.warnings) == (not accepted)
    assert result.updated[key] == int(accepted and not dry_run)
    await f.db.refresh(row)
    assert row.credential_id == (f.credential.id if accepted and not dry_run else None)


@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_device_controller_must_share_site_even_within_one_org(owned_core_rows, dry_run):
    f = owned_core_rows
    another = Site(organization_id=f.org.id, name="Another owned site", slug=uuid4().hex)
    f.db.add(another)
    await f.db.flush()
    controller = Controller(site_id=another.id, name="Different site", controller_type="omada", host="192.0.2.53", port=443)
    f.db.add(controller)
    await f.db.flush()
    original = f.device.controller_id
    result = await restore(f, {"devices": [{"id": str(f.device.id), "controller_id": str(controller.id)}]}, dry_run=dry_run)
    assert not result.errors and result.warnings and result.updated["devices"] == 0
    await f.db.refresh(f.device)
    assert f.device.controller_id == original


@pytest.mark.parametrize("scope", ["owned", "foreign", "stale-foreign"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_site_group_reference_is_owned(owned_core_rows, scope, dry_run):
    from app.models.enterprise import SiteGroup

    f = owned_core_rows
    group = SiteGroup(organization_id=f.other.id if scope == "foreign" else f.org.id, name=uuid4().hex)
    f.db.add(group)
    await f.db.flush()
    if scope == "stale-foreign":
        await f.db.execute(update(SiteGroup).where(SiteGroup.id == group.id)
                           .values(organization_id=f.other.id).execution_options(synchronize_session=False))
        assert group.organization_id == f.org.id
    result = await restore(f, {"sites": [{"id": str(f.site.id), "site_group_id": str(group.id)}]}, dry_run=dry_run)
    accepted = scope == "owned"
    assert not result.errors and bool(result.warnings) == (not accepted)
    await f.db.refresh(f.site)
    assert f.site.site_group_id == (group.id if accepted and not dry_run else None)


@pytest.mark.parametrize("scope", ["owned", "foreign", "deleted", "stale-foreign"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_user_provider_reference_is_owned_and_live(owned_core_rows, scope, dry_run):
    from app.models.sso import SSOProtocol, SSOProvider

    f = owned_core_rows
    from app.services.backup_contributors.account_security import collect_snapshot

    provider = SSOProvider(organization_id=f.org.id, name="Recovery provider",
                           slug=uuid4().hex, protocol=SSOProtocol.OIDC)
    f.db.add(provider)
    await f.db.flush()
    source = await collect_snapshot(f.db, f.org.id)
    assert [p["id"] for p in source["sso_providers"]] == [str(provider.id)]
    subject = uuid4()
    source["users"] = [owned_account(
        f, subject, username=uuid4().hex, email=uuid4().hex + "@example.com",
        hashed_password="!SSO_MANAGED", auth_provider="oidc", external_id="owned-subject-" + uuid4().hex,
        sso_provider_id=str(provider.id),
    )]
    if scope == "foreign":
        provider.organization_id = f.other.id
    elif scope == "deleted":
        provider.deleted_at = datetime.now(UTC)
    await f.db.flush()
    if scope == "stale-foreign":
        await f.db.execute(update(SSOProvider).where(SSOProvider.id == provider.id)
                           .values(organization_id=f.other.id).execution_options(synchronize_session=False))
        assert provider.organization_id == f.org.id
    result = await restore(f, source, dry_run=dry_run)
    accepted = scope == "owned"
    assert bool(result.errors) == (not accepted)
    await f.db.refresh(f.user)
    assert f.user.sso_provider_id is None  # No implicit conversion of the existing local identity.
    restored = await f.db.get(User, subject)
    if accepted and not dry_run:
        assert restored is not None
        assert restored.sso_provider_id == provider.id and restored.auth_provider == "oidc"
        assert restored.hashed_password == "!SSO_MANAGED"
    else:
        assert restored is None


@pytest.mark.parametrize("kind", ["site", "credential", "controller", "device"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_core_duplicate_identity_rejected_with_complete_rollback(owned_core_rows, monkeypatch, kind, dry_run):
    f = owned_core_rows
    row, key, _, _, _ = resource(f, kind)
    original = row.name
    report = await dispatch(f, {key: [{"id": str(row.id), "name": "First change"},
                                      {"id": str(row.id), "name": "Ambiguous second change"}]},
                            monkeypatch, dry_run=dry_run)
    assert report["summary"]["contributors_failed"] == 1 and report["summary"]["total_errors"]
    assert f.db.is_active
    await f.db.refresh(row)
    assert row.name == original


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_config_profile_restore_ignores_archived_sso_authority(owned_core_rows, existing, dry_run):
    from app.models.sso import SSOProtocol, SSOProvider

    f = owned_core_rows
    provider = SSOProvider(organization_id=f.other.id, name="Foreign provider",
                           slug=uuid4().hex, protocol=SSOProtocol.OIDC)
    f.db.add(provider)
    await f.db.flush()
    pk = f.user.id if existing else uuid4()
    identity = uuid4().hex
    result = await CoreBackupContributor().restore(
        f.db, f.org.id, ContributorPayload(schema_version="1.0.0", data={"users": [{
            "id": str(pk), "email": identity + "@example.invalid", "username": identity,
            "full_name": "Safe restored profile", "sso_provider_id": str(provider.id),
            "auth_provider": "oidc", "external_id": "must-not-apply",
        }]}), dry_run=dry_run, options={"overwrite_existing": True, "restore_users": True, "include_secrets": False},
    )
    assert not result.errors
    assert result.created["users"] == int(not existing)
    assert result.updated["users"] == int(existing and not dry_run)
    row = await f.db.get(User, pk, populate_existing=True)
    if row is None:
        assert dry_run and not existing
    else:
        assert row.sso_provider_id is None and row.auth_provider is None and row.external_id is None
        if not dry_run:
            assert row.full_name == "Safe restored profile"
            if not existing:
                assert not row.is_active and row.role == "viewer"
