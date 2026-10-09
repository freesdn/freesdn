# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Module recovery must not reparent another tenant's existing resources."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, update

from app.models.core import Organization, Site, User
from app.modules.cameras.backup import CamerasBackupContributor
from app.modules.cameras.models import Camera, CameraGroup, CameraGroupMember
from app.modules.firewall.backup import FirewallBackupContributor
from app.modules.firewall.models import FirewallDevice
from app.modules.voip.backup import VoipBackupContributor
from app.modules.voip.models import PBX, Extension
from app.services.backup import BackupService
from app.services.backup_contributors import (
    BackupArchive,
    BackupManifest,
    ContributorEntry,
    ContributorPayload,
    CoreBackupContributor,
)


@pytest_asyncio.fixture
async def owned_module_rows(db_session):
    org, other = [Organization(name="Owned module recovery", slug=uuid4().hex) for _ in range(2)]
    db_session.add_all([org, other])
    await db_session.flush()
    site, foreign_site = [Site(organization_id=o.id, name="Owned module site", slug=uuid4().hex) for o in (org, other)]
    db_session.add_all([site, foreign_site])
    await db_session.flush()
    group = CameraGroup(organization_id=org.id, name="Original group", members=[])
    pbx = PBX(site_id=site.id, name="Original PBX", ip_address="192.0.2.10")
    firewall = FirewallDevice(site_id=site.id, name="Original firewall", ip_address="192.0.2.20")
    db_session.add_all([group, pbx, firewall])
    await db_session.flush()
    return SimpleNamespace(db=db_session, org=org, other=other, site=site, foreign_site=foreign_site,
                           group=group, pbx=pbx, firewall=firewall)


async def restore(f, contributor, data, *, dry_run=False, overwrite=True):
    return await contributor.restore(f.db, f.org.id, ContributorPayload(schema_version="1.0.0", data=data),
                                     dry_run=dry_run, options={"overwrite_existing": overwrite})


def resource(f, kind):
    if kind == "camera-group":
        return f.group, CamerasBackupContributor(), "camera_groups", "organization_id", f.org.id, f.other.id
    if kind == "pbx":
        return f.pbx, VoipBackupContributor(), "pbx", "site_id", f.site.id, f.foreign_site.id
    return f.firewall, FirewallBackupContributor(), "devices", "site_id", f.site.id, f.foreign_site.id


@pytest.mark.parametrize("kind", ["camera-group", "pbx", "firewall"])
@pytest.mark.parametrize("scope", ["owned", "foreign", "deleted", "stale-foreign"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_module_restore_checks_existing_owner_before_accepting_uploaded_owner(owned_module_rows, kind, scope, dry_run):
    f = owned_module_rows
    row, contributor, key, owner_field, owner, foreign = resource(f, kind)
    original_name = row.name
    if scope == "foreign":
        setattr(row, owner_field, foreign)
    elif scope == "deleted":
        row.deleted_at = datetime.now(UTC)
    await f.db.flush()
    if scope == "stale-foreign":
        await f.db.execute(update(type(row)).where(type(row).id == row.id).values({owner_field: foreign}).execution_options(synchronize_session=False))
        assert getattr(row, owner_field) == owner
    result = await restore(f, contributor, {key: [{"id": str(row.id), owner_field: str(owner), "name": "Archived replacement"}]}, dry_run=dry_run)
    await f.db.refresh(row)
    accepted = scope == "owned"
    assert row.name == ("Archived replacement" if accepted and not dry_run else original_name)
    assert getattr(row, owner_field) == (foreign if scope in {"foreign", "stale-foreign"} else owner)
    if accepted:
        assert not result.errors and not result.warnings
        assert result.updated[key] == (0 if dry_run else 1)
    else:
        assert result.updated[key] == 0 and result.skipped[key] == 1
        assert result.warnings, "A rejected existing owner must be visible in the recovery report"
    assert bool(row.deleted_at) == (scope == "deleted")


@pytest.mark.parametrize("kind", ["camera-group", "pbx", "firewall"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_no_overwrite_does_not_accept_foreign_existing_parent(owned_module_rows, kind, dry_run):
    f = owned_module_rows
    row, contributor, key, owner_field, owner, foreign = resource(f, kind)
    setattr(row, owner_field, foreign)
    await f.db.flush()
    result = await restore(f, contributor, {key: [{"id": str(row.id), owner_field: str(owner), "name": "Archived replacement"}]}, dry_run=dry_run, overwrite=False)
    assert result.updated[key] == 0 and result.skipped[key] == 1 and result.warnings
    await f.db.refresh(row)
    assert getattr(row, owner_field) == foreign


@pytest.mark.parametrize("dry_run", [False, True])
async def test_new_group_claiming_foreign_organization_is_not_silently_rewritten(owned_module_rows, dry_run):
    f = owned_module_rows
    identity = uuid4()
    result = await restore(f, CamerasBackupContributor(), {"camera_groups": [{"id": str(identity), "organization_id": str(f.other.id), "name": "Wrong organization"}]}, dry_run=dry_run)
    assert result.created["camera_groups"] == 0 and result.skipped["camera_groups"] == 1
    assert await f.db.get(CameraGroup, identity) is None


async def test_archived_relationship_cannot_delete_existing_group_members(owned_module_rows):
    f = owned_module_rows
    camera = Camera(organization_id=f.org.id, site_id=f.site.id, name="Owned camera", ip_address="192.0.2.30")
    f.db.add(camera)
    await f.db.flush()
    member = CameraGroupMember(camera_id=camera.id, group=f.group)
    f.db.add(member)
    await f.db.flush()
    identity = member.id
    await f.db.refresh(f.group, ["members"])
    result = await restore(f, CamerasBackupContributor(), {"camera_groups": [{"id": str(f.group.id), "organization_id": str(f.org.id), "name": "Restored title", "members": []}]})
    assert not result.errors
    assert await f.db.scalar(select(CameraGroupMember.id).where(CameraGroupMember.id == identity)) == identity
    await f.db.refresh(f.group)
    assert f.group.name == "Restored title"


@pytest.mark.parametrize("mode", ["insert", "update"])
async def test_invalid_module_row_does_not_poison_session_and_is_reported_as_error(owned_module_rows, mode):
    f = owned_module_rows
    invalid = f.group.id if mode == "update" else uuid4()
    valid = uuid4()
    result = await restore(f, CamerasBackupContributor(), {"camera_groups": [
        {"id": str(invalid), "organization_id": str(f.org.id), "name": None},
        {"id": str(valid), "organization_id": str(f.org.id), "name": "Owned valid row after failure"},
    ]})
    assert result.status == "error" and result.errors and result.skipped["camera_groups"] == 1
    assert f.db.is_active
    assert await f.db.scalar(select(CameraGroup.name).where(CameraGroup.id == valid)) == "Owned valid row after failure"
    if mode == "update":
        await f.db.refresh(f.group)
        assert f.group.name == "Original group"
    # The surrounding dispatcher, tested separately, rolls back the complete
    # contributor when this error result is returned; this call does not commit.


@pytest.mark.parametrize("mode", ["insert", "update"])
async def test_real_camera_dispatch_rolls_back_all_rows_after_a_rejected_write(owned_module_rows, monkeypatch, mode):
    from app.services import backup_contributors
    from app.services.backup_contributors.registry import BackupContributorRegistry

    f = owned_module_rows
    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    registry.register(CamerasBackupContributor())
    monkeypatch.setattr(backup_contributors, "get_registry", lambda: registry)
    invalid = f.group.id if mode == "update" else uuid4()
    valid = uuid4()
    archive = BackupArchive(
        manifest=BackupManifest(backup_id=str(uuid4()), created_at=datetime.now(UTC), organization_id=str(f.org.id), contributors=[
            ContributorEntry(id="core", schema_version="1.0.0", counts={}),
            ContributorEntry(id="cameras", schema_version="1.0.0", counts={"camera_groups": 2}),
        ]),
        contributors={"core": {}, "cameras": {"camera_groups": [
            {"id": str(valid), "organization_id": str(f.org.id), "name": "Must roll back with module"},
            {"id": str(invalid), "organization_id": str(f.org.id), "name": None},
        ]}},
    )
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=f.org.id, dry_run=False, restore_options={"overwrite_existing": True},
    )
    assert report["summary"]["contributors_failed"] == 1 and report["summary"]["total_errors"] > 0
    assert await f.db.scalar(select(CameraGroup.id).where(CameraGroup.id == valid)) is None
    assert f.db.is_active
    await f.db.refresh(f.group)
    assert f.group.name == "Original group"


@pytest.mark.parametrize("scope", ["foreign", "global", "deleted"])
async def test_voip_restore_does_not_link_an_extension_to_out_of_scope_user(owned_module_rows, scope):
    f = owned_module_rows
    identity = uuid4().hex
    user = User(organization_id=f.other.id if scope == "foreign" else None if scope == "global" else f.org.id,
                email=identity + "@example.invalid", username=identity, hashed_password="!",
                deleted_at=datetime.now(UTC) if scope == "deleted" else None)
    f.db.add(user)
    await f.db.flush()
    extension = uuid4()
    result = await restore(f, VoipBackupContributor(), {
        "pbx": [{"id": str(f.pbx.id), "site_id": str(f.site.id), "name": f.pbx.name}],
        "extensions": [{"id": str(extension), "pbx_id": str(f.pbx.id), "user_id": str(user.id),
                        "extension_number": "401", "display_name": "Owned restored extension"}],
    })
    assert not result.errors
    saved = await f.db.get(Extension, extension)
    assert saved is not None and saved.user_id is None


@pytest.mark.parametrize("dry_run", [False, True])
async def test_rejected_camera_does_not_authorize_group_membership(owned_module_rows, dry_run):
    f = owned_module_rows
    camera = Camera(organization_id=f.other.id, site_id=f.foreign_site.id, name="Owned foreign camera", ip_address="192.0.2.40")
    f.db.add(camera)
    await f.db.flush()
    member = uuid4()
    result = await restore(f, CamerasBackupContributor(), {
        "cameras": [{"id": str(camera.id), "organization_id": str(f.org.id), "site_id": str(f.site.id), "name": "Must not reparent"}],
        "camera_groups": [{"id": str(f.group.id), "organization_id": str(f.org.id), "name": f.group.name}],
        "camera_group_members": [{"id": str(member), "camera_id": str(camera.id), "group_id": str(f.group.id)}],
    }, dry_run=dry_run)
    assert result.created["camera_group_members"] == 0 and result.skipped["camera_group_members"] == 1
    assert await f.db.get(CameraGroupMember, member) is None
    await f.db.refresh(camera)
    assert camera.organization_id == f.other.id and camera.site_id == f.foreign_site.id
