# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Decoded duplicate bindings refuse before preview/apply changes account state.

The authentic encrypted collector produces the starting archive. Mutations are
at the decoded contributor boundary; no AEAD or external IdP bypass is claimed.
"""

import copy
import json
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.core import User
from app.services.backup import BackupService
from tests.services.test_backup_vault_security_archive_validation import archive_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


@pytest.mark.parametrize("dry_run", [False, True], ids=["apply", "preview"])
@pytest.mark.parametrize("active", [True, False], ids=["active", "disabled"])
@pytest.mark.parametrize("duplicate", [True, False], ids=["duplicate", "distinct-control"])
async def test_vault_distinguishes_duplicate_external_bindings_from_distinct_users(
    vault_db, tmp_path, monkeypatch, dry_run, active, duplicate, record_property,
):
    f, archive, org_id, security_snapshot = await archive_fixture(vault_db, tmp_path, monkeypatch)
    before_security = await security_snapshot()
    before_users = [dict(row) for row in (await f.db.execute(
        select(*User.__table__.columns).where(User.organization_id == org_id).order_by(User.id),
    )).mappings()]
    source = archive.contributors["core"]["users"][0]
    new = copy.deepcopy(source)
    identity = uuid4()
    new.update(id=str(identity), username=identity.hex, email=identity.hex + "@example.com",
               is_active=active)
    if not duplicate:
        new["external_id"] = "owned-distinct-subject"
    archive.contributors["core"]["users"].append(new)
    f.db.info["owned_user_ids"].append(identity)
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=dry_run,
        restore_options={"overwrite_existing": True, "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )
    await f.db.commit()
    after_security = await security_snapshot()
    after_users = [dict(row) for row in (await f.db.execute(
        select(*User.__table__.columns).where(User.organization_id == org_id).order_by(User.id),
    )).mappings()]
    created = any(row["id"] == identity for row in after_users)
    unchanged = after_users == before_users and after_security == before_security
    record_property("contributors_failed", report["summary"]["contributors_failed"])
    record_property("new_binding_durably_created", created)
    record_property("all_owned_users_and_destination_security_unchanged", unchanged)
    if duplicate:
        assert report["summary"]["contributors_failed"] == 1
        assert report["summary"]["total_created"] == report["summary"]["total_updated"] == 0
        assert unchanged and not created
    else:
        assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
        if dry_run:
            assert unchanged and not created
        else:
            assert created and len(after_users) == len(before_users) + 1
            restored = next(row for row in after_users if row["id"] == identity)
            assert restored["external_id"] == "owned-distinct-subject"
            assert restored["is_active"] is active
    rendered = json.dumps(report)
    for secret in (f.seed, f.pending_seed, f.provider_secret, f.password, source["hashed_password"]):
        assert secret not in rendered


@pytest.mark.parametrize("dry_run", [False, True], ids=["apply", "preview"])
@pytest.mark.parametrize("active", [True, False], ids=["active-target", "disabled-target"])
@pytest.mark.parametrize("collision", [True, False], ids=["destination-collision", "distinct-control"])
async def test_vault_refuses_binding_owned_by_a_different_destination_account(
    vault_db, tmp_path, monkeypatch, dry_run, active, collision, record_property,
):
    f, archive, org_id, security_snapshot = await archive_fixture(vault_db, tmp_path, monkeypatch)
    f.user.is_active = active
    await f.db.commit()
    before_security = await security_snapshot()
    before_users = [dict(row) for row in (await f.db.execute(
        select(*User.__table__.columns).where(User.organization_id == org_id).order_by(User.id),
    )).mappings()]
    data = archive.contributors["core"]
    incoming = copy.deepcopy(data["users"][0])
    identity = uuid4()
    incoming.update(id=str(identity), username=identity.hex, email=identity.hex + "@example.com")
    if not collision:
        incoming["external_id"] = "owned-distinct-destination-subject"
    # The incoming graph contains only one account and is internally unique.
    # Its conflict exists only in the current destination, under another UUID.
    data["users"] = [incoming]
    for grant in data["user_site_access"]:
        grant.update(id=str(uuid4()), user_id=str(identity))
    f.db.info["owned_user_ids"].append(identity)
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=dry_run,
        restore_options={"overwrite_existing": True, "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )
    await f.db.commit()
    after_security = await security_snapshot()
    after_users = [dict(row) for row in (await f.db.execute(
        select(*User.__table__.columns).where(User.organization_id == org_id).order_by(User.id),
    )).mappings()]
    created = any(row["id"] == identity for row in after_users)
    unchanged = after_users == before_users and after_security == before_security
    record_property("contributors_failed", report["summary"]["contributors_failed"])
    record_property("new_binding_durably_created", created)
    record_property("all_owned_users_and_destination_security_unchanged", unchanged)
    if collision:
        assert report["summary"]["contributors_failed"] == 1
        assert report["summary"]["total_created"] == report["summary"]["total_updated"] == 0
        assert unchanged and not created
    else:
        assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
        if dry_run:
            assert unchanged and not created
        else:
            assert created and len(after_users) == len(before_users) + 1
            assert all(next(row for row in after_users if row["id"] == old["id"]) == old
                       for old in before_users), "Unarchived destination accounts must not change"
    rendered = json.dumps(report)
    for secret in (f.seed, f.pending_seed, f.provider_secret, f.password, incoming["hashed_password"]):
        assert secret not in rendered
