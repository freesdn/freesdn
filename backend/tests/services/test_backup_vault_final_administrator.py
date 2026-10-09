# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Normal vault overwrite must preserve the existing administrator safety rule.

Real dispatcher and committed owned rows. This is separate from first-install
recovery and from the setup gate's non-deleted-administrator count. Disabling
the final active administrator does not by itself prove setup reopens.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.core.security import get_password_hash
from app.models.core import Organization, Site, User
from app.services.backup import BackupService
from tests.services.test_backup_vault_security_roundtrip import export_vault, source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db

CASES = [(role, survivor) for role in ["super_admin", "org_admin"]
         for survivor in ["none", "active-same-org", "inactive", "deleted", "active-other-org"]]
CASES.append(("super_admin", "org-admin-same-org"))


@pytest.mark.parametrize("role,survivor_kind", CASES)
async def test_normal_vault_cannot_disable_last_platform_or_organization_administrator(vault_db, tmp_path, monkeypatch, role, survivor_kind):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    f.user.role = role
    f.user.is_active = False
    site = Site(organization_id=f.org.id, name="Archived administrator-site name", slug=uuid4().hex)
    f.db.add(site)
    archive = await export_vault(f)
    f.user.is_active = True
    f.user.token_version = 1000
    site.name = "Current administrator-site name"
    other_org = Organization(name="Owned independent admin organization", slug=uuid4().hex)
    f.db.add(other_org)
    await f.db.flush()
    f.db.info["owned_org_ids"].append(other_org.id)

    def add_admin(*, org_id, admin_role, active=True, deleted=False):
        identity = uuid4().hex
        user = User(id=uuid4(), organization_id=org_id, username=identity, email=identity + "@example.com",
                    role=admin_role, is_active=active, is_verified=True,
                    hashed_password=get_password_hash("Owned surviving administrator password"),
                    deleted_at=datetime.now(UTC) if deleted else None)
        f.db.add(user)
        f.db.info["owned_user_ids"].append(user.id)

    if role == "org_admin":
        add_admin(org_id=other_org.id, admin_role="super_admin")
    if survivor_kind != "none":
        add_admin(org_id=other_org.id if survivor_kind == "active-other-org" else f.org.id,
                  admin_role="org_admin" if survivor_kind == "org-admin-same-org" else role,
                  active=survivor_kind != "inactive", deleted=survivor_kind == "deleted")
    await f.db.commit()
    org_id, user_id, site_id = f.org.id, f.user.id, site.id

    async def state():
        account = (await f.db.execute(select(*User.__table__.columns).where(User.id == user_id))).mappings().one()
        org_admins = await f.db.scalar(select(func.count()).select_from(User).where(
            User.organization_id == org_id, User.role.in_(["super_admin", "org_admin"]),
            User.is_active.is_(True), User.deleted_at.is_(None),
        ))
        platform_admins = await f.db.scalar(select(func.count()).select_from(User).where(
            User.role == "super_admin", User.is_active.is_(True), User.deleted_at.is_(None),
        ))
        return dict(account), org_admins, platform_admins, await f.db.scalar(select(Site.name).where(Site.id == site_id))

    before = await state()
    assert before[1] > 0 and before[2] > 0
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=False,
        restore_options={"overwrite_existing": True, "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )
    await f.db.commit()
    after = await state()
    if survivor_kind == "active-same-org":
        assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
        assert after[0]["is_active"] is False and after[1] > 0 and after[2] > 0
        assert after[3] == "Archived administrator-site name"
    else:
        # Include committed state in this first assertion to record whether a
        # baseline actually leaves zero admins; later equality may not execute.
        assert (report["summary"]["contributors_failed"], after[0]["is_active"], after[1] > 0, after[2] > 0) == (1, True, True, True)
        assert after == before, "Refusal must roll back the complete core contributor"
