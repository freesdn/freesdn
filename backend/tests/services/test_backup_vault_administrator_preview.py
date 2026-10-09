# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Administrator previews report refusal or valid replacement without writes."""

import copy
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.security import get_password_hash
from app.models.core import User
from app.services.backup import BackupService
from tests.services.test_backup_vault_security_roundtrip import export_vault, source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


@pytest.mark.parametrize("case", ["last-admin", "existing-survivor", "new-survivor-last",
                                  "no-overwrite", "active-unchanged", "already-disabled"])
async def test_administrator_restore_preview_projects_final_state_without_writes(vault_db, tmp_path, monkeypatch, case):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    archive = await export_vault(f)
    org_id, user_id = f.org.id, f.user.id
    archived = archive.contributors["core"]["users"][0]
    if case != "active-unchanged":
        archived["is_active"] = False
    if case in {"existing-survivor", "new-survivor-last"}:
        identity, new_id = uuid4().hex, uuid4()
        f.db.info["owned_user_ids"].append(new_id)
        if case == "existing-survivor":
            f.db.add(User(id=new_id, organization_id=org_id, username=identity,
                          email=identity + "@example.com", role="super_admin", is_active=True,
                          hashed_password=get_password_hash("Owned preview survivor password")))
        else:
            new = copy.deepcopy(archived)
            new.update(id=str(new_id), username=identity, email=identity + "@example.com", is_active=True)
            archive.contributors["core"]["users"].append(new)
    if case == "already-disabled":
        f.user.is_active = False
    await f.db.commit()

    async def rows():
        return [dict(row) for row in (await f.db.execute(select(*User.__table__.columns)
                                                       .where(User.organization_id == org_id)
                                                       .order_by(User.id))).mappings()]

    before = await rows()
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=True,
        restore_options={"overwrite_existing": case != "no-overwrite", "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )
    await f.db.commit()
    assert report["summary"]["contributors_failed"] == (1 if case == "last-admin" else 0)
    assert await rows() == before
    assert any(row["id"] == user_id for row in before)
