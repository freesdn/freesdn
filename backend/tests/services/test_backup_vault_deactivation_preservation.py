# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""An older sealed vault must not reactivate a disabled destination account."""

import gzip
import hashlib
import json
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.db.session import create_test_engine
from app.models.core import Organization, User
from app.models.security_audit import AuditLogRecord
from app.modules.backup.models import Backup, BackupStatus, StorageLocation
from app.services.backup import BackupEncryption, BackupService, LocalStorageBackend
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    CoreBackupContributor,
)


@pytest.mark.parametrize("role", ["super_admin", "viewer"])
@pytest.mark.parametrize("mode", [
    "revoked_after_snapshot", "preview", "no_overwrite", "configuration",
    "still_active", "archive_disables", "fresh_account",
])
async def test_vault_preserves_destination_deactivation(monkeypatch, tmp_path, role, mode):
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    engine = create_test_engine()
    org_id, user_id, survivor_id = uuid4(), uuid4(), uuid4()
    phrase = "Owned deactivation archive phrase"
    hashed_password = get_password_hash("Owned!Account7-" + uuid4().hex)
    try:
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as db:
            db.add(Organization(id=org_id, name="Owned deactivation", slug=uuid4().hex))
            await db.flush()
            for identity, user_role, active in [
                (user_id, role, mode != "archive_disables"),
                (survivor_id, "super_admin", True),
            ]:
                db.add(User(id=identity, organization_id=org_id, username=identity.hex,
                            email=identity.hex + "@example.com", role=user_role,
                            is_active=active, is_verified=True, token_version=17,
                            hashed_password=hashed_password))
            storage = StorageLocation(organization_id=org_id, name="Owned archive",
                                      storage_type="local", config={"path": str(tmp_path)}, is_active=True)
            db.add(storage)
            await db.commit()
            service = BackupService(db)
            secret = mode != "configuration"
            backup = await service.create_backup(
                name="Owned account snapshot", organization_id=org_id,
                include_devices=False, include_users=True, include_automation=False,
                include_secrets=secret, passphrase=phrase if secret else None,
                storage_location_id=storage.id, is_encrypted=True,
            )
            assert backup.status == BackupStatus.COMPLETED and not backup.error_message
            await db.commit()
            blob = await LocalStorageBackend(storage.config).load(backup.storage_path)
            size = int.from_bytes(blob[:4], "big")
            header, body = json.loads(blob[4:4 + size]), blob[4 + size:]
            assert header["secrets"] is secret and header["encrypted"] is True
            assert hashlib.sha256(body).hexdigest() == header["checksum"]
            assert phrase.encode() not in blob and hashed_password.encode() not in blob
            cipher = BackupEncryption(master_key=phrase) if secret else service.encryption
            archive = BackupArchive.model_validate_json(gzip.decompress(cipher.decrypt(body, header["key_id"])))
            user = await db.get(User, user_id, populate_existing=True)
            if mode == "fresh_account":
                await db.delete(user)
            else:
                user.is_active = mode in {"still_active", "archive_disables"}
                user.token_version = 1000
            await db.commit()
            report = await service._dispatch_restore_via_contributors(
                archive, organization_id=org_id, dry_run=mode == "preview",
                restore_options={"include_secrets": secret, "restore_users": True,
                                 "restore_devices": False, "overwrite_existing": mode != "no_overwrite"},
            )
            await db.commit()
            # Query committed scalars before assertions, bypassing stale ORM
            # identities and making the observed transition explicit.
            active, counter = (await db.execute(select(User.is_active, User.token_version)
                                                  .where(User.id == user_id))).one()
            surviving_admin = await db.scalar(select(User.is_active).where(User.id == survivor_id))
            assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
            expected_active = mode in {"still_active", "fresh_account"}
            assert active is expected_active, {"mode": mode, "role": role, "actual_active": active,
                                               "expected_active": expected_active, "counter": counter}
            assert surviving_admin is True
            if mode in {"preview", "no_overwrite", "configuration"}:
                assert counter == 1000
            elif mode != "fresh_account":
                assert counter > 1000
            # Fresh counter/MFA/SSO fidelity has separate failing evidence;
            # this control establishes only the archived active-state policy.
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.organization_id == org_id))
            await cleanup.execute(delete(Backup).where(Backup.organization_id == org_id))
            await cleanup.execute(delete(StorageLocation).where(StorageLocation.organization_id == org_id))
            await cleanup.execute(delete(User).where(User.id.in_([user_id, survivor_id])))
            await cleanup.execute(delete(Organization).where(Organization.id == org_id))
            await cleanup.commit()
        await engine.dispose()
