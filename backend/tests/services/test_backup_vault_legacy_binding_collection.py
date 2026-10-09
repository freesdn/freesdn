# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Full vault collection must refuse ambiguous already-deployed SSO identities.

The database comes from the frozen old schema plus real migrations through 021.
No uniqueness index is removed. These cases do not authenticate an external IdP.
"""

import gzip
import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.core import User
from app.modules.backup.models import Backup, BackupStatus
from app.services.backup import (
    BackupEncryption,
    BackupRecoveryError,
    BackupService,
    LocalStorageBackend,
)
from app.services.backup_contributors import BackupArchive
from tests.services.sso_legacy_fixture import legacy_vault_database
from tests.services.test_backup_vault_security_roundtrip import source_fixture


@pytest.mark.parametrize("protocol", ["oidc", "saml", "ldap"])
@pytest.mark.parametrize("profile", [
    "duplicate-active", "duplicate-disabled", "distinct-control", "deleted-control",
])
async def test_legacy_ambiguous_binding_is_refused_before_vault_storage(
    tmp_path, monkeypatch, request, protocol, profile,
):
    async with legacy_vault_database(monkeypatch, request) as db:
        f = await source_fixture(db, tmp_path, monkeypatch, protocol=protocol)
        identity = uuid4()
        other = User(
            id=identity, organization_id=f.org.id, username=identity.hex,
            email=identity.hex + "@example.com", role="viewer",
            hashed_password="!SSO_MANAGED", auth_provider=protocol,
            external_id="owned-distinct-subject" if profile == "distinct-control" else f.user.external_id,
            sso_provider_id=f.provider.id, token_version=29,
            is_active=profile != "duplicate-disabled", is_verified=True, mfa_enabled=False,
            deleted_at=datetime.now(UTC) if profile == "deleted-control" else None,
        )
        db.add(other)
        db.info["owned_user_ids"].append(identity)
        await db.commit()

        async def current_users():
            async with AsyncSession(db.bind) as observer:
                return [dict(row) for row in (await observer.execute(
                    select(*User.__table__.columns).where(
                        User.organization_id == f.org.id,
                    ).order_by(User.id),
                )).mappings()]

        before = await current_users()
        writes = []
        actual_save = LocalStorageBackend.save

        async def observe_actual_save(self, *args, **kwargs):
            writes.append(True)
            return await actual_save(self, *args, **kwargs)

        monkeypatch.setattr(LocalStorageBackend, "save", observe_actual_save)
        refused = False
        error = None
        try:
            await BackupService(db).create_backup(
                name="Owned legacy binding vault", organization_id=f.org.id,
                include_devices=False, include_users=True, include_automation=False,
                include_secrets=True, passphrase=f.phrase,
                storage_location_id=f.storage.id, is_encrypted=True,
            )
        except BackupRecoveryError as exc:
            refused = True
            error = str(exc)
        # Observe the catalogue, storage and users before contract assertions so
        # a first failure has precise limits instead of implying later checks ran.
        await db.commit()
        row = (await db.execute(select(Backup).where(
            Backup.organization_id == f.org.id,
        ))).scalar_one()
        after = await current_users()
        files = list(tmp_path.rglob("*.fsdnvault"))
        unchanged = before == after
        request.node.user_properties.extend([
            ("collector_refused", refused),
            ("catalogue_failed", row.status == BackupStatus.FAILED),
            ("storage_save_called", bool(writes)),
            ("vault_file_count", len(files)),
            ("owned_user_security_unchanged", unchanged),
        ])
        if profile.startswith("duplicate-"):
            assert refused and error and "Full vault collection failed" in error
            assert row.status == BackupStatus.FAILED and row.storage_path is None
            assert writes == [] and not files
            assert row.error_message
            for secret in (f.user.external_id, f.user.email, other.email, f.seed,
                           f.provider_secret, f.user.hashed_password, f.retained_code):
                assert secret not in row.error_message and secret not in error
        else:
            assert not refused and row.status == BackupStatus.COMPLETED
            assert not row.error_message and len(writes) == len(files) == 1
            blob = await LocalStorageBackend(f.storage.config).load(row.storage_path)
            size = int.from_bytes(blob[:4], "big")
            header, body = json.loads(blob[4:4 + size]), blob[4 + size:]
            assert header["secrets"] is True and header["encrypted"] is True
            assert hashlib.sha256(body).hexdigest() == header["checksum"]
            archive = BackupArchive.model_validate_json(gzip.decompress(
                BackupEncryption(master_key=f.phrase).decrypt(body, header["key_id"]),
            ))
            users = archive.contributors["core"]["users"]
            expected = {str(f.user.id), str(identity)} if profile == "distinct-control" else {str(f.user.id)}
            assert {user["id"] for user in users} == expected
            for secret in (f.seed, f.provider_secret, f.user.hashed_password):
                assert secret.encode() not in blob
        assert unchanged
