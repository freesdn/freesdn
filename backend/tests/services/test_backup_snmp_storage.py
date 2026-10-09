"""Actual encrypted core archives retain long communities across storage restore.

The core restore path runs against PostgreSQL; this is not a full customer
disaster-recovery, multi-contributor or hardware-acceptance test.
"""

import gzip
import hashlib
import json
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet

from app.core import crypto
from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.models.core import Credential, Organization
from app.modules.backup.models import BackupStatus, StorageLocation
from app.services.backup import BackupEncryption, BackupService, LocalStorageBackend
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    CoreBackupContributor,
)


@pytest.mark.parametrize("community", ["x" * 512, "🔑" * 512], ids=["ascii", "unicode"])
@pytest.mark.parametrize("secrets", [False, True], ids=["config", "vault"])
async def test_encrypted_core_archive_restores_snmp_capacity(
    db_session, tmp_path, monkeypatch, community, secrets
):
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    org = Organization(name="Owned SNMP archive", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    credential = Credential(
        organization_id=org.id,
        name="Owned SNMP credential",
        credential_type="snmp_community",
        snmp_community=encrypt_credential(community),
        encrypted_password=encrypt_credential("owned-companion-secret"),
        options={"port": 161},
    )
    storage = StorageLocation(
        organization_id=org.id,
        name="Owned SNMP storage",
        storage_type="local",
        config={"path": str(tmp_path)},
        is_active=True,
    )
    db_session.add_all([credential, storage])
    await db_session.flush()
    identity = credential.id
    original_ciphertext = credential.snmp_community
    service = BackupService(db_session)
    phrase = "owned-disposable-snmp-archive-passphrase"
    backup = await service.create_backup(
        name="Owned SNMP archive",
        organization_id=org.id,
        include_devices=False,
        include_users=False,
        include_secrets=secrets,
        passphrase=phrase if secrets else None,
        storage_location_id=storage.id,
        is_encrypted=True,
    )
    assert backup.status == BackupStatus.COMPLETED and not backup.error_message
    raw = await LocalStorageBackend({"path": str(tmp_path)}).load(backup.storage_path)
    size = int.from_bytes(raw[:4], "big")
    header = json.loads(raw[4 : 4 + size])
    encrypted = raw[4 + size :]
    assert header["encrypted"] is True and header["secrets"] is secrets
    assert hashlib.sha256(encrypted).hexdigest() == header["checksum"]
    assert community.encode() not in raw and original_ciphertext.encode() not in raw
    encryption = BackupEncryption(master_key=phrase) if secrets else service.encryption
    archive = BackupArchive.model_validate_json(
        gzip.decompress(encryption.decrypt(encrypted, header["key_id"]))
    )
    data = archive.contributors["core"]
    assert len(data["credentials"]) == 1
    assert data["credentials"][0]["snmp_community"] == (community if secrets else None)
    if secrets:
        await db_session.delete(credential)
        await db_session.flush()
        # A portable vault must restore under the destination's different key.
        monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))
    else:
        credential.snmp_community = encrypt_credential("destination-" + community)
        await db_session.flush()
        live_ciphertext = credential.snmp_community
    result = await service._restore_data(
        data,
        dry_run=False,
        overwrite_existing=True,
        restore_devices=False,
        restore_users=False,
        include_secrets=secrets,
    )
    await db_session.commit()
    restored = await db_session.get(Credential, identity, populate_existing=True)
    assert restored is not None and restored.organization_id == org.id
    assert restored.options == {"port": 161} and is_encrypted(restored.snmp_community)
    assert result["credentials"]["created" if secrets else "updated"] == 1
    assert result["credentials"]["skipped"] == 0
    if secrets:
        assert restored.snmp_community != original_ciphertext
        assert decrypt_credential(restored.snmp_community) == community
        assert decrypt_credential(restored.encrypted_password) == "owned-companion-secret"
    else:
        assert restored.snmp_community == live_ciphertext
        assert decrypt_credential(restored.snmp_community) == "destination-" + community
