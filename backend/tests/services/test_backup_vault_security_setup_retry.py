# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real first-install HTTP failures leave no administrator and permit a valid retry."""

import gzip
import hashlib
import json
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import delete, func, select

from app.core import security_utils
from app.core.security_utils import decrypt_field
from app.models.core import Organization, User
from app.modules.backup.models import Backup, StorageLocation
from app.services.backup import BackupEncryption
from tests.services.test_backup_vault_security_roundtrip import export_vault, source_fixture
from tests.services.test_backup_vault_security_roundtrip import (
    vault_auth_client as vault_auth_client,
)
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


def seal_archive(archive, phrase):
    body, key_id = BackupEncryption(master_key=phrase).encrypt(gzip.compress(archive.model_dump_json().encode()))
    header = json.dumps({"backup_id": str(uuid4()), "checksum": hashlib.sha256(body).hexdigest(),
                         "encrypted": True, "compressed": True, "secrets": True,
                         "key_id": key_id, "version": "2.0"}).encode()
    return len(header).to_bytes(4, "big") + header + body


@pytest.mark.parametrize("case", ["legacy", "missing-mfa-state", "high-cost-hash", "valid-control"])
async def test_security_archive_failure_keeps_setup_retryable_with_real_http(vault_db, vault_auth_client, tmp_path, monkeypatch, case):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    original = await export_vault(f)
    org_id, user_id, username = f.org.id, f.user.id, f.user.username
    damaged = original.model_copy(deep=True)
    if case == "legacy":
        damaged.manifest.contributors[0].schema_version = "1.0.0"
        damaged.contributors["core"].pop("account_security_format")
        damaged.contributors["core"]["users"][0].pop("mfa_enabled")
    elif case == "missing-mfa-state":
        damaged.contributors["core"]["users"][0].pop("mfa_enabled")
    elif case == "high-cost-hash":
        user = damaged.contributors["core"]["users"][0]
        user["hashed_password"] = user["hashed_password"].replace("m=65536", "m=2147483647")
    first_blob, valid_blob = seal_archive(damaged, f.phrase), seal_archive(original, f.phrase)
    for model in [User, Backup, StorageLocation]:
        await f.db.execute(delete(model).where(model.organization_id == org_id))
    await f.db.execute(delete(Organization).where(Organization.id == org_id))
    await f.db.commit()
    monkeypatch.setattr(security_utils, "_fernet_instance", Fernet(Fernet.generate_key()))

    async def counts():
        return [await f.db.scalar(select(func.count()).select_from(model)) for model in [Organization, User]]

    async def restore(blob):
        return await vault_auth_client.post("/api/v1/setup/restore",
                                           files={"file": ("owned-security.fsdnvault", blob, "application/octet-stream")},
                                           data={"passphrase": f.phrase})

    assert await counts() == [0, 0], "Owned fixture must be fresh without deleting unrelated rows"
    response = await restore(first_blob)
    if case != "valid-control":
        assert (response.status_code, await counts()) == (409, [0, 0])
        assert response.json().get("success") is not True
        for secret in [f.seed, f.password, f.phrase]:
            assert secret not in response.text
        status = await vault_auth_client.get("/api/v1/setup/status")
        assert status.status_code == 200 and status.json()["is_complete"] is False
        response = await restore(valid_blob)
    assert response.status_code == 200 and response.json()["success"] is True
    assert await counts() == [1, 1]
    restored = await f.db.get(User, user_id, populate_existing=True)
    assert restored.mfa_enabled is True and decrypt_field(restored.mfa_secret) == f.seed
    assert restored.token_version > 17
    login = await vault_auth_client.post("/api/v1/auth/login", json={"login": username, "password": f.password})
    assert login.status_code == 200 and login.json().get("require_mfa") is True
    assert (await restore(valid_blob)).status_code == 403
