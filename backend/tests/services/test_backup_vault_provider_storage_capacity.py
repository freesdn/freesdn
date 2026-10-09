# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Portable provider secrets must fit their destination encrypted columns."""

import pytest

from app.core.security_utils import decrypt_field
from app.models.sso import SSOProvider
from app.services.backup import BackupRecoveryError
from tests.services.test_backup_vault_security_roundtrip import (
    export_vault,
    recover_under_new_key,
    source_fixture,
)
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


@pytest.mark.parametrize("protocol,field", [("oidc", "oidc_client_secret"), ("ldap", "ldap_bind_password")])
@pytest.mark.parametrize("case", ["ascii-fit", "ascii-too-large", "utf8-fit", "utf8-too-large"])
async def test_provider_export_refuses_values_that_cannot_fit_after_reencryption(vault_db, tmp_path, monkeypatch, protocol, field, case):
    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol=protocol)
    values = {"ascii-fit": "x" * 319, "ascii-too-large": "x" * 320,
              "utf8-fit": "é" * 159 + "x", "utf8-too-large": "é" * 160}
    secret = values[case]
    # The field decryptor intentionally supports historical plaintext rows.
    # Both input lengths fit the PostgreSQL VARCHAR(512) source column, but
    # authenticated encryption plus prefix expands the destination value.
    setattr(f.provider, field, secret)
    await f.db.commit()
    if case.endswith("too-large"):
        with pytest.raises(BackupRecoveryError):
            await export_vault(f)
    else:
        archive = await export_vault(f)
        _, provider_id = await recover_under_new_key(f, archive, monkeypatch)
        provider = await f.db.get(SSOProvider, provider_id, populate_existing=True)
        encrypted = getattr(provider, field)
        assert encrypted != secret and len(encrypted) <= 512
        assert decrypt_field(encrypted) == secret
