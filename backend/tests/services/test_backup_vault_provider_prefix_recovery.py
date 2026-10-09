# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Legitimate provider secret contents survive portable recovery under a new key."""

from uuid import uuid4

import pytest

from app.core.security_utils import decrypt_field, encrypt_field
from app.models.sso import SSOProvider
from tests.services.test_backup_vault_security_roundtrip import (
    export_vault,
    recover_under_new_key,
    source_fixture,
)
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


@pytest.mark.parametrize("protocol,field", [("oidc", "oidc_client_secret"),
                                          ("saml", "saml_signing_key"),
                                          ("ldap", "ldap_bind_password")])
async def test_provider_secret_prefix_survives_destination_field_key_rotation(vault_db, tmp_path, monkeypatch, protocol, field):
    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol=protocol)
    secret = "fernet:Owned provider credential contents " + uuid4().hex
    source_ciphertext = encrypt_field(secret)
    setattr(f.provider, field, source_ciphertext)
    archive = await export_vault(f)
    restored_user, provider_id = await recover_under_new_key(f, archive, monkeypatch)
    provider = await f.db.get(SSOProvider, provider_id, populate_existing=True)
    destination_ciphertext = getattr(provider, field)
    assert restored_user.sso_provider_id == provider_id
    assert destination_ciphertext != source_ciphertext and destination_ciphertext != secret
    assert decrypt_field(destination_ciphertext) == secret
