# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private proposed security-source contract; not frozen or executed.

These tests exercise collection before storage and the real JIT provisioning
method. They do not authenticate an external identity provider. High-cost PHC
strings are only serialized or structurally inspected, never authenticated.
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.security_utils import decrypt_field, encrypt_field
from app.models.core import Organization
from app.models.sso import SSOProvider
from app.modules.backup.models import Backup, BackupStatus
from app.services.backup import BackupRecoveryError, BackupService, LocalStorageBackend
from app.services.sso import SSOService
from tests.services.test_backup_vault_security_roundtrip import (
    export_vault,
    recover_under_new_key,
    source_fixture,
)
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db

INVALID_SOURCE_STATES = [
    "enabled_missing_seed", "invalid_live_seed", "unreadable_live_seed",
    "unreadable_pending_seed", "pending_codes_without_seed",
    "malformed_codes", "object_codes", "plaintext_code", "duplicate_codes",
    "too_many_codes", "high_cost_code", "high_memory_password",
    "high_time_password", "high_parallelism_password", "unsupported_hash_algorithm",
    "malformed_password_hash", "active_local_disabled_marker", "local_sso_marker",
    "negative_version", "exhausted_version", "negative_failed_attempts",
    "missing_provider_binding", "missing_external_subject", "foreign_provider",
    "deleted_provider", "unreadable_provider_secret", "provider_protocol_mismatch",
]


def distinct_encoded_hashes(encoded, count):
    # No costly verification or hashing of attacker-selected parameters. A
    # changed first salt character remains canonical unpadded base64 and makes
    # these structurally valid PHC strings distinct for the count boundary.
    parts = encoded.split("$")
    assert len(parts) == 6 and len(parts[4]) == 22
    return ["$".join([*parts[:4], letter + parts[4][1:], parts[5]])
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:count]]


@pytest.mark.parametrize("case", INVALID_SOURCE_STATES)
async def test_full_vault_refuses_invalid_security_before_storage(vault_db, tmp_path, monkeypatch, case):
    provider_case = case in {
        "missing_provider_binding", "missing_external_subject", "foreign_provider",
        "deleted_provider", "unreadable_provider_secret", "provider_protocol_mismatch",
    }
    f = await source_fixture(vault_db, tmp_path, monkeypatch,
                             protocol="oidc" if provider_case else None)
    codes = json.loads(f.user.mfa_backup_codes)
    if case == "enabled_missing_seed":
        f.user.mfa_secret = None
    elif case == "invalid_live_seed":
        f.user.mfa_secret = encrypt_field("invalid seed containing spaces")
    elif case == "unreadable_live_seed":
        f.user.mfa_secret = "fernet:owned-invalid-ciphertext"
    elif case == "unreadable_pending_seed":
        f.user.mfa_pending_secret = "fernet:owned-invalid-ciphertext"
        f.user.mfa_pending_backup_codes = json.dumps(codes)
    elif case == "pending_codes_without_seed":
        f.user.mfa_pending_secret = None
        f.user.mfa_pending_backup_codes = json.dumps(codes)
    elif case == "malformed_codes":
        f.user.mfa_backup_codes = "[malformed"
    elif case == "object_codes":
        f.user.mfa_backup_codes = json.dumps({"code": codes[0]})
    elif case == "plaintext_code":
        f.user.mfa_backup_codes = json.dumps([f.retained_code])
    elif case == "duplicate_codes":
        f.user.mfa_backup_codes = json.dumps(codes * 2)
    elif case == "too_many_codes":
        f.user.mfa_backup_codes = json.dumps(distinct_encoded_hashes(codes[0], 11))
    elif case == "high_cost_code":
        f.user.mfa_backup_codes = json.dumps([codes[0].replace("m=65536", "m=1073741824")])
    elif case == "high_memory_password":
        f.user.hashed_password = f.user.hashed_password.replace("m=65536", "m=1073741824")
    elif case == "high_time_password":
        f.user.hashed_password = f.user.hashed_password.replace("t=3", "t=1000000")
    elif case == "high_parallelism_password":
        f.user.hashed_password = f.user.hashed_password.replace("p=4", "p=1024")
    elif case == "unsupported_hash_algorithm":
        f.user.hashed_password = f.user.hashed_password.replace("$argon2id$", "$argon2d$")
    elif case == "malformed_password_hash":
        f.user.hashed_password = "$argon2id$broken"
    elif case == "active_local_disabled_marker":
        f.user.hashed_password = "!"
    elif case == "local_sso_marker":
        f.user.hashed_password = "!SSO_MANAGED"
    elif case == "negative_version":
        f.user.token_version = -1
    elif case == "exhausted_version":
        f.user.token_version = 2**31 - 1
    elif case == "negative_failed_attempts":
        f.user.failed_login_attempts = -1
    elif case == "missing_provider_binding":
        f.user.sso_provider_id = None
    elif case == "missing_external_subject":
        f.user.external_id = None
    elif case == "foreign_provider":
        foreign = Organization(name="Owned foreign provider", slug=uuid4().hex)
        f.db.add(foreign)
        await f.db.flush()
        f.db.info["owned_org_ids"].append(foreign.id)
        f.provider.organization_id = foreign.id
    elif case == "deleted_provider":
        f.provider.deleted_at = datetime.now(UTC)
    elif case == "unreadable_provider_secret":
        f.provider.oidc_client_secret = "fernet:owned-invalid-ciphertext"
    else:
        assert case == "provider_protocol_mismatch"
        f.user.auth_provider = "ldap"
    await f.db.commit()

    writes = []
    real_save = LocalStorageBackend.save

    async def observe_real_save(self, *args, **kwargs):
        writes.append(True)
        return await real_save(self, *args, **kwargs)

    monkeypatch.setattr(LocalStorageBackend, "save", observe_real_save)
    with pytest.raises(BackupRecoveryError, match="Full vault collection failed"):
        await BackupService(f.db).create_backup(
            name="Owned invalid-security vault", organization_id=f.org.id,
            include_devices=False, include_users=True, include_automation=False,
            include_secrets=True, passphrase=f.phrase,
            storage_location_id=f.storage.id, is_encrypted=True,
        )
    # Exceptions from fixtures/DB setup are outside the expected-error block.
    # The actual creation path must persist a safe failed catalogue record.
    row = (await f.db.execute(select(Backup).where(Backup.organization_id == f.org.id))).scalar_one()
    assert row.status == BackupStatus.FAILED and row.storage_path is None
    assert writes == [] and not list(tmp_path.rglob("*.fsdnvault"))
    assert row.error_message and f.user.hashed_password not in row.error_message
    assert f.seed not in row.error_message and f.provider_secret not in row.error_message


@pytest.mark.parametrize("protocol", ["oidc", "saml", "ldap"])
async def test_actual_jit_account_marker_survives_portable_vault(vault_db, tmp_path, monkeypatch, protocol):
    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol=protocol)
    # Replace the hand-built account with the real provisioning method's row.
    # This method starts after external assertions have been verified; calling
    # it directly is not evidence of a valid IdP exchange or signature check.
    await f.db.delete(f.user)
    await f.db.flush()
    f.provider.jit_provisioning = True
    # Real provider administration persists configuration before sign-in starts.
    await f.db.commit()
    identity = uuid4().hex
    subject_key = {"oidc": "sub", "saml": "NameID", "ldap": "dn"}[protocol]
    f.user = await SSOService(f.db)._provision_or_update_user(
        f.provider, {"email": identity + "@example.com", "username": identity},
        {subject_key: "owned-jit-subject"},
    )
    f.db.info["owned_user_ids"].append(f.user.id)
    assert f.user.hashed_password == "!SSO_MANAGED"
    assert f.user.auth_provider == protocol and f.user.sso_provider_id == f.provider.id
    archived_version = f.user.token_version
    archive = await export_vault(f)
    restored, provider_id = await recover_under_new_key(f, archive, monkeypatch)
    provider = await f.db.get(SSOProvider, provider_id, populate_existing=True)
    assert restored.hashed_password == "!SSO_MANAGED"
    assert restored.is_active and restored.is_verified
    assert restored.auth_provider == protocol and restored.external_id == "owned-jit-subject"
    assert restored.sso_provider_id == provider_id and provider is not None
    assert provider.protocol.value == protocol and restored.token_version > archived_version
    secret_field = {"oidc": "oidc_client_secret", "saml": "saml_signing_key", "ldap": "ldap_bind_password"}[protocol]
    assert decrypt_field(getattr(provider, secret_field)) == f.provider_secret


async def test_disabled_configuration_profile_is_not_activated_by_vault(vault_db, tmp_path, monkeypatch):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    f.user.hashed_password = "!"
    f.user.is_active = False
    f.user.is_verified = False
    f.user.mfa_enabled = False
    f.user.mfa_secret = None
    f.user.mfa_backup_codes = None
    f.user.mfa_last_totp_step = None
    f.user.role = "viewer"
    archive = await export_vault(f)
    restored, _ = await recover_under_new_key(f, archive, monkeypatch)
    assert restored.hashed_password == "!" and restored.role == "viewer"
    assert restored.is_active is False and restored.is_verified is False
    assert restored.mfa_enabled is False and restored.sso_provider_id is None
