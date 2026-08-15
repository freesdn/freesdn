# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Secure (.fsdnvault) backup — the crypto invariants that make a full backup
portable + safe.

The full live export→restore→re-key round-trips (controllers, users, VPN, VoIP,
cameras, firewall) are exercised against a real DB during development; these are the
fast, DB-free unit checks of the load-bearing property: a vault is sealed under the
OPERATOR PASSPHRASE (not the instance SECRET_KEY), so it opens on any instance with
the passphrase and refuses the wrong one. That portability is what lets the restore
re-key each secret onto the target instance.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import InvalidToken

from app.services.backup import CONTROLLER_SECRET_CONFIG_KEYS, BackupEncryption

_PASSPHRASE = "operator-backup-passphrase-correct-horse"
_SECRET = b"WG-PRIVATE-KEY-do-not-leak-7f3a"


def test_vault_seal_opens_with_passphrase() -> None:
    enc, key_id = BackupEncryption(master_key=_PASSPHRASE).encrypt(_SECRET)
    # A fresh BackupEncryption (i.e. a different process / instance) opens it with
    # only the passphrase — independent of any instance SECRET_KEY.
    assert BackupEncryption(master_key=_PASSPHRASE).decrypt(enc, key_id) == _SECRET


def test_vault_seal_refuses_wrong_passphrase() -> None:
    enc, key_id = BackupEncryption(master_key=_PASSPHRASE).encrypt(_SECRET)
    with pytest.raises(InvalidToken):
        BackupEncryption(master_key="not-the-passphrase-0000").decrypt(enc, key_id)


def test_vault_seal_is_not_instance_key_bound() -> None:
    # A vault sealed under the passphrase must NOT be openable with a different key
    # (e.g. some instance SECRET_KEY) — that is exactly what makes it portable rather
    # than instance-locked like the config snapshot.
    enc, key_id = BackupEncryption(master_key=_PASSPHRASE).encrypt(_SECRET)
    with pytest.raises(InvalidToken):
        BackupEncryption(master_key="some-instance-secret-key-aaaaaaaa").decrypt(enc, key_id)


def test_vault_uses_v2_kdf_at_owasp_iterations() -> None:
    # The seal uses the current PBKDF2 v2 format at the OWASP-2025 iteration count, so
    # a stolen .fsdnvault is as hard to brute-force as the config snapshot.
    _enc, key_id = BackupEncryption(master_key=_PASSPHRASE).encrypt(_SECRET)
    assert key_id.startswith(f"v2:{BackupEncryption.PBKDF2_ITERATIONS}:")


def test_controller_secret_config_keys_are_the_known_set() -> None:
    # The collect/restore re-key path keys off this constant; lock it so a new secret
    # config field can't silently travel un-decrypted (instance-bound) in a vault.
    assert set(CONTROLLER_SECRET_CONFIG_KEYS) == {"password", "client_secret"}
