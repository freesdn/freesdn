# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the central :mod:`app.core.redaction` strip-list.

SNMPv3 + RouterOS-specific keys live in the central allowlist so the
per-service ``_mask_routeros`` walks can be deleted. These tests guard
against the per-service walks sneaking back without a corresponding
update to the central list.
"""

from __future__ import annotations

from app.core.redaction import redact_list, redact_secrets

# ─── SNMPv3 password / encryption ────────────────────────────────────


def test_redacts_snmpv3_auth_password() -> None:
    row = {
        "name": "monitor",
        "auth-password": "supersecret",
        "auth-protocol": "SHA1",
    }
    out = redact_secrets(row)
    assert out["auth-password"] == "***"
    # Non-secret peers stay untouched.
    assert out["auth-protocol"] == "SHA1"
    assert out["name"] == "monitor"


def test_redacts_snmpv3_encryption_password() -> None:
    row = {
        "name": "monitor",
        "encryption-password": "anothersecret",
        "encryption-protocol": "AES",
    }
    out = redact_secrets(row)
    assert out["encryption-password"] == "***"
    assert out["encryption-protocol"] == "AES"


def test_redacts_mschapv2_password() -> None:
    row = {"mschapv2-password": "creds", "user": "alice"}
    out = redact_secrets(row)
    assert out["mschapv2-password"] == "***"
    assert out["user"] == "alice"


def test_redacts_unifi_device_ssh_password_and_mesh_key() -> None:
    """UniFi /stat/device rows carry x_ssh_password (plaintext device SSH login
    -> shell) + x_vwirekey (mesh uplink PSK) inline. Neither normalizes to a
    base strip-list key, so they have explicit entries; a controller:read
    operator must never read them back through list_devices."""
    row = {
        "mac": "aa:bb:cc:dd:ee:ff",
        "x_authkey": "authkey",
        "x_ssh_password": "SSHPASS",
        "ssh_password": "SSHPASS2",
        "x_ssh_username": "root",  # username is not a secret — must stay
        "x_vwirekey": "MESHKEY",
        "name": "AP-Lobby",
    }
    out = redact_secrets(row)
    assert out["x_ssh_password"] == "***"
    assert out["ssh_password"] == "***"
    assert out["x_vwirekey"] == "***"
    assert out["x_authkey"] == "***"
    # Non-secret peers stay visible (the username is needed to render the row).
    assert out["x_ssh_username"] == "root"
    assert out["name"] == "AP-Lobby"
    assert out["mac"] == "aa:bb:cc:dd:ee:ff"


# ─── RouterOS-specific keys formerly redundantly masked ──────────────


def test_redacts_ipsec_shared_secret() -> None:
    row = {"name": "peer-a", "shared-secret": "preshared!"}
    out = redact_secrets(row)
    assert out["shared-secret"] == "***"


def test_redacts_ipsec_secret_underscore_form() -> None:
    row = {"ipsec_secret": "preshared!"}
    out = redact_secrets(row)
    assert out["ipsec_secret"] == "***"


def test_redacts_private_key_file() -> None:
    row = {"private-key-file": "/flash/secret.key"}
    out = redact_secrets(row)
    assert out["private-key-file"] == "***"


def test_redacts_routeros_auth_secret() -> None:
    row = {"auth-secret": "ospf-md5-key"}
    out = redact_secrets(row)
    assert out["auth-secret"] == "***"


def test_redacts_routeros_radius_secret() -> None:
    row = {"radius-secret": "shhh"}
    out = redact_secrets(row)
    assert out["radius-secret"] == "***"


def test_redacts_private_key_passphrase() -> None:
    row = {"private-key-passphrase": "key-pass"}
    out = redact_secrets(row)
    assert out["private-key-passphrase"] == "***"


# ─── Nested / list payloads — recursion still works ──────────────────


def test_recurses_into_lists_for_snmpv3() -> None:
    rows = [
        {"name": "alice", "auth-password": "a"},
        {"name": "bob", "encryption-password": "b"},
    ]
    out = redact_list(rows)
    assert out[0]["auth-password"] == "***"
    assert out[1]["encryption-password"] == "***"


def test_norm_key_collapses_hyphens_consistently() -> None:
    # Both hyphenated and underscored forms of the same secret are
    # redacted (normalisation lives in ``_norm_key``).
    row = {
        "auth-password": "a",
        "auth_password": "b",
        "ENCRYPTION-PASSWORD": "c",  # case-insensitive
    }
    out = redact_secrets(row)
    assert out["auth-password"] == "***"
    assert out["auth_password"] == "***"
    assert out["ENCRYPTION-PASSWORD"] == "***"


def test_non_sensitive_keys_pass_through() -> None:
    row = {"name": "foo", "address": "1.2.3.4", "comment": "hi"}
    out = redact_secrets(row)
    assert out == row
