# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for the storage_config credential-key heuristic (readiness).

``StorageLocation.config`` is a JSONB blob meant for non-secret backend
settings (region, endpoint URL, bucket name, path prefix, timeout, use_ssl).
Storage backend secrets MUST live in
``StorageLocation.encrypted_credentials`` — Fernet-encrypted via
``app.core.crypto``. Without enforcement, operators stash plaintext
credentials in the config blob and they then surface in pg_dump output,
audit-log copies, and any superuser-readable SQL query.

The backup/restore chapter added a substring-matching
heuristic to ``_validate_storage_config`` that rejects credential-like
keys (with snake_case, PascalCase, and dashed variants normalized to
the same form) while allowing the documented path/file indirection
(``private_key_path``, ``credentials_file``, ``ca_cert_path``).

These tests assert the heuristic's coverage in both directions plus the
schema-level integration so a typo in either layer is caught.
"""

from __future__ import annotations

import pytest

from app.schemas.backup import (
    StorageLocationCreate,
    StorageLocationUpdate,
    _looks_like_credential_key,
    _validate_storage_config,
)


# ── heuristic positives: must reject ────────────────────────────────────


@pytest.mark.parametrize(
    "key",
    [
        # snake_case
        "password",
        "passwd",
        "passphrase",
        "secret",
        "secret_key",
        "access_key",
        "access_token",
        "refresh_token",
        "api_key",
        "api_token",
        "client_secret",
        "private_key",
        "auth_token",
        "bearer_token",
        # PascalCase / camelCase
        "AccessKey",
        "RefreshToken",
        "ApiKey",
        "ClientSecret",
        "BearerToken",
        # dashed (some YAML configs use this)
        "aws-access-key",
        "sftp-password",
        "access-token-v2",
        # SHOUTING with prefix
        "AWS_SECRET_ACCESS_KEY",
        "SFTP_PASSWORD",
        # vendor-prefixed variants
        "aws_access_key_id",
        "gcp_service_key",
        "azure_client_secret_b64",
    ],
)
def test_credential_keys_are_rejected(key: str) -> None:
    assert _looks_like_credential_key(key), (
        f"{key!r} should be flagged as a credential-class field"
    )


# ── heuristic negatives: must allow ─────────────────────────────────────


@pytest.mark.parametrize(
    "key",
    [
        # Legitimate non-secret backend settings
        "region",
        "endpoint_url",
        "endpoint",
        "bucket",
        "bucket_name",
        "path",
        "path_prefix",
        "timeout",
        "use_ssl",
        "verify_ssl",
        "max_concurrency",
        "storage_class",
        "kms_key_id",  # SSE-KMS key REFERENCE (id), not the key itself
        # Path / file indirection — the secret lives in the sandboxed file
        "private_key_path",
        "credentials_file",
        "api_token_file",
        "ca_cert_path",
        "service_account_filepath",
    ],
)
def test_legitimate_config_keys_are_allowed(key: str) -> None:
    assert not _looks_like_credential_key(key), (
        f"{key!r} should NOT be flagged as a credential-class field"
    )


# ── full validator integration ──────────────────────────────────────────


def test_validator_accepts_clean_config() -> None:
    cfg = {
        "region": "us-east-1",
        "endpoint_url": "https://s3.example.com",
        "bucket": "freesdn-backups",
        "path_prefix": "postgres-dumps/",
        "use_ssl": True,
        "timeout": 30,
    }
    assert _validate_storage_config(cfg) == cfg


def test_validator_passes_none() -> None:
    assert _validate_storage_config(None) is None


def test_validator_rejects_credential_with_helpful_message() -> None:
    """The error message MUST point operators at
    ``encrypted_credentials`` — otherwise they'll just rename the key
    to defeat the check."""
    with pytest.raises(ValueError, match="encrypted_credentials"):
        _validate_storage_config({
            "region": "us-east-1",
            "access_key": "AKIA....",
        })


def test_validator_rejects_mixed_credential_in_otherwise_clean_config() -> None:
    """One offending key in a 5-key config is enough to fail validation."""
    with pytest.raises(ValueError, match="credential"):
        _validate_storage_config({
            "region": "us-east-1",
            "endpoint_url": "https://s3.example.com",
            "bucket": "b",
            "path_prefix": "/",
            "secret_access_key": "leaked",  # ← the offender
        })


def test_validator_allows_path_indirection_for_creds() -> None:
    """``*_path``/``*_file`` keys reference a sandboxed file, not an
    inline secret — they're the legitimate way to point at an SFTP
    private key. Must pass."""
    cfg = {
        "private_key_path": "/etc/freesdn/backup-keys/sftp_id_ed25519",
        "ca_cert_path": "/etc/freesdn/backup-keys/ca.pem",
        "host": "backup.example.com",
        "port": 22,
    }
    assert _validate_storage_config(cfg) == cfg


# ── schema-layer integration ────────────────────────────────────────────


def test_storage_location_create_rejects_credential_field() -> None:
    """The validator is wired into the Pydantic schema — a create call
    with a credential-class key in ``config`` must raise at schema
    validation time, before any service-layer code touches it."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc:
        StorageLocationCreate(
            name="my-s3",
            storage_type="s3",
            config={"region": "us-east-1", "access_key": "AKIA..."},
        )
    # The substring "encrypted_credentials" must appear in the error
    # message so the operator can find the fix path.
    assert "encrypted_credentials" in str(exc.value)


def test_storage_location_update_rejects_credential_field() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc:
        StorageLocationUpdate(config={"refresh_token": "1//xyz"})
    assert "encrypted_credentials" in str(exc.value)


def test_storage_location_create_passes_clean_config() -> None:
    """Round-trip: a clean config in StorageLocationCreate must validate
    AND the validator must not mutate the dict."""
    cfg = {"region": "us-east-1", "bucket": "b", "endpoint_url": "https://s3"}
    loc = StorageLocationCreate(name="x", storage_type="s3", config=cfg)
    assert loc.config == cfg
