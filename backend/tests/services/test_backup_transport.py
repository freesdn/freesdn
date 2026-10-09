# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Fail-closed storage policies and truthful connection verification."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services.backup import BackupService, FTPStorageBackend, SFTPStorageBackend
from app.services.backup_transport import StorageConfigurationError, require_host_key, require_tls


@pytest.mark.parametrize("value", [False, None, "", "false", "False", "TRUE", "1", 1, [], {}])
def test_plaintext_and_ambiguous_tls_settings_rejected(value):
    with pytest.raises(StorageConfigurationError, match="Plaintext FTP"):
        require_tls(value)


@pytest.mark.parametrize("value", [True, "true"])
def test_explicit_tls_settings_accepted(value):
    require_tls(value)


@pytest.mark.parametrize("value", [None, "", "SHA256:abc", "MD5:00:11", "SHA256:" + "a" * 44])
def test_untrusted_sftp_configuration_rejected(value):
    with pytest.raises(StorageConfigurationError, match="trusted server"):
        require_host_key(value)


@pytest.fixture
def pin_loopback(monkeypatch):
    # Only tests bypass the public-address policy to reach a disposable peer.
    monkeypatch.setattr("app.services.backup.resolve_and_pin_host", lambda *_a, **_kw: "127.0.0.1")


@pytest.mark.parametrize(
    "path",
    [
        "/etc/shadow",
        "/backups/../secrets",
        "/backups2/file",
        "/backups",
        "/backups/file\r\nDELE /other",
        "ftp://attacker.test/backups/file",
        "ftp://user@backup.test/backups/file",
        "ftp://backup.test:25/backups/file",
        "/backups/dir\\file",
    ],
)
async def test_destination_paths_rejected_before_network(path, pin_loopback, monkeypatch):
    connector = MagicMock()
    monkeypatch.setattr("app.services.backup.ftps_connection", connector)
    backend = FTPStorageBackend({"host": "backup.test", "use_tls": True})
    with pytest.raises(StorageConfigurationError):
        await backend.load(path)
    connector.assert_not_called()


@pytest.mark.parametrize("config", [{}, {"use_tls": False}, {"use_tls": "false"}])
async def test_legacy_plaintext_destination_never_opens_socket(config, pin_loopback, monkeypatch):
    connect = MagicMock()
    monkeypatch.setattr("app.services.backup_transport.PinnedFTP_TLS", connect)
    backend = FTPStorageBackend({"host": "backup.test", **config})
    with pytest.raises(StorageConfigurationError, match="Plaintext FTP"):
        await backend.load("/backups/file")
    connect.assert_not_called()


def location():
    return SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        storage_type="ftp",
        config={"host": "backup.test", "use_tls": True},
        encrypted_credentials=None,
        is_active=True,
    )


def service(loc):
    db = AsyncMock()
    db.get.return_value = loc
    db.add = MagicMock()
    return BackupService(db)


def probe_backend():
    backend = SimpleNamespace(
        SUPPORTS_DELETE=True,
        save=AsyncMock(return_value="/backups/probe"),
        exists=AsyncMock(return_value=True),
        load=AsyncMock(),
        delete=AsyncMock(return_value=True),
    )

    async def download(_path):
        return backend.save.await_args.args[1]

    backend.load.side_effect = download
    return backend


@pytest.mark.parametrize(
    "failure", ["missing", "corrupt", "cleanup_false", "cleanup_error", "provider"]
)
async def test_probe_never_claims_false_success(failure, monkeypatch):
    loc = location()
    svc = service(loc)
    backend = probe_backend()
    if failure == "missing":
        backend.exists.return_value = False
    elif failure == "corrupt":
        backend.load.side_effect = None
        backend.load.return_value = b"corrupt"
    elif failure == "cleanup_false":
        backend.delete.return_value = False
    elif failure == "cleanup_error":
        backend.delete.side_effect = RuntimeError("test-secret-should-not-leak")
    else:
        backend.load.side_effect = RuntimeError("test-secret-should-not-leak")
    monkeypatch.setattr("app.services.backup.get_storage_backend", lambda *_a: backend)
    result = await svc.test_storage_location(loc.id)
    assert result["success"] is False and loc.last_test_status == "failed"
    assert "test-secret" not in json.dumps(result) + loc.last_test_message
    backend.delete.assert_awaited_once()


async def test_probe_requires_round_trip_and_cleanup(monkeypatch):
    loc = location()
    backend = probe_backend()
    monkeypatch.setattr("app.services.backup.get_storage_backend", lambda *_a: backend)
    result = await service(loc).test_storage_location(loc.id)
    assert result["success"] is True
    assert result["details"] == {"round_trip_verified": True, "cleanup": "acknowledged"}


@pytest.mark.parametrize("mode", ["corrupt", "policy_override", "disabled", "append_only"])
async def test_probe_fails_closed_without_writes(mode, monkeypatch):
    loc = location()
    if mode == "disabled":
        loc.is_active = False
    if mode in {"corrupt", "policy_override"}:
        loc.encrypted_credentials = "broken-ciphertext"
        if mode == "policy_override":
            monkeypatch.setattr("app.core.crypto.decrypt_credential", lambda _: '{"use_tls":false}')
    backend = SimpleNamespace(SUPPORTS_DELETE=False, save=AsyncMock())
    factory = MagicMock(return_value=backend)
    monkeypatch.setattr("app.services.backup.get_storage_backend", factory)
    result = await service(loc).test_storage_location(loc.id)
    assert result["success"] is False
    backend.save.assert_not_awaited()
    if mode != "append_only":
        factory.assert_not_called()


async def test_config_and_credential_patch_preserves_existing_fields(pin_loopback):
    from app.core.crypto import decrypt_credential, encrypt_credential

    loc = location()
    loc.config.update({"username": "backup-user", "remote_path": "/backups", "port": 2121})
    loc.encrypted_credentials = encrypt_credential(json.dumps({"password": "old", "token": "keep"}))
    await service(loc).update_storage_location(
        loc.id, config={"remote_path": "/new-root"}, credentials={"password": "new"}
    )
    assert loc.config == {
        "host": "backup.test",
        "use_tls": True,
        "username": "backup-user",
        "remote_path": "/new-root",
        "port": 2121,
    }
    assert json.loads(decrypt_credential(loc.encrypted_credentials)) == {
        "password": "new",
        "token": "keep",
    }


async def test_sftp_mismatch_precedes_password_and_closes_resources(monkeypatch, pin_loopback):
    import paramiko

    sock = MagicMock()
    transport = MagicMock()
    transport.get_remote_server_key.return_value.asbytes.return_value = b"wrong-host-key"
    monkeypatch.setattr(
        "app.services.backup_transport.socket.create_connection", lambda *_a, **_kw: sock
    )
    monkeypatch.setattr(paramiko, "Transport", lambda *_a: transport)
    backend = SFTPStorageBackend(
        {
            "host": "backup.test",
            "username": "test",
            "password": "secret",
            "host_key_sha256": "SHA256:" + base64.b64encode(b"x" * 32).decode().rstrip("="),
        }
    )
    with pytest.raises(StorageConfigurationError, match="No credentials were sent"):
        await backend.load("/backups/file")
    transport.auth_password.assert_not_called()
    transport.auth_publickey.assert_not_called()
    transport.close.assert_called_once()
    sock.close.assert_called_once()


@pytest.mark.parametrize(
    "storage_type,config,review",
    [
        ("ftp", {}, True),
        ("ftp", {"use_tls": "false"}, True),
        ("ftp", {"use_tls": True}, False),
        ("sftp", {}, True),
        ("sftp", {"host_key_sha256": "SHA256:" + "A" * 43}, False),
        ("local", {}, False),
    ],
)
def test_storage_review_status_discloses_no_configuration(storage_type, config, review):
    from datetime import UTC, datetime

    from app.modules.backup.models import StorageLocation
    from app.schemas.backup import StorageLocationResponse

    loc = StorageLocation(
        id=uuid4(),
        name="Destination",
        storage_type=storage_type,
        config={**config, "host": "private-name", "password": "legacy-secret"},
        is_active=True,
        is_default=False,
        created_at=datetime.now(UTC),
    )
    result = StorageLocationResponse.model_validate(loc).model_dump()
    assert result["transport_security_review_required"] is review
    assert "config" not in result and "encrypted_credentials" not in result
    assert "legacy-secret" not in str(result) and "private-name" not in str(result)


async def test_new_ftp_destinations_default_to_tls(pin_loopback):
    svc = service(None)
    loc = await svc.create_storage_location(
        name="New", storage_type="ftp", config={"host": "backup.test"}
    )
    assert loc.config["use_tls"] is True


async def test_new_sftp_destination_requires_trusted_fingerprint(pin_loopback):
    svc = service(None)
    with pytest.raises(StorageConfigurationError, match="fingerprint"):
        await svc.create_storage_location(
            name="New", storage_type="sftp", config={"host": "backup.test"}
        )
    svc.db.add.assert_not_called()


@pytest.mark.parametrize(
    "module",
    [
        "paramiko",
        "boto3",
        "botocore",
        "google.oauth2.service_account",
        "googleapiclient.discovery",
        "dropbox",
        "croniter",
    ],
)
def test_supported_backup_runtime_dependencies_are_installed(module):
    import importlib

    importlib.import_module(module)
