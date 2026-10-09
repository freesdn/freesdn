# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real SSH authentication and SFTP transfer against an isolated in-process peer."""

from __future__ import annotations

import contextlib
import os
import socket
import threading
from types import SimpleNamespace

import paramiko
import pytest

from app.services.backup import SFTPStorageBackend
from app.services.backup_transport import StorageConfigurationError


@pytest.fixture
def sftp_peer(tmp_path, monkeypatch):
    host_key = paramiko.RSAKey.generate(2048)
    client_key = paramiko.RSAKey.generate(2048)
    private = tmp_path / "private.pem"
    client_key.write_private_key_file(str(private), password="fixture-passphrase")
    private.chmod(0o600)
    root = tmp_path / "remote"
    root.mkdir()
    authentications = []

    class Auth(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            authentications.append("password")
            return (
                paramiko.AUTH_SUCCESSFUL
                if (username, password) == ("test", "fixture-password")
                else paramiko.AUTH_FAILED
            )

        def check_auth_publickey(self, username, key):
            authentications.append("key")
            return (
                paramiko.AUTH_SUCCESSFUL
                if username == "test" and key == client_key
                else paramiko.AUTH_FAILED
            )

        def get_allowed_auths(self, _username):
            return "password,publickey"

        def check_channel_request(self, kind, _channel_id):
            return (
                paramiko.OPEN_SUCCEEDED
                if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            )

    class Files(paramiko.SFTPServerInterface):
        def local(self, path):
            resolved = (root / path.lstrip("/")).resolve()
            assert resolved.is_relative_to(root)
            return resolved

        def stat(self, path):
            try:
                return paramiko.SFTPAttributes.from_stat(self.local(path).stat())
            except OSError as exc:
                return paramiko.SFTPServer.convert_errno(exc.errno)

        def mkdir(self, path, _attr):
            self.local(path).mkdir()
            return paramiko.SFTP_OK

        def open(self, path, flags, _attr):
            try:
                fd = os.open(self.local(path), flags, 0o600)
            except OSError as exc:
                return paramiko.SFTPServer.convert_errno(exc.errno)
            handle = paramiko.SFTPHandle(flags)
            if flags & os.O_WRONLY:
                handle.writefile = os.fdopen(fd, "wb")
            else:
                handle.readfile = os.fdopen(fd, "rb")
            return handle

        def remove(self, path):
            self.local(path).unlink()
            return paramiko.SFTP_OK

        def rename(self, oldpath, newpath):
            self.local(oldpath).rename(self.local(newpath))
            return paramiko.SFTP_OK

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.1)
    stop = threading.Event()
    transports = []
    errors = []

    def serve():
        while not stop.is_set():
            try:
                sock, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            transport = paramiko.Transport(sock)
            transports.append(transport)
            transport.add_server_key(host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, Files)
            try:
                transport.start_server(server=Auth())
            except (EOFError, ConnectionResetError, paramiko.SSHException):
                pass  # Rejecting an untrusted host can close SSH before handshake acknowledgement.
            except Exception as exc:
                errors.append(type(exc).__name__)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    monkeypatch.setattr("app.services.backup.resolve_and_pin_host", lambda *_a, **_kw: "127.0.0.1")
    # Test the real encrypted-key loader without using any host private key.
    monkeypatch.setattr("app.services.backup._validate_private_key_path", lambda path: path)
    yield SimpleNamespace(
        config={
            "host": "backup.test",
            "port": listener.getsockname()[1],
            "username": "test",
            "password": "fixture-password",
            "host_key_sha256": host_key.fingerprint,
        },
        private=private,
        root=root,
        authentications=authentications,
    )
    stop.set()
    listener.close()
    thread.join(5)
    for transport in transports:
        with contextlib.suppress(Exception):
            transport.close()
    assert not thread.is_alive() and not errors


@pytest.mark.parametrize("key_auth", [False, True])
async def test_real_sftp_round_trip_and_encrypted_key(sftp_peer, key_auth):
    config = dict(sftp_peer.config)
    if key_auth:
        config.update(private_key_path=str(sftp_peer.private), password="fixture-passphrase")
    backend = SFTPStorageBackend(config)
    data = b"vault-content\x00\xff" * 100
    path = await backend.save("test", data, "backup.fsdn")
    assert await backend.exists(path)
    assert await backend.get_size(path) == len(data)
    assert await backend.load(path) == data
    assert await backend.delete(path)
    assert await backend.exists(path) is False
    assert not list(sftp_peer.root.rglob("*.partial-*"))
    assert set(sftp_peer.authentications) == {"key" if key_auth else "password"}


async def test_real_ssh_wrong_host_key_sends_no_credentials(sftp_peer):
    backend = SFTPStorageBackend({**sftp_peer.config, "host_key_sha256": "SHA256:" + "A" * 43})
    with pytest.raises(StorageConfigurationError, match="No credentials were sent"):
        await backend.load("/backups/file")
    assert not sftp_peer.authentications


async def test_real_sftp_size_bound(sftp_peer, monkeypatch):
    folder = sftp_peer.root / "backups"
    folder.mkdir()
    (folder / "file").write_bytes(b"x" * 11)
    monkeypatch.setattr("app.services.backup.MAX_BACKUP_IMPORT_BYTES", 10)
    with pytest.raises(StorageConfigurationError, match="size limit"):
        await SFTPStorageBackend(sftp_peer.config).load("/backups/file")
