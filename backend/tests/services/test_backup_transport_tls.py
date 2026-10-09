# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real explicit FTPS sockets, control/data certificate checks and pinned routing."""

from __future__ import annotations

import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services.backup import FTPStorageBackend
from app.services.backup_transport import StorageConfigurationError


class TLSPeer:
    def __init__(self, cert, key):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.files = {}
        self.authenticated = 0
        self.protected_transfers = 0
        self.stopped = threading.Event()
        self.errors = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                self.handle(connection)
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                pass  # Clients intentionally reject invalid TLS or oversized transfers.
            except Exception as exc:
                self.errors.append(type(exc).__name__)
            finally:
                connection.close()

    def handle(self, connection):
        connection.settimeout(5)
        stream = connection.makefile("rb")
        listener = None
        rename_from = None
        protected = False
        connection.sendall(b"220 Test FTPS\r\n")
        try:
            while line := stream.readline():
                command, _, argument = line.decode().rstrip("\r\n").partition(" ")
                if command == "AUTH":
                    connection.sendall(b"234 TLS\r\n")
                    stream.close()
                    connection = self.context.wrap_socket(connection, server_side=True)
                    stream = connection.makefile("rb")
                    continue
                assert isinstance(connection, ssl.SSLSocket), "Authentication without TLS"
                response = b"200 OK\r\n"
                if command == "PROT":
                    assert argument == "P"
                    protected = True
                elif command == "USER":
                    response = b"331 Password\r\n"
                elif command == "PASS":
                    self.authenticated += 1
                    response = b"230 Logged in\r\n"
                elif command == "PASV":
                    listener = socket.socket()
                    listener.bind(("127.0.0.1", 0))
                    listener.listen()
                    listener.settimeout(5)
                    port = listener.getsockname()[1]
                    # Ignore a malicious PASV host and use the control peer address.
                    response = f"227 Passive (10,0,0,99,{port // 256},{port % 256})\r\n".encode()
                elif command in {"STOR", "RETR"}:
                    assert listener is not None and protected
                    connection.sendall(b"150 Data\r\n")
                    data_socket, _ = listener.accept()
                    listener.close()
                    listener = None
                    with self.context.wrap_socket(data_socket, server_side=True) as channel:
                        channel.settimeout(5)
                        self.protected_transfers += 1
                        if command == "STOR":
                            chunks = []
                            while chunk := channel.recv(8192):
                                chunks.append(chunk)
                            self.files[argument] = b"".join(chunks)
                        else:
                            channel.sendall(self.files[argument])
                        channel.unwrap().close()
                    response = b"226 Transferred\r\n"
                elif command == "RNFR":
                    rename_from = argument
                    response = b"350 Rename\r\n"
                elif command == "RNTO":
                    self.files[argument] = self.files.pop(rename_from)
                    response = b"250 Renamed\r\n"
                elif command == "SIZE":
                    response = f"213 {len(self.files[argument])}\r\n".encode()
                elif command == "DELE":
                    self.files.pop(argument)
                    response = b"250 Deleted\r\n"
                elif command == "CWD":
                    response = b"250 Directory\r\n"
                connection.sendall(response)
        finally:
            stream.close()
            connection.close()
            if listener is not None:
                listener.close()

    def close(self):
        self.stopped.set()
        self.socket.close()
        self.thread.join(6)
        assert not self.thread.is_alive()
        assert self.errors == []


@pytest.fixture
def ftps_peer(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "backup.test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("backup.test")]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, True, True, None, None), critical=True
        )
        .sign(key, hashes.SHA256())
    )
    certificate = tmp_path / "ca.pem"
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile = tmp_path / "key.pem"
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    keyfile.chmod(0o600)
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    monkeypatch.setattr("app.services.backup.resolve_and_pin_host", lambda *_a, **_kw: "127.0.0.1")
    peer = TLSPeer(certificate, keyfile)
    yield peer
    peer.close()


async def test_real_ftps_round_trip_and_legacy_url(ftps_peer):
    backend = FTPStorageBackend(
        {
            "host": "backup.test",
            "port": ftps_peer.port,
            "use_tls": "true",
            "username": "test",
            "password": "test-only",
        }
    )
    payload = b"encrypted-backup-payload\x00\xff" * 1000
    path = await backend.save("backup-id", payload, "backup.fsdn")
    assert path.startswith("ftps://127.0.0.1:")
    assert len(ftps_peer.files) == 1 and ".partial-" not in next(iter(ftps_peer.files))
    assert await backend.exists(path)
    assert await backend.get_size(path) == len(payload)
    assert await backend.load(path.replace("ftps://", "ftp://")) == payload
    assert await backend.delete(path)
    assert not ftps_peer.files
    assert ftps_peer.protected_transfers == 2


@pytest.mark.parametrize("wrong_host", [False, True])
async def test_real_ftps_rejects_untrusted_or_wrong_hostname_before_credentials(
    ftps_peer, monkeypatch, wrong_host
):
    if not wrong_host:
        monkeypatch.delenv("SSL_CERT_FILE")
    backend = FTPStorageBackend(
        {
            "host": "wrong.test" if wrong_host else "backup.test",
            "port": ftps_peer.port,
            "use_tls": True,
        }
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        await backend.load("/backups/file")
    assert ftps_peer.authenticated == 0


async def test_ftps_download_bound_enforced(ftps_peer, monkeypatch):
    monkeypatch.setattr("app.services.backup.MAX_BACKUP_IMPORT_BYTES", 10)
    ftps_peer.files["/backups/file"] = b"x" * 20
    backend = FTPStorageBackend({"host": "backup.test", "port": ftps_peer.port, "use_tls": True})
    with pytest.raises(StorageConfigurationError, match="size limit"):
        await backend.load("/backups/file")
