# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned loopback HTTP/TLS peer; the production SSRF admission is a test boundary."""

import base64
import gzip
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote, urlsplit
from xml.sax.saxutils import escape

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HOST = "backup.webdav.test"
USERNAME = "owned-webdav-user"
PASSWORD = "owned-webdav-synthetic-password"


class WebDAVPeer:
    def __init__(self, certificate, keyfile):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate, keyfile)
        self.sni = []
        self.context.set_servername_callback(lambda _socket, name, _context: self.sni.append(name))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.files = {}
        self.requests = []
        self.errors = []
        self.override = {}
        self.chunked = False
        self.compress = False
        self.stopped = threading.Event()
        self._lock = threading.RLock()
        self._connections = set()
        self._workers = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def config(self, hostname=HOST):
        return {"url": f"https://{hostname}:{self.port}/dav", "path": "/backups",
                "username": USERNAME, "password": PASSWORD}

    def locator(self, path="/dav/backups/owned.fsdn"):
        return f"webdav://127.0.0.1:{self.port}{path}"

    @staticmethod
    def metadata(href, size, *, status="HTTP/1.1 200 OK", collection=False):
        resource_type = "<d:collection/>" if collection else ""
        return (f'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
                f'<d:href>{escape(href)}</d:href><d:propstat><d:prop>'
                f'<d:getcontentlength>{escape(str(size))}</d:getcontentlength>'
                f'<d:resourcetype>{resource_type}</d:resourcetype></d:prop>'
                f'<d:status>{escape(status)}</d:status></d:propstat>'
                '</d:response></d:multistatus>').encode()

    def _serve(self):
        while not self.stopped.is_set():
            try:
                connection, _address = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with self._lock:
                self._connections.add(connection)
            worker = threading.Thread(target=self._handle, args=(connection,), daemon=True)
            self._workers.append(worker)
            worker.start()

    def _handle(self, raw):
        connection = raw
        stream = None
        try:
            raw.settimeout(5)
            connection = self.context.wrap_socket(raw, server_side=True)
            with self._lock:
                self._connections.discard(raw)
                self._connections.add(connection)
            stream = connection.makefile("rb")
            while not self.stopped.is_set():
                line = stream.readline(8193)
                if not line:
                    break
                assert len(line) <= 8192, "Owned peer request-line limit"
                method, target, version = line.decode("ascii").strip().split(" ")
                assert version == "HTTP/1.1"
                headers = {}
                total = 0
                while field := stream.readline(8193):
                    total += len(field)
                    assert total < 32768, "Owned peer header limit"
                    if field == b"\r\n":
                        break
                    key, value = field.decode("latin-1").split(":", 1)
                    headers[key.lower()] = value.strip()
                count = int(headers.get("content-length", "0"))
                assert 0 <= count <= 2 * 1024**2, "Owned peer upload limit"
                payload = stream.read(count)
                assert len(payload) == count
                expected = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
                path = unquote(urlsplit(target).path)
                self.requests.append({"method": method, "target": target, "Host": headers.get("host"),
                                      "authorized": headers.get("authorization") == expected,
                                      "Depth": headers.get("depth"), "body_bytes": len(payload),
                                      "TLS": isinstance(connection, ssl.SSLSocket)})
                extra = {}
                if headers.get("authorization") != expected:
                    code, body = 401, b""
                elif method in self.override:
                    code, body, extra = self.override[method]
                elif method == "MKCOL":
                    code, body = 201, b""
                elif method == "PUT":
                    self.files[path] = payload
                    code, body = 201, b""
                elif method == "GET":
                    code, body = (200, self.files[path]) if path in self.files else (404, b"")
                elif method == "DELETE":
                    code, body = (204, b"") if path in self.files else (404, b"")
                    self.files.pop(path, None)
                elif method == "PROPFIND":
                    code, body = (207, self.metadata(target, len(self.files[path]))) if path in self.files else (404, b"")
                    extra = {"Content-Type": "application/xml; charset=utf-8"}
                else:
                    code, body = 405, b""
                if self.compress and method == "GET" and code == 200:
                    body = gzip.compress(body)
                    extra = {**extra, "Content-Encoding": "gzip"}
                chunked = self.chunked and method == "GET" and code == 200
                framing = {"Transfer-Encoding": "chunked"} if chunked else {"Content-Length": str(len(body))}
                response_headers = {**framing, "Connection": "keep-alive", **extra}
                wire = f"HTTP/1.1 {code} Owned\r\n" + "".join(f"{k}: {v}\r\n" for k, v in response_headers.items()) + "\r\n"
                connection.sendall(wire.encode("ascii"))
                if chunked:
                    for offset in range(0, len(body), 128):
                        part = body[offset:offset + 128]
                        connection.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                    connection.sendall(b"0\r\n\r\n")
                else:
                    connection.sendall(body)
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, TimeoutError):
            pass  # Invalid certificates and deliberate early read refusals are controls.
        except OSError as error:
            if not self.stopped.is_set():
                self.errors.append(type(error).__name__)
        except Exception as error:
            self.errors.append(type(error).__name__)
        finally:
            if stream is not None:
                stream.close()
            connection.close()
            raw.close()
            with self._lock:
                self._connections.discard(connection)
                self._connections.discard(raw)

    def close(self):
        self.stopped.set()
        self.socket.close()
        self.thread.join(2)
        with self._lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for worker in self._workers:
            worker.join(2)
        assert not self.thread.is_alive() and all(not worker.is_alive() for worker in self._workers)
        assert not self._connections and not self.errors, "Owned peer cleanup or protocol error"
        self.context.set_servername_callback(None)


@pytest.fixture
def webdav_peer(tmp_path, monkeypatch, request):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned WebDAV CA")])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.now(UTC)
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, None, None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, None, None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path, certificate, keyfile = (tmp_path / name for name in ("owned-ca.pem", "owned-peer.pem", "owned-key.pem"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    keyfile.chmod(0o600)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)

    def owned_pin(host, *, allow_private=False):
        assert host in {HOST, "wrong.webdav.test"} and allow_private is False
        return "127.0.0.1"

    # Explicit protocol boundary: production URL parsing and HTTPX/TLS remain,
    # but destination admission is replaced solely for this owned loopback peer.
    monkeypatch.setattr("app.services.backup.resolve_and_pin_host", owned_pin)

    async def owned_native_pin(host, *, allow_private=False):
        # The same explicit loopback protocol boundary applies to the separate
        # bounded vault constructor. This fixture does not qualify real DNS.
        return owned_pin(host, allow_private=allow_private)

    monkeypatch.setattr("app.services.vault_native_resolution.resolve_storage_host", owned_native_pin)
    peer = WebDAVPeer(certificate, keyfile)
    try:
        yield peer
    finally:
        peer.close()
        request.node.user_properties.extend({
            "owned_peer_cleanup_complete": True,
            "owned_peer_workers": len(peer._workers),
            "owned_peer_connections_remaining": len(peer._connections),
        }.items())
