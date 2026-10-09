"""Owned TLS, RFC6455 and HTTPS peer; no appliance or external identity provider."""

import base64
import gzip
import hashlib
import json
import socket
import ssl
import struct
import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HOST = "owned.truenas.test"
USERNAME = "owned-appliance-user"
API_KEY = "owned-appliance-synthetic-key"


class TrueNASPeer:
    def __init__(self, certificate, keyfile):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate, keyfile)
        self.sni = []
        self.context.set_servername_callback(lambda _sock, name, _ctx: self.sni.append(name))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.mode = "normal"
        self.body = b"owned encrypted-shaped archive; protocol-only fixture\n" * 2048
        self.requests, self.calls, self.errors = [], [], []
        self.stopped, self.blocked, self.release = threading.Event(), threading.Event(), threading.Event()
        self._lock = threading.RLock()
        self._connections, self._workers = set(), []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with self._lock:
                self._connections.add(connection)
            worker = threading.Thread(target=self._handle, args=(connection,), daemon=True)
            self._workers.append(worker)
            worker.start()

    def _pause(self):
        self.blocked.set()
        while not self.stopped.is_set() and not self.release.wait(.05):
            pass

    @staticmethod
    def _exact(stream, count):
        value = stream.read(count)
        if len(value) != count:
            raise EOFError
        return value

    @staticmethod
    def _send_frame(connection, value, opcode=1):
        if isinstance(value, dict):
            value = json.dumps(value).encode()
        count = len(value)
        size = bytes([count]) if count < 126 else b"\x7e" + struct.pack("!H", count) if count < 65536 else b"\x7f" + struct.pack("!Q", count)
        connection.sendall(bytes([0x80 | opcode]) + size + value)

    def _websocket(self, connection, stream, headers):
        if self.mode == "ws_redirect":
            connection.sendall(b"HTTP/1.1 302 Found\r\nLocation: wss://external.invalid/api/current\r\nContent-Length: 0\r\n\r\n")
            return
        # SHA-1 is mandatory RFC6455 handshake syntax, not a security digest.
        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(), usedforsecurity=False).digest())
        connection.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        while not self.stopped.is_set():
            head = self._exact(stream, 2)
            assert head[0] & 0x80 and head[1] & 0x80
            opcode, count = head[0] & 15, head[1] & 127
            if count == 126:
                count = struct.unpack("!H", self._exact(stream, 2))[0]
            elif count == 127:
                count = struct.unpack("!Q", self._exact(stream, 8))[0]
            assert count <= 65536
            mask = self._exact(stream, 4)
            payload = self._exact(stream, count)
            payload = bytes(v ^ mask[i % 4] for i, v in enumerate(payload))
            if opcode == 8:
                self._send_frame(connection, payload, 8)
                return
            assert opcode == 1
            call = json.loads(payload)
            assert call["jsonrpc"] == "2.0" and type(call["id"]) is int
            method, args = call["method"], call["params"]
            self.calls.append({"method": method, "params": args})
            if self.mode == "slow_control" and method == "auth.login_ex":
                self._pause()
            if method == "auth.login_ex":
                expected = {"mechanism": "API_KEY_PLAIN", "username": USERNAME, "api_key": API_KEY}
                result = {"response_type": "SUCCESS" if args == [expected] and self.mode != "auth_refused" else "AUTH_ERR"}
            elif method == "core.download":
                assert args == ["filesystem.get", ["/mnt/tank/backups/owned-id/2026/archive.fsdnvault"], "archive.fsdnvault"]
                result = [42, "/_download/42?auth_token=owned-one-shot"]
                if self.mode in {"foreign_url", "backslash_url", "fragment_url"}:
                    result[1] = {"foreign_url": "https://external.invalid/_download/42", "backslash_url": "/_download/42\\outside", "fragment_url": "/_download/42#secret"}[self.mode]
                elif self.mode == "bad_job":
                    result[0] = True
            elif method == "core.job_abort":
                assert args == [42]
                result = None
            else:
                raise AssertionError("Unplanned appliance method")
            reply = {"jsonrpc": "2.0", "id": call["id"], "result": result}
            if method == "auth.login_ex":
                if self.mode == "event_flood":
                    for _ in range(40):
                        self._send_frame(connection, {"jsonrpc": "2.0", "method": "owned.event"})
                    continue
                if self.mode == "oversized_control":
                    self._send_frame(connection, b"x" * 70000)
                    continue
                if self.mode == "binary_control":
                    self._send_frame(connection, json.dumps(reply).encode(), 2)
                    continue
                if self.mode == "duplicate_control":
                    self._send_frame(connection, b'{"jsonrpc":"2.0","id":1,"id":1,"result":{"response_type":"SUCCESS"}}')
                    continue
            self._send_frame(connection, reply)

    def _download(self, connection):
        if self.mode == "slow_body":
            self._pause()
        if self.mode == "http_redirect":
            connection.sendall(b"HTTP/1.1 302 Found\r\nLocation: https://external.invalid/file\r\nContent-Length: 0\r\n\r\n")
            return
        body, extra = self.body, b""
        if self.mode in {"gzip", "gzip_bomb", "gzip_truncated", "gzip_trailing"}:
            body = gzip.compress(body)
            extra = b"Content-Encoding: gzip\r\n"
            if self.mode == "gzip_truncated":
                body = body[:-8]
            elif self.mode == "gzip_trailing":
                body += b"trailing-data"
        if self.mode == "unknown_encoding":
            extra = b"Content-Encoding: unknown\r\n"
        if self.mode == "huge_headers":
            extra = b"X-Large: " + b"h" * 33000 + b"\r\nX-Other: " + b"h" * 33000 + b"\r\n"
        if self.mode == "chunked":
            connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
            for n in range(0, len(body), 1024):
                part = body[n:n + 1024]
                connection.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            connection.sendall(b"0\r\n\r\n")
            return
        length = len(body) + 10 if self.mode == "truncated" else len(body)
        framing = b"Content-Length: " + str(length).encode() + b"\r\n"
        if self.mode == "duplicate_length":
            framing += framing
        elif self.mode == "ambiguous_transfer":
            framing += b"Transfer-Encoding: chunked\r\n"
        connection.sendall(b"HTTP/1.1 200 OK\r\n" + framing + extra + b"Connection: close\r\n\r\n" + body)

    def _handle(self, raw):
        connection, stream = raw, None
        try:
            raw.settimeout(10)
            connection = self.context.wrap_socket(raw, server_side=True)
            with self._lock:
                self._connections.discard(raw)
                self._connections.add(connection)
            stream = connection.makefile("rb")
            line = stream.readline(8193)
            if not line:
                return
            assert len(line) <= 8192
            method, target, version = line.decode("ascii").strip().split(" ")
            assert method == "GET" and version == "HTTP/1.1"
            headers, total = {}, 0
            while field := stream.readline(8193):
                total += len(field)
                assert total <= 32768
                if field == b"\r\n":
                    break
                name, value = field.decode("latin-1").split(":", 1)
                headers[name.lower()] = value.strip()
            self.requests.append({"target": target, "headers": headers, "tls": True})
            if target == "/api/current":
                self._websocket(connection, stream, headers)
            else:
                assert target == "/_download/42?auth_token=owned-one-shot"
                self._download(connection)
        except (EOFError, ssl.SSLError, ConnectionResetError, BrokenPipeError, TimeoutError):
            pass
        except OSError as error:
            if not self.stopped.is_set():
                self.errors.append(type(error).__name__)
        except Exception as error:
            self.errors.append(type(error).__name__ + ":" + str(error))
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
        self.release.set()
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
        assert not self.thread.is_alive() and all(not w.is_alive() for w in self._workers)
        assert not self._connections and not self.errors
        self.context.set_servername_callback(None)


@pytest.fixture
def truenas_peer(tmp_path, monkeypatch, request):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned TrueNAS CA")])
    now = datetime.now(UTC)
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, None, None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .issuer_name(issuer).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path, certificate, keyfile = (tmp_path / n for n in ("owned-ca.pem", "owned-peer.pem", "owned-key.pem"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    keyfile.chmod(0o600)
    monkeypatch.setenv("FREESDN_DEVICE_CA_BUNDLE", str(ca_path))
    peer = TrueNASPeer(certificate, keyfile)
    peer.ca_path = ca_path
    try:
        yield peer
    finally:
        peer.close()
        request.node.user_properties.extend({"truenas_owned_peer_cleanup": True,
            "truenas_peer_connections_remaining": len(peer._connections),
            "truenas_peer_workers": len(peer._workers)}.items())
