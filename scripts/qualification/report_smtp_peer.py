# SPDX-License-Identifier: AGPL-3.0-only
"""Private loopback TLS SMTP peer for the isolated restore rehearsal only."""

if not __debug__:
    raise RuntimeError("Qualification must run without Python optimization")

import os
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class SMTPPeer:
    def __init__(self, cert, key, port=1587):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", port))
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.mode = "accept"
        self.messages = []
        self.authenticated = 0
        self.errors = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                self.handle(conn)
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                pass  # Expected certificate rejection.
            except (AssertionError, OSError, ValueError) as exc:
                self.errors.append(type(exc).__name__)
            finally:
                conn.close()

    def handle(self, conn):
        conn.settimeout(5)
        stream = conn.makefile("rb")
        conn.sendall(b"220 Test SMTP\r\n")
        try:
            while line := stream.readline():
                cmd = line.split(b" ", 1)[0].strip().upper()
                if cmd == b"EHLO":
                    conn.sendall(b"250-test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
                elif cmd == b"STARTTLS":
                    conn.sendall(b"220 Begin TLS\r\n")
                    stream.close()
                    conn = self.context.wrap_socket(conn, server_side=True)
                    stream = conn.makefile("rb")
                elif cmd == b"QUIT":
                    # Outbox sender does not rely on QUIT for acceptance.
                    conn.sendall(b"221 Bye\r\n")
                    return
                else:
                    assert isinstance(conn, ssl.SSLSocket), (
                        "Credentials or mail sent before TLS"
                    )
                    if cmd == b"AUTH":
                        self.authenticated += 1
                        conn.sendall(b"235 Authenticated\r\n")
                    elif cmd == b"RCPT" and self.mode in {"temporary", "permanent"}:
                        conn.sendall(
                            b"450 Retry later\r\n"
                            if self.mode == "temporary"
                            else b"550 No recipient\r\n"
                        )
                    elif cmd == b"DATA":
                        conn.sendall(b"354 Continue\r\n")
                        data = bytearray()
                        while (line := stream.readline()) != b".\r\n":
                            if not line:
                                return
                            data.extend(line)
                        self.messages.append(bytes(data))
                        if self.mode == "lost_ack":
                            return
                        conn.sendall(b"250 Queued\r\n")
                        if self.mode == "close_after_ack":
                            return
                    else:
                        conn.sendall(b"250 OK\r\n")
        finally:
            stream.close()
            conn.close()

    def close(self):
        self.stopped.set()
        self.socket.close()
        self.thread.join(6)
        assert not self.thread.is_alive()
        assert not self.errors


def start_peer(directory: Path) -> SMTPPeer:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
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
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, True, True, None, None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    certificate, keyfile = directory / "ca.pem", directory / "key.pem"
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    keyfile.chmod(0o600)
    os.environ["SSL_CERT_FILE"] = str(certificate)
    return SMTPPeer(certificate, keyfile)
