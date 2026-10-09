# SPDX-License-Identifier: AGPL-3.0-only
"""Real SMTP STARTTLS, certificate rejection, refusal and lost-ACK cases."""

import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services.notification import NotificationPayload, SMTPProvider
from app.services.sla_report_mail import send_notice


class SMTPPeer:
    def __init__(self, cert, key):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.mode = "accept"
        self.refusal_text = b"Synthetic refusal"
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
            except Exception as exc:
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
                    assert isinstance(conn, ssl.SSLSocket), "Credentials or mail sent before TLS"
                    if cmd == b"AUTH":
                        self.authenticated += 1
                        conn.sendall(
                            b"535 " + self.refusal_text + b"\r\n"
                            if self.mode == "auth_reject"
                            else b"235 Authenticated\r\n"
                        )
                    elif cmd == b"RCPT" and self.mode in {"temporary", "permanent"}:
                        conn.sendall(
                            (b"450 " if self.mode == "temporary" else b"550 ")
                            + self.refusal_text
                            + b"\r\n"
                        )
                    elif cmd == b"DATA":
                        if self.mode in {"data_temporary", "data_permanent"}:
                            conn.sendall(
                                (b"451 " if self.mode == "data_temporary" else b"554 ")
                                + self.refusal_text
                                + b"\r\n"
                            )
                            continue
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


@pytest.fixture
def smtp_peer(tmp_path, monkeypatch):
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
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, True, True, None, None), critical=True
        )
        .sign(key, hashes.SHA256())
    )
    certificate, keyfile = tmp_path / "ca.pem", tmp_path / "key.pem"
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    keyfile.chmod(0o600)
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    peer = SMTPPeer(certificate, keyfile)
    yield peer
    peer.close()


def provider_for(peer, **extra):
    return SMTPProvider(
        {
            "host": "localhost",
            "port": peer.port,
            "from_email": "sender@example.test",
            "username": "synthetic",
            "password": "synthetic-test-only",
            **extra,
        }
    )


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("accept", "accepted"),
        ("close_after_ack", "accepted"),
        ("temporary", "retry"),
        ("permanent", "failed"),
        ("lost_ack", "unknown"),
    ],
)
async def test_real_smtp_acceptance_boundary(smtp_peer, mode, expected):
    smtp_peer.mode = mode
    result = await send_notice(
        provider_for(smtp_peer),
        "reader@example.test",
        "https://console.example.test/sla/reports?report=test",
        "<test@freesdn.invalid>",
    )
    assert result.state == expected
    assert smtp_peer.authenticated == 1
    if smtp_peer.messages:
        message = BytesParser(policy=policy.default).parsebytes(smtp_peer.messages[0])
        assert message["Message-ID"] == "<test@freesdn.invalid>"
        assert message["To"] == "reader@example.test"
        assert not list(message.iter_attachments())
        assert "Sign in" in message.get_content()


@pytest.mark.parametrize("operation", ["notice", "send", "verify"])
@pytest.mark.parametrize("failure", ["untrusted", "hostname"])
async def test_invalid_certificate_never_sends_credentials(
    smtp_peer, monkeypatch, operation, failure
):
    if failure == "untrusted":
        monkeypatch.delenv("SSL_CERT_FILE")
    provider = provider_for(smtp_peer, host="127.0.0.1" if failure == "hostname" else "localhost")
    if operation == "notice":
        result = await send_notice(
            provider,
            "reader@example.test",
            "https://console.example.test",
            "<test@freesdn.invalid>",
        )
        assert result.error_code == "smtp_certificate_invalid"
    elif operation == "send":
        result = await provider.send(
            "reader@example.test", NotificationPayload(title="Test", body="Test")
        )
        assert not result.success
    else:
        assert not (await provider.verify())[0]
    assert smtp_peer.authenticated == 0
    assert smtp_peer.messages == []


async def test_known_good_certificate_for_existing_provider(smtp_peer):
    provider = provider_for(smtp_peer)
    assert (await provider.verify())[0]
    assert (
        await provider.send("reader@example.test", NotificationPayload(title="Test", body="Test"))
    ).success
    assert len(smtp_peer.messages) == 1


@pytest.mark.parametrize("tls", [False, "true", "false", None])
async def test_notice_refuses_non_boolean_or_disabled_tls(smtp_peer, tls):
    result = await send_notice(
        provider_for(smtp_peer, use_tls=tls),
        "reader@example.test",
        "https://console.example.test",
        "<test@freesdn.invalid>",
    )
    assert result.error_code == "verified_tls_required"
    assert not smtp_peer.authenticated


@pytest.mark.parametrize(
    "operation,mode,transient",
    [
        ("send", "auth_reject", False),
        ("verify", "auth_reject", False),
        ("send", "temporary", True),
        ("send", "permanent", False),
        ("send", "data_temporary", True),
        ("send", "data_permanent", False),
    ],
)
async def test_real_smtp_refusals_keep_private_replies_out_of_diagnostics(
    smtp_peer, caplog, operation, mode, transient
):
    from app.tasks.notification_retry import is_transient_error

    canary = "owned-smtp-private-reply@example.test"
    smtp_peer.mode = mode
    smtp_peer.refusal_text = canary.encode()
    provider = provider_for(smtp_peer)
    if operation == "send":
        result = await provider.send(
            "reader@example.test", NotificationPayload(title="Test", body="Test")
        )
        ok, message = result.success, result.error
    else:
        ok, message = await provider.verify()
    assert not ok and message
    assert smtp_peer.authenticated == 1
    assert not smtp_peer.messages
    assert canary not in message and canary not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    assert is_transient_error(message) is transient
