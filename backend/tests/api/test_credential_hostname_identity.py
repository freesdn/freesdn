"""Preserve requested hostname identity while connecting to a pinned private IP.

System hostname resolution, PostgreSQL and owned TLS/HTTP listeners are real.
The isolated local runner binds its own hosts file inside a mount namespace;
container qualification uses Docker's existing hostname mapping.
"""

import base64
import ipaddress
import socket
import socketserver
import ssl
import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from httpx import ASGITransport, AsyncClient

from tests.api.test_credential_default_scope import credential_rows
from tests.api.test_credential_http_outcomes import make_outcome_fixture, outcome_cases
from tests.api.test_credential_proxy_isolation import ENV_KEYS, owned_bind_address


def hostname_cases():
    cases = []
    for status in [200, 401, 503]:
        for mode in ["dns", "tls-optout", "plain-fallback", "ip-control"]:
            cases.append({"label": f"{mode}-{status}", "mode": mode, "target_status": status})
    for mode in [
        "ip-only-hostname",
        "wrong-name",
        "untrusted",
        "plain-no-fallback",
        "https-error-no-fallback",
        "redirect-not-followed",
    ]:
        cases.append({"label": mode, "mode": mode})
    for case in outcome_cases():
        if case["status"] != 200:
            cases.append({**case, "label": "denied-" + case["label"], "mode": "dns"})
    assert len(cases) == 28
    return cases


def hostname_certificates(folder, host, hostname, mode):
    now = datetime.now(UTC)

    def authority(name):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, True, True, None, None),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        return key, cert

    ca_key, ca = authority("Owned hostname identity CA")
    _, unrelated = authority("Owned unrelated hostname CA")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san = (
        x509.IPAddress(ipaddress.ip_address(host))
        if mode in {"ip-control", "ip-only-hostname"}
        else x509.DNSName("wrong.invalid" if mode == "wrong-name" else hostname)
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned TLS target")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, None, None), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    for name, data in [
        ("ca.pem", ca.public_bytes(serialization.Encoding.PEM)),
        ("unrelated.pem", unrelated.public_bytes(serialization.Encoding.PEM)),
        ("server.pem", cert.public_bytes(serialization.Encoding.PEM)),
        (
            "server.key",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        ),
    ]:
        path = folder / name
        path.write_bytes(data)
        path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(folder / "server.pem"), str(folder / "server.key"))
    return context


class HostnamePeer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host, hostname, context, case):
        super().__init__((host, 0), HostnameHandler)
        self.host, self.hostname, self.context, self.case = host, hostname, context, case
        self.requests, self.errors, self.snis = [], [], []
        self.tls_attempts = 0

        def capture_sni(connection, name, _context):
            self.snis.append(name)
            connection.owned_server_name = name

        context.set_servername_callback(capture_sni)
        self.worker = threading.Thread(
            target=self.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.worker.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.worker.join(5)
        assert not self.worker.is_alive()
        assert not self.errors


class HostnameHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw = connection = self.request
        raw.settimeout(5)
        try:
            first = raw.recv(1, socket.MSG_PEEK)
            if not first:
                return
            tls = first == b"\x16"
            mode = self.server.case["mode"]
            if tls:
                self.server.tls_attempts += 1
                if mode in {"plain-fallback", "plain-no-fallback"}:
                    return
                try:
                    connection = self.server.context.wrap_socket(raw, server_side=True)
                except ssl.SSLError:
                    return
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = connection.recv(4096)
                assert chunk
                data += chunk
                assert len(data) <= 16384
            lines = data.split(b"\r\n")
            assert lines[0] == b"GET / HTTP/1.1"
            headers = {
                line.split(b":", 1)[0].lower(): line.split(b":", 1)[1].strip()
                for line in lines[1:]
                if b":" in line
            }
            assert headers.get(b"authorization") == b"Basic " + base64.b64encode(
                b"owned-http-user:owned-credential-default-secret"
            )
            expected_host = (
                (self.server.host if mode == "ip-control" else self.server.hostname)
                + ":"
                + str(self.server.server_address[1])
            )
            correct_host = headers.get(b"host") == expected_host.encode()
            correct_sni = getattr(connection, "owned_server_name", None) == self.server.hostname
            expected_status = self.server.case.get("target_status", 200)
            if mode == "https-error-no-fallback":
                expected_status = 503
            elif mode == "redirect-not-followed":
                expected_status = 302
            # The IP-only certificate case isolates the identity check from
            # virtual-host routing: the old implementation accepts this cert.
            route_ok = mode == "ip-only-hostname" or (
                correct_host and (not tls or mode == "ip-control" or correct_sni)
            )
            status = expected_status if route_ok else 404
            self.server.requests.append(
                {
                    "tls": tls,
                    "correct_host": correct_host,
                    "correct_sni": correct_sni if tls else None,
                    "status": status,
                    "synthetic_auth_received": True,
                }
            )
            location = b"Location: https://127.0.0.1:1/never-follow\r\n" if status == 302 else b""
            connection.sendall(
                f"HTTP/1.1 {status} Owned\r\nContent-Length: 0\r\n".encode()
                + location
                + b"Connection: close\r\n\r\n"
            )
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
            return
        except Exception as error:
            self.server.errors.append(type(error).__name__)
        finally:
            if connection is not raw:
                connection.close()


async def make_hostname_fixture(db, case, folder, setenv, delenv):
    for key in ENV_KEYS:
        delenv(key, raising=False)
    host, hostname = owned_bind_address(), socket.gethostname().lower()
    resolved = {row[4][0] for row in socket.getaddrinfo(hostname, None, socket.AF_INET)}
    assert resolved == {host}, "Use only the owned system hostname mapping"
    context = hostname_certificates(folder, host, hostname, case["mode"])
    setenv(
        "SSL_CERT_FILE",
        str(folder / ("unrelated.pem" if case["mode"] == "untrusted" else "ca.pem")),
    )
    peer = HostnamePeer(host, hostname, context, case)
    try:
        f = await make_outcome_fixture(db, {"status": 200, **case})
        f.hostname_case, f.peer = case, peer
        f.payload.update(
            target_ip=case.get("target", host if case["mode"] == "ip-control" else hostname),
            port=peer.server_address[1],
            verify_ssl=case["mode"] != "tls-optout",
            allow_plaintext_http=case["mode"] in {"plain-fallback", "https-error-no-fallback"},
        )
        return f
    except BaseException:
        peer.close()
        raise


async def inspect_hostname_response(f, response, *, before=False):
    case = f.hostname_case
    expected_status = case.get("status", 200)
    assert response.status_code == expected_status, response.text
    actual = await credential_rows(f.db, f.ids)
    for key, row in actual.items():
        omit = (
            {"last_used", "last_test_result", "updated_at"}
            if expected_status == 200 and key == f.target_id
            else set()
        )
        assert {k: v for k, v in row.items() if k not in omit} == {
            k: v for k, v in f.before[key].items() if k not in omit
        }
    if expected_status != 200:
        assert not f.peer.requests and f.peer.tls_attempts == 0
        return {
            "status": expected_status,
            "requests": [],
            "existing_credential_rows_checked": len(actual),
        }
    mode = case["mode"]
    rejected = mode in {"wrong-name", "untrusted", "plain-no-fallback"}
    rejected |= mode == "ip-only-hostname" and not before
    rejected |= before and mode in {"dns", "redirect-not-followed"}
    result_status = case.get("target_status", 200)
    if mode == "https-error-no-fallback":
        result_status = 503
    elif mode == "redirect-not-followed":
        result_status = 302
    if before and mode in {"tls-optout", "plain-fallback", "https-error-no-fallback"}:
        result_status = 404
    expected_success = not rejected and 200 <= result_status < 300
    body = response.json()
    assert body["success"] is expected_success
    assert actual[f.target_id]["last_test_result"] == (
        "reachable" if expected_success else "failed"
    )
    assert f.peer.tls_attempts == 1
    assert len(f.peer.requests) == (0 if rejected else 1)
    if not rejected:
        assert body["device_info"]["status_code"] == result_status
        assert body["device_info"]["authentication_verified"] is False
        row = f.peer.requests[0]
        assert row["tls"] is not (
            mode == "plain-fallback" or before and mode == "https-error-no-fallback"
        )
        if not before:
            assert row["correct_host"]
            if row["tls"]:
                assert row["correct_sni"] is (mode != "ip-control")
    assert "owned-credential-default-secret" not in response.text
    return {
        "status": expected_status,
        "success": body["success"],
        "requests": f.peer.requests,
        "TLS_attempts": f.peer.tls_attempts,
        "existing_credential_rows_checked": len(actual),
    }


@pytest.mark.parametrize("case", hostname_cases(), ids=lambda c: c["label"])
async def test_credential_check_preserves_hostname_identity(
    db_session, monkeypatch, tmp_path, case
):
    f = await make_hostname_fixture(
        db_session, case, tmp_path, monkeypatch.setenv, monkeypatch.delenv
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=f.app, raise_app_exceptions=False),
            base_url="http://owned-fixture",
            trust_env=False,
        ) as client:
            response = await client.post(f.path, json=f.payload)
        await inspect_hostname_response(f, response)
    finally:
        f.peer.close()
