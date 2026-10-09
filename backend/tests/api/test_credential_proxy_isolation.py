"""Stored-secret probes ignore ambient proxies while preserving CA configuration.

PostgreSQL, incoming API and outgoing HTTP/TLS are real. Peers use only owned
listeners and synthetic secrets. No HTTPX/DNS/security helper is replaced.
"""

import base64
import ipaddress
import os
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

PROXY_KEYS = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
ENV_KEYS = [
    *PROXY_KEYS,
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
]


def proxy_cases():
    cases = []
    for proxy in PROXY_KEYS:
        for trust in ["file", "directory", "opt-out", "untrusted", "none"]:
            cases.append({"label": f"{proxy}-{trust}", "proxy": proxy, "trust": trust})
        cases.append({"label": f"{proxy}-no-proxy-control", "proxy": proxy, "no_proxy": True})
    for proxy in ["HTTP_PROXY", "http_proxy"]:
        cases.append({"label": f"{proxy}-plaintext", "proxy": proxy, "plain": True})
        cases.append({"label": f"{proxy}-HTTPS-control", "proxy": proxy})
    for case in outcome_cases():
        if case["status"] != 200:
            cases.append({**case, "label": "denied-" + case["label"], "proxy": "HTTPS_PROXY"})
    assert len(cases) == 38
    return cases


def owned_bind_address():
    host = os.environ.get("QUALIFICATION_TARGET_IP") or socket.gethostbyname(socket.gethostname())
    address = ipaddress.ip_address(host)
    assert address.is_private and not (
        address.is_loopback or address.is_link_local or address.is_unspecified
    ), "Use an owned private interface; the isolated runner sets QUALIFICATION_TARGET_IP."
    return host


def proxy_certificates(folder, host):
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

    ca_key, ca = authority("Owned HTTP outcome fixture CA")
    _, unrelated = authority("Owned unrelated CA")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned proxy target")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))]),
            critical=False,
        )
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
    directory = folder / "ca-directory"
    directory.mkdir()
    # OpenSSL subject_hash of the fixed CA distinguished name above. Only the
    # subject is fixed: each test generates a new key and certificate in tmp_path.
    (directory / "dcc9740d.0").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(folder / "server.pem"), str(folder / "server.key"))
    return context


class OwnedHTTPPeer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host, context, *, proxy=False, plain=False):
        super().__init__((host, 0), OwnedHTTPHandler)
        self.context, self.proxy, self.plain = context, proxy, plain
        self.requests = []
        self.errors = []
        self.tls_attempts = 0
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


class OwnedHTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        connection = raw = self.request
        raw.settimeout(10)
        try:
            first = raw.recv(1, socket.MSG_PEEK)
            if not first:
                return
            tls = first == b"\x16"
            if tls:
                self.server.tls_attempts += 1
                if self.server.plain:
                    return
                try:
                    connection = self.server.context.wrap_socket(raw, server_side=True)
                except ssl.SSLError:
                    return
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = connection.recv(4096)
                assert chunk, "Incomplete owned HTTP request"
                data += chunk
                assert len(data) <= 16384
            lines = data.split(b"\r\n")
            headers = {
                line.split(b":", 1)[0].lower(): line.split(b":", 1)[1].strip()
                for line in lines[1:]
                if b":" in line
            }
            is_connect = lines[0].startswith(b"CONNECT ")
            expected = b"Basic " + base64.b64encode(
                b"owned-http-user:owned-credential-default-secret"
            )
            auth_matches = headers.get(b"authorization") == expected
            if not is_connect:
                assert auth_matches, "Expected synthetic authentication"
            if not self.server.proxy:
                assert lines[0] == b"GET / HTTP/1.1"
            self.server.requests.append(
                {"connect": is_connect, "tls": tls, "synthetic_auth_received": auth_matches}
            )
            code = 502 if is_connect else 200
            connection.sendall(
                f"HTTP/1.1 {code} Owned\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
            )
        except Exception as error:
            self.server.errors.append(type(error).__name__)
        finally:
            if connection is not raw:
                connection.close()


async def make_proxy_fixture(db, case, folder, setenv, delenv):
    for key in ENV_KEYS:
        delenv(key, raising=False)
    host = owned_bind_address()
    context = proxy_certificates(folder, host)
    target = OwnedHTTPPeer(host, context, plain=case.get("plain", False))
    proxy = OwnedHTTPPeer("127.0.0.1", context, proxy=True)
    trust = case.get("trust", "file")
    if trust in {"file", "opt-out", "untrusted"}:
        setenv("SSL_CERT_FILE", str(folder / ("ca.pem" if trust == "file" else "unrelated.pem")))
    elif trust == "directory":
        setenv("SSL_CERT_DIR", str(folder / "ca-directory"))
    setenv(case["proxy"], f"http://127.0.0.1:{proxy.server_address[1]}")
    if case.get("no_proxy"):
        setenv("NO_PROXY", host)
    try:
        f = await make_outcome_fixture(db, {"target_status": 200, "status": 200, **case})
        f.proxy_case = case
        f.target_peer, f.proxy_peer = target, proxy
        f.payload.update(
            target_ip=case.get("target", host),
            port=target.server_address[1],
            verify_ssl=trust != "opt-out",
            allow_plaintext_http=case.get("plain", False),
        )
        return f
    except BaseException:
        target.close()
        proxy.close()
        raise


async def inspect_proxy_response(f, response, *, before=False):
    case = f.proxy_case
    expected_status = case.get("status", 200)
    assert response.status_code == expected_status, response.text
    rows = await credential_rows(f.db, f.ids)
    for key, row in rows.items():
        omit = (
            {"last_used", "last_test_result", "updated_at"}
            if expected_status == 200 and key == f.target_id
            else set()
        )
        assert {k: v for k, v in row.items() if k not in omit} == {
            k: v for k, v in f.before[key].items() if k not in omit
        }
    intercepted = (
        before
        and expected_status == 200
        and not case.get("no_proxy")
        and (case["proxy"] in PROXY_KEYS or case.get("plain"))
    )
    assert len(f.proxy_peer.requests) == int(bool(intercepted)), (
        "Ambient proxy received an unintended request"
    )
    if expected_status != 200:
        assert not f.target_peer.requests and not f.target_peer.tls_attempts
        return {
            "status": expected_status,
            "proxy_requests": 0,
            "target_requests": 0,
            "existing_credential_rows_checked": len(rows),
        }
    expected_success = case.get("trust", "file") not in {"none", "untrusted"}
    if intercepted and not case.get("plain"):
        expected_success = False
    body = response.json()
    assert body["success"] is expected_success
    assert rows[f.target_id]["last_test_result"] == ("reachable" if expected_success else "failed")
    assert len(f.target_peer.requests) == int(expected_success and not intercepted)
    if expected_success:
        assert body["device_info"]["authentication_verified"] is False
        assert body["device_info"]["scheme"] == ("http" if case.get("plain") else "https")
    if intercepted:
        assert f.proxy_peer.requests[0]["synthetic_auth_received"] is bool(case.get("plain"))
    assert "owned-credential-default-secret" not in response.text
    return {
        "status": expected_status,
        "success": body["success"],
        "proxy_requests": len(f.proxy_peer.requests),
        "proxy_received_synthetic_auth": any(
            r["synthetic_auth_received"] for r in f.proxy_peer.requests
        ),
        "target_requests": len(f.target_peer.requests),
        "existing_credential_rows_checked": len(rows),
    }


@pytest.mark.parametrize("case", proxy_cases(), ids=lambda c: c["label"])
async def test_credential_probe_ignores_ambient_proxy_preserving_CA(
    db_session, monkeypatch, tmp_path, case
):
    f = await make_proxy_fixture(db_session, case, tmp_path, monkeypatch.setenv, monkeypatch.delenv)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=f.app, raise_app_exceptions=False),
            base_url="http://owned-fixture",
            trust_env=False,
        ) as client:
            response = await client.post(f.path, json=f.payload)
        await inspect_proxy_response(f, response)
    finally:
        f.target_peer.close()
        f.proxy_peer.close()
