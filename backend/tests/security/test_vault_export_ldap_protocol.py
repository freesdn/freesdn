"""Owned real LDAP wire/TLS probes; authority is controlled, not SQL proof."""

import asyncio
import ipaddress
import secrets
import ssl
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import anyio
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ldap3.protocol.rfc4511 import LDAPMessage
from pyasn1.codec.ber.decoder import decode
from pyasn1.codec.ber.encoder import encode

from app.core import vault_ldap_reauthentication as module
from app.core.vault_export_proof import VaultProofContext
from tests.harness_wait import HARNESS_WAIT_SECONDS


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    root = tmp_path_factory.mktemp("ldap-certs")
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned LDAP test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    contexts = {}
    for kind in ("valid", "wrong-host", "expired"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = (
            "other.example.invalid"
            if kind == "wrong-host"
            else "directory.example.invalid"
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=3))
            .not_valid_after(
                now - timedelta(days=1)
                if kind == "expired"
                else now + timedelta(days=1)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    True, False, True, False, False, False, False, False, False
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_path, key_path = root / (kind + ".pem"), root / (kind + ".key")
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_path, key_path)
        contexts[kind] = context
    return pem, contexts


async def packet(reader):
    header = await reader.readexactly(2)
    length = header[1]
    if length & 128:
        more = await reader.readexactly(length & 127)
        header += more
        length = int.from_bytes(more)
    assert length < 4096
    raw = header + await reader.readexactly(length)
    value, rest = decode(raw, asn1Spec=LDAPMessage())
    assert not rest
    return value


def reply(message_id, operation, code=0):
    message = LDAPMessage()
    message["messageID"] = message_id
    result = message["protocolOp"][operation]
    result["resultCode"] = code
    result["matchedDN"] = ""
    result["diagnosticMessage"] = "owned diagnostic, never a public error"
    return message


@pytest_asyncio.fixture
async def owned(monkeypatch, certificates):
    pem, contexts = certificates
    f = SimpleNamespace(
        mode="success",
        checks=0,
        fail_check=0,
        passwords=[],
        dns=[],
        operations=[],
        tls=[],
        sni=[],
        writers=[],
        tasks=set(),
        errors=[],
        entered=asyncio.Event(),
        release=asyncio.Event(),
        closed=0,
        client_writers=[],
        close_entered=asyncio.Event(),
        close_release=asyncio.Event(),
    )

    async def resolve(host):
        f.dns.append(host)
        assert host == "directory.example.invalid"
        # Explicit owned loopback destination admission; not production DNS/SSRF proof.
        return "127.0.0.1"

    monkeypatch.setattr(module, "_resolve", resolve)

    async def check():
        f.checks += 1
        if f.fail_check == f.checks:
            raise ValueError("owned private authority reason")

    f.check = check
    original_close = module._close

    async def observe_close(writer):
        f.client_writers.append(writer)
        f.close_entered.set()
        if f.mode == "pause-close":
            await f.close_release.wait()
        await original_close(writer)

    monkeypatch.setattr(module, "_close", observe_close)

    @asynccontextmanager
    async def server(protocol="ldaps", certificate="valid", trusted=True):
        context = contexts[certificate]
        context.set_servername_callback(
            lambda _socket, name, _context: f.sni.append(name)
        )

        async def serve(reader, writer):
            task = asyncio.current_task()
            f.tasks.add(task)
            f.writers.append(writer)
            try:
                if protocol == "ldap":
                    start = await packet(reader)
                    assert start["protocolOp"].getName() == "extendedReq"
                    assert (
                        str(start["protocolOp"]["extendedReq"]["requestName"])
                        == module._START_TLS
                    )
                    f.operations.append("starttls")
                    response = reply(
                        int(start["messageID"]),
                        "extendedResp",
                        53 if f.mode == "refuse-starttls" else 0,
                    )
                    if f.mode == "wrong-starttls-oid":
                        response["protocolOp"]["extendedResp"]["responseName"] = "1.2.3"
                    writer.write(encode(response))
                    await writer.drain()
                    if f.mode in {"refuse-starttls", "wrong-starttls-oid"}:
                        assert await reader.read() == b""
                        return
                    await writer.start_tls(
                        context, ssl_handshake_timeout=2, ssl_shutdown_timeout=1
                    )
                bind = await packet(reader)
                assert bind["protocolOp"].getName() == "bindRequest"
                body = bind["protocolOp"]["bindRequest"]
                assert int(body["version"]) == 3
                assert str(body["name"]) == "cn=existing,dc=example,dc=invalid"
                assert body["authentication"].getName() == "simple"
                f.operations.append("bind")
                f.passwords.append(body["authentication"]["simple"].asOctets())
                f.tls.append(writer.get_extra_info("ssl_object").version())
                f.entered.set()
                if f.mode == "pause-bind":
                    await f.release.wait()
                    # A deadline may already have closed this owned peer. Do
                    # not write through a TLS transport destroyed by cleanup.
                    if writer.is_closing():
                        return
                response = reply(
                    int(bind["messageID"]),
                    "bindResponse",
                    {"invalid": 49, "referral": 10, "auth-method": 7}.get(f.mode, 0),
                )
                if f.mode == "wrong-id":
                    response["messageID"] = int(bind["messageID"]) + 1
                if f.mode == "sasl":
                    response["protocolOp"]["bindResponse"]["serverSaslCreds"] = (
                        b"unexpected"
                    )
                raw = encode(response)
                raw = {
                    "oversized": b"\x30\x82\xff\xff",
                    "indefinite": b"\x30\x80",
                    "length-width": b"\x30\x84",
                    "wrong-tag": b"\x31\x00",
                    "truncated": b"\x30\x05\x02",
                    "nested-request": b"\x30\x07\x02\x01\x02\x63\x02\x00\x00",
                    "wrong-result-tag": b"\x30\x07\x02\x01\x02\x78\x02\x00\x00",
                }.get(f.mode, raw)
                if f.mode == "drip":
                    writer.write(raw[:2])
                    await writer.drain()
                    await f.release.wait()
                else:
                    for offset in range(0, len(raw), 3):
                        writer.write(raw[offset : offset + 3])
                        await writer.drain()
                    if f.mode != "truncated":
                        assert (
                            await reader.read() == b""
                        )  # no search, referral, second bind or unbind needed
            except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
                pass
            except Exception as error:
                f.errors.append(repr(error))
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, ssl.SSLError):
                    pass
                f.closed += 1
                f.tasks.discard(task)

        srv = await asyncio.start_server(
            serve, "127.0.0.1", 0, ssl=context if protocol == "ldaps" else None
        )
        port = srv.sockets[0].getsockname()[1]
        binding = module.LDAPExportBinding(
            VaultProofContext(
                uuid4(), uuid4(), 4, "access_jti", str(uuid4()), "create", "a" * 64
            ),
            "b" * 64,
            uuid4(),
            "c" * 64,
            f"{protocol}://directory.example.invalid:{port}",
            "cn=existing,dc=example,dc=invalid",
            True,
            pem if trusted else None,
        )
        flow = module.VaultLDAPReauthentication(binding=binding, check_current=check)
        try:
            yield flow
        finally:
            f.release.set()
            f.close_release.set()
            srv.close()
            await srv.wait_closed()
            for writer in f.writers:
                writer.close()
            if f.tasks:
                await asyncio.wait_for(asyncio.gather(*list(f.tasks)), HARNESS_WAIT_SECONDS)
            assert not f.tasks and not f.errors
            assert all(writer.is_closing() for writer in f.client_writers)
            assert module._ADMISSION.borrowed_tokens == 0

    f.server = server
    yield f


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["ldaps", "ldap"])
@pytest.mark.parametrize(
    "password", ["fresh synthetic password", "ümlaut-密碼", " " * 12]
)
async def test_real_verified_bind_exact_identity_and_no_extra_operation(
    owned, protocol, password
):
    async with owned.server(protocol) as flow:
        result = await flow.confirm(password)
        assert result.provider_id == flow.binding.provider_id
        assert result.request_binding == flow.binding.request_binding
        assert result.authenticated_at <= result.completed_at <= time.time()
        assert owned.passwords == [password.encode()]
        assert owned.operations == (
            ["starttls", "bind"] if protocol == "ldap" else ["bind"]
        )
        assert owned.tls[0] in {"TLSv1.2", "TLSv1.3"}
        assert owned.sni == ["directory.example.invalid"]
        assert owned.dns == ["directory.example.invalid"]
        assert owned.checks == 3 and len(owned.client_writers) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["ldaps", "ldap"])
@pytest.mark.parametrize(
    "certificate,trusted", [("wrong-host", True), ("expired", True), ("valid", False)]
)
async def test_certificate_failures_before_credentials(
    owned, protocol, certificate, trusted
):
    async with owned.server(protocol, certificate, trusted) as flow:
        with pytest.raises(module.LDAPConfirmationError) as found:
            await flow.confirm(secrets.token_urlsafe(24))
        chain = []
        error = found.value
        while error is not None and error not in chain:
            chain.append(error)
            error = error.__context__
        assert any(isinstance(item, ssl.SSLCertVerificationError) for item in chain)
        verification = next(
            item for item in chain if isinstance(item, ssl.SSLCertVerificationError)
        )
        assert (
            verification.verify_code
            == {"wrong-host": 62, "expired": 10, "valid": 20}[certificate]
        )
        assert not owned.passwords


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["ldaps", "ldap"])
@pytest.mark.parametrize(
    "mode",
    [
        "invalid",
        "referral",
        "auth-method",
        "wrong-id",
        "sasl",
        "oversized",
        "indefinite",
        "length-width",
        "wrong-tag",
        "truncated",
        "nested-request",
        "wrong-result-tag",
    ],
)
async def test_wire_refusals_own_and_close_connection(owned, protocol, mode):
    owned.mode = mode
    async with owned.server(protocol) as flow:
        with pytest.raises(module.LDAPConfirmationError) as error:
            await flow.confirm("synthetic secret only")
        assert str(error.value) == module._ERROR
        assert len(owned.passwords) == 1 and len(owned.client_writers) == 1
        assert owned.operations.count("bind") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["refuse-starttls", "wrong-starttls-oid"])
async def test_starttls_refusal_sends_no_password(owned, mode):
    owned.mode = mode
    async with owned.server("ldap") as flow:
        with pytest.raises(module.LDAPConfirmationError):
            await flow.confirm("synthetic secret only")
        assert not owned.passwords and owned.operations == ["starttls"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "password", ["", None, b"bytes", "x" * 1025, "密" * 400, "abc\x00def", "abc\ndef"]
)
async def test_invalid_password_refused_without_io(owned, password):
    async with owned.server() as flow:
        with pytest.raises(module.LDAPConfirmationError):
            await flow.confirm(password)
        assert not owned.dns and not owned.operations and owned.checks == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", [1, 2, 3])
@pytest.mark.parametrize("protocol", ["ldaps", "ldap"])
async def test_authority_rechecked_before_credentials_and_after_close(
    owned, phase, protocol
):
    owned.fail_check = phase
    async with owned.server(protocol) as flow:
        with pytest.raises(module.LDAPConfirmationError):
            await flow.confirm("synthetic secret only")
        assert owned.checks == phase
        assert len(owned.passwords) == (1 if phase == 3 else 0)
        if phase == 3:
            assert owned.client_writers[0].is_closing()


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["ldaps", "ldap"])
@pytest.mark.parametrize("mode", ["pause-bind", "drip", "pause-close"])
async def test_real_scaled_deadline_refuses_late_success(
    owned, monkeypatch, protocol, mode
):
    owned.mode = mode
    monkeypatch.setattr(module, "_OPERATION_SECONDS", 0.15)
    async with owned.server(protocol) as flow:
        task = asyncio.create_task(flow.confirm("synthetic secret only"))
        await asyncio.wait_for(owned.entered.wait(), HARNESS_WAIT_SECONDS)
        if mode == "pause-close":
            await asyncio.wait_for(owned.close_entered.wait(), HARNESS_WAIT_SECONDS)
            await asyncio.sleep(0.20)
            assert not task.done()
            owned.close_release.set()
        with pytest.raises(module.LDAPConfirmationError):
            await asyncio.wait_for(task, HARNESS_WAIT_SECONDS)
        assert len(owned.client_writers) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["pause-bind", "pause-close"])
@pytest.mark.parametrize("cancellation", ["asyncio", "anyio"])
async def test_repeated_cancellation_retains_connection_ownership(
    owned, phase, cancellation
):
    owned.mode = phase
    delivered = []
    async with owned.server() as flow:
        scopes = []

        async def run():
            with anyio.CancelScope() as scope:
                scopes.append(scope)
                delivered.append(await flow.confirm("synthetic secret only"))

        task = asyncio.create_task(run())
        event = owned.entered if phase == "pause-bind" else owned.close_entered
        await asyncio.wait_for(event.wait(), HARNESS_WAIT_SECONDS)
        if cancellation == "asyncio":
            task.cancel()
            await asyncio.sleep(0.02)
            task.cancel()
        else:
            scopes[0].cancel()
        await asyncio.sleep(0.03)
        assert not task.done() and module._ADMISSION.borrowed_tokens == 1
        owned.release.set()
        owned.close_release.set()
        if cancellation == "asyncio":
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, HARNESS_WAIT_SECONDS)
        else:
            await asyncio.wait_for(task, HARNESS_WAIT_SECONDS)
        assert not delivered and len(owned.client_writers) == 1


@pytest.mark.asyncio
async def test_admission_refuses_third_then_recovers(owned):
    owned.mode = "pause-bind"
    async with owned.server() as flow:
        tasks = [
            asyncio.create_task(flow.confirm("synthetic secret only")) for _ in range(2)
        ]
        async with asyncio.timeout(HARNESS_WAIT_SECONDS):
            while len(owned.passwords) < 2:
                await asyncio.sleep(0.001)
        dns_count = len(owned.dns)
        with pytest.raises(module.LDAPConfirmationError):
            await flow.confirm("synthetic secret only")
        assert len(owned.dns) == dns_count
        owned.release.set()
        assert len(await asyncio.gather(*tasks)) == 2
        assert module._ADMISSION.borrowed_tokens == 0
        owned.mode = "success"
        await flow.confirm("synthetic secret only")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"url": "ldap://directory.example.invalid", "require_tls": False},
        {"url": "http://directory.example.invalid"},
        {"url": "ldaps://user:pass@directory.example.invalid"},
        {"url": "ldaps://directory.example.invalid/path"},
        {"url": "ldaps://directory.example.invalid?x=y"},
        {"url": "ldaps://directory.example.invalid#fragment"},
        {"url": "ldaps://directory.example.invalid:0"},
        {"url": "ldaps://directory.example.invalid:99999"},
        {"url": "ldaps://[fe80::1%eth0]"},
        {"subject_dn": ""},
        {"subject_dn": "not-a-dn"},
        {"subject_dn": "cn=" + "a" * 513},
        {"ca_pem": ""},
        {"ca_pem": "a" * 65537},
        {"require_tls": 1},
        {"request_binding": "a"},
        {"provider_digest": "a"},
        {"provider_id": "not-a-uuid"},
    ],
)
async def test_invalid_binding_has_no_connection(owned, changes):
    async with owned.server() as flow:
        with pytest.raises(module.LDAPConfirmationError):
            replace(flow.binding, **changes)
        assert not owned.operations and not owned.dns


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addresses,accepted",
    [
        (["192.168.10.12"], True),
        (["10.1.2.3", "fd00::1"], True),
        (["127.0.0.1"], False),
        (["169.254.169.254"], False),
        (["::1"], False),
        (["192.168.1.1", "127.0.0.1"], False),
        ([], False),
        (["192.168.1.1"] * 33, False),
    ],
)
async def test_async_dns_admission_all_candidates(monkeypatch, addresses, accepted):
    calls = []

    async def answer(host, *, lifetime):
        calls.append((host, lifetime))
        return SimpleNamespace(addresses=lambda: iter(addresses))

    monkeypatch.setattr(module.dns.asyncresolver, "resolve_name", answer)
    if accepted:
        assert await module._resolve("directory.example.invalid") == addresses[0]
    else:
        with pytest.raises((ValueError, module.LDAPConfirmationError)):
            await module._resolve("directory.example.invalid")
    assert calls == [("directory.example.invalid", 5)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address,accepted", [("192.168.1.1", True), ("127.0.0.1", False), ("::1", False)]
)
async def test_literal_pin_never_resolves_again(monkeypatch, address, accepted):
    async def forbidden(*args, **kwargs):
        pytest.fail("IP literal triggered DNS")

    monkeypatch.setattr(module.dns.asyncresolver, "resolve_name", forbidden)
    if accepted:
        assert ipaddress.ip_address(
            await module._resolve(address)
        ) == ipaddress.ip_address(address)
    else:
        with pytest.raises(ValueError):
            await module._resolve(address)


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["ldaps", "ldap"])
@pytest.mark.parametrize(
    "password,wire",
    [
        ("I\u00adX", b"IX"),
        ("user\u00a0pass", b"user pass"),
        ("\u2168", b"IX"),
        ("a\u030a", "å".encode()),
        ("\u200b", b" "),
    ],
)
async def test_simple_password_preparation_matches_existing_login(
    owned, protocol, password, wire
):
    async with owned.server(protocol) as flow:
        await flow.confirm(password)
        assert owned.passwords == [wire]
        assert owned.checks == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["ldaps", "ldap"])
@pytest.mark.parametrize("password", ["\u00ad", "\ufeff", "a\ue000", "a\u0627"])
async def test_prepared_empty_or_prohibited_password_never_binds(
    owned, protocol, password
):
    async with owned.server(protocol) as flow:
        with pytest.raises(module.LDAPConfirmationError):
            await flow.confirm(password)
        assert not owned.operations and not owned.dns and not owned.passwords
