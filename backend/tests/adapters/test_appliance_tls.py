# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real loopback TLS: credentials must not cross an untrusted connection."""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import ssl
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.adapters.appliance_tls import appliance_tls_context
from app.adapters.exceptions import AdapterAuthenticationError, AdapterConnectionError
from app.adapters.truenas.adapter import TrueNASAdapter
from app.adapters.truenas.client import TrueNASClient
from app.adapters.truenas.ws_client import TrueNASWSClient
from app.adapters.unifi_protect.adapter import UniFiProtectAdapter
from app.schemas.core import ControllerCreate, ControllerProbe
from tests.harness_wait import HARNESS_WAIT_SECONDS


@pytest.fixture
def certificates(tmp_path, monkeypatch):
    monkeypatch.delenv("FREESDN_DEVICE_CA_BUNDLE", raising=False)
    now = dt.datetime.now(dt.UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FreeSDN test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=2))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def server_context(kind="valid"):
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=2))
            .not_valid_after(now + dt.timedelta(days=-1 if kind == "expired" else 1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("wrong.invalid" if kind == "wrong-host" else "localhost")]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path, key_path = tmp_path / (kind + ".pem"), tmp_path / (kind + ".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx

    return ca_path, server_context


@asynccontextmanager
async def https_server(context, received, *, redirect=None):
    async def handle(reader, writer):
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HARNESS_WAIT_SECONDS)
            length = next(
                (
                    int(line.split(b":", 1)[1])
                    for line in header.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                ),
                0,
            )
            body = await reader.readexactly(length) if length else b""
            received.append((header, body))
            payload = b'{"state":"READY","job_id":42}'
            status = b"200 OK"
            extra = b""
            if redirect:
                status = b"307 Temporary Redirect"
                extra = b"Location: " + redirect.encode() + b"\r\n"
            writer.write(
                b"HTTP/1.1 "
                + status
                + b"\r\n"
                + extra
                + b"Content-Type: application/json\r\nConnection: close\r\nContent-Length: "
                + str(len(payload)).encode()
                + b"\r\n\r\n"
                + payload
            )
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["rest", "protect", "ws"])
@pytest.mark.parametrize("trust", ["trusted", "unknown-ca", "wrong-host", "expired"])
async def test_real_tls_authentication_requires_valid_peer(
    certificates, monkeypatch, transport, trust
):
    ca, context_factory = certificates
    context = context_factory(trust if trust in {"wrong-host", "expired"} else "valid")
    if trust != "unknown-ca":
        monkeypatch.setenv("FREESDN_DEVICE_CA_BUNDLE", str(ca))
    received = []

    async def ws_handle(ws):
        received.append(json.loads(await ws.recv()))
        await ws.send(
            json.dumps(
                {"jsonrpc": "2.0", "id": received[-1]["id"], "result": {"response_type": "SUCCESS"}}
            )
        )
        await ws.wait_closed()

    if transport == "ws":
        server = await websockets.serve(ws_handle, "127.0.0.1", 0, ssl=context)
        port = server.sockets[0].getsockname()[1]
        client = TrueNASWSClient("localhost", api_key="synthetic-key", port=port)
        try:
            if trust == "trusted":
                await client.connect()
            else:
                with pytest.raises(AdapterAuthenticationError):
                    await client.connect()
        finally:
            await client.disconnect()
            server.close()
            await server.wait_closed()
    else:
        async with https_server(context, received) as port:
            client = (
                TrueNASClient("localhost", api_key="synthetic-key", port=port)
                if transport == "rest"
                else UniFiProtectAdapter(
                    "localhost", "synthetic-user", "synthetic-password", port=port
                )
            )
            try:
                if trust == "trusted":
                    await client.connect()
                else:
                    with pytest.raises(AdapterConnectionError):
                        await client.connect()
            finally:
                await client.disconnect()
    if trust == "trusted":
        assert received, "trusted local appliance did not receive authentication"
        encoded = repr(received)
        assert ("synthetic-password" if transport == "protect" else "synthetic-key") in encoded
    else:
        assert received == [], "application credentials reached an untrusted peer"


@pytest.mark.asyncio
async def test_certificate_failure_never_falls_back_to_rest(certificates, monkeypatch):
    import app.adapters.truenas.adapter as module

    _, context_factory = certificates
    received = []
    rest = AsyncMock()
    monkeypatch.setattr(module, "TrueNASClient", rest)
    async with https_server(context_factory(), received) as port:
        adapter = TrueNASAdapter("localhost", api_key="synthetic-key", port=port)
        with pytest.raises(AdapterAuthenticationError):
            await adapter._open_transport()
    rest.assert_not_called()
    assert received == []


@pytest.mark.asyncio
async def test_websocket_redirect_cannot_receive_login_frame(certificates, monkeypatch):
    ca, context_factory = certificates
    monkeypatch.setenv("FREESDN_DEVICE_CA_BUNDLE", str(ca))
    redirected, initial = [], []

    async def recipient(ws):
        redirected.append(await ws.recv())

    server = await websockets.serve(recipient, "127.0.0.1", 0, ssl=context_factory())
    port = server.sockets[0].getsockname()[1]
    try:
        async with https_server(
            context_factory(), initial, redirect=f"wss://localhost:{port}/api/current"
        ) as origin:
            client = TrueNASWSClient("localhost", api_key="synthetic-key", port=origin)
            try:
                with pytest.raises(AdapterConnectionError):
                    await client.connect()
            finally:
                await client.disconnect()
    finally:
        server.close()
        await server.wait_closed()
    assert len(initial) == 1 and redirected == []


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["rest", "protect"])
async def test_authenticated_redirect_cannot_downgrade_to_http(
    certificates, monkeypatch, transport
):
    ca, context_factory = certificates
    monkeypatch.setenv("FREESDN_DEVICE_CA_BUNDLE", str(ca))
    first, downgraded = [], []
    async with https_server(None, downgraded) as plain_port:
        async with https_server(
            context_factory(), first, redirect=f"http://localhost:{plain_port}/leak"
        ) as port:
            client = (
                TrueNASClient("localhost", api_key="synthetic-key", port=port)
                if transport == "rest"
                else UniFiProtectAdapter(
                    "localhost", "synthetic-user", "synthetic-password", port=port
                )
            )
            try:
                with pytest.raises(AdapterConnectionError):
                    await client.connect()
            finally:
                await client.disconnect()
    assert len(first) == 1 and downgraded == []


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["upload", "download"])
@pytest.mark.parametrize("trusted", [True, False])
async def test_transfer_channels_use_the_same_tls_trust(
    certificates, monkeypatch, operation, trusted
):
    ca, context_factory = certificates
    if trusted:
        monkeypatch.setenv("FREESDN_DEVICE_CA_BUNDLE", str(ca))
    received = []
    async with https_server(context_factory(), received) as port:
        client = TrueNASWSClient("localhost", api_key="synthetic-key", port=port)
        client._begin_download = AsyncMock(return_value=(42, "/_download/42?auth_token=synthetic"))

        async def perform():
            if operation == "upload":
                return await client.upload_blob(dest_path="/mnt/tank/test", blob=b"synthetic-data")
            return await client.download_blob("/mnt/tank/test")

        if trusted:
            assert await perform()
        else:
            with pytest.raises(AdapterConnectionError):
                await perform()
    assert bool(received) == trusted


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://example.invalid/leak",
        "https://example.invalid/_download/1",
        "//example.invalid/_download/1",
        "/_download/1\r\nX: secret",
        "/other",
        "/_download/1#fragment",
        "/\\example.invalid/_download/1",
    ],
)
async def test_download_response_cannot_select_credential_destination(url):
    client = TrueNASWSClient("localhost", api_key="synthetic-key")
    client._begin_download = AsyncMock(return_value=(1, url))
    with pytest.raises(AdapterConnectionError, match="unsafe download URL"):
        await client.download_blob("/mnt/tank/test")


def test_invalid_configured_ca_does_not_fall_back_to_unverified(tmp_path, monkeypatch):
    bad = tmp_path / "not-a-ca.pem"
    bad.write_text("invalid certificate")
    monkeypatch.setenv("FREESDN_DEVICE_CA_BUNDLE", str(bad))
    for verify in (True, False):
        with pytest.raises(AdapterConnectionError, match="trust store"):
            appliance_tls_context(verify, adapter_id="truenas")


def test_explicit_insecure_opt_out_warns(certificates, caplog):
    ctx = appliance_tls_context(False, adapter_id="truenas")
    assert not ctx.check_hostname and ctx.verify_mode == ssl.CERT_NONE
    assert "explicitly disabled" in caplog.text


def test_controller_defaults_and_explicit_legacy_choice():
    data = {
        "name": "test",
        "controller_type": "truenas",
        "host": "nas.example.invalid",
        "port": 9443,
        "site_id": uuid4(),
        "username": "synthetic-user",
        "password": "synthetic-password",
    }
    assert ControllerCreate(**data).verify_ssl is True
    assert ControllerProbe(host="nas.example.invalid").verify_ssl is True
    assert ControllerCreate(**data, verify_ssl=False).verify_ssl is False
    assert (
        TrueNASClient("nas.example.invalid", port=9443).base_url
        == "https://nas.example.invalid:9443"
    )
    assert (
        TrueNASClient("nas.example.invalid", port=80).base_url == "https://nas.example.invalid:443"
    )
