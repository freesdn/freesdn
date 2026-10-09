"""Saved gateway tests retain vendor settings without overriding trusted identity."""

import asyncio
import base64
import ipaddress
import json
import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.adapters.base import AdapterResult
from app.adapters.mikrotik import client as mikrotik_client
from app.adapters.pfsense import client as pfsense_client
from app.core.crypto import encrypt_dict
from app.models.core import Organization
from app.modules.firewall.gateway_service import (
    GatewayNotFoundError,
    GatewayService,
    adapter_registry,
)
from app.modules.firewall.models import GatewayConnection

VENDORS = ["opnsense", "pfsense", "mikrotik", "openwrt"]
OPTIONS = {"use_ssl": True, "timeout": 7, "api_version": "v2"}
UNTRUSTED = {
    "host": "192.168.99.99",
    "port": 9999,
    "verify_ssl": False,
    "vendor": "other-vendor",
    "adapter_id": "other-adapter",
    "username": "other-user",
    "password": "other-password",
    "api_key": "other-key",
    "api_secret": "other-secret",
    "HOST": "192.168.88.88",
    "PASSWORD": "other-password",
    "force": True,
    "direct_write_force": True,
    "ADAPTER_READ_ONLY": False,
}


def credentials(vendor):
    return (
        {"api_key": "owned-key", "api_secret": "owned-secret"}
        if vendor in {"opnsense", "pfsense"}
        else {"username": "owned-user", "password": "owned-secret"}
    )


@pytest_asyncio.fixture
async def owner(db_session):
    org = Organization(name="Owned saved transport", slug="owned-policy-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    return org


async def saved_gateway(db_session, owner, vendor, settings, *, port=8443, verify_ssl=True):
    gateway = GatewayConnection(
        org_id=owner.id,
        name="Owned saved policy",
        vendor=vendor,
        host="192.168.77.77",
        port=port,
        verify_ssl=verify_ssl,
        credentials=encrypt_dict(credentials(vendor)),
        settings=settings,
        sync_enabled=False,
    )
    db_session.add(gateway)
    await db_session.flush()
    return gateway


@pytest.fixture
def factory(monkeypatch):
    calls = []
    adapter = AsyncMock()
    adapter.test_connection.return_value = AdapterResult.ok(data={"hostname": "owned-appliance"})

    def create(**kwargs):
        calls.append(kwargs)
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    return calls, adapter


def assert_identity(call, vendor, *, trust=True):
    assert call["adapter_id"] == vendor
    assert call["host"] == "192.168.77.77" and call["port"] == 8443
    assert call["username"] == ("owned-key" if vendor in {"opnsense", "pfsense"} else "owned-user")
    assert call["password"] == "owned-secret" and call["verify_ssl"] is trust
    assert (
        not {
            "vendor",
            "api_key",
            "api_secret",
            "HOST",
            "PASSWORD",
            "force",
            "direct_write_force",
            "ADAPTER_READ_ONLY",
        }
        & call.keys()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("override", [None, False, True])
async def test_saved_test_retains_transport_settings_and_explicit_trust_override(
    db_session, owner, factory, vendor, override
):
    gateway = await saved_gateway(db_session, owner, vendor, dict(OPTIONS))
    result = await GatewayService(db_session).test_existing_gateway(
        gateway.id, owner.id, verify_ssl=override
    )
    calls, adapter = factory
    assert result["success"] and len(calls) == 1
    assert_identity(calls[0], vendor, trust=override is not False)
    assert all(calls[0].get(key) == value for key, value in OPTIONS.items())
    adapter.disconnect.assert_awaited_once()
    await db_session.refresh(gateway)
    assert gateway.settings == OPTIONS and gateway.verify_ssl is True


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("entry", ["live", "test"])
async def test_settings_cannot_replace_stored_destination_credentials_or_write_policy(
    db_session, owner, factory, vendor, entry
):
    settings = {**OPTIONS, **UNTRUSTED}
    gateway = await saved_gateway(db_session, owner, vendor, settings)
    service = GatewayService(db_session)
    if entry == "live":
        service._build_adapter(gateway)
    else:
        assert (await service.test_existing_gateway(gateway.id, owner.id))["success"]
    calls, _ = factory
    assert len(calls) == 1
    assert_identity(calls[0], vendor)
    assert all(calls[0].get(key) == value for key, value in OPTIONS.items())
    assert gateway.settings == settings  # Existing JSON is projected, not rewritten.


@pytest.mark.parametrize("vendor", VENDORS)
def test_raw_options_cannot_override_adapter_identity_or_write_controls(factory, vendor):
    service = GatewayService(None)
    service._build_adapter_from_raw(
        vendor,
        "192.168.77.77",
        8443,
        True,
        **credentials(vendor),
        adapter_id="other-adapter",
        force=True,
        use_ssl=True,
    )
    calls, _ = factory
    assert len(calls) == 1
    assert_identity(calls[0], vendor)
    assert calls[0]["use_ssl"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("settings", [None, {}])
async def test_legacy_missing_settings_keep_connection_defaults(
    db_session, owner, factory, vendor, settings
):
    gateway = await saved_gateway(db_session, owner, vendor, settings)
    assert (await GatewayService(db_session).test_existing_gateway(gateway.id, owner.id))["success"]
    calls, _ = factory
    assert_identity(calls[0], vendor)
    assert not OPTIONS.keys() & calls[0].keys()


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", VENDORS)
async def test_foreign_gateway_refused_before_building_adapter(db_session, owner, factory, vendor):
    gateway = await saved_gateway(db_session, owner, vendor, dict(OPTIONS))
    with pytest.raises(GatewayNotFoundError):
        await GatewayService(db_session).test_existing_gateway(gateway.id, uuid4())
    calls, adapter = factory
    assert not calls
    adapter.test_connection.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("vendor", ["mikrotik", "pfsense"])
@pytest.mark.parametrize("use_ssl", [False, True])
@pytest.mark.parametrize("peer_scheme", ["http", "https"])
async def test_saved_protocol_policy_with_real_HTTP_TLS_peers(
    db_session, owner, monkeypatch, tmp_path, vendor, use_ssl, peer_scheme
):
    """Only fixture hostname is relocated; scheme/port are selected by real clients."""
    requests, pools, errors = [], [], []
    handlers = set()

    async def peer(reader, writer):
        handlers.add(asyncio.current_task())
        try:
            first = await asyncio.wait_for(reader.readexactly(1), 5)
            if first == b"\x16" and peer_scheme == "http":
                return  # A TLS ClientHello is not credential-bearing HTTP.
            header = first + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            assert len(header) < 8192
            lines = header.decode().split("\r\n")
            method, path, _ = lines[0].split()
            assert method == "GET"
            values = {
                row.split(":", 1)[0].lower(): row.split(":", 1)[1].strip()
                for row in lines[1:]
                if ":" in row
            }
            if vendor == "mikrotik":
                assert (
                    values["authorization"]
                    == "Basic " + base64.b64encode(b"owned-user:owned-secret").decode()
                )
                assert path in {"/rest/system/resource", "/rest/system/identity"}
                payload = (
                    [{"version": "fixture"}]
                    if path.endswith("resource")
                    else [{"name": "owned-mikrotik"}]
                )
            else:
                assert values["authorization"] == "owned-key owned-secret"
                assert path == "/api/v2/system/version"
                payload = {"code": 200, "status": "ok", "data": {"version": "fixture"}}
            requests.append({"path": path, "TLS": writer.get_extra_info("ssl_object") is not None})
            body = json.dumps(payload).encode()
            writer.write(
                f"HTTP/1.1 200 Owned\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        except Exception as exc:
            errors.append(type(exc).__name__)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass
            handlers.discard(asyncio.current_task())

    server_ssl = None
    if peer_scheme == "https":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned-loopback")])
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path, key_path = tmp_path / "certificate.pem", tmp_path / "key.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ssl.load_cert_chain(cert_path, key_path)
    server = await asyncio.start_server(peer, "127.0.0.1", 0, ssl=server_ssl)
    port = server.sockets[0].getsockname()[1]
    assert port not in {443, 8729}

    def build(**kwargs):
        url = httpx.URL(kwargs["base_url"])
        assert url.host == "192.168.77.77" and url.port == port
        assert kwargs["verify"] is False  # Deliberate legacy opt-out is kept.
        kwargs["base_url"] = url.copy_with(host="127.0.0.1")
        kwargs["trust_env"] = False
        kwargs["timeout"] = httpx.Timeout(2.0)
        pool = httpx.AsyncClient(**kwargs)
        pools.append(pool)
        return pool

    module = mikrotik_client if vendor == "mikrotik" else pfsense_client
    monkeypatch.setattr(module, "build_async_client", build)
    try:
        async with server:
            gateway = await saved_gateway(
                db_session, owner, vendor, {"use_ssl": use_ssl}, port=port, verify_ssl=False
            )
            result = await GatewayService(db_session).test_existing_gateway(gateway.id, owner.id)
            if handlers:
                await asyncio.wait_for(asyncio.gather(*list(handlers)), 5)
            expected = use_ssl is (peer_scheme == "https")
            assert result["success"] is expected
            assert bool(requests) is expected
            assert all(row["TLS"] is use_ssl for row in requests)
            assert not errors
            assert pools and all(pool.is_closed for pool in pools)
            await db_session.refresh(gateway)
            assert gateway.settings == {"use_ssl": use_ssl} and gateway.verify_ssl is False
    finally:
        for pool in pools:
            await pool.aclose()
        if handlers:
            await asyncio.wait_for(asyncio.gather(*list(handlers)), 5)
