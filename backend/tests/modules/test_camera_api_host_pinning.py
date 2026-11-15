# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Every camera and NVR connection goes to the address the host check accepted.

The camera service and tasks already pinned Hikvision and ONVIF, but the camera
API built its Hikvision and NVR adapters, and its RTSP URLs, from the stored
host, and UniFi Protect kept the stored name. A name that answered privately
during the check could answer with a public address when the stored login was
sent (DNS rebinding), and for Protect a valid certificate for an attacker's
name passed TLS verification. Protect now connects to the checked address and
still verifies the certificate against the stored name.

No device is contacted: DNS is a table, and TLS is a local test server.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import datetime as dt
import ipaddress
import ssl
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from app.adapters.exceptions import AdapterAuthenticationError, AdapterConnectionError
from app.core.crypto import encrypt_credential
from app.modules.cameras import api as cameras_api
from app.modules.cameras.service import StreamService
from tests.modules.test_camera_host_pinning import dns  # noqa: F401 - fixture

_BACKEND = Path(__file__).resolve().parents[2]


def _camera(host: str) -> SimpleNamespace:
    return SimpleNamespace(
        nvr_id=None,
        ip_address=host,
        port=80,
        username="admin",
        password_encrypted=encrypt_credential("pw"),
        organization_id=None,
    )


async def test_the_api_credentials_carry_the_checked_address(dns) -> None:  # noqa: F811
    dns["cam.rebind.test"] = ["10.1.2.9"]
    host, port, username, password = await cameras_api._resolve_credentials(
        _camera("cam.rebind.test"),
        None,  # type: ignore[arg-type]
    )
    assert (host, port, username, password) == ("10.1.2.9", 80, "admin", "pw")


async def test_the_api_refuses_a_stored_host_that_resolves_publicly(dns) -> None:  # noqa: F811
    dns["cam.public.test"] = ["8.8.8.8"]
    with pytest.raises(HTTPException) as refused:
        await cameras_api._resolve_credentials(_camera("cam.public.test"), None)  # type: ignore[arg-type]
    assert refused.value.status_code == 400


def test_no_camera_endpoint_builds_an_adapter_from_a_stored_host() -> None:
    """Every adapter built in these endpoints gets a checked address."""
    builders = {
        "HikvisionAdapter",
        "ONVIFAdapter",
        "UniFiProtectAdapter",
        "_create_adapter",
        "_create_camera_adapter",
    }
    offenders = []
    for rel in ("app/modules/cameras/api.py", "app/api/v1/endpoints/actions.py"):
        tree = ast.parse((_BACKEND / rel).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name not in builders:
                continue
            for keyword in node.keywords:
                value = keyword.value
                if (
                    keyword.arg == "host"
                    and isinstance(value, ast.Attribute)
                    and value.attr == "ip_address"
                ):
                    offenders.append(f"{rel}:{node.lineno}")
    assert offenders == []


# ── UniFi Protect: the checked address, the stored name for TLS ──────────────


def _certificate(name: str) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


@pytest.fixture
async def protect_server(tmp_path, monkeypatch):
    """A TLS server on 127.0.0.1 whose certificate names ``nvr.rebind.test``."""
    cert_pem, key_pem = _certificate("nvr.rebind.test")
    (tmp_path / "cert.pem").write_bytes(cert_pem)
    (tmp_path / "key.pem").write_bytes(key_pem)
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    seen: dict[str, list[Any]] = {"sni": [], "requests": []}

    def _sni(_sock: Any, name: str | None, _ctx: Any) -> None:
        seen["sni"].append(name)

    server_ctx.sni_callback = _sni

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            seen["requests"].append(head.decode("latin-1"))
            writer.write(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]
    # The client trusts exactly this certificate, and checks the name on it.
    client_ctx = ssl.create_default_context(cadata=cert_pem.decode())
    client_ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT  # a bare test certificate
    import app.adapters.unifi_protect.adapter as protect

    monkeypatch.setattr(protect, "appliance_tls_context", lambda *_a, **_k: client_ctx)
    try:
        yield port, seen
    finally:
        server.close()
        await server.wait_closed()


def _protect(host: str, port: int, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Build Protect as the camera service does; the check accepts this test's server.

    ``host`` resolves nowhere, so only a connection to the checked address can
    reach the server.
    """
    from app.adapters.unifi_protect.adapter import UniFiProtectAdapter

    monkeypatch.setattr(
        "app.modules.cameras.host_guard.check_stored_camera_host", lambda _host: "127.0.0.1"
    )
    adapter = StreamService._create_camera_adapter(
        host=host, port=port, username="admin", password="pw", vendor="unifi_protect"
    )
    assert isinstance(adapter, UniFiProtectAdapter) and adapter.verify_ssl is True
    return adapter


async def test_protect_logs_in_at_the_checked_address_verifying_the_name(
    protect_server, monkeypatch
) -> None:
    port, seen = protect_server
    adapter = _protect("nvr.rebind.test", port, monkeypatch)
    try:
        with pytest.raises(AdapterAuthenticationError):
            await adapter.connect()  # the server answers 401 to the login
    finally:
        await adapter._client.aclose()
    assert seen["sni"] == ["nvr.rebind.test"]
    assert len(seen["requests"]) == 1
    request = seen["requests"][0].lower()
    assert request.startswith("post /api/auth/login ")
    assert f"host: nvr.rebind.test:{port}\r\n" in request
    assert adapter.host == "nvr.rebind.test"
    assert ipaddress.ip_address(adapter._client.base_url.host) == ipaddress.ip_address("127.0.0.1")


async def test_protect_refuses_a_certificate_for_another_name(protect_server, monkeypatch) -> None:
    port, seen = protect_server
    adapter = _protect("other.rebind.test", port, monkeypatch)
    try:
        with pytest.raises(AdapterConnectionError):
            await adapter.connect()
    finally:
        await adapter._client.aclose()
    assert seen["requests"] == []  # the login never left


# ── PTZ: a move and a preset save go to the checked address ─────────────────


class _OneCamera:
    def __init__(self, camera: Any) -> None:
        self.camera = camera

    async def execute(self, _query: Any) -> Any:
        return SimpleNamespace(scalar_one_or_none=lambda: self.camera)


async def test_ptz_moves_and_preset_saves_go_to_the_checked_address(
    dns,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.modules.cameras.service import PTZService

    dns["ptz.rebind.test"] = ["10.1.2.11"]
    camera = SimpleNamespace(
        id="cam-1",
        ip_address="ptz.rebind.test",
        device_type="onvif",
        username="admin",
        password_encrypted=encrypt_credential("pw"),
        has_ptz=True,
        organization_id=None,
        site_id=None,
    )
    hosts: list[str] = []

    class _Adapter:
        async def ptz_control(self, **_kw: Any) -> Any:
            return SimpleNamespace(success=True, error=None, data={})

        async def set_preset(self, **_kw: Any) -> Any:
            return SimpleNamespace(success=True, error=None, data={})

        async def disconnect(self) -> None:
            return None

    async def _get_adapter(*, host: str, **_kw: Any) -> _Adapter:
        hosts.append(host)
        return _Adapter()

    monkeypatch.setattr("app.adapters.get_adapter", _get_adapter)
    service = PTZService(_OneCamera(camera))  # type: ignore[arg-type]
    await service.control_ptz(camera_id="cam-1", action="left")  # type: ignore[arg-type]
    with contextlib.suppress(Exception):  # only where the login went matters here
        await service.set_preset(camera_id="cam-1", preset=2, name="door")  # type: ignore[arg-type]
    assert hosts == ["10.1.2.11", "10.1.2.11"]

    dns["ptz.rebind.test"] = ["8.8.8.8"]
    from app.modules.cameras.service import CameraError

    with pytest.raises(CameraError):
        await service.control_ptz(camera_id="cam-1", action="left")  # type: ignore[arg-type]
    assert len(hosts) == 2
