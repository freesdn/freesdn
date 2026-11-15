# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A stored camera or NVR host is contacted at the address that was checked.

``check_stored_camera_host`` resolved a stored hostname, checked the address
(private, not loopback, link-local or metadata), then returned the NAME, and
its callers built the adapter with the name. The transport resolved it again,
so a name that answered with a private address during the check could answer
with a forbidden one when the stored login was sent (DNS rebinding). The ONVIF
snapshot also retried a 401 with HTTP Basic, sending the stored login in clear
to whatever the name resolved to by then.

No device is contacted: DNS is a table, and HTTP is a recorder.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.adapters.exceptions import AdapterConnectionError
from app.adapters.onvif.adapter import ONVIFAdapter
from app.core.crypto import encrypt_credential
from app.modules.cameras.host_guard import CameraHostRefused, check_stored_camera_host
from app.modules.cameras.service import NVRDiscoveryService, StreamService

_REAL_GETADDRINFO = socket.getaddrinfo


@pytest.fixture
def dns(monkeypatch):
    """Hostnames answer from ``table``; the answer can be changed mid-test."""
    table: dict[str, list[str]] = {}

    def fake(host, port, family=0, type=0, proto=0, flags=0):
        if host not in table:
            return _REAL_GETADDRINFO(host, port, family, type, proto, flags)
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (ip, 0),
            )
            for ip in table[host]
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return table


def test_a_hostname_comes_back_as_the_address_that_was_checked(dns) -> None:
    dns["cam.lan.test"] = ["10.1.2.3"]
    assert check_stored_camera_host("cam.lan.test") == "10.1.2.3"


def test_an_ip_literal_comes_back_unchanged() -> None:
    assert check_stored_camera_host(" 192.168.5.6 ") == "192.168.5.6"


def test_a_dual_stack_name_is_pinned_to_its_ipv4_address(dns) -> None:
    dns["cam.dual.test"] = ["fd00::5", "10.1.2.4"]
    assert check_stored_camera_host("cam.dual.test") == "10.1.2.4"


def test_a_name_with_only_ipv6_addresses_is_refused(dns) -> None:
    dns["cam.v6.test"] = ["fd00::6"]
    with pytest.raises(CameraHostRefused, match="IPv4"):
        check_stored_camera_host("cam.v6.test")


@pytest.mark.parametrize("vendor", ["onvif", "hikvision", "dahua"])
def test_the_adapter_connects_to_the_checked_address_not_the_name(dns, vendor) -> None:
    dns["cam.rebind.test"] = ["10.1.2.5"]
    adapter = StreamService._create_camera_adapter(
        host="cam.rebind.test", port=80, username="admin", password="pw", vendor=vendor
    )
    # The name now points at the metadata service; the adapter never asks again.
    dns["cam.rebind.test"] = ["169.254.169.254"]
    assert adapter.host == "10.1.2.5"
    if vendor != "hikvision":
        assert adapter._host_pinned is True


async def test_nvr_sync_discovers_at_the_checked_address(dns) -> None:
    dns["nvr.rebind.test"] = ["10.1.2.7"]
    nvr = SimpleNamespace(
        id="n1",
        ip_address="nvr.rebind.test",
        port=80,
        username="admin",
        password_encrypted=encrypt_credential("stored-secret"),
    )

    class _Result:
        def scalar_one_or_none(self) -> Any:
            return nvr

    class _Db:
        async def execute(self, _q: Any) -> _Result:
            return _Result()

    seen: list[str] = []

    class _Stop(Exception):
        pass

    async def discover(host, *_a, **_k):
        seen.append(host)
        raise _Stop

    service = NVRDiscoveryService(_Db())  # type: ignore[arg-type]
    service.discover_channels = discover  # type: ignore[method-assign]
    with pytest.raises(_Stop):
        await service.sync_nvr("n1")  # type: ignore[arg-type]
    assert seen == ["10.1.2.7"]


class _Http:
    def __init__(self) -> None:
        self.auth: list[str] = []

    async def get(self, _url: str, *, auth: Any, timeout: float) -> httpx.Response:
        self.auth.append(type(auth).__name__)
        return httpx.Response(401, request=httpx.Request("GET", _url))


@pytest.mark.parametrize(
    ("pinned", "expected"),
    [(False, ["DigestAuth"]), (True, ["DigestAuth", "BasicAuth"])],
)
async def test_onvif_snapshot_offers_basic_auth_only_to_a_checked_address(
    pinned, expected
) -> None:
    adapter = ONVIFAdapter(
        host="10.1.2.8", username="admin", password="pw", port=80, host_pinned=pinned
    )
    adapter._connected = True
    http = _Http()
    adapter._http = http  # type: ignore[assignment]

    async def snapshot_uri(*_a: Any) -> str:
        return "http://10.1.2.8/onvif/snapshot.jpg"

    adapter._get_snapshot_uri = snapshot_uri  # type: ignore[method-assign]
    with pytest.raises(AdapterConnectionError):
        await adapter.get_snapshot(channel=1)
    assert http.auth == expected
