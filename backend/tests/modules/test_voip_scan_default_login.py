# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A phone scan never guesses passwords unless the operator opts in.

A VoIP discovery scan run without credentials logged into every phone it found
with admin/admin, and with credentials it tried admin/admin as a second guess.
Grandstream phones lock their admin account after failed logins, and the scan
sprayed a default password across the network. Now a scan without credentials
only identifies phones from unauthenticated requests, the operator's
credentials are the only ones tried, and the factory default login is a
per-scan opt-in (``try_default_credentials``).

These run the real probe against a real HTTP server that answers like a
Grandstream phone (or a Yealink one) and records every request it receives.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import pytest
import pytest_asyncio
from aiohttp import web
from pydantic import ValidationError

from app.modules.voip import discovery
from app.modules.voip.schemas import (
    BulkConnectRequest,
    DiscoveryScanRequest,
    PhoneConnectionTestRequest,
    PhoneCredentials,
)

TOKEN = "challenge-token-31"


@dataclass
class _Seen:
    method: str
    path: str
    authorization: str | None
    body: str


@dataclass
class FakePhone:
    address: str
    seen: list[_Seen] = field(default_factory=list)

    def logins(self) -> list[_Seen]:
        return [s for s in self.seen if s.path in ("/cgi-bin/access", "/cgi-bin/dologin")]

    def basic_auth_users(self) -> list[str]:
        out = []
        for s in self.seen:
            if s.authorization and s.authorization.startswith("Basic "):
                out.append(base64.b64decode(s.authorization[6:]).decode())
        return out

    def dologin_password_hashes(self) -> list[str]:
        return [
            s.body.split("password=", 1)[1]
            for s in self.seen
            if s.path == "/cgi-bin/dologin" and "password=" in s.body
        ]


def _login_hash(password: str) -> str:
    return hashlib.sha256((password + TOKEN).encode()).hexdigest()


async def _serve(kind: str) -> tuple[web.AppRunner, FakePhone]:
    phone = FakePhone(address="")

    async def handler(request: web.Request) -> web.Response:
        phone.seen.append(
            _Seen(
                request.method,
                request.path,
                request.headers.get("Authorization"),
                await request.text(),
            )
        )
        if kind == "grandstream":
            if request.path == "/cgi-bin/api.values.get":
                body = {"P67": "000b82aabbcc", "P68": "1.0.11.7"}
                return web.json_response({"response": "success", "body": body})
            if request.path == "/cgi-bin/metaconfig_get":
                return web.json_response([])
            if request.path == "/cgi-bin/access":
                return web.json_response({"response": "success", "body": TOKEN})
            if request.path == "/cgi-bin/dologin":
                return web.json_response({"response": "error", "body": "bad login"})
            if request.path == "/":
                return web.Response(text="<html><title>Grandstream</title></html>")
        if kind == "yealink" and request.path == "/servlet":
            if request.headers.get("Authorization"):
                return web.Response(text=json.dumps({"model": "T46S", "vendor": "Yealink"}))
            return web.Response(status=401)
        return web.Response(status=404)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    phone.address = f"127.0.0.1:{port}"
    return runner, phone


@pytest_asyncio.fixture
async def grandstream() -> AsyncIterator[FakePhone]:
    runner, phone = await _serve("grandstream")
    try:
        yield phone
    finally:
        await runner.cleanup()


@pytest_asyncio.fixture
async def yealink() -> AsyncIterator[FakePhone]:
    runner, phone = await _serve("yealink")
    try:
        yield phone
    finally:
        await runner.cleanup()


async def test_a_scan_without_credentials_identifies_but_never_logs_in(
    grandstream: FakePhone,
) -> None:
    found = await discovery.http_probe_host(grandstream.address, timeout=5.0)

    assert found is not None and found.mac_address == "00:0b:82:aa:bb:cc"
    assert grandstream.seen, "the phone was never contacted"
    assert grandstream.logins() == []
    assert grandstream.basic_auth_users() == []
    assert not any("password" in s.body for s in grandstream.seen)


async def test_a_yealink_without_credentials_gets_no_authorization_header(
    yealink: FakePhone,
) -> None:
    await discovery.http_probe_host(yealink.address, timeout=5.0)

    assert any(s.path == "/servlet" for s in yealink.seen)
    assert all(s.authorization is None for s in yealink.seen)


async def test_operator_credentials_are_the_only_ones_tried(grandstream: FakePhone) -> None:
    await discovery.http_probe_host(
        grandstream.address,
        timeout=5.0,
        credentials={"username": "ops", "password": "Phone-Pass-1"},
    )

    assert grandstream.dologin_password_hashes() == [_login_hash("Phone-Pass-1")]
    assert set(grandstream.basic_auth_users()) <= {"ops:Phone-Pass-1"}
    assert "admin:admin" not in grandstream.basic_auth_users()


async def test_the_factory_login_is_tried_only_when_opted_in(grandstream: FakePhone) -> None:
    await discovery.http_probe_host(grandstream.address, timeout=5.0, try_default_credentials=True)

    assert _login_hash("admin") in grandstream.dologin_password_hashes()


def test_the_scan_request_defaults_to_identify_only() -> None:
    assert DiscoveryScanRequest().try_default_credentials is False
    with pytest.raises(ValidationError):
        DiscoveryScanRequest(credentials={})  # an empty login is not admin/admin


@pytest.mark.parametrize("schema", [PhoneCredentials, PhoneConnectionTestRequest])
def test_login_requests_carry_no_default_login(schema) -> None:
    with pytest.raises(ValidationError):
        schema()


def test_bulk_connect_needs_an_explicit_login() -> None:
    with pytest.raises(ValidationError):
        BulkConnectRequest(phone_ids=["00000000-0000-4000-8000-000000000001"])
