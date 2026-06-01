# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unit tests for the rewritten GrandstreamPhoneClient (GXP2170-class firmware).

These tests don't talk to a real phone — they exercise the auth-payload
shapes, the challenge-response derivation, and the request routing logic
against a stub aiohttp server. Live integration is exercised by the
``scripts/gxp_full_test.py`` smoke test against 192.0.2.10.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from app.adapters.grandstream.client import (
    GrandstreamPhoneClient,
    _account_user_pvalue,
    _sha256_hex,
)
from app.adapters.grandstream.exceptions import (
    GrandstreamAuthError,
    GrandstreamConnectionError,
)


# ────────────────────────────────────────────────────────────────────
# Hash function used in the challenge-response auth
# ────────────────────────────────────────────────────────────────────


def test_sha256_hex_matches_sjcl_hex_encoding():
    """sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(x)) === hashlib.sha256(x).hexdigest()."""
    # Known vectors (independent of any phone) so we don't accidentally
    # drift away from the format the GWT client uses.
    assert _sha256_hex("") == hashlib.sha256(b"").hexdigest()
    assert (
        _sha256_hex("admin")
        == "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    )
    # password+token concatenation is the dologin formula
    assert _sha256_hex("testpass" + "tok123") == hashlib.sha256(
        b"testpasstok123"
    ).hexdigest()


# ────────────────────────────────────────────────────────────────────
# Account index → numeric P-value mapping
# ────────────────────────────────────────────────────────────────────


def test_account_user_pvalue_mapping():
    """Per the live capture: Account 1→P35, 2→P404, 3→P504, …, 6→P804."""
    assert _account_user_pvalue(1) == "35"
    assert _account_user_pvalue(2) == "404"
    assert _account_user_pvalue(3) == "504"
    assert _account_user_pvalue(4) == "604"
    assert _account_user_pvalue(5) == "704"
    assert _account_user_pvalue(6) == "804"
    # Out-of-range returns empty string (caller will skip)
    assert _account_user_pvalue(0) == ""
    assert _account_user_pvalue(7) == ""


# ────────────────────────────────────────────────────────────────────
# Plaintext-HTTP guard
# ────────────────────────────────────────────────────────────────────


def test_refuses_plaintext_without_acknowledgement():
    """Default ``use_ssl=True`` and missing ``acknowledge_plaintext`` must raise."""
    with pytest.raises(GrandstreamConnectionError, match="plain HTTP"):
        GrandstreamPhoneClient(
            host="192.168.1.100",
            password="x",
            use_ssl=False,
            # acknowledge_plaintext defaults to False
        )


def test_accepts_plaintext_with_acknowledgement():
    """``acknowledge_plaintext=True`` opts in to HTTP for brownfield phones."""
    client = GrandstreamPhoneClient(
        host="192.168.1.100",
        password="x",
        use_ssl=False,
        acknowledge_plaintext=True,
    )
    assert client._base_url == "http://192.168.1.100:80"


def test_https_default_base_url():
    client = GrandstreamPhoneClient(host="phone.example.com", password="x")
    assert client._base_url == "https://phone.example.com:80"


# ────────────────────────────────────────────────────────────────────
# Required HTTP headers
# ────────────────────────────────────────────────────────────────────


def test_required_headers_include_origin_and_referer():
    """Every request must carry Origin + Referer or the phone returns 403."""
    client = GrandstreamPhoneClient(
        host="192.0.2.10",
        password="x",
        use_ssl=False,
        acknowledge_plaintext=True,
    )
    h = client._headers()
    # The phone rejects requests without these
    assert h["Origin"] == "http://192.0.2.10:80"
    assert h["Referer"] == "http://192.0.2.10:80/"
    assert h["X-Requested-With"] == "XMLHttpRequest"


def test_json_body_header_set_when_requested():
    client = GrandstreamPhoneClient(
        host="phone.example.com", password="x",
    )
    h = client._headers(json_body=True)
    assert h["Content-Type"] == "application/json"
    # Non-json calls don't force a Content-Type (aiohttp picks
    # form-encoded for ``data=`` payloads).
    h2 = client._headers(json_body=False)
    assert "Content-Type" not in h2


# ────────────────────────────────────────────────────────────────────
# set_config payload shape
# ────────────────────────────────────────────────────────────────────


def test_set_config_payload_split_alias_vs_pvalue(monkeypatch):
    """``set_config`` must POST {alias: {…}, pvalue: {…}} via PUT.

    The GXP firmware returns 501 on POST and 400 on flat dict shapes.
    Verify we split ``@`` keys into alias, everything else into pvalue,
    and we use HTTP PUT (not POST).
    """
    client = GrandstreamPhoneClient(
        host="phone.example.com", password="x",
    )

    captured: dict = {}

    async def fake_request(method, path, *, data=None, params=None,
                           json_body=None, include_sid=False):
        captured["method"] = method
        captured["path"] = path
        captured["json_body"] = json_body
        captured["include_sid"] = include_sid
        return {"response": "success"}

    monkeypatch.setattr(client, "_request", fake_request)

    import asyncio
    ok = asyncio.run(client.set_config({
        "@call.dial.clickToDial.enable": "1",  # alias
        "P35": "203",                          # pvalue (numeric, strips leading P)
        "AccountRegistered1": "1",             # pvalue (named)
        "35": "203",                           # pvalue (raw numeric)
    }))
    assert ok is True
    assert captured["method"] == "PUT", "config_update needs PUT, not POST"
    assert captured["path"].endswith("/cgi-bin/config_update")
    assert captured["include_sid"] is True

    body = captured["json_body"]
    assert isinstance(body, dict)
    assert set(body.keys()) == {"alias", "pvalue"}
    assert body["alias"] == {"@call.dial.clickToDial.enable": "1"}
    # Numeric P-values must be stripped of the leading P
    assert body["pvalue"] == {
        "35": "203",
        "AccountRegistered1": "1",
    }


def test_set_config_empty_dict_is_noop(monkeypatch):
    """``set_config({})`` returns True without touching the wire."""
    client = GrandstreamPhoneClient(
        host="phone.example.com", password="x",
    )
    called = []

    async def fake_request(*a, **k):
        called.append((a, k))
        return {"response": "success"}

    monkeypatch.setattr(client, "_request", fake_request)
    import asyncio
    assert asyncio.run(client.set_config({})) is True
    assert called == [], "empty config write must not hit the network"


# ────────────────────────────────────────────────────────────────────
# api-sys_operation: reboot / factory_reset / provision payload shape
# ────────────────────────────────────────────────────────────────────


def test_reboot_uses_form_encoded_body_with_sid(monkeypatch):
    """``reboot()`` POSTs form-encoded ``request=REBOOT&sid=<sid>``.

    JSON body returns 501 on this firmware — the body MUST be the
    legacy form-encoded shape with sid IN the body (not the URL).
    """
    client = GrandstreamPhoneClient(
        host="phone.example.com", password="x",
    )
    client._sid = "test-sid-abc"

    captured: dict = {}

    async def fake_request(method, path, *, data=None, params=None,
                           json_body=None, include_sid=False):
        captured["method"] = method
        captured["path"] = path
        captured["data"] = data
        captured["json_body"] = json_body
        return {"response": "success"}

    monkeypatch.setattr(client, "_request", fake_request)
    import asyncio
    assert asyncio.run(client.reboot()) is True
    assert captured["method"] == "POST"
    assert captured["path"].endswith("/cgi-bin/api-sys_operation")
    assert captured["data"] == {"request": "REBOOT", "sid": "test-sid-abc"}
    assert captured["json_body"] is None, "must be form-encoded, not JSON"


def test_factory_reset_uses_RESET_op(monkeypatch):
    client = GrandstreamPhoneClient(
        host="phone.example.com", password="x",
    )
    client._sid = "sid-xyz"
    captured: dict = {}

    async def fake_request(method, path, *, data=None, **k):
        captured["data"] = data
        return {"response": "success"}

    monkeypatch.setattr(client, "_request", fake_request)
    import asyncio
    assert asyncio.run(client.factory_reset()) is True
    assert captured["data"]["request"] == "RESET"
    assert captured["data"]["sid"] == "sid-xyz"


def test_provision_now_uses_PROV_op(monkeypatch):
    client = GrandstreamPhoneClient(
        host="phone.example.com", password="x",
    )
    client._sid = "sid-prov"
    captured: dict = {}

    async def fake_request(method, path, *, data=None, **k):
        captured["data"] = data
        return {"response": "success"}

    monkeypatch.setattr(client, "_request", fake_request)
    import asyncio
    assert asyncio.run(client.provision_now()) is True
    assert captured["data"]["request"] == "PROV"


# ────────────────────────────────────────────────────────────────────
# get_lockout response handling
# ────────────────────────────────────────────────────────────────────


def test_login_raises_on_locked_response(monkeypatch):
    """If dologin returns ``body: "locked"`` we must raise AuthError, not silently treat as success."""
    client = GrandstreamPhoneClient(
        host="phone.example.com", password="x",
    )

    # Stub the aiohttp session entirely
    class _StubResp:
        def __init__(self, status, body):
            self.status = status
            self._body = body

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def json(self, content_type=None):
            return self._body

    class _StubSession:
        def __init__(self):
            self.calls = []

        def post(self, url, **kw):
            self.calls.append((url, kw))
            if url.endswith("/cgi-bin/access"):
                return _StubResp(200, {"response": "success", "body": "tok"})
            if url.endswith("/cgi-bin/dologin"):
                return _StubResp(200, {"response": "error", "body": "locked"})
            raise AssertionError(f"unexpected call: {url}")

    client._session = _StubSession()  # type: ignore

    import asyncio
    with pytest.raises(GrandstreamAuthError, match="locked"):
        asyncio.run(client._login())


def test_login_raises_on_wrong_password(monkeypatch):
    """Wrong-password progression (``wrong4`` → ``wrong3`` → … → ``locked``) must raise."""
    client = GrandstreamPhoneClient(
        host="phone.example.com", password="bad",
    )

    class _StubResp:
        def __init__(self, body):
            self.status = 200
            self._body = body

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def json(self, content_type=None):
            return self._body

    class _StubSession:
        def post(self, url, **kw):
            if url.endswith("/cgi-bin/access"):
                return _StubResp({"response": "success", "body": "tok"})
            return _StubResp({"response": "error", "body": "wrong4"})

    client._session = _StubSession()  # type: ignore
    import asyncio
    with pytest.raises(GrandstreamAuthError, match="wrong4"):
        asyncio.run(client._login())
