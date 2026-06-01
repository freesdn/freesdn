# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreePBX OAuth2 token lifecycle, the token-refresh lock, and AMI security.

These cover paths the readiness audit flagged as untested:
* OAuth2 ``_oauth2_login`` parsing + expiry math, ``_ensure_oauth2_token``
  cache/refresh, and the double-checked refresh LOCK (concurrent callers must
  trigger exactly one re-login, not a thundering herd on the token endpoint).
* AMI toll-fraud Originate allowlist + CRLF-injection sanitizer.
* Locks in the tranche-2 hardening: trunk write endpoints are 501 (the direct
  service write-methods are gone), and the apply request exposes ``auto_reload``.

All offline — a fake session feeds canned token responses; no live PBX.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from app.adapters.freepbx.ami_client import (
    _AMI_ORIGINATE_APP_ALLOWLIST,
    AMIClient,
    AMIProtocolError,
    _sanitize_ami_value,
)
from app.adapters.freepbx.exceptions import FreePBXAuthError
from app.adapters.freepbx.rest_client import FreePBXRestClient

# ── token-endpoint fake session ─────────────────────────────────────────


class _Resp:
    def __init__(self, status: int, text: str):
        self.status = status
        self._text = text

    async def text(self) -> str:
        return self._text


class _Ctx:
    def __init__(self, resp: _Resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *a):
        return False


class _TokenSession:
    def __init__(self, status: int = 200, text: str = '{"access_token": "tok-1", "expires_in": 3600}'):
        self.status = status
        self.text = text
        self.posts = 0

    def post(self, *a, **k):
        self.posts += 1
        return _Ctx(_Resp(self.status, self.text))


def _client(session: _TokenSession) -> FreePBXRestClient:
    c = FreePBXRestClient(
        host="pbx.example.test", username="admin", password="x",
        api_client_id="cid", api_client_secret="csec",
    )
    c._auth_mode = "oauth2"
    c._session = session
    return c


# ── OAuth2 login + expiry ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oauth2_login_parses_token_and_expiry():
    c = _client(_TokenSession(text='{"access_token": "tok-abc", "expires_in": 3600}'))
    await c._oauth2_login()
    assert c._oauth2_token == "tok-abc"
    # refreshes ~60s early -> expiry is in the future, well under a full hour out
    assert c._oauth2_expires_at > time.monotonic() + 3000
    assert c._oauth2_expires_at <= time.monotonic() + 3600


@pytest.mark.asyncio
async def test_oauth2_login_401_raises_auth_error():
    c = _client(_TokenSession(status=401, text="nope"))
    with pytest.raises(FreePBXAuthError):
        await c._oauth2_login()


@pytest.mark.asyncio
async def test_ensure_token_uses_cache_when_valid():
    c = _client(_TokenSession())
    c._oauth2_token = "cached"
    c._oauth2_expires_at = time.monotonic() + 1000
    tok = await c._ensure_oauth2_token()
    assert tok == "cached"
    assert c._session.posts == 0  # no re-login when the cached token is valid


@pytest.mark.asyncio
async def test_ensure_token_refreshes_when_expired():
    c = _client(_TokenSession(text='{"access_token": "fresh", "expires_in": 3600}'))
    c._oauth2_token = "stale"
    c._oauth2_expires_at = time.monotonic() - 1  # already expired
    tok = await c._ensure_oauth2_token()
    assert tok == "fresh"
    assert c._session.posts == 1


@pytest.mark.asyncio
async def test_concurrent_refresh_logs_in_once_under_lock():
    """The double-checked refresh lock: N concurrent callers seeing an expired
    token must trigger exactly ONE _oauth2_login, not N (token-endpoint
    thundering-herd / overwrite race that the audit flagged)."""
    c = _client(_TokenSession())
    c._oauth2_token = None
    c._oauth2_expires_at = 0

    calls = {"n": 0}

    async def _fake_login():
        calls["n"] += 1
        await asyncio.sleep(0)  # yield so the other 9 callers queue on the lock
        c._oauth2_token = "tok-shared"
        c._oauth2_expires_at = time.monotonic() + 3600

    c._oauth2_login = _fake_login  # type: ignore[assignment]

    tokens = await asyncio.gather(*(c._ensure_oauth2_token() for _ in range(10)))
    assert calls["n"] == 1  # serialized + re-checked -> single login
    assert all(t == "tok-shared" for t in tokens)


# ── AMI security: toll-fraud allowlist + CRLF sanitize ───────────────────


def test_ami_originate_allowlist_contents():
    assert {"Dial", "Playback", "Queue", "ConfBridge"} <= set(_AMI_ORIGINATE_APP_ALLOWLIST)
    for dangerous in ("System", "Exec", "AGI", "MixMonitor", "Originate"):
        assert dangerous not in _AMI_ORIGINATE_APP_ALLOWLIST


@pytest.mark.asyncio
@pytest.mark.parametrize("app", ["System", "Exec", "AGI", "MixMonitor"])
async def test_ami_originate_rejects_dangerous_application(app):
    """Originate refuses RCE/file-write dialplan apps before any I/O."""
    ami = AMIClient(host="pbx.example.test", username="admin", secret="x")
    with pytest.raises(AMIProtocolError, match="allowlist"):
        await ami.originate(channel="PJSIP/100", application=app, data="evil")


def test_ami_sanitize_strips_crlf_injection():
    # An attacker-supplied value trying to inject a second AMI action.
    raw = "100\r\nAction: Originate\r\nChannel: PJSIP/evil"
    cleaned = _sanitize_ami_value(raw)
    assert "\r" not in cleaned and "\n" not in cleaned
    assert cleaned == "100Action: OriginateChannel: PJSIP/evil"


# ── tranche-2 hardening locks ────────────────────────────────────────────


def test_apply_request_exposes_auto_reload():
    from app.schemas.gateway_vpn import ApplyPendingChangeRequest

    assert ApplyPendingChangeRequest().auto_reload is False  # safe default
    assert ApplyPendingChangeRequest(force=True, auto_reload=True).auto_reload is True


def test_direct_trunk_write_service_methods_removed():
    """The un-staged trunk write surface (bypassed the dual-gate) is gone."""
    from app.modules.voip.service import VoIPService

    for gone in ("create_pbx_trunk", "update_pbx_trunk", "delete_pbx_trunk"):
        assert not hasattr(VoIPService, gone), f"{gone} should be removed"
