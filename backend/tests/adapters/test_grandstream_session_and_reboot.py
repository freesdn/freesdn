# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Grandstream session refresh and reboot acknowledgement (F-07).

Two defects at the same seam, both introduced or left by the retry-idempotency
work:

1. STALE SID. ``_request`` built the URL (and any sid-bearing form body) ONCE,
   before the retry loop. A 401 triggers ``_login()``, which replaces
   ``self._sid`` -- but the retry re-sent the OLD identifier, so the
   re-authentication this transport advertises never worked for config writes.

2. ERASED ACKNOWLEDGEMENT. A phone acknowledges a reboot by DROPPING the
   connection, and ``reboot()`` is written to read ``ServerDisconnectedError``
   as exactly that. The non-idempotent branch wrapped it in
   ``GrandstreamConnectionError``, so that handler never fired and a phone that
   DID reboot was recorded as a definite failure.
"""

from __future__ import annotations

import aiohttp
import pytest

from app.adapters.grandstream.client import GrandstreamPhoneClient


class _FakeResponse:
    def __init__(self, status: int, body: str = "{}") -> None:
        self.status = status
        self._body = body
        self.content_type = "application/json"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def text(self):
        return self._body

    async def json(self, **_kwargs):
        import json as _json

        return _json.loads(self._body)


class _RecordingSession:
    """Records every URL/body it is asked for; 401s any stale SID."""

    def __init__(self, good_sid: str) -> None:
        self.urls: list[str] = []
        self.bodies: list[dict | None] = []
        self._good = good_sid

    def request(self, _method, url, **kwargs):
        self.urls.append(url)
        self.bodies.append(kwargs.get("data"))
        sid_ok = f"sid={self._good}" in url or (
            isinstance(kwargs.get("data"), dict) and kwargs["data"].get("sid") == self._good
        )
        return _FakeResponse(200 if sid_ok else 401)


def _client(session, sid="stale"):
    c = GrandstreamPhoneClient.__new__(GrandstreamPhoneClient)
    c._session = session
    c._sid = sid
    c._base_url = "http://phone.local"
    return c


@pytest.mark.asyncio
async def test_the_retry_after_login_uses_the_refreshed_sid(monkeypatch) -> None:
    """The core regression: a 401 must be retried with the NEW session id.

    Fails before the fix -- both requests carried ``sid=stale``.
    """
    session = _RecordingSession(good_sid="fresh")
    client = _client(session)

    async def _login():
        client._sid = "fresh"

    monkeypatch.setattr(client, "_login", _login)

    await client._request("GET", "/cgi-bin/config_get", include_sid=True)

    assert len(session.urls) == 2, f"expected one retry, got {session.urls}"
    assert "sid=stale" in session.urls[0]
    assert "sid=fresh" in session.urls[1], (
        f"the retry must carry the refreshed SID; got {session.urls[1]}"
    )


@pytest.mark.asyncio
async def test_a_sid_bearing_form_body_is_refreshed_too(monkeypatch) -> None:
    """``_sys_operation`` puts the sid in the BODY, not the query."""
    session = _RecordingSession(good_sid="fresh")
    client = _client(session)

    async def _login():
        client._sid = "fresh"

    monkeypatch.setattr(client, "_login", _login)

    await client._request(
        "POST", "/cgi-bin/api-sys_operation", data={"request": "REBOOT", "sid": "stale"}
    )

    assert len(session.bodies) == 2, f"expected one retry, got {session.bodies}"
    assert session.bodies[1]["sid"] == "fresh", (
        f"the retried body must carry the refreshed SID; got {session.bodies[1]}"
    )


class _DroppingSession:
    """A phone that accepts the command and drops the connection as it reboots."""

    def __init__(self) -> None:
        self.calls = 0

    def request(self, _method, _url, **_kwargs):
        self.calls += 1
        raise aiohttp.ServerDisconnectedError("phone went down")


@pytest.mark.asyncio
async def test_a_dropped_connection_reaches_the_reboot_acknowledgement() -> None:
    """Fails before the fix: the drop was wrapped, so reboot() returned False
    for a phone that had in fact rebooted."""
    session = _DroppingSession()
    client = _client(session)

    with pytest.raises(aiohttp.ServerDisconnectedError):
        await client._request("POST", "/cgi-bin/api-sys_operation", data={"request": "REBOOT"})

    assert session.calls == 1, (
        f"a mutation must be transmitted exactly once; got {session.calls}"
    )
