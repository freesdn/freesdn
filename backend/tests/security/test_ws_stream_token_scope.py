# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A camera stream token must not open the org-wide realtime WebSocket.

Background
----------
``POST /cameras/{id}/stream-token`` mints the narrowest credential in the
product on purpose: it lives about a minute and carries ``scope="stream"`` plus
the single ``camera_id`` it was issued for. That shape exists because the token
is passed in a URL query string, where it gets written to proxy logs, browser
history and referrer headers -- so it is designed to be nearly worthless if it
leaks.

The camera endpoints honour it (``app/modules/cameras/api.py``): a query-string
token MUST be ``scope="stream"``, and its ``camera_id`` must equal the camera
being requested.

``authenticate_websocket`` read the claim and then compared it to nothing. The
extraction line was the only mention of ``scope`` in the whole module. So the
same one-camera, one-minute token also authenticated the general realtime
WebSocket and subscribed the holder to their entire organization -- device
status, alerts, VPN, discovery, every event family the socket carries. The
credential built to be the narrowest was silently the widest.

The guard refuses ANY narrowing scope rather than just ``"stream"``, so a scope
added later cannot inherit the same hole by default.
"""

from __future__ import annotations

import inspect

import pytest

from app.api.v1.endpoints import websocket as ws


class _FakePayload(dict):
    pass


@pytest.fixture
def fake_verify(monkeypatch):
    """Swap verify_token so these tests exercise the guard, not the JWT library."""
    holder: dict = {}

    async def _verify(token: str, token_type: str = "access"):
        return holder.get("payload")

    monkeypatch.setattr(ws, "verify_token", _verify)
    return holder


def _base_claims(**extra):
    claims = {
        "sub": "11111111-1111-1111-1111-111111111111",
        "org_id": "22222222-2222-2222-2222-222222222222",
        "role": "operator",
        "permissions": ["cameras.view"],
        "tv": 0,
        "jti": "jti-1",
    }
    claims.update(extra)
    return claims


# ── The regression ───────────────────────────────────────────────


async def test_stream_scoped_token_is_refused(fake_verify) -> None:
    """
    The exact credential /cameras/{id}/stream-token mints. It used to
    authenticate successfully and open an org-wide subscription.
    """
    fake_verify["payload"] = _base_claims(
        scope="stream", camera_id="33333333-3333-3333-3333-333333333333"
    )
    assert await ws.authenticate_websocket("t") is None


@pytest.mark.parametrize("scope", ["stream", "media", "download", "export", "anything-else"])
async def test_any_narrowing_scope_is_refused(fake_verify, scope: str) -> None:
    """
    Refusing only "stream" would leave the next scope to inherit the hole. The
    rule is: a token that narrows itself cannot open the full socket.
    """
    fake_verify["payload"] = _base_claims(scope=scope)
    assert await ws.authenticate_websocket("t") is None


# ── The normal path must be untouched ────────────────────────────


async def test_a_full_access_token_still_authenticates(fake_verify) -> None:
    """The realtime socket must keep working for ordinary logins."""
    fake_verify["payload"] = _base_claims()
    info = await ws.authenticate_websocket("t")
    assert info is not None
    assert info["user_id"] == "11111111-1111-1111-1111-111111111111"
    assert info["organization_id"] == "22222222-2222-2222-2222-222222222222"


async def test_an_explicitly_null_scope_still_authenticates(fake_verify) -> None:
    """A claim present but empty is not a narrowing scope."""
    for empty in (None, ""):
        fake_verify["payload"] = _base_claims(scope=empty)
        assert await ws.authenticate_websocket("t") is not None


async def test_a_token_without_sub_is_still_refused(fake_verify) -> None:
    """The pre-existing check must survive the new one."""
    claims = _base_claims()
    claims.pop("sub")
    fake_verify["payload"] = claims
    assert await ws.authenticate_websocket("t") is None


async def test_an_invalid_token_is_still_refused(fake_verify) -> None:
    fake_verify["payload"] = None
    assert await ws.authenticate_websocket("t") is None


# ── Guard the guard ──────────────────────────────────────────────


def test_the_scope_claim_is_actually_compared_to_something() -> None:
    """
    The original defect was subtle precisely because the claim WAS extracted --
    it looked handled. Assert it is now used in a condition, not just read.
    """
    src = inspect.getsource(ws.authenticate_websocket)
    code = "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))
    assert "token_scope" in code
    assert "if token_scope:" in code, "the scope claim is being read but not enforced again"
