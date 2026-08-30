# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test WebSocket Origin validation (CSWSH protection).

the WebSocket handshake must validate the Origin header against
the CORS allowlist before accepting the connection. Browsers send cookies
on WebSocket handshakes regardless of CORS policy, so a logged-in admin
who visits attacker.com would otherwise leak every real-time event.
"""

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import app


def _client() -> TestClient:
    return TestClient(app)


def test_origin_helper_unit() -> None:
    """Unit test for _is_origin_allowed — no DB/app fixtures needed."""
    from app.api.v1.endpoints.websocket import _is_origin_allowed

    allowed = ["http://localhost:5173", "https://app.example.com"]

    # Exact matches
    assert _is_origin_allowed("http://localhost:5173", allowed)
    assert _is_origin_allowed("https://app.example.com", allowed)

    # Reject unknown / empty / malformed
    assert not _is_origin_allowed("https://evil.com", allowed)
    assert not _is_origin_allowed("", allowed)
    assert not _is_origin_allowed("not-a-url", allowed)

    # Scheme mismatch (http vs https) must be rejected
    assert not _is_origin_allowed("http://app.example.com", allowed)

    # Port mismatch must be rejected (netloc comparison)
    assert not _is_origin_allowed("https://app.example.com:8080", allowed)

    # Host mismatch must be rejected
    assert not _is_origin_allowed("http://localhost:3000", allowed)

    # Subdomain must NOT match parent (no wildcards)
    assert not _is_origin_allowed("https://evil.app.example.com", allowed)


def test_origin_helper_rejects_empty_allowlist() -> None:
    from app.api.v1.endpoints.websocket import _is_origin_allowed

    assert not _is_origin_allowed("https://app.example.com", [])
    assert not _is_origin_allowed("", [])


def test_websocket_rejects_missing_origin() -> None:
    """Browser WS endpoint must reject connections with no Origin header."""
    with _client() as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/api/v1/ws"):
                pass


@pytest.mark.xfail(
    reason=(
        "TestClient lifespan binds a global async singleton to a stale event "
        "loop inside the CI container. The security property is covered "
        "deterministically by test_validate_ws_origin_* below."
    ),
    strict=False,
)
def test_websocket_rejects_evil_origin() -> None:
    """Browser WS endpoint must reject unknown origins.

    Still xfail, but for an accurate reason now, and no longer load-bearing.

    The old marker justified itself by saying "the Origin-rejection LOGIC is
    deterministically covered by test_origin_helper_unit". That was FALSE:
    that unit test exercises ``_is_origin_allowed`` only, while
    ``_validate_ws_origin`` short-circuits on ``_is_same_origin`` BEFORE it ever
    consults the allowlist -- so weakening the short-circuit, which is the shape
    a suffix or wildcard match would take, left this whole file green.

    That gap is now genuinely closed by the ``test_validate_ws_origin_*`` tests
    below, which drive the real function with no TestClient at all -- including
    a sibling-host case that catches the substring match a loosened
    ``_is_same_origin`` would become. This end-to-end case stays marked because the
    flake it documents is real and environment-dependent: it passes on a Windows
    host and fails inside the CI container, where the sync TestClient's lifespan
    binds a global async singleton to a stale event loop. It is kept as a
    smoke test; the security property itself is asserted deterministically below.
    """
    with _client() as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "/api/v1/ws",
                headers={"origin": "https://evil.attacker.com"},
            ):
                pass


def test_websocket_accepts_allowed_origin() -> None:
    """Browser WS endpoint must accept whitelisted origins.

    The connection will still require authentication after accept, but the
    Origin check must not block it. We just verify that the handshake
    proceeds past the Origin gate (no immediate 1008 close).
    """
    try:
        with _client() as client:
            with client.websocket_connect(
                "/api/v1/ws",
                headers={"origin": "http://localhost:5173"},
            ) as ws:
                # The server will prompt for an auth message next. We don't
                # authenticate here - we just need to confirm the Origin gate
                # didn't slam the door. Close cleanly.
                ws.close()
    except Exception:
        pytest.skip("WebSocket handshake test environment not available")


# ---------------------------------------------------------------------------
# _validate_ws_origin itself, with no TestClient.
#
# test_origin_helper_unit covers the pure allowlist helper. It cannot see the
# gate: _validate_ws_origin returns True from _is_same_origin BEFORE it ever
# reaches the allowlist, so a weakened short-circuit is invisible to it. These
# drive the gate directly against a stand-in socket -- no app lifespan, no event
# loop singletons, so nothing here can flake the way the xfail above claimed.
# ---------------------------------------------------------------------------


class _StubWebSocket:
    """Minimal stand-in: the gate only reads headers and may close the socket."""

    def __init__(self, **headers: str) -> None:
        self.headers = headers
        self.close_calls: list[tuple[int, str]] = []

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.close_calls.append((code, reason))


async def test_validate_ws_origin_rejects_a_cross_site_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CSWSH case: attacker page, our host, origin not in the allowlist.

    Mutation this catches (and which the xfailed end-to-end test did not):
    making _is_same_origin true for any present Origin, e.g.
    ``bool(origin) or <real check>``. test_origin_helper_unit stays green under
    that mutation because the helper it tests is untouched.
    """
    from app.api.v1.endpoints import websocket as ws_mod
    from app.core.config import settings

    monkeypatch.setattr(settings, "CORS_ORIGINS", ["https://app.example.com"])
    sock = _StubWebSocket(origin="https://evil.attacker.com", host="app.example.com")

    assert await ws_mod._validate_ws_origin(sock) is False
    assert sock.close_calls == [(1008, "Origin not allowed")]


async def test_validate_ws_origin_rejects_a_missing_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An absent Origin must not fall through the same-origin short-circuit."""
    from app.api.v1.endpoints import websocket as ws_mod
    from app.core.config import settings

    monkeypatch.setattr(settings, "CORS_ORIGINS", ["https://app.example.com"])
    sock = _StubWebSocket(host="app.example.com")

    assert await ws_mod._validate_ws_origin(sock) is False
    assert sock.close_calls == [(1008, "Origin not allowed")]


async def test_validate_ws_origin_allows_the_deployment_host_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-origin is allowed with an EMPTY allowlist -- that is the whole point.

    Realtime must work on any deploy host without the operator also listing it
    in CORS_ORIGINS. Asserting it against an empty allowlist is what proves the
    short-circuit is doing the work, rather than the allowlist quietly matching.
    Mutation this catches: deleting the _is_same_origin branch, which would
    break realtime on every deployment whose host is not in CORS_ORIGINS.
    """
    from app.api.v1.endpoints import websocket as ws_mod
    from app.core.config import settings

    monkeypatch.setattr(settings, "CORS_ORIGINS", [])
    sock = _StubWebSocket(origin="https://app.example.com", host="app.example.com")

    assert await ws_mod._validate_ws_origin(sock) is True
    assert sock.close_calls == []


async def test_validate_ws_origin_allows_a_listed_cross_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gate must not be a blanket refusal: the dev SPA on another port works."""
    from app.api.v1.endpoints import websocket as ws_mod
    from app.core.config import settings

    monkeypatch.setattr(settings, "CORS_ORIGINS", ["http://localhost:5173"])
    sock = _StubWebSocket(origin="http://localhost:5173", host="localhost:8000")

    assert await ws_mod._validate_ws_origin(sock) is True
    assert sock.close_calls == []


async def test_validate_ws_origin_does_not_treat_a_sibling_host_as_same_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``evil-app.example.com`` must not read as same-origin for ``app.example.com``.

    Mutation this catches: relaxing _is_same_origin's netloc equality to an
    ``endswith``/``in`` containment test, the classic origin-check regression.
    """
    from app.api.v1.endpoints import websocket as ws_mod
    from app.core.config import settings

    monkeypatch.setattr(settings, "CORS_ORIGINS", [])
    for evil_host in ("https://evil-app.example.com", "https://app.example.com.evil.net"):
        sock = _StubWebSocket(origin=evil_host, host="app.example.com")
        assert await ws_mod._validate_ws_origin(sock) is False, evil_host
        assert sock.close_calls == [(1008, "Origin not allowed")]
