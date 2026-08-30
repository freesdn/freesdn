# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The edge's Content-Security-Policy must be as strict as the backend's.

CSP is enforced per RESPONSE. The header that governs what a script on the page
may do is the one served with the DOCUMENT -- and the document comes from the
edge (Caddy by default, nginx via the escape-hatch profile), not from FastAPI.
So a CSP hardening applied only in ``app/core/middleware.py`` protects the JSON
responses and leaves the page itself under the old policy.

That is what had happened. The backend's own comment reads:

    connect-src is 'self' ONLY: same-origin WebSocket (wss://same-host) is
    already covered by 'self', so we do not need the ws:/wss: wildcards.
    Removing them prevents data exfiltration to attacker-controlled WebSocket
    endpoints in the event of an XSS.

...while ``frontend/Caddyfile``, ``frontend/nginx/http-only.conf`` and
``frontend/nginx/ssl.conf`` all still served ``connect-src 'self' ws: wss:``.
The bare scheme sources match ANY host, so the deliberate hardening did not
apply anywhere it mattered. Observed on a running clean install on 2026-08-29 by
reading the header off ``curl -D -``; the same-origin WebSocket keeps working
under plain ``'self'`` (verified: ``/api/v1/ws`` still handshakes 101).

Rather than pin the exact string in four places -- which is how they drifted --
this compares the edge files against the header the backend actually emits, and
separately refuses scheme wildcards in ``connect-src``.

ONE CAVEAT, and it is the only way this tightening can bite. ``'self'`` covers a
same-origin WebSocket, and the shipped production bundle always uses one:
``getWebSocketUrl()`` (frontend/src/lib/api/client.ts) falls back to
``${protocol}//${window.location.host}/api/v1/ws`` unless ``VITE_WS_URL`` or
``VITE_API_URL`` is set, Vite bakes those at BUILD time, and neither
docker-compose.yml nor frontend/Dockerfile passes a ``VITE_*`` build arg -- so no
shipped build can take the cross-origin branch. Anyone who forks and BUILDS with
``VITE_WS_URL`` pointing at another origin must add that origin to ``connect-src``
explicitly; a scheme source is not the way to do it, and ``'self'`` will not cover
it. Raised by the external review, which was right that the code path
exists and right that a curl 101 handshake does not test browser enforcement.
"""

from __future__ import annotations

import pathlib
import re

import pytest

#: Directives where a wildcard is a real weakening, and where the two sides
#: should agree. ``frame-ancestors`` is deliberately NOT here: the edge allows
#: same-origin framing ('self') and sends X-Frame-Options: SAMEORIGIN to match,
#: while the API sends DENY. That difference is intentional and about the page,
#: not about drift.
_COMPARED = ("connect-src", "script-src", "object-src", "default-src")

#: A scheme-source in connect-src matches every host using that scheme.
_SCHEME_WILDCARD = re.compile(r"^(?:ws|wss|http|https|data|blob):$|^\*$")


def _frontend_dir() -> pathlib.Path | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "frontend"
        if candidate.is_dir():
            return candidate
    return None


_FRONTEND = _frontend_dir()

pytestmark = pytest.mark.skipif(
    _FRONTEND is None,
    reason="frontend/ is not in this checkout (backend-only mount)",
)

_EDGE_FILES = ("Caddyfile", "nginx/http-only.conf", "nginx/ssl.conf")


def _parse(csp: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.split()
        if tokens:
            out[tokens[0]] = tokens[1:]
    return out


def _backend_csp() -> dict[str, list[str]]:
    """The header the API actually emits, read off a real response."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        header = client.get("/health").headers.get("content-security-policy")
    assert header, "the API sent no Content-Security-Policy at all"
    return _parse(header)


def _edge_csps() -> dict[str, dict[str, list[str]]]:
    assert _FRONTEND is not None
    found: dict[str, dict[str, list[str]]] = {}
    for name in _EDGE_FILES:
        path = _FRONTEND / name
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if "Content-Security-Policy" not in line or line.lstrip().startswith("#"):
                continue
            match = re.search(r'"([^"]*default-src[^"]*)"', line)
            if match:
                found[name] = _parse(match.group(1))
                break
    return found


def test_every_edge_config_declares_a_csp() -> None:
    """Guard the guard: a file that stopped matching would be silently skipped."""
    edges = _edge_csps()
    missing = [n for n in _EDGE_FILES if n not in edges]
    assert not missing, (
        f"no Content-Security-Policy found in {missing}. Either the header was "
        "removed -- which is the bug -- or the line no longer matches this "
        "parser, in which case the file is now unchecked."
    )


def test_connect_src_has_no_scheme_wildcards() -> None:
    """``ws:``/``wss:`` in connect-src permit every host, not just this one."""
    offenders: list[str] = []
    for name, csp in _edge_csps().items():
        bad = [s for s in csp.get("connect-src", []) if _SCHEME_WILDCARD.match(s)]
        if bad:
            offenders.append(f"{name}: connect-src {bad}")
    assert not offenders, (
        "a bare scheme source in connect-src matches ANY host, so an injected "
        "script can open a socket to an attacker and stream data out. Same-origin "
        "WebSockets are already covered by 'self' (CSP3), and /api/v1/ws was "
        "confirmed to still handshake without them:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("directive", _COMPARED)
def test_the_edge_is_not_looser_than_the_backend(directive: str) -> None:
    """Any source the edge allows and the API does not is unreviewed drift."""
    backend = _backend_csp()
    if directive not in backend:
        pytest.skip(f"the backend declares no {directive}")
    allowed = set(backend[directive])
    looser: list[str] = []
    for name, csp in _edge_csps().items():
        extra = sorted(set(csp.get(directive, [])) - allowed)
        if extra:
            looser.append(f"{name}: {directive} additionally allows {extra}")
    assert not looser, (
        f"the edge serves the DOCUMENT, so its {directive} is the one that binds "
        "a script on the page. These sources are permitted there but not by the "
        "API, which means a hardening was applied to only one of the two:\n  " + "\n  ".join(looser)
    )
