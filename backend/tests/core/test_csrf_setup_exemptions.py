# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The first-install restore path must not 403 on CSRF.

Background
----------
``CSRFMiddleware`` requires a token on every state-changing method, with an
explicit exempt set for the setup wizard, "runs before any session exists". Six
setup routes were listed. Two were not:

    /api/v1/setup/restore            <- the .fsdnvault disaster recovery
    /api/v1/setup/database/migrate   <- the Database step's "Run migrations"

On a brand-new install there is no session cookie yet, so no browser can
possibly present a CSRF token. An operator clicking "Restore from a backup
instead" on the Welcome step, choosing their ``.fsdnvault`` and entering the
passphrase got::

    403 {"error": {"code": 403, "message": "CSRF token missing"}}

before ``restore_from_vault`` was ever entered. That is the worst possible
moment for an unexplained error: the operator has already lost the instance and
that file is their only copy.

What hid it: ``/api/v1/setup/admin`` sits directly beside those two, carries the
IDENTICAL ``require_setup_incomplete`` gate, and WAS exempt -- so the wizard's
happy path worked perfectly and only the recovery path was broken.

Exempting them is bounded by that gate, not by CSRF: ``require_setup_incomplete``
403s the instant a ``super_admin`` exists, so neither route can be used against a
live instance.

These tests drive the real middleware class rather than asserting on the
constant, so a future refactor of the matching logic cannot pass them while
still rejecting the request.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.middleware import CSRFMiddleware

# Every setup route that must work before a session exists.
_SETUP_PRE_SESSION = [
    "/api/v1/setup/status",
    "/api/v1/setup/admin",
    "/api/v1/setup/organization",
    "/api/v1/setup/controllers",
    "/api/v1/setup/modules",
    "/api/v1/setup/complete",
    "/api/v1/setup/restore",
    "/api/v1/setup/database/migrate",
]


@pytest.fixture
def client() -> TestClient:
    """An app carrying the real CSRF middleware and echoing every POST."""
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.post("/{full_path:path}")
    async def _echo(full_path: str) -> dict:
        return {"reached_handler": True}

    return TestClient(app)


# ── The regression ───────────────────────────────────────────────


def test_first_install_restore_is_not_blocked(client: TestClient) -> None:
    """
    The .fsdnvault recovery path. No cookies, no headers -- exactly what a fresh
    browser on a brand-new install sends.
    """
    resp = client.post("/api/v1/setup/restore")
    assert resp.status_code != 403, (
        "CSRF blocked first-install restore; the operator has already lost their "
        "instance at this point and cannot present a token that does not exist"
    )
    assert resp.json()["reached_handler"] is True


def test_run_migrations_is_not_blocked(client: TestClient) -> None:
    resp = client.post("/api/v1/setup/database/migrate")
    assert resp.status_code != 403
    assert resp.json()["reached_handler"] is True


@pytest.mark.parametrize("path", _SETUP_PRE_SESSION)
def test_every_pre_session_setup_route_is_reachable(client: TestClient, path: str) -> None:
    """
    Pin the whole wizard, not just the two that were broken. Any pre-session
    route added later without an exemption fails here rather than in the field.
    """
    resp = client.post(path)
    assert resp.status_code != 403, f"{path} is CSRF-blocked before a session can exist"


# ── The protection that must remain ──────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/devices/",
        "/api/v1/backups/restore",
        "/api/v1/setup/sample-data",
        "/api/v1/setup/controllers/test",
        "/api/v1/auth/sso/providers",
    ],
)
def test_ordinary_state_changing_routes_are_still_protected(client: TestClient, path: str) -> None:
    """
    The exemption must stay narrow. /backups/restore in particular is the
    ORDINARY restore endpoint -- it runs against a live, authenticated instance
    and is a completely different route from the first-install /setup/restore.
    Exempting it would be a real CSRF hole.
    """
    resp = client.post(path)
    assert resp.status_code == 403, f"{path} lost its CSRF protection"


def test_a_setup_prefix_is_not_blanket_exempt(client: TestClient) -> None:
    """
    The exempt set is exact paths, deliberately -- a "/api/v1/setup" prefix rule
    would sweep in the post-login wizard steps that are gated by
    require_setup_authorized rather than require_setup_incomplete.
    """
    assert client.post("/api/v1/setup/anything-else").status_code == 403


def test_safe_methods_were_never_the_issue(client: TestClient) -> None:
    """GET is not CSRF-checked; the failure was specific to the POSTs."""
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.get("/{full_path:path}")
    async def _get(full_path: str) -> dict:
        return {"ok": True}

    assert TestClient(app).get("/api/v1/setup/database").status_code == 200
