# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Two bugs the test suite could not see, found by driving the running stack.

Both are the same lesson in different clothes: a green suite plus a green
``curl`` is not the same as a working product, because both were exercising
the shapes the code already expected.

1. THE SESSION COULD NEVER OUTLIVE ONE ACCESS TOKEN
   ``RefreshTokenRequest.refresh_token`` was REQUIRED, while the endpoint
   documents itself as accepting "refresh token from JSON body OR httpOnly
   cookie". A browser has the cookie and nothing to put in the body, so the
   SPA posts ``{}`` -- from the axios 401-interceptor (client.ts) and from the
   auth store (authStore.ts).

   ``{}`` is a PRESENT body that fails validation, so every refresh returned
   422. The interceptor treats a failed refresh as a dead session: it clears
   auth state and drops the user on the login screen.

   Net effect: the access token lives 3600s, and at expiry the mechanism meant
   to renew the session silently ended it instead. Every user was logged out
   an hour in, losing whatever they had open.

   Why nothing caught it: the suite never posts an empty body, and ``curl``
   with NO body at all returns 200 -- so both obvious checks pass. Only a real
   browser sends the one shape that fails. It reproduced identically on
   fastapi 0.138.2 and 0.141.1, so it long predates this release's dependency
   bump.

2. FOUR FIREWALL WRITE PATHS 500'd INSTEAD OF 404'ing
   ``FirewallService._verify_device_org`` raises ``DeviceNotFoundError`` for a
   device that is not a firewall device in the caller's org. The firewall API
   catches its SIBLINGS -- RuleNotFoundError, NATNotFoundError,
   VPNNotFoundError -- but never that one; it is not even imported there.

   So rule create, rule reorder, NAT create and VPN create answered a wrong or
   foreign device id with an opaque 500. Unit tests call the service directly
   and assert the exception, which passes happily -- the gap is in FastAPI's
   handler registration, which only exists in an assembled app.
"""

from __future__ import annotations

import inspect

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.schemas.core import RefreshTokenRequest


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. the refresh body ──────────────────────────────────────────


def test_an_empty_body_validates() -> None:
    """
    The exact payload the SPA sends. This raised ValidationError, which FastAPI
    turned into the 422 that logged everyone out.
    """
    assert RefreshTokenRequest.model_validate({}).refresh_token is None


def test_a_body_carrying_a_token_still_validates() -> None:
    """Non-browser clients that DO put the token in the body must keep working."""
    assert RefreshTokenRequest.model_validate({"refresh_token": "abc"}).refresh_token == "abc"


def test_the_endpoint_accepts_the_shapes_a_browser_actually_sends() -> None:
    """
    Drive it through a real app, because the bug lived in request validation --
    calling the handler directly would never have shown it.
    """
    app = FastAPI()

    @app.post("/refresh")
    async def _refresh(body: RefreshTokenRequest | None = None) -> dict:
        return {"token": body.refresh_token if body else None}

    client = TestClient(app)
    assert client.post("/refresh").status_code == 200  # no body at all (curl)
    assert client.post("/refresh", json={}).status_code == 200  # the SPA's shape
    assert client.post("/refresh", json={"refresh_token": "x"}).status_code == 200


def test_the_handler_still_prefers_the_body_then_falls_back_to_the_cookie() -> None:
    """
    Making the field optional must not change WHICH token is used -- an
    explicit body token still wins over the cookie.
    """
    from app.api.v1.endpoints.auth import refresh_token as refresh_endpoint

    code = _code(refresh_endpoint)
    assert "refresh_data.refresh_token if refresh_data else None" in code
    assert "request.cookies.get(" in code


def test_the_frontend_really_does_post_an_empty_object() -> None:
    """
    Premise. If the SPA ever stops sending ``{}``, this fix becomes belt-and-
    braces rather than load-bearing -- worth knowing rather than assuming.
    """
    import pathlib

    fe = None
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "frontend" / "src" / "lib" / "api" / "client.ts"
        if candidate.is_file():
            fe = candidate
            break
    if fe is None:  # pragma: no cover - backend-only checkout
        pytest.skip("frontend source not present")

    assert "auth/refresh`, {}" in fe.read_text(encoding="utf-8").replace("'", "`")


def test_a_failed_refresh_still_means_something() -> None:
    """
    The fix must not make refresh unconditionally succeed. A garbage token or
    an absent cookie is still a dead session and must still be refused.
    """
    from app.api.v1.endpoints.auth import refresh_token as refresh_endpoint

    code = _code(refresh_endpoint)
    assert "No refresh token provided" in code
    assert "status.HTTP_401_UNAUTHORIZED" in code


# ── 2. the firewall domain exception ─────────────────────────────


def test_the_firewall_domain_error_maps_to_404() -> None:
    """
    Registered on the app, not caught per-endpoint, because
    ``_verify_device_org`` is reached from four different write paths and
    catching it in one of them would leave the other three at 500.
    """
    from app.core import middleware

    code = _code(middleware.setup_exception_handlers)
    assert "FirewallError" in code
    assert "status_code=404" in code


def test_it_is_registered_through_the_real_app_factory() -> None:
    """
    The gap was in handler REGISTRATION, so assert against an assembled app
    rather than the source: a handler that exists but is never registered is
    the same 500.
    """
    from app.core.middleware import setup_exception_handlers
    from app.modules.firewall.service import DeviceNotFoundError, FirewallError

    app = FastAPI()
    setup_exception_handlers(app)

    registered = app.exception_handlers
    assert FirewallError in registered, "no handler registered for FirewallError"

    # DeviceNotFoundError subclasses FirewallError, so the base handler covers
    # it -- and covers the siblings the API already catches, harmlessly.
    assert issubclass(DeviceNotFoundError, FirewallError)


def test_the_handler_returns_404_for_a_raised_device_error() -> None:
    """End to end through Starlette's exception machinery."""
    from app.core.middleware import setup_exception_handlers
    from app.modules.firewall.service import DeviceNotFoundError

    app = FastAPI()
    setup_exception_handlers(app)

    @app.get("/boom")
    async def _boom() -> dict:
        raise DeviceNotFoundError("11111111-1111-1111-1111-111111111111")

    resp = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert resp.status_code == 404, "a foreign/unknown device id still 500s"
    assert resp.json()["error"]["code"] == 404


def test_the_message_does_not_distinguish_foreign_from_absent() -> None:
    """
    404 rather than 403 is deliberate: a device in another org must not be
    distinguishable from one that does not exist, matching the site-grant
    convention used elsewhere.
    """
    from app.core import middleware

    code = _code(middleware.setup_exception_handlers)
    assert '"type": "not_found"' in code


def test_every_verify_device_org_caller_is_covered() -> None:
    """
    Guard the class. A base-class handler covers all four write paths; catching
    the exception in one endpoint would not.
    """
    from app.modules.firewall import service

    src = inspect.getsource(service)
    assert src.count("_verify_device_org(") >= 4


def test_the_api_still_catches_its_siblings_per_endpoint() -> None:
    """
    The pre-existing per-endpoint handling is untouched; the app-level handler
    is a backstop for the one that was missed, not a replacement.
    """
    from app.modules.firewall import api

    code = _code(api)
    for name in ("RuleNotFoundError", "NATNotFoundError", "VPNNotFoundError"):
        assert f"except {name}" in code
