# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Adapter exception -> HTTP status guard (Pattern 4)
==================================================

The central handlers in ``app.core.middleware.setup_exception_handlers`` map the
canonical adapter exceptions to HTTP statuses (read-only -> 403, confirm -> 409,
not-found -> 404, connection/auth/generic -> 502, timeout -> 504, rate-limit ->
429). Starlette resolves a handler by walking ``type(exc).__mro__`` and taking
the first registered class -- so a vendor exception that does NOT inherit the
right canonical type silently falls through to the ``AdapterError`` catch-all
(502) or the generic handler (500).

This guard replicates that MRO lookup and asserts every categorised adapter
exception (a subclass of ``AdapterError`` whose name names a category) resolves
to the correct status -- preventing new divergent vendor classes from
reintroducing wrong codes (e.g. a write-refusal surfacing as a 502 crash).
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil

import app.adapters as _adapters_pkg
from app.adapters import exceptions as canon

# Canonical type -> HTTP status, mirroring middleware.setup_exception_handlers.
REGISTERED: dict[type, int] = {
    canon.AdapterConnectionError: 502,
    canon.AdapterAuthenticationError: 502,
    canon.AdapterNotFoundError: 404,
    canon.AdapterTimeoutError: 504,
    canon.AdapterRateLimitError: 429,
    canon.AdapterConfirmationRequiredError: 409,
    canon.AdapterReadOnlyError: 403,
    canon.AdapterError: 502,
}

# Categorised by class name -> expected effective HTTP status.
_NAME_RULES = (
    (("readonly", "read_only"), 403),
    (("confirm",), 409),
    (("notfound", "not_found"), 404),
    (("timeout",), 504),
    (("ratelimit", "rate_limit"), 429),
    (("auth",), 502),                       # authentication / authorization
    (("connection", "unreachable"), 502),
)

# Documented intentional exceptions (NOT exception-handler bugs):
#   freepbx read-only is caught inside the adapter and returned as an
#   AdapterResult; it is meant to surface as 423 at the voip API layer
#   (an AdapterResult->HTTP concern, i.e. Pattern 6 -- not this handler).
ALLOWLIST: dict[str, str] = {
    "app.adapters.freepbx.adapter.FreePBXReadOnlyError": (
        "caught internally -> AdapterResult; maps to 423 at the voip API (Pattern 6)"
    ),
}


def _effective_status(cls: type) -> int | None:
    for base in cls.__mro__:
        if base in REGISTERED:
            return REGISTERED[base]
    return None  # -> generic Exception handler -> 500


def _expected_by_name(name: str) -> int | None:
    low = name.lower()
    for keys, status in _NAME_RULES:
        if any(k in low for k in keys):
            return status
    return None


def _iter_adapter_exceptions():
    for mod in pkgutil.walk_packages(
        _adapters_pkg.__path__, _adapters_pkg.__name__ + "."
    ):
        try:
            m = importlib.import_module(mod.name)
        except Exception:
            continue  # optional/heavy adapter deps absent in the test env
        for _, cls in inspect.getmembers(m, inspect.isclass):
            if cls.__module__ != mod.name:
                continue  # only classes DEFINED here
            if not issubclass(cls, canon.AdapterError):
                continue
            yield cls


def test_categorised_adapter_exceptions_map_to_correct_status() -> None:
    violations: list[str] = []
    for cls in _iter_adapter_exceptions():
        expected = _expected_by_name(cls.__name__)
        if expected is None:
            continue
        key = f"{cls.__module__}.{cls.__name__}"
        if key in ALLOWLIST:
            continue
        actual = _effective_status(cls)
        if actual != expected:
            violations.append(
                f"{key}: resolves to {actual} but its name implies {expected} "
                f"(inherit the matching canonical app.adapters.exceptions type)"
            )
    assert not violations, "Adapter exception(s) map to the wrong HTTP status:\n  " + "\n  ".join(
        sorted(violations)
    )


def test_fixed_vendor_exceptions_inherit_canonical_types() -> None:
    """Lock the specific Pattern-4 fixes (divergent vendor classes rebased)."""
    from app.adapters.exceptions import DeviceNotFoundError
    from app.adapters.grandstream.adapter import GrandstreamReadOnlyError
    from app.adapters.hikvision.adapter import (
        AdapterReadOnlyError as HikvisionReadOnly,
    )
    from app.adapters.omada.exceptions import OmadaNotFoundError
    from app.adapters.onvif.adapter import AdapterReadOnlyError as OnvifReadOnly
    from app.adapters.unifi.exceptions import (
        AdapterReadOnlyError as UniFiReadOnly,
    )
    from app.adapters.unifi.exceptions import (
        UniFiAuthError,
        UniFiConnectionError,
    )

    for ro in (HikvisionReadOnly, OnvifReadOnly, GrandstreamReadOnlyError, UniFiReadOnly):
        assert issubclass(ro, canon.AdapterReadOnlyError), ro
    for nf in (DeviceNotFoundError, OmadaNotFoundError):
        assert issubclass(nf, canon.AdapterNotFoundError), nf
    assert issubclass(UniFiAuthError, canon.AdapterAuthenticationError)
    assert issubclass(UniFiConnectionError, canon.AdapterConnectionError)


def test_canonical_contract_is_stable() -> None:
    """Each canonical type must still resolve to its documented status (guards
    against an accidental change to the central handler / hierarchy)."""
    assert _effective_status(canon.AdapterReadOnlyError) == 403
    assert _effective_status(canon.AdapterConfirmationRequiredError) == 409
    assert _effective_status(canon.AdapterNotFoundError) == 404
    assert _effective_status(canon.AdapterTimeoutError) == 504
    assert _effective_status(canon.AdapterRateLimitError) == 429
    assert _effective_status(canon.AdapterConnectionError) == 502
    assert _effective_status(canon.AdapterError) == 502


# ─────────────────────────────────────────────────────────────────────────
# Generic-handler status_code pass-through (UniFi/FreePBX/Grandstream *APIError)
# ─────────────────────────────────────────────────────────────────────────


def _client_raising(exc: Exception):
    """A TestClient over a one-route app whose handler raises ``exc``, with the
    real central exception handlers wired — so we exercise the runtime branch,
    not just the MRO mapping."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.core.middleware import setup_exception_handlers

    app = FastAPI()
    setup_exception_handlers(app)

    @app.get("/boom")
    async def _boom():  # pragma: no cover - body trivial
        raise exc

    return TestClient(app, raise_server_exceptions=False)


def test_api_error_4xx_status_is_surfaced_not_flattened_to_502() -> None:
    """A UniFiAPIError carrying the controller's own 4xx (bad input / conflict /
    not-found) must surface that real status — NOT an opaque 502 — so the
    operator sees the actual reason. Regression for the apply-time finding where
    a 'name already exists' / 'invalid VLAN' controller rejection looked like a
    gateway crash."""
    from app.adapters.unifi.exceptions import UniFiAPIError

    for upstream in (400, 404, 405, 409, 422, 429):
        resp = _client_raising(
            UniFiAPIError("controller rejected request", status_code=upstream)
        ).get("/boom")
        assert resp.status_code == upstream, (
            f"UniFiAPIError(status_code={upstream}) should surface {upstream}, "
            f"got {resp.status_code}"
        )
        assert resp.json()["error"]["code"] == upstream


def test_device_side_auth_status_stays_502_not_surfaced() -> None:
    """A device-side auth failure (401/403/407 — the GATEWAY's stored creds for
    the device are wrong) must NOT surface as a literal 401/403 to the browser:
    the SPA axios interceptor token-refreshes on ANY 401 and can log the operator
    out over an upstream device-credential problem. These stay 502 (gateway
    fault). Guards the generic *APIError catch-all for non-UniFi vendors."""
    from app.adapters.unifi.exceptions import UniFiAPIError

    for upstream in (401, 403, 407):
        resp = _client_raising(
            UniFiAPIError("device rejected our credentials", status_code=upstream)
        ).get("/boom")
        assert resp.status_code == 502, (
            f"device-side {upstream} must stay 502, not surface as {resp.status_code}"
        )


def test_api_error_5xx_or_missing_status_stays_502() -> None:
    """A 5xx from the controller (or no status_code at all) IS a genuine upstream
    fault → stays 502."""
    from app.adapters.unifi.exceptions import UniFiAPIError

    for upstream in (500, 502, 503):
        resp = _client_raising(
            UniFiAPIError("controller exploded", status_code=upstream)
        ).get("/boom")
        assert resp.status_code == 502

    # No status_code → unchanged 502 behaviour.
    resp = _client_raising(UniFiAPIError("opaque failure")).get("/boom")
    assert resp.status_code == 502
