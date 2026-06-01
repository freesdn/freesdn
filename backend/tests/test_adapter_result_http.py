# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for the AdapterResult -> HTTP bridge (Pattern 6).

Asserts raise_for_adapter_result maps each error_code to the correct FINAL HTTP
status -- either via a canonical adapter exception (mapped by the central
middleware handler) or a direct HTTPException for codes with no canonical type.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.adapters import exceptions as exc
from app.adapters.base import AdapterResult
from app.core.adapter_result import raise_for_adapter_result

# Canonical exception -> HTTP status, mirroring app/core/middleware.py.
_CANON_STATUS = {
    exc.AdapterReadOnlyError: 403,
    exc.AdapterConfirmationRequiredError: 409,
    exc.AdapterNotFoundError: 404,
    exc.AdapterTimeoutError: 504,
    exc.AdapterRateLimitError: 429,
    exc.AdapterAuthenticationError: 502,
    exc.AdapterConnectionError: 502,
    exc.AdapterError: 502,
}


def _final_status(e: BaseException) -> int | None:
    if isinstance(e, HTTPException):
        return e.status_code
    for base in type(e).__mro__:
        if base in _CANON_STATUS:
            return _CANON_STATUS[base]
    return None


_CASES = [
    ("READ_ONLY", 403),
    ("CONFIRMATION_REQUIRED", 409),
    ("CONFIRM", 409),
    ("NOT_FOUND", 404),
    ("TIMEOUT", 504),
    ("DIAGNOSTIC_TIMEOUT", 504),
    ("RATE_LIMITED", 429),
    ("AUTH_FAILED", 502),          # upstream auth -> 502, NOT 401
    ("CONNECTION_FAILED", 502),
    ("NO_SITE", 502),
    ("NOT_SUPPORTED", 501),
    ("PROTECT_NOT_INSTALLED", 501),
    ("INVALID_CONFIG", 400),
    ("MISSING_IDENTIFIER", 400),
    ("NO_PARENT_INTERFACE", 400),
    ("SERVICE_NOT_ALLOWED", 403),
    ("VLAN_CREATE_FAILED", 502),   # arbitrary *_FAILED -> 502
    ("SSID_DELETE_FAILED", 502),
    ("TOTALLY_UNMAPPED", 502),     # unknown code -> 502
    (None, 502),                   # no code -> 502
]


@pytest.mark.parametrize("code,expected", _CASES)
def test_error_code_maps_to_status(code: str | None, expected: int) -> None:
    with pytest.raises((HTTPException, exc.AdapterError)) as ei:
        raise_for_adapter_result(AdapterResult.fail("boom", error_code=code))
    assert _final_status(ei.value) == expected


def test_success_is_noop() -> None:
    raise_for_adapter_result(AdapterResult.ok(data={"x": 1}))  # must not raise


def test_not_found_ok_suppresses_404() -> None:
    raise_for_adapter_result(
        AdapterResult.fail("gone", error_code="NOT_FOUND"), not_found_ok=True
    )  # must not raise
    # ...but still raises without the flag:
    with pytest.raises(exc.AdapterNotFoundError):
        raise_for_adapter_result(AdapterResult.fail("gone", error_code="NOT_FOUND"))


def test_detail_is_preserved() -> None:
    with pytest.raises(exc.AdapterReadOnlyError) as ei:
        raise_for_adapter_result(
            AdapterResult.fail("read-only engaged", error_code="READ_ONLY")
        )
    assert "read-only engaged" in str(ei.value)


def test_gateway_write_result_chokepoint() -> None:
    """GatewayService._write_result (the chokepoint for ~30 gateway write
    endpoints) returns a dict on success and RAISES on failure — so a failed
    gateway write no longer surfaces as HTTP 200 with success:false."""
    from app.modules.firewall.gateway_service import GatewayService

    ok = GatewayService._write_result(AdapterResult.ok(data={"id": "abc"}))
    assert ok["success"] is True and ok["vendor_id"] == "abc"

    with pytest.raises((HTTPException, exc.AdapterError)):
        GatewayService._write_result(
            AdapterResult.fail("device unreachable", error_code="CONNECTION_FAILED")
        )
    with pytest.raises(exc.AdapterReadOnlyError):
        GatewayService._write_result(
            AdapterResult.fail("blocked", error_code="READ_ONLY")
        )
