# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Focused tests for OmadaAdapter error translation contract.
"""

from app.adapters.omada.adapter import OmadaAdapter
from app.adapters.omada.exceptions import (
    OmadaAuthorizationError,
    OmadaConnectionError,
    OmadaNotFoundError,
    OmadaRateLimitError,
    OmadaValidationError,
)


def _adapter() -> OmadaAdapter:
    return OmadaAdapter("10.0.0.2", "admin", "secret")


def test_translate_validation_error():
    adapter = _adapter()
    result = adapter._fail_from_exception(
        OmadaValidationError("invalid ssid config"),
        default_error_code="DEFAULT",
    )
    assert result.success is False
    assert result.error_code == "VALIDATION_ERROR"
    assert result.error == "invalid_configuration"


def test_translate_not_found_error():
    adapter = _adapter()
    result = adapter._fail_from_exception(
        OmadaNotFoundError("missing vlan"),
        default_error_code="DEFAULT",
    )
    assert result.success is False
    assert result.error_code == "NOT_FOUND"
    assert result.error == "resource_not_found"


def test_translate_rate_limit_error():
    adapter = _adapter()
    result = adapter._fail_from_exception(
        OmadaRateLimitError("retry later"),
        default_error_code="DEFAULT",
    )
    assert result.success is False
    assert result.error_code == "RATE_LIMITED"
    assert result.error == "rate_limited"


def test_translate_permission_error():
    adapter = _adapter()
    result = adapter._fail_from_exception(
        OmadaAuthorizationError("forbidden"),
        default_error_code="DEFAULT",
    )
    assert result.success is False
    assert result.error_code == "PERMISSION_DENIED"
    assert result.error == "insufficient_permissions"


def test_translate_connection_error():
    adapter = _adapter()
    result = adapter._fail_from_exception(
        OmadaConnectionError("controller unreachable"),
        default_error_code="DEFAULT",
    )
    assert result.success is False
    assert result.error_code == "CONNECTION_ERROR"
    assert result.error == "controller_unreachable"


def test_translate_generic_error_uses_default_code():
    adapter = _adapter()
    result = adapter._fail_from_exception(
        RuntimeError("boom"),
        default_error_code="OPERATION_FAILED",
    )
    assert result.success is False
    assert result.error_code == "OPERATION_FAILED"
    assert result.error == "boom"
