# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
AdapterResult -> HTTP bridge (Pattern 6)
========================================

Adapter methods RETURN ``AdapterResult(success=False, error_code=...)`` for
many operations instead of raising. An endpoint that returns such a result (or
``result.to_dict()``) verbatim emits **HTTP 200 with success:false** — a failed
operation (often a failed WRITE) that looks like 200 OK to the client. Others
collapse every failure to a flat 502, losing the cause.

``raise_for_adapter_result`` maps a failed result's ``error_code`` to the right
outcome:

* codes with a canonical adapter exception are re-raised as that exception, so
  the central handler in :mod:`app.core.middleware` maps them
  (read-only -> 403, not-found -> 404, timeout -> 504, rate-limit -> 429,
  confirm -> 409, connection/auth/generic -> 502);
* codes that need a status with no canonical exception raise ``HTTPException``
  directly (not-supported -> 501, validation -> 400, policy block -> 403).

Note: upstream auth failure (``AUTH_FAILED``) is **502**, not 401 — the gateway
could not authenticate to the *device*; the API client's own auth is fine, so a
401 would be misleading.

Usage::

    result = await adapter.do_thing(...)
    raise_for_adapter_result(result)   # no-op on success
    return result.data
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConfirmationRequiredError,
    AdapterConnectionError,
    AdapterError,
    AdapterNotFoundError,
    AdapterRateLimitError,
    AdapterReadOnlyError,
    AdapterTimeoutError,
)

# error_code -> canonical adapter exception (mapped to HTTP by middleware).
_CANONICAL: dict[str, type[AdapterError]] = {
    "READ_ONLY": AdapterReadOnlyError,  # 403
    "CONFIRMATION_REQUIRED": AdapterConfirmationRequiredError,  # 409
    "CONFIRM": AdapterConfirmationRequiredError,  # 409
    "NOT_FOUND": AdapterNotFoundError,  # 404
    "TIMEOUT": AdapterTimeoutError,  # 504
    "DIAGNOSTIC_TIMEOUT": AdapterTimeoutError,  # 504
    "RATE_LIMITED": AdapterRateLimitError,  # 429
    "AUTH_FAILED": AdapterAuthenticationError,  # 502 (upstream auth)
    "CONNECTION_FAILED": AdapterConnectionError,  # 502
    "CONNECTION_ERROR": AdapterConnectionError,  # 502
    "NO_SITE": AdapterConnectionError,  # 502 (controller state)
}

# error_code -> explicit HTTP status (no canonical exception exists for these).
_HTTP_STATUS: dict[str, int] = {
    "NOT_SUPPORTED": 501,
    "NOT_IMPLEMENTED": 501,
    "PROTECT_NOT_INSTALLED": 501,
    "UNSUPPORTED_VPN_TYPE": 501,
    "INVALID_VLAN_TAG": 400,
    "INVALID_ALIAS_TYPE": 400,
    "INVALID_CONFIG": 400,
    "MISSING_IDENTIFIER": 400,
    "NO_PARENT_INTERFACE": 400,
    "SERVICE_NOT_ALLOWED": 403,
}


def raise_for_adapter_result(result: Any, *, not_found_ok: bool = False) -> None:
    """Raise the appropriate error for a failed ``AdapterResult``; no-op on success.

    ``not_found_ok`` lets a caller treat a ``NOT_FOUND`` failure as non-fatal
    (returns instead of raising 404) — e.g. an idempotent delete.
    """
    if getattr(result, "success", True):
        return

    code = getattr(result, "error_code", None)
    detail = (
        getattr(result, "error", None)
        or getattr(result, "message", None)
        or "adapter operation failed"
    )

    if not_found_ok and code == "NOT_FOUND":
        return

    exc_type = _CANONICAL.get(code) if code else None
    if exc_type is not None:
        raise exc_type(detail)

    http_status = _HTTP_STATUS.get(code) if code else None
    if http_status is not None:
        raise HTTPException(status_code=http_status, detail=detail)

    # Default — *_FAILED / UNKNOWN / UNEXPECTED_ERROR / unmapped / no code:
    # an upstream/device operation failure -> 502 via the AdapterError handler.
    raise AdapterError(detail)
