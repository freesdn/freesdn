# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - FreePBX Adapter Exceptions
=========================================
"""

from __future__ import annotations

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
    AdapterTimeoutError,
)


class FreePBXError(AdapterError):
    """Base exception for FreePBX adapter errors."""

    def __init__(
        self,
        message: str,
        *,
        adapter_id: str | None = "freepbx",
    ):
        super().__init__(message, adapter_id=adapter_id)


class FreePBXConnectionError(FreePBXError, AdapterConnectionError):
    """FreePBX/Asterisk server is unreachable.

    Inherits from ``FreePBXError`` so that adapter-level ``except FreePBXError``
    handlers catch it, *and* from ``AdapterConnectionError`` so middleware still
    maps it to HTTP 502 (upstream connection failure). The MRO is consistent
    because both bases descend from ``AdapterError``.
    """

    pass


class FreePBXAuthError(FreePBXError, AdapterAuthenticationError):
    """FreePBX authentication failed.

    Inherits from ``FreePBXError`` so adapter-level ``except FreePBXError``
    handlers catch it, *and* from ``AdapterAuthenticationError`` so middleware
    still maps it to HTTP 401. The MRO is consistent because both bases descend
    from ``AdapterError``.
    """

    pass


class FreePBXApiError(FreePBXError):
    """FreePBX REST API returned an error."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        adapter_id: str | None = "freepbx",
    ):
        super().__init__(message, adapter_id=adapter_id)
        self.status_code = status_code


# ─── AMI-specific exceptions ────────────────────────────────────────────────


class AMIConnectionError(FreePBXConnectionError):
    """Cannot connect to Asterisk Manager Interface (TCP:5038)."""

    pass


class AMIAuthError(FreePBXAuthError):
    """AMI authentication failed (bad username/secret)."""

    pass


class AMITimeoutError(AdapterTimeoutError):
    """AMI action timed out waiting for response."""

    pass


class AMIProtocolError(FreePBXError):
    """Unexpected AMI protocol message."""

    pass


# ─── ARI-specific exceptions ────────────────────────────────────────────────


class ARIConnectionError(FreePBXConnectionError):
    """Cannot connect to Asterisk REST Interface (HTTP:8088)."""

    pass


class ARIAuthError(FreePBXAuthError):
    """ARI authentication failed."""

    pass


class ARIWebSocketError(FreePBXConnectionError):
    """ARI WebSocket connection error."""

    pass
