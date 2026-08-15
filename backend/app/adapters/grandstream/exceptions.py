# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Grandstream Adapter Exceptions
==============================================
"""

from __future__ import annotations

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
    AdapterTimeoutError,
)


class GrandstreamError(AdapterError):
    """Base exception for Grandstream adapter errors."""

    def __init__(
        self,
        message: str,
        *,
        adapter_id: str | None = "grandstream",
    ):
        super().__init__(message, adapter_id=adapter_id)


class GrandstreamConnectionError(AdapterConnectionError):
    """Grandstream phone is unreachable."""

    pass


class GrandstreamAuthError(AdapterAuthenticationError):
    """Grandstream phone authentication failed."""

    pass


class GrandstreamApiError(GrandstreamError):
    """Grandstream API returned an error."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        adapter_id: str | None = "grandstream",
    ):
        super().__init__(message, adapter_id=adapter_id)
        self.status_code = status_code


class GrandstreamProvisioningError(GrandstreamError):
    """Error during phone provisioning (XML generation or push)."""

    pass


class GrandstreamTimeoutError(AdapterTimeoutError):
    """Grandstream phone request timed out."""

    pass
