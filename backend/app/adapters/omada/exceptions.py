# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Omada adapter exceptions.
"""

from __future__ import annotations

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
    AdapterRateLimitError,
    AdapterTimeoutError,
    ConfigurationError,
    DeviceNotFoundError,
    DeviceOfflineError,
)


class OmadaError(AdapterError):
    """Base exception for Omada errors."""

    def __init__(
        self,
        message: str,
        *,
        error_code: int | None = None,
        adapter_id: str | None = "omada",
    ):
        super().__init__(message, adapter_id=adapter_id)
        self.omada_error_code = error_code


class OmadaConnectionError(AdapterConnectionError):
    """Omada controller is unreachable or unstable."""


class OmadaAuthError(AdapterAuthenticationError):
    """Omada authentication failed."""


class OmadaSessionExpiredError(OmadaAuthError):
    """Omada session is expired and requires re-authentication."""


class OmadaApiError(OmadaError):
    """Omada returned a non-success API response."""


class OmadaValidationError(ConfigurationError):
    """Omada rejected request validation."""


class OmadaAuthorizationError(OmadaError):
    """User is authenticated but lacks permissions."""


class OmadaNotFoundError(DeviceNotFoundError):
    """Requested Omada resource was not found."""


class OmadaRateLimitError(AdapterRateLimitError):
    """Local or remote Omada rate limit exceeded."""


class OmadaTimeoutError(AdapterTimeoutError):
    """Omada request timed out."""


class OmadaDeviceOfflineError(DeviceOfflineError):
    """Target Omada device is offline for requested operation."""


class OmadaUnsupportedVersionError(OmadaError):
    """Controller version is below supported minimum."""
