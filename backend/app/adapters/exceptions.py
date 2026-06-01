# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Adapter Exceptions
================================

Custom exceptions for adapter operations.
"""


class AdapterError(Exception):
    """Base exception for all adapter errors."""

    def __init__(self, message: str, adapter_id: str | None = None):
        self.message = message
        self.adapter_id = adapter_id
        super().__init__(self.message)


class AdapterReadOnlyError(AdapterError):
    """Raised when a write is refused because ``ADAPTER_READ_ONLY`` is engaged.

    A POLICY refusal, not an upstream failure: the write was blocked before it
    ever reached the device. The app-level handler maps this to HTTP 403 (with
    the "set ADAPTER_READ_ONLY=false + force=true" guidance) instead of letting
    it surface as an opaque 500/502.
    """

    pass


class AdapterConfirmationRequiredError(AdapterError):
    """Raised when a destructive/irreversible op needs explicit confirmation.

    A policy PRECONDITION, not a failure: the operation is permitted, but the
    caller must opt in per-action with ``confirmed=true`` (the UI shows a
    type-to-confirm dialog). The app-level handler maps this to HTTP 409 with
    ``type=confirmation_required`` so the frontend can prompt and resubmit —
    instead of the op surfacing as an opaque 500.
    """

    pass


class AdapterConnectionError(AdapterError):
    """Raised when connection to device/controller fails."""

    pass


class AdapterAuthenticationError(AdapterError):
    """Raised when authentication fails."""

    pass


class AdapterNotFoundError(AdapterError):
    """Raised when adapter for a vendor is not found."""

    pass


class AdapterTimeoutError(AdapterError):
    """Raised when operation times out."""

    def __init__(
        self,
        message: str,
        adapter_id: str | None = None,
        timeout: float | None = None,
    ):
        super().__init__(message, adapter_id)
        self.timeout = timeout


class AdapterRateLimitError(AdapterError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str,
        adapter_id: str | None = None,
        retry_after: float | None = None,
    ):
        super().__init__(message, adapter_id)
        self.retry_after = retry_after


class CapabilityNotSupportedError(AdapterError):
    """Raised when capability is not supported by adapter."""

    def __init__(
        self,
        message: str,
        adapter_id: str | None = None,
        capability: str | None = None,
    ):
        super().__init__(message, adapter_id)
        self.capability = capability


class DeviceNotFoundError(AdapterNotFoundError):
    """Raised when device is not found.

    Inherits AdapterNotFoundError (not the bare AdapterError) so the central
    handler maps it to 404, not the 502 catch-all. OmadaNotFoundError inherits
    this class, so the fix cascades to the Omada adapter too.
    """

    def __init__(
        self,
        message: str,
        adapter_id: str | None = None,
        device_id: str | None = None,
    ):
        super().__init__(message, adapter_id)
        self.device_id = device_id


class DeviceOfflineError(AdapterError):
    """Raised when device is offline."""

    def __init__(
        self,
        message: str,
        adapter_id: str | None = None,
        device_id: str | None = None,
    ):
        super().__init__(message, adapter_id)
        self.device_id = device_id


class ConfigurationError(AdapterError):
    """Raised when configuration is invalid."""

    pass
