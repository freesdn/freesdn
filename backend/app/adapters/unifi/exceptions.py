# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi adapter exceptions.

A thin per-vendor layer on top of :mod:`app.adapters.exceptions` so the
write-gate refusal carries a vendor-specific marker class. The
``AdapterReadOnlyError`` follows the reference contract shared
with Omada / Proxmox / OPNsense / pfSense / MikroTik / Hikvision.
"""

from __future__ import annotations

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
)
from app.adapters.exceptions import (
    AdapterReadOnlyError as _BaseAdapterReadOnlyError,
)


class AdapterReadOnlyError(_BaseAdapterReadOnlyError):
    """Raised when a write is refused because ``ADAPTER_READ_ONLY=true``.

    Per the reference dual-gate contract: every destructive
    method on :class:`UniFiAdapter` refuses to execute unless the
    operator (a) clears the global ``ADAPTER_READ_ONLY`` flag in
    settings **and** (b) the caller passes ``force=True``.
    """

    pass


class UniFiAuthError(AdapterAuthenticationError):
    """Raised when the UniFi controller rejects credentials or session."""

    pass


class UniFiAPIError(AdapterError):
    """Raised when a UniFi REST call returns an error response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        meta_rc: str | None = None,
        meta_msg: str | None = None,
    ) -> None:
        super().__init__(message, adapter_id="unifi")
        self.status_code = status_code
        self.meta_rc = meta_rc
        self.meta_msg = meta_msg


class UniFiConnectionError(AdapterConnectionError):
    """Raised when the UniFi controller is unreachable / breaker is OPEN."""

    pass


__all__ = [
    "AdapterReadOnlyError",
    "UniFiAuthError",
    "UniFiAPIError",
    "UniFiConnectionError",
]
