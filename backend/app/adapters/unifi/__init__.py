# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN - Ubiquiti UniFi Adapter."""

from app.adapters.unifi.adapter import (
    AdapterReadOnlyError,
    UniFiAdapter,
    _enforce_read_only,
    _is_adapter_read_only,
)
from app.adapters.unifi.client import UniFiClient
from app.adapters.unifi.exceptions import (
    UniFiAPIError,
    UniFiAuthError,
    UniFiConnectionError,
)
from app.adapters.unifi.validators import (
    validate_controller_host,
    validate_mac,
    validate_object_id,
    validate_poe_mode,
    validate_port_idx,
    validate_site,
)

__all__ = [
    "UniFiAdapter",
    "UniFiClient",
    "AdapterReadOnlyError",
    "UniFiAuthError",
    "UniFiAPIError",
    "UniFiConnectionError",
    "validate_site",
    "validate_mac",
    "validate_object_id",
    "validate_port_idx",
    "validate_poe_mode",
    "validate_controller_host",
    "_is_adapter_read_only",
    "_enforce_read_only",
]
