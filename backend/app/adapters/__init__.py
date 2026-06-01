# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Adapter System
============================

Vendor-agnostic adapter framework for device management.

The adapter system provides:
- Base adapter class with standard interface
- Capability system for feature detection
- Adapter registry for lookup
- Vendor-specific implementations (Omada, Hikvision, etc.)
"""

from typing import Any

from app.adapters.base import (
    AdapterDevice,  # Legacy support
    AdapterManifest,
    AdapterResult,
    BaseAdapter,
    DeviceTypeCapabilities,
    DiscoveredDevice,
)
from app.adapters.capabilities import (
    Capability,
    CapabilityCategory,
    get_capabilities_by_category,
    get_capability_category,
)
from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
    AdapterNotFoundError,
    AdapterRateLimitError,
    AdapterTimeoutError,
    CapabilityNotSupportedError,
    ConfigurationError,
    DeviceNotFoundError,
    DeviceOfflineError,
)
from app.adapters.hikvision import HikvisionAdapter
from app.adapters.mikrotik import MikroTikAdapter

# Import vendor adapters (lazy import to avoid circular deps)
from app.adapters.omada import OmadaAdapter
from app.adapters.onvif import ONVIFAdapter
from app.adapters.opnsense import OPNsenseAdapter
from app.adapters.pfsense import PfSenseAdapter
from app.adapters.pool import (
    AdapterConnectionPool,
    PooledConnection,
    PoolStats,
    adapter_pool,
)
from app.adapters.registry import (
    AdapterRegistry,
    adapter_registry,
    get_adapter_registry,
)
from app.adapters.unifi import UniFiAdapter

__all__ = [
    # Base classes
    "BaseAdapter",
    "AdapterManifest",
    "DeviceTypeCapabilities",
    "DiscoveredDevice",
    "AdapterResult",
    "AdapterDevice",
    # Capabilities
    "Capability",
    "CapabilityCategory",
    "get_capabilities_by_category",
    "get_capability_category",
    # Registry
    "AdapterRegistry",
    "adapter_registry",
    "get_adapter_registry",
    # Connection Pool
    "AdapterConnectionPool",
    "PooledConnection",
    "PoolStats",
    "adapter_pool",
    # Exceptions
    "AdapterError",
    "AdapterConnectionError",
    "AdapterAuthenticationError",
    "AdapterNotFoundError",
    "AdapterTimeoutError",
    "AdapterRateLimitError",
    "CapabilityNotSupportedError",
    "DeviceNotFoundError",
    "DeviceOfflineError",
    "ConfigurationError",
    # Vendor adapters
    "OmadaAdapter",
    "HikvisionAdapter",
    "OPNsenseAdapter",
    "PfSenseAdapter",
    "MikroTikAdapter",
    "UniFiAdapter",
    "ONVIFAdapter",
    # Helper functions
    "get_adapter",
]


async def get_adapter(
    adapter_type: str,
    host: str,
    username: str | None = None,
    password: str | None = None,
    **kwargs: Any,
) -> BaseAdapter:
    """
    Get an adapter instance for the given type and credentials.

    Args:
        adapter_type: Adapter type (e.g., 'hikvision', 'omada')
        host: Device/controller host address
        username: Authentication username
        password: Authentication password
        **kwargs: Additional adapter configuration

    Returns:
        Configured and connected adapter instance
    """
    registry = get_adapter_registry()
    adapter = registry.create_adapter(
        adapter_id=adapter_type,
        host=host,
        username=username or "",
        password=password or "",
        **kwargs,
    )
    await adapter.connect()
    return adapter
