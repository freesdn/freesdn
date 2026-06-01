# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Adapter Factory
=============================

Factory for creating controller adapters based on type.

Two surfaces, single source of truth:

* :func:`get_adapter` here returns a **disconnected** adapter. It is
  kept synchronous because ~25 task / service call sites already call
  it that way, and turning them async would be a cross-cutting
  rewrite that has no perf benefit (the call itself is just
  ``Class(...)``; connect lives in ``async with adapter:`` at the
  use site).
* :func:`app.adapters.get_adapter` returns a **connected** adapter
  (async). That is the one ``GatewayServiceBase._get_client`` uses
  via the pool path.

Both surfaces dispatch through the same ``adapter_registry`` /
class map so adding a new vendor is a one-place change.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.adapters.base import BaseAdapter


class AdapterNotFoundError(Exception):
    """Raised when no adapter is found for a controller type."""

    pass


def get_adapter_class(controller_type: str):
    """
    Get the adapter class for a controller type.

    Args:
        controller_type: The type of controller (e.g., 'omada', 'unifi', 'hikvision')

    Returns:
        The adapter class

    Raises:
        AdapterNotFoundError: If no adapter exists for the given type
    """
    # Import here to avoid circular imports
    from app.adapters.hikvision import HikvisionAdapter
    from app.adapters.mikrotik import MikroTikAdapter
    from app.adapters.omada import OmadaAdapter
    from app.adapters.opnsense import OPNsenseAdapter
    from app.adapters.pfsense import PfSenseAdapter
    from app.adapters.proxmox import ProxmoxAdapter
    from app.adapters.unifi import UniFiAdapter

    adapters = {
        "omada": OmadaAdapter,
        "tplink_omada": OmadaAdapter,
        "hikvision": HikvisionAdapter,
        "opnsense": OPNsenseAdapter,
        "pfsense": PfSenseAdapter,
        "mikrotik": MikroTikAdapter,
        "proxmox": ProxmoxAdapter,
        "unifi": UniFiAdapter,
        "ubiquiti": UniFiAdapter,
    }

    adapter_class = adapters.get(controller_type.lower())

    if not adapter_class:
        raise AdapterNotFoundError(
            f"No adapter found for controller type: {controller_type}. "
            f"Available types: {list(adapters.keys())}"
        )

    return adapter_class


def get_adapter(
    controller_type: str, host: str, username: str, password: str, **kwargs
) -> "BaseAdapter":
    """
    Create an adapter instance for a controller. Disconnected — the
    caller is expected to ``async with adapter: ...`` or call
    ``await adapter.connect()`` explicitly.

    Args:
        controller_type: The type of controller
        host: Controller hostname or IP
        username: Authentication username
        password: Authentication password
        **kwargs: Additional adapter-specific arguments

    Returns:
        Configured adapter instance (not yet connected)
    """
    adapter_class = get_adapter_class(controller_type)
    return adapter_class(host=host, username=username, password=password, **kwargs)


def get_available_adapter_types() -> list[str]:
    """Get list of available adapter types."""
    return [
        "omada",
        "tplink_omada",
        "hikvision",
        "opnsense",
        "pfsense",
        "mikrotik",
        "proxmox",
        "unifi",
        "ubiquiti",
    ]
