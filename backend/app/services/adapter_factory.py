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

from typing import TYPE_CHECKING, Any

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


def build_adapter_for_controller(controller: Any) -> "BaseAdapter":
    """
    Build a configured adapter from a ``Controller`` ROW.

    ``get_adapter`` above takes four separate positional arguments
    (controller_type, host, username, password) and is SYNCHRONOUS. That shape
    is easy to get wrong from a service that only has the ORM row, and it was:
    ``reconciliation_service._push_vlan_to_controller`` called
    ``await get_adapter(ctrl, self.db)``, which raises TypeError before a single
    packet reaches the device. Every VLAN push to a controller limb therefore
    failed 100% of the time, and since a UniFi/Omada device can ONLY appear in a
    role map as a controller assignment, that was the whole cross-vendor
    distribution case.

    This helper is the safe form: hand it the row, get a ready adapter. It also
    carries the two details a caller reliably forgets -- decrypting the stored
    secrets, and passing the cloud-mode OAuth2 fields for a cloud-connected
    Omada controller.
    """
    cloud_kwargs: dict[str, Any] = {}
    if getattr(controller, "connection_mode", None) == "cloud":
        cloud_kwargs = {
            "client_id": getattr(controller, "client_id", "") or "",
            "client_secret": _decrypt_secret(getattr(controller, "client_secret", None)),
            "omada_id": getattr(controller, "omada_id", "") or "",
            "cloud_region": getattr(controller, "cloud_region", None) or "us",
        }

    return get_adapter(
        controller_type=controller.controller_type,
        host=controller.host,
        username=getattr(controller, "username", "") or "",
        password=_decrypt_secret(getattr(controller, "password", None)),
        port=getattr(controller, "port", None),
        use_ssl=getattr(controller, "use_ssl", True),
        verify_ssl=getattr(controller, "verify_ssl", False),
        mode=getattr(controller, "connection_mode", None) or "local",
        **cloud_kwargs,
    )


def _decrypt_secret(value: str | None) -> str:
    """Plaintext for a stored controller secret, tolerating already-plain values."""
    from app.core.crypto import decrypt_credential, is_encrypted

    if not value:
        return ""
    if not is_encrypted(value):
        return value
    try:
        return decrypt_credential(value)
    except ValueError:
        return value


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
