# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Adapter Registry
==============================

Central registry for adapter discovery and lookup.
"""

import logging
from typing import Any

from app.adapters.base import AdapterManifest, BaseAdapter
from app.adapters.capabilities import Capability
from app.adapters.exceptions import AdapterNotFoundError

logger = logging.getLogger(__name__)


class AdapterRegistry:
    """
    Central registry for all vendor adapters.

    Provides:
    - Adapter registration and lookup
    - Capability queries across adapters
    - Adapter instantiation with credentials

    Usage:
        # Register adapter
        registry.register(OmadaAdapter)

        # Get adapter class
        adapter_class = registry.get("omada")

        # Create instance
        adapter = registry.create_adapter("omada", host, user, password)
    """

    def __init__(self) -> None:
        """Initialize the registry."""
        self._adapters: dict[str, type[BaseAdapter]] = {}
        self._manifests: dict[str, AdapterManifest] = {}

    def register(self, adapter_class: type[BaseAdapter]) -> None:
        """
        Register an adapter class.

        Args:
            adapter_class: Adapter class to register
        """
        if not hasattr(adapter_class, "manifest"):
            raise ValueError(f"Adapter {adapter_class.__name__} missing manifest")

        manifest = adapter_class.manifest
        adapter_id = manifest.id

        if adapter_id in self._adapters:
            logger.warning("Overwriting existing adapter: %s", adapter_id)

        self._adapters[adapter_id] = adapter_class
        self._manifests[adapter_id] = manifest
        logger.info("Registered adapter: %s (%s)", adapter_id, manifest.name)

    def unregister(self, adapter_id: str) -> bool:
        """
        Unregister an adapter.

        Args:
            adapter_id: Adapter identifier

        Returns:
            bool: True if adapter was removed
        """
        if adapter_id in self._adapters:
            del self._adapters[adapter_id]
            del self._manifests[adapter_id]
            logger.info("Unregistered adapter: %s", adapter_id)
            return True
        return False

    def get(self, adapter_id: str) -> type[BaseAdapter]:
        """
        Get an adapter class by ID.

        Args:
            adapter_id: Adapter identifier

        Returns:
            Adapter class

        Raises:
            AdapterNotFoundError: If adapter not found
        """
        if adapter_id not in self._adapters:
            raise AdapterNotFoundError(
                f"Adapter not found: {adapter_id}",
                adapter_id=adapter_id,
            )
        return self._adapters[adapter_id]

    def get_manifest(self, adapter_id: str) -> AdapterManifest:
        """
        Get adapter manifest by ID.

        Args:
            adapter_id: Adapter identifier

        Returns:
            Adapter manifest

        Raises:
            AdapterNotFoundError: If adapter not found
        """
        if adapter_id not in self._manifests:
            raise AdapterNotFoundError(
                f"Adapter not found: {adapter_id}",
                adapter_id=adapter_id,
            )
        return self._manifests[adapter_id]

    def create_adapter(
        self,
        adapter_id: str,
        host: str,
        username: str,
        password: str,
        **kwargs: Any,
    ) -> BaseAdapter:
        """
        Create an adapter instance.

        Args:
            adapter_id: Adapter identifier
            host: Controller/device host
            username: Authentication username
            password: Authentication password
            **kwargs: Additional configuration

        Returns:
            Configured adapter instance
        """
        adapter_class = self.get(adapter_id)
        return adapter_class(host, username, password, **kwargs)

    def list_adapters(self) -> list[str]:
        """Get list of registered adapter IDs."""
        return list(self._adapters.keys())

    def list_manifests(self) -> list[AdapterManifest]:
        """Get list of all adapter manifests."""
        return list(self._manifests.values())

    def has_adapter(self, adapter_id: str) -> bool:
        """Check if adapter is registered."""
        return adapter_id in self._adapters

    # =========================================================================
    # Capability Queries
    # =========================================================================

    def get_adapters_with_capability(
        self,
        capability: Capability,
        device_type: str | None = None,
    ) -> list[str]:
        """
        Get adapters that support a capability.

        Args:
            capability: Capability to check
            device_type: Optional device type filter

        Returns:
            List of adapter IDs
        """
        result = []

        for adapter_id, manifest in self._manifests.items():
            for dt, caps in manifest.device_types.items():
                if device_type and dt != device_type:
                    continue
                if capability in caps.capabilities:
                    result.append(adapter_id)
                    break

        return result

    def get_adapter_capabilities(
        self,
        adapter_id: str,
        device_type: str | None = None,
    ) -> list[Capability]:
        """
        Get all capabilities for an adapter.

        Args:
            adapter_id: Adapter identifier
            device_type: Optional device type filter

        Returns:
            List of capabilities
        """
        manifest = self.get_manifest(adapter_id)
        capabilities: set[Capability] = set()

        for dt, caps in manifest.device_types.items():
            if device_type and dt != device_type:
                continue
            capabilities.update(caps.capabilities)

        return list(capabilities)

    def get_adapters_for_device_type(self, device_type: str) -> list[str]:
        """
        Get adapters that support a device type.

        Args:
            device_type: Device type (ap, switch, camera, etc.)

        Returns:
            List of adapter IDs
        """
        result = []

        for adapter_id, manifest in self._manifests.items():
            if device_type in manifest.device_types:
                result.append(adapter_id)

        return result

    def get_supported_device_types(self, adapter_id: str) -> list[str]:
        """
        Get device types supported by an adapter.

        Args:
            adapter_id: Adapter identifier

        Returns:
            List of device types
        """
        manifest = self.get_manifest(adapter_id)
        return list(manifest.device_types.keys())

    # =========================================================================
    # Auto-discovery
    # =========================================================================

    def discover_adapters(self) -> list[str]:
        """
        Auto-discover and register adapters.

        Looks for adapters in the adapters directory.

        Returns:
            List of discovered adapter IDs
        """
        discovered = []

        # Import known adapters
        try:
            from app.adapters.omada import OmadaAdapter

            self.register(OmadaAdapter)
            discovered.append("omada")
        except ImportError as e:
            logger.debug("Omada adapter not available: %s", e)

        try:
            from app.adapters.hikvision import HikvisionAdapter

            self.register(HikvisionAdapter)
            discovered.append("hikvision")
        except ImportError as e:
            logger.debug("Hikvision adapter not available: %s", e)

        try:
            from app.adapters.opnsense import OPNsenseAdapter

            self.register(OPNsenseAdapter)
            discovered.append("opnsense")
        except ImportError as e:
            logger.debug("OPNsense adapter not available: %s", e)

        try:
            from app.adapters.pfsense import PfSenseAdapter

            self.register(PfSenseAdapter)
            discovered.append("pfsense")
        except ImportError as e:
            logger.debug("pfSense adapter not available: %s", e)

        try:
            from app.adapters.mikrotik import MikroTikAdapter

            self.register(MikroTikAdapter)
            discovered.append("mikrotik")
        except ImportError as e:
            logger.debug("MikroTik adapter not available: %s", e)

        try:
            from app.adapters.unifi import UniFiAdapter

            self.register(UniFiAdapter)
            discovered.append("unifi")
        except ImportError as e:
            logger.debug("UniFi adapter not available: %s", e)

        try:
            # UniFi Protect coexists with the UniFi Network adapter on
            # the same UOS host; it's a separate registry entry because
            # operators may deploy the two apps independently (Network
            # only / Protect only / both).
            from app.adapters.unifi_protect import UniFiProtectAdapter

            self.register(UniFiProtectAdapter)
            discovered.append("unifi_protect")
        except ImportError as e:
            logger.debug("UniFi Protect adapter not available: %s", e)

        try:
            from app.adapters.openwrt import OpenWRTAdapter

            self.register(OpenWRTAdapter)
            discovered.append("openwrt")
        except ImportError as e:
            logger.debug("OpenWRT adapter not available: %s", e)

        try:
            from app.adapters.freepbx import FreePBXAdapter

            self.register(FreePBXAdapter)
            discovered.append("freepbx")
        except ImportError as e:
            logger.debug("FreePBX adapter not available: %s", e)

        try:
            from app.adapters.grandstream import GrandstreamAdapter

            self.register(GrandstreamAdapter)
            discovered.append("grandstream")
        except ImportError as e:
            logger.debug("Grandstream adapter not available: %s", e)

        try:
            from app.adapters.proxmox import ProxmoxAdapter

            self.register(ProxmoxAdapter)
            discovered.append("proxmox")
        except ImportError as e:
            logger.debug("Proxmox adapter not available: %s", e)

        try:
            from app.adapters.onvif import ONVIFAdapter

            self.register(ONVIFAdapter)
            discovered.append("onvif")
        except ImportError as e:
            logger.debug("ONVIF adapter not available: %s", e)

        try:
            from app.adapters.truenas import TrueNASAdapter

            self.register(TrueNASAdapter)
            discovered.append("truenas")
        except ImportError as e:
            logger.debug("TrueNAS adapter not available: %s", e)

        logger.info("Discovered %d adapters: %s", len(discovered), discovered)
        return discovered


# Global registry instance
adapter_registry = AdapterRegistry()
adapter_registry.discover_adapters()


def get_adapter_registry() -> AdapterRegistry:
    """Get the global adapter registry."""
    return adapter_registry
