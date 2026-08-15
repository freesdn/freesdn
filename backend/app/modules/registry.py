# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Module Registry
=============================

The module registry maintains the state of all loaded modules and provides
methods for querying and managing modules.

The registry is a singleton that is initialized at application startup.
"""

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

from app.modules.base import (
    BaseModule,
    ModuleCapability,
    ModuleNotEnabledError,
    ModuleNotFoundError,
    ModuleState,
)
from app.modules.manifest import ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class ModuleRegistry:
    """
    Registry of all loaded modules.

    The registry maintains:
    - Loaded module instances
    - Module states
    - Organization enablement cache

    Usage:
        # Get a module
        module = module_registry.get_module("network")

        # Check if module is enabled for an org
        if module_registry.is_enabled("network", org_id):
            # Use module
            pass

        # Get all enabled modules for an org
        modules = module_registry.get_enabled_modules(org_id)
    """

    def __init__(self):
        """Initialize empty registry."""
        self._modules: dict[str, BaseModule] = {}
        self._enabled_cache: dict[UUID, set[str]] = {}
        self._initialized = False

    @property
    def initialized(self) -> bool:
        """Check if registry has been initialized."""
        return self._initialized

    @property
    def modules(self) -> dict[str, BaseModule]:
        """Get all loaded modules."""
        return self._modules.copy()

    def register(self, module: BaseModule) -> None:
        """
        Register a module in the registry.

        Args:
            module: Module instance to register

        Raises:
            ValueError: If module with same ID is already registered
        """
        if module.id in self._modules:
            raise ValueError(f"Module '{module.id}' is already registered")

        self._modules[module.id] = module
        logger.info("Registered module: %s v%s", module.id, module.manifest.version)

    def unregister(self, module_id: str) -> None:
        """
        Unregister a module from the registry.

        Args:
            module_id: ID of module to unregister
        """
        if module_id in self._modules:
            del self._modules[module_id]
            logger.info("Unregistered module: %s", module_id)

    def get_module(self, module_id: str) -> BaseModule:
        """
        Get a module by ID.

        Args:
            module_id: ID of the module

        Returns:
            The module instance

        Raises:
            ModuleNotFoundError: If module is not found
        """
        if module_id not in self._modules:
            raise ModuleNotFoundError(module_id)
        return self._modules[module_id]

    def get_module_or_none(self, module_id: str) -> BaseModule | None:
        """
        Get a module by ID or None if not found.

        Args:
            module_id: ID of the module

        Returns:
            The module instance or None
        """
        return self._modules.get(module_id)

    def has_module(self, module_id: str) -> bool:
        """
        Check if a module is registered.

        Args:
            module_id: ID of the module

        Returns:
            True if module is registered
        """
        return module_id in self._modules

    def get_manifest(self, module_id: str) -> ModuleManifest:
        """
        Get a module's manifest.

        Args:
            module_id: ID of the module

        Returns:
            The module manifest

        Raises:
            ModuleNotFoundError: If module is not found
        """
        return self.get_module(module_id).manifest

    def get_all_manifests(self) -> list[ModuleManifest]:
        """
        Get manifests of all registered modules.

        Returns:
            List of all module manifests
        """
        return [m.manifest for m in self._modules.values()]

    # ==========================================
    # Enablement Management
    # ==========================================

    def set_enabled_modules(
        self,
        organization_id: UUID,
        module_ids: set[str],
    ) -> None:
        """
        Set the enabled modules for an organization (cache).

        This is called when loading organization data to populate
        the enablement cache.

        Args:
            organization_id: Organization ID
            module_ids: Set of enabled module IDs
        """
        # Always include core modules
        core_modules = {m.id for m in self._modules.values() if m.manifest.is_core}
        self._enabled_cache[organization_id] = module_ids | core_modules

    def is_enabled(self, module_id: str, organization_id: UUID) -> bool:
        """
        Check if a module is enabled for an organization.

        Args:
            module_id: Module ID to check
            organization_id: Organization ID

        Returns:
            True if module is enabled
        """
        # Core modules are always enabled
        module = self._modules.get(module_id)
        if module and module.manifest.is_core:
            return True

        # Check cache
        enabled = self._enabled_cache.get(organization_id, set())
        return module_id in enabled

    def require_enabled(self, module_id: str, organization_id: UUID) -> BaseModule:
        """
        Get a module, raising if not enabled.

        Args:
            module_id: Module ID
            organization_id: Organization ID

        Returns:
            The module instance

        Raises:
            ModuleNotFoundError: If module doesn't exist
            ModuleNotEnabledError: If module is not enabled
        """
        module = self.get_module(module_id)
        if not self.is_enabled(module_id, organization_id):
            raise ModuleNotEnabledError(module_id, organization_id)
        return module

    def get_enabled_modules(self, organization_id: UUID) -> list[BaseModule]:
        """
        Get all enabled modules for an organization.

        Args:
            organization_id: Organization ID

        Returns:
            List of enabled module instances
        """
        enabled_ids = self._enabled_cache.get(organization_id, set())

        # Add core modules
        modules = []
        for module in self._modules.values():
            if module.manifest.is_core or module.id in enabled_ids:
                modules.append(module)

        return modules

    def get_enabled_module_ids(self, organization_id: UUID) -> set[str]:
        """
        Get IDs of all enabled modules for an organization.

        Args:
            organization_id: Organization ID

        Returns:
            Set of enabled module IDs
        """
        enabled = self._enabled_cache.get(organization_id, set())
        core = {m.id for m in self._modules.values() if m.manifest.is_core}
        return enabled | core

    def clear_enabled_cache(self, organization_id: UUID | None = None) -> None:
        """
        Clear the enabled modules cache.

        Args:
            organization_id: If provided, only clear for this org
        """
        if organization_id:
            self._enabled_cache.pop(organization_id, None)
        else:
            self._enabled_cache.clear()

    # ==========================================
    # Capability Queries
    # ==========================================

    def get_modules_with_capability(
        self,
        capability: ModuleCapability,
        organization_id: UUID | None = None,
    ) -> list[BaseModule]:
        """
        Get modules that provide a specific capability.

        Args:
            capability: The capability to look for
            organization_id: If provided, only return enabled modules

        Returns:
            List of modules with the capability
        """
        modules = []
        for module in self._modules.values():
            if module.manifest.has_capability(capability):
                if organization_id is None or self.is_enabled(module.id, organization_id):
                    modules.append(module)
        return modules

    def get_modules_for_device_type(
        self,
        device_type: str,
        organization_id: UUID | None = None,
    ) -> list[BaseModule]:
        """
        Get modules that handle a specific device type.

        Args:
            device_type: The device type (switch, camera, etc.)
            organization_id: If provided, only return enabled modules

        Returns:
            List of modules handling the device type
        """
        modules = []
        for module in self._modules.values():
            if module.manifest.has_device_type(device_type):
                if organization_id is None or self.is_enabled(module.id, organization_id):
                    modules.append(module)
        return modules

    def has_capability(
        self,
        capability: ModuleCapability,
        organization_id: UUID,
    ) -> bool:
        """
        Check if any enabled module provides a capability.

        Args:
            capability: The capability to check
            organization_id: Organization ID

        Returns:
            True if capability is available
        """
        return len(self.get_modules_with_capability(capability, organization_id)) > 0

    # ==========================================
    # State Management
    # ==========================================

    def get_module_states(self) -> dict[str, ModuleState]:
        """Get states of all modules."""
        return {m.id: m.state for m in self._modules.values()}

    def get_modules_by_state(self, state: ModuleState) -> list[BaseModule]:
        """Get all modules in a specific state."""
        return [m for m in self._modules.values() if m.state == state]

    async def start_module_for_org(
        self,
        module_id: str,
        organization_id: UUID,
        db: "AsyncSession",
    ) -> None:
        """
        Start a module for an organization.

        Args:
            module_id: Module ID
            organization_id: Organization ID
            db: Database session
        """
        module = self.get_module(module_id)
        await module.on_start(organization_id, db)

        # Update cache
        if organization_id not in self._enabled_cache:
            self._enabled_cache[organization_id] = set()
        self._enabled_cache[organization_id].add(module_id)

        logger.info("Started module %s for org %s", module_id, organization_id)

    async def stop_module_for_org(
        self,
        module_id: str,
        organization_id: UUID,
        db: "AsyncSession",
    ) -> None:
        """
        Stop a module for an organization.

        Args:
            module_id: Module ID
            organization_id: Organization ID
            db: Database session
        """
        module = self.get_module(module_id)
        await module.on_stop(organization_id, db)

        # Update cache
        if organization_id in self._enabled_cache:
            self._enabled_cache[organization_id].discard(module_id)

        logger.info("Stopped module %s for org %s", module_id, organization_id)

    # ==========================================
    # Navigation & UI
    # ==========================================

    def get_navigation_items(self, organization_id: UUID) -> list[dict[str, Any]]:
        """
        Get navigation items for enabled modules.

        Args:
            organization_id: Organization ID

        Returns:
            List of navigation item dictionaries, sorted by order
        """
        items = []
        for module in self.get_enabled_modules(organization_id):
            for nav in module.manifest.nav_items:
                items.append(
                    {
                        "module_id": module.id,
                        "path": nav.path,
                        "label": nav.label,
                        "icon": nav.icon,
                        "order": nav.order,
                        "parent": nav.parent,
                        "permission": nav.permission,
                    }
                )

        # Sort by order
        items.sort(key=lambda x: x["order"])
        return items

    def get_dashboard_widgets(self, organization_id: UUID) -> list[dict[str, Any]]:
        """
        Get dashboard widgets for enabled modules.

        Args:
            organization_id: Organization ID

        Returns:
            List of widget dictionaries
        """
        widgets = []
        for module in self.get_enabled_modules(organization_id):
            for widget in module.manifest.widgets:
                widgets.append(
                    {
                        "module_id": module.id,
                        "id": widget.id,
                        "name": widget.name,
                        "description": widget.description,
                        "component": widget.component,
                        "default_size": widget.default_size,
                        "supports_refresh": widget.supports_refresh,
                        "refresh_interval": widget.refresh_interval,
                        "permission": widget.permission,
                    }
                )

        return widgets

    def mark_initialized(self) -> None:
        """Mark the registry as initialized."""
        self._initialized = True
        logger.info("Module registry initialized with %d modules", len(self._modules))


# Global module registry instance
module_registry = ModuleRegistry()
