# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Module System
===========================

The module system provides a pluggable architecture for extending FreeSDN
with optional functionality. Organizations can enable only the modules
they need, keeping the interface clean and resources efficient.

Core Concepts:
- **Module**: A self-contained feature set (network, cameras, voip, etc.)
- **Manifest**: Metadata describing the module (id, name, capabilities)
- **Loader**: Discovers and loads modules at startup
- **Registry**: Tracks loaded modules and their state

Example Usage:
    from app.modules import module_registry

    # Check if a module is enabled for an org
    if module_registry.is_enabled("network", org_id):
        # Use network module features
        pass

    # Get all enabled modules
    modules = module_registry.get_enabled_modules(org_id)
"""

from app.modules.base import BaseModule, ModuleCapability, ModuleState
from app.modules.loader import ModuleLoader
from app.modules.manifest import ModuleDependency, ModuleManifest
from app.modules.registry import ModuleRegistry, module_registry

__all__ = [
    # Base classes
    "BaseModule",
    "ModuleCapability",
    "ModuleState",
    # Manifest
    "ModuleManifest",
    "ModuleDependency",
    # Loader and Registry
    "ModuleLoader",
    "ModuleRegistry",
    "module_registry",
]
