# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Module Manifest
=============================

Module manifest schema defines metadata about a module including:
- Identity (id, name, version)
- Dependencies on other modules
- Capabilities provided
- Device types handled
- Permissions defined
- UI navigation items
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.modules.base import ModuleCapability


class ModuleCategory(StrEnum):
    """Categories for organizing modules."""

    NETWORK = "network"  # Network infrastructure
    SECURITY = "security"  # Security & access control
    SURVEILLANCE = "surveillance"  # Video surveillance
    COMMUNICATION = "communication"  # VoIP, messaging
    AUTOMATION = "automation"  # Rules & automation
    SYSTEM = "system"  # System utilities


@dataclass
class ModuleDependency:
    """
    Defines a dependency on another module.

    Attributes:
        module_id: ID of the required module
        min_version: Minimum version required (semver)
        optional: If True, module works without this dependency
    """

    module_id: str
    min_version: str = "1.0.0"
    optional: bool = False


@dataclass
class ModulePermission:
    """
    Defines a permission provided by the module.

    Permissions follow the format: {module}.{resource}.{action}
    Example: network.vlans.create

    Attributes:
        code: Permission code (e.g., "network.vlans.create")
        name: Human-readable name
        description: Detailed description
        resource: Resource type this permission applies to (optional)
        action: Action type (read, create, update, delete, execute) (optional)
        id: Alias for code - unique permission identifier
    """

    name: str
    description: str
    code: str | None = None
    resource: str | None = None
    action: str | None = None
    id: str | None = None

    def __post_init__(self):
        """Set code from id if not provided."""
        if self.code is None and self.id is not None:
            self.code = self.id
        elif self.id is None and self.code is not None:
            self.id = self.code


@dataclass
class ModuleNavItem:
    """
    Defines a navigation item for the module in the UI.

    Attributes:
        path: URL path (relative to /app/)
        label: Display label
        icon: Icon name (lucide-react icon)
        order: Sort order in navigation
        parent: Parent nav item path (for nested navigation)
        permission: Required permission to see this item
        badge: Optional badge (e.g., notification count)
        id: Unique identifier for the nav item
        children: Child navigation items for nested menus
    """

    path: str
    label: str
    icon: str
    order: int = 0
    parent: str | None = None
    permission: str | None = None
    badge: str | None = None
    id: str | None = None
    children: list["ModuleNavItem"] = field(default_factory=list)


@dataclass
class ModuleWidget:
    """
    Defines a dashboard widget provided by the module.

    Attributes:
        id: Unique widget identifier
        name: Display name
        description: Widget description
        component: Frontend component name
        default_size: Default grid size (small, medium, large)
        supports_refresh: Whether widget supports refresh
        refresh_interval: Default refresh interval in seconds
        permission: Required permission to see this widget
    """

    id: str
    name: str
    description: str
    component: str
    default_size: str = "medium"  # small, medium, large, full
    supports_refresh: bool = True
    refresh_interval: int = 60
    permission: str | None = None


# Alias for backwards compatibility
ModuleDashboardWidget = ModuleWidget


@dataclass
class ModuleFeatureFlag:
    """
    Defines a feature flag for the module.

    Feature flags allow granular control over module features.
    They can be enabled/disabled per organization.

    Attributes:
        id: Unique feature flag identifier
        name: Human-readable name
        description: Detailed description
        default_enabled: Whether enabled by default
    """

    id: str
    name: str
    description: str
    default_enabled: bool = False


@dataclass
class ModuleManifest:
    """
    Complete manifest describing a module.

    The manifest is used by the module system to:
    - Identify and catalog the module
    - Check dependencies before loading
    - Register API routes with proper prefixes
    - Set up permissions
    - Configure UI navigation

    Example:
        manifest = ModuleManifest(
            id="network",
            name="Network Management",
            version="1.0.0",
            description="Manage VLANs, WiFi, switches, and PoE",
            category=ModuleCategory.NETWORK,
            capabilities=[
                ModuleCapability.VLAN_MANAGEMENT,
                ModuleCapability.WIFI_MANAGEMENT,
            ],
            device_types=["switch", "access_point", "router"],
        )
    """

    # ==========================================
    # Identity
    # ==========================================

    id: str
    """Unique module identifier (lowercase, alphanumeric, underscores, hyphens)."""

    name: str
    """Human-readable module name."""

    version: str
    """Module version (semver format: MAJOR.MINOR.PATCH)."""

    description: str
    """Short description of the module."""

    # ==========================================
    # Classification
    # ==========================================

    category: str | ModuleCategory = ModuleCategory.SYSTEM
    """Module category for organization (can be string or ModuleCategory enum)."""

    # ==========================================
    # Requirements
    # ==========================================

    min_core_version: str = "1.0.0"
    """Minimum FreeSDN core version required."""

    dependencies: list[ModuleDependency] = field(default_factory=list)
    """Other modules this module depends on."""

    required_capabilities: list[ModuleCapability] = field(default_factory=list)
    """Capabilities required from other modules."""

    # ==========================================
    # Capabilities
    # ==========================================

    capabilities: list[ModuleCapability] = field(default_factory=list)
    """Capabilities this module provides."""

    device_types: list[str] = field(default_factory=list)
    """Device types this module can manage (switch, camera, phone, etc.)."""

    # ==========================================
    # Permissions
    # ==========================================

    permissions: list[ModulePermission] = field(default_factory=list)
    """Permissions defined by this module."""

    # ==========================================
    # UI Configuration
    # ==========================================

    nav_items: list[ModuleNavItem] = field(default_factory=list)
    """Navigation items for the sidebar."""

    widgets: list[ModuleWidget] = field(default_factory=list)
    """Dashboard widgets provided by this module."""

    icon: str = "Package"
    """Default icon for this module (lucide-react icon name)."""

    color: str = "#6366f1"
    """Theme color for this module (hex color)."""

    # ==========================================
    # Feature Flags
    # ==========================================

    is_core: bool = False
    """If True, module is always loaded and cannot be disabled."""

    is_beta: bool = False
    """If True, module is in beta and may have issues."""

    is_premium: bool = False
    """If True, module requires a premium subscription tier."""

    coming_soon: bool = False
    """If True, the module is a preview that is not ready for production use.
    The admin UI presents it as a non-enableable "Coming soon" entry, and the
    enablement service refuses to turn it on for an organization."""

    # ==========================================
    # Module Configuration
    # ==========================================

    feature_flags: list[ModuleFeatureFlag] = field(default_factory=list)
    """Feature flags for granular control over module features."""

    default_settings: dict[str, Any] = field(default_factory=dict)
    """Default settings for the module."""

    settings_schema: dict[str, Any] | None = None
    """JSON Schema for validating module settings."""

    api_prefix: str | None = None
    """API route prefix for this module (e.g., '/network')."""

    # ==========================================
    # Documentation
    # ==========================================

    docs_url: str | None = None
    """URL to module documentation."""

    changelog_url: str | None = None
    """URL to module changelog."""

    author: str = "FreeSDN Team"
    """Module author/maintainer."""

    license: str = "AGPL-3.0-only"
    """Module license."""

    # ==========================================
    # Methods
    # ==========================================

    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": self.category,
            "min_core_version": self.min_core_version,
            "dependencies": [
                {
                    "module_id": d.module_id,
                    "min_version": d.min_version,
                    "optional": d.optional,
                }
                for d in self.dependencies
            ],
            "capabilities": [c.value for c in self.capabilities],
            "device_types": self.device_types,
            "permissions": [
                {
                    "code": p.code,
                    "name": p.name,
                    "description": p.description,
                    "resource": p.resource,
                    "action": p.action,
                }
                for p in self.permissions
            ],
            "nav_items": [
                {
                    "path": n.path,
                    "label": n.label,
                    "icon": n.icon,
                    "order": n.order,
                    "parent": n.parent,
                    "permission": n.permission,
                }
                for n in self.nav_items
            ],
            "widgets": [
                {
                    "id": w.id,
                    "name": w.name,
                    "description": w.description,
                    "component": w.component,
                    "default_size": w.default_size,
                    "supports_refresh": w.supports_refresh,
                    "refresh_interval": w.refresh_interval,
                    "permission": w.permission,
                }
                for w in self.widgets
            ],
            "icon": self.icon,
            "color": self.color,
            "is_core": self.is_core,
            "is_beta": self.is_beta,
            "is_premium": self.is_premium,
            "coming_soon": self.coming_soon,
            "docs_url": self.docs_url,
            "author": self.author,
            "license": self.license,
        }

    def has_capability(self, capability: ModuleCapability) -> bool:
        """Check if module provides a specific capability."""
        return capability in self.capabilities

    def has_device_type(self, device_type: str) -> bool:
        """Check if module handles a specific device type."""
        return device_type in self.device_types

    def get_permission_codes(self) -> list[str]:
        """Get all permission codes defined by this module."""
        return [p.code for p in self.permissions]

    def __post_init__(self):
        """Validate manifest after initialization."""
        # Validate ID format
        normalized_id = self.id.replace("_", "").replace("-", "")
        if not normalized_id.isalnum():
            raise ValueError(
                f"Module ID '{self.id}' must be alphanumeric with underscores or hyphens"
            )

        # Validate version format (basic semver check)
        parts = self.version.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ValueError(
                f"Module version '{self.version}' must be in semver format (MAJOR.MINOR.PATCH)"
            )
