# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Module Pydantic Schemas
=====================================

Request/response schemas for the Module API.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# ==========================================
# Module Manifest Schemas
# ==========================================


class DependencySchema(BaseModel):
    """Module dependency information."""

    module_id: str
    min_version: str
    optional: bool


class PermissionSchema(BaseModel):
    """Permission defined by a module."""

    code: str
    name: str
    description: str
    resource: str | None = None
    action: str | None = None


class NavItemSchema(BaseModel):
    """Navigation item for module."""

    path: str
    label: str
    icon: str
    order: int
    parent: str | None = None
    permission: str | None = None


class WidgetSchema(BaseModel):
    """Dashboard widget provided by module."""

    id: str
    name: str
    description: str
    component: str
    default_size: str
    supports_refresh: bool
    refresh_interval: int
    permission: str | None = None


class ModuleManifestResponse(BaseModel):
    """Module manifest information."""

    id: str
    name: str
    version: str
    description: str
    category: str
    min_core_version: str
    dependencies: list[DependencySchema]
    capabilities: list[str]
    device_types: list[str]
    permissions: list[PermissionSchema]
    nav_items: list[NavItemSchema]
    widgets: list[WidgetSchema]
    icon: str
    color: str
    is_core: bool
    is_beta: bool
    is_premium: bool
    coming_soon: bool = False
    docs_url: str | None = None
    author: str
    license: str


# ==========================================
# Module Status Schemas
# ==========================================


class ModuleStateResponse(BaseModel):
    """Current state of a module."""

    id: str
    name: str
    version: str
    state: str  # unloaded, loading, loaded, running, stopped, error
    error: str | None = None


class ModuleListResponse(BaseModel):
    """List of available modules."""

    modules: list[ModuleManifestResponse]
    total: int


# ==========================================
# Organization Module Schemas
# ==========================================


class OrgModuleRead(BaseModel):
    """Module enablement for an organization."""

    module_id: str
    is_enabled: bool
    enabled_at: datetime | None = None
    disabled_at: datetime | None = None
    settings: dict[str, Any] = Field(default_factory=dict)

    # Include manifest info
    manifest: ModuleManifestResponse | None = None

    model_config = {"from_attributes": True}


class OrgModuleEnable(BaseModel):
    """Request to enable a module for an organization."""

    module_id: str
    settings: dict[str, Any] = Field(default_factory=dict)


class OrgModuleDisable(BaseModel):
    """Request to disable a module for an organization."""

    module_id: str


class OrgModuleSettingsUpdate(BaseModel):
    """Request to update module settings."""

    settings: dict[str, Any]


class OrgModuleListResponse(BaseModel):
    """List of modules for an organization."""

    modules: list[OrgModuleRead]
    total: int


# ==========================================
# Module Navigation & Widgets
# ==========================================


class NavigationResponse(BaseModel):
    """Navigation items for the current organization."""

    items: list[dict[str, Any]]


class WidgetsResponse(BaseModel):
    """Dashboard widgets for the current organization."""

    widgets: list[dict[str, Any]]


# ==========================================
# Module Events
# ==========================================


class ModuleEventRead(BaseModel):
    """Module event log entry."""

    id: str
    organization_id: str | None
    module_id: str
    event_type: str
    timestamp: datetime
    user_id: str | None
    details: dict[str, Any]
    error_message: str | None = None

    model_config = {"from_attributes": True}


class ModuleEventsResponse(BaseModel):
    """List of module events."""

    events: list[ModuleEventRead]
    total: int


# ==========================================
# Feature Flags
# ==========================================


class FeatureFlagRead(BaseModel):
    """Feature flag for a module."""

    module_id: str
    feature_key: str
    is_enabled: bool
    value: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class FeatureFlagUpdate(BaseModel):
    """Request to update a feature flag."""

    is_enabled: bool
    value: dict[str, Any] | None = None


class FeatureFlagsResponse(BaseModel):
    """List of feature flags for a module."""

    flags: list[FeatureFlagRead]
