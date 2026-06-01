# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin Manifest Schema
=====================================

Pydantic model that parses and validates a plugin's plugin.yaml manifest file.
Also provides conversion to the backend ModuleManifest type for registration.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, Field, field_validator, model_validator

from app.modules.manifest import (
    ModuleCategory,
    ModuleManifest,
    ModuleNavItem,
    ModulePermission,
)


class PluginDependency(BaseModel):
    module_id: str
    min_version: str = "1.0.0"
    optional: bool = False


class PluginPermission(BaseModel):
    code: str
    name: str
    description: str = ""


class PluginNavItem(BaseModel):
    path: str
    label: str
    icon: str = "Package"
    order: int = 50


class PluginPublicRoute(BaseModel):
    path: str
    methods: list[str] = Field(default_factory=lambda: ["POST"])

    @field_validator("path")
    @classmethod
    def _validate_path(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("public route path must not contain path traversal")
        if not re.match(r"^/[a-z0-9][a-z0-9/_-]*$", v):
            raise ValueError(
                "public route path must start with '/' and contain only "
                "lowercase alphanumeric characters, hyphens, underscores, and slashes"
            )
        return v.rstrip("/") or "/"

    @field_validator("methods")
    @classmethod
    def _validate_methods(cls, methods: list[str]) -> list[str]:
        allowed = {"POST", "PUT", "PATCH", "DELETE"}
        normalized = [method.upper() for method in methods]
        if not normalized:
            raise ValueError("public route methods must not be empty")
        invalid = sorted({method for method in normalized if method not in allowed})
        if invalid:
            raise ValueError(
                f"public route methods must be one of {sorted(allowed)}; got {invalid}"
            )
        return normalized


class PluginManifest(BaseModel):
    """Parsed and validated content of a plugin's plugin.yaml file."""

    #: Reserved IDs that must not be used by plugins (core module namespaces)
    _RESERVED_IDS: ClassVar[frozenset[str]] = frozenset(
        {
            "admin",
            "auth",
            "api",
            "core",
            "system",
            "devices",
            "alerts",
            "users",
            "settings",
            "backup",
            "vpn",
            "automation",
            "webhooks",
            "ai",
            "collector",
            "integrations",
            "plugins",
            "marketplace",
            "health",
            "status",
            "metrics",
            "internal",
            # Native, full-trust in-tree module namespaces. A plugin must never
            # mount under one of these (id or api_prefix first segment) and
            # masquerade as a first-party module — that breaks the two-tier
            # native-vs-plugin trust boundary. Keep in sync with the in-tree
            # app/modules/* ids.
            "cameras",
            "storage",
            "network",
            "hypervisor",
            "firewall",
            "gateway",
            "voip",
            "access_control",
            "fabric",
        }
    )

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{0,98}[a-z0-9]$")
    name: str = Field(min_length=1, max_length=200)
    version: str
    description: str = Field(default="", max_length=2000)
    author: str = Field(default="", max_length=200)
    license: str = "MIT"
    homepage: str | None = Field(default=None, max_length=500)
    min_core_version: str = "1.0.0"

    dependencies: list[PluginDependency] = []
    entry_point: str = "plugin.py"
    class_name: str

    permissions: list[PluginPermission] = []
    api_prefix: str | None = None
    nav_items: list[PluginNavItem] = []
    public_routes: list[PluginPublicRoute] = []

    event_subscriptions: list[str] = Field(default=[])
    settings_schema: dict[str, Any] | None = None
    python_dependencies: list[str] = Field(default=[], max_length=50)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: str) -> str:
        if v in cls._RESERVED_IDS:
            raise ValueError(f"Plugin ID '{v}' is reserved and cannot be used")
        return v

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ValueError(f"Version '{v}' must be in semver format (MAJOR.MINOR.PATCH)")
        return v

    @field_validator("entry_point")
    @classmethod
    def _validate_entry_point(cls, v: str) -> str:
        if ".." in v or v.startswith("/") or v.startswith("\\"):
            raise ValueError("entry_point must not contain path traversal")
        if not v.endswith(".py"):
            raise ValueError("entry_point must be a .py file")
        if not re.match(r"^[a-zA-Z0-9_/\-]+\.py$", v):
            raise ValueError("entry_point contains invalid characters")
        return v

    @field_validator("class_name")
    @classmethod
    def _validate_class_name(cls, v: str) -> str:
        if not v.isidentifier():
            raise ValueError("class_name must be a valid Python identifier")
        if v.startswith("_"):
            raise ValueError("class_name must not start with an underscore")
        return v

    @field_validator("api_prefix")
    @classmethod
    def _validate_api_prefix(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if ".." in v:
            raise ValueError("api_prefix must not contain path traversal")
        if not re.match(r"^/[a-z0-9][a-z0-9/_-]*$", v):
            raise ValueError(
                "api_prefix must start with '/' and contain only "
                "lowercase alphanumeric characters, hyphens, underscores, and slashes"
            )
        # The first path segment must not collide with a native module / core
        # namespace — otherwise a plugin's routes mount under, e.g.,
        # /api/v1/cameras and read as first-party.
        first_segment = v.strip("/").split("/", 1)[0]
        if first_segment in cls._RESERVED_IDS:
            raise ValueError(
                f"api_prefix '/{first_segment}' is reserved by a native module / core namespace"
            )
        return v

    @model_validator(mode="after")
    def _validate_event_subscriptions(self) -> PluginManifest:
        """Keep plugin event subscriptions inside the contract.

        A plugin may subscribe to its OWN ``plugin.{id}.*`` namespace freely and
        to SPECIFIC native events it wants to react to, but it must not slurp an
        entire native namespace with a recursive ``#`` wildcard (e.g.
        ``device.#`` / ``controller.#``) nor request the bare ``*`` / ``#``
        firehose — that turns the declared-subscription contract into
        platform-wide visibility of native device activity. (The SDK also
        rejects the bare firehose at subscribe time; this fails closed earlier,
        at manifest parse.)
        """
        own_prefix = f"plugin.{self.id}."
        for pattern in self.event_subscriptions:
            p = (pattern or "").strip()
            if not p or p in {"*", "#"}:
                raise ValueError("event_subscriptions must not contain the bare '*' / '#' firehose")
            if p == self.id or p.startswith(own_prefix) or p == f"plugin.{self.id}":
                continue  # own namespace — unrestricted
            if "#" in p:
                raise ValueError(
                    f"event subscription '{p}' uses a recursive '#' wildcard outside the "
                    f"plugin's own 'plugin.{self.id}.*' namespace; subscribe to specific "
                    "native events instead"
                )
        return self

    @field_validator("python_dependencies")
    @classmethod
    def _validate_python_deps(cls, deps: list[str]) -> list[str]:
        # Require exact version pinning (==) for reproducibility and supply-chain safety.
        # Loose specifiers (>=, ~=, !=, etc.) are rejected to prevent transitive upgrades.
        pattern = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*==[a-zA-Z0-9_.]+$")
        for dep in deps:
            dep_stripped = dep.strip()
            if not pattern.match(dep_stripped):
                raise ValueError(
                    f"Dependency '{dep_stripped}' must use exact version pinning "
                    "(e.g., 'requests==2.31.0'). Loose specifiers (>=, ~=, etc.) "
                    "are not allowed for supply-chain safety."
                )
            # Block known dangerous pip options and extras syntax
            if "[" in dep_stripped:
                raise ValueError(f"Dependency extras not allowed: {dep_stripped}")
            if dep_stripped.startswith("-") or ";" in dep_stripped:
                raise ValueError(f"Dependency spec contains disallowed characters: '{dep}'")
        return deps

    @field_validator("homepage")
    @classmethod
    def _validate_homepage(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v.startswith(("http://", "https://")):
            raise ValueError("homepage must be an http:// or https:// URL")
        return v

    @classmethod
    def from_yaml(cls, path: str) -> PluginManifest:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)

    @classmethod
    def from_yaml_string(cls, content: str) -> PluginManifest:
        data = yaml.safe_load(content)
        return cls.model_validate(data)

    def to_module_manifest(self) -> ModuleManifest:
        """Convert plugin.yaml data to ModuleManifest for the module registry."""
        return ModuleManifest(
            id=self.id,
            name=self.name,
            version=self.version,
            description=self.description,
            author=self.author,
            license=self.license,
            category=ModuleCategory.SYSTEM,
            capabilities=[],
            permissions=[
                ModulePermission(code=p.code, name=p.name, description=p.description)
                for p in self.permissions
            ],
            nav_items=[
                ModuleNavItem(path=n.path, label=n.label, icon=n.icon, order=n.order)
                for n in self.nav_items
            ],
            api_prefix=self.api_prefix or f"/{self.id}",
        )
