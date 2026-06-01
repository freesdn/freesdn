# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Module Loader
===========================

The module loader discovers and loads modules from the modules directory.

It handles:
- Module discovery
- Dependency resolution
- Load order determination
- Module initialization
"""

import importlib
import importlib.util
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, FastAPI

from app.modules.base import BaseModule, ModuleLoadError, ModuleState
from app.modules.registry import ModuleRegistry, module_registry

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# Built-in modules that are always available
BUILTIN_MODULES = [
    "network",
    "cameras",
    "voip",
    "access_control",
    "firewall",
    "backup",
    "ai",
    "collector",
    "hypervisor",
]

# Modules whose code is consumed by another module and should NOT be
# registered as standalone.  The gateway orchestration code lives in
# app/modules/gateway/ but is loaded by FirewallModule — registering it
# separately would duplicate every orchestration route under /gateway/*.
EXCLUDED_MODULES: set[str] = {"gateway"}


class ModuleLoader:
    """
    Discovers and loads FreeSDN modules.

    The loader scans the modules directory for valid modules,
    resolves dependencies, and loads them in the correct order.

    Usage:
        loader = ModuleLoader()
        await loader.discover_modules()
        await loader.load_all_modules()
        loader.register_routes(app)
    """

    def __init__(
        self,
        registry: ModuleRegistry | None = None,
        modules_path: Path | None = None,
    ):
        """
        Initialize the loader.

        Args:
            registry: Module registry to use (default: global registry)
            modules_path: Path to modules directory (default: app/modules)
        """
        self.registry = registry or module_registry
        self.modules_path = modules_path or Path(__file__).parent
        self._discovered: dict[str, type[BaseModule]] = {}
        self._load_order: list[str] = []

    def discover_modules(self) -> list[str]:
        """
        Discover available modules in the modules directory.

        Looks for directories containing a module.py file with a
        module class that extends BaseModule.

        Returns:
            List of discovered module IDs
        """
        discovered = []

        for module_dir in self.modules_path.iterdir():
            if not module_dir.is_dir():
                continue

            # Skip private directories and known non-module dirs
            if module_dir.name.startswith("_"):
                continue
            if module_dir.name in ("__pycache__",):
                continue

            # Skip modules that are consumed by another module (not standalone)
            if module_dir.name in EXCLUDED_MODULES:
                logger.debug(
                    "Skipping %s: in EXCLUDED_MODULES (loaded by another module)",
                    module_dir.name,
                )
                continue

            # Check for module.py
            module_file = module_dir / "module.py"
            if not module_file.exists():
                logger.debug("Skipping %s: no module.py", module_dir.name)
                continue

            try:
                # Load the module file
                module_class = self._load_module_class(module_dir.name, module_file)
                if module_class:
                    self._discovered[module_dir.name] = module_class
                    discovered.append(module_dir.name)
                    logger.info("Discovered module: %s", module_dir.name)
            except Exception as e:
                logger.error(
                    f"Failed to discover module {module_dir.name}: {e}",
                    exc_info=True,
                )

        return discovered

    def _load_module_class(
        self,
        module_id: str,
        module_file: Path,
    ) -> type[BaseModule] | None:
        """
        Load the module class from a module.py file.

        Args:
            module_id: Module identifier
            module_file: Path to module.py

        Returns:
            Module class or None if not found
        """
        # Create a unique module name
        module_name = f"app.modules.{module_id}.module"

        # Load the module
        spec = importlib.util.spec_from_file_location(module_name, module_file)
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        # Find the module class
        # Look for a class that extends BaseModule
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, BaseModule) and attr is not BaseModule:
                return attr

        # Also check for a 'module' attribute
        if hasattr(module, "module"):
            module_attr = module.module
            if isinstance(module_attr, type) and issubclass(module_attr, BaseModule):
                return module_attr

        logger.warning("No BaseModule subclass found in %s", module_file)
        return None

    def resolve_dependencies(self) -> list[str]:
        """
        Resolve module dependencies and determine load order.

        Uses topological sort to order modules so dependencies
        are loaded first.

        Returns:
            Ordered list of module IDs to load

        Raises:
            ModuleLoadError: If circular dependency detected
        """
        # Build dependency graph
        graph: dict[str, set[str]] = {}
        for module_id, module_class in self._discovered.items():
            # Instantiate temporarily to get manifest
            try:
                instance = module_class()
                deps = {d.module_id for d in instance.manifest.dependencies if not d.optional}
                graph[module_id] = deps
            except Exception as e:
                logger.error("Failed to get dependencies for %s: %s", module_id, e)
                graph[module_id] = set()

        # Topological sort
        self._load_order = self._topological_sort(graph)
        return self._load_order

    def _topological_sort(self, graph: dict[str, set[str]]) -> list[str]:
        """
        Perform topological sort on dependency graph.

        Args:
            graph: Dictionary of module_id -> set of dependencies

        Returns:
            Sorted list of module IDs

        Raises:
            ModuleLoadError: If circular dependency detected
        """
        # Kahn's algorithm
        in_degree: dict[str, int] = dict.fromkeys(graph, 0)

        for node in graph:
            for dep in graph[node]:
                if dep in in_degree:
                    in_degree[node] += 1

        # Start with nodes that have no dependencies
        queue = [node for node, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            node = queue.pop(0)
            result.append(node)

            # Remove edges from this node
            for other, deps in graph.items():
                if node in deps:
                    in_degree[other] -= 1
                    if in_degree[other] == 0:
                        queue.append(other)

        # Check for cycles
        if len(result) != len(graph):
            remaining = set(graph.keys()) - set(result)
            raise ModuleLoadError("unknown", f"Circular dependency detected involving: {remaining}")

        return result

    async def load_module(self, module_id: str) -> BaseModule:
        """
        Load a single module.

        Args:
            module_id: Module ID to load

        Returns:
            Loaded module instance

        Raises:
            ModuleLoadError: If module fails to load
        """
        if module_id not in self._discovered:
            raise ModuleLoadError(module_id, "Module not discovered")

        module_class = self._discovered[module_id]

        try:
            # Instantiate the module
            module = module_class()
            module._state = ModuleState.LOADING

            # Validate dependencies are loaded
            for dep in module.manifest.dependencies:
                if not dep.optional and not self.registry.has_module(dep.module_id):
                    raise ModuleLoadError(
                        module_id, f"Missing required dependency: {dep.module_id}"
                    )

            # Call on_load hook
            await module.on_load()

            # Register in registry
            self.registry.register(module)

            logger.info(f"Loaded module: {module.id} v{module.manifest.version}")
            return module

        except ModuleLoadError:
            raise
        except Exception as e:
            raise ModuleLoadError(module_id, str(e)) from e

    async def load_all_modules(self) -> list[BaseModule]:
        """
        Load all discovered modules in dependency order.

        Returns:
            List of loaded module instances
        """
        if not self._load_order:
            self.resolve_dependencies()

        loaded = []
        for module_id in self._load_order:
            try:
                module = await self.load_module(module_id)
                loaded.append(module)
            except ModuleLoadError as e:
                logger.error(
                    f"Failed to load module {module_id}: {e}",
                    exc_info=True,
                )
                # Continue loading other modules

        self.registry.mark_initialized()
        return loaded

    async def unload_module(self, module_id: str) -> None:
        """
        Unload a module.

        Args:
            module_id: Module ID to unload
        """
        module = self.registry.get_module_or_none(module_id)
        if module:
            await module.on_unload()
            self.registry.unregister(module_id)
            logger.info("Unloaded module: %s", module_id)

    def register_routes(
        self,
        app: FastAPI,
        prefix: str = "/api/v1",
    ) -> None:
        """
        Register module API routes with the FastAPI app.

        Each module's routes are mounted at:
        {prefix}/{module_id}/

        Args:
            app: FastAPI application
            prefix: API prefix (default: /api/v1)
        """
        for module in self.registry.modules.values():
            try:
                router = module.get_router()
                if router:
                    app.include_router(
                        router,
                        prefix=f"{prefix}/{module.id}",
                        tags=[module.name],
                    )
                    logger.info(
                        f"Registered routes for module: {module.id} at {prefix}/{module.id}"
                    )
            except Exception as e:
                logger.error(
                    f"Failed to register routes for {module.id}: {e}",
                    exc_info=True,
                )

    def get_combined_router(self, prefix: str = "") -> APIRouter:
        """
        Get a combined router with all module routes.

        This is an alternative to registering routes directly with the app.

        Args:
            prefix: Optional prefix for all routes

        Returns:
            Combined APIRouter
        """
        combined = APIRouter(prefix=prefix)

        for module in self.registry.modules.values():
            try:
                router = module.get_router()
                if router:
                    combined.include_router(
                        router,
                        prefix=f"/{module.id}",
                        tags=[module.name],
                    )
            except Exception as e:
                logger.error("Failed to get router for %s: %s", module.id, e)

        return combined


async def load_modules(app: FastAPI) -> ModuleLoader:
    """
    Convenience function to discover, load, and register all modules.

    Args:
        app: FastAPI application

    Returns:
        The module loader instance
    """
    loader = ModuleLoader()

    # Discover modules
    discovered = loader.discover_modules()
    logger.info("Discovered %d modules: %s", len(discovered), discovered)

    # Resolve dependencies and load
    await loader.load_all_modules()

    # Register routes
    loader.register_routes(app)

    return loader
