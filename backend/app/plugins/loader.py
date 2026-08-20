# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin Loader
=============================

Handles install, upgrade, uninstall, and runtime loading of third-party
plugins from the filesystem plugin directory.

Plugin directory layout::

    /data/plugins/
        acme-monitoring/
            plugin.yaml
            plugin.py
            requirements.txt
            .venv/              (isolated virtualenv per plugin)
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import logging
import os
import shutil
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile, status

from app.core.config import settings
from app.plugins.schema import PluginManifest
from app.plugins.sdk import (
    FreeSDNPlugin,
    bind_request_caller,
    bind_request_plugin_runtime,
    reset_request_caller,
    reset_request_plugin_runtime,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.plugins import InstalledPlugin

logger = logging.getLogger(__name__)

PLUGIN_DIR = Path(os.getenv("PLUGIN_DIR", "/data/plugins"))
MAX_ZIP_SIZE = 50 * 1024 * 1024
MAX_UNCOMPRESSED_SIZE = 200 * 1024 * 1024


class PluginLoadError(Exception):
    """Raised when a plugin fails to load."""


class PluginLoader:
    """Manages the lifecycle of third-party FreeSDN plugins."""

    def __init__(self) -> None:
        self._loaded: dict[str, FreeSDNPlugin] = {}
        self._plugin_classes: dict[str, type[FreeSDNPlugin]] = {}
        self._active: dict[tuple[str, UUID], FreeSDNPlugin] = {}
        # Track sys.path entries added per plugin for cleanup
        self._plugin_paths: dict[str, list[str]] = {}
        self._registered_routes: set[str] = set()
        # NOTE: per-plugin lifecycle mutex. Install / upgrade /
        # uninstall / enable / disable for the same plugin_id must NOT
        # interleave — concurrent ZIP extraction into the same dir, or a
        # ``stop_plugin_everywhere`` racing with ``install``, can leave the
        # filesystem and ``_loaded`` map in inconsistent states (half-deleted
        # venvs, stale class refs, orphaned sys.path entries). One
        # ``asyncio.Lock`` per plugin_id, lazily created. We also guard
        # creation of the lock-table itself with a single ``_locks_lock``
        # so two concurrent first-time lookups can't both create a Lock
        # for the same plugin_id.
        self._lifecycle_locks: dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()

    def lifecycle_lock(self, plugin_id: str) -> asyncio.Lock:
        """Public accessor for the per-plugin lifecycle lock.

        Callers (e.g. enable/disable endpoints) should
        ``async with plugin_loader.lifecycle_lock(plugin_id):`` around any
        sequence of loader operations they want to be atomic with install /
        upgrade / uninstall. Note: the underlying lock is non-reentrant —
        callers MUST NOT re-acquire it from within an already-held block.
        """
        # Synchronous variant of _lock_for: safe to call without await since
        # both dicts use simple GIL-protected reads; the rare miss is
        # resolved by the async path the first time _lock_for is called for
        # this plugin (e.g. during install). For endpoint code paths the
        # plugin already exists, so the lock is virtually always present.
        lock = self._lifecycle_locks.get(plugin_id)
        if lock is None:
            lock = asyncio.Lock()
            self._lifecycle_locks[plugin_id] = lock
        return lock

    async def _lock_for(self, plugin_id: str) -> asyncio.Lock:
        """Return (creating if needed) the per-plugin lifecycle lock.

        Lazily allocates one ``asyncio.Lock`` per plugin_id. The double-
        check pattern inside the ``_locks_lock`` critical section ensures
        two coroutines that race on the same brand-new plugin still share
        a single Lock.
        """
        lock = self._lifecycle_locks.get(plugin_id)
        if lock is not None:
            return lock
        async with self._locks_lock:
            lock = self._lifecycle_locks.get(plugin_id)
            if lock is None:
                lock = asyncio.Lock()
                self._lifecycle_locks[plugin_id] = lock
            return lock

    # ── Installation ─────────────────────────────────────────────────────────

    async def install_plugin(
        self,
        source: bytes | UploadFile,
        db: AsyncSession,
        installed_by_id: Any,
        source_url: str | None = None,
    ) -> InstalledPlugin:
        """
        Install a plugin from a ZIP archive.

        1. Extract to temp dir, parse plugin.yaml, validate
        2. Check FreeSDN core version compatibility
        3. Create isolated venv, pip install python_dependencies
        4. Copy to PLUGIN_DIR/{plugin_id}/
        5. Load plugin class, call plugin.on_install(db)
        6. Register in DB
        """
        from app.models.plugins import InstalledPlugin

        if isinstance(source, UploadFile):
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = await source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ZIP_SIZE:
                    raise PluginLoadError(
                        f"Plugin archive too large ({total} bytes). "
                        f"Maximum size is {MAX_ZIP_SIZE // (1024 * 1024)} MB."
                    )
                chunks.append(chunk)
            raw = b"".join(chunks)
        else:
            raw = source

        if len(raw) > MAX_ZIP_SIZE:
            raise PluginLoadError(
                f"Plugin archive too large ({len(raw)} bytes). "
                f"Maximum size is {MAX_ZIP_SIZE // (1024 * 1024)} MB."
            )

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            try:
                with zipfile.ZipFile(BytesIO(raw)) as zf:
                    # Check total uncompressed size (zip bomb protection)
                    total_size = sum(zi.file_size for zi in zf.infolist())
                    if total_size > MAX_UNCOMPRESSED_SIZE:
                        raise PluginLoadError(
                            f"Plugin archive uncompressed size too large "
                            f"({total_size} bytes). Maximum is "
                            f"{MAX_UNCOMPRESSED_SIZE // (1024 * 1024)} MB."
                        )

                    # Check for path traversal (zip-slip) before extraction
                    tmp_resolved = tmp.resolve()
                    for member in zf.namelist():
                        target = (tmp / member).resolve()
                        try:
                            target.relative_to(tmp_resolved)
                        except ValueError as exc:
                            raise PluginLoadError(
                                f"ZIP contains path traversal entry: {member}"
                            ) from exc
                    zf.extractall(tmp)
            except zipfile.BadZipFile as exc:
                raise PluginLoadError(f"Invalid ZIP file: {exc}") from exc

            # Find plugin.yaml — may be at root or inside a single subdirectory
            manifest_path = tmp / "plugin.yaml"
            if not manifest_path.exists():
                subdirs = [d for d in tmp.iterdir() if d.is_dir()]
                if len(subdirs) == 1:
                    manifest_path = subdirs[0] / "plugin.yaml"
                    tmp = subdirs[0]

            if not manifest_path.exists():
                raise PluginLoadError("No plugin.yaml found in ZIP archive")

            manifest = PluginManifest.from_yaml(str(manifest_path))
            plugin_dest = PLUGIN_DIR / manifest.id

            # NOTE: serialise lifecycle operations from this point
            # on — everything below mutates the filesystem destination,
            # ``_loaded``, ``_plugin_paths`` and ``_plugin_classes``, all of
            # which must be observed atomically per plugin_id. The lock is
            # acquired INSIDE the TemporaryDirectory context so that ``tmp``
            # remains valid for the ``shutil.copytree(tmp, plugin_dest)``
            # below.
            lifecycle_lock = await self._lock_for(manifest.id)
            async with lifecycle_lock:
                # Check if already installed (upgrade path)
                existing_db = await _get_installed_plugin(db, manifest.id)
                if existing_db and existing_db.status == "installed":
                    raise PluginLoadError(
                        f"Plugin '{manifest.id}' is already installed. "
                        "Use upgrade_plugin() to upgrade."
                    )

                # Ensure plugin dir exists
                PLUGIN_DIR.mkdir(parents=True, exist_ok=True)

                # Copy to destination
                if plugin_dest.exists():
                    shutil.rmtree(plugin_dest)
                shutil.copytree(tmp, plugin_dest)

                # Install python dependencies into isolated venv (in thread to avoid
                # blocking the event loop) only when explicitly enabled.
                if manifest.python_dependencies:
                    if not settings.PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS:
                        raise PluginLoadError(
                            "Plugin declares python_dependencies but runtime dependency "
                            "installs are disabled by policy"
                        )
                    await asyncio.to_thread(
                        _install_python_deps, plugin_dest, manifest.python_dependencies
                    )

                # Load the plugin class
                plugin_instance, plugin_cls, added_paths = _load_plugin_class(plugin_dest, manifest)
                self._plugin_paths[manifest.id] = added_paths
                self._plugin_classes[manifest.id] = plugin_cls

                # Call on_install lifecycle hook
                try:
                    await plugin_instance.on_install(db)
                except Exception as exc:
                    logger.warning("Plugin %s on_install raised: %s", manifest.id, exc)

                # Save to DB
                # Register in memory (must happen before any return)
                self._loaded[manifest.id] = plugin_instance

                if existing_db:
                    existing_db.version = manifest.version
                    existing_db.status = "installed"
                    existing_db.is_active = True
                    existing_db.manifest_cache = manifest.model_dump()
                    await db.commit()
                    return existing_db
                else:
                    record = InstalledPlugin(
                        plugin_id=manifest.id,
                        name=manifest.name,
                        version=manifest.version,
                        description=manifest.description,
                        author=manifest.author,
                        license=manifest.license,
                        homepage=manifest.homepage,
                        installed_by=installed_by_id,
                        installed_from=source_url,
                        plugin_dir=str(plugin_dest),
                        is_active=True,
                        status="installed",
                        manifest_cache=manifest.model_dump(),
                    )
                    db.add(record)
                    await db.commit()
                    await db.refresh(record)

                return record

    async def uninstall_plugin(self, plugin_id: str, db: AsyncSession) -> None:
        """
        Remove a plugin.

        1. Call on_uninstall lifecycle hook
        2. Remove from memory
        3. Delete plugin dir
        4. Mark DB record as uninstalled
        """
        # NOTE: serialise per-plugin lifecycle (see install_plugin).
        lifecycle_lock = await self._lock_for(plugin_id)
        async with lifecycle_lock:
            record = await _get_installed_plugin(db, plugin_id)
            if not record:
                raise PluginLoadError(f"Plugin '{plugin_id}' is not installed")

            await self.stop_plugin_everywhere(plugin_id, db)

            # Call lifecycle hook if loaded
            plugin_instance = self._loaded.get(plugin_id)
            if plugin_instance:
                try:
                    await plugin_instance.on_uninstall(db)
                except Exception as exc:
                    logger.warning("Plugin %s on_uninstall raised: %s", plugin_id, exc)

                del self._loaded[plugin_id]
                self._plugin_classes.pop(plugin_id, None)
                self._registered_routes.discard(plugin_id)

            # Clean up sys.path entries added for this plugin
            for p in self._plugin_paths.pop(plugin_id, []):
                with contextlib.suppress(ValueError):
                    sys.path.remove(p)

            # Remove directory
            plugin_dir = Path(record.plugin_dir)
            if plugin_dir.exists():
                shutil.rmtree(plugin_dir, ignore_errors=True)

            record.status = "uninstalled"
            record.is_active = False
            await db.commit()

    async def upgrade_plugin(
        self,
        plugin_id: str,
        source: bytes | UploadFile,
        db: AsyncSession,
        installed_by_id: Any,
    ) -> InstalledPlugin:
        """Upgrade an installed plugin to a new version."""

        existing = await _get_installed_plugin(db, plugin_id)
        if not existing:
            raise PluginLoadError(f"Plugin '{plugin_id}' is not installed")

        from_version = existing.version

        # Re-install overtop (install_plugin handles this).
        #
        # The "upgrading" marker is COMMITTED before the install runs, so if the
        # install raises -- a corrupt archive, a failed manifest validation, a
        # bad signature -- the exception used to propagate with the row still
        # reading "upgrading". Nothing ever set it back. load_all_plugins only
        # loads rows whose status is "installed", so the plugin was silently
        # dropped at every subsequent startup: a single bad upload permanently
        # disabled a working plugin, and the only visible symptom was that it
        # stopped existing.
        previous_status = existing.status
        previous_active = existing.is_active
        existing.status = "upgrading"
        await db.commit()

        try:
            record = await self.install_plugin(source, db, installed_by_id)
        except Exception:
            # Put the row back the way we found it, then let the caller see the
            # real error. Best-effort: a rollback failure must not mask the
            # original exception.
            try:
                await db.rollback()
                stale = await _get_installed_plugin(db, plugin_id)
                if stale is not None:
                    stale.status = previous_status
                    stale.is_active = previous_active
                    await db.commit()
            except Exception:
                logger.error(
                    "Could not restore plugin %s to status=%r after a failed upgrade; "
                    "it may need to be re-enabled by hand",
                    plugin_id,
                    previous_status,
                    exc_info=True,
                )
            raise

        # Call upgrade hook
        plugin_instance = self._loaded.get(plugin_id)
        if plugin_instance:
            try:
                await plugin_instance.on_upgrade(from_version, db)
            except Exception as exc:
                logger.warning("Plugin %s on_upgrade raised: %s", plugin_id, exc)

        return record

    # ── Loading at startup ────────────────────────────────────────────────────

    async def load_all_plugins(self, db: AsyncSession) -> list[FreeSDNPlugin]:
        """Called at app startup. Load all active installed plugins from DB."""
        from sqlalchemy import select

        from app.models.plugins import InstalledPlugin

        result = await db.execute(
            select(InstalledPlugin).where(
                InstalledPlugin.is_active,
                InstalledPlugin.status == "installed",
            )
        )
        records = result.scalars().all()

        loaded = []
        for record in records:
            plugin_dir = Path(record.plugin_dir)
            if not plugin_dir.exists():
                logger.warning("Plugin dir missing for %s: %s", record.plugin_id, plugin_dir)
                continue
            try:
                manifest = PluginManifest.from_yaml(str(plugin_dir / "plugin.yaml"))
                lifecycle_lock = await self._lock_for(manifest.id)
                async with lifecycle_lock:
                    plugin_instance, plugin_cls, added_paths = _load_plugin_class(
                        plugin_dir, manifest
                    )
                    self._loaded[manifest.id] = plugin_instance
                    self._plugin_classes[manifest.id] = plugin_cls
                    self._plugin_paths[manifest.id] = added_paths
                loaded.append(plugin_instance)
                logger.info("Loaded plugin %s@%s", manifest.id, manifest.version)
            except Exception as exc:
                logger.error("Failed to load plugin %s: %s", record.plugin_id, exc, exc_info=True)

        return loaded

    def register_plugin_routes(self, app: FastAPI, plugin_id: str) -> None:
        """Register a loaded plugin's API routes into the running FastAPI app."""
        if plugin_id in self._registered_routes:
            return
        plugin = self._loaded.get(plugin_id)
        if not plugin:
            return
        router = plugin.get_router()
        if router.routes:
            prefix = self.get_route_prefix(plugin_id)
            app.include_router(
                router,
                prefix=prefix,
                tags=[plugin.manifest.name],
                dependencies=[Depends(self._build_route_guard(plugin_id))],
            )
            self._registered_routes.add(plugin_id)
            logger.info("Registered routes for plugin %s at %s", plugin_id, prefix)

    def unregister_plugin_routes(self, plugin_id: str) -> None:
        """FastAPI route removal is restart-only; keep an explicit no-op stub."""
        logger.debug("Plugin route unregistration requested for %s (restart required)", plugin_id)

    async def load_plugin(self, plugin_id: str, db: AsyncSession) -> FreeSDNPlugin:
        """Load a single installed plugin into memory."""
        record = await _get_installed_plugin(db, plugin_id)
        if not record or record.status == "uninstalled":
            raise PluginLoadError(f"Plugin '{plugin_id}' is not installed")

        plugin_dir = Path(record.plugin_dir)
        if not plugin_dir.exists():
            raise PluginLoadError(f"Plugin directory missing for '{plugin_id}': {plugin_dir}")

        manifest = PluginManifest.from_yaml(str(plugin_dir / "plugin.yaml"))
        # Serialize the load + registry mutation under the per-plugin lifecycle
        # lock so a concurrent install/upgrade/uninstall of the same plugin can't
        # interleave and corrupt the _loaded/_plugin_classes/_plugin_paths maps.
        lifecycle_lock = await self._lock_for(plugin_id)
        async with lifecycle_lock:
            plugin_instance, plugin_cls, added_paths = _load_plugin_class(plugin_dir, manifest)
            self._loaded[plugin_id] = plugin_instance
            self._plugin_classes[plugin_id] = plugin_cls
            self._plugin_paths[plugin_id] = added_paths
        logger.info("Loaded plugin %s@%s", manifest.id, manifest.version)
        return plugin_instance

    async def start_for_org(
        self,
        plugin_id: str,
        organization_id: UUID,
        db: AsyncSession,
    ) -> FreeSDNPlugin:
        """Start a loaded plugin for a specific organization."""
        key = (plugin_id, organization_id)
        existing = self._active.get(key)
        if existing is not None:
            return existing

        template = self._loaded.get(plugin_id)
        plugin_cls = self._plugin_classes.get(plugin_id)
        if template is None or plugin_cls is None:
            raise PluginLoadError(f"Plugin '{plugin_id}' is not loaded")

        runtime_instance = plugin_cls()
        runtime_instance._plugin_dir = template._plugin_dir
        runtime_instance._plugin_manifest_data = template._plugin_manifest_data

        # Build the org-scoped SDK before invoking plugin code so plugins that
        # forget super().on_start() still get a working context.
        runtime_instance._init_context(organization_id, db)
        try:
            await runtime_instance.on_start(organization_id, db)
            runtime_instance.bind_event_subscriptions()
        except Exception:
            with contextlib.suppress(Exception):
                await runtime_instance.on_stop(organization_id, db)
            with contextlib.suppress(Exception):
                from app.plugins.bridges import ai_bridge, automation_bridge

                automation_bridge.unregister_plugin(plugin_id)
                ai_bridge.unregister_plugin_tools(plugin_id)
            raise
        self._active[key] = runtime_instance
        logger.info("Started plugin %s for org %s", plugin_id, organization_id)
        return runtime_instance

    async def stop_for_org(
        self,
        plugin_id: str,
        organization_id: UUID,
        db: AsyncSession | None = None,
    ) -> bool:
        """Stop a running plugin instance for a specific organization."""
        key = (plugin_id, organization_id)
        runtime_instance = self._active.pop(key, None)
        if runtime_instance is None:
            return False

        await runtime_instance.on_stop(organization_id, db)

        if not any(active_plugin_id == plugin_id for active_plugin_id, _ in self._active):
            try:
                from app.plugins.bridges import ai_bridge, automation_bridge

                automation_bridge.unregister_plugin(plugin_id)
                ai_bridge.unregister_plugin_tools(plugin_id)
            except Exception as exc:
                logger.debug("Bridge cleanup for %s: %s", plugin_id, exc)

        logger.info("Stopped plugin %s for org %s", plugin_id, organization_id)
        return True

    async def stop_plugin_everywhere(
        self,
        plugin_id: str,
        db: AsyncSession | None = None,
    ) -> None:
        """Stop a plugin for every org it is currently active in."""
        active_org_ids = [
            org_id for active_plugin_id, org_id in self._active if active_plugin_id == plugin_id
        ]
        for org_id in active_org_ids:
            await self.stop_for_org(plugin_id, org_id, db)

    def is_active_for_org(self, plugin_id: str, organization_id: UUID) -> bool:
        """Return whether the plugin is running for the given organization."""
        return (plugin_id, organization_id) in self._active

    def has_any_active(self, plugin_id: str) -> bool:
        """Return whether the plugin is running for any organization."""
        return any(active_plugin_id == plugin_id for active_plugin_id, _ in self._active)

    def get_active_for_org(self, plugin_id: str, organization_id: UUID) -> FreeSDNPlugin | None:
        """Return the active plugin runtime for the given org, if any."""
        return self._active.get((plugin_id, organization_id))

    def get_any_active(self, plugin_id: str) -> FreeSDNPlugin | None:
        """Return any active runtime for the plugin."""
        for (active_plugin_id, _), plugin in self._active.items():
            if active_plugin_id == plugin_id:
                return plugin
        return None

    def discover_installed_plugins(self) -> list[str]:
        """Scan PLUGIN_DIR for valid plugin directories."""
        if not PLUGIN_DIR.exists():
            return []
        result = []
        for d in PLUGIN_DIR.iterdir():
            if d.is_dir() and (d / "plugin.yaml").exists():
                result.append(d.name)
        return result

    def get_loaded(self) -> dict[str, FreeSDNPlugin]:
        """Return map of currently-loaded plugin instances."""
        return dict(self._loaded)

    def get_active(self) -> dict[tuple[str, UUID], FreeSDNPlugin]:
        """Return map of active per-organization plugin runtime instances."""
        return dict(self._active)

    def get_route_prefix(self, plugin_id: str) -> str:
        """Return the mounted API prefix for the plugin."""
        plugin = self._loaded.get(plugin_id)
        if plugin is None:
            return f"/api/v1/{plugin_id}"
        return f"/api/v1{plugin.manifest.api_prefix or '/' + plugin_id}"

    def _match_public_route(
        self,
        plugin_id: str,
        request_path: str,
        method: str,
    ) -> bool:
        """Return True iff the request targets a manifest-declared public route."""
        from app.plugins.public_auth import normalize_public_route_path

        plugin = self._loaded.get(plugin_id)
        if plugin is None:
            return False

        manifest_data = plugin._plugin_manifest_data
        public_routes = getattr(manifest_data, "public_routes", []) or []
        if not public_routes:
            return False

        prefix = self.get_route_prefix(plugin_id)
        if not request_path.startswith(prefix):
            return False

        local_path = request_path[len(prefix) :] or "/"
        normalized_local_path = normalize_public_route_path(local_path)
        normalized_method = method.upper()
        for public_route in public_routes:
            if (
                normalized_local_path == normalize_public_route_path(public_route.path)
                and normalized_method in public_route.methods
            ):
                return True
        return False

    def _build_route_guard(self, plugin_id: str) -> Any:
        """Build a request-scoped guard for plugin routes.

        FastAPI cannot fully remove plugin routes at runtime, so mounted routes
        must refuse traffic when a plugin is globally disabled or when the
        authenticated caller's organization no longer has an active runtime.
        """

        from app.core.dependencies import get_current_user_optional
        from app.db import get_session
        from app.plugins.public_auth import verify_public_plugin_request

        async def plugin_route_guard(
            request: Request,
            session: Any = Depends(get_session),
            current_user: Any = Depends(get_current_user_optional),
        ) -> Any:
            runtime: FreeSDNPlugin | None = None
            if current_user and getattr(current_user, "organization_id", None):
                runtime = self.get_active_for_org(plugin_id, current_user.organization_id)
                if runtime is None:
                    raise HTTPException(
                        status_code=status.HTTP_410_GONE,
                        detail="Plugin is not active for this organization",
                    )
            elif current_user:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Plugin routes require organization context",
                )
            else:
                if not self._match_public_route(plugin_id, request.url.path, request.method):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required for this plugin route",
                    )
                public_request = await verify_public_plugin_request(
                    request,
                    session,
                    plugin_id,
                )
                runtime = self.get_active_for_org(plugin_id, public_request.organization_id)
                if runtime is None:
                    raise HTTPException(
                        status_code=status.HTTP_410_GONE,
                        detail="Plugin is not active for this organization",
                    )

            if runtime is None and not self.has_any_active(plugin_id):
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Plugin is disabled or unavailable",
                )

            if runtime is None:
                yield
                return

            token = bind_request_plugin_runtime(runtime)
            # bind the authenticated caller so privileged SDK ops run with
            # plugin ∩ caller authority (confused-deputy guard). Public/HMAC routes
            # have no current_user → caller stays unbound (plugin authority).
            caller_token = bind_request_caller(current_user) if current_user else None
            # (site-grant): this route guard authenticates via
            # get_current_user_optional, which (unlike get_current_user) does NOT
            # publish the caller into current_user_var — so the SDK's site-grant
            # primitives (site_ids_for_request / assert_site_access_for_request)
            # would no-op and a SITE-LIMITED operator could read/mutate sibling-
            # site devices and alerts through a plugin route. Publish the caller
            # here so those primitives enforce the per-user site grant; reset in
            # finally. Public/HMAC/automation routes have no current_user → the
            # contextvar stays unbound (plugin acts with its own authority).
            from app.core.site_access import current_user_var

            site_token = current_user_var.set(current_user) if current_user else None
            try:
                yield
            finally:
                reset_request_plugin_runtime(token)
                if caller_token is not None:
                    reset_request_caller(caller_token)
                if site_token is not None:
                    current_user_var.reset(site_token)

        return plugin_route_guard


# ── Module-level singleton ────────────────────────────────────────────────────

plugin_loader = PluginLoader()


# ── Internal helpers ──────────────────────────────────────────────────────────


async def _get_installed_plugin(db: AsyncSession, plugin_id: str) -> InstalledPlugin | None:
    from sqlalchemy import select

    from app.models.plugins import InstalledPlugin

    result = await db.execute(select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id))
    return result.scalar_one_or_none()


def _install_python_deps(plugin_dir: Path, deps: list[str]) -> None:
    """Create isolated venv and install python dependencies.

    NOTE: supply-chain hardening.

    Plugins that declare Python deps MUST now ship a ``requirements.txt``
    file (alongside ``plugin.yaml``) that pins every dependency to a
    specific version AND a sha256 hash::

        requests==2.31.0 \
            --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f

    The shipped file is used verbatim with ``pip install
    --require-hashes`` so a typo-squatted package on PyPI cannot be
    silently substituted. The index URL is pinned to
    ``settings.PLUGIN_PYPI_INDEX_URL`` and ``--no-cache-dir`` is set so
    cached attacker artifacts on the host can't poison the install.

    If ``settings.PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS`` is False this
    function is unreachable (the caller raises before getting here).

    TODO: document the lockfile requirement in the plugin SDK docs.
    """
    venv_dir = plugin_dir / ".venv"
    shipped_req = plugin_dir / "requirements.txt"

    # The plugin MUST ship a hash-pinned requirements.txt. If it doesn't,
    # refuse the install: the legacy "synthesize requirements.txt from the
    # manifest's python_dependencies list" path generated unhashed pins
    # like ``requests>=2.0`` and ran them straight through pip, which is
    # the exact supply-chain hole this fix closes.
    if not shipped_req.exists():
        raise PluginLoadError(
            "Plugin declares python_dependencies but ships no "
            "requirements.txt with hash pins. Generate one with "
            "`pip-compile --generate-hashes` and include it in the "
            "plugin archive alongside plugin.yaml."
        )

    req_text = shipped_req.read_text(encoding="utf-8", errors="replace")
    if "--hash=" not in req_text:
        raise PluginLoadError(
            "Plugin requirements.txt is missing --hash= annotations. "
            "FreeSDN requires every dependency to be pinned by sha256. "
            "Regenerate with `pip-compile --generate-hashes`."
        )

    # Sanity check the manifest deps against the requirements file. We
    # don't try to parse hashes; we just confirm each manifest entry
    # appears somewhere in the file so a plugin can't list `requests` in
    # the manifest but quietly install `evil-package` via requirements.txt.
    # (The reverse — file contains deps not in manifest — is allowed for
    # transitives the manifest author chose to pin explicitly.)
    req_lower = req_text.lower()
    for dep in deps:
        # Extract the bare distribution name from manifest entries like
        # "requests>=2.0" or "requests[socks]==2.31.0".
        name = dep
        for sep in ("[", "=", ">", "<", "!", "~", ";", " "):
            idx = name.find(sep)
            if idx >= 0:
                name = name[:idx]
        name = name.strip().lower()
        if name and name not in req_lower:
            raise PluginLoadError(
                f"Plugin manifest declares dependency '{dep}' but it is "
                f"not present in the shipped requirements.txt. Regenerate "
                f"the lockfile to match the manifest."
            )

    # Create venv
    try:
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            check=True,
            capture_output=True,
        )
        pip = venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / "pip"
        # --require-hashes:   every package must have at least one
        #                     --hash= annotation in the requirements file.
        # --no-deps:          transitive resolution off — the lockfile
        #                     must already enumerate every package.
        # --no-cache-dir:     do not reuse cached wheels from the host
        #                     (defeats local-cache poisoning).
        # --only-binary :all: never run setup.py from a sdist — sdists
        #                     execute arbitrary Python at install time.
        # --index-url pinned: a future-deprecated extra-index-url won't
        #                     be silently consulted; only this one is.
        # --no-input:         pip 23+ defaults to interactive in some
        #                     code paths, which would hang the worker.
        subprocess.run(
            [
                str(pip),
                "install",
                "--require-hashes",
                "--no-deps",
                "--no-cache-dir",
                "--only-binary",
                ":all:",
                "--index-url",
                settings.PLUGIN_PYPI_INDEX_URL,
                "--no-input",
                "-r",
                str(shipped_req),
                "--quiet",
            ],
            check=True,
            capture_output=True,
            timeout=180,
        )
        logger.info(
            "Installed hashed Python deps for plugin at %s (manifest: %d entries)",
            plugin_dir,
            len(deps),
        )
    except subprocess.CalledProcessError as exc:
        stderr = (
            (exc.stderr or b"").decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else str(exc.stderr or "")
        )
        logger.error("Plugin dependency installation failed: %s", stderr)
        raise PluginLoadError(
            "Failed to install plugin dependencies — check that every "
            "package in requirements.txt has a valid --hash= sha256 pin."
        ) from exc


def _load_plugin_class(
    plugin_dir: Path,
    manifest: PluginManifest,
) -> tuple[FreeSDNPlugin, type[FreeSDNPlugin], list[str]]:
    """Dynamically import the plugin's entry point and instantiate the class.

    Plugin code is loaded behind a load-time import-hygiene guard that
    refuses imports of OS/process/network modules and trims the plugin's
    builtins (no raw ``exec``/``eval``/``__import__``/``open``). See
    ``sandbox.py`` for what this does and does not protect against — it is
    tripwire-level hygiene, not a real security sandbox. Plugins run in
    the same Python process as the backend and must only be installed
    from trusted sources.
    """
    from app.plugins.sandbox import (
        PluginSecurityError,
        plugin_import_guard,
        restrict_plugin_builtins,
    )
    from app.plugins.sdk_alias import install_freesdn_sdk_alias

    # Validate entry_point does not escape plugin directory
    entry_path = (plugin_dir / manifest.entry_point).resolve()
    plugin_dir_resolved = plugin_dir.resolve()
    try:
        entry_path.relative_to(plugin_dir_resolved)
    except ValueError as exc:
        raise PluginLoadError(
            f"Entry point '{manifest.entry_point}' escapes plugin directory"
        ) from exc
    if not entry_path.exists():
        raise PluginLoadError(f"Entry point '{manifest.entry_point}' not found in {plugin_dir}")

    # Add plugin venv site-packages to sys.path if it exists
    # Append (not insert) to avoid shadowing core application modules
    added_paths: list[str] = []
    venv_site = plugin_dir / ".venv" / "lib"
    if venv_site.exists():
        for sp in venv_site.glob("python*/site-packages"):
            sp_str = str(sp)
            if sp_str not in sys.path:
                sys.path.append(sp_str)
                added_paths.append(sp_str)

    # Load the module behind the load-time import-hygiene guard.
    # This is NOT a security boundary — see sandbox.py.
    spec = importlib.util.spec_from_file_location(
        f"freesdn_plugin_{manifest.id}",
        entry_path,
    )
    if not spec or not spec.loader:
        raise PluginLoadError(f"Failed to create module spec for {entry_path}")

    mod = importlib.util.module_from_spec(spec)

    # Restrict builtins BEFORE executing module code
    restrict_plugin_builtins(mod, manifest.id)

    # Alias `freesdn_sdk` -> the runtime impls so a plugin authored against the
    # published dev SDK (`from freesdn_sdk import FreeSDNPlugin`) loads + gets
    # the real BaseModule-backed base + injected ctx.
    install_freesdn_sdk_alias()

    try:
        with plugin_import_guard(manifest.id):
            spec.loader.exec_module(mod)
    except PluginSecurityError:
        raise  # Re-raise security violations as-is
    except Exception as exc:
        raise PluginLoadError(f"Failed to load plugin {manifest.id}: {exc}") from exc

    cls = getattr(mod, manifest.class_name, None)
    if cls is None:
        raise PluginLoadError(f"Class '{manifest.class_name}' not found in {entry_path}")
    if not issubclass(cls, FreeSDNPlugin):
        raise PluginLoadError(f"Class '{manifest.class_name}' must extend FreeSDNPlugin")

    instance = cls()
    instance._plugin_dir = plugin_dir
    instance._plugin_manifest_data = manifest
    return instance, cls, added_paths
