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

from app import __version__ as CORE_VERSION
from app.core.config import settings
from app.core.middleware import invalidate_route_cache
from app.plugins.schema import PluginManifest
from app.plugins.sdk import (
    FreeSDNPlugin,
    bind_request_caller,
    bind_request_plugin_runtime,
    reset_request_caller,
    reset_request_plugin_runtime,
)
from app.plugins.supervision import PluginNotReady, supervisor

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.plugins import InstalledPlugin

logger = logging.getLogger(__name__)

PLUGIN_DIR = Path(os.getenv("PLUGIN_DIR", "/data/plugins"))
MAX_ZIP_SIZE = 50 * 1024 * 1024
MAX_UNCOMPRESSED_SIZE = 200 * 1024 * 1024


class PluginLoadError(Exception):
    """Raised when a plugin fails to load."""


def _version_tuple(value: str) -> tuple[int, ...] | None:
    """Parse a dotted version into comparable ints, or None if it is not one.

    Tolerant on purpose: a trailing suffix like "1.2.0-beta" compares on its
    numeric head. Returns None for anything with no leading number at all,
    which the caller treats as "cannot judge" rather than "incompatible".
    """
    parts: list[int] = []
    for chunk in str(value).strip().split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) or None


def _check_core_compatibility(manifest: PluginManifest) -> None:
    """Refuse a plugin that declares it needs a newer core than this one.

    install_plugin has advertised "Check FreeSDN core version compatibility" as
    step 2 since it was written, and never did it: min_core_version was parsed
    into the manifest schema and then read by nobody. A plugin declaring
    min_core_version 99.0.0 installed cleanly on core 26.08.2, and the operator
    found out when it failed at runtime against an API that did not exist yet.

    Fails OPEN on an unparseable version. This is a compatibility hint from the
    author, not a security control, and refusing to install a working plugin
    because its metadata has an unusual version string would trade a real
    failure for a cosmetic one.
    """
    required_raw = getattr(manifest, "min_core_version", None)
    if not required_raw:
        return
    required = _version_tuple(required_raw)
    current = _version_tuple(CORE_VERSION)
    if required is None or current is None:
        logger.warning(
            "Plugin %s declares min_core_version=%r which cannot be compared "
            "against core %r; allowing the install.",
            manifest.id,
            required_raw,
            CORE_VERSION,
        )
        return
    # Compare on the shorter length so 26.8 and 26.8.2 do not disagree.
    width = min(len(required), len(current))
    if current[:width] < required[:width]:
        raise PluginLoadError(
            f"Plugin '{manifest.id}' requires FreeSDN {required_raw} or newer, "
            f"but this instance is {CORE_VERSION}."
        )


async def _read_plugin_source(source: Any) -> bytes:
    """Return the archive bytes for a plugin install, from bytes or an upload.

    Test for BYTES, not for UploadFile.

    ``isinstance(source, UploadFile)`` looks correct and is not. FastAPI's
    UploadFile is a SUBCLASS of starlette's, and the multipart parser hands the
    endpoint a ``starlette.datastructures.UploadFile`` -- so an isinstance check
    against the fastapi child is always False. Every uploaded archive therefore
    skipped the streaming read, fell through to the raw object, and died on
    ``len(raw)`` with "object of type 'UploadFile' has no len()". Plugin install
    by upload, the primary install path, returned 500 for every file.

    Duck-typing on the bytes side is the durable fix: anything that is not
    already bytes is treated as an async file-like, which covers both UploadFile
    classes and any future replacement.
    """
    if isinstance(source, bytes | bytearray):
        raw = bytes(source)
        if len(raw) > MAX_ZIP_SIZE:
            raise PluginLoadError(
                f"Plugin archive too large ({len(raw)} bytes). "
                f"Maximum size is {MAX_ZIP_SIZE // (1024 * 1024)} MB."
            )
        return raw

    if not hasattr(source, "read"):
        raise PluginLoadError(f"Unsupported plugin source type: {type(source).__name__}")

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await source.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        # Checked per chunk so an oversized upload is refused while it streams,
        # rather than after the whole thing is already in memory.
        if total > MAX_ZIP_SIZE:
            raise PluginLoadError(
                f"Plugin archive too large ({total} bytes). "
                f"Maximum size is {MAX_ZIP_SIZE // (1024 * 1024)} MB."
            )
        chunks.append(chunk)
    return b"".join(chunks)


class PluginLoader:
    """Manages the lifecycle of third-party FreeSDN plugins."""

    def __init__(self) -> None:
        self._loaded: dict[str, FreeSDNPlugin] = {}
        self._plugin_classes: dict[str, type[FreeSDNPlugin]] = {}
        self._active: dict[tuple[str, UUID], FreeSDNPlugin] = {}
        # Track sys.path entries added per plugin for cleanup
        self._plugin_paths: dict[str, list[str]] = {}
        self._registered_routes: set[str] = set()
        #: plugin_id -> the (path, method) shape mounted for it, so an
        #: upgrade can tell a code change from a route-table change.
        self._route_shape: dict[str, frozenset[tuple[str, str]]] = {}
        #: plugins whose mounted route TABLE no longer matches their code.
        #: Method bodies reload in place; paths do not.
        self._restart_required: set[str] = set()
        #: plugin_id -> get_router source as it was when mounted.
        self._router_source: dict[str, str | None] = {}
        #: plugin_id -> the template object its MOUNTED routes are closed over,
        #: kept across an uninstall. FastAPI cannot unmount a route, so after an
        #: uninstall the handlers are still in the app and still bound to that
        #: object; dropping the only reference to it left a REINSTALL unable to
        #: reach the thing it had to update.
        self._orphaned_template: dict[str, FreeSDNPlugin] = {}
        # Populated by load_all_plugins(): plugin_ids the DB reports as active
        # whose package is not on disk. Read by the lifespan to degrade the
        # subsystem rather than let them look healthy while doing nothing.
        self.missing_on_disk: list[str] = []
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

        raw = await _read_plugin_source(source)

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
            _check_core_compatibility(manifest)
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

                # Reinstalling over a plugin whose routes are already mounted:
                # let the EXISTING template adopt the new code, so the handlers
                # closed over it start running the upgrade immediately. Records
                # whether a restart is still needed for a changed route table.
                self._restart_required.discard(manifest.id)
                if manifest.id in self._registered_routes:
                    # The object the mounted handlers are closed over. Normally
                    # that is the live template; after an uninstall ``_loaded``
                    # no longer has it, because uninstall drops the entry while
                    # DELIBERATELY keeping ``_registered_routes`` (FastAPI cannot
                    # unmount, and forgetting would mount a second copy of every
                    # route). Reading ``_loaded`` directly therefore raised
                    # KeyError and turned every install-uninstall-reinstall into
                    # a 500 -- for any plugin that had ever served a request.
                    bound = self.mounted_template(manifest.id)
                    if bound is None:
                        # Routes are mounted and nothing here can reach what they
                        # point at. Say so rather than report a live upgrade.
                        self._restart_required.add(manifest.id)
                    else:
                        self._loaded[manifest.id] = bound
                        if not self.adopt_new_code(manifest.id, plugin_instance):
                            self._restart_required.add(manifest.id)
                        # Keep serving the object the routes point at.
                        plugin_instance = self._loaded[manifest.id]
                    self._orphaned_template.pop(manifest.id, None)

                # Call on_install lifecycle hook
                try:
                    async with supervisor.guard(manifest.id, "lifecycle", record_only=True):
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
                    async with supervisor.guard(plugin_id, "lifecycle", record_only=True):
                        await plugin_instance.on_uninstall(db)
                except Exception as exc:
                    logger.warning("Plugin %s on_uninstall raised: %s", plugin_id, exc)

                if plugin_id in self._registered_routes:
                    # Its handlers are still mounted and still closed over this
                    # object, so a later reinstall has to be able to update it.
                    self._orphaned_template[plugin_id] = plugin_instance
                del self._loaded[plugin_id]
                self._plugin_classes.pop(plugin_id, None)
                # A reinstall deserves a clean slate: carrying a quarantine
                # across an uninstall would keep punishing the replacement for
                # what its predecessor did.
                supervisor.reset(plugin_id)
                # NOT discarded. FastAPI cannot unmount a route, so after an
                # uninstall the plugin's routes are still in the app; forgetting
                # that made a REINSTALL mount a SECOND copy of every one of
                # them. FastAPI serves the first match, which is the ORIGINAL
                # handler, so the reinstalled plugin kept running its old code
                # while the UI showed the new version -- and each cycle grew the
                # route table permanently.
                #
                # Leaving the entry is safe: plugin_route_guard already answers
                # 410 for a plugin that is not active for the caller's
                # organization, which is exactly what an uninstalled one is.

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
                async with supervisor.guard(plugin_id, "lifecycle", record_only=True):
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
        # Plugins the database says are installed and active but whose files are
        # not on disk. That is not a warning-and-carry-on situation: the routes
        # are gone, on_event never fires, and the UI still shows the plugin as
        # running. The lifespan reads this to degrade the subsystem so /health
        # says so out loud.
        self.missing_on_disk = []
        for record in records:
            plugin_dir = Path(record.plugin_dir)
            if not plugin_dir.exists():
                logger.warning(
                    "Plugin %s is active in the database but its files are missing at %s. "
                    "It will NOT run. This is what an ephemeral PLUGIN_DIR looks like after "
                    "a container is recreated; check that /data/plugins is on a named volume.",
                    record.plugin_id,
                    plugin_dir,
                )
                self.missing_on_disk.append(record.plugin_id)
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

    def restart_required(self, plugin_id: str) -> bool:
        """Does this plugin need an API restart to serve its current code?

        False for the ordinary case now that code reloads in place. True only
        when the new version changed its route table, because paths were fixed
        when the router was mounted.
        """
        return plugin_id in self._restart_required

    def mounted_template(self, plugin_id: str) -> FreeSDNPlugin | None:
        """The object this plugin's MOUNTED route handlers are closed over.

        Normally the live template. After an uninstall it is the orphan: the
        handlers are still in the app -- FastAPI cannot unmount a route -- and
        still bound to the object that was loaded then, while ``_loaded`` has
        dropped it. A reinstall has to update THAT object, so it must be able to
        find it; reading ``_loaded`` directly raised KeyError and made every
        install-uninstall-reinstall cycle a 500 for any plugin that had ever
        served a request.

        None means the routes are mounted and nothing here can reach what they
        point at, which is the one case that genuinely needs a restart.
        """
        return self._loaded.get(plugin_id) or self._orphaned_template.get(plugin_id)

    def register_plugin_routes(
        self, app: FastAPI, plugin_id: str, *, replace: bool = False
    ) -> None:
        """Mount a loaded plugin's API routes into the running FastAPI app.

        ``replace`` is accepted and deliberately does nothing to the route
        TABLE -- see :meth:`adopt_new_code`, which is what actually makes an
        upgrade take effect.
        """
        if plugin_id in self._registered_routes and not replace:
            return
        if plugin_id in self._registered_routes:
            return
        plugin = self._loaded.get(plugin_id)
        if not plugin:
            return
        router = plugin.get_router()
        if router.routes:
            prefix = self.get_route_prefix(plugin_id)
            _supervise_router(router, plugin_id)
            app.include_router(
                router,
                prefix=prefix,
                tags=[plugin.manifest.name],
                dependencies=[Depends(self._build_route_guard(plugin_id))],
            )
            self._registered_routes.add(plugin_id)
            self._route_shape[plugin_id] = _route_shape(router)
            # Captured NOW, while the old file is still on disk. Reading it
            # later is too late: an upgrade replaces plugin.py at the same
            # path, so inspect.getsource on the OLD class returns the NEW
            # file and every comparison says "unchanged".
            self._router_source[plugin_id] = _source_of(plugin.__class__.get_router)
            # The trailing-slash normalizer caches the route table on first
            # request and would never see these. Without this, a plugin
            # installed into a running instance answers /my-plugin/ and 404s on
            # /my-plugin -- and the scaffold's own nav_items path is the bare
            # form, so the first thing an author clicks after installing is the
            # one spelling that fails.
            invalidate_route_cache()
            logger.info("Registered routes for plugin %s at %s", plugin_id, prefix)

    def adopt_new_code(self, plugin_id: str, new_instance: FreeSDNPlugin) -> bool:
        """Make already-mounted routes run the NEW version's code.

        A plugin's REST handlers are closures over the TEMPLATE instance built
        when the plugin was first loaded. Reinstalling or upgrading replaced the
        files and built a new template, but the mounted closures still pointed
        at the old object: new code on disk, new version in the UI, old
        behaviour on every endpoint. The only advertised remedy was "restart the
        API", which on an appliance means dropping every other plugin, every
        websocket and every in-flight request to pick up a one-line fix.

        The fix is to let the EXISTING object adopt the new class, rather than
        trying to re-point the routes at a new object. Rebinding ``__class__``
        keeps the identity every closure already captured while sending method
        lookup to the new code, so the handlers are running the upgrade the
        moment this returns.

        Route removal was the other candidate and was rejected on purpose:
        fastapi wraps every ``include_router`` in an opaque ``_IncludedRouter``
        whose children are not reachable as ``.routes``, so unmounting means
        reaching into internals that this codebase has already been bitten by
        once across a version bump.

        Returns True when the reload is COMPLETE. It is not complete when the
        new version changed its route table: paths and methods were fixed at
        mount time, so an added, removed or renamed endpoint still needs a
        restart. Callers report that rather than leave it to be discovered.
        """
        old = self._loaded.get(plugin_id)
        if old is None or old is new_instance:
            return True

        # What reloads and what does not, measured rather than assumed:
        #
        #   METHOD bodies reload. Verified live -- a settings method changed to
        #   return 777 and then 888 was picked up on the next request each time,
        #   with no restart.
        #
        #   ROUTE HANDLER bodies do NOT. ``get_router`` builds its handlers as
        #   closures once, at mount time, and rebinding the class does not
        #   rewrite a function object that already exists.
        #
        # So the question that decides whether a restart is still needed is
        # narrow and answerable: did ``get_router`` itself change? Comparing its
        # source is exact for that, and it subsumes a changed route table.
        mounted_source = self._router_source.get(plugin_id)
        changed_routes = _get_router_changed(mounted_source, new_instance.__class__)

        try:
            old.__class__ = new_instance.__class__
            # Carry the new instance's freshly-initialised state across, then
            # restore the bindings the running object owns: ctx and event
            # subscriptions belong to THIS object's lifecycle, and replacing
            # them would orphan live subscriptions.
            ctx = getattr(old, "_ctx", None)
            subs = getattr(old, "_event_subscription_ids", None)
            old.__dict__.update(
                {k: v for k, v in new_instance.__dict__.items() if not k.startswith("_ctx")}
            )
            if ctx is not None:
                old._ctx = ctx
            if subs is not None:
                old._event_subscription_ids = subs
        except TypeError:
            # Incompatible layout (a plugin using __slots__, say). Nothing is
            # broken; the reload just did not happen.
            logger.warning(
                "Plugin %s could not adopt new code in place; a restart is required",
                plugin_id,
            )
            return False

        if not changed_routes:
            # Handlers are equivalent, so what is mounted now matches this
            # version. Refresh the baseline or the next upgrade compares
            # against a version nobody is running.
            self._router_source[plugin_id] = _source_of(new_instance.__class__.get_router)
        logger.info("Plugin %s adopted new code without a restart", plugin_id)
        if changed_routes:
            logger.info(
                "Plugin %s changed get_router(); its HTTP handlers still need a restart",
                plugin_id,
            )
            return False
        return True

    def routes_changed(self, plugin_id: str, plugin: FreeSDNPlugin) -> bool:
        """Would this version need a restart to serve its route table?"""
        before = self._route_shape.get(plugin_id)
        if before is None:
            return False
        try:
            return _route_shape(plugin.get_router()) != before
        except Exception:  # noqa: BLE001
            return True

    def unregister_plugin_routes(self, plugin_id: str) -> None:
        """FastAPI route removal is restart-only; keep an explicit no-op stub.

        Removing routes would mean walking into ``_IncludedRouter``, whose
        children fastapi does not expose. :meth:`adopt_new_code` reloads the
        code behind the existing routes instead, which covers everything except
        a changed route TABLE.
        """
        logger.debug("Plugin route unregistration requested for %s (restart required)", plugin_id)

    async def load_plugin(self, plugin_id: str, db: AsyncSession) -> FreeSDNPlugin:
        """Load a single installed plugin into memory."""
        record = await _get_installed_plugin(db, plugin_id)
        if not record or record.status == "uninstalled":
            raise PluginLoadError(f"Plugin '{plugin_id}' is not installed")

        plugin_dir = Path(record.plugin_dir)
        if not plugin_dir.exists():
            # Deliberately no absolute path: this is the one PluginLoadError
            # that carried one, and these messages are surfaced to the caller.
            logger.error("Plugin directory missing for %s: %s", plugin_id, plugin_dir)
            raise PluginLoadError(
                f"Plugin files for '{plugin_id}' are missing on disk. Reinstall the plugin."
            )

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
            # Refuse a quarantined plugin's routes before doing any work. Its
            # handlers are the code that got it quarantined; running them again
            # on every request is exactly what the budget exists to stop. 503
            # with Retry-After, because this is temporary by construction and a
            # caller should know when to come back.
            from app.plugins.supervision import PluginState, supervisor

            health = supervisor.health(plugin_id)
            if health.state is PluginState.QUARANTINED:
                import time as _time

                retry_after = max(1, int(health.quarantined_until - _time.monotonic()))
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        f"Plugin '{plugin_id}' is temporarily quarantined after repeated "
                        f"failures ({health.quarantine_reason or 'unknown'})."
                    ),
                    headers={"Retry-After": str(retry_after)},
                )

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
                # Its own session for the duration of the request. Every SDK
                # object used to share the one captured at on_start, so two
                # overlapping calls into a plugin raced on a single asyncpg
                # connection and one failed with "concurrent operations are not
                # permitted". Not the REQUEST's session: the SDK commits its own
                # writes, and committing the request's would land a half-finished
                # request transaction.
                from app.plugins.sdk import plugin_session_scope

                async with plugin_session_scope():
                    yield
            finally:
                reset_request_plugin_runtime(token)
                if caller_token is not None:
                    reset_request_caller(caller_token)
                if site_token is not None:
                    current_user_var.reset(site_token)

        return plugin_route_guard


# ── Module-level singleton ────────────────────────────────────────────────────


def _source_of(func: Any) -> str | None:
    """The source of a function, read fresh from disk.

    ``linecache`` memoises by filename and a plugin upgrade replaces the file at
    the same path, so without invalidating it ``getsource`` happily returns the
    previous version's lines.
    """
    import inspect
    import linecache

    try:
        path = inspect.getsourcefile(func)
        if path:
            linecache.checkcache(path)
        return inspect.getsource(func)
    except (OSError, TypeError):
        return None


def _get_router_changed(mounted_source: str | None, new_cls: type) -> bool:
    """Did the plugin's ``get_router`` change since its routes were mounted?

    The one thing an in-place code swap cannot fix. Rebinding ``__class__``
    redirects method lookup on the existing object, so methods reload; the route
    handlers are function objects ``get_router`` already produced, and those
    keep running whatever they were compiled from.

    Compared against source captured at MOUNT time, not against the old class:
    an upgrade overwrites plugin.py at the same path, so reading the old class's
    source afterwards returns the new file and every comparison reports
    "unchanged" -- which is exactly the under-report that would tell an operator
    no restart was needed while their endpoints served old handlers.

    Unknown source counts as changed. Over-reporting a restart is recoverable;
    under-reporting it means running old code believing you upgraded.
    """
    if mounted_source is None:
        return True
    new_source = _source_of(new_cls.get_router)
    if new_source is None:
        return True
    return mounted_source != new_source


def _route_shape(router: Any) -> frozenset[tuple[str, str]]:
    """The (path, method) pairs a router exposes.

    Compared before and after an upgrade to answer one question: did the route
    TABLE change? Method bodies reload in place; paths were fixed when the
    router was mounted, so a new or renamed endpoint is the one case that still
    needs a restart.
    """
    shape: set[tuple[str, str]] = set()
    for route in getattr(router, "routes", []) or []:
        path = str(getattr(route, "path", "") or "")
        for method in sorted(getattr(route, "methods", None) or []):
            shape.add((path, str(method)))
    return frozenset(shape)


def _supervise_router(router: Any, plugin_id: str) -> None:
    """Route every plugin endpoint through the supervisor.

    Wrapping happens BEFORE ``include_router`` on purpose: FastAPI builds each
    route's dependant by inspecting the endpoint's signature, and
    ``functools.wraps`` sets ``__wrapped__`` so ``inspect.signature`` follows
    through to the original. Wrapping afterwards would leave the dependant
    pointing at the unwrapped callable and the supervision would simply not run.

    The route guard already REFUSES a quarantined plugin before any work. This
    is the other half: it observes the OUTCOME, so route failures count toward
    the same budget as event failures. Without it a plugin could 500 on every
    request indefinitely and never be quarantined, because nothing was counting.
    """
    import functools

    for route in getattr(router, "routes", []):
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None or getattr(endpoint, "__freesdn_supervised__", False):
            continue

        @functools.wraps(endpoint)
        async def supervised(*args: Any, __endpoint: Any = endpoint, **kwargs: Any) -> Any:
            try:
                async with supervisor.guard(plugin_id, "route"):
                    return await __endpoint(*args, **kwargs)
            except PluginNotReady as exc:
                # 503, not 500. The platform did not break -- the thing this
                # plugin talks to is unavailable, and a caller told "internal
                # server error" goes looking for a bug in FreeSDN. Retry-After
                # carries the supervisor's own backoff, so a client that honours
                # it stops asking at exactly the rate the platform intends.
                retry = supervisor.health(plugin_id).retry_after
                headers = {"Retry-After": str(int(retry))} if retry else None
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"Plugin '{plugin_id}' is waiting on a dependency: {exc.reason}",
                    headers=headers,
                ) from exc

        supervised.__freesdn_supervised__ = True  # type: ignore[attr-defined]
        route.endpoint = supervised


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
        explain_missing_name,
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
        # The manifest name is the author's own string and is the actionable
        # half; the absolute server path is not, and these messages now reach an
        # API response rather than only a log.
        logger.error("Entry point %r not found for plugin in %s", manifest.entry_point, plugin_dir)
        raise PluginLoadError(
            f"Entry point '{manifest.entry_point}' is not present in the plugin package"
        )

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
    except NameError as exc:
        raise PluginLoadError(
            explain_missing_name(exc, manifest.id) or f"Failed to load plugin {manifest.id}: {exc}"
        ) from exc
    except Exception as exc:
        raise PluginLoadError(f"Failed to load plugin {manifest.id}: {exc}") from exc

    cls = getattr(mod, manifest.class_name, None)
    if cls is None:
        raise PluginLoadError(f"Class '{manifest.class_name}' not found in {entry_path}")
    if not issubclass(cls, FreeSDNPlugin):
        raise PluginLoadError(f"Class '{manifest.class_name}' must extend FreeSDNPlugin")

    # Constructing the instance runs the plugin's __init__, which is plugin code
    # under the same restricted builtins as the module body -- and was NOT
    # covered by the handling above, so a withheld builtin used in __init__
    # surfaced as a bare "name 'type' is not defined" from an install endpoint.
    try:
        instance = cls()
    except NameError as exc:
        raise PluginLoadError(
            explain_missing_name(exc, manifest.id)
            or f"Failed to construct {manifest.class_name}: {exc}"
        ) from exc
    except Exception as exc:
        raise PluginLoadError(f"Failed to construct {manifest.class_name}: {exc}") from exc
    instance._plugin_dir = plugin_dir
    instance._plugin_manifest_data = manifest
    return instance, cls, added_paths
