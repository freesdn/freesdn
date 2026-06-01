# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - FastAPI Main Application
======================================

Application factory with lifespan management, middleware, and router setup.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

# Configure structured logging BEFORE any other imports that might log.
# Honors LOG_LEVEL and LOG_FORMAT from settings (json vs. colored text).
from app.core.config import settings  # noqa: E402
from app.core.logging import setup_logging  # noqa: E402

setup_logging(
    level=settings.LOG_LEVEL,
    json_format=(settings.LOG_FORMAT.lower() == "json"),
)

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from app.api.v1 import api_router  # noqa: E402
from app.core.events import event_bus  # noqa: E402
from app.core.metrics import setup_metrics  # noqa: E402
from app.core.middleware import setup_middleware  # noqa: E402
from app.modules.api import router as modules_router  # noqa: E402
from app.modules.loader import ModuleLoader  # noqa: E402
from app.modules.registry import module_registry  # noqa: E402
from app.plugins.loader import plugin_loader  # noqa: E402
from app.setup.api import router as setup_router  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Subsystem health tracking
# ---------------------------------------------------------------------------
# Populated during lifespan startup.  Consumed by the /health endpoint to
# report degraded subsystems so operators get actionable signals instead of
# silent failures.  Defined in app.core.startup to avoid circular imports.
from app.core.startup import SUBSYSTEM_STATUS  # noqa: E402


async def _rehydrate_enabled_modules(db) -> int:
    """Re-start every enabled module for every active org at process boot.

    Module ``on_start`` side effects (e.g. the collector's UDP listeners) are
    otherwise only run on an explicit user toggle and silently stop after any
    redeploy/restart — modules, unlike plugins, were never re-hydrated at boot.
    Resilient: one module's failure is logged, never fatal. Returns the number
    of (module, org) pairs started.
    """
    from sqlalchemy import select

    from app.models.core import Organization
    from app.modules.models import OrganizationModule

    active_orgs = {
        row[0]
        for row in (
            await db.execute(select(Organization.id).where(Organization.is_active.is_(True)))
        ).all()
    }
    enabled = (
        await db.execute(
            select(OrganizationModule.module_id, OrganizationModule.organization_id).where(
                OrganizationModule.is_enabled.is_(True)
            )
        )
    ).all()
    started = 0
    for module_id, org_id in enabled:
        if org_id not in active_orgs or module_id not in module_registry.modules:
            continue
        try:
            await module_registry.start_module_for_org(module_id, org_id, db)
            started += 1
        except Exception as exc:
            logger.warning(
                "Module %s failed to re-hydrate for org %s at startup: %s",
                module_id,
                org_id,
                exc,
                exc_info=True,
            )
    return started


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """
    Application lifespan context manager.

    Handles startup and shutdown events including module loading.
    Non-critical subsystems are wrapped in try/except so that a Redis outage
    or broken module never prevents the API from serving — but the failure is
    recorded in SUBSYSTEM_STATUS and surfaced via the health endpoint.

    When ``settings.STRICT_STARTUP`` is True, **critical** subsystems
    (event_bus, modules) will re-raise and abort startup.
    """
    # Startup
    logger.info("Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)
    logger.info("Environment: %s", settings.ENVIRONMENT)
    logger.info("Debug: %s", settings.DEBUG)

    # ── Credential key-canary ────────────────────────────────────────────
    # Confirm SECRET_KEY can still decrypt EXISTING stored credentials BEFORE
    # the app does anything that might re-encrypt new secrets. A changed
    # SECRET_KEY (e.g. the wrong env file) makes every stored credential
    # undecryptable; without this guard the app would silently re-encrypt NEW
    # secrets under a key that can't read the OLD ones (permanent, mixed-key
    # data loss). Refuses to boot in production on a mismatch; loud CRITICAL
    # elsewhere so dev/recovery isn't bricked. Override only for an intentional
    # rotation after re-encryption (ALLOW_CREDENTIAL_KEY_MISMATCH).
    try:
        from sqlalchemy import select

        from app.core.crypto import verify_blobs
        from app.db import async_session_factory
        from app.models.core import Controller

        blobs: list = []
        async with async_session_factory() as _db:
            for c in (await _db.execute(select(Controller))).scalars().all():
                cfg = c.config if isinstance(c.config, dict) else {}
                blobs += [
                    cfg[k]
                    for k in ("token_secret", "password", "api_secret_enc")
                    if isinstance(cfg.get(k), str)
                ]
            try:
                from app.modules.firewall.models import GatewayConnection

                for g in (await _db.execute(select(GatewayConnection))).scalars().all():
                    if isinstance(g.credentials, dict):
                        blobs.append(g.credentials)
            except Exception:  # noqa: BLE001 — firewall module optional
                pass
        canary = verify_blobs(blobs)
        if canary["status"] == "mismatch":
            logger.critical(
                "CREDENTIAL KEY MISMATCH: %d of %d stored credentials cannot be "
                "decrypted with the current SECRET_KEY. The app would re-encrypt "
                "NEW secrets under a key that cannot read the existing ones "
                "(silent data loss). Likely cause: wrong SECRET_KEY / wrong env "
                "file (.env vs .env.dev). Set ALLOW_CREDENTIAL_KEY_MISMATCH=true "
                "ONLY for an intentional rotation after re-encryption.",
                canary["failed"],
                canary["encrypted"],
            )
            SUBSYSTEM_STATUS["credential_key"] = "mismatch"
            if settings.ENVIRONMENT == "production" and not settings.ALLOW_CREDENTIAL_KEY_MISMATCH:
                raise RuntimeError(
                    "SECRET_KEY cannot decrypt existing credentials — refusing to "
                    "start (see CRITICAL log; ALLOW_CREDENTIAL_KEY_MISMATCH=true "
                    "overrides for an intentional rotation)."
                )
        else:
            SUBSYSTEM_STATUS["credential_key"] = "healthy"
            if canary["encrypted"]:
                logger.info(
                    "Credential key-canary OK (%d/%d decrypt)",
                    canary["ok"],
                    canary["encrypted"],
                )
    except RuntimeError:
        raise  # deliberate production refuse — propagate
    except Exception as exc:  # noqa: BLE001 — the canary must never itself break boot
        SUBSYSTEM_STATUS["credential_key"] = "skipped"
        logger.warning("Credential key-canary check skipped: %s", exc, exc_info=True)

    # Connect event bus (critical when STRICT_STARTUP — API works without Redis pub/sub)
    try:
        await event_bus.connect()
        await event_bus.start_listening()
        SUBSYSTEM_STATUS["event_bus"] = "healthy"
    except Exception as exc:
        SUBSYSTEM_STATUS["event_bus"] = "degraded"
        logger.warning("Event bus failed to connect: %s", exc, exc_info=True)
        if settings.STRICT_STARTUP:
            raise RuntimeError("Critical subsystem failed: event_bus") from exc

    # Start the adapter connection pool's background cleanup loop. The
    # singleton ``adapter_pool`` is populated on first use by
    # ``GatewayServiceBase._get_client``, but the eviction loop only
    # runs after ``start()`` is awaited — without this call idle pooled
    # sessions never get evicted and the UniFi-OS rate-limit cascade
    # the pool's own code comments warn about becomes possible. The
    # matching ``stop()`` is wired at the bottom of this lifespan.
    try:
        from app.adapters.pool import adapter_pool

        await adapter_pool.start()
        SUBSYSTEM_STATUS["adapter_pool"] = "healthy"
    except Exception as exc:
        SUBSYSTEM_STATUS["adapter_pool"] = "degraded"
        logger.warning("Adapter connection pool failed to start: %s", exc, exc_info=True)

    # Connect cross-instance WebSocket pubsub (degraded-only — single-pod
    # deployments still work, just without targeted-send fan-out across
    # pods). Broadcast fan-out already goes through the event bus.
    try:
        from app.api.v1.endpoints.websocket import manager as ws_manager
        from app.services.websocket_pubsub import get_ws_pubsub

        ws_pubsub = get_ws_pubsub()
        await ws_pubsub.connect(on_targeted=ws_manager._deliver_remote_to_user)
        SUBSYSTEM_STATUS["ws_pubsub"] = "healthy" if ws_pubsub.connected else "single_pod"
    except Exception as exc:
        SUBSYSTEM_STATUS["ws_pubsub"] = "degraded"
        logger.warning("WS cross-instance pubsub failed: %s", exc, exc_info=True)

    # Load modules (critical when STRICT_STARTUP — core API works without optional modules)
    loader = ModuleLoader()
    try:
        logger.info("Loading modules...")
        discovered = loader.discover_modules()
        logger.info("Discovered %d modules: %s", len(discovered), discovered)

        if discovered:
            await loader.load_all_modules()
            loader.register_routes(app, prefix=settings.API_V1_PREFIX)

        logger.info("Module registry initialized with %d modules", len(module_registry.modules))
        SUBSYSTEM_STATUS["modules"] = "healthy"
    except Exception as exc:
        SUBSYSTEM_STATUS["modules"] = "degraded"
        logger.error("Module loading failed: %s", exc, exc_info=True)
        if settings.STRICT_STARTUP:
            raise RuntimeError("Critical subsystem failed: modules") from exc

    # Re-hydrate enabled modules so their on_start side effects (e.g. the
    # collector's UDP listeners) survive a restart — modules, unlike plugins,
    # were never restarted at boot, so a module silently stopped after redeploy.
    try:
        from app.db import async_session_factory

        async with async_session_factory() as db:
            n = await _rehydrate_enabled_modules(db)
        logger.info("Re-hydrated %d enabled module(s) at startup", n)
    except Exception as exc:
        logger.warning("Module re-hydration at startup failed: %s", exc, exc_info=True)

    # Start automation engine (subscribes to the event bus + loads active rules)
    try:
        from app.services.automation import AutomationService, automation_engine

        await automation_engine.start()
        # start() only SUBSCRIBES to the bus; without loading the active rules
        # here, EVENT-triggered automation is cold-start-inert after every
        # restart until an admin happens to browse the rules list.
        from app.db import async_session_factory

        async with async_session_factory() as db:
            await AutomationService(db, engine=automation_engine)._load_rules_from_db()
        logger.info("Automation engine started")
        SUBSYSTEM_STATUS["automation"] = "healthy"
    except Exception as exc:
        SUBSYSTEM_STATUS["automation"] = "degraded"
        logger.warning("Automation engine failed to start: %s", exc, exc_info=True)

    # Wire the Fabric negotiator to the live event bus (non-critical): configure
    # its RBAC permission-checker, DB session factory, and ConnectionRun audit
    # recorder, prime enabled Connections from the DB, and subscribe to the bus.
    try:
        from app.core.fabric.runtime import wire_and_start

        primed = await wire_and_start()
        logger.info("Fabric negotiator live (%d connection(s) primed)", primed)
        SUBSYSTEM_STATUS["fabric"] = "healthy"
    except Exception as exc:
        SUBSYSTEM_STATUS["fabric"] = "degraded"
        logger.warning("Fabric negotiator failed to start: %s", exc, exc_info=True)

    # Load third-party plugins from PLUGIN_DIR (non-critical)
    try:
        from app.db import async_session_factory

        async with async_session_factory() as db:
            loaded_plugins = await plugin_loader.load_all_plugins(db)
            plugin_start_failures = False
            for plugin in loaded_plugins:
                plugin_loader.register_plugin_routes(app, plugin.manifest.id)
            if loaded_plugins:
                from sqlalchemy import select

                from app.models.core import Organization
                from app.models.plugins import PluginOrganizationState

                result = await db.execute(
                    select(Organization.id).where(Organization.is_active.is_(True))
                )
                org_ids = [row[0] for row in result.all()]
                for plugin in loaded_plugins:
                    disabled_result = await db.execute(
                        select(PluginOrganizationState.organization_id).where(
                            PluginOrganizationState.plugin_id == plugin.manifest.id,
                            PluginOrganizationState.is_enabled.is_(False),
                        )
                    )
                    disabled_org_ids = {row[0] for row in disabled_result.all()}
                    for org_id in org_ids:
                        if org_id in disabled_org_ids:
                            continue
                        try:
                            await plugin_loader.start_for_org(plugin.manifest.id, org_id, db)
                        except Exception as exc:
                            plugin_start_failures = True
                            logger.warning(
                                "Plugin %s failed to start for org %s: %s",
                                plugin.manifest.id,
                                org_id,
                                exc,
                                exc_info=True,
                            )
            if loaded_plugins:
                logger.info("Loaded %d third-party plugins", len(loaded_plugins))
        SUBSYSTEM_STATUS["plugins"] = (
            "degraded" if loaded_plugins and plugin_start_failures else "healthy"
        )
    except Exception as exc:
        SUBSYSTEM_STATUS["plugins"] = "degraded"
        logger.warning("Plugin loading failed: %s", exc, exc_info=True)

    # Sync module-managed devices (NVRs, phones, firewalls) into core devices
    # table AND create firmware status records so Device Inventory, Topology,
    # and Firmware Management pages all show every device type immediately.
    #
    # Run in the BACKGROUND (not awaited in the lifespan): a slow/large sync — or
    # this growing to make live adapter calls — must never block startup or trip
    # the Gunicorn worker boot timeout into an API crash-loop.
    # Startup completes immediately; data populates a moment later and pages
    # refetch. Strong ref on app.state so the task isn't GC'd.
    async def _initial_device_sync() -> None:
        try:
            from app.db import async_session_factory
            from app.services.device_sync import DeviceSyncService
            from app.services.firmware import PersistentFirmwareService as fw_svc

            async with async_session_factory() as session:
                sync_result = await DeviceSyncService.sync_all(session)
                logger.info("Initial device sync: %s", sync_result)
                # Create/update firmware status records for all devices
                fw_result = await fw_svc.check_updates(session)
                await session.commit()
                logger.info("Initial firmware check: %s", fw_result)
            SUBSYSTEM_STATUS["device_sync"] = "healthy"
        except Exception as exc:
            SUBSYSTEM_STATUS["device_sync"] = "degraded"
            logger.warning("Initial device sync failed: %s", exc, exc_info=True)

    import asyncio as _asyncio

    SUBSYSTEM_STATUS["device_sync"] = "pending"
    app.state._initial_sync_task = _asyncio.create_task(_initial_device_sync())

    # Seed built-in DPI classification rules (idempotent)
    try:
        from app.db import async_session_factory
        from app.modules.collector.services.classifier import seed_builtin_rules

        async with async_session_factory() as session:
            await seed_builtin_rules(session)
            await session.commit()
            logger.info("DPI classification rules seeded")
        SUBSYSTEM_STATUS["dpi_rules"] = "healthy"
    except Exception as exc:
        SUBSYSTEM_STATUS["dpi_rules"] = "degraded"
        logger.warning("DPI rule seeding failed: %s", exc, exc_info=True)

    # HLS session reaper — MUST run in THIS (API) process because HLS sessions
    # live in HLSStreamService._sessions, a per-process in-memory ClassVar. The
    # Celery beat reaper runs in the worker process where that dict is always
    # empty, so it can never see/kill a real session. Without this,
    # any abandoned playback tab leaks a live ffmpeg transcode + dir + FD until
    # the API restarts.
    try:
        import asyncio as _asyncio

        from app.modules.cameras.service import HLSStreamService

        _hls_svc = HLSStreamService()

        async def _hls_reaper() -> None:
            while True:
                try:
                    await _asyncio.sleep(15)
                    await _hls_svc.cleanup_stale_sessions()
                except _asyncio.CancelledError:
                    break
                except Exception:  # pragma: no cover - never let the reaper die
                    logger.debug("HLS reaper iteration failed", exc_info=True)

        app.state._hls_reaper_task = _asyncio.create_task(_hls_reaper())
        logger.info("HLS session reaper started (in-process)")
    except Exception:
        logger.warning("Failed to start HLS reaper", exc_info=True)

    yield

    # Shutdown
    # Stop the HLS reaper and kill any sessions still alive so a redeploy leaves
    # no orphan ffmpeg subprocesses behind.
    try:
        import asyncio as _asyncio
        import contextlib as _contextlib

        from app.modules.cameras.service import HLSStreamService

        task = getattr(app.state, "_hls_reaper_task", None)
        if task is not None:
            task.cancel()
            with _contextlib.suppress(Exception, _asyncio.CancelledError):
                await task
        async with HLSStreamService._lock:
            _svc = HLSStreamService()
            for _sid in list(HLSStreamService._sessions.keys()):
                _meta = HLSStreamService._sessions.get(_sid)
                if _meta is not None:
                    with _contextlib.suppress(Exception):
                        await _svc._kill_session(_sid, _meta)
    except Exception:
        logger.debug("Error stopping HLS reaper / draining sessions", exc_info=True)

    logger.info("Unloading modules...")
    for module_id in list(module_registry.modules.keys()):
        try:
            await loader.unload_module(module_id)
        except Exception:
            logger.debug("Error unloading module %s", module_id, exc_info=True)

    try:
        from app.db import async_session_factory

        active_plugins = plugin_loader.get_active()
        async with async_session_factory() as session:
            for plugin_id, organization_id in list(active_plugins):
                try:
                    await plugin_loader.stop_for_org(plugin_id, organization_id, session)
                except Exception:
                    logger.debug(
                        "Error stopping plugin %s for org %s",
                        plugin_id,
                        organization_id,
                        exc_info=True,
                    )
    except Exception:
        logger.debug("Error stopping plugins", exc_info=True)

    try:
        from app.services.automation import automation_engine

        await automation_engine.stop()
    except Exception:
        logger.debug("Error stopping automation engine", exc_info=True)

    # Cancel the Fabric background sweep started in wire_and_start().
    try:
        from app.core.fabric.runtime import stop_fabric_runtime

        await stop_fabric_runtime()
    except Exception:
        logger.debug("Error stopping Fabric runtime", exc_info=True)

    try:
        from app.services.websocket_pubsub import get_ws_pubsub

        await get_ws_pubsub().disconnect()
    except Exception:
        logger.debug("Error disconnecting WS pubsub", exc_info=True)

    try:
        await event_bus.disconnect()
    except Exception:
        logger.debug("Error disconnecting event bus", exc_info=True)

    # Drain the adapter connection pool: close all pooled httpx clients
    # so we don't leak open sockets at process exit. The pool is
    # populated on first use by ``GatewayServiceBase._get_client``.
    try:
        from app.adapters.pool import adapter_pool

        await adapter_pool.stop()
    except Exception:
        logger.debug("Error stopping adapter pool", exc_info=True)
    logger.info("Shutting down %s", settings.APP_NAME)


def create_application() -> FastAPI:
    """
    Application factory.

    Creates and configures the FastAPI application.
    """
    # Disable OpenAPI/Swagger in production AND staging unless explicitly enabled
    # (the codebase treats staging == production for security posture).
    enable_docs = settings.ENABLE_DOCS and settings.ENVIRONMENT not in ("production", "staging")

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Unified Network Management Platform",
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json" if enable_docs else None,
        docs_url=f"{settings.API_V1_PREFIX}/docs" if enable_docs else None,
        redoc_url=f"{settings.API_V1_PREFIX}/redoc" if enable_docs else None,
        # FastAPI natively serializes via Pydantic (ORJSONResponse is deprecated)
        lifespan=lifespan,
        # Disable trailing-slash redirects. Behind a reverse proxy (Vite
        # dev / nginx / Traefik / k8s ingress) FastAPI's 307 carries the
        # internal hostname (``http://api:8000/...``) in the Location
        # header — the browser cannot resolve that and the request hangs
        # forever as "pending". A path-normalize ASGI middleware (see
        # ``setup_middleware`` below) strips trailing slashes BEFORE
        # routing so ``/foo`` and ``/foo/`` both reach the same handler
        # without any client-visible redirect.
        redirect_slashes=False,
    )

    # Setup middleware (request ID, logging, rate limiting, exception handlers)
    setup_middleware(app)

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Request-ID",
            "X-API-Key",
            "X-CSRF-Token",
            "Accept",
            "Origin",
        ],
        expose_headers=[
            "X-Request-ID",
            "X-Response-Time",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
        ],
    )

    # Include API router
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # Include modules management router
    app.include_router(modules_router, prefix=settings.API_V1_PREFIX)

    # Include setup wizard router (public, no JWT required)
    app.include_router(setup_router, prefix=settings.API_V1_PREFIX)

    # Install Prometheus /metrics endpoint (no-op when ENABLE_METRICS=false).
    # Mounted after routes so path templates are already registered when
    # the instrumentator middleware inspects each request.
    setup_metrics(app)

    return app


# Create application instance
app = create_application()


@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, Any]:
    """Health check endpoint for container orchestration."""
    degraded = [k for k, v in SUBSYSTEM_STATUS.items() if v != "healthy"]
    status = "degraded" if degraded else "healthy"
    response: dict[str, Any] = {
        "status": status,
        "app": settings.APP_NAME,
    }
    if degraded:
        response["degraded_subsystems"] = degraded
    return response


@app.get("/", tags=["Root"])
async def root() -> dict[str, Any]:
    """Root endpoint with API information."""
    return {
        "app": settings.APP_NAME,
        "docs": f"{settings.API_V1_PREFIX}/docs" if settings.ENABLE_DOCS else None,
        "api": settings.API_V1_PREFIX,
    }
