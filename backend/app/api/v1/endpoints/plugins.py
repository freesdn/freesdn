# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin Management API
======================================

Endpoints for installing, managing, and configuring third-party plugins.
Requires org_admin role minimum.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import (
    CurrentUser,
    get_current_active_user,
    is_unscoped_org_admin,
    is_unscoped_superuser,
)
from app.db import get_session
from app.models.plugins import InstalledPlugin, PluginOrganizationState, PluginSetting
from app.plugins.loader import PluginLoadError, plugin_loader
from app.plugins.public_auth import (
    PLUGIN_PUBLIC_NONCE_HEADER,
    PLUGIN_PUBLIC_ORG_HEADER,
    PLUGIN_PUBLIC_SIGNATURE_HEADER,
    PLUGIN_PUBLIC_TIMESTAMP_HEADER,
    get_public_webhook_secret,
    rotate_public_webhook_secret,
)
from app.services.audit import AuditAction, AuditService, ResourceType

logger = logging.getLogger(__name__)
router = APIRouter()
MAX_PLUGIN_DOWNLOAD_BYTES = 50 * 1024 * 1024

# Domain allowlist for direct URL plugin installs.
# Empty list = block ALL URL installs (safest default).
# Set via PLUGIN_ALLOWED_DOMAINS env var (comma-separated), e.g.:
#   PLUGIN_ALLOWED_DOMAINS=github.com,gitlab.com
import os as _os

PLUGIN_ALLOWED_DOMAINS: list[str] = [
    d.strip().lower() for d in _os.getenv("PLUGIN_ALLOWED_DOMAINS", "").split(",") if d.strip()
]


async def _audit_plugin_install(
    session: AsyncSession,
    user: CurrentUser,
    record: InstalledPlugin,
    source: str,
) -> None:
    """Log a plugin installation to the audit trail."""
    try:
        audit = AuditService(session)
        await audit.log(
            action=AuditAction.INSTALL,
            resource_type=ResourceType.PLUGIN,
            resource_name=record.name,
            actor_id=user.id,
            actor_name=getattr(user, "full_name", None) or getattr(user, "email", None),
            actor_email=getattr(user, "email", None),
            organization_id=getattr(user, "organization_id", None),
            extra_metadata={
                "plugin_id": record.plugin_id,
                "plugin_version": record.version,
                "source": source,
            },
            tags=["plugin", "supply-chain"],
        )
    except Exception:
        # Audit failure must never block the install itself
        logger.warning(
            "Failed to create audit log for plugin install: %s", record.plugin_id, exc_info=True
        )


async def _audit_plugin_lifecycle(
    session: AsyncSession,
    user: CurrentUser,
    action: AuditAction,
    plugin_id: str,
    plugin_name: str | None,
    version: str | None,
    extra: dict[str, Any] | None = None,
) -> None:
    """
    Audit a plugin lifecycle operation (uninstall/enable/disable/upgrade).

    close forensic blind-spot — previously only install was audited.
    """
    try:
        audit = AuditService(session)
        await audit.log(
            action=action,
            resource_type=ResourceType.PLUGIN,
            resource_name=plugin_name or plugin_id,
            actor_id=user.id,
            actor_name=getattr(user, "full_name", None) or getattr(user, "email", None),
            actor_email=getattr(user, "email", None),
            organization_id=getattr(user, "organization_id", None),
            extra_metadata={
                "plugin_id": plugin_id,
                "plugin_version": version,
                **(extra or {}),
            },
            tags=["plugin", "supply-chain"],
        )
    except Exception:
        # Audit failure must never block the lifecycle operation itself
        logger.warning(
            "Failed to create audit log for plugin %s: %s",
            action,
            plugin_id,
            exc_info=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────


class PluginSummary(BaseModel):
    plugin_id: str
    name: str
    version: str
    description: str | None
    author: str | None
    is_active: bool
    status: str

    class Config:
        from_attributes = True


class PluginDetail(PluginSummary):
    license: str | None
    homepage: str | None
    plugin_dir: str
    manifest_cache: dict[str, Any]
    installed_from: str | None


class PluginInstallFromUrl(BaseModel):
    # URL is also allowlisted at the endpoint via
    # ``PLUGIN_ALLOWED_DOMAINS`` and ``PLUGIN_ENABLE_DIRECT_URL_INSTALLS``
    # — the cap here is the input-shape gate that rejects
    # unbounded / control-char strings before the allowlist check.
    url: str = Field(..., min_length=1, max_length=2048)


class PluginSettingsUpdate(BaseModel):
    # Previously unbounded dict — a 1 MB settings blob would persist
    # one row per key. Capped at 32 KiB via validator.
    settings: dict[str, Any]

    @field_validator("settings")
    @classmethod
    def _settings_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json as _json

        size = len(_json.dumps(v, default=str).encode("utf-8"))
        if size > 32 * 1024:
            raise ValueError(f"settings exceeds 32768 bytes (got {size})")
        return v


class PluginHealthResponse(BaseModel):
    plugin_id: str
    status: str
    is_loaded: bool
    is_active: bool
    organization_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class PluginPublicRouteInfo(BaseModel):
    path: str
    methods: list[str]


class PluginPublicAuthStatus(BaseModel):
    plugin_id: str
    organization_id: str
    has_secret: bool
    public_routes: list[PluginPublicRouteInfo]
    headers: list[str]


class PluginPublicAuthSecretResponse(PluginPublicAuthStatus):
    secret: str


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _require_org_admin(current_user: CurrentUser) -> None:
    # gate on the explicit permission OR an UNSCOPED org-admin role. The
    # previous raw ``is_org_admin`` arm let a scoped API key (deliberately
    # narrowed away from ``plugins.admin``) manage org plugins via its role.
    if not current_user.has_permission("plugins.admin") and not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requires org admin role",
        )


def _require_plugin_platform_admin(current_user: CurrentUser) -> None:
    if not is_unscoped_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requires super admin role",
        )


async def _get_active_org_ids(session: AsyncSession) -> list[Any]:
    from app.models.core import Organization

    result = await session.execute(select(Organization.id).where(Organization.is_active.is_(True)))
    return [row[0] for row in result.all()]


async def _get_disabled_org_ids(session: AsyncSession, plugin_id: str) -> set[Any]:
    result = await session.execute(
        select(PluginOrganizationState.organization_id).where(
            PluginOrganizationState.plugin_id == plugin_id,
            PluginOrganizationState.is_enabled.is_(False),
        )
    )
    return {row[0] for row in result.all()}


async def _get_org_plugin_state(
    session: AsyncSession,
    plugin_id: str,
    organization_id: Any,
) -> PluginOrganizationState | None:
    result = await session.execute(
        select(PluginOrganizationState).where(
            PluginOrganizationState.plugin_id == plugin_id,
            PluginOrganizationState.organization_id == organization_id,
        )
    )
    return result.scalar_one_or_none()


async def _get_org_plugin_states(
    session: AsyncSession,
    plugin_ids: list[str],
    organization_id: Any | None,
) -> dict[str, PluginOrganizationState]:
    if not plugin_ids or organization_id is None:
        return {}
    result = await session.execute(
        select(PluginOrganizationState).where(
            PluginOrganizationState.organization_id == organization_id,
            PluginOrganizationState.plugin_id.in_(plugin_ids),
        )
    )
    return {row.plugin_id: row for row in result.scalars().all()}


def _is_globally_enabled(plugin: InstalledPlugin) -> bool:
    return plugin.is_active and plugin.status == "installed"


def _effective_plugin_status(
    plugin: InstalledPlugin,
    org_state: PluginOrganizationState | None,
) -> str:
    if not _is_globally_enabled(plugin):
        return plugin.status
    if org_state is not None and not org_state.is_enabled:
        return "disabled"
    return "installed"


def _serialize_plugin(
    plugin: InstalledPlugin,
    org_state: PluginOrganizationState | None = None,
) -> PluginDetail:
    effective_status = _effective_plugin_status(plugin, org_state)
    return PluginDetail(
        plugin_id=plugin.plugin_id,
        name=plugin.name,
        version=plugin.version,
        description=plugin.description,
        author=plugin.author,
        is_active=(effective_status == "installed"),
        status=effective_status,
        license=plugin.license,
        homepage=plugin.homepage,
        plugin_dir=plugin.plugin_dir,
        manifest_cache=plugin.manifest_cache,
        installed_from=plugin.installed_from,
    )


async def _set_org_plugin_enabled(
    session: AsyncSession,
    plugin_id: str,
    organization_id: Any,
    *,
    is_enabled: bool,
) -> None:
    row = await _get_org_plugin_state(session, plugin_id, organization_id)
    if is_enabled:
        if row is not None:
            await session.delete(row)
        return

    if row is None:
        session.add(
            PluginOrganizationState(
                plugin_id=plugin_id,
                organization_id=organization_id,
                is_enabled=False,
            )
        )
        return

    row.is_enabled = False


def _is_global_scope(current_user: CurrentUser) -> bool:
    return is_unscoped_superuser(current_user) and current_user.organization_id is None


def _manifest_public_routes(plugin: InstalledPlugin) -> list[PluginPublicRouteInfo]:
    public_routes = plugin.manifest_cache.get("public_routes", [])
    return [
        PluginPublicRouteInfo(
            path=str(route.get("path", "")),
            methods=[str(method).upper() for method in route.get("methods", [])],
        )
        for route in public_routes
        if route.get("path")
    ]


async def _start_plugin_for_org(
    plugin_id: str,
    organization_id: Any,
    session: AsyncSession,
    app: Any | None = None,
) -> None:
    if plugin_id not in plugin_loader.get_loaded():
        await plugin_loader.load_plugin(plugin_id, session)

    if app is not None:
        plugin_loader.register_plugin_routes(app, plugin_id)

    await plugin_loader.start_for_org(plugin_id, organization_id, session)


async def _start_plugin_everywhere(
    plugin_id: str,
    session: AsyncSession,
    app: Any | None = None,
) -> None:
    disabled_org_ids = await _get_disabled_org_ids(session, plugin_id)
    started_orgs: list[Any] = []
    try:
        for org_id in await _get_active_org_ids(session):
            if org_id in disabled_org_ids:
                continue
            await _start_plugin_for_org(plugin_id, org_id, session, app)
            started_orgs.append(org_id)
    except Exception:
        for org_id in started_orgs:
            await plugin_loader.stop_for_org(plugin_id, org_id, session)
        raise


async def _download_plugin_archive(url: str) -> bytes:
    """
    Download a plugin archive with size cap and DNS-rebinding-safe SSRF guard.

    ``safe_http_request`` buffers the whole body before returning, which
    would defeat our streaming size-cap. Instead we replicate its
    DNS-pinning logic manually and keep ``client.stream(...)`` so we can
    fail fast on oversized downloads without loading them fully into memory.
    """
    import ipaddress
    from urllib.parse import urlparse, urlunparse

    import httpx

    from app.core.security_utils import _is_ip_safe, _resolve_and_validate

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail=f"Plugin URL scheme {parsed.scheme!r} not allowed",
        )
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Plugin URL has no hostname")

    # DNS-pin: resolve once and validate; reject private/loopback/link-local.
    try:
        direct_ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        direct_ip = None

    try:
        if direct_ip is not None:
            if not _is_ip_safe(direct_ip):
                raise ValueError(f"Plugin URL targets blocked IP {parsed.hostname!r}")
            resolved = str(direct_ip)
        else:
            resolved = _resolve_and_validate(parsed.hostname)
    except ValueError as ssrf_err:
        raise HTTPException(status_code=400, detail=f"SSRF blocked: {ssrf_err}") from ssrf_err

    # Build IP-pinned URL preserving port/path/query/fragment.
    port = parsed.port
    is_ipv6 = ":" in resolved
    if is_ipv6:
        netloc_ip = f"[{resolved}]:{port}" if port else f"[{resolved}]"
    else:
        netloc_ip = f"{resolved}:{port}" if port else resolved

    ip_url = urlunparse(
        (
            parsed.scheme,
            netloc_ip,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
    # Host header so HTTP vhost routing still works on the far end.
    host_headers = {"Host": parsed.hostname}
    # Pass sni_hostname so httpcore uses the ORIGINAL hostname for TLS SNI +
    # certificate verification even though the socket connects to the pinned IP.
    # Without this, an IP-literal URL causes TLS to verify the cert against the
    # IP address, which fails for virtually all real hostname certificates.
    stream_extensions: dict[str, object] = {}
    if parsed.scheme == "https":
        stream_extensions["sni_hostname"] = parsed.hostname

    total = 0
    chunks: list[bytes] = []
    async with (
        httpx.AsyncClient(
            timeout=60.0,
            follow_redirects=False,
            max_redirects=0,
        ) as client,
        client.stream("GET", ip_url, headers=host_headers, extensions=stream_extensions) as resp,
    ):
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > MAX_PLUGIN_DOWNLOAD_BYTES:
                raise HTTPException(
                    status_code=400,
                    detail="Download too large (max 50 MB)",
                )
            chunks.append(chunk)
    return b"".join(chunks)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_model=list[PluginDetail])
async def list_plugins(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[PluginDetail]:
    """List all installed plugins with full details."""
    _require_org_admin(current_user)
    result = await session.execute(
        select(InstalledPlugin)
        .where(InstalledPlugin.status != "uninstalled")
        .order_by(InstalledPlugin.name)
    )
    plugins = list(result.scalars().all())
    org_states = await _get_org_plugin_states(
        session,
        [plugin.plugin_id for plugin in plugins],
        current_user.organization_id,
    )
    return [_serialize_plugin(plugin, org_states.get(plugin.plugin_id)) for plugin in plugins]


@router.get("/{plugin_id}", response_model=PluginDetail)
async def get_plugin(
    plugin_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PluginDetail:
    """Get plugin detail including cached manifest."""
    _require_org_admin(current_user)
    result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    org_state = await _get_org_plugin_state(
        session,
        plugin_id,
        current_user.organization_id,
    )
    return _serialize_plugin(plugin, org_state)


@router.post("/install", response_model=PluginDetail, status_code=status.HTTP_201_CREATED)
async def install_plugin(
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    file: UploadFile = File(None),
) -> InstalledPlugin:
    """Install a plugin from a ZIP file upload."""
    _require_plugin_platform_admin(current_user)
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    try:
        record = await plugin_loader.install_plugin(
            source=file,
            db=session,
            installed_by_id=current_user.id,
        )
        await _start_plugin_everywhere(record.plugin_id, session, request.app)
        await _audit_plugin_install(session, current_user, record, source="upload")
        return record
    except PluginLoadError as exc:
        logger.error("Plugin install failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=400, detail="Plugin installation failed")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Plugin install failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Install failed") from exc


@router.post("/install-url", response_model=PluginDetail, status_code=status.HTTP_201_CREATED)
async def install_plugin_from_url(
    body: PluginInstallFromUrl,
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InstalledPlugin:
    """Install a plugin by downloading from a URL."""
    _require_plugin_platform_admin(current_user)
    try:
        if not settings.PLUGIN_ENABLE_DIRECT_URL_INSTALLS:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Direct URL plugin installs are disabled by policy. "
                    "Enable PLUGIN_ENABLE_DIRECT_URL_INSTALLS to allow them."
                ),
            )

        # Validate URL domain against allowlist
        from urllib.parse import urlparse

        parsed = urlparse(body.url)
        hostname = (parsed.hostname or "").lower()
        if not PLUGIN_ALLOWED_DOMAINS:
            raise HTTPException(
                status_code=403,
                detail="Direct URL plugin installs are disabled. "
                "No allowed domains configured (set PLUGIN_ALLOWED_DOMAINS).",
            )
        if hostname not in PLUGIN_ALLOWED_DOMAINS:
            raise HTTPException(
                status_code=403,
                detail=f"Domain '{hostname}' is not in the plugin download allowlist. "
                f"Allowed: {', '.join(PLUGIN_ALLOWED_DOMAINS)}",
            )

        # _download_plugin_archive applies DNS-rebinding-safe
        # SSRF validation by resolving + pinning the hostname to a validated IP.
        raw = await _download_plugin_archive(body.url)

        record = await plugin_loader.install_plugin(
            source=raw,
            db=session,
            installed_by_id=current_user.id,
            source_url=body.url,
        )
        await _start_plugin_everywhere(record.plugin_id, session, request.app)
        await _audit_plugin_install(session, current_user, record, source=f"url:{body.url}")
        return record
    except PluginLoadError as exc:
        logger.error("Plugin install-url failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=400, detail="Plugin installation failed")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Plugin install-url failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Install failed") from exc


@router.delete("/{plugin_id}", status_code=status.HTTP_204_NO_CONTENT)
async def uninstall_plugin(
    plugin_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Uninstall a plugin (calls on_uninstall hook then removes files)."""
    _require_plugin_platform_admin(current_user)
    # Capture plugin details BEFORE uninstall (the loader may delete the row).
    pre_result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    pre_plugin = pre_result.scalar_one_or_none()
    pre_name = pre_plugin.name if pre_plugin else None
    pre_version = pre_plugin.version if pre_plugin else None
    try:
        await plugin_loader.uninstall_plugin(plugin_id, session)
    except PluginLoadError as exc:
        logger.error("Plugin uninstall failed for %s: %s", plugin_id, exc, exc_info=True)
        raise HTTPException(status_code=404, detail="Plugin not found")
    # audit lifecycle operation
    await _audit_plugin_lifecycle(
        session,
        current_user,
        action=AuditAction.UNINSTALL,
        plugin_id=plugin_id,
        plugin_name=pre_name,
        version=pre_version,
    )


@router.post("/{plugin_id}/enable", response_model=PluginSummary)
async def enable_plugin(
    plugin_id: str,
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PluginSummary:
    """Enable a disabled plugin."""
    if not _is_global_scope(current_user):
        _require_org_admin(current_user)
    result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    # Serialise the DB flip against a concurrent install / upgrade / uninstall
    # of the same plugin via the loader's per-plugin lifecycle lock.
    #
    # STARTING the plugin happens AFTER the lock is released, and that placement
    # is load-bearing rather than stylistic. lifecycle_lock is documented
    # non-reentrant ("callers MUST NOT re-acquire it from within an already-held
    # block"), and the start path re-acquires it three frames down:
    #
    #   _start_plugin_everywhere -> _start_plugin_for_org
    #     -> plugin_loader.load_plugin  ->  async with await self._lock_for(...)
    #
    # so doing it inside the block deadlocked the request FOREVER -- no timeout,
    # no error, the connection simply never returned. It fired whenever the
    # plugin was absent from the loader's in-process _loaded map, which
    # load_all_plugins guarantees for any globally-disabled plugin after a
    # restart: i.e. the ordinary "disable a plugin, restart the API, re-enable
    # it" flow.
    #
    # Every sibling endpoint already had this right -- install (:544), the
    # install-retry path (:604) and upgrade (:809) all call
    # _start_plugin_everywhere outside any lock and rely on the loader's own
    # per-operation locking. Enable was the sole exception. Disable is safe
    # because the stop_* methods take no lock.
    start_scope: tuple[str, Any] | None = None
    async with plugin_loader.lifecycle_lock(plugin_id):
        if _is_global_scope(current_user):
            plugin.is_active = True
            plugin.status = "installed"
            await session.commit()
            start_scope = ("global", None)
            effective_status = "installed"
            extra_metadata = {"scope": "global"}
        else:
            if current_user.organization_id is None:
                raise HTTPException(status_code=400, detail="Organization required")
            if not _is_globally_enabled(plugin):
                raise HTTPException(
                    status_code=409,
                    detail="Plugin is globally disabled. A super admin must enable it first.",
                )
            await _set_org_plugin_enabled(
                session,
                plugin_id,
                current_user.organization_id,
                is_enabled=True,
            )
            await session.commit()
            start_scope = ("org", current_user.organization_id)
            effective_status = "installed"
            extra_metadata = {
                "scope": "organization",
                "organization_id": str(current_user.organization_id),
            }

    # Lock released — safe to let the loader take it for itself.
    if start_scope is not None:
        if start_scope[0] == "global":
            await _start_plugin_everywhere(plugin_id, session, request.app)
        else:
            await _start_plugin_for_org(plugin_id, start_scope[1], session, request.app)
    # audit lifecycle operation
    await _audit_plugin_lifecycle(
        session,
        current_user,
        action=AuditAction.ENABLE,
        plugin_id=plugin_id,
        plugin_name=plugin.name,
        version=plugin.version,
        extra=extra_metadata,
    )
    return PluginSummary(
        plugin_id=plugin.plugin_id,
        name=plugin.name,
        version=plugin.version,
        description=plugin.description,
        author=plugin.author,
        is_active=(effective_status == "installed"),
        status=effective_status,
    )


@router.post("/{plugin_id}/disable", response_model=PluginSummary)
async def disable_plugin(
    plugin_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PluginSummary:
    """Disable a plugin without removing it."""
    if not _is_global_scope(current_user):
        _require_org_admin(current_user)
    result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    # NOTE: serialise disable via per-plugin lifecycle lock.
    async with plugin_loader.lifecycle_lock(plugin_id):
        if _is_global_scope(current_user):
            plugin.is_active = False
            plugin.status = "disabled"
            await session.commit()
            await plugin_loader.stop_plugin_everywhere(plugin_id, session)
            effective_status = "disabled"
            extra_metadata = {"scope": "global"}
        else:
            if current_user.organization_id is None:
                raise HTTPException(status_code=400, detail="Organization required")
            await _set_org_plugin_enabled(
                session,
                plugin_id,
                current_user.organization_id,
                is_enabled=False,
            )
            await session.commit()
            await plugin_loader.stop_for_org(plugin_id, current_user.organization_id, session)
            effective_status = "disabled"
            extra_metadata = {
                "scope": "organization",
                "organization_id": str(current_user.organization_id),
            }
    # audit lifecycle operation
    await _audit_plugin_lifecycle(
        session,
        current_user,
        action=AuditAction.DISABLE,
        plugin_id=plugin_id,
        plugin_name=plugin.name,
        version=plugin.version,
        extra=extra_metadata,
    )
    return PluginSummary(
        plugin_id=plugin.plugin_id,
        name=plugin.name,
        version=plugin.version,
        description=plugin.description,
        author=plugin.author,
        is_active=False,
        status=effective_status,
    )


@router.post("/{plugin_id}/upgrade", response_model=PluginDetail)
async def upgrade_plugin(
    plugin_id: str,
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    file: UploadFile = File(None),
) -> InstalledPlugin:
    """Upgrade an installed plugin by uploading a new ZIP."""
    _require_plugin_platform_admin(current_user)
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    # Capture pre-upgrade version for audit trail
    pre_result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    pre_plugin = pre_result.scalar_one_or_none()
    pre_version = pre_plugin.version if pre_plugin else None
    try:
        await plugin_loader.stop_plugin_everywhere(plugin_id, session)
        record = await plugin_loader.upgrade_plugin(
            plugin_id=plugin_id,
            source=file,
            db=session,
            installed_by_id=current_user.id,
        )
        await _start_plugin_everywhere(plugin_id, session, request.app)
        # audit lifecycle operation
        await _audit_plugin_lifecycle(
            session,
            current_user,
            action=AuditAction.UPGRADE,
            plugin_id=plugin_id,
            plugin_name=record.name,
            version=record.version,
            extra={"previous_version": pre_version},
        )
        return record
    except PluginLoadError as exc:
        logger.error("Plugin upgrade failed for %s: %s", plugin_id, exc, exc_info=True)
        raise HTTPException(status_code=400, detail="Plugin upgrade failed")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Plugin upgrade failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Upgrade failed") from exc


async def _verify_plugin_installed(session: AsyncSession, plugin_id: str) -> None:
    """Reject settings ops on non-existent plugin_ids.

    Without this the ``GET /{plugin_id}/settings`` endpoint
    returned ``{"settings": {}}`` for any string the caller chose,
    and ``PUT`` happily persisted orphan rows referencing plugin
    IDs that were never installed.
    """
    row = (
        await session.execute(
            select(InstalledPlugin.plugin_id).where(InstalledPlugin.plugin_id == plugin_id)
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Plugin not found")


@router.get("/{plugin_id}/settings")
async def get_plugin_settings(
    plugin_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Get org-scoped settings for a plugin."""
    _require_org_admin(current_user)
    await _verify_plugin_installed(session, plugin_id)
    if not current_user.organization_id:
        return {"settings": {}}
    result = await session.execute(
        select(PluginSetting).where(
            PluginSetting.plugin_id == plugin_id,
            PluginSetting.organization_id == current_user.organization_id,
        )
    )
    settings = {row.key: row.value for row in result.scalars().all()}
    return {"settings": settings}


@router.put("/{plugin_id}/settings")
async def update_plugin_settings(
    plugin_id: str,
    body: PluginSettingsUpdate,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Update org-scoped settings for a plugin."""
    _require_org_admin(current_user)
    await _verify_plugin_installed(session, plugin_id)
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="Organization required")

    # Upsert each key atomically. A prior SELECT-then-INSERT raced under
    # concurrent PUTs for the same (plugin_id, org_id, key): both requests
    # could SELECT-miss and INSERT, so one commit hit the
    # ``ix_plugin_settings_lookup`` unique index and surfaced as a 500.
    # ON CONFLICT ... DO UPDATE collapses insert/update into one statement.
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    for key, value in body.settings.items():
        stmt = pg_insert(PluginSetting).values(
            plugin_id=plugin_id,
            organization_id=current_user.organization_id,
            key=key,
            value=value,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["plugin_id", "organization_id", "key"],
            set_={"value": value},
        )
        await session.execute(stmt)

    await session.commit()
    return {"settings": body.settings}


@router.get("/{plugin_id}/health", response_model=PluginHealthResponse)
async def get_plugin_health(
    plugin_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PluginHealthResponse:
    """Return plugin runtime health for the caller's organization."""
    _require_org_admin(current_user)

    result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    plugin = result.scalar_one_or_none()
    if not plugin or plugin.status == "uninstalled":
        raise HTTPException(status_code=404, detail="Plugin not found")

    runtime = None
    organization_id = current_user.organization_id
    if organization_id is not None:
        runtime = plugin_loader.get_active_for_org(plugin_id, organization_id)
    elif is_unscoped_superuser(current_user):
        runtime = plugin_loader.get_any_active(plugin_id)

    if runtime is None:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Plugin is not active for this organization",
        )

    details = await runtime.health_check()
    normalized_details = details if isinstance(details, dict) else {"result": details}
    runtime_org_id = (
        str(runtime.ctx.organization_id)
        if runtime.ctx is not None
        else (str(organization_id) if organization_id else None)
    )
    return PluginHealthResponse(
        plugin_id=plugin_id,
        status=str(normalized_details.get("status", "ok")),
        is_loaded=(plugin_id in plugin_loader.get_loaded()),
        is_active=True,
        organization_id=runtime_org_id,
        details=normalized_details,
    )


@router.get("/{plugin_id}/public-auth", response_model=PluginPublicAuthStatus)
async def get_plugin_public_auth_status(
    plugin_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PluginPublicAuthStatus:
    """Return org-scoped public-route auth status for the plugin."""
    _require_org_admin(current_user)
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="Organization required")

    result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    plugin = result.scalar_one_or_none()
    if not plugin or plugin.status == "uninstalled":
        raise HTTPException(status_code=404, detail="Plugin not found")

    public_routes = _manifest_public_routes(plugin)
    if not public_routes:
        raise HTTPException(
            status_code=400,
            detail="Plugin does not declare any public routes",
        )

    secret = await get_public_webhook_secret(
        session,
        plugin_id,
        current_user.organization_id,
    )
    return PluginPublicAuthStatus(
        plugin_id=plugin_id,
        organization_id=str(current_user.organization_id),
        has_secret=(secret is not None),
        public_routes=public_routes,
        headers=[
            PLUGIN_PUBLIC_ORG_HEADER,
            PLUGIN_PUBLIC_TIMESTAMP_HEADER,
            PLUGIN_PUBLIC_NONCE_HEADER,
            PLUGIN_PUBLIC_SIGNATURE_HEADER,
        ],
    )


@router.post(
    "/{plugin_id}/public-auth/rotate-secret",
    response_model=PluginPublicAuthSecretResponse,
)
async def rotate_plugin_public_auth_secret(
    plugin_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PluginPublicAuthSecretResponse:
    """Generate a new org-scoped HMAC secret for the plugin's public routes."""
    _require_org_admin(current_user)
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="Organization required")

    result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    plugin = result.scalar_one_or_none()
    if not plugin or plugin.status == "uninstalled":
        raise HTTPException(status_code=404, detail="Plugin not found")

    public_routes = _manifest_public_routes(plugin)
    if not public_routes:
        raise HTTPException(
            status_code=400,
            detail="Plugin does not declare any public routes",
        )

    secret = await rotate_public_webhook_secret(
        session,
        plugin_id,
        current_user.organization_id,
    )
    await session.commit()
    await _audit_plugin_lifecycle(
        session,
        current_user,
        action=AuditAction.UPDATE,
        plugin_id=plugin_id,
        plugin_name=plugin.name,
        version=plugin.version,
        extra={
            "operation": "rotate_public_auth_secret",
            "scope": "organization",
            "organization_id": str(current_user.organization_id),
        },
    )
    return PluginPublicAuthSecretResponse(
        plugin_id=plugin_id,
        organization_id=str(current_user.organization_id),
        has_secret=True,
        public_routes=public_routes,
        headers=[
            PLUGIN_PUBLIC_ORG_HEADER,
            PLUGIN_PUBLIC_TIMESTAMP_HEADER,
            PLUGIN_PUBLIC_NONCE_HEADER,
            PLUGIN_PUBLIC_SIGNATURE_HEADER,
        ],
        secret=secret,
    )
