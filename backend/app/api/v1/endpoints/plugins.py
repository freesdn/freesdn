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
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
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
from app.plugins.capabilities import (
    CAPABILITIES,
    MUTATING_CAPABILITIES,
    known_codes,
)
from app.plugins.loader import PluginLoadError, plugin_loader
from app.plugins.mutation_authority import capture_plugin_mutation_authority
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
    #: Set by the install and upgrade paths. True only when the new version
    #: changed its HTTP handlers, which an in-place code swap cannot rewrite.
    #: Absent on a plain read, where the question does not arise.
    restart_required: bool | None = None
    note: str | None = None


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


class PluginScheduleInfo(BaseModel):
    """One declared schedule and what has actually become of it.

    ``last_run`` and ``next_run_at`` are the point. A schedule an operator can
    see declared but cannot see RUNNING is indistinguishable from one that is
    quietly failing, and unattended work that fails quietly is the whole reason
    supervision exists.
    """

    name: str
    method: str
    interval_seconds: int
    description: str = ""
    enabled: bool
    next_run_at: float | None = None
    last_run: dict[str, Any] | None = None
    #: Counters from THIS worker only. Under multiple workers the true totals
    #: are higher; ``last_run`` is shared through Redis and is not affected.
    runs_this_worker: int = 0
    failures_this_worker: int = 0
    #: A local refusal to attempt work, not an executed run or global status.
    blocked_this_worker: dict[str, Any] | None = None


class PluginScheduleUpdate(BaseModel):
    enabled: bool


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
    replace_routes: bool = False,
) -> None:
    if plugin_id not in plugin_loader.get_loaded():
        await plugin_loader.load_plugin(plugin_id, session)

    if app is not None:
        # ``replace_routes`` is what makes an upgrade take effect without a
        # restart. Without it the handlers stay bound to the PREVIOUS template
        # object: new code on disk, new version in the UI, old behaviour on the
        # endpoint, and nothing anywhere saying so.
        plugin_loader.register_plugin_routes(app, plugin_id, replace=replace_routes)

    await plugin_loader.start_for_org(plugin_id, organization_id, session)


def _with_reload_note(record: Any) -> Any:
    """Attach the reload verdict to a record on its way out.

    Set on the object rather than returned separately so it flows through
    ``response_model=PluginDetail`` unchanged. The record is a live ORM row, so
    these are plain attributes pydantic reads, never columns it writes back.
    """
    info = _reload_note(record.plugin_id)
    record.restart_required = info["restart_required"]
    record.note = info.get("note")
    return record


def _reload_note(plugin_id: str) -> dict[str, Any]:
    """Whether this plugin is fully live, in the response the operator reads.

    An upgrade now reloads METHOD bodies in place, so the ordinary case needs no
    restart. It cannot rewrite the plugin's HTTP handlers -- ``get_router``
    builds those once at mount time -- so a version that changed ``get_router``
    is serving new methods behind old endpoints, and says so.

    Reported on every path that installs or upgrades. Previously only the
    marketplace path said anything, so the same situation was legible or silent
    depending on which button an operator pressed.
    """
    needs_restart = plugin_loader.restart_required(plugin_id)
    out: dict[str, Any] = {"restart_required": needs_restart}
    if needs_restart:
        out["note"] = (
            "This version changed its HTTP endpoints. Its methods are already "
            "live, but the routes keep serving the previous handlers until the "
            "API restarts."
        )
    return out


async def _validate_plugin_config(plugin_id: str, organization_id: Any) -> str | None:
    """Ask the plugin whether its settings actually work.

    Advisory by design. The settings are already saved when this runs: an
    operator half-way through configuring a plugin must not be blocked by a
    remote that happens to be down, and a plugin whose validator is wrong must
    not be able to lock its own configuration.

    Supervised like any other call into plugin code, and bounded -- a validator
    that hangs would hang the settings form.
    """
    runtime = plugin_loader.get_active_for_org(plugin_id, organization_id)
    if runtime is None:
        return None
    validate = getattr(runtime, "async_validate_config", None)
    if validate is None:
        return None

    from app.plugins.sdk import plugin_session_scope
    from app.plugins.supervision import PluginNotReady, PluginQuarantined, supervisor

    try:
        async with plugin_session_scope(), supervisor.guard(plugin_id, "lifecycle", timeout=15.0):
            result = await validate()
        return str(result)[:300] if result else None
    except PluginNotReady as exc:
        # Worth reporting and NOT worth treating as a bad configuration: the
        # settings may be perfect and the remote merely down.
        return f"Could not check: {exc.reason}"
    except PluginQuarantined:
        return None
    except TimeoutError:
        return "Could not check: the plugin's validator timed out"
    except Exception as exc:  # noqa: BLE001 - a broken validator must not break saving
        logger.warning("Plugin %s validator raised: %s", plugin_id, exc)
        return None


async def _start_plugin_everywhere(
    plugin_id: str,
    session: AsyncSession,
    app: Any | None = None,
    replace_routes: bool = False,
) -> None:
    disabled_org_ids = await _get_disabled_org_ids(session, plugin_id)
    started_orgs: list[Any] = []
    try:
        for org_id in await _get_active_org_ids(session):
            if org_id in disabled_org_ids:
                continue
            await _start_plugin_for_org(plugin_id, org_id, session, app, replace_routes)
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


class CapabilityInfo(BaseModel):
    """One entry in the platform's capability vocabulary."""

    code: str
    summary: str
    core_permissions: list[str]
    mutating: bool


class PluginSupervisionResponse(BaseModel):
    """Fleet-wide supervision state."""

    quarantined: list[str]
    plugins: dict[str, Any]


@router.get("/supervision", response_model=PluginSupervisionResponse)
async def get_plugin_supervision(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> PluginSupervisionResponse:
    """Error rate, latency and quarantine state for every plugin at once.

    The per-plugin health endpoint answers "is THIS plugin ok". This answers the
    question an operator actually has during an incident: which of them is
    misbehaving. Before supervision existed there was no way to ask either --
    plugin failures were logged without naming the plugin.

    Declared above ``/{plugin_id}`` because FastAPI matches in definition order
    and would otherwise read "supervision" as a plugin id.
    """
    _require_org_admin(current_user)
    from app.plugins.supervision import supervisor

    return PluginSupervisionResponse(
        quarantined=supervisor.quarantined_plugins(),
        plugins=supervisor.snapshot(),
    )


@router.post("/{plugin_id}/supervision/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset_plugin_supervision(
    plugin_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> None:
    """Clear a plugin's error budget and lift its quarantine immediately.

    For the operator who has fixed the cause -- restored the upstream the plugin
    was calling, corrected its settings -- and does not want to wait out a
    cooldown that doubles each time. Without this the only remedies were waiting
    or restarting the API.
    """
    _require_org_admin(current_user)
    from app.plugins.supervision import supervisor

    supervisor.reset(plugin_id)
    logger.info("Supervision state reset for plugin %s by %s", plugin_id, current_user.id)


@router.get("/capabilities", response_model=list[CapabilityInfo])
async def list_capabilities(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> list[CapabilityInfo]:
    """The capability vocabulary a plugin manifest may declare.

    The consent dialog needs this because a manifest's ``name`` and
    ``description`` for a permission are written by the PLUGIN AUTHOR. A plugin
    can label ``devices.stage`` as "Read Alerts" and the operator approving the
    install would read the author's wording, not what the code actually grants.
    Rendering the platform's own summary, keyed by code, is what makes the
    consent dialog mean something.

    Declared above ``/{plugin_id}`` deliberately: FastAPI matches in definition
    order, so a route registered after the path parameter would be shadowed and
    "capabilities" would be read as a plugin id.
    """
    _require_org_admin(current_user)
    return [
        CapabilityInfo(
            code=capability.code,
            summary=capability.summary,
            core_permissions=sorted(capability.core_permissions),
            mutating=capability.code in MUTATING_CAPABILITIES,
        )
        for capability in (CAPABILITIES[code] for code in known_codes())
    ]


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
    check_authority = capture_plugin_mutation_authority(request, current_user, session)
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    try:
        record = await plugin_loader.install_plugin(
            source=file,
            db=session,
            installed_by_id=current_user.id,
            before_mutation=check_authority,
        )
        await _start_plugin_everywhere(record.plugin_id, session, request.app)
        await _audit_plugin_install(session, current_user, record, source="upload")
        return _with_reload_note(record)
    except PluginLoadError as exc:
        # Name the reason. The endpoint requires an unscoped super admin, so
        # there is no audience here that should not see a plugin diagnostic --
        # and the person who can fix it is the person reading the response.
        logger.error("Plugin install failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=400, detail=f"Plugin installation failed: {exc}")
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
    check_authority = capture_plugin_mutation_authority(request, current_user, session)
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
            before_mutation=check_authority,
            source_url=body.url,
        )
        await _start_plugin_everywhere(record.plugin_id, session, request.app)
        await _audit_plugin_install(session, current_user, record, source=f"url:{body.url}")
        return _with_reload_note(record)
    except PluginLoadError as exc:
        logger.error("Plugin install-url failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=400, detail=f"Plugin installation failed: {exc}")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Plugin install-url failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Install failed") from exc


@router.delete("/{plugin_id}", status_code=status.HTTP_204_NO_CONTENT)
async def uninstall_plugin(
    plugin_id: str,
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    purge_settings: Annotated[
        bool,
        Query(
            description=(
                "Also delete this plugin's stored settings for every organization, "
                "including any encrypted credentials. Off by default so an accidental "
                "uninstall does not lose a working configuration."
            )
        ),
    ] = False,
) -> None:
    """Uninstall a plugin (calls on_uninstall hook then removes files).

    Settings are KEPT by default and a reinstall picks them back up, which is
    what makes uninstall-reinstall a safe troubleshooting step. The cost is that
    a credential outlives the plugin that used it, and the uninstall dialog used
    to say only that settings "may remain" -- vague about something that always
    happens, and silent about the part that matters, which is the token.

    ``purge_settings=true`` removes them. Kept as a choice rather than made the
    default because the two reasons to uninstall want opposite behaviour: fixing
    a misbehaving plugin wants the configuration back, and removing a plugin you
    are done with wants the credential gone.
    """
    _require_plugin_platform_admin(current_user)
    check_authority = capture_plugin_mutation_authority(request, current_user, session)
    # Capture plugin details BEFORE uninstall (the loader may delete the row).
    pre_result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    pre_plugin = pre_result.scalar_one_or_none()
    pre_name = pre_plugin.name if pre_plugin else None
    pre_version = pre_plugin.version if pre_plugin else None
    try:
        await plugin_loader.uninstall_plugin(plugin_id, session, before_mutation=check_authority)
    except PluginLoadError as exc:
        logger.error("Plugin uninstall failed for %s: %s", plugin_id, exc, exc_info=True)
        raise HTTPException(status_code=404, detail="Plugin not found")
    purged = 0
    if purge_settings:
        # Every organization's settings, not just the caller's: this is a
        # PLATFORM uninstall, the files are gone for everyone, and leaving one
        # tenant's credentials behind because a different tenant's admin pressed
        # the button would be the worst of both answers.
        result = await session.execute(
            delete(PluginSetting).where(PluginSetting.plugin_id == plugin_id)
        )
        purged = result.rowcount or 0
        await session.execute(
            delete(PluginOrganizationState).where(PluginOrganizationState.plugin_id == plugin_id)
        )
        await session.commit()
        logger.info("Purged %d stored setting(s) for uninstalled plugin %s", purged, plugin_id)

    # audit lifecycle operation
    await _audit_plugin_lifecycle(
        session,
        current_user,
        action=AuditAction.UNINSTALL,
        plugin_id=plugin_id,
        plugin_name=pre_name,
        version=pre_version,
        extra={"purged_settings": purged if purge_settings else None},
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
    check_authority = capture_plugin_mutation_authority(request, current_user, session)
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
        await check_authority()
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
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PluginSummary:
    """Disable a plugin without removing it."""
    if not _is_global_scope(current_user):
        _require_org_admin(current_user)
    check_authority = capture_plugin_mutation_authority(request, current_user, session)
    result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    # NOTE: serialise disable via per-plugin lifecycle lock.
    async with plugin_loader.lifecycle_lock(plugin_id):
        await check_authority()
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
    check_authority = capture_plugin_mutation_authority(request, current_user, session)
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    # Capture pre-upgrade version for audit trail
    pre_result = await session.execute(
        select(InstalledPlugin).where(InstalledPlugin.plugin_id == plugin_id)
    )
    pre_plugin = pre_result.scalar_one_or_none()
    pre_version = pre_plugin.version if pre_plugin else None
    try:
        # The loader validates the archive before stopping active runtimes,
        # then holds its lifecycle lock across shutdown and file replacement.
        record = await plugin_loader.upgrade_plugin(
            plugin_id=plugin_id,
            source=file,
            db=session,
            installed_by_id=current_user.id,
            before_mutation=check_authority,
        )
        await _start_plugin_everywhere(plugin_id, session, request.app, replace_routes=True)
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
        return _with_reload_note(record)
    except PluginLoadError as exc:
        logger.error("Plugin upgrade failed for %s: %s", plugin_id, exc, exc_info=True)
        raise HTTPException(status_code=400, detail=f"Plugin upgrade failed: {exc}")
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
    raw = {row.key: row.value for row in result.scalars().all()}

    # Never return a stored secret, and never return the ciphertext either --
    # handing back "fernet:gAAAA..." would put it in logs and browser history
    # for no benefit. A declared-secret key reports only whether it is set, so
    # the UI can show "configured" without ever holding the value.
    secret_keys = await _secret_setting_keys(session, plugin_id)
    settings: dict[str, Any] = {}
    for key, value in raw.items():
        if key.endswith(":encrypted"):
            continue  # the twin below reports it
        if key.startswith("__"):
            # Platform-internal state, not configuration. A plugin's own
            # bookkeeping shared this table with the operator's settings and was
            # rendered in the settings form as an editable field, which invites
            # someone to "fix" a value the plugin depends on. The ``__`` prefix
            # is reserved; see PUT below, which refuses to write one.
            continue
        if key in secret_keys:
            configured = bool(raw.get(f"{key}:encrypted")) or bool(value)
            settings[key] = SECRET_MASK if configured else ""
        else:
            settings[key] = value
    # A secret whose plaintext twin was already blanked still needs an entry.
    for key in secret_keys:
        if key not in settings:
            settings[key] = SECRET_MASK if raw.get(f"{key}:encrypted") else ""
    return {"settings": settings}


#: What GET reports in place of a stored secret, and what PUT reads back as
#: "leave this one alone". Defined once because the two ends have to agree: if
#: GET masks with one string and PUT recognises another, a round-trip stores the
#: mask AS the credential.
SECRET_MASK = "***"


async def _secret_setting_keys(session: AsyncSession, plugin_id: str) -> set[str]:
    """Setting keys the plugin declared as secret in its manifest.

    A plugin marks a field secret with ``"secret": true`` (or the JSON Schema
    idiom ``"format": "password"``) in its ``settings_schema``:

        settings_schema:
          properties:
            api_token:
              type: string
              secret: true

    Reads the CACHED manifest rather than the file, so this cannot be influenced
    by anything on disk after install, and returns an empty set on any doubt --
    which degrades to the previous plaintext behaviour rather than to a
    corrupted setting.
    """
    cached = (
        await session.execute(
            select(InstalledPlugin.manifest_cache).where(InstalledPlugin.plugin_id == plugin_id)
        )
    ).scalar_one_or_none()
    if not isinstance(cached, dict):
        return set()
    schema = cached.get("settings_schema")
    if not isinstance(schema, dict):
        return set()
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return set()
    return {
        key
        for key, spec in properties.items()
        if isinstance(spec, dict)
        and (spec.get("secret") is True or str(spec.get("format", "")).lower() == "password")
    }


@router.put("/{plugin_id}/settings")
async def update_plugin_settings(
    plugin_id: str,
    body: PluginSettingsUpdate,
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Update org-scoped settings for a plugin."""
    _require_org_admin(current_user)
    check_authority = capture_plugin_mutation_authority(request, current_user, session)
    await _verify_plugin_installed(session, plugin_id)
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="Organization required")

    # Upsert each key atomically. A prior SELECT-then-INSERT raced under
    # concurrent PUTs for the same (plugin_id, org_id, key): both requests
    # could SELECT-miss and INSERT, so one commit hit the
    # ``ix_plugin_settings_lookup`` unique index and surfaced as a 500.
    # ON CONFLICT ... DO UPDATE collapses insert/update into one statement.
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    # Which fields the plugin declared as secret. A credential typed into the
    # settings UI used to land in plugin_settings as PLAINTEXT and stay there:
    # the SDK had set_secret/get_secret, which keep a value encrypted under a
    # separate ``<key>:encrypted`` entry, but nothing connected them to the form
    # the operator actually fills in. Every credential-bearing plugin therefore
    # had to migrate the value itself on first read, and until it did the token
    # sat readable to anyone with settings access.
    reserved = sorted(k for k in body.settings if k.startswith("__"))
    if reserved:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Keys beginning with '__' are reserved for platform state and cannot be "
                f"set as configuration: {', '.join(reserved)}"
            ),
        )

    secret_keys = await _secret_setting_keys(session, plugin_id)
    stored: dict[str, Any] = {}

    for key, value in body.settings.items():
        target_key, target_value = key, value

        # A secret submitted as the MASK means "I did not touch this one".
        #
        # GET reports a configured secret as ``***`` and never the value, so the
        # most natural thing any client does -- read the settings, change one
        # field, write them back -- used to send ``***`` for every untouched
        # credential, and this endpoint encrypted that literal AS the
        # credential. The real token was destroyed silently: the plugin then
        # authenticated with ``***`` and failed, while the UI went on reporting
        # the field as configured. Reproduced end to end before fixing:
        #
        #   PUT {"zabbix_token": "REAL-SECRET-TOKEN-123"}  -> stored, encrypted
        #   GET                                            -> {"zabbix_token": "***"}
        #   PUT (same body, one unrelated field edited)    -> 200
        #   decrypt(stored)                                -> '***'
        #
        # Skipping it entirely is deliberate: it leaves whatever is already
        # there untouched, including nothing. Storing the mask is never the
        # right outcome, and an operator who genuinely wants a credential of
        # three asterisks is a case worth losing to keep every other one safe.
        if key in secret_keys and value == SECRET_MASK:
            stored[key] = SECRET_MASK
            continue

        if key in secret_keys and isinstance(value, str) and value:
            from app.core.security_utils import encrypt_webhook_secret

            target_key = f"{key}:encrypted"
            target_value = encrypt_webhook_secret(value)
            # Blank the plaintext twin so a value written before this existed,
            # or by an older client, does not linger next to the encrypted one.
            await session.execute(
                pg_insert(PluginSetting)
                .values(
                    plugin_id=plugin_id,
                    organization_id=current_user.organization_id,
                    key=key,
                    value="",
                )
                .on_conflict_do_update(
                    index_elements=["plugin_id", "organization_id", "key"],
                    set_={"value": ""},
                )
            )
            stored[key] = SECRET_MASK
        else:
            stored[key] = value

        stmt = pg_insert(PluginSetting).values(
            plugin_id=plugin_id,
            organization_id=current_user.organization_id,
            key=target_key,
            value=target_value,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["plugin_id", "organization_id", "key"],
            set_={"value": target_value},
        )
        await session.execute(stmt)

        if key in secret_keys and value == "":
            # An explicit blank clears both storage forms. Otherwise the SDK
            # falls back to the old encrypted value after the plaintext clears.
            # Match replacement's plaintext-then-ciphertext lock order and keep
            # both changes in the transaction checked below before committing.
            await session.execute(
                delete(PluginSetting).where(
                    PluginSetting.plugin_id == plugin_id,
                    PluginSetting.organization_id == current_user.organization_id,
                    PluginSetting.key == f"{key}:encrypted",
                )
            )

    # An upsert can wait for another settings writer. Recheck the initiating
    # account, tenant and credential after every pending write has returned, so
    # revoked callers cannot commit either a setting or its encrypted twin.
    # Re-running API-key authentication here would commit last_used and these
    # writes; use the non-committing scalar authority check instead.
    try:
        await check_authority()
    except BaseException:
        await session.rollback()
        raise
    await session.commit()

    # Ask the plugin whether what was just saved actually works. Advisory: the
    # commit above already happened, and this only adds a warning the operator
    # would otherwise have had to wait for a schedule to discover.
    warning = await _validate_plugin_config(plugin_id, current_user.organization_id)

    # Never echo a secret back, not even the one just sent. It would land in
    # request logs and browser history for no benefit.
    result: dict[str, Any] = {"settings": stored}
    if warning:
        result["warning"] = warning
    return result


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

    # The plugin's OWN answer, supervised: health_check is plugin-authored code
    # like any other, and a health check that hangs is a health check that takes
    # the endpoint down with it.
    from app.plugins.supervision import supervisor

    try:
        async with supervisor.guard(plugin_id, "lifecycle", timeout=10.0, record_only=True):
            details = await runtime.health_check()
    except Exception as exc:
        # Covers a quarantined plugin, a timeout and anything the plugin raises.
        # A health endpoint that 500s because the thing it reports on is broken
        # is the least useful possible behaviour.
        details = {"status": "unhealthy", "error": f"{type(exc).__name__}: {exc}"[:300]}
    normalized_details = details if isinstance(details, dict) else {"result": details}

    # What SUPERVISION knows, which is the part the plugin cannot self-report:
    # its error rate, its latency, and whether the platform has stopped calling
    # it. A plugin quarantined for failing every event will happily answer
    # "status: ok" to its own health check.
    supervision = supervisor.snapshot(plugin_id)
    normalized_details["supervision"] = supervision
    if supervision.get("state") == "quarantined":
        normalized_details["status"] = "quarantined"
    elif supervision.get("state") == "degraded" and normalized_details.get("status") == "ok":
        normalized_details["status"] = "degraded"
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


async def _schedule_infos(
    plugin_id: str,
    organization_id: UUID,
    session: AsyncSession,
) -> list[PluginScheduleInfo]:
    from app.models.plugins import PluginSetting
    from app.plugins.scheduler import DISABLED_SETTING_PREFIX, plugin_scheduler

    runtime = plugin_loader.get_active_for_org(plugin_id, organization_id)
    if runtime is None:
        return []
    manifest = getattr(runtime, "_plugin_manifest_data", None)
    schedules = list(getattr(manifest, "schedules", None) or [])
    if not schedules:
        return []

    # One query for every toggle rather than one per schedule.
    rows = await session.execute(
        select(PluginSetting.key, PluginSetting.value).where(
            PluginSetting.plugin_id == plugin_id,
            PluginSetting.organization_id == organization_id,
            PluginSetting.key.startswith(DISABLED_SETTING_PREFIX),
        )
    )
    # Absent is NOT the same as enabled: a schedule shipping
    # ``enabled_by_default: false`` has no row until an operator decides.
    toggles = {key[len(DISABLED_SETTING_PREFIX) :]: value for key, value in rows.all()}

    stats = plugin_scheduler.stats(plugin_id, organization_id)
    infos: list[PluginScheduleInfo] = []
    for sched in schedules:
        stat = stats.get(sched.name, {})
        enabled = not toggles[sched.name] if sched.name in toggles else sched.enabled_by_default
        infos.append(
            PluginScheduleInfo(
                name=sched.name,
                method=sched.method,
                interval_seconds=sched.interval_seconds,
                description=sched.description,
                enabled=enabled,
                next_run_at=(
                    plugin_scheduler.next_run_at(plugin_id, organization_id, sched)
                    if enabled
                    else None
                ),
                last_run=await plugin_scheduler.last_run(plugin_id, organization_id, sched.name),
                runs_this_worker=int(stat.get("runs", 0)),
                failures_this_worker=int(stat.get("failures", 0)),
                blocked_this_worker=stat.get("blocked"),
            )
        )
    return infos


@router.get("/{plugin_id}/schedules", response_model=list[PluginScheduleInfo])
async def list_plugin_schedules(
    plugin_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[PluginScheduleInfo]:
    """What this plugin runs unattended, and whether it is actually running."""
    _require_org_admin(current_user)
    await _verify_plugin_installed(session, plugin_id)
    if not current_user.organization_id:
        return []
    return await _schedule_infos(plugin_id, current_user.organization_id, session)


@router.put("/{plugin_id}/schedules/{name}", response_model=PluginScheduleInfo)
async def set_plugin_schedule_enabled(
    plugin_id: str,
    name: str,
    body: PluginScheduleUpdate,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PluginScheduleInfo:
    """Turn one schedule on or off for this organization.

    Per organization, not per plugin: on a shared appliance one tenant wanting
    a quiet inventory sync must not stop another's drift scan. Stored under the
    reserved ``__`` settings prefix, so it never appears in -- or is clobbered
    by -- the operator's configuration form.
    """
    from app.models.plugins import PluginSetting
    from app.plugins.scheduler import DISABLED_SETTING_PREFIX

    _require_org_admin(current_user)
    await _verify_plugin_installed(session, plugin_id)
    org_id = current_user.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization required")

    runtime = plugin_loader.get_active_for_org(plugin_id, org_id)
    manifest = getattr(runtime, "_plugin_manifest_data", None) if runtime else None
    known = {s.name for s in (getattr(manifest, "schedules", None) or [])}
    if name not in known:
        # 404 rather than silently storing a toggle for a schedule that does not
        # exist -- which would read as success and change nothing forever.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Plugin '{plugin_id}' declares no schedule named '{name}'",
        )

    from sqlalchemy.dialects.postgresql import insert as pg_insert

    key = f"{DISABLED_SETTING_PREFIX}{name}"
    value = "" if body.enabled else "1"
    stmt = pg_insert(PluginSetting).values(
        plugin_id=plugin_id,
        organization_id=org_id,
        key=key,
        value=value,
    )
    await session.execute(
        stmt.on_conflict_do_update(
            index_elements=["plugin_id", "organization_id", "key"],
            set_={"value": value},
        )
    )
    await session.commit()

    infos = await _schedule_infos(plugin_id, org_id, session)
    for info in infos:
        if info.name == name:
            return info
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")


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
