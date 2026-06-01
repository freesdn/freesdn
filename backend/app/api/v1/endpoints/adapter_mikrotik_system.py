# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik System / Operations endpoint.

URL layout::

    GET   /api/v1/gateway-mikrotik-system/{controller_id}/info
    GET   /api/v1/gateway-mikrotik-system/{controller_id}/services
    GET   /api/v1/gateway-mikrotik-system/{controller_id}/files
    GET   /api/v1/gateway-mikrotik-system/{controller_id}/logs
    GET   /api/v1/gateway-mikrotik-system/{controller_id}/switch/chips
    GET   /api/v1/gateway-mikrotik-system/{controller_id}/switch/ports
    GET   /api/v1/gateway-mikrotik-system/{controller_id}/switch/vlans
    GET   /api/v1/gateway-mikrotik-system/{controller_id}/switch/rules
    POST  /api/v1/gateway-mikrotik-system/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-mikrotik-system/{controller_id}/changes

Reads run live; writes stage. Stage endpoint locks ``feature`` to
``mikrotik.system.*``.
"""

from __future__ import annotations

import time
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_min_role, require_permissions
from app.db.session import get_session
from app.schemas.gateway_mikrotik import (
    MikroTikBackupFile,
    MikroTikFirmwareStatus,
    MikroTikLldpInterface,
    MikroTikNeighbor,
    MikroTikPackage,
    MikroTikTopologyResponse,
)
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_mikrotik_system import GatewayMikrotikSystemService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-mikrotik-system",
    tags=["gateway-mikrotik-system"],
)


# ─── Listing-response TTL cache (PERF-CRIT-4) ─────────────────────────
#
# The original ``_paginate`` re-fetched every RouterOS table on every
# page request — on a router with 50k log lines, that's 50k rows
# pulled per page-flip. We cache the full upstream response per
# ``(controller_id, endpoint_key, query_hash)`` for 30s so page-flips
# don't refetch.
#
# The cache is intentionally small (256 entries) and a tight TTL so
# stale data is bounded — operator UI typically re-renders within
# seconds of an apply, the cache TTL is short enough that operator-
# visible drift is < 30s. Cache is **content cache only**: the
# permission / tenant scoping check runs on every request *before*
# we touch the cache, so cross-tenant cache poisoning is structurally
# impossible.
_PAGINATE_CACHE_MAX = 256
_PAGINATE_CACHE_TTL = 30.0  # seconds
_paginate_cache: dict[tuple[str, str, str, str], tuple[float, dict[str, Any]]] = {}


def _paginate_cache_key(
    organization_id: UUID,
    controller_id: UUID,
    endpoint_key: str,
    query_hash: str,
) -> tuple[str, str, str, str]:
    """Cache key includes organization_id so a stale cache from one
    tenant can never serve another (defence-in-depth — the auth
    check on the request already prevents this)."""
    return (str(organization_id), str(controller_id), endpoint_key, query_hash)


async def _paginate_cached(
    *,
    organization_id: UUID,
    controller_id: UUID,
    endpoint_key: str,
    query_hash: str,
    fetch: Any,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Page-flip-friendly variant of the original ``_paginate``.

    Caches the full upstream response for ``_PAGINATE_CACHE_TTL`` seconds
    and slices in-memory on every call. Successive page requests within
    the TTL skip the controller fetch entirely. After TTL expiry, the
    next request transparently refetches.

    ``fetch`` is an awaitable that returns the full ``{items: [...]}``
    response shape — same as the original ``_paginate`` consumed.
    """
    now = time.monotonic()
    key = _paginate_cache_key(organization_id, controller_id, endpoint_key, query_hash)
    cached = _paginate_cache.get(key)
    if cached is not None:
        expires_at, response = cached
        if expires_at > now:
            items = response.get("items") or []
            total = len(items)
            return {
                **response,
                "items": items[offset : offset + limit],
                "limit": limit,
                "offset": offset,
                "total": total,
            }
        # TTL expired — drop the stale entry below.
        _paginate_cache.pop(key, None)

    # Miss / expired: fetch fresh.
    response = await fetch()
    # Bounded cache size — evict the oldest 25% when full.
    if len(_paginate_cache) >= _PAGINATE_CACHE_MAX:
        cutoff = sorted(_paginate_cache.items(), key=lambda kv: kv[1][0])
        for stale_key, _ in cutoff[: _PAGINATE_CACHE_MAX // 4]:
            _paginate_cache.pop(stale_key, None)
    _paginate_cache[key] = (now + _PAGINATE_CACHE_TTL, response)

    items = response.get("items") or []
    total = len(items)
    return {
        **response,
        "items": items[offset : offset + limit],
        "limit": limit,
        "offset": offset,
        "total": total,
    }


def _invalidate_paginate_cache(organization_id: UUID, controller_id: UUID) -> None:
    """Drop every cached listing response for a controller.

    Called from the stage endpoint so a write the operator just made
    becomes visible on the next list request rather than the 30s
    TTL window.
    """
    prefix = (str(organization_id), str(controller_id))
    for key in list(_paginate_cache.keys()):
        if key[:2] == prefix:
            _paginate_cache.pop(key, None)


def _paginate(response: dict[str, Any], limit: int, offset: int) -> dict[str, Any]:
    """Legacy in-memory slicer kept for parity with the test suite.

    New code paths should prefer ``_paginate_cached`` so successive
    page requests don't refetch the full RouterOS table.
    """
    items = response.get("items") or []
    total = len(items)
    sliced = items[offset : offset + limit]
    return {
        **response,
        "items": sliced,
        "limit": limit,
        "offset": offset,
        "total": total,
    }


@router.get("/{controller_id}/info")
async def get_system_info(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Singleton aggregation — no pagination.
    svc = GatewayMikrotikSystemService(session)
    return await svc.get_system_info(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/services")
async def list_services(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSystemService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="services",
        query_hash="",
        fetch=lambda: svc.list_services(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/files")
async def list_files(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSystemService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="files",
        query_hash="",
        fetch=lambda: svc.list_files(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/logs")
async def list_logs(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSystemService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="logs",
        query_hash="",
        fetch=lambda: svc.list_logs(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/switch/chips")
async def list_switch_chips(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSystemService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="switch.chips",
        query_hash="",
        fetch=lambda: svc.list_switch_chips(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/switch/ports")
async def list_switch_ports(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSystemService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="switch.ports",
        query_hash="",
        fetch=lambda: svc.list_switch_ports(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/switch/vlans")
async def list_switch_vlans(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSystemService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="switch.vlans",
        query_hash="",
        fetch=lambda: svc.list_switch_vlans(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/switch/rules")
async def list_switch_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSystemService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="switch.rules",
        query_hash="",
        fetch=lambda: svc.list_switch_rules(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


# ─── GET routes — firmware / packages / backups / neighbors ──


@router.get(
    "/{controller_id}/firmware/status",
    response_model=MikroTikFirmwareStatus,
)
async def get_firmware_status(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Read ``/system/package/update`` — installed + available info."""
    svc = GatewayMikrotikSystemService(session)
    row = await svc.get_firmware_status(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )
    return MikroTikFirmwareStatus.model_validate(row or {})


@router.get(
    "/{controller_id}/packages",
    response_model=list[MikroTikPackage],
)
async def list_packages(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Read installed RouterOS packages."""
    svc = GatewayMikrotikSystemService(session)
    rows = await svc.list_packages(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )
    return [MikroTikPackage.model_validate(r) for r in rows]


@router.get(
    "/{controller_id}/backup/list",
    response_model=list[MikroTikBackupFile],
)
async def list_backups(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Read backup / export / package artefacts on the router's
    file system."""
    svc = GatewayMikrotikSystemService(session)
    rows = await svc.list_backups(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )
    return [MikroTikBackupFile.model_validate(r) for r in rows]


@router.get(
    "/{controller_id}/backup/metadata/{name}",
    response_model=MikroTikBackupFile,
)
async def get_backup_metadata(
    controller_id: UUID,
    name: str,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Read single-file metadata."""
    svc = GatewayMikrotikSystemService(session)
    row = await svc.get_backup_metadata(
        controller_id,
        user.organization_id,
        name,
        is_superuser=user.is_superuser,
    )
    return MikroTikBackupFile.model_validate(row or {"name": name})


@router.get("/{controller_id}/backup/download/{name}")
async def download_backup(
    controller_id: UUID,
    name: str,
    # a RouterOS .backup/.rsc export carries PPP/RADIUS secrets,
    # SNMP communities, WiFi/IPsec PSKs and password hashes — a secret EXPORT,
    # not a read. Double-gate like OPNsense config-download (controller:write +
    # super_admin) so viewer/operator cannot pull it.
    user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    _enforce_role: Annotated[CurrentUser, Depends(require_min_role("super_admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Stream a backup / export file as bytes.

    the contents are streamed via :class:`StreamingResponse`
    so a large backup doesn't have to be buffered in memory before the
    first byte hits the wire. Currently the RouterOS client returns
    contents inline (text exports) — the streaming wrapper is in place
    for when a future client method swaps to a chunked transfer.
    """
    svc = GatewayMikrotikSystemService(session)
    name_out, contents = await svc.stream_backup_content(
        controller_id,
        user.organization_id,
        name,
        is_superuser=user.is_superuser,
    )
    media_type = "text/plain" if name.endswith(".rsc") else "application/octet-stream"

    async def _iter() -> Any:
        # Yield in 64KB chunks so a multi-MB export streams instead of
        # arriving in one blob.
        chunk_size = 64 * 1024
        data = contents.encode() if isinstance(contents, str) else (contents or b"")
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]

    headers = {
        "Content-Disposition": f'attachment; filename="{name_out}"',
        "X-MikroTik-File-Name": name_out,
    }
    return StreamingResponse(_iter(), media_type=media_type, headers=headers)


@router.get(
    "/{controller_id}/neighbors",
    response_model=list[MikroTikNeighbor],
)
async def list_neighbors(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Read CDP / LLDP / MNDP-discovered neighbors."""
    svc = GatewayMikrotikSystemService(session)
    rows = await svc.list_neighbors(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )
    return [MikroTikNeighbor.model_validate(r) for r in rows]


@router.get("/{controller_id}/neighbors/settings")
async def get_neighbor_settings(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Read the neighbor-discovery singleton (protocols + interface list)."""
    svc = GatewayMikrotikSystemService(session)
    return await svc.get_neighbor_settings(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get(
    "/{controller_id}/lldp",
    response_model=list[MikroTikLldpInterface],
)
async def list_lldp(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Read per-interface LLDP state."""
    svc = GatewayMikrotikSystemService(session)
    rows = await svc.list_lldp_interfaces(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )
    return [MikroTikLldpInterface.model_validate(r) for r in rows]


@router.get(
    "/{controller_id}/topology",
    response_model=MikroTikTopologyResponse,
)
async def get_topology(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Composed ``{nodes, edges}`` topology envelope."""
    svc = GatewayMikrotikSystemService(session)
    envelope = await svc.get_topology(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )
    return MikroTikTopologyResponse.model_validate(
        {
            "nodes": envelope.get("nodes") or [],
            "edges": envelope.get("edges") or [],
        }
    )


# Catastrophic ``mikrotik.system.*`` feature codes — these can wipe a
# router config / brick the device / pivot to SSRF. The staging
# gate enforces ``site_admin`` minimum role on top of the permission
# gate. Mirrors ``gateway_vpn._CATASTROPHIC_FEATURE_PREFIXES`` for the
# system subset.
_CATASTROPHIC_SYSTEM_FEATURES: frozenset[str] = frozenset(
    {
        "mikrotik.system.reboot",
        "mikrotik.system.shutdown",
        "mikrotik.system.backup_load",
        "mikrotik.system.tool_fetch",
        "mikrotik.system.export_config",
        "mikrotik.system.firmware.install",
        "mikrotik.system.package.uninstall",
        "mikrotik.system.backup.restore",
        # backup.upload writes arbitrary file name+contents to
        # the RouterOS filesystem (script-injection / device takeover). Treat it
        # as a controller/device-admin operation, not loose network:write.
        "mikrotik.system.backup.upload",
    }
)

# Subset that requires ``controller:write`` (rather than the looser
# default ``network:write``) at stage time. Source of truth lives in
# ``gateway_vpn._MIKROTIK_CONTROLLER_TIER_FEATURES``; mirrored here so
# the stage endpoint can decide before reaching the dispatcher.
_CONTROLLER_TIER_SYSTEM_FEATURES: frozenset[str] = frozenset(
    {
        "mikrotik.system.reboot",
        "mikrotik.system.shutdown",
        "mikrotik.system.backup_load",
        "mikrotik.system.file_delete",
        "mikrotik.system.tool_fetch",
        "mikrotik.system.export_config",
        "mikrotik.system.firmware.install",
        "mikrotik.system.package.uninstall",
        "mikrotik.system.backup.restore",
        # backup.upload writes arbitrary file name+contents to
        # the RouterOS filesystem (script-injection / device takeover). Treat it
        # as a controller/device-admin operation, not loose network:write.
        "mikrotik.system.backup.upload",
    }
)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_mikrotik_system_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("mikrotik.system."):
        raise HTTPException(
            400,
            detail=("MikroTik system endpoint only accepts mikrotik.system.* features"),
        )
    # controller-tier subfeatures (reboot, shutdown,
    # backup_load, file_delete, tool_fetch, export_config, plus the
    # firmware/package/backup additions) require
    # ``controller:write``. Stage gate must match the apply gate
    # otherwise a low-tier operator can plant the change in the queue.
    if feature in _CONTROLLER_TIER_SYSTEM_FEATURES and not user.has_permission("controller:write"):
        raise HTTPException(
            403,
            detail=(f"feature {feature!r} requires controller:write permission to stage"),
        )
    # catastrophic subfeatures also require site_admin
    # minimum role at stage time. Same role gate the apply endpoint
    # enforces — duplicating it here closes the queue-poison window.
    if feature in _CATASTROPHIC_SYSTEM_FEATURES and not user.has_min_role("site_admin"):
        raise HTTPException(
            403,
            detail=(
                f"feature {feature!r} is catastrophic and requires minimum role site_admin to stage"
            ),
        )
    svc = GatewayMikrotikSystemService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    # Listing-cache invalidation: drop any cached responses for this
    # controller so the change becomes visible on the next read.
    _invalidate_paginate_cache(user.organization_id, controller_id)
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_mikrotik_system(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="mikrotik.system.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
