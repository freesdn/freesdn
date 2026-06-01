# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Security endpoint.

URL layout::

    GET   /api/v1/gateway-mikrotik-security/{controller_id}/users
    GET   /api/v1/gateway-mikrotik-security/{controller_id}/certificates
    GET   /api/v1/gateway-mikrotik-security/{controller_id}/snmp/settings
    GET   /api/v1/gateway-mikrotik-security/{controller_id}/snmp/communities
    GET   /api/v1/gateway-mikrotik-security/{controller_id}/radius/servers
    GET   /api/v1/gateway-mikrotik-security/{controller_id}/radius/incoming
    POST  /api/v1/gateway-mikrotik-security/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-mikrotik-security/{controller_id}/changes

Reads run live; writes stage. Stage endpoint locks ``feature`` to
``mikrotik.security.*``.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.adapter_mikrotik_system import (
    _invalidate_paginate_cache,
    _paginate_cached,
)
from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_mikrotik import (
    MikroTikSnmpTrapTarget,
    MikroTikSnmpV3User,
)
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_mikrotik_security import (
    GatewayMikrotikSecurityService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-mikrotik-security",
    tags=["gateway-mikrotik-security"],
)


# Catastrophic feature codes — these require ``site_admin`` even at
# stage time. Same list maintained in
# ``gateway_vpn._CATASTROPHIC_FEATURE_PREFIXES``; we mirror the
# MikroTik-relevant subset here so stage-gate decisions are local.
_CATASTROPHIC_STAGE_FEATURES: frozenset[str] = frozenset(
    {
        # No mikrotik.security.* features are catastrophic per the central
        # list, but the kept frozenset lets us add them if a future
        # security feature qualifies (e.g. wiping the user table).
    }
)


def _paginate(response: dict[str, Any], limit: int, offset: int) -> dict[str, Any]:
    """Legacy in-memory slicer kept for parity. New code prefers
    ``_paginate_cached`` so page-flips don't refetch."""
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


@router.get("/{controller_id}/users")
async def list_users(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSecurityService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="security.users",
        query_hash="",
        fetch=lambda: svc.list_users(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/certificates")
async def list_certificates(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSecurityService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="security.certificates",
        query_hash="",
        fetch=lambda: svc.list_certificates(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/snmp/settings")
async def get_snmp_settings(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Singleton — no pagination.
    svc = GatewayMikrotikSecurityService(session)
    return await svc.get_snmp_settings(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/snmp/communities")
async def list_snmp_communities(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSecurityService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="security.snmp.communities",
        query_hash="",
        fetch=lambda: svc.list_snmp_communities(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{controller_id}/snmp/trap-targets",
    response_model=list[MikroTikSnmpTrapTarget],
)
async def list_snmp_trap_targets(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """List SNMP trap targets (RouterOS ``trap-target`` comma-list)."""
    svc = GatewayMikrotikSecurityService(session)
    targets = await svc.list_snmp_trap_targets(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )
    return [MikroTikSnmpTrapTarget(host=t) for t in targets]


@router.get(
    "/{controller_id}/snmp/v3-users",
    response_model=list[MikroTikSnmpV3User],
)
async def list_snmp_v3_users(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """List SNMPv3 users (``/snmp/users``)."""
    svc = GatewayMikrotikSecurityService(session)
    rows = await svc.list_snmp_v3_users(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )
    return [MikroTikSnmpV3User.model_validate(r) for r in rows]


@router.get("/{controller_id}/radius/servers")
async def list_radius_servers(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikSecurityService(session)
    return await _paginate_cached(
        organization_id=user.organization_id,
        controller_id=controller_id,
        endpoint_key="security.radius.servers",
        query_hash="",
        fetch=lambda: svc.list_radius_servers(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/radius/incoming")
async def get_radius_incoming(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Singleton — no pagination.
    svc = GatewayMikrotikSecurityService(session)
    return await svc.get_radius_incoming(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_mikrotik_security_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    # mikrotik.security.* mutates admin-tier surface (users,
    # certificates, RADIUS, SNMP). Stage gate must be at least as strict
    # as the apply gate, otherwise a low-tier operator can stage an
    # admin change and a separate apply caller (with controller:write)
    # rubber-stamps it. The apply step would refuse, but having the
    # change sitting in the pending queue is itself a leakable signal.
    user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("mikrotik.security."):
        raise HTTPException(
            400,
            detail=("MikroTik security endpoint only accepts mikrotik.security.* features"),
        )
    # catastrophic features require site_admin at stage
    # time too. No mikrotik.security.* feature currently qualifies,
    # but the frozenset above + this check guard against future
    # additions silently bypassing the role gate.
    if feature in _CATASTROPHIC_STAGE_FEATURES and not user.has_min_role("site_admin"):
        raise HTTPException(
            403,
            detail=(
                f"feature {feature!r} is catastrophic and requires minimum role site_admin to stage"
            ),
        )
    svc = GatewayMikrotikSecurityService(session)
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
async def list_pending_mikrotik_security(
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
        feature_prefix="mikrotik.security.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
