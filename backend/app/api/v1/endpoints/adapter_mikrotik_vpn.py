# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik VPN endpoint.

URL layout::

    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/ipsec/peers
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/ipsec/identities
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/ipsec/policies
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/ipsec/profiles
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/ipsec/proposals
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/ipsec/active
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/wireguard/interfaces
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/wireguard/peers
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/l2tp/server
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/pptp/server
    POST  /api/v1/gateway-mikrotik-vpn/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-mikrotik-vpn/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint, which dispatches
``mikrotik.vpn.*`` features through this service's ``build_applier``.

Stage endpoint locks ``feature`` to ``mikrotik.vpn.*`` so a caller
with ``network:write`` cannot smuggle a non-VPN feature through this
URL.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_mikrotik_vpn import GatewayMikrotikVpnService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-mikrotik-vpn",
    tags=["gateway-mikrotik-vpn"],
)


def _paginate(response: dict[str, Any], limit: int, offset: int) -> dict[str, Any]:
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


# ── IPsec reads ─────────────────────────────────────────────────────


@router.get("/{controller_id}/ipsec/peers")
async def list_ipsec_peers(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return _paginate(
        await svc.list_ipsec_peers(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/ipsec/identities")
async def list_ipsec_identities(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return _paginate(
        await svc.list_ipsec_identities(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/ipsec/policies")
async def list_ipsec_policies(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return _paginate(
        await svc.list_ipsec_policies(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/ipsec/profiles")
async def list_ipsec_profiles(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return _paginate(
        await svc.list_ipsec_profiles(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/ipsec/proposals")
async def list_ipsec_proposals(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return _paginate(
        await svc.list_ipsec_proposals(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/ipsec/active")
async def list_ipsec_active(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return _paginate(
        await svc.list_ipsec_active(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


# ── WireGuard reads ─────────────────────────────────────────────────


@router.get("/{controller_id}/wireguard/interfaces")
async def list_wireguard_interfaces(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return _paginate(
        await svc.list_wireguard_interfaces(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/wireguard/peers")
async def list_wireguard_peers(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return _paginate(
        await svc.list_wireguard_peers(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


# ── L2TP / PPTP reads ───────────────────────────────────────────────


@router.get("/{controller_id}/l2tp/server")
async def get_l2tp_server(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return await svc.get_l2tp_server(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/pptp/server")
async def get_pptp_server(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayMikrotikVpnService(session)
    return await svc.get_pptp_server(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


# ── Stage / list pending ────────────────────────────────────────────


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_mikrotik_vpn_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("mikrotik.vpn."):
        raise HTTPException(
            400,
            detail=("MikroTik VPN endpoint only accepts mikrotik.vpn.* features"),
        )
    svc = GatewayMikrotikVpnService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,  # MikroTik is controller-scoped (no FreeSDN sub-sites)
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_mikrotik_vpn(
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
        feature_prefix="mikrotik.vpn.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
