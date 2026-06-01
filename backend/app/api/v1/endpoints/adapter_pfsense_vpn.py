# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense VPN endpoint.

URL layout::

    GET   /api/v1/gateway-pfsense-vpn/{controller_id}/openvpn/servers
    GET   /api/v1/gateway-pfsense-vpn/{controller_id}/openvpn/clients
    GET   /api/v1/gateway-pfsense-vpn/{controller_id}/openvpn/status
    GET   /api/v1/gateway-pfsense-vpn/{controller_id}/wireguard/tunnels
    GET   /api/v1/gateway-pfsense-vpn/{controller_id}/wireguard/peers
    GET   /api/v1/gateway-pfsense-vpn/{controller_id}/ipsec/tunnels
    GET   /api/v1/gateway-pfsense-vpn/{controller_id}/ipsec/status
    POST  /api/v1/gateway-pfsense-vpn/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-pfsense-vpn/{controller_id}/changes

Reads run live. The ``stage`` route is wired for shape-parity with the
OPNsense and Omada VPN endpoints, but every staged change today will
land on a 501 at apply-time because the pfSense client does not yet
expose VPN write methods. Stage URL still locks ``feature`` to
``pfsense.vpn.*`` so a caller can't smuggle non-VPN features through.
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
from app.services.adapter_pfsense_vpn import GatewayPfsenseVpnService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-pfsense-vpn",
    tags=["gateway-pfsense-vpn"],
)


def _paginate(payload: Any, limit: int, offset: int) -> Any:
    """Slice ``payload['items']`` and add a paging block."""
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        items = payload["items"]
        total = len(items)
        sliced = items[offset : offset + limit]
        return {
            **payload,
            "items": sliced,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "returned": len(sliced),
                "total": total,
            },
        }
    return payload


# ── OpenVPN reads ───────────────────────────────────────────────────────


@router.get("/{controller_id}/openvpn/servers")
async def list_openvpn_servers(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseVpnService(session)
    payload = await svc.list_openvpn_servers(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/openvpn/clients")
async def list_openvpn_clients(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseVpnService(session)
    payload = await svc.list_openvpn_clients(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/openvpn/status")
async def get_openvpn_status(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Single-status read — not a list, no pagination.
    svc = GatewayPfsenseVpnService(session)
    return await svc.get_openvpn_status(controller_id, user.organization_id)


# ── WireGuard reads ─────────────────────────────────────────────────────


@router.get("/{controller_id}/wireguard/tunnels")
async def list_wireguard_tunnels(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseVpnService(session)
    payload = await svc.list_wireguard_tunnels(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/wireguard/peers")
async def list_wireguard_peers(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseVpnService(session)
    payload = await svc.list_wireguard_peers(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


# ── IPsec reads ─────────────────────────────────────────────────────────


@router.get("/{controller_id}/ipsec/tunnels")
async def list_ipsec_tunnels(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseVpnService(session)
    payload = await svc.list_ipsec_tunnels(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/ipsec/status")
async def get_ipsec_status(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Single-status read — not a list, no pagination.
    svc = GatewayPfsenseVpnService(session)
    return await svc.get_ipsec_status(controller_id, user.organization_id)


# ── Stage / list pending ────────────────────────────────────────────────


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_pfsense_vpn_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("pfsense.vpn."):
        raise HTTPException(
            400,
            detail=("pfSense VPN endpoint only accepts pfsense.vpn.* features"),
        )
    svc = GatewayPfsenseVpnService(session)
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
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_pfsense_vpn(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="pfsense.vpn.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
