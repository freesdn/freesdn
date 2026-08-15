# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense VPN endpoint.

URL layout::

    GET   /api/v1/gateway-opnsense-vpn/{controller_id}/wireguard/servers
    GET   /api/v1/gateway-opnsense-vpn/{controller_id}/wireguard/peers
    GET   /api/v1/gateway-opnsense-vpn/{controller_id}/openvpn/instances
    GET   /api/v1/gateway-opnsense-vpn/{controller_id}/openvpn/status
    GET   /api/v1/gateway-opnsense-vpn/{controller_id}/ipsec/tunnels
    GET   /api/v1/gateway-opnsense-vpn/{controller_id}/ipsec/status
    POST  /api/v1/gateway-opnsense-vpn/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-opnsense-vpn/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint, which now
dispatches OPNsense features through this service's ``build_applier``.

Stage endpoint locks ``feature`` to ``opnsense.vpn.*`` so a caller
with ``firewall:write`` can't smuggle a non-VPN feature through this
URL. (VPN reads/writes stay under the firewall permission set —
OPNsense IS the firewall, and operators with write access to the
firewall already have the keys to the box.)
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.validation import validate_id
from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_opnsense_vpn import (
    GatewayOpnsenseVpnService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-opnsense-vpn",
    tags=["gateway-opnsense-vpn"],
)


# ── Reads ─ WireGuard ────────────────────────────────────────────────


@router.get("/{controller_id}/wireguard/servers")
async def list_wireguard_servers(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseVpnService(session)
    return await svc.list_wireguard_servers(controller_id, user.organization_id)


@router.get("/{controller_id}/wireguard/peers")
async def list_wireguard_peers(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseVpnService(session)
    return await svc.list_wireguard_peers(controller_id, user.organization_id)


# ── Reads ─ OpenVPN ──────────────────────────────────────────────────


@router.get("/{controller_id}/openvpn/instances")
async def list_openvpn_instances(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseVpnService(session)
    return await svc.list_openvpn_instances(controller_id, user.organization_id)


@router.get("/{controller_id}/openvpn/status")
async def get_openvpn_status(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseVpnService(session)
    return await svc.get_openvpn_status(controller_id, user.organization_id)


# ── Reads ─ IPsec ────────────────────────────────────────────────────


@router.get("/{controller_id}/ipsec/tunnels")
async def list_ipsec_tunnels(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseVpnService(session)
    return await svc.list_ipsec_tunnels(controller_id, user.organization_id)


@router.get("/{controller_id}/ipsec/status")
async def get_ipsec_status(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseVpnService(session)
    return await svc.get_ipsec_status(controller_id, user.organization_id)


# ── Stage ────────────────────────────────────────────────────────────


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_opnsense_vpn_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("opnsense.vpn."):
        raise HTTPException(
            400,
            detail=("OPNsense VPN endpoint only accepts opnsense.vpn.* features"),
        )
    # Defense-in-depth: update/delete operations target an existing
    # vendor-issued ID. Validate at stage-time so a malformed value
    # never reaches the staging row, never reaches the URL on apply.
    if operation in ("update", "delete"):
        if not body.target_id:
            raise HTTPException(
                400,
                detail=("OPNsense VPN update/delete requires target_id"),
            )
        validate_id(body.target_id, label="target_id")
    svc = GatewayOpnsenseVpnService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,  # OPNsense is controller-scoped (no FreeSDN sub-sites)
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


# ── List pending ─────────────────────────────────────────────────────


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_opnsense_vpn(
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
        feature_prefix="opnsense.vpn.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
