# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OpenWrt DHCP/DNS write endpoint.

URL layout::

    POST  /api/v1/gateway-openwrt-dhcp/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-openwrt-dhcp/{controller_id}/changes

Stage-only — same shape as ``gateway-openwrt-firewall``. Apply path is
the shared ``/gateway-vpn/changes/{id}/apply`` dispatcher.

Locked to ``openwrt.dhcp.*`` and ``openwrt.dns.*`` prefixes since both
domains share the dnsmasq UCI file and the same adapter cluster.
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
from app.services.adapter_openwrt_dhcp import GatewayOpenWrtDhcpService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-openwrt-dhcp",
    tags=["gateway-openwrt-dhcp"],
)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_openwrt_dhcp_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not (feature.startswith("openwrt.dhcp.") or feature.startswith("openwrt.dns.")):
        raise HTTPException(
            400,
            detail=("OpenWrt DHCP endpoint only accepts openwrt.dhcp.* or openwrt.dns.* features"),
        )
    svc = GatewayOpenWrtDhcpService(session)
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
async def list_pending_openwrt_dhcp(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    # Drawer fetches both DHCP + DNS staged rows from this one endpoint —
    # OR the two prefixes at the SQL layer so we don't post-filter.
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefixes=["openwrt.dhcp.", "openwrt.dns."],
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
