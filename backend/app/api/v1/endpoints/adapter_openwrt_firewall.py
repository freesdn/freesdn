# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OpenWrt Firewall write endpoint.

URL layout::

    POST  /api/v1/gateway-openwrt-firewall/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-openwrt-firewall/{controller_id}/changes

Stage-only — the live reads remain under ``/gateway-openwrt/{cid}/*``
(the umbrella read namespace). Writes route through the shared apply
dispatcher at ``/gateway-vpn/changes/{change_id}/apply``.

Feature prefix is locked to ``openwrt.firewall.*`` so a caller with
``firewall:write`` can't smuggle a non-firewall feature through this URL.
Mirror the pfSense / OPNsense per-domain split.
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
from app.services.adapter_openwrt_firewall import (
    GatewayOpenWrtFirewallService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-openwrt-firewall",
    tags=["gateway-openwrt-firewall"],
)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_openwrt_firewall_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("openwrt.firewall."):
        raise HTTPException(
            400,
            detail=("OpenWrt firewall endpoint only accepts openwrt.firewall.* features"),
        )
    svc = GatewayOpenWrtFirewallService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,  # OpenWrt is controller-scoped, no FreeSDN sub-sites
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_openwrt_firewall(
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
        feature_prefix="openwrt.firewall.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
