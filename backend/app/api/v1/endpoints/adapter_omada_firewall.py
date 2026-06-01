# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway firewall depth endpoints
==========================================================

URL filter, app/DPI control, port forwarding, DMZ, 1:1 NAT, UPnP,
attack defense, ALG, IDS/IPS. Reads run live; writes always stage.

URL layout::

    GET     /api/v1/gateway-firewall/{controller_id}/sites/{site_id}/lists/{collection}
    GET     /api/v1/gateway-firewall/{controller_id}/sites/{site_id}/configs/{config_name}
    POST    /api/v1/gateway-firewall/{controller_id}/sites/{site_id}/changes/{feature}
    GET     /api/v1/gateway-firewall/{controller_id}/sites/{site_id}/changes

collection ∈ {url_filter, app_filter, app_categories, port_forward,
one_to_one_nat, upnp_mappings, ids_ips_events}

config_name ∈ {dmz, upnp, attack_defense, alg, ids_ips}
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_omada_firewall import GatewayFirewallService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-firewall", tags=["gateway-firewall"])


@router.get("/{controller_id}/sites/{site_id}/lists/{collection}")
async def list_collection(
    controller_id: UUID,
    site_id: UUID,
    collection: str,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Per-user site grant: site_id is an explicit path param,
    # so enforce the caller's grant before the live read. No-op for
    # super_admin / org_admin / grant-less users.
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayFirewallService(session)
    return await svc.list_collection(controller_id, user.organization_id, site_id, collection)


@router.get("/{controller_id}/sites/{site_id}/configs/{config_name}")
async def get_config(
    controller_id: UUID,
    site_id: UUID,
    config_name: str,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayFirewallService(session)
    return await svc.get_config(controller_id, user.organization_id, site_id, config_name)


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_firewall_change(
    controller_id: UUID,
    site_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("firewall."):
        from fastapi import HTTPException

        raise HTTPException(400, detail="firewall endpoint only accepts firewall.* features")
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayFirewallService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=site_id,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/sites/{site_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_firewall_changes(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    assert_can_access_site(user, site_id, detail="site not found")
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="firewall.",
        status_filter=status_filter,
        limit=limit,
    )
    changes = [c for c in changes if c.site_id == site_id]
    return [PendingChangeResponse.from_model(c) for c in changes]
