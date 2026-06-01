# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Firewall endpoint.

URL layout::

    GET   /api/v1/gateway-opnsense-firewall/{controller_id}/rules
    GET   /api/v1/gateway-opnsense-firewall/{controller_id}/aliases
    POST  /api/v1/gateway-opnsense-firewall/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-opnsense-firewall/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint, which now
dispatches OPNsense features through this service's ``build_applier``.

Stage endpoint locks ``feature`` to ``opnsense.firewall.*`` so a
caller with ``firewall:write`` can't smuggle a non-firewall feature
through this URL.
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
from app.services.adapter_opnsense_firewall import (
    GatewayOpnsenseFirewallService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-opnsense-firewall",
    tags=["gateway-opnsense-firewall"],
)


@router.get("/{controller_id}/rules")
async def list_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayOpnsenseFirewallService(session)
    return await svc.list_rules(
        controller_id,
        user.organization_id,
        limit=limit,
        offset=offset,
    )


@router.get("/{controller_id}/aliases")
async def list_aliases(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayOpnsenseFirewallService(session)
    return await svc.list_aliases(
        controller_id,
        user.organization_id,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_opnsense_firewall_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("opnsense.firewall."):
        raise HTTPException(
            400,
            detail=("OPNsense firewall endpoint only accepts opnsense.firewall.* features"),
        )
    svc = GatewayOpnsenseFirewallService(session)
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


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_opnsense_firewall(
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
        feature_prefix="opnsense.firewall.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
