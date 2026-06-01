# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense Interfaces endpoint.

URL layout::

    GET   /api/v1/gateway-pfsense-interfaces/{controller_id}/interfaces
    GET   /api/v1/gateway-pfsense-interfaces/{controller_id}/stats
    GET   /api/v1/gateway-pfsense-interfaces/{controller_id}/vlans
    POST  /api/v1/gateway-pfsense-interfaces/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-pfsense-interfaces/{controller_id}/changes

Reads run live; VLAN writes go through staging. Stage endpoint locks
``feature`` to ``pfsense.interfaces.*``.
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
from app.services.adapter_pfsense_interfaces import (
    GatewayPfsenseInterfacesService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-pfsense-interfaces",
    tags=["gateway-pfsense-interfaces"],
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


@router.get("/{controller_id}/interfaces")
async def list_interfaces(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseInterfacesService(session)
    payload = await svc.list_interfaces(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/stats")
async def get_interface_stats(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseInterfacesService(session)
    payload = await svc.get_interface_stats(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/vlans")
async def list_vlans(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseInterfacesService(session)
    payload = await svc.list_vlans(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_pfsense_interfaces_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("pfsense.interfaces."):
        raise HTTPException(
            400,
            detail=("pfSense interfaces endpoint only accepts pfsense.interfaces.* features"),
        )
    svc = GatewayPfsenseInterfacesService(session)
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
async def list_pending_pfsense_interfaces(
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
        feature_prefix="pfsense.interfaces.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
