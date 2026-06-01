# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense NAT endpoint.

URL layout::

    GET   /api/v1/gateway-pfsense-nat/{controller_id}/outbound
    GET   /api/v1/gateway-pfsense-nat/{controller_id}/port-forwards
    GET   /api/v1/gateway-pfsense-nat/{controller_id}/one-to-one
    POST  /api/v1/gateway-pfsense-nat/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-pfsense-nat/{controller_id}/changes

Reads run live; writes stage. Stage endpoint locks ``feature`` to
``pfsense.nat.*`` so a caller can't smuggle a non-NAT feature through
this URL.
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
from app.services.adapter_pfsense_nat import GatewayPfsenseNatService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-pfsense-nat",
    tags=["gateway-pfsense-nat"],
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


@router.get("/{controller_id}/outbound")
async def list_outbound_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseNatService(session)
    payload = await svc.list_outbound_rules(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/port-forwards")
async def list_port_forwards(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseNatService(session)
    payload = await svc.list_port_forwards(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/one-to-one")
async def list_one_to_one(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseNatService(session)
    payload = await svc.list_one_to_one(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_pfsense_nat_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("pfsense.nat."):
        raise HTTPException(
            400,
            detail=("pfSense NAT endpoint only accepts pfsense.nat.* features"),
        )
    svc = GatewayPfsenseNatService(session)
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
async def list_pending_pfsense_nat(
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
        feature_prefix="pfsense.nat.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
