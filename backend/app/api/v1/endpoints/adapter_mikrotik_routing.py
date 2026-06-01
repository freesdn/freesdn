# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Routing endpoint.

URL layout::

    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/routes
    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/ospf/instances
    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/ospf/areas
    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/ospf/area-ranges
    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/ospf/interface-templates
    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/ospf/neighbors
    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/bgp/connections
    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/bgp/templates
    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/bgp/sessions
    POST  /api/v1/gateway-mikrotik-routing/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-mikrotik-routing/{controller_id}/changes

Reads run live; writes stage. Stage endpoint locks ``feature`` to
``mikrotik.routing.*``.
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
from app.services.adapter_mikrotik_routing import (
    GatewayMikrotikRoutingService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-mikrotik-routing",
    tags=["gateway-mikrotik-routing"],
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


# ── Static routes ───────────────────────────────────────────────────


@router.get("/{controller_id}/routes")
async def list_routes(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikRoutingService(session)
    return _paginate(
        await svc.list_routes(controller_id, user.organization_id, is_superuser=user.is_superuser),
        limit,
        offset,
    )


# ── OSPF reads ──────────────────────────────────────────────────────


@router.get("/{controller_id}/ospf/instances")
async def list_ospf_instances(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikRoutingService(session)
    return _paginate(
        await svc.list_ospf_instances(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/ospf/areas")
async def list_ospf_areas(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikRoutingService(session)
    return _paginate(
        await svc.list_ospf_areas(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/ospf/area-ranges")
async def list_ospf_area_ranges(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikRoutingService(session)
    return _paginate(
        await svc.list_ospf_area_ranges(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/ospf/interface-templates")
async def list_ospf_interface_templates(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikRoutingService(session)
    return _paginate(
        await svc.list_ospf_interface_templates(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/ospf/neighbors")
async def list_ospf_neighbors(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikRoutingService(session)
    return _paginate(
        await svc.list_ospf_neighbors(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


# ── BGP reads ───────────────────────────────────────────────────────


@router.get("/{controller_id}/bgp/connections")
async def list_bgp_connections(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikRoutingService(session)
    return _paginate(
        await svc.list_bgp_connections(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/bgp/templates")
async def list_bgp_templates(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikRoutingService(session)
    return _paginate(
        await svc.list_bgp_templates(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/bgp/sessions")
async def list_bgp_sessions(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikRoutingService(session)
    return _paginate(
        await svc.list_bgp_sessions(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


# ── Stage / list pending ────────────────────────────────────────────


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_mikrotik_routing_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("mikrotik.routing."):
        raise HTTPException(
            400,
            detail=("MikroTik routing endpoint only accepts mikrotik.routing.* features"),
        )
    svc = GatewayMikrotikRoutingService(session)
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
async def list_pending_mikrotik_routing(
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
        feature_prefix="mikrotik.routing.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
