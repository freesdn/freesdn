# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Hotspot endpoint.

URL layout::

    GET   /api/v1/gateway-mikrotik-hotspot/{controller_id}/servers
    GET   /api/v1/gateway-mikrotik-hotspot/{controller_id}/profiles
    GET   /api/v1/gateway-mikrotik-hotspot/{controller_id}/users
    GET   /api/v1/gateway-mikrotik-hotspot/{controller_id}/user-profiles
    GET   /api/v1/gateway-mikrotik-hotspot/{controller_id}/active
    GET   /api/v1/gateway-mikrotik-hotspot/{controller_id}/hosts
    GET   /api/v1/gateway-mikrotik-hotspot/{controller_id}/walled-garden
    POST  /api/v1/gateway-mikrotik-hotspot/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-mikrotik-hotspot/{controller_id}/changes

Reads run live; writes stage. Stage endpoint locks ``feature`` to
``mikrotik.hotspot.*``.
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
from app.services.adapter_mikrotik_hotspot import (
    GatewayMikrotikHotspotService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-mikrotik-hotspot",
    tags=["gateway-mikrotik-hotspot"],
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


@router.get("/{controller_id}/servers")
async def list_servers(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikHotspotService(session)
    return _paginate(
        await svc.list_servers(controller_id, user.organization_id, is_superuser=user.is_superuser),
        limit,
        offset,
    )


@router.get("/{controller_id}/profiles")
async def list_profiles(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikHotspotService(session)
    return _paginate(
        await svc.list_profiles(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/users")
async def list_users(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikHotspotService(session)
    return _paginate(
        await svc.list_users(controller_id, user.organization_id, is_superuser=user.is_superuser),
        limit,
        offset,
    )


@router.get("/{controller_id}/user-profiles")
async def list_user_profiles(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikHotspotService(session)
    return _paginate(
        await svc.list_user_profiles(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/active")
async def list_active(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikHotspotService(session)
    return _paginate(
        await svc.list_active(controller_id, user.organization_id, is_superuser=user.is_superuser),
        limit,
        offset,
    )


@router.get("/{controller_id}/hosts")
async def list_hosts(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikHotspotService(session)
    return _paginate(
        await svc.list_hosts(controller_id, user.organization_id, is_superuser=user.is_superuser),
        limit,
        offset,
    )


@router.get("/{controller_id}/walled-garden")
async def list_walled_garden(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikHotspotService(session)
    return _paginate(
        await svc.list_walled_garden(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_mikrotik_hotspot_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("mikrotik.hotspot."):
        raise HTTPException(
            400,
            detail=("MikroTik hotspot endpoint only accepts mikrotik.hotspot.* features"),
        )
    svc = GatewayMikrotikHotspotService(session)
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
async def list_pending_mikrotik_hotspot(
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
        feature_prefix="mikrotik.hotspot.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
