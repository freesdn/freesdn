# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik CAPsMAN endpoint.

URL layout::

    GET   /api/v1/gateway-mikrotik-capsman/{controller_id}/configurations
    GET   /api/v1/gateway-mikrotik-capsman/{controller_id}/datapaths
    GET   /api/v1/gateway-mikrotik-capsman/{controller_id}/security
    GET   /api/v1/gateway-mikrotik-capsman/{controller_id}/manager
    GET   /api/v1/gateway-mikrotik-capsman/{controller_id}/access-list
    GET   /api/v1/gateway-mikrotik-capsman/{controller_id}/registrations
    GET   /api/v1/gateway-mikrotik-capsman/{controller_id}/interfaces
    POST  /api/v1/gateway-mikrotik-capsman/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-mikrotik-capsman/{controller_id}/changes

Reads run live; writes stage. Stage endpoint locks ``feature`` to
``mikrotik.capsman.*``.
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
from app.services.adapter_mikrotik_capsman import (
    GatewayMikrotikCapsmanService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-mikrotik-capsman",
    tags=["gateway-mikrotik-capsman"],
)


def _paginate(response: dict[str, Any], limit: int, offset: int) -> dict[str, Any]:
    """Slice ``response['items']`` to ``[offset:offset+limit]`` with
    metadata. RouterOS REST has no native pagination so we fetch
    everything and trim — bounded by the per-page cap."""
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


@router.get("/{controller_id}/configurations")
async def list_configurations(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikCapsmanService(session)
    return _paginate(
        await svc.list_configurations(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/datapaths")
async def list_datapaths(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikCapsmanService(session)
    return _paginate(
        await svc.list_datapaths(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/security")
async def list_security(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikCapsmanService(session)
    return _paginate(
        await svc.list_security(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/manager")
async def get_manager(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Singleton — no pagination.
    svc = GatewayMikrotikCapsmanService(session)
    return await svc.get_manager(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/access-list")
async def list_access_list(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikCapsmanService(session)
    return _paginate(
        await svc.list_access_list(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/registrations")
async def list_registrations(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikCapsmanService(session)
    return _paginate(
        await svc.list_registrations(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/interfaces")
async def list_interfaces(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikCapsmanService(session)
    return _paginate(
        await svc.list_interfaces(
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
async def stage_mikrotik_capsman_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("mikrotik.capsman."):
        raise HTTPException(
            400,
            detail=("MikroTik CAPsMAN endpoint only accepts mikrotik.capsman.* features"),
        )
    svc = GatewayMikrotikCapsmanService(session)
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
async def list_pending_mikrotik_capsman(
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
        feature_prefix="mikrotik.capsman.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
