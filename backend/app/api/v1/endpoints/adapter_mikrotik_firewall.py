# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Firewall endpoint.

URL layout::

    GET   /api/v1/gateway-mikrotik-firewall/{controller_id}/filter
    GET   /api/v1/gateway-mikrotik-firewall/{controller_id}/nat
    GET   /api/v1/gateway-mikrotik-firewall/{controller_id}/mangle
    GET   /api/v1/gateway-mikrotik-firewall/{controller_id}/address-lists
    POST  /api/v1/gateway-mikrotik-firewall/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-mikrotik-firewall/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint, which dispatches
MikroTik features through this service's ``build_applier``.

Reads are gated on ``network:read`` (MikroTik is a network device
managing L2/L3 plumbing — distinct from the firewall-specific
permissions used for OPNsense/pfSense). Writes are gated on
``network:write``. The stage endpoint also locks ``feature`` to
``mikrotik.firewall.*`` so a caller with ``network:write`` can't
smuggle a non-firewall feature through this URL.
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
from app.services.adapter_mikrotik_firewall import (
    GatewayMikrotikFirewallService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-mikrotik-firewall",
    tags=["gateway-mikrotik-firewall"],
)


def _paginate(response: dict[str, Any], limit: int, offset: int) -> dict[str, Any]:
    """Slice ``response['items']`` with metadata. RouterOS REST has
    no native pagination so we fetch and trim — bounded per page."""
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


@router.get("/{controller_id}/filter")
async def list_filter_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikFirewallService(session)
    return _paginate(
        await svc.list_filter_rules(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/nat")
async def list_nat_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikFirewallService(session)
    return _paginate(
        await svc.list_nat_rules(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/mangle")
async def list_mangle_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikFirewallService(session)
    return _paginate(
        await svc.list_mangle_rules(
            controller_id,
            user.organization_id,
            is_superuser=user.is_superuser,
        ),
        limit,
        offset,
    )


@router.get("/{controller_id}/address-lists")
async def list_address_lists(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayMikrotikFirewallService(session)
    return _paginate(
        await svc.list_address_lists(
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
async def stage_mikrotik_firewall_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("mikrotik.firewall."):
        raise HTTPException(
            400,
            detail=("MikroTik firewall endpoint only accepts mikrotik.firewall.* features"),
        )
    svc = GatewayMikrotikFirewallService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,  # MikroTik is controller-scoped (no FreeSDN sub-sites)
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_mikrotik_firewall(
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
        feature_prefix="mikrotik.firewall.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
