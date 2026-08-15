# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense DHCP endpoint.

URL layout::

    GET   /api/v1/gateway-pfsense-dhcp/{controller_id}/servers
    GET   /api/v1/gateway-pfsense-dhcp/{controller_id}/leases
    GET   /api/v1/gateway-pfsense-dhcp/{controller_id}/static-mappings
    POST  /api/v1/gateway-pfsense-dhcp/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-pfsense-dhcp/{controller_id}/changes

Reads run live; writes stage. Stage endpoint locks ``feature`` to
``pfsense.dhcp.*``.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.validation import validate_id
from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_pfsense_dhcp import GatewayPfsenseDhcpService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-pfsense-dhcp",
    tags=["gateway-pfsense-dhcp"],
)


# Pagination — pfSense doesn't natively paginate, but the slice still
# prevents 10MB JSON dumps when a controller returns a pathologically
# long lease table. Same shape every other gateway-* vendor list
# endpoint uses.


def _paginate(payload: Any, limit: int, offset: int) -> Any:
    """Slice ``payload['items']`` (when present) and add a paging block.

    Leaves the rest of the response shape untouched so the
    ``controller_id`` / ``fetched_at`` envelope continues to match
    every other gateway-* read.
    """
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


@router.get("/{controller_id}/servers")
async def list_servers(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseDhcpService(session)
    payload = await svc.list_servers(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/leases")
async def list_leases(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    svc = GatewayPfsenseDhcpService(session)
    payload = await svc.list_leases(controller_id, user.organization_id)
    return _paginate(payload, limit, offset)


@router.get("/{controller_id}/static-mappings")
async def list_static_mappings(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    interface: Annotated[str, Query(min_length=1, max_length=32)] = "lan",
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    # Length bounds alone aren't enough — ``interface`` flows into the
    # pfSense URL query (``?interface=...``) so we re-shape-check it
    # at the FreeSDN edge with the same regex every other vendor uses.
    validate_id(interface, label="interface")
    svc = GatewayPfsenseDhcpService(session)
    payload = await svc.list_static_mappings(
        controller_id, user.organization_id, interface=interface
    )
    return _paginate(payload, limit, offset)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_pfsense_dhcp_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("pfsense.dhcp."):
        raise HTTPException(
            400,
            detail=("pfSense DHCP endpoint only accepts pfsense.dhcp.* features"),
        )
    svc = GatewayPfsenseDhcpService(session)
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
async def list_pending_pfsense_dhcp(
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
        feature_prefix="pfsense.dhcp.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
