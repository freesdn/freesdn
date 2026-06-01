# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Traffic Shaper endpoint.

URL layout::

    GET   /api/v1/gateway-opnsense-shaper/{controller_id}/pipes
    GET   /api/v1/gateway-opnsense-shaper/{controller_id}/queues
    GET   /api/v1/gateway-opnsense-shaper/{controller_id}/rules
    POST  /api/v1/gateway-opnsense-shaper/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-opnsense-shaper/{controller_id}/changes

Reads run live; writes stage. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint, which dispatches
OPNsense features through this service's ``build_applier``.

Stage endpoint locks ``feature`` to ``opnsense.shaper.*`` so a caller
with ``firewall:write`` can't smuggle a non-shaper feature through
this URL. Reads inherit ``firewall:read`` because OPNsense IS the
firewall — traffic shaping is a sub-feature of that surface.
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
from app.services.adapter_opnsense_shaper import GatewayOpnsenseShaperService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-opnsense-shaper",
    tags=["gateway-opnsense-shaper"],
)


@router.get("/{controller_id}/pipes")
async def list_pipes(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseShaperService(session)
    return await svc.list_pipes(controller_id, user.organization_id)


@router.get("/{controller_id}/queues")
async def list_queues(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseShaperService(session)
    return await svc.list_queues(controller_id, user.organization_id)


@router.get("/{controller_id}/rules")
async def list_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseShaperService(session)
    return await svc.list_rules(controller_id, user.organization_id)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_opnsense_shaper_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("opnsense.shaper."):
        raise HTTPException(
            400,
            detail=("OPNsense shaper endpoint only accepts opnsense.shaper.* features"),
        )
    # Defense-in-depth: update/delete operations target an existing
    # vendor-issued ID. Validate at stage-time so a malformed value
    # never reaches the staging row, never reaches the URL on apply.
    if operation in ("update", "delete"):
        if not body.target_id:
            raise HTTPException(
                400,
                detail=("OPNsense shaper update/delete requires target_id"),
            )
        validate_id(body.target_id, label="target_id")
    svc = GatewayOpnsenseShaperService(session)
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
async def list_pending_opnsense_shaper(
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
        feature_prefix="opnsense.shaper.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
