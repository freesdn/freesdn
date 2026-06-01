# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense System endpoint.

URL layout::

    GET   /api/v1/gateway-pfsense-system/{controller_id}/info
    GET   /api/v1/gateway-pfsense-system/{controller_id}/version
    GET   /api/v1/gateway-pfsense-system/{controller_id}/firmware-info
    POST  /api/v1/gateway-pfsense-system/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-pfsense-system/{controller_id}/changes

Reads run live; reboots / halts go through staging. Apply path is the
shared ``/gateway-vpn/changes/{change_id}/apply`` endpoint.

Stage endpoint locks ``feature`` to ``pfsense.system.*``.
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
from app.services.adapter_pfsense_system import GatewayPfsenseSystemService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-pfsense-system",
    tags=["gateway-pfsense-system"],
)


@router.get("/{controller_id}/info")
async def get_system_info(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayPfsenseSystemService(session)
    return await svc.get_info(controller_id, user.organization_id)


@router.get("/{controller_id}/version")
async def get_system_version(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayPfsenseSystemService(session)
    return await svc.get_version(controller_id, user.organization_id)


@router.get("/{controller_id}/firmware-info")
async def get_firmware_info(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayPfsenseSystemService(session)
    return await svc.get_firmware_info(controller_id, user.organization_id)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_pfsense_system_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("pfsense.system."):
        raise HTTPException(
            400,
            detail=("pfSense system endpoint only accepts pfsense.system.* features"),
        )
    svc = GatewayPfsenseSystemService(session)
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
async def list_pending_pfsense_system(
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
        feature_prefix="pfsense.system.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
