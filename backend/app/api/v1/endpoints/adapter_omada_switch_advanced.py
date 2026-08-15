# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway switch-advanced endpoints (sFlow, mirror sessions, LLDP-MED,
QinQ, per-port jumbo, PoE budget, per-switch voice VLAN, MSTP).
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_base import validate_mac
from app.services.adapter_omada_switch_advanced import GatewaySwitchAdvancedService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-switch-advanced", tags=["gateway-switch-advanced"])


@router.get("/{controller_id}/sites/{site_id}/switches/{mac}/configs/{config_name}")
async def get_switch_config(
    controller_id: UUID,
    site_id: UUID,
    mac: str,
    config_name: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    mac = validate_mac(mac)
    svc = GatewaySwitchAdvancedService(session)
    return await svc.get_switch_config(
        controller_id, user.organization_id, site_id, mac, config_name
    )


@router.get("/{controller_id}/sites/{site_id}/switches/{mac}/mirror-sessions")
async def list_mirror_sessions(
    controller_id: UUID,
    site_id: UUID,
    mac: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    mac = validate_mac(mac)
    svc = GatewaySwitchAdvancedService(session)
    return await svc.list_mirror_sessions(controller_id, user.organization_id, site_id, mac)


@router.get("/{controller_id}/sites/{site_id}/switches/{mac}/ports/{port_id}/jumbo-frame")
async def get_per_port_jumbo(
    controller_id: UUID,
    site_id: UUID,
    mac: str,
    port_id: int,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    mac = validate_mac(mac)
    svc = GatewaySwitchAdvancedService(session)
    return await svc.get_per_port_jumbo(controller_id, user.organization_id, site_id, mac, port_id)


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_switch_advanced(
    controller_id: UUID,
    site_id: UUID,
    feature: str,
    operation: Annotated[str, Query()],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("switch."):
        raise HTTPException(
            400,
            detail="switch-advanced endpoint only accepts switch.* features",
        )
    svc = GatewaySwitchAdvancedService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=site_id,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/sites/{site_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_switch_advanced(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        site_id=site_id,
        feature_prefix="switch.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
