# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi WLANs endpoint (stage + read)."""

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
from app.services.adapter_staging import AdapterStagingService
from app.services.adapter_unifi_wlans import GatewayUniFiWlansService

router = APIRouter(
    prefix="/gateway-unifi-wlans",
    tags=["gateway-unifi-wlans"],
)


@router.get("/{controller_id}/sites/{site}/wlans")
async def list_wlans(
    controller_id: UUID,
    site: str,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayUniFiWlansService(session)
    return await svc.list_wlans(
        controller_id=controller_id,
        organization_id=user.organization_id,
        site=site,
        is_superuser=user.is_superuser,
    )


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_unifi_wlans_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("unifi.wlans."):
        raise HTTPException(
            400,
            detail=("UniFi WLANs endpoint only accepts unifi.wlans.* features"),
        )
    # Defense-in-depth — WLAN id is a Mongo ObjectID; reject anything
    # that doesn't match the canonical hex-24 shape at the stage
    # boundary so the audit log only ever contains valid identifiers.
    if body.target_id is not None:
        from app.adapters.unifi.validators import validate_object_id

        try:
            validate_object_id(body.target_id, label="wlan_id")
        except Exception as exc:
            raise HTTPException(
                400,
                detail=(f"unifi.wlans.* target_id must be a WLAN ObjectID: {exc}"),
            ) from exc
    svc = GatewayUniFiWlansService(session)
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
async def list_pending_unifi_wlans(
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
        feature_prefix="unifi.wlans.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
