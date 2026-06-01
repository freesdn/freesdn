# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Services endpoint.

URL layout::

    GET   /api/v1/gateway-opnsense-services/{controller_id}/services
    POST  /api/v1/gateway-opnsense-services/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-opnsense-services/{controller_id}/changes

Reads run live; start / stop / restart go through staging. Apply path
is the shared ``/gateway-vpn/changes/{change_id}/apply`` endpoint, which
dispatches OPNsense features through this service's ``build_applier``.

Stage endpoint locks ``feature`` to ``opnsense.services.*`` so a caller
with ``firewall:write`` can't smuggle a non-services feature through
this URL.
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
from app.services.adapter_opnsense_services import (
    GatewayOpnsenseServicesService,
)
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-opnsense-services",
    tags=["gateway-opnsense-services"],
)


@router.get("/{controller_id}/services")
async def list_services(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseServicesService(session)
    return await svc.list_services(controller_id, user.organization_id)


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_opnsense_services_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("opnsense.services."):
        raise HTTPException(
            400,
            detail=("OPNsense services endpoint only accepts opnsense.services.* features"),
        )
    # The OPNsense API targets a service by name (no UUID). Validate
    # the name BEFORE staging so a caller can't smuggle a path-traversal
    # payload through ``target_id`` and have it reach the URL only at
    # apply-time.
    if not body.target_id:
        raise HTTPException(
            400,
            detail=(
                "OPNsense services require target_id (service name) — "
                "e.g. 'unbound', 'dhcpd', 'openvpn'"
            ),
        )
    validate_id(body.target_id, label="service_name")

    svc = GatewayOpnsenseServicesService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,  # OPNsense is controller-scoped
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_opnsense_services(
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
        feature_prefix="opnsense.services.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
