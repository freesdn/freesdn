# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway bulk-ops + cloning endpoints.

Layout::

    GET   /api/v1/gateway-bulk/{controller_id}/sites/{site_id}/templates
    POST  /api/v1/gateway-bulk/{controller_id}/sites/{site_id}/changes/{feature}
    GET   /api/v1/gateway-bulk/{controller_id}/sites/{site_id}/changes
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_omada_bulk import GatewayBulkService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-bulk", tags=["gateway-bulk"])

# Bulk endpoint may stage bulk.* (device/SSID/client mass ops) plus
# site.clone / site.template.* (which the apply dispatcher routes back
# here). Anything else is a privilege-boundary smuggle attempt.
_BULK_STAGE_ALLOWED_PREFIXES = ("bulk.", "site.clone", "site.template.")


@router.get(
    "/{controller_id}/sites/{site_id}/templates",
    summary="List site templates",
)
async def list_templates(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayBulkService(session)
    return await svc.list_site_templates(controller_id, user.organization_id, site_id)


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_bulk_change(
    controller_id: UUID,
    site_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith(_BULK_STAGE_ALLOWED_PREFIXES):
        raise HTTPException(
            400,
            detail="bulk endpoint only accepts bulk.* / site.clone / site.template.* features",
        )
    svc = GatewayBulkService(session)
    if feature == "bulk.device.move_site":
        # Defense-in-depth: the authoritative target-site grant check lives in
        # the applier (services/adapter_omada_bulk.py), but reject a cross-grant
        # move at STAGE time too so the bad intent never lands as a pending row.
        # site_mappings is {omada_site_id: freesdn_site_uuid}; resolve the target
        # Omada id to its mapped FreeSDN site and assert the caller's grant on it.
        target_site_id = (body.payload or {}).get("target_site_id")
        if target_site_id is not None:
            ctrl = await svc._get_controller(controller_id, user.organization_id)
            mapped = (ctrl.site_mappings or {}).get(str(target_site_id))
            if mapped is not None:
                assert_can_access_site(user, UUID(str(mapped)), detail="target site not found")
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
async def list_pending_bulk(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    # Bulk page wants both bulk.* and site.* (site.clone, site.template.*).
    # Filter at the SQL layer to avoid silent drops past LIMIT.
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        site_id=site_id,
        feature_prefixes=["bulk.", "site."],
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
