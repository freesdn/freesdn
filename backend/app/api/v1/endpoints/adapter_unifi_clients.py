# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway UniFi Clients endpoint (stage + read).

URL layout::

    GET   /api/v1/gateway-unifi-clients/{controller_id}/sites/{site}/clients
    POST  /api/v1/gateway-unifi-clients/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-unifi-clients/{controller_id}/changes

Reads run live; writes stage in ``core.adapter_pending_changes``. Apply
goes through the shared ``/gateway-vpn/changes/{change_id}/apply``
endpoint so the same Pending Changes drawer + apply UX serves both
MikroTik and UniFi.

Naming note: the prefix is ``gateway-unifi-clients`` not
``unifi-clients`` so the URL pattern lines up with the existing
``gateway-mikrotik-*`` family. UniFi is a Controller (not a Gateway),
but the polymorphic resolver accepts either, and the drawer keys its
fanout on the ``gateway-{vendor}-{domain}`` prefix.
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
from app.services.adapter_staging import AdapterStagingService
from app.services.adapter_unifi_clients import GatewayUniFiClientsService

router = APIRouter(
    prefix="/gateway-unifi-clients",
    tags=["gateway-unifi-clients"],
)


@router.get("/{controller_id}/sites/{site}/clients")
async def list_clients(
    controller_id: UUID,
    site: str,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayUniFiClientsService(session)
    return await svc.list_clients(
        controller_id=controller_id,
        organization_id=user.organization_id,
        site=site,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/sites/{site}/clients/{mac}")
async def get_client(
    controller_id: UUID,
    site: str,
    mac: str,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayUniFiClientsService(session)
    one = await svc.get_one(
        controller_id=controller_id,
        organization_id=user.organization_id,
        site=site,
        mac=mac,
    )
    # contract — 404 on not-found, not 200+null.
    if one is None:
        raise HTTPException(
            404,
            detail=f"client {mac} not found at site {site}",
        )
    return {"controller_id": controller_id, "site": site, "client": one}


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_unifi_clients_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("unifi.clients."):
        raise HTTPException(
            400,
            detail=("UniFi Clients endpoint only accepts unifi.clients.* features"),
        )
    # Defense-in-depth: validate the
    # client MAC at stage time, not just at apply time. Without this,
    # a malformed target_id (e.g. ``"../../../../api/self"``) sits in
    # the staging table looking legitimate until apply tries to use it
    # and validates inside the adapter. Audit log entries reflect the
    # validated shape; bad input never enters the queue.
    if body.target_id is not None:
        from app.adapters.unifi.validators import validate_mac

        try:
            validate_mac(body.target_id)
        except Exception as exc:
            raise HTTPException(
                400,
                detail=(f"unifi.clients.* target_id must be a MAC address: {exc}"),
            ) from exc
    svc = GatewayUniFiClientsService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,  # UniFi sites are controller-scoped strings, not
        # FreeSDN sub-sites; the UniFi site name lives in payload.site
        # so the applier can route to it.
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_unifi_clients(
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
        feature_prefix="unifi.clients.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
