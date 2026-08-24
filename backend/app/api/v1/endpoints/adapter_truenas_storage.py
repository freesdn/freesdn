# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Storage writes — stage only.

    POST  /api/v1/gateway-storage/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-storage/{controller_id}/changes

There were eighty-one staging routes across every other vendor domain and none
for storage, because until now the only storage write was ``storage.store_blob``
and Fabric staged that one itself. Adding dataset create, snapshot create and
delete, and scrub start left four operations that were routed in ``_APPLY``,
gated, tested -- and reachable by nothing: no Fabric operation offered them and
no HTTP route could stage them.

Stage only, like every sibling. The apply path is the shared
``/gateway-vpn/changes/{id}/apply`` dispatcher, which resolves the service by
feature prefix and demands ``storage.write`` to apply -- the same permission
demanded here, so the two ends of the gate agree.
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
from app.services.adapter_truenas_storage import (
    _APPLY,
    _WITHHELD_OPERATIONS,
    GatewayTrueNASStorageService,
)

router = APIRouter(prefix="/gateway-storage", tags=["gateway-storage"])

_PREFIXES = ("storage.", "truenas.storage.")


def validate_storage_operation(feature: str, operation: str) -> None:
    """Refuse anything this endpoint cannot actually carry out.

    Pulled out of the route so it can be tested by calling it. The checks lived
    inline first, and the tests could only grep the route's source -- which
    meant a mutation that removed the ``if`` while leaving the ``raise``
    unreachable passed them all.

    Order matters: withheld before unknown. A withheld operation IS a known
    name, so reporting it as unrecognised would send an operator looking for a
    typo in something the platform is deliberately not offering.
    """
    if not feature.startswith(_PREFIXES):
        raise HTTPException(400, detail="storage endpoint only accepts storage.* features")

    key = (feature.removeprefix("truenas."), operation)

    # Refused at STAGE, not only at apply. A withheld operation that stages
    # cleanly and dies on apply has already been reviewed and approved by
    # somebody, which is the worst moment to discover the platform never
    # intended to offer it.
    if key in _WITHHELD_OPERATIONS:
        raise HTTPException(
            400,
            detail=(
                f"{feature}/{operation} is not offered: it destroys data "
                "irreversibly and needs a confirmation flow this release does not have"
            ),
        )

    if key not in _APPLY:
        raise HTTPException(
            400,
            detail=(
                f"no storage operation {feature!r}/{operation!r}; supported: "
                + ", ".join(sorted(f"{f}/{o}" for f, o in _APPLY))
            ),
        )


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Stage a storage write. Does NOT touch the appliance.",
)
async def stage_storage_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | delete | start")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("storage.write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Record a write intent against a storage appliance.

    Nothing reaches the appliance here. The change appears in the pending list
    and only runs if an operator later force-applies it.
    """
    validate_storage_operation(feature, operation)

    svc = GatewayTrueNASStorageService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        # Storage appliances are org-scoped, not site-scoped: a NAS serves
        # whatever sites the org points at it, and the Controller row carries
        # the site relationship already.
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
async def list_pending_storage(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("storage.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    """Pending storage changes for one appliance, for the review drawer."""
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefixes=list(_PREFIXES),
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
