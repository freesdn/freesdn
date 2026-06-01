# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX extensions (staged writes) endpoint.

URL layout::

    GET   /api/v1/gateway-freepbx-extensions/{pbx_id}/extensions
    GET   /api/v1/gateway-freepbx-extensions/{pbx_id}/extensions/{ext_number}
    POST  /api/v1/gateway-freepbx-extensions/{pbx_id}/changes/{feature}
    GET   /api/v1/gateway-freepbx-extensions/{pbx_id}/changes

``{pbx_id}`` is a ``voip.pbx`` row id (NOT a ``core.controllers`` id);
``FreePBXServiceBase`` resolves it and lazily pairs a controllers row for
the staging FK at stage time.

Reads run live against the PBX. Writes STAGE — they record a pending
change and never touch the live PBX. The apply path is the shared
``POST /api/v1/gateway-vpn/changes/{change_id}/apply`` endpoint, which
enforces the ``ADAPTER_READ_ONLY`` + ``force`` dual-gate before any write
reaches the PBX.

The stage endpoint locks ``feature`` to ``pbx.extension.*`` so a caller
with ``voip.manage_phones`` cannot smuggle a non-extension feature
through this URL.
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
from app.services.adapter_freepbx_extensions import FreePBXExtensionsService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(
    prefix="/gateway-freepbx-extensions",
    tags=["gateway-freepbx-extensions"],
)

_FEATURE_PREFIX = "pbx.extension."


@router.get("/{pbx_id}/extensions")
async def list_extensions(
    pbx_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = FreePBXExtensionsService(session)
    return await svc.list_extensions(pbx_id, user.organization_id)


@router.get("/{pbx_id}/extensions/{ext_number}")
async def get_extension(
    pbx_id: UUID,
    ext_number: str,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    ext_number = validate_id(ext_number, label="ext_number")
    svc = FreePBXExtensionsService(session)
    return await svc.get_extension(pbx_id, user.organization_id, ext_number)


@router.post(
    "/{pbx_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_extension_change(
    pbx_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith(_FEATURE_PREFIX):
        raise HTTPException(
            400,
            detail="FreePBX extensions endpoint only accepts pbx.extension.* features",
        )
    svc = FreePBXExtensionsService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=pbx_id,
        organization_id=user.organization_id,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{pbx_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_extension_changes(
    pbx_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=pbx_id,
        feature_prefix=_FEATURE_PREFIX,
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]
