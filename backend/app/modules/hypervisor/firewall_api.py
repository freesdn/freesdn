# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db, require_min_role
from app.core.dependencies import CurrentUser
from app.modules.hypervisor.firewall_schemas import (
    FirewallOperationRequest,
    FirewallOperationResponse,
    FirewallReviewRequest,
    FirewallReviewResponse,
)
from app.services.hypervisor_firewall_operations import HypervisorFirewallOperationService

router = APIRouter()


@router.post(
    "/controllers/{controller_id}/firewall/operations/review", response_model=FirewallReviewResponse
)
async def review_firewall_operation(
    controller_id: UUID,
    body: FirewallReviewRequest,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_min_role("site_admin")),
) -> dict[str, Any]:
    return await HypervisorFirewallOperationService(session, current_user).review(
        controller_id, body
    )


@router.post(
    "/controllers/{controller_id}/firewall/operations",
    response_model=FirewallOperationResponse,
    status_code=202,
)
async def submit_firewall_operation(
    controller_id: UUID,
    body: FirewallOperationRequest,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_min_role("site_admin")),
) -> FirewallOperationResponse:
    return await HypervisorFirewallOperationService(session, current_user).submit(
        controller_id, body
    )
