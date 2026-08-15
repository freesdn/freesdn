# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway diagnostics endpoints — live read-only telemetry. The
``run-speed-test`` and ``locate`` actions are intentionally NOT staged
because they are non-mutating (don't change config, just trigger a
short-lived measurement). They still go through controller:write so a
reader can't probe.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.services.adapter_base import GatewayServiceBase, validate_mac

router = APIRouter(prefix="/gateway-diagnostics", tags=["gateway-diagnostics"])


class _DiagService(GatewayServiceBase):
    async def call(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        method_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        result = await getattr(client, method_name)(omada_site_id, *args, **kwargs)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "data": result,
            "fetched_at": datetime.now(UTC),
        }


@router.post("/{controller_id}/sites/{site_id}/gateways/{mac}/speed-test")
async def run_speed_test(
    controller_id: UUID,
    site_id: UUID,
    mac: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    mac = validate_mac(mac)
    svc = _DiagService(session)
    return await svc.call(
        controller_id,
        user.organization_id,
        site_id,
        "run_gateway_speed_test",
        mac,
    )


@router.get("/{controller_id}/sites/{site_id}/gateways/{mac}/speed-test")
async def get_speed_test_result(
    controller_id: UUID,
    site_id: UUID,
    mac: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    mac = validate_mac(mac)
    svc = _DiagService(session)
    return await svc.call(
        controller_id,
        user.organization_id,
        site_id,
        "get_gateway_speed_test_result",
        mac,
    )


@router.get("/{controller_id}/sites/{site_id}/gateways/{mac}/sessions")
async def get_session_stats(
    controller_id: UUID,
    site_id: UUID,
    mac: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    mac = validate_mac(mac)
    svc = _DiagService(session)
    return await svc.call(
        controller_id,
        user.organization_id,
        site_id,
        "get_gateway_session_stats",
        mac,
    )


@router.get("/{controller_id}/sites/{site_id}/gateways/{mac}/sessions/list")
async def list_active_sessions(
    controller_id: UUID,
    site_id: UUID,
    mac: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> Any:
    mac = validate_mac(mac)
    svc = _DiagService(session)
    return await svc.call(
        controller_id,
        user.organization_id,
        site_id,
        "get_gateway_active_sessions",
        mac,
        limit=limit,
    )
