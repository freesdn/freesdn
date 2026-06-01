# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway insights endpoints
====================================================

Pure read-only telemetry feeds. No staging needed — these don't mutate
controller state. Powers the dashboard widgets shipped in v2.6.0 plus
new "what's eating my bandwidth" / "where are my noisy clients"
visibility.

URL layout::

    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/app-traffic
    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/app-traffic/{app_id}/history
    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/top-talkers
    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/past-connections
    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/rf-heatmap
    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/wifi-survey/{mac}
    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/anomalies
    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/ai-suggestions
    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/mesh-topology
    GET  /api/v1/gateway-insights/{controller_id}/sites/{site_id}/cable-diag-history/{mac}
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.services.adapter_base import (
    GatewayServiceBase,
    validate_mac,
    validate_omada_id,
)

router = APIRouter(prefix="/gateway-insights", tags=["gateway-insights"])


class _InsightsService(GatewayServiceBase):
    """Pure read service — no writes, no staging."""

    async def get(
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


@router.get("/{controller_id}/sites/{site_id}/app-traffic")
async def app_traffic_stats(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    period: Annotated[str, Query(description="1h | 24h | 7d | 30d")] = "1h",
    top_n: Annotated[int, Query(ge=1, le=100)] = 10,
) -> Any:
    svc = _InsightsService(session)
    return await svc.get(
        controller_id,
        user.organization_id,
        site_id,
        "get_app_traffic_stats",
        period=period,
        top_n=top_n,
    )


@router.get("/{controller_id}/sites/{site_id}/app-traffic/{app_id}/history")
async def app_traffic_history(
    controller_id: UUID,
    site_id: UUID,
    app_id: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    granularity: Annotated[str, Query()] = "hour",
    period: Annotated[str, Query()] = "24h",
) -> Any:
    app_id = validate_omada_id(app_id, label="app_id")
    svc = _InsightsService(session)
    return await svc.get(
        controller_id,
        user.organization_id,
        site_id,
        "get_app_traffic_history",
        app_id,
        granularity=granularity,
        period=period,
    )


@router.get("/{controller_id}/sites/{site_id}/top-talkers")
async def top_talkers(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    period: Annotated[str, Query()] = "1h",
    top_n: Annotated[int, Query(ge=1, le=100)] = 10,
    kind: Annotated[str, Query(description="client | ssid | ap")] = "client",
) -> Any:
    svc = _InsightsService(session)
    return await svc.get(
        controller_id,
        user.organization_id,
        site_id,
        "get_top_talkers",
        period=period,
        top_n=top_n,
        kind=kind,
    )


@router.get("/{controller_id}/sites/{site_id}/past-connections")
async def past_connections(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    client_mac: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> Any:
    svc = _InsightsService(session)
    return await svc.get(
        controller_id,
        user.organization_id,
        site_id,
        "get_past_connections",
        client_mac=client_mac,
        limit=limit,
    )


@router.get("/{controller_id}/sites/{site_id}/rf-heatmap")
async def rf_heatmap(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = _InsightsService(session)
    return await svc.get(controller_id, user.organization_id, site_id, "get_rf_heatmap")


@router.get("/{controller_id}/sites/{site_id}/wifi-survey/{mac}")
async def wifi_survey(
    controller_id: UUID,
    site_id: UUID,
    mac: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    mac = validate_mac(mac)
    svc = _InsightsService(session)
    return await svc.get(controller_id, user.organization_id, site_id, "get_wifi_survey", mac)


@router.get("/{controller_id}/sites/{site_id}/anomalies")
async def anomalies(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    period: Annotated[str, Query()] = "24h",
) -> Any:
    svc = _InsightsService(session)
    return await svc.get(
        controller_id,
        user.organization_id,
        site_id,
        "get_anomalies",
        period=period,
    )


@router.get("/{controller_id}/sites/{site_id}/ai-suggestions")
async def ai_suggestions(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = _InsightsService(session)
    return await svc.get(controller_id, user.organization_id, site_id, "get_ai_suggestions")


@router.get("/{controller_id}/sites/{site_id}/mesh-topology")
async def mesh_topology(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = _InsightsService(session)
    return await svc.get(
        controller_id,
        user.organization_id,
        site_id,
        "get_mesh_topology_tree",
    )


@router.get("/{controller_id}/sites/{site_id}/cable-diag-history/{mac}")
async def cable_diag_history(
    controller_id: UUID,
    site_id: UUID,
    mac: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> Any:
    mac = validate_mac(mac)
    svc = _InsightsService(session)
    return await svc.get(
        controller_id,
        user.organization_id,
        site_id,
        "get_cable_diag_history",
        mac,
        limit=limit,
    )
