# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Client Roaming API Endpoints
============================================

Roaming event retrieval, aggregate statistics,
sticky-client detection, and roaming configuration.

Endpoints:
  - GET  /roaming/events          - Paginated roaming events
  - GET  /roaming/stats           - Aggregate roaming statistics
  - GET  /roaming/sticky-clients  - Detect sticky clients
  - PUT  /wifi-networks/{id}/roaming - Update roaming configuration
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import get_db
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.modules.network.models import WifiNetwork
from app.services.roaming import RoamingAnalyticsService

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Inline Pydantic Schemas
# ─────────────────────────────────────────────────────────────────────────────


class RoamingEventResponse(BaseModel):
    id: UUID
    organization_id: UUID
    client_mac: str
    from_device_id: UUID | None = None
    to_device_id: UUID | None = None
    from_bssid: str | None = None
    to_bssid: str | None = None
    from_rssi: int | None = None
    to_rssi: int | None = None
    roam_time_ms: int | None = None
    roam_type: str | None = None
    timestamp: datetime

    class Config:
        from_attributes = True


class RoamingEventListResponse(BaseModel):
    events: list[RoamingEventResponse]
    total: int


class PerAPStats(BaseModel):
    device_id: str
    roams_in: int = 0
    roams_out: int = 0


class RoamingStatsResponse(BaseModel):
    total_roams: int = 0
    avg_roam_time_ms: float | None = None
    roam_type_breakdown: dict[str, int] = Field(default_factory=dict)
    per_ap_stats: list[PerAPStats] = Field(default_factory=list)


class StickyClientResponse(BaseModel):
    client_mac: str
    current_device_id: str | None = None
    current_bssid: str | None = None
    rssi: int | None = None
    last_roam_at: str | None = None
    roam_type: str | None = None


class RoamingConfigUpdate(BaseModel):
    roaming_protocol: str | None = Field(
        None,
        description="802.11r, 802.11k, 802.11v, or null to disable",
        pattern=r"^(802\.11r|802\.11k|802\.11v)$",
    )
    minimum_rssi: int | None = Field(
        None,
        description="Minimum RSSI threshold (dBm) for roaming decisions",
        ge=-100,
        le=0,
    )
    fast_roaming: bool | None = Field(None, description="Enable fast roaming (802.11r)")


class RoamingConfigResponse(BaseModel):
    wifi_network_id: str
    ssid: str
    roaming_protocol: str | None = None
    minimum_rssi: int | None = None
    fast_roaming: bool | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _org_id(user: Any) -> Any:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


# ─────────────────────────────────────────────────────────────────────────────
# Roaming Events
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/events", response_model=RoamingEventListResponse)
async def list_roaming_events(
    client_mac: str | None = Query(
        None, max_length=17, pattern=r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
    ),
    device_id: UUID | None = None,
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """List paginated roaming events for the organisation."""
    org_id = _org_id(user)
    service = RoamingAnalyticsService(db)
    events, total = await service.list_roaming_events(
        org_id,
        client_mac=client_mac,
        device_id=device_id,
        hours=hours,
        limit=limit,
        offset=offset,
    )
    return RoamingEventListResponse(
        events=[RoamingEventResponse.model_validate(e) for e in events],
        total=total,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Aggregate Stats
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/stats", response_model=RoamingStatsResponse)
async def get_roaming_stats(
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get aggregate roaming statistics."""
    org_id = _org_id(user)
    service = RoamingAnalyticsService(db)
    stats = await service.get_roaming_stats(org_id, hours=hours)
    return RoamingStatsResponse(**stats)


# ─────────────────────────────────────────────────────────────────────────────
# Sticky Clients
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/sticky-clients", response_model=list[StickyClientResponse])
async def get_sticky_clients(
    rssi_threshold: int = Query(-75, le=-30, ge=-100),
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Detect clients stuck on a weak AP (sticky clients)."""
    org_id = _org_id(user)
    service = RoamingAnalyticsService(db)
    clients = await service.get_sticky_clients(
        org_id,
        rssi_threshold=rssi_threshold,
        hours=hours,
    )
    return [StickyClientResponse(**c) for c in clients]


# ─────────────────────────────────────────────────────────────────────────────
# Roaming Configuration (WiFi Network)
# ─────────────────────────────────────────────────────────────────────────────


@router.put(
    "/wifi-networks/{wifi_network_id}/roaming",
    response_model=RoamingConfigResponse,
)
async def update_roaming_config(
    wifi_network_id: UUID,
    body: RoamingConfigUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Update 802.11r/k/v roaming settings for a WiFi network."""
    org_id = _org_id(user)

    # Verify the WiFi network belongs to the user's organization
    result = await db.execute(
        select(WifiNetwork)
        .options(selectinload(WifiNetwork.site))
        .where(
            WifiNetwork.id == wifi_network_id,
            WifiNetwork.deleted_at.is_(None),
        )
    )
    wifi = result.scalar_one_or_none()
    if not wifi:
        raise HTTPException(status_code=404, detail="WiFi network not found")

    # Check org ownership via the site relationship
    if not wifi.site or wifi.site.organization_id != org_id:
        raise HTTPException(status_code=404, detail="WiFi network not found")

    # Per-user site grant: a site-limited operator must not push roaming config
    # to a WiFi network in a sibling site (no-op for super_admin / org_admin).
    assert_can_access_site(user, wifi.site_id, detail="WiFi network not found")

    service = RoamingAnalyticsService(db)
    config = await service.push_roaming_config(
        wifi_network_id,
        body.model_dump(exclude_unset=True),
    )
    await db.commit()
    return RoamingConfigResponse(**config)
