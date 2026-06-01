# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Dashboard Endpoints
==================================

Dashboard statistics and summary endpoints.

Optimized for scale: uses 3 aggregated queries instead of 12 separate
COUNT queries, with a 10-second TTL cache per org+site.
"""

import time
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    CurrentUser,
    get_current_active_user,
    is_unscoped_superuser,
)
from app.core.site_access import assert_can_access_site, site_ids_for_request, site_scope_filter
from app.db import get_session
from app.models import Controller, Device, DeviceStatus, Organization, Site
from app.models.alert_rules import Alert
from app.modules.cameras.models import Camera, CameraStatus

router = APIRouter()

# Simple TTL cache for dashboard stats (avoids repeated DB queries per page load)
_dashboard_cache: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 10  # seconds — dashboard data is stale-tolerant
_CACHE_MAX_ENTRIES = 500  # prevent unbounded growth


# ===========================================
# Response Models
# ===========================================


class DeviceStats(BaseModel):
    """Device counts with status breakdown."""

    total: int = 0
    online: int = 0
    offline: int = 0
    warning: int = 0


class CameraStats(BaseModel):
    """Camera statistics."""

    total: int = 0
    online: int = 0
    recording: int = 0


class AlertStats(BaseModel):
    """Alert statistics."""

    critical: int = 0
    warning: int = 0
    total: int = 0


class DashboardStats(BaseModel):
    """Dashboard statistics response - matches frontend DashboardStats interface."""

    organizations: int = 1
    sites: int = 0
    controllers: int = 0
    devices: DeviceStats = DeviceStats()
    cameras: CameraStats = CameraStats()
    alerts: AlertStats = AlertStats()


# ===========================================
# Dashboard Stats Endpoint
# ===========================================


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = Query(None, description="Filter by site"),
) -> Any:
    """
    Get dashboard statistics.

    Optimized: uses 3 aggregated queries instead of 12 separate COUNT queries.
    Results are TTL-cached (10s) per org+site.
    """
    org_id = current_user.organization_id

    # SITE-GRANT: a site-limited operator must only see stats for
    # sites they were granted. Enforce the explicit site_id grant here, and
    # constrain every aggregate to the granted set when no site is pinned.
    if site_id is not None:
        assert_can_access_site(current_user, site_id, detail="Site not found")
    granted = site_ids_for_request(current_user)

    # The cache key MUST encode the caller's site-grant scope, otherwise a
    # site-limited user could read an admin's org-wide cached entry (cross-site
    # leak) or vice-versa. ``granted`` is None for unrestricted callers, so they
    # all share the org-wide cache; site-limited users key on their grant set.
    grant_key = "all" if granted is None else "g:" + ",".join(sorted(str(s) for s in granted))
    cache_key = f"{org_id}:{site_id or 'all'}:{grant_key}"

    # Check TTL cache
    if cache_key in _dashboard_cache:
        ts, cached = _dashboard_cache[cache_key]
        if time.monotonic() - ts < _CACHE_TTL:
            return cached

    # --- Query 1: sites + controllers in a single round-trip ---
    site_filters = [Site.organization_id == org_id, site_scope_filter(current_user, Site.id)]
    if site_id:
        site_filters.append(Site.id == site_id)

    infra_result = await session.execute(
        select(
            func.count(Site.id.distinct()).label("sites"),
            func.count(Controller.id).label("controllers"),
        )
        .select_from(Site)
        .outerjoin(Controller, Controller.site_id == Site.id)
        .where(*site_filters)
    )
    infra = infra_result.one()
    total_sites = infra.sites or 0
    total_controllers = infra.controllers or 0

    # --- Query 2: all device stats in ONE aggregated query ---
    device_scope = [Site.organization_id == org_id, site_scope_filter(current_user, Site.id)]
    if site_id:
        device_scope.append(Site.id == site_id)

    dev_result = await session.execute(
        select(
            func.count(Device.id).label("total"),
            func.count(Device.id).filter(Device.status == DeviceStatus.ONLINE).label("online"),
            func.count(Device.id).filter(Device.status == DeviceStatus.OFFLINE).label("offline"),
            func.count(Device.id)
            .filter(
                Device.status.in_(
                    [
                        DeviceStatus.DEGRADED,
                        DeviceStatus.PROVISIONING,
                        DeviceStatus.ADOPTION_FAILED,
                    ]
                )
            )
            .label("warning"),
        )
        # Join Site directly via Device.site_id (NOT through Controller): an
        # INNER join on Controller silently dropped every controller-less device
        # (manually-adopted / agent-discovered / NVR shadow rows) from the
        # totals, and resolved the org/site filter off the controller's site
        # rather than the device's. Controller isn't used in the
        # SELECT, so removing it is both correct and cheaper.
        .select_from(Device)
        .join(Site, Device.site_id == Site.id)
        .where(*device_scope)
    )
    d = dev_result.one()

    # --- Query 2b: camera stats from the AUTHORITATIVE cameras table ---
    # Cameras are NOT Device rows (only NVRs are synced into devices.devices),
    # so a Device.device_type=='camera' filter always reads 0. Count straight
    # from cameras.cameras, scoped to the same org (+site) as the rest of the
    # dashboard. Camera carries organization_id + site_id directly.
    cam_scope = [
        Camera.organization_id == org_id,
        Camera.deleted_at.is_(None),
        site_scope_filter(current_user, Camera.site_id),
    ]
    if site_id:
        cam_scope.append(Camera.site_id == site_id)
    cam_result = await session.execute(
        select(
            func.count(Camera.id).label("total"),
            func.count(Camera.id)
            .filter(Camera.status == CameraStatus.ONLINE.value)
            .label("online"),
            func.count(Camera.id)
            .filter(Camera.status == CameraStatus.RECORDING.value)
            .label("recording"),
        ).where(*cam_scope)
    )
    cam = cam_result.one()

    # --- Query 3: all alert stats in ONE aggregated query ---
    alert_scope = [Alert.organization_id == org_id]
    if granted is not None:
        # Site-limited: granted-site alerts + org-level (NULL site_id) alerts.
        alert_scope.append(Alert.site_id.in_(list(granted)) | Alert.site_id.is_(None))
    if site_id:
        alert_scope.append(Alert.site_id == site_id)

    alert_result = await session.execute(
        select(
            func.count(Alert.id).label("total"),
            func.count(Alert.id).filter(Alert.severity == "critical").label("critical"),
            func.count(Alert.id).filter(Alert.severity == "warning").label("warning"),
        ).where(*alert_scope)
    )
    a = alert_result.one()

    # Org count (cheap — superusers only)
    if is_unscoped_superuser(current_user):  # scope-aware
        org_result = await session.execute(
            select(func.count(Organization.id)).where(
                Organization.is_active.is_(True),
                Organization.deleted_at.is_(None),
            )
        )
        org_count = org_result.scalar() or 1
    else:
        org_count = 1

    stats = DashboardStats(
        organizations=org_count,
        sites=total_sites,
        controllers=total_controllers,
        devices=DeviceStats(
            total=d.total or 0,
            online=d.online or 0,
            offline=d.offline or 0,
            warning=d.warning or 0,
        ),
        cameras=CameraStats(
            total=cam.total or 0,
            online=cam.online or 0,
            recording=cam.recording or 0,
        ),
        alerts=AlertStats(
            critical=a.critical or 0,
            warning=a.warning or 0,
            total=a.total or 0,
        ),
    )

    # Store in cache (evict oldest if over limit)
    if len(_dashboard_cache) >= _CACHE_MAX_ENTRIES:
        oldest_key = min(_dashboard_cache, key=lambda k: _dashboard_cache[k][0])
        del _dashboard_cache[oldest_key]
    _dashboard_cache[cache_key] = (time.monotonic(), stats)
    return stats
