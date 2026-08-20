# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Analytics API Endpoints
======================================

REST API for the analytics module. Matches the frontend analyticsApi methods.

Endpoints:
- GET  /analytics/dashboard/summary        - Dashboard summary
- GET  /analytics/metrics/definitions       - List metric definitions
- GET  /analytics/metrics/definitions/{name} - Get single definition
- POST /analytics/metrics/definitions       - Create custom metric
- PUT  /analytics/metrics/definitions/{name} - Update metric definition
- POST /analytics/metrics/query             - Query metric data (time-series)
- POST /analytics/metrics/record            - Record metric data point
- GET  /analytics/metrics/{name}/latest     - Latest metric value
- GET  /analytics/devices/{id}/health       - Single device health
- GET  /analytics/devices/health            - Multiple device health
- GET  /analytics/sites/{id}/network        - Network overview
- GET  /analytics/sites/{id}/traffic        - Traffic analytics
- GET  /analytics/sites/{id}/clients        - Client analytics
- GET  /analytics/alerts                    - List alerts
- GET  /analytics/alerts/{id}               - Get alert
- PATCH /analytics/alerts/{id}              - Update alert (ack/resolve)
- GET  /analytics/widgets                   - List dashboard widgets
- POST /analytics/widgets                   - Create widget
- PUT  /analytics/widgets/{id}              - Update widget
- DELETE /analytics/widgets/{id}            - Delete widget
- GET  /analytics/aggregations              - Available aggregation types
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import (
    assert_can_access_site,
    site_ids_for_request,
    site_scope_filter,
)
from app.db import get_session
from app.db.session import get_logdb_session

logger = logging.getLogger(__name__)
from app.models.core import Site
from app.schemas.analytics import (
    AlertResponse,
    AlertUpdateRequest,
    ClientAnalyticsResponse,
    DashboardSummaryResponse,
    DeviceHealthResponse,
    MetricDefinitionCreate,
    MetricDefinitionResponse,
    MetricDefinitionUpdate,
    MetricQueryRequest,
    MetricQueryResponse,
    MetricRecordRequest,
    NetworkOverviewResponse,
    TrafficAnalyticsResponse,
    TrafficDataPointResponse,
    WidgetCreateRequest,
    WidgetResponse,
    WidgetUpdateRequest,
)
from app.schemas.core import MessageResponse
from app.services.analytics import PersistentAnalyticsService

router = APIRouter()

svc = PersistentAnalyticsService


# =============================================================================
# Tenant-isolation helpers
# =============================================================================


def _org_id(user: Any) -> UUID:
    """Extract organization_id from the current user; reject if missing."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _org_site_filter(organization_id: UUID) -> Any:
    """Scalar subquery returning site IDs that belong to *organization_id*."""
    return (
        select(Site.id)
        .where(Site.organization_id == organization_id, Site.deleted_at.is_(None))
        .scalar_subquery()
    )


async def _verify_site_ownership(
    session: AsyncSession,
    site_id: UUID,
    organization_id: UUID,
    user: Any = None,
) -> "Site":
    """Load a Site and raise 404 if it does not belong to the organisation.

    SITE-GRANT: when ``user`` is supplied, also enforce the
    per-user site grant — a site-limited operator may only resolve sites
    they were explicitly granted, never a sibling site in the same org.
    Chokepoint for every analytics endpoint that resolves an explicit
    ``site_id`` (dashboard summary, traffic, clients, metric record/latest,
    device-health list, network overview, alerts list).
    """
    result = await session.execute(
        select(Site).where(
            Site.id == site_id,
            Site.organization_id == organization_id,
            Site.deleted_at.is_(None),
        )
    )
    site = result.scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    if user is not None:
        assert_can_access_site(user, site_id, detail="Site not found")
    return site


async def _verify_device_site(
    session: AsyncSession,
    device_id: UUID,
    organization_id: UUID,
    user: Any = None,
) -> None:
    """Raise 404 unless ``device_id`` belongs to a site this caller may access.

    SITE-GRANT: the metric latest/record endpoints accept a raw
    ``device_id`` query/body param that was passed straight through to the
    LogDB lookup with only an organization_id filter. A site-limited operator
    could therefore read or record the latest metric for a device in a sibling
    site of the same org. Resolve the device's owning site (org-scoped) and
    enforce the per-user grant on it. No-op for unrestricted admins.
    """
    from app.models.devices import Device

    result = await session.execute(
        select(Device.site_id).where(
            Device.id == device_id,
            Device.site_id.in_(_org_site_filter(organization_id)),
        )
    )
    row = result.one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    if user is not None:
        assert_can_access_site(user, row.site_id, detail="Device not found")


# =============================================================================
# Dashboard
# =============================================================================


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    site_id: UUID | None = Query(None),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Get aggregated dashboard summary."""
    org = _org_id(user)
    if site_id:
        await _verify_site_ownership(session, site_id, org, user)
    data = await svc.get_dashboard_summary(
        session,
        organization_id=org,
        site_id=site_id,
        # SITE-GRANT: constrain org-wide summary to granted sites.
        accessible_site_ids=site_ids_for_request(user),
    )
    return data


# =============================================================================
# Cross-Site Comparison
# =============================================================================


@router.get("/sites/comparison")
async def get_sites_comparison(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[CurrentUser, Depends(require_permissions("analytics:read"))],
) -> dict[str, Any]:
    """Roll-up of key metrics across every site in the operator's org.

    Returns one row per site with:
      * device counts (total + online + by type: phones / cameras / firewalls)
      * alert counts (last 24h, open, last 7d)
      * SLA breaches (last 24h)
      * firmware compliance %
      * controllers (total + healthy)

    Designed for the cross-site comparison UI: each metric is a column,
    each site is a row, the FE highlights outliers (worst per-metric
    site gets a chip).

    Single endpoint, batched queries — total query count is fixed
    regardless of how many sites the org has.
    """
    from sqlalchemy import and_, case, func
    from sqlalchemy import select as sa_select

    from app.models.alert_rules import Alert
    from app.models.core import Controller, Site
    from app.models.devices import Device
    from app.models.firmware import DeviceFirmwareStatus
    from app.modules.cameras.models import Camera
    from app.modules.voip.models import Phone

    org = _org_id(user)

    # ── 1. Load every site in the user's org. ──
    # SITE-GRANT: a site-limited operator must only see the
    # cross-site comparison rows for sites they were granted — never every
    # sibling site in the org. site_scope_filter is a no-op for unrestricted
    # callers (super/org admins, grant-less users).
    sites_q = sa_select(Site).where(
        Site.deleted_at.is_(None),
        site_scope_filter(user, Site.id),
    )
    if org:
        sites_q = sites_q.where(Site.organization_id == org)
    sites_q = sites_q.order_by(Site.name)
    sites = list((await session.execute(sites_q)).scalars())
    site_ids = [s.id for s in sites]

    if not sites:
        return {"sites": [], "summary": {"total_sites": 0}}

    now = datetime.now(UTC)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)

    # ── 2. One GROUP BY query per metric (5 queries total). ──

    # Devices (and online subset)
    dev_q = (
        sa_select(
            Device.site_id,
            func.count(Device.id).label("total"),
            func.count(case((Device.status == "online", 1))).label("online"),
            func.count(case((Device.device_type == "switch", 1))).label("switches"),
            func.count(case((Device.device_type == "access_point", 1))).label("aps"),
            func.count(case((Device.device_type == "firewall", 1))).label("firewalls"),
            func.count(case((Device.device_type == "phone", 1))).label("phones_shadow"),
        )
        .where(
            Device.deleted_at.is_(None),
            Device.site_id.in_(site_ids),
        )
        .group_by(Device.site_id)
    )
    dev_rows = {r.site_id: r for r in (await session.execute(dev_q)).all()}

    # Actual phone fleet (voip.phones is the canonical phone source,
    # devices.devices may lag).
    phone_q = (
        sa_select(
            Phone.site_id,
            func.count(Phone.id).label("total"),
            func.count(case((Phone.sip_registered.is_(True), 1))).label("registered"),
            func.count(case((Phone.lifecycle_state == "managed", 1))).label("managed"),
        )
        .where(
            Phone.deleted_at.is_(None),
            Phone.site_id.in_(site_ids),
        )
        .group_by(Phone.site_id)
    )
    phone_rows = {r.site_id: r for r in (await session.execute(phone_q)).all()}

    # Actual camera fleet (cameras.cameras is canonical — cameras are NOT
    # synced into devices.devices, so the Device.device_type=='camera' count
    # above is always 0). Count per-site straight from the cameras table.
    cam_q = (
        sa_select(
            Camera.site_id,
            func.count(Camera.id).label("total"),
            func.count(case((Camera.status == "online", 1))).label("online"),
        )
        .where(
            Camera.deleted_at.is_(None),
            Camera.site_id.in_(site_ids),
        )
        .group_by(Camera.site_id)
    )
    cam_rows = {r.site_id: r for r in (await session.execute(cam_q)).all()}

    # Alerts. The Alert model lives in alert_rules and uses ``status`` =
    # FIRING/RESOLVED/ACK etc. and ``fired_at`` (not ``first_seen``).
    alert_q = (
        sa_select(
            Alert.site_id,
            func.count(case((Alert.status == "firing", 1))).label("open"),
            func.count(case((Alert.fired_at >= cutoff_24h, 1))).label("last_24h"),
            func.count(case((Alert.fired_at >= cutoff_7d, 1))).label("last_7d"),
            func.count(
                case((and_(Alert.severity == "critical", Alert.status == "firing"), 1))
            ).label("critical_open"),
        )
        .where(
            Alert.site_id.in_(site_ids),
        )
        .group_by(Alert.site_id)
    )
    alert_rows = {r.site_id: r for r in (await session.execute(alert_q)).all()}

    # Controllers
    ctrl_q = (
        sa_select(
            Controller.site_id,
            func.count(Controller.id).label("total"),
            func.count(case((Controller.status == "connected", 1))).label("connected"),
        )
        .where(
            Controller.deleted_at.is_(None),
            Controller.site_id.in_(site_ids),
        )
        .group_by(Controller.site_id)
    )
    ctrl_rows = {r.site_id: r for r in (await session.execute(ctrl_q)).all()}

    # Firmware compliance — counts compliant vs total managed
    try:
        fw_q = (
            sa_select(
                DeviceFirmwareStatus.site_id,
                func.count(DeviceFirmwareStatus.id).label("total"),
                func.count(case((DeviceFirmwareStatus.compliant.is_(True), 1))).label("compliant"),
            )
            .where(
                DeviceFirmwareStatus.site_id.in_(site_ids),
            )
            .group_by(DeviceFirmwareStatus.site_id)
        )
        fw_rows = {r.site_id: r for r in (await session.execute(fw_q)).all()}
    except Exception:
        # If the firmware table doesn't have a ``compliant`` column on
        # this schema version, just skip — don't blow up the whole
        # comparison.
        fw_rows = {}

    # ── 3. Stitch per-site rows. ──
    site_data: list[dict[str, Any]] = []
    for s in sites:
        dev = dev_rows.get(s.id)
        ph = phone_rows.get(s.id)
        cm = cam_rows.get(s.id)
        al = alert_rows.get(s.id)
        ct = ctrl_rows.get(s.id)
        fw = fw_rows.get(s.id)

        total_devices = (dev.total if dev else 0) or 0
        online_devices = (dev.online if dev else 0) or 0
        online_pct = round(100.0 * online_devices / total_devices, 1) if total_devices > 0 else None

        fw_total = (fw.total if fw else 0) or 0
        fw_compliant = (fw.compliant if fw else 0) or 0
        fw_pct = round(100.0 * fw_compliant / fw_total, 1) if fw_total > 0 else None

        site_data.append(
            {
                "site_id": str(s.id),
                "name": s.name,
                "slug": s.slug,
                "devices": {
                    "total": total_devices,
                    "online": online_devices,
                    "online_pct": online_pct,
                    "switches": (dev.switches if dev else 0) or 0,
                    "access_points": (dev.aps if dev else 0) or 0,
                    "cameras": (cm.total if cm else 0) or 0,
                    "firewalls": (dev.firewalls if dev else 0) or 0,
                    "phones": (dev.phones_shadow if dev else 0) or 0,
                },
                "phones": {
                    "total": (ph.total if ph else 0) or 0,
                    "sip_registered": (ph.registered if ph else 0) or 0,
                    "managed": (ph.managed if ph else 0) or 0,
                },
                "alerts": {
                    "open": (al.open if al else 0) or 0,
                    "critical_open": (al.critical_open if al else 0) or 0,
                    "last_24h": (al.last_24h if al else 0) or 0,
                    "last_7d": (al.last_7d if al else 0) or 0,
                },
                "controllers": {
                    "total": (ct.total if ct else 0) or 0,
                    "connected": (ct.connected if ct else 0) or 0,
                },
                "firmware": {
                    "tracked": fw_total,
                    "compliant": fw_compliant,
                    "compliance_pct": fw_pct,
                },
            }
        )

    # ── 4. Org-level rollup (sum across sites). ──
    summary = {
        "total_sites": len(site_data),
        "total_devices": sum(s["devices"]["total"] for s in site_data),
        "total_online_devices": sum(s["devices"]["online"] for s in site_data),
        "total_phones": sum(s["phones"]["total"] for s in site_data),
        "total_alerts_open": sum(s["alerts"]["open"] for s in site_data),
        "total_critical_open": sum(s["alerts"]["critical_open"] for s in site_data),
        "total_controllers": sum(s["controllers"]["total"] for s in site_data),
        "generated_at": now.isoformat(),
    }

    return {"sites": site_data, "summary": summary}


# =============================================================================
# Metric Definitions
# =============================================================================


@router.get("/metrics/definitions", response_model=list[MetricDefinitionResponse])
async def list_metric_definitions(
    category: str | None = Query(None, max_length=100),
    is_active: bool | None = Query(None),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """List all metric definitions."""
    defs = await svc.list_metric_definitions(session, category=category, is_active=is_active)
    return defs


@router.get("/metrics/definitions/{metric_name}", response_model=MetricDefinitionResponse)
async def get_metric_definition(
    metric_name: str,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Get a single metric definition."""
    # Cap matches the DB column width (varchar(255)).
    if len(metric_name) > 255:
        raise HTTPException(
            status_code=422,
            detail="metric_name too long (max 255)",
        )
    defn = await svc.get_metric_definition(session, metric_name)
    if not defn:
        raise HTTPException(status_code=404, detail="Metric definition not found")
    return defn


@router.post("/metrics/definitions", response_model=MetricDefinitionResponse, status_code=201)
async def create_metric_definition(
    data: MetricDefinitionCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:write")),
) -> Any:
    """Create a custom metric definition.

    NOTE on tenancy: ``MetricDefinitionRecord`` has no organization_id
    column — metric definitions are PLATFORM-WIDE (unique by name).
    To prevent an org_admin from creating a metric whose ``name``
    collides with another tenant's existing custom metric (which
    would break the other tenant's queries), restrict create to
    super_admin. ``analytics:write`` still gates the endpoint at the
    dep layer; the body-level check below enforces the additional
    super_admin requirement.
    """
    from app.core.dependencies import is_platform_super_admin

    # platform-wide WRITE — a SCOPED super_admin key (even one carrying
    # analytics:write) must not create/modify a global metric definition.
    if not is_platform_super_admin(user) or getattr(user, "_scoped", False):
        raise HTTPException(
            status_code=403,
            detail="Metric definitions are platform-wide; only super_admin may create/modify them",
        )
    existing = await svc.get_metric_definition(session, data.name)
    if existing:
        raise HTTPException(status_code=409, detail="Metric definition already exists")
    # Defense in depth: two concurrent POSTs with the same name both
    # pass the get-then-check above. The DB has a unique constraint
    # on ``analytics.metric_definitions.name`` (uq_metric_definitions_name)
    # so the loser of the race hits IntegrityError. Translate to a
    # clean 409 instead of bubbling a 500.
    try:
        record = await svc.create_metric_definition(
            session,
            data.model_dump(exclude_none=True),
            created_by=user.id,
        )
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=409,
            detail="Metric definition already exists",
        ) from exc
    return record


@router.put("/metrics/definitions/{metric_name}", response_model=MetricDefinitionResponse)
async def update_metric_definition(
    metric_name: str,
    data: MetricDefinitionUpdate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:write")),
) -> Any:
    """Update a metric definition.

    See create endpoint above — metric definitions are platform-wide
    so updates are restricted to super_admin to prevent cross-tenant
    interference (renaming / disabling a metric another tenant is
    actively querying).
    """
    from app.core.dependencies import is_platform_super_admin

    # platform-wide WRITE — a SCOPED super_admin key (even one carrying
    # analytics:write) must not create/modify a global metric definition.
    if not is_platform_super_admin(user) or getattr(user, "_scoped", False):
        raise HTTPException(
            status_code=403,
            detail="Metric definitions are platform-wide; only super_admin may create/modify them",
        )
    record = await svc.update_metric_definition(
        session,
        metric_name,
        data.model_dump(exclude_none=True),
    )
    if not record:
        raise HTTPException(status_code=404, detail="Metric definition not found")
    return record


# =============================================================================
# Metric Data Queries
# =============================================================================


@router.post("/metrics/query", response_model=MetricQueryResponse)
async def query_metrics(
    request: MetricQueryRequest,
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Query time-series metric data with aggregation."""
    org = _org_id(user)
    defn = await svc.get_metric_definition(session, request.metric_name)
    display_name = defn.display_name if defn else request.metric_name
    unit = defn.unit if defn else None

    # Always enforce organization_id filter for tenant isolation
    filters = dict(request.filters) if request.filters else {}
    filters["organization_id"] = str(org)

    # SITE-GRANT: a site-limited operator must not read org-wide
    # time-series across sibling sites. If they pinned an explicit site, assert
    # the grant on it; otherwise constrain the query to their granted sites.
    granted = site_ids_for_request(user)
    if granted is not None:
        explicit_site = filters.get("site_id")
        if explicit_site:
            assert_can_access_site(user, UUID(str(explicit_site)), detail="Site not found")
        else:
            filters["site_id_in"] = [str(s) for s in granted]

    data_points = await svc.query_metrics(
        logdb,
        metric_name=request.metric_name,
        start_time=request.start_time,
        end_time=request.end_time,
        granularity=request.granularity or "5m",
        aggregation=request.aggregation or "avg",
        filters=filters,
        limit=request.limit or 1000,
    )

    # Calculate aggregations from returned data
    values = [dp["value"]["value"] for dp in data_points if dp["value"].get("value") is not None]
    aggregations = None
    if values:
        aggregations = {
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "count": len(values),
            "sum": sum(values),
            "last": values[-1],
        }

    return MetricQueryResponse(
        metric_name=request.metric_name,
        display_name=display_name,
        unit=unit,
        granularity=request.granularity or "5m",
        data_points=data_points,
        aggregations=aggregations,
    )


@router.post("/metrics/record", response_model=MessageResponse, status_code=201)
async def record_metric(
    data: MetricRecordRequest,
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    user: CurrentUser = Depends(require_permissions("analytics:write")),
) -> Any:
    """Record a single metric data point."""
    org = _org_id(user)
    if data.site_id:
        await _verify_site_ownership(session, data.site_id, org, user)
    # SITE-GRANT: a raw device_id in the body was persisted with only
    # an org filter — a site-limited operator could record a metric point against
    # a sibling-site device. Resolve + grant-check the device's owning site.
    if data.device_id:
        await _verify_device_site(session, data.device_id, org, user)
    await svc.record_metric(
        logdb,
        metric_name=data.metric_name,
        value=data.value,
        labels=data.labels,
        timestamp=data.timestamp,
        organization_id=org,
        site_id=data.site_id,
        device_id=data.device_id,
    )
    return MessageResponse(message="Metric recorded")


@router.get("/metrics/{metric_name}/latest")
async def get_latest_metric(
    metric_name: str,
    site_id: UUID | None = Query(None),
    device_id: UUID | None = Query(None),
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Get the latest value for a metric."""
    org = _org_id(user)
    if site_id:
        await _verify_site_ownership(session, site_id, org, user)
    # SITE-GRANT: a raw device_id was passed straight to LogDB with
    # only an org filter — a site-limited operator could read the latest metric
    # for a sibling-site device. Resolve + grant-check the device's site.
    if device_id:
        await _verify_device_site(session, device_id, org, user)

    # SITE-GRANT: when a site-limited caller pins neither an explicit
    # site nor device, the LogDB lookup would return the org-wide latest point —
    # potentially from a sibling site. Constrain the lookup to the granted set so
    # an empty grant yields no data (404) rather than org-wide. No-op for admins.
    accessible_site_ids = None
    if not site_id and not device_id:
        accessible_site_ids = site_ids_for_request(user)

    data = await svc.get_latest_metric(
        logdb,
        metric_name,
        site_id=site_id,
        device_id=device_id,
        organization_id=org,
        accessible_site_ids=accessible_site_ids,
    )
    if not data:
        raise HTTPException(status_code=404, detail="No data found for metric")
    return data


# =============================================================================
# Device Health
# =============================================================================


@router.get("/devices/{device_id}/health", response_model=DeviceHealthResponse)
async def get_device_health(
    device_id: UUID,
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Get health score and metrics for a specific device."""
    org = _org_id(user)

    # Verify the device belongs to a site owned by this organization
    from app.models.devices import Device

    result = await session.execute(
        select(Device).where(
            Device.id == device_id,
            Device.site_id.in_(_org_site_filter(org)),
            Device.deleted_at.is_(None),
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # SITE-GRANT: a site-limited operator may only read health for
    # devices in sites they were granted, not any device in the org.
    assert_can_access_site(user, device.site_id, detail="Device not found")

    data = await svc.get_device_health(session, logdb, device_id)
    if not data:
        raise HTTPException(status_code=404, detail="Device not found")
    return data


@router.get("/devices/health", response_model=list[DeviceHealthResponse])
async def get_devices_health(
    site_id: UUID | None = Query(None),
    device_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Get health for multiple devices."""
    org = _org_id(user)
    if site_id:
        await _verify_site_ownership(session, site_id, org, user)
    return await svc.get_devices_health(
        session,
        logdb,
        site_id=site_id,
        device_type=device_type,
        limit=limit,
        organization_id=org,
        # SITE-GRANT: constrain the org-wide health list to the
        # site-limited caller's granted sites (None = unrestricted admin).
        accessible_site_ids=site_ids_for_request(user),
    )


# =============================================================================
# Site Analytics (Network, Traffic, Clients)
# =============================================================================


@router.get("/sites/{site_id}/network", response_model=NetworkOverviewResponse)
async def get_network_overview(
    site_id: UUID,
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Get network overview for a site."""
    org = _org_id(user)
    from sqlalchemy import func

    from app.models.alert_rules import Alert
    from app.models.devices import Device, DeviceClient, DeviceStatus

    site = await _verify_site_ownership(session, site_id, org, user)

    device_q = select(
        func.count().label("total"),
        func.count().filter(Device.status == DeviceStatus.ONLINE).label("online"),
        func.count().filter(Device.status == DeviceStatus.OFFLINE).label("offline"),
    ).where(Device.site_id == site_id)
    device_row = (await session.execute(device_q)).one()

    # Client counts from DeviceClient table (joined through Device → site)
    total_clients = 0
    wireless_clients = 0
    try:
        client_q = (
            select(func.count())
            .select_from(DeviceClient)
            .join(Device, DeviceClient.device_id == Device.id)
            .where(Device.site_id == site_id, DeviceClient.is_online.is_(True))
        )
        total_clients = (await session.execute(client_q)).scalar() or 0
        wireless_clients = total_clients  # DeviceClient tracks wireless clients
    except SQLAlchemyError:
        pass

    # Traffic aggregates from DeviceClient
    total_rx_bytes = 0
    total_tx_bytes = 0
    try:
        traffic_q = (
            select(
                func.coalesce(func.sum(DeviceClient.rx_bytes), 0).label("rx"),
                func.coalesce(func.sum(DeviceClient.tx_bytes), 0).label("tx"),
            )
            .select_from(DeviceClient)
            .join(Device, DeviceClient.device_id == Device.id)
            .where(Device.site_id == site_id, DeviceClient.is_online.is_(True))
        )
        traffic_row = (await session.execute(traffic_q)).one()
        total_rx_bytes = int(traffic_row.rx)
        total_tx_bytes = int(traffic_row.tx)
    except SQLAlchemyError:
        pass

    # Active alerts for this site
    active_alerts = 0
    try:
        alert_q = (
            select(func.count())
            .select_from(Alert)
            .where(Alert.site_id == site_id, Alert.status == "firing")
        )
        active_alerts = (await session.execute(alert_q)).scalar() or 0
    except SQLAlchemyError:
        pass

    # WAN utilization from metrics if available
    wan_utilization = 0.0
    try:
        wan_data = await svc.query_metrics(
            logdb,
            "network.wan_utilization",
            start_time=datetime.now(UTC) - timedelta(minutes=5),
            end_time=datetime.now(UTC),
            granularity="1m",
            aggregation="avg",
            filters={"site_id": str(site_id), "organization_id": str(org)},
        )
        if wan_data:
            vals = [d["value"].get("value", 0) for d in wan_data if d["value"].get("value")]
            if vals:
                wan_utilization = round(sum(vals) / len(vals), 1)
    except SQLAlchemyError as exc:
        logger.warning("LogDB query failed for WAN utilization (site=%s): %s", site_id, exc)

    return NetworkOverviewResponse(
        site_id=str(site_id),
        site_name=site.name,
        total_devices=device_row.total,
        devices_online=device_row.online,
        devices_offline=device_row.offline,
        total_clients=total_clients,
        wired_clients=0,
        wireless_clients=wireless_clients,
        guest_clients=0,
        total_rx_bytes=total_rx_bytes,
        total_tx_bytes=total_tx_bytes,
        wan_utilization=wan_utilization,
        active_alerts=active_alerts,
        timestamp=datetime.now(UTC).isoformat(),
    )


@router.get("/sites/{site_id}/traffic", response_model=TrafficAnalyticsResponse)
async def get_traffic_analytics(
    site_id: UUID,
    hours: int = Query(24, ge=1, le=720),
    session: AsyncSession = Depends(get_session),
    logdb: AsyncSession = Depends(get_logdb_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Get traffic analytics for a site."""
    org = _org_id(user)
    await _verify_site_ownership(session, site_id, org, user)
    now = datetime.now(UTC)
    start = now - timedelta(hours=hours)

    metric_filters = {"site_id": str(site_id), "organization_id": str(org)}
    rx_data = await svc.query_metrics(
        logdb,
        "network.throughput_rx",
        start_time=start,
        end_time=now,
        granularity="1h",
        aggregation="sum",
        filters=metric_filters,
    )
    tx_data = await svc.query_metrics(
        logdb,
        "network.throughput_tx",
        start_time=start,
        end_time=now,
        granularity="1h",
        aggregation="sum",
        filters=metric_filters,
    )

    rx_values = [d["value"]["value"] for d in rx_data if d["value"].get("value")]
    tx_values = [d["value"]["value"] for d in tx_data if d["value"].get("value")]

    # Query client count metrics per time bucket
    client_data = await svc.query_metrics(
        logdb,
        "network.client_count",
        start_time=start,
        end_time=now,
        granularity="1h",
        aggregation="avg",
        filters=metric_filters,
    )
    client_by_ts: dict[str, int] = {}
    for d in client_data:
        val = d.get("value", {}).get("value")
        if val is not None:
            client_by_ts[d["timestamp"]] = int(val)

    data_points = []
    tx_by_ts: dict[str, float] = {}
    for d in tx_data:
        val = d.get("value", {}).get("value")
        if val is not None:
            tx_by_ts[d["timestamp"]] = val

    for rx in rx_data:
        ts = rx["timestamp"]
        data_points.append(
            TrafficDataPointResponse(
                timestamp=ts,
                rx_bps=rx["value"].get("value", 0),
                tx_bps=tx_by_ts.get(ts, 0),
                clients=client_by_ts.get(ts, 0),
            )
        )

    return TrafficAnalyticsResponse(
        site_id=str(site_id),
        period_hours=hours,
        total_rx_bytes=int(sum(rx_values)) if rx_values else 0,
        total_tx_bytes=int(sum(tx_values)) if tx_values else 0,
        peak_rx_bps=max(rx_values) if rx_values else 0.0,
        peak_tx_bps=max(tx_values) if tx_values else 0.0,
        avg_rx_bps=sum(rx_values) / len(rx_values) if rx_values else 0.0,
        avg_tx_bps=sum(tx_values) / len(tx_values) if tx_values else 0.0,
        data_points=data_points,
    )


@router.get("/sites/{site_id}/clients", response_model=ClientAnalyticsResponse)
async def get_client_analytics(
    site_id: UUID,
    hours: int = Query(24, ge=1, le=720),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Get client analytics for a site."""
    org = _org_id(user)
    await _verify_site_ownership(session, site_id, org, user)
    from sqlalchemy import func

    from app.models.devices import Device, DeviceClient

    # ``hours`` was declared, validated and then ignored: the counts covered
    # every client ever seen at the site, so the range selector produced the
    # same two numbers for 1 hour and for 30 days. Bound both counts by
    # ``last_seen`` within the window; rows that have never reported a
    # ``last_seen`` are outside any window and are excluded.
    cutoff = datetime.now(UTC) - timedelta(hours=hours)

    total = 0
    active = 0
    try:
        q = (
            select(func.count())
            .select_from(DeviceClient)
            .join(Device, DeviceClient.device_id == Device.id)
            .where(
                Device.site_id == site_id,
                DeviceClient.last_seen.is_not(None),
                DeviceClient.last_seen >= cutoff,
            )
        )
        total = (await session.execute(q)).scalar() or 0

        active_q = (
            select(func.count())
            .select_from(DeviceClient)
            .join(Device, DeviceClient.device_id == Device.id)
            .where(
                Device.site_id == site_id,
                DeviceClient.is_online.is_(True),
                DeviceClient.last_seen.is_not(None),
                DeviceClient.last_seen >= cutoff,
            )
        )
        active = (await session.execute(active_q)).scalar() or 0
    except SQLAlchemyError:
        pass

    return ClientAnalyticsResponse(
        total_clients=total,
        active_clients=active,
    )


# =============================================================================
# Alerts
# =============================================================================


@router.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    site_id: UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """List analytics alerts."""
    org = _org_id(user)
    if site_id:
        await _verify_site_ownership(session, site_id, org, user)
    alerts = await svc.list_alerts(
        session,
        status=status_filter,
        severity=severity,
        site_id=site_id,
        limit=limit,
        organization_id=org,
        # SITE-GRANT: constrain org-wide alert list to granted sites.
        accessible_site_ids=site_ids_for_request(user),
    )
    return alerts


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """Get a single alert."""
    org = _org_id(user)
    from app.models.analytics import AnalyticsAlert

    result = await session.execute(
        select(AnalyticsAlert).where(
            AnalyticsAlert.id == alert_id,
            AnalyticsAlert.organization_id == org,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    # SITE-GRANT: a site-limited operator may only read alerts for
    # sites they were granted (org-level alerts with NULL site_id stay visible).
    assert_can_access_site(user, alert.site_id, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: UUID,
    data: AlertUpdateRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:write")),
) -> Any:
    """Update alert (acknowledge, resolve, add notes)."""
    org = _org_id(user)

    # Verify alert belongs to this organization before allowing mutation
    from app.models.analytics import AnalyticsAlert

    check = await session.execute(
        select(AnalyticsAlert.id, AnalyticsAlert.site_id).where(
            AnalyticsAlert.id == alert_id,
            AnalyticsAlert.organization_id == org,
        )
    )
    row = check.one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    # SITE-GRANT: a site-limited operator may only mutate alerts
    # for sites they were granted.
    assert_can_access_site(user, row.site_id, detail="Alert not found")

    alert = await svc.update_alert(
        session,
        alert_id,
        data.model_dump(exclude_none=True),
        updated_by=user.id,
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


# =============================================================================
# Dashboard Widgets
# =============================================================================


@router.get("/widgets", response_model=list[WidgetResponse])
async def list_widgets(
    dashboard_name: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """List dashboard widgets."""
    org = _org_id(user)
    return await svc.list_widgets(
        session,
        dashboard_name=dashboard_name,
        owner_id=user.id,
        organization_id=org,
    )


@router.post("/widgets", response_model=WidgetResponse, status_code=201)
async def create_widget(
    data: WidgetCreateRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:write")),
) -> Any:
    """Create a dashboard widget."""
    org = _org_id(user)
    widget = await svc.create_widget(
        session,
        data.model_dump(exclude_none=True),
        owner_id=user.id,
        organization_id=org,
    )
    return widget


@router.put("/widgets/{widget_id}", response_model=WidgetResponse)
async def update_widget(
    widget_id: UUID,
    data: WidgetUpdateRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:write")),
) -> Any:
    """Update a dashboard widget."""
    org = _org_id(user)

    # Verify widget belongs to this organization
    from app.models.analytics import DashboardWidget

    check = await session.execute(
        select(DashboardWidget.id).where(
            DashboardWidget.id == widget_id,
            DashboardWidget.organization_id == org,
        )
    )
    if not check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Widget not found")

    widget = await svc.update_widget(session, widget_id, data.model_dump(exclude_none=True))
    if not widget:
        raise HTTPException(status_code=404, detail="Widget not found")
    return widget


@router.delete("/widgets/{widget_id}", response_model=MessageResponse)
async def delete_widget(
    widget_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:write")),
) -> Any:
    """Delete a dashboard widget."""
    org = _org_id(user)

    # Verify widget belongs to this organization
    from app.models.analytics import DashboardWidget

    check = await session.execute(
        select(DashboardWidget.id).where(
            DashboardWidget.id == widget_id,
            DashboardWidget.organization_id == org,
        )
    )
    if not check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Widget not found")

    deleted = await svc.delete_widget(session, widget_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Widget not found")
    return MessageResponse(message="Widget deleted")


# =============================================================================
# Utility
# =============================================================================


@router.get("/aggregations")
async def get_aggregation_types(
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """List available aggregation types."""
    from app.models.analytics import AggregationType

    return [{"value": a.value, "label": a.value.upper()} for a in AggregationType]


# =============================================================================
# Enterprise Analytics — Unified Real-Data Endpoint
# =============================================================================


@router.get("/dashboard/enterprise")
async def get_enterprise_analytics(
    hours: int = Query(24, ge=1, le=720, description="Time window in hours"),
    site_id: UUID | None = Query(None),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_permissions("analytics:read")),
) -> Any:
    """
    Comprehensive enterprise analytics aggregating real data from all subsystems.

    Returns device fleet, network clients, security posture, audit trail,
    controller health, and per-device-type breakdowns — all from live DB queries.
    """
    from sqlalchemy import and_, case, func, or_

    from app.models.core import Controller
    from app.models.devices import (
        Device,
        DeviceClient,
        DevicePort,
        DeviceStatus,
        PortStatus,
    )

    org = _org_id(user)
    now = datetime.now(UTC)
    window_start = now - timedelta(hours=hours)

    # FailedLoginRecord / IPBlockRecord are PLATFORM-GLOBAL
    # (no organization_id / site_id column) so their counts are not
    # tenant-associable. Mirror the /security/summary fix: only a
    # super_admin may see the platform figures; org/read-tier callers get 0
    # and the platform tables are not queried at all.
    # scope-aware — a scoped super_admin key without 'audit:read' is
    # treated as a non-platform caller and gets 0 (platform tables not queried).
    from app.core.dependencies import is_platform_super_admin

    is_super_admin = is_platform_super_admin(user)

    if site_id:
        await _verify_site_ownership(session, site_id, org, user)

    # Always filter by organization; narrow to site_id when provided
    org_site_sub = _org_site_filter(org)
    org_filter = Device.site_id.in_(org_site_sub)

    # SITE-GRANT: a site-limited operator must never see the
    # org-wide enterprise rollup across sibling sites. When no explicit site is
    # pinned, narrow every slice (devices, sites, controllers) to the caller's
    # granted set. site_scope_filter is a no-op for unrestricted admins.
    grant_filter = site_scope_filter(user, Device.site_id)

    # Composed device filter: always org-scoped, grant-scoped, optionally
    # narrowed to one site.
    def _device_where():
        if site_id:
            return and_(org_filter, grant_filter, Device.site_id == site_id)
        return and_(org_filter, grant_filter)

    device_filter = _device_where()

    # ── 1. Device Fleet ──────────────────────────────────────────────────────
    device_q = (
        select(
            func.count().label("total"),
            func.count().filter(Device.status == DeviceStatus.ONLINE).label("online"),
            func.count().filter(Device.status == DeviceStatus.OFFLINE).label("offline"),
            func.count().filter(Device.status == DeviceStatus.DEGRADED).label("degraded"),
            func.avg(Device.cpu_usage_percent).label("avg_cpu"),
            func.avg(Device.memory_usage_percent).label("avg_mem"),
            func.avg(Device.temperature_celsius).label("avg_temp"),
            func.max(Device.cpu_usage_percent).label("max_cpu"),
            func.max(Device.memory_usage_percent).label("max_mem"),
            func.max(Device.temperature_celsius).label("max_temp"),
        )
        .select_from(Device)
        .where(device_filter)
    )
    dr = (await session.execute(device_q)).one()

    # By device type
    dtype_q = (
        select(
            Device.device_type,
            func.count().label("total"),
            func.count().filter(Device.status == DeviceStatus.ONLINE).label("online"),
            func.count().filter(Device.status == DeviceStatus.OFFLINE).label("offline"),
        )
        .where(device_filter)
        .group_by(Device.device_type)
    )
    dtype_rows = (await session.execute(dtype_q)).all()
    by_type = {
        row.device_type: {"total": row.total, "online": row.online, "offline": row.offline}
        for row in dtype_rows
    }

    # By manufacturer
    mfr_q = (
        select(
            func.coalesce(Device.manufacturer, "Unknown").label("manufacturer"),
            func.count().label("total"),
        )
        .where(device_filter)
        .group_by("manufacturer")
        .order_by(func.count().desc())
        .limit(10)
    )
    mfr_rows = (await session.execute(mfr_q)).all()
    by_manufacturer = [{"name": r.manufacturer, "count": r.total} for r in mfr_rows]

    # ── 2. Network Clients ───────────────────────────────────────────────────
    client_sub = select(Device.id).where(device_filter)
    client_q = select(
        func.count().label("total"),
        func.count().filter(DeviceClient.is_online == True).label("online"),  # noqa: E712
        func.count().filter(DeviceClient.band == "2.4GHz").label("band_2g"),
        func.count().filter(DeviceClient.band == "5GHz").label("band_5g"),
        func.count().filter(DeviceClient.band == "6GHz").label("band_6g"),
        func.avg(DeviceClient.signal_dbm).label("avg_signal"),
        func.sum(DeviceClient.tx_bytes).label("total_tx"),
        func.sum(DeviceClient.rx_bytes).label("total_rx"),
    ).where(DeviceClient.device_id.in_(client_sub))
    cr = (await session.execute(client_q)).one()

    # Signal distribution
    signal_dist_q = (
        select(
            case(
                (DeviceClient.signal_dbm > -45, "excellent"),
                (DeviceClient.signal_dbm > -55, "good"),
                (DeviceClient.signal_dbm > -65, "fair"),
                (DeviceClient.signal_dbm > -75, "weak"),
                else_="poor",
            ).label("quality"),
            func.count().label("count"),
        )
        .where(DeviceClient.device_id.in_(client_sub))
        .where(DeviceClient.signal_dbm.isnot(None))
        .group_by("quality")
    )
    sig_rows = (await session.execute(signal_dist_q)).all()
    signal_distribution = {r.quality: r.count for r in sig_rows}

    # Top SSIDs
    ssid_q = (
        select(DeviceClient.ssid, func.count().label("clients"))
        .where(DeviceClient.device_id.in_(client_sub))
        .where(DeviceClient.ssid.isnot(None))
        .group_by(DeviceClient.ssid)
        .order_by(func.count().desc())
        .limit(10)
    )
    ssid_rows = (await session.execute(ssid_q)).all()
    top_ssids = [{"ssid": r.ssid, "clients": r.clients} for r in ssid_rows]

    # ── 3. Ports & PoE ──────────────────────────────────────────────────────
    port_sub = select(Device.id).where(device_filter)
    port_q = select(
        func.count().label("total"),
        func.count().filter(DevicePort.status == PortStatus.UP).label("up"),
        func.count().filter(DevicePort.status == PortStatus.DOWN).label("down"),
        func.count().filter(DevicePort.is_poe_enabled == True).label("poe_ports"),  # noqa: E712
        func.sum(DevicePort.poe_power_watts).label("total_poe_watts"),
        func.sum(DevicePort.tx_bytes).label("total_tx"),
        func.sum(DevicePort.rx_bytes).label("total_rx"),
        func.sum(DevicePort.errors).label("total_errors"),
    ).where(DevicePort.device_id.in_(port_sub))
    pr = (await session.execute(port_q)).one()

    # ── 4. Sites ─────────────────────────────────────────────────────────────
    site_q = (
        select(
            Site.id,
            Site.name,
            func.count(Device.id).label("device_count"),
            func.count().filter(Device.status == DeviceStatus.ONLINE).label("online"),
            func.count().filter(Device.status == DeviceStatus.OFFLINE).label("offline"),
        )
        .outerjoin(Device, Device.site_id == Site.id)
        .where(Site.organization_id == org, site_scope_filter(user, Site.id))
        .group_by(Site.id, Site.name)
    )
    if site_id:
        site_q = site_q.where(Site.id == site_id)
    site_rows = (await session.execute(site_q)).all()
    sites = [
        {
            "id": str(r.id),
            "name": r.name,
            "devices": r.device_count,
            "online": r.online,
            "offline": r.offline,
            "health": round(r.online / r.device_count * 100, 1) if r.device_count else 100,
        }
        for r in site_rows
    ]
    total_sites = len(site_rows)

    # ── 5. Controllers ───────────────────────────────────────────────────────
    ctrl_q = (
        select(
            Controller.id,
            Controller.name,
            Controller.controller_type,
            Controller.status,
            Controller.host,
            Controller.sync_enabled,
            func.count(Device.id).label("device_count"),
        )
        .outerjoin(Device, Device.controller_id == Controller.id)
        .where(
            Controller.site_id.in_(org_site_sub),
            site_scope_filter(user, Controller.site_id),
        )
        .group_by(
            Controller.id,
            Controller.name,
            Controller.controller_type,
            Controller.status,
            Controller.host,
            Controller.sync_enabled,
        )
    )
    # every other slice (sites/devices/clients) narrows by the
    # selected site, but the controllers slice did not — the Controllers stat
    # card + Sync-All fan-out stayed org-wide in site mode. Mirror the siblings.
    if site_id:
        ctrl_q = ctrl_q.where(Controller.site_id == site_id)
    ctrl_rows = (await session.execute(ctrl_q)).all()
    controllers = [
        {
            "id": str(r.id),
            "name": r.name,
            "type": r.controller_type,
            "status": r.status,
            "host": r.host,
            "sync_enabled": r.sync_enabled,
            "device_count": r.device_count,
        }
        for r in ctrl_rows
    ]

    # ── 6. Security Posture (from audit schema) ─────────────────────────────
    security: dict[str, Any] = {
        "failed_logins_window": 0,
        "active_ip_blocks": 0,
        "unresolved_anomalies": 0,
        "total_security_events": 0,
    }
    try:
        from app.models.security_audit import (
            FailedLoginRecord,
            IPBlockRecord,
            SecurityAnomalyRecord,
            SecurityEventRecord,
        )

        # platform-global tables — only super_admin may see
        # these figures. For org/read-tier callers leave the initialized 0
        # and DO NOT query the tables.
        if is_super_admin:
            fl_q = (
                select(func.count())
                .select_from(FailedLoginRecord)
                .where(FailedLoginRecord.timestamp >= window_start)
            )
            security["failed_logins_window"] = (await session.execute(fl_q)).scalar() or 0

            ip_q = (
                select(func.count())
                .select_from(IPBlockRecord)
                .where(
                    IPBlockRecord.is_active == True,  # noqa: E712
                    or_(IPBlockRecord.expires_at.is_(None), IPBlockRecord.expires_at > now),
                )
            )
            security["active_ip_blocks"] = (await session.execute(ip_q)).scalar() or 0

        anom_q = (
            select(func.count())
            .select_from(SecurityAnomalyRecord)
            .where(
                SecurityAnomalyRecord.resolved == False,  # noqa: E712
                SecurityAnomalyRecord.organization_id == org,
            )
        )
        security["unresolved_anomalies"] = (await session.execute(anom_q)).scalar() or 0

        se_q = (
            select(func.count())
            .select_from(SecurityEventRecord)
            .where(
                SecurityEventRecord.timestamp >= window_start,
                SecurityEventRecord.organization_id == org,
            )
        )
        security["total_security_events"] = (await session.execute(se_q)).scalar() or 0
    except (ImportError, SQLAlchemyError):
        pass  # audit tables may not exist

    # ── 7. Audit Trail (from audit schema) ───────────────────────────────────
    audit_stats: dict[str, Any] = {"total_events": 0, "by_level": {}, "by_source": {}}
    try:
        from app.models.security_audit import AuditLogRecord

        # the audit aggregates must respect the SAME per-user site grant
        # as the device/site/controller slices above — otherwise a site-limited
        # analytics reader infers sibling-site audit activity. site_scope_filter is
        # a no-op for unrestricted admins.
        _audit_grant = site_scope_filter(user, AuditLogRecord.site_id)
        al_total = (
            select(func.count())
            .select_from(AuditLogRecord)
            .where(
                AuditLogRecord.timestamp >= window_start,
                AuditLogRecord.organization_id == org,
                _audit_grant,
            )
        )
        audit_stats["total_events"] = (await session.execute(al_total)).scalar() or 0

        al_status = (
            select(AuditLogRecord.status, func.count().label("c"))
            .where(AuditLogRecord.timestamp >= window_start)
            .where(AuditLogRecord.organization_id == org)
            .where(_audit_grant)
            .group_by(AuditLogRecord.status)
        )
        for row in (await session.execute(al_status)).all():
            audit_stats["by_level"][row.status or "unknown"] = row.c

        al_resource = (
            select(AuditLogRecord.resource_type, func.count().label("c"))
            .where(AuditLogRecord.timestamp >= window_start)
            .where(AuditLogRecord.organization_id == org)
            .where(AuditLogRecord.resource_type.isnot(None))
            .where(_audit_grant)
            .group_by(AuditLogRecord.resource_type)
            .order_by(func.count().desc())
            .limit(10)
        )
        for row in (await session.execute(al_resource)).all():
            audit_stats["by_source"][row.resource_type] = row.c
    except (ImportError, SQLAlchemyError):
        pass

    # ── 8. Incidents ─────────────────────────────────────────────────────────
    incident_stats: dict[str, Any] = {"open": 0, "investigating": 0, "resolved": 0, "total": 0}
    try:
        from app.models.correlation import Incident

        # incident aggregates respect the per-user site grant too.
        inc_q = (
            select(Incident.status, func.count().label("c"))
            .where(Incident.organization_id == org)
            .where(site_scope_filter(user, Incident.site_id))
            .group_by(Incident.status)
        )
        for row in (await session.execute(inc_q)).all():
            incident_stats[row.status] = row.c
            incident_stats["total"] += row.c
    except (ImportError, SQLAlchemyError):
        pass

    # ── 9. Top Devices by Resource Usage ─────────────────────────────────────
    top_cpu_q = (
        select(Device.id, Device.name, Device.device_type, Device.cpu_usage_percent, Device.status)
        .where(device_filter)
        .where(Device.cpu_usage_percent.isnot(None))
        .order_by(Device.cpu_usage_percent.desc())
        .limit(10)
    )
    top_cpu = [
        {
            "id": str(r.id),
            "name": r.name,
            "type": r.device_type,
            "cpu": round(r.cpu_usage_percent, 1),
            "status": r.status,
        }
        for r in (await session.execute(top_cpu_q)).all()
    ]

    top_mem_q = (
        select(
            Device.id, Device.name, Device.device_type, Device.memory_usage_percent, Device.status
        )
        .where(device_filter)
        .where(Device.memory_usage_percent.isnot(None))
        .order_by(Device.memory_usage_percent.desc())
        .limit(10)
    )
    top_mem = [
        {
            "id": str(r.id),
            "name": r.name,
            "type": r.device_type,
            "memory": round(r.memory_usage_percent, 1),
            "status": r.status,
        }
        for r in (await session.execute(top_mem_q)).all()
    ]

    # ── 10. Health Score Computation ─────────────────────────────────────────
    total = dr.total or 1
    online_pct = (dr.online or 0) / total * 100
    avg_cpu = float(dr.avg_cpu or 0)
    avg_mem = float(dr.avg_mem or 0)

    health_score = max(
        0,
        min(
            100,
            round(
                online_pct * 0.4
                + max(0, 100 - avg_cpu) * 0.2
                + max(0, 100 - avg_mem) * 0.2
                + (
                    # never deduct on a platform-global figure the
                    # caller can't see. Non-super-admin callers always get the
                    # full failed-login credit (failed_logins_window stays 0).
                    (
                        100
                        if security["failed_logins_window"] < 5
                        else 50
                        if security["failed_logins_window"] < 20
                        else 0
                    )
                    if is_super_admin
                    else 100
                )
                * 0.1
                + (100 if incident_stats["open"] == 0 else 50 if incident_stats["open"] < 3 else 0)
                * 0.1
            ),
        ),
    )

    return {
        "timestamp": now.isoformat(),
        "hours": hours,
        "health_score": health_score,
        "fleet": {
            "total": dr.total or 0,
            "online": dr.online or 0,
            "offline": dr.offline or 0,
            "degraded": dr.degraded or 0,
            "avg_cpu": round(avg_cpu, 1),
            "avg_memory": round(float(dr.avg_mem or 0), 1),
            "avg_temp": round(float(dr.avg_temp or 0), 1) if dr.avg_temp else None,
            "max_cpu": round(float(dr.max_cpu or 0), 1) if dr.max_cpu else None,
            "max_memory": round(float(dr.max_mem or 0), 1) if dr.max_mem else None,
            "max_temp": round(float(dr.max_temp or 0), 1) if dr.max_temp else None,
            "by_type": by_type,
            "by_manufacturer": by_manufacturer,
        },
        "clients": {
            "total": cr.total or 0,
            "online": cr.online or 0,
            "band_2g": cr.band_2g or 0,
            "band_5g": cr.band_5g or 0,
            "band_6g": cr.band_6g or 0,
            "avg_signal_dbm": round(float(cr.avg_signal or 0), 1) if cr.avg_signal else None,
            "total_tx_bytes": int(cr.total_tx or 0),
            "total_rx_bytes": int(cr.total_rx or 0),
            "signal_distribution": signal_distribution,
            "top_ssids": top_ssids,
        },
        "ports": {
            "total": pr.total or 0,
            "up": pr.up or 0,
            "down": pr.down or 0,
            "poe_ports": pr.poe_ports or 0,
            "total_poe_watts": round(float(pr.total_poe_watts or 0), 1),
            "total_tx_bytes": int(pr.total_tx or 0),
            "total_rx_bytes": int(pr.total_rx or 0),
            "total_errors": int(pr.total_errors or 0),
        },
        "sites": sites,
        "total_sites": total_sites,
        "controllers": controllers,
        "security": security,
        "audit": audit_stats,
        "incidents": incident_stats,
        "top_devices_cpu": top_cpu,
        "top_devices_memory": top_mem,
    }
