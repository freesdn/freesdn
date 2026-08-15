# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Dashboard API
=======================================

Read-only endpoints for the orchestration dashboard:
imported cache (firewall rules, NAT, VPN, IDS, interfaces, DHCP leases)
and aggregate overview.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.db import get_session
from app.modules.gateway.models import (
    CanonicalVLAN,
    DistributionRecord,
    DriftEvent,
    ImportedDHCPLease,
    ImportedFirewallRule,
    ImportedIDSEvent,
    ImportedInterface,
    ImportedNATRule,
    ImportedVPNTunnel,
    SiteRoleMap,
)
from app.modules.gateway.schemas import (
    ImportedDHCPLeaseListResponse,
    ImportedDHCPLeaseResponse,
    ImportedIDSEventResponse,
    ImportedIDSListResponse,
    ImportedInterfaceListResponse,
    ImportedInterfaceResponse,
    ImportedNATListResponse,
    ImportedRuleListResponse,
    ImportedVPNListResponse,
)
from app.modules.gateway.schemas import (
    ImportedNATResponse as ImportedNATRuleResponse,
)
from app.modules.gateway.schemas import (
    ImportedRuleResponse as ImportedFirewallRuleResponse,
)
from app.modules.gateway.schemas import (
    ImportedVPNResponse as ImportedVPNTunnelResponse,
)

router = APIRouter(prefix="/dashboard", tags=["Gateway Dashboard"])


DbSession = Annotated[AsyncSession, Depends(get_session)]


def _org_id(user) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


# ── GET  /gateway/dashboard/overview ────────────────────────────────────


@router.get("/overview")
async def dashboard_overview(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    db: DbSession,
    site_id: UUID | None = None,
):
    """Aggregate dashboard counters for the gateway module."""
    org_id = _org_id(current_user)
    if site_id:
        assert_can_access_site(current_user, site_id)
    base_filters = [
        CanonicalVLAN.organization_id == org_id,
        site_scope_filter(current_user, CanonicalVLAN.site_id),
    ]
    if site_id:
        base_filters.append(CanonicalVLAN.site_id == site_id)

    vlan_count = (
        await db.execute(
            select(func.count())
            .select_from(CanonicalVLAN)
            .where(
                *base_filters,
                CanonicalVLAN.deleted_at.is_(None),
            )
        )
    ).scalar() or 0

    rm_filters = [
        SiteRoleMap.organization_id == org_id,
        site_scope_filter(current_user, SiteRoleMap.site_id),
    ]
    if site_id:
        rm_filters.append(SiteRoleMap.site_id == site_id)
    role_map_count = (
        await db.execute(select(func.count()).select_from(SiteRoleMap).where(*rm_filters))
    ).scalar() or 0

    dist_filters = [
        DistributionRecord.organization_id == org_id,
        site_scope_filter(current_user, DistributionRecord.site_id),
    ]
    if site_id:
        dist_filters.append(DistributionRecord.site_id == site_id)
    dist_count = (
        await db.execute(select(func.count()).select_from(DistributionRecord).where(*dist_filters))
    ).scalar() or 0

    drift_filters = [
        DriftEvent.organization_id == org_id,
        site_scope_filter(current_user, DriftEvent.site_id),
    ]
    drift_filters.append(DriftEvent.resolved_at.is_(None))
    if site_id:
        drift_filters.append(DriftEvent.site_id == site_id)
    drift_open = (
        await db.execute(select(func.count()).select_from(DriftEvent).where(*drift_filters))
    ).scalar() or 0

    return {
        "total_vlans": vlan_count,
        "total_role_maps": role_map_count,
        "total_distributions": dist_count,
        "open_drift_events": drift_open,
    }


# ── Imported-Cache Read-Only Endpoints ──────────────────────────────────


@router.get("/firewall-rules", response_model=ImportedRuleListResponse)
async def list_imported_firewall_rules(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    db: DbSession,
    device_id: UUID | None = None,
    site_id: UUID | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Read-only: imported firewall rules from brain devices."""
    org_id = _org_id(current_user)
    base = select(ImportedFirewallRule).where(
        ImportedFirewallRule.organization_id == org_id,
        site_scope_filter(current_user, ImportedFirewallRule.site_id),
    )
    if device_id:
        base = base.where(ImportedFirewallRule.device_id == device_id)
    if site_id:
        base = base.where(ImportedFirewallRule.site_id == site_id)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0
    rows = (
        (
            await db.execute(
                base.order_by(ImportedFirewallRule.rule_index).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ImportedRuleListResponse(
        items=[ImportedFirewallRuleResponse.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/nat-rules", response_model=ImportedNATListResponse)
async def list_imported_nat_rules(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    db: DbSession,
    device_id: UUID | None = None,
    site_id: UUID | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Read-only: imported NAT rules."""
    org_id = _org_id(current_user)
    base = select(ImportedNATRule).where(
        ImportedNATRule.organization_id == org_id,
        site_scope_filter(current_user, ImportedNATRule.site_id),
    )
    if device_id:
        base = base.where(ImportedNATRule.device_id == device_id)
    if site_id:
        base = base.where(ImportedNATRule.site_id == site_id)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0
    rows = (await db.execute(base.limit(limit).offset(offset))).scalars().all()
    return ImportedNATListResponse(
        items=[ImportedNATRuleResponse.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/vpn-tunnels", response_model=ImportedVPNListResponse)
async def list_imported_vpn_tunnels(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    db: DbSession,
    device_id: UUID | None = None,
    site_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Read-only: imported VPN tunnels."""
    org_id = _org_id(current_user)
    base = select(ImportedVPNTunnel).where(
        ImportedVPNTunnel.organization_id == org_id,
        site_scope_filter(current_user, ImportedVPNTunnel.site_id),
    )
    if device_id:
        base = base.where(ImportedVPNTunnel.device_id == device_id)
    if site_id:
        base = base.where(ImportedVPNTunnel.site_id == site_id)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0
    rows = (await db.execute(base.limit(limit).offset(offset))).scalars().all()
    return ImportedVPNListResponse(
        items=[ImportedVPNTunnelResponse.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/ids-events", response_model=ImportedIDSListResponse)
async def list_imported_ids_events(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    db: DbSession,
    device_id: UUID | None = None,
    site_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Read-only: imported IDS/IPS events."""
    org_id = _org_id(current_user)
    base = select(ImportedIDSEvent).where(
        ImportedIDSEvent.organization_id == org_id,
        site_scope_filter(current_user, ImportedIDSEvent.site_id),
    )
    if device_id:
        base = base.where(ImportedIDSEvent.device_id == device_id)
    if site_id:
        base = base.where(ImportedIDSEvent.site_id == site_id)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0
    rows = (await db.execute(base.limit(limit).offset(offset))).scalars().all()
    return ImportedIDSListResponse(
        items=[ImportedIDSEventResponse.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/interfaces", response_model=ImportedInterfaceListResponse)
async def list_imported_interfaces(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    db: DbSession,
    device_id: UUID | None = None,
    site_id: UUID | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Read-only: imported network interfaces."""
    org_id = _org_id(current_user)
    base = select(ImportedInterface).where(
        ImportedInterface.organization_id == org_id,
        site_scope_filter(current_user, ImportedInterface.site_id),
    )
    if device_id:
        base = base.where(ImportedInterface.device_id == device_id)
    if site_id:
        base = base.where(ImportedInterface.site_id == site_id)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0
    rows = (await db.execute(base.limit(limit).offset(offset))).scalars().all()
    return ImportedInterfaceListResponse(
        items=[ImportedInterfaceResponse.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/dhcp-leases", response_model=ImportedDHCPLeaseListResponse)
async def list_imported_dhcp_leases(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    db: DbSession,
    device_id: UUID | None = None,
    site_id: UUID | None = None,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    """Read-only: imported DHCP leases."""
    org_id = _org_id(current_user)
    base = select(ImportedDHCPLease).where(
        ImportedDHCPLease.organization_id == org_id,
        site_scope_filter(current_user, ImportedDHCPLease.site_id),
    )
    if device_id:
        base = base.where(ImportedDHCPLease.device_id == device_id)
    if site_id:
        base = base.where(ImportedDHCPLease.site_id == site_id)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0
    rows = (await db.execute(base.limit(limit).offset(offset))).scalars().all()
    return ImportedDHCPLeaseListResponse(
        items=[ImportedDHCPLeaseResponse.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
