# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Canonical Resource API
================================================

CRUD endpoints for canonical VLANs, DHCP scopes/reservations,
DNS records, and address groups.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_active_user, require_permissions
from app.db import get_session
from app.modules.gateway.schemas import (
    CanonicalVLANCreate,
    CanonicalVLANDetailResponse,
    CanonicalVLANListResponse,
    CanonicalVLANResponse,
    CanonicalVLANUpdate,
    DHCPReservationCreate,
    DHCPReservationResponse,
    DHCPScopeCreate,
    DHCPScopeResponse,
    DNSRecordCreate,
    DNSRecordResponse,
    DNSRecordUpdate,
)
from app.modules.gateway.services.canonical_service import (
    CanonicalService,
    DNSRecordNotFoundError,
    SiteNotInOrgError,
    VLANConflictError,
    VLANNotFoundError,
)

router = APIRouter(tags=["Gateway Canonical Resources"])


def _org_id(user) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _assert_can_access_site(user, site_id) -> None:
    """a site-limited user must not push canonical config to a site
    outside their UserSiteAccess grant. No-op for org/super admins and users
    with no grants (CurrentUser.is_site_limited handles that)."""
    if site_id is None:
        return
    if getattr(user, "is_site_limited", False) and not user.can_access_site(site_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")


def _svc(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> CanonicalService:
    # thread the authenticated caller so the service can
    # apply the per-user site grant to list queries and to
    # object read / create-by-reference paths. No-op for super/org admins.
    return CanonicalService(session, current_user=current_user)


# =====================================================================
# Canonical VLANs
# =====================================================================


@router.get("/vlans", response_model=CanonicalVLANListResponse)
async def list_vlans(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
    site_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List canonical VLANs, optionally filtered by site or org."""
    org_id = _org_id(current_user)
    _assert_can_access_site(current_user, site_id)  # validate explicit param
    items, total = await svc.list_vlans(
        org_id,
        site_id=site_id,
        limit=limit,
        offset=offset,
    )
    return CanonicalVLANListResponse(
        items=[CanonicalVLANResponse.model_validate(v) for v in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/vlans/{vlan_id}", response_model=CanonicalVLANDetailResponse)
async def get_vlan(
    vlan_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Get a VLAN with its DHCP scopes, DNS records, and address groups."""
    org_id = _org_id(current_user)
    try:
        vlan = await svc.get_vlan(vlan_id, org_id=org_id)
    except VLANNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN not found")
    return vlan


@router.post("/vlans", response_model=CanonicalVLANResponse, status_code=status.HTTP_201_CREATED)
async def create_vlan(
    body: CanonicalVLANCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_vlans"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Create a new canonical VLAN definition."""
    org_id = _org_id(current_user)
    _assert_can_access_site(current_user, getattr(body, "site_id", None))
    try:
        vlan = await svc.create_vlan(org_id, **body.model_dump(exclude_unset=True))
        return CanonicalVLANResponse.model_validate(vlan)
    except VLANConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
    except SiteNotInOrgError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")


@router.patch("/vlans/{vlan_id}", response_model=CanonicalVLANResponse)
async def update_vlan(
    vlan_id: UUID,
    body: CanonicalVLANUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_vlans"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Update an existing canonical VLAN."""
    org_id = _org_id(current_user)
    try:
        existing = await svc.get_vlan(vlan_id, org_id=org_id)
        _assert_can_access_site(current_user, existing.site_id)
        vlan = await svc.update_vlan(vlan_id, org_id=org_id, **body.model_dump(exclude_unset=True))
        return CanonicalVLANResponse.model_validate(vlan)
    except VLANNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN not found")


@router.delete("/vlans/{vlan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vlan(
    vlan_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_vlans"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Delete a canonical VLAN and cascade remove related resources."""
    org_id = _org_id(current_user)
    try:
        existing = await svc.get_vlan(vlan_id, org_id=org_id)
        _assert_can_access_site(current_user, existing.site_id)
        await svc.delete_vlan(vlan_id, org_id=org_id)
    except VLANNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN not found")


# =====================================================================
# DHCP Scopes & Reservations
# =====================================================================


@router.get("/dhcp/scopes", response_model=list[DHCPScopeResponse])
async def list_dhcp_scopes(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
    site_id: UUID | None = None,
):
    """List DHCP scopes, optionally filtered by site."""
    org_id = _org_id(current_user)
    _assert_can_access_site(current_user, site_id)  # validate explicit param
    scopes, _total = await svc.list_dhcp_scopes(org_id, site_id=site_id)
    return [DHCPScopeResponse.model_validate(s) for s in scopes]


@router.post(
    "/dhcp/scopes",
    response_model=DHCPScopeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_dhcp_scope(
    body: DHCPScopeCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_dhcp"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Create a DHCP scope for a canonical VLAN."""
    org_id = _org_id(current_user)
    scope = await svc.create_dhcp_scope(org_id, **body.model_dump(exclude_unset=True))
    return DHCPScopeResponse.model_validate(scope)


@router.post(
    "/dhcp/reservations",
    response_model=DHCPReservationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_dhcp_reservation(
    body: DHCPReservationCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_dhcp"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Create a static DHCP reservation."""
    org_id = _org_id(current_user)
    try:
        reservation = await svc.create_dhcp_reservation(
            org_id, **body.model_dump(exclude_unset=True)
        )
    except VLANNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN not found")
    return DHCPReservationResponse.model_validate(reservation)


@router.delete(
    "/dhcp/reservations/{reservation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_dhcp_reservation(
    reservation_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_dhcp"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Delete a DHCP reservation."""
    org_id = _org_id(current_user)
    await svc.delete_dhcp_reservation(reservation_id, org_id=org_id)


# =====================================================================
# DNS Records
# =====================================================================


@router.get("/dns/records", response_model=list[DNSRecordResponse])
async def list_dns_records(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
    site_id: UUID | None = None,
):
    """List DNS records, optionally filtered by site."""
    org_id = _org_id(current_user)
    _assert_can_access_site(current_user, site_id)  # validate explicit param
    records, _total = await svc.list_dns_records(org_id, site_id=site_id)
    return [DNSRecordResponse.model_validate(r) for r in records]


@router.post(
    "/dns/records",
    response_model=DNSRecordResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_dns_record(
    body: DNSRecordCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_dns"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Create a DNS override record."""
    org_id = _org_id(current_user)
    _assert_can_access_site(current_user, getattr(body, "site_id", None))
    try:
        record = await svc.create_dns_record(org_id, **body.model_dump(exclude_unset=True))
    except SiteNotInOrgError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")
    return DNSRecordResponse.model_validate(record)


@router.patch("/dns/records/{record_id}", response_model=DNSRecordResponse)
async def update_dns_record(
    record_id: UUID,
    body: DNSRecordUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_dns"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Update a DNS record."""
    org_id = _org_id(current_user)
    try:
        record = await svc.update_dns_record(
            record_id, org_id=org_id, **body.model_dump(exclude_unset=True)
        )
        return DNSRecordResponse.model_validate(record)
    except DNSRecordNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "DNS record not found")


@router.delete("/dns/records/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dns_record(
    record_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.manage_dns"))],
    svc: Annotated[CanonicalService, Depends(_svc)],
):
    """Delete a DNS record."""
    org_id = _org_id(current_user)
    await svc.delete_dns_record(record_id, org_id=org_id)
