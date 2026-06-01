# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Network Module - API Routes
===================================

REST API endpoints for network management functionality.
Implements CRUD operations for VLANs, WiFi networks, switch ports, and clients.
"""

import logging
from datetime import UTC
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    CurrentUser,
    get_current_active_user,
    is_unscoped_superuser,
    require_permissions,
)
from app.core.site_access import assert_can_access_site, site_ids_for_request
from app.db import get_session
from app.modules.network.service import (
    ClientNotFoundError,
    DeviceNotFoundError,
    DuplicateError,
    NetworkClientService,
    NetworkDeviceService,
    NetworkSummaryService,
    PortNotFoundError,
    SwitchPortService,
    TopologyService,
    VlanNotFoundError,
    VlanService,
    WifiNetworkNotFoundError,
    WifiNetworkService,
)
from app.services.device_control import DeviceControlService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Network"])


def _org_id(user: CurrentUser) -> UUID:
    """Extract organization_id from current user, or raise 400."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(status_code=400, detail="Organization context required")
    return oid  # type: ignore[no-any-return]


def _apply_site_limiting(user: CurrentUser) -> set[UUID] | None:
    """Return the set of granted site IDs for a site-limited user, else None.

    a site-limited user (one with ≥1
    explicit site grant who is not super_admin / org_admin) must only see
    rows for their granted sites. ``None`` means "no per-user site limit"
    (super_admin / org_admin / grant-less user) — the service applies the
    normal org scope only. Thread the result into list/stats/topology/summary
    service methods so sibling-site rows are excluded at the query level
    (keeping pagination counts accurate).
    """
    if getattr(user, "is_site_limited", False):
        return set(user.accessible_site_ids)
    return None


async def _assert_site_in_org(
    db: AsyncSession,
    site_id: UUID | None,
    user: CurrentUser,
) -> None:
    """Reject a request whose site_id doesn't belong to the caller's org.

    create_vlan / create_wifi previously stamped the caller's org on the
    new row but passed an unchecked ``site_id`` straight through, letting
    a caller bind a VLAN/WiFi to another tenant's site. superuser is
    exempt; a null site_id (org-wide object) is allowed.
    """
    if site_id is None:
        return
    from app.models.core import Site

    q = select(Site.id).where(Site.id == site_id, Site.deleted_at.is_(None))
    if not is_unscoped_superuser(user):  # scope-aware
        q = q.where(Site.organization_id == _org_id(user))
    if (await db.execute(q)).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Site not found")
    # a site-limited user may only bind/act on granted sites.
    assert_can_access_site(user, site_id, detail="Site not found")


def _scope_job_site_id(
    user: CurrentUser,
    site_id: UUID | None,
) -> UUID | None:
    """Resolve the site_id an org-wide queued job (discovery / topology-refresh /
    full-sync) may run for, enforcing the per-user site grant (sweep).

    These endpoints fan a Celery task across the org when no ``site_id`` is
    given. The underlying tasks take only a single ``site_id`` and run in a
    background context where ``current_user_var`` is unset, so the per-user
    grant cannot be enforced inside the task. We therefore enforce it here:

    - super_admin / org_admin / grant-less user → no-op; the caller-supplied
      ``site_id`` (possibly ``None`` = org-wide) is returned unchanged.
    - site-limited caller WITH a ``site_id`` → must be a granted site, else 404
      (``assert_can_access_site``); the granted ``site_id`` is returned so the
      job is scoped to exactly that site.
    - site-limited caller WITHOUT a ``site_id`` → an org-wide fan-out would reach
      sibling sites they were never granted. We refuse the unscoped run with a
      404 (no existence oracle) — a site-limited operator must name a granted
      site for these jobs.
    """
    if not getattr(user, "is_site_limited", False):
        return site_id
    if site_id is not None:
        assert_can_access_site(user, site_id, detail="Site not found")
        return site_id
    granted = site_ids_for_request(user)
    detail = "A granted site_id is required for this operation" if granted else "Site not found"
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


# ============================================================================
# Pydantic Schemas
# ============================================================================


class VlanBase(BaseModel):
    """Base VLAN schema."""

    vlan_id: int = Field(..., ge=1, le=4094, description="VLAN ID (1-4094)")
    name: str = Field(..., min_length=1, max_length=64)
    description: str | None = None


class VlanCreate(VlanBase):
    """Schema for creating a VLAN."""

    site_id: UUID | None = None
    dhcp_enabled: bool = False
    dhcp_start: str | None = None
    dhcp_end: str | None = None
    gateway: str | None = None
    subnet_mask: str | None = None


class VlanUpdate(BaseModel):
    """Schema for updating a VLAN."""

    name: str | None = Field(None, min_length=1, max_length=64)
    description: str | None = None
    dhcp_enabled: bool | None = None
    dhcp_start: str | None = None
    dhcp_end: str | None = None
    gateway: str | None = None
    subnet_mask: str | None = None


class VlanResponse(BaseModel):
    """VLAN response schema."""

    id: UUID
    vlan_id: int
    name: str
    description: str | None = None
    site_id: UUID | None = None
    dhcp_enabled: bool = False
    dhcp_start: str | None = None
    dhcp_end: str | None = None
    gateway: str | None = None
    subnet_mask: str | None = None

    class Config:
        from_attributes = True


class VlanListResponse(BaseModel):
    """Paginated VLAN list response."""

    items: list[VlanResponse]
    total: int
    skip: int
    limit: int


class WifiNetworkBase(BaseModel):
    """Base WiFi network schema."""

    ssid: str = Field(..., min_length=1, max_length=32)
    security: str = Field(default="wpa2-personal")
    vlan_id: int | None = Field(None, ge=1, le=4094)
    hidden: bool = False
    enabled: bool = True
    band: str = "both"
    client_isolation: bool = False
    band_steering: bool = True
    fast_roaming: bool = True


class WifiNetworkCreate(WifiNetworkBase):
    """Schema for creating a WiFi network."""

    password: str | None = Field(None, min_length=8, max_length=63)
    site_id: UUID | None = None
    rate_limit_enabled: bool = False
    rate_limit_up: int | None = None
    rate_limit_down: int | None = None


class WifiNetworkUpdate(BaseModel):
    """Schema for updating a WiFi network."""

    ssid: str | None = Field(None, min_length=1, max_length=32)
    password: str | None = Field(None, min_length=8, max_length=63)
    security: str | None = None
    vlan_id: int | None = Field(None, ge=1, le=4094)
    hidden: bool | None = None
    enabled: bool | None = None
    band: str | None = None
    client_isolation: bool | None = None
    band_steering: bool | None = None
    fast_roaming: bool | None = None
    rate_limit_enabled: bool | None = None
    rate_limit_up: int | None = None
    rate_limit_down: int | None = None


class WifiNetworkResponse(BaseModel):
    """WiFi network response schema."""

    id: UUID
    ssid: str
    security: str
    vlan_id: int | None = None
    site_id: UUID | None = None
    hidden: bool = False
    enabled: bool = True
    band: str = "both"
    client_isolation: bool = False
    band_steering: bool = True
    fast_roaming: bool = True
    rate_limit_enabled: bool = False
    rate_limit_up: int | None = None
    rate_limit_down: int | None = None

    class Config:
        from_attributes = True


class WifiNetworkListResponse(BaseModel):
    """Paginated WiFi network list response."""

    items: list[WifiNetworkResponse]
    total: int
    skip: int
    limit: int


class SwitchPortBase(BaseModel):
    """Base switch port schema."""

    port_number: int
    name: str | None = None
    is_enabled: bool = True
    is_poe_enabled: bool = False
    vlan_id: int | None = None


class SwitchPortUpdate(BaseModel):
    """Schema for updating a switch port."""

    name: str | None = None
    is_enabled: bool | None = None
    enabled: bool | None = None
    is_poe_enabled: bool | None = None
    poe_enabled: bool | None = None
    vlan_id: int | None = Field(None, ge=1, le=4094)
    native_vlan: int | None = Field(None, ge=1, le=4094)
    tagged_vlans: list[int] | None = None


class SwitchPortResponse(BaseModel):
    """Switch port response schema.

    Maps from DevicePort ORM: id, device_id, port_number, name,
    port_type, status, is_enabled, is_poe_enabled, vlan_id,
    speed_mbps, duplex, poe_power_watts, poe_class,
    tx_bytes, rx_bytes, tx_packets, rx_packets, errors,
    connected_mac, connected_device_id.
    """

    id: UUID
    device_id: UUID
    port_number: int
    name: str | None = None
    port_type: str = "ethernet"
    is_enabled: bool = True
    is_poe_enabled: bool = False
    vlan_id: int | None = None
    status: str = "unknown"
    speed_mbps: int | None = None
    duplex: str | None = None
    poe_power_watts: float | None = None
    rx_bytes: int | None = 0
    tx_bytes: int | None = 0

    class Config:
        from_attributes = True


class NetworkClientBase(BaseModel):
    """Base network client schema."""

    mac_address: str
    hostname: str | None = None


class NetworkClientUpdate(BaseModel):
    """Schema for updating a network client."""

    hostname: str | None = None
    display_name: str | None = None
    blocked: bool | None = None
    notes: str | None = None


class NetworkClientResponse(BaseModel):
    """Network client response schema.

    Maps from DeviceClient ORM which has:
    id, device_id, mac_address, hostname, ip_address, ssid, band,
    channel, signal_dbm, noise_dbm, connected_at, last_seen,
    is_online, tx_bytes, rx_bytes, tx_rate_mbps, rx_rate_mbps.
    """

    id: UUID
    mac_address: str
    ip_address: str | None = None
    hostname: str | None = None
    device_id: UUID | None = None
    ssid: str | None = None
    band: str | None = None
    signal_dbm: int | None = None
    is_online: bool = True
    rx_bytes: int = 0
    tx_bytes: int = 0
    last_seen: str | None = None

    class Config:
        from_attributes = True


class NetworkClientListResponse(BaseModel):
    """Paginated network client list response."""

    items: list[NetworkClientResponse]
    total: int
    skip: int
    limit: int


class NetworkDeviceResponse(BaseModel):
    """Network device response schema."""

    id: UUID
    name: str
    device_type: str
    model: str | None = None
    manufacturer: str | None = None
    firmware_version: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    status: str = "unknown"
    uptime_seconds: int | None = None
    site_id: UUID | None = None
    capabilities: dict[str, Any] | None = None

    class Config:
        from_attributes = True


class NetworkDeviceListResponse(BaseModel):
    """Paginated network device list response."""

    items: list[NetworkDeviceResponse]
    total: int
    skip: int
    limit: int


class TopologyNode(BaseModel):
    """Topology node schema."""

    id: str
    name: str
    device_type: str
    ip_address: str | None = None
    status: str = "unknown"
    model: str | None = None
    manufacturer: str | None = None


class TopologyLink(BaseModel):
    """Topology link schema."""

    source: str
    target: str
    source_port: str | None = None
    target_port: str | None = None
    speed: str | None = None
    status: str = "unknown"


class TopologyResponse(BaseModel):
    """Network topology response."""

    nodes: list[TopologyNode]
    links: list[TopologyLink]


class TrafficStats(BaseModel):
    """Traffic statistics schema."""

    timestamp: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int


class NetworkSummaryResponse(BaseModel):
    """Network summary statistics response."""

    devices: dict[str, Any]
    clients: dict[str, Any]
    total_vlans: int
    total_wifi_networks: int


# ============================================================================
# Type Aliases for Dependencies
# ============================================================================

DBSession = Annotated[AsyncSession, Depends(get_session)]
AuthUser = Annotated[CurrentUser, Depends(get_current_active_user)]
DeviceReadUser = Annotated[CurrentUser, Depends(require_permissions("device:read"))]
DeviceWriteUser = Annotated[CurrentUser, Depends(require_permissions("device:update"))]
DeviceAdminUser = Annotated[CurrentUser, Depends(require_permissions("device:admin"))]


def _action_error_status(error: str | None) -> int:
    """Map device-control error identifiers to HTTP status codes."""
    if error in {"device_not_found", "DeviceNotFoundError"}:
        return status.HTTP_404_NOT_FOUND
    if error in {"capability_not_supported", "CapabilityNotSupportedError"}:
        return status.HTTP_409_CONFLICT
    # Policy refusals, not server errors: read-only mode → 403, missing
    # confirmation → 409. device_control sets ``error`` to the exception class
    # name, so these AdapterError subclasses arrive here as their class names.
    if error in {"AdapterReadOnlyError", "READ_ONLY", "read_only"}:
        return status.HTTP_403_FORBIDDEN
    if error in {"AdapterConfirmationRequiredError", "confirmation_required"}:
        return status.HTTP_409_CONFLICT
    if error in {
        "no_adapter",
        "AdapterConnectionError",
        "AdapterTimeoutError",
        "AdapterRateLimitError",
    }:
        return status.HTTP_503_SERVICE_UNAVAILABLE
    if error in {"AdapterAuthenticationError"}:
        return status.HTTP_502_BAD_GATEWAY
    return status.HTTP_500_INTERNAL_SERVER_ERROR


async def _resolve_control_device_id(
    db: AsyncSession,
    network_device_id: UUID,
    network_device: Any,
) -> UUID | None:
    """
    Resolve a network module device UUID to the core devices table UUID.

    The network module can store a mirrored device row with a different UUID.
    """
    from app.models.devices import Device as CoreDevice

    direct = await db.execute(select(CoreDevice.id).where(CoreDevice.id == network_device_id))
    direct_id = direct.scalar_one_or_none()
    if direct_id:
        return direct_id

    external_id = getattr(network_device, "external_id", None)
    site_id = getattr(network_device, "site_id", None)
    if external_id:
        query = select(CoreDevice.id).where(CoreDevice.external_id == external_id)
        if site_id:
            query = query.where(CoreDevice.site_id == site_id)
        row = await db.execute(query)
        resolved = row.scalar_one_or_none()
        if resolved:
            return resolved

    mac_address = getattr(network_device, "mac_address", None)
    if mac_address:
        query = select(CoreDevice.id).where(CoreDevice.mac_address == str(mac_address).upper())
        if site_id:
            query = query.where(CoreDevice.site_id == site_id)
        row = await db.execute(query)
        resolved = row.scalar_one_or_none()
        if resolved:
            return resolved

    return None


# ============================================================================
# VLAN Endpoints
# ============================================================================


@router.get("/vlans", response_model=VlanListResponse)
async def list_vlans(
    db: DBSession,
    current_user: DeviceReadUser,
    site_id: UUID | None = Query(None, description="Filter by site"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> VlanListResponse:
    """
    List all VLANs for the current user's organization.

    Optionally filter by site.
    """
    service = VlanService(db)
    vlans, total = await service.list(
        organization_id=_org_id(current_user),
        site_id=site_id,
        skip=skip,
        limit=limit,
        site_ids=_apply_site_limiting(current_user),
    )

    return VlanListResponse(
        items=[VlanResponse.model_validate(v) for v in vlans],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.post("/vlans", response_model=VlanResponse, status_code=status.HTTP_201_CREATED)
async def create_vlan(
    vlan: VlanCreate,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> VlanResponse:
    """Create a new VLAN."""
    await _assert_site_in_org(db, vlan.site_id, current_user)
    service = VlanService(db)

    try:
        new_vlan = await service.create(
            organization_id=_org_id(current_user),
            vlan_id=vlan.vlan_id,
            name=vlan.name,
            description=vlan.description,
            site_id=vlan.site_id,
            dhcp_enabled=vlan.dhcp_enabled,
            dhcp_start=vlan.dhcp_start,
            dhcp_end=vlan.dhcp_end,
            gateway=vlan.gateway,
            subnet_mask=vlan.subnet_mask,
        )
        return VlanResponse.model_validate(new_vlan)
    except DuplicateError as e:
        logger.error("Duplicate VLAN error: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A VLAN with this ID already exists",
        )


@router.get("/vlans/{vlan_uuid}", response_model=VlanResponse)
async def get_vlan(
    vlan_uuid: UUID,
    db: DBSession,
    current_user: DeviceReadUser,
) -> VlanResponse:
    """Get a specific VLAN by UUID."""
    service = VlanService(db)

    try:
        vlan = await service.get(vlan_uuid, _org_id(current_user))
        assert_can_access_site(current_user, vlan.site_id, detail=f"VLAN {vlan_uuid} not found")
        return VlanResponse.model_validate(vlan)
    except VlanNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"VLAN {vlan_uuid} not found",
        )


@router.put("/vlans/{vlan_uuid}", response_model=VlanResponse)
async def update_vlan(
    vlan_uuid: UUID,
    vlan: VlanUpdate,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> VlanResponse:
    """Update a VLAN."""
    service = VlanService(db)

    try:
        existing = await service.get(vlan_uuid, _org_id(current_user))
        assert_can_access_site(current_user, existing.site_id, detail=f"VLAN {vlan_uuid} not found")
        updated = await service.update(
            vlan_uuid,
            _org_id(current_user),
            **vlan.model_dump(exclude_unset=True),
        )
        return VlanResponse.model_validate(updated)
    except VlanNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"VLAN {vlan_uuid} not found",
        )


@router.delete("/vlans/{vlan_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vlan(
    vlan_uuid: UUID,
    db: DBSession,
    current_user: DeviceAdminUser,
) -> None:
    """Delete a VLAN."""
    service = VlanService(db)

    try:
        existing = await service.get(vlan_uuid, _org_id(current_user))
        assert_can_access_site(current_user, existing.site_id, detail=f"VLAN {vlan_uuid} not found")
        await service.delete(vlan_uuid, _org_id(current_user))
    except VlanNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"VLAN {vlan_uuid} not found",
        )


# ============================================================================
# WiFi Network Endpoints
# ============================================================================


@router.get("/wifi", response_model=WifiNetworkListResponse)
async def list_wifi_networks(
    db: DBSession,
    current_user: DeviceReadUser,
    site_id: UUID | None = Query(None, description="Filter by site"),
    enabled: bool | None = Query(None, description="Filter by enabled status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> WifiNetworkListResponse:
    """List all WiFi networks for the current user's organization."""
    service = WifiNetworkService(db)
    networks, total = await service.list(
        organization_id=_org_id(current_user),
        site_id=site_id,
        enabled=enabled,
        skip=skip,
        limit=limit,
        site_ids=_apply_site_limiting(current_user),
    )

    return WifiNetworkListResponse(
        items=[WifiNetworkResponse.model_validate(n) for n in networks],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.post("/wifi", response_model=WifiNetworkResponse, status_code=status.HTTP_201_CREATED)
async def create_wifi_network(
    wifi: WifiNetworkCreate,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> WifiNetworkResponse:
    """Create a new WiFi network."""
    await _assert_site_in_org(db, wifi.site_id, current_user)
    service = WifiNetworkService(db)

    # Encrypt password before storing
    from app.core.crypto import encrypt_credential

    password_hash = encrypt_credential(wifi.password) if wifi.password else None

    try:
        network = await service.create(
            organization_id=_org_id(current_user),
            ssid=wifi.ssid,
            security=wifi.security,
            password_hash=password_hash,
            vlan_id=wifi.vlan_id,
            site_id=wifi.site_id,
            hidden=wifi.hidden,
            enabled=wifi.enabled,
            band=wifi.band,
            client_isolation=wifi.client_isolation,
            band_steering=wifi.band_steering,
            fast_roaming=wifi.fast_roaming,
            rate_limit_enabled=wifi.rate_limit_enabled,
            rate_limit_up=wifi.rate_limit_up,
            rate_limit_down=wifi.rate_limit_down,
        )
        return WifiNetworkResponse.model_validate(network)
    except DuplicateError as e:
        logger.error("Duplicate WiFi network error: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A WiFi network with this SSID already exists",
        )


@router.get("/wifi/{wifi_id}", response_model=WifiNetworkResponse)
async def get_wifi_network(
    wifi_id: UUID,
    db: DBSession,
    current_user: DeviceReadUser,
) -> WifiNetworkResponse:
    """Get a specific WiFi network."""
    service = WifiNetworkService(db)

    try:
        network = await service.get(wifi_id, _org_id(current_user))
        assert_can_access_site(
            current_user, network.site_id, detail=f"WiFi network {wifi_id} not found"
        )
        return WifiNetworkResponse.model_validate(network)
    except WifiNetworkNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"WiFi network {wifi_id} not found",
        )


@router.put("/wifi/{wifi_id}", response_model=WifiNetworkResponse)
async def update_wifi_network(
    wifi_id: UUID,
    wifi: WifiNetworkUpdate,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> WifiNetworkResponse:
    """Update a WiFi network."""
    service = WifiNetworkService(db)

    # Handle password update
    updates = wifi.model_dump(exclude_unset=True)
    if "password" in updates:
        from app.core.crypto import encrypt_credential

        updates["password_hash"] = encrypt_credential(updates.pop("password"))

    try:
        existing = await service.get(wifi_id, _org_id(current_user))
        assert_can_access_site(
            current_user, existing.site_id, detail=f"WiFi network {wifi_id} not found"
        )
        network = await service.update(
            wifi_id,
            _org_id(current_user),
            **updates,
        )
        return WifiNetworkResponse.model_validate(network)
    except WifiNetworkNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"WiFi network {wifi_id} not found",
        )


@router.delete("/wifi/{wifi_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_wifi_network(
    wifi_id: UUID,
    db: DBSession,
    current_user: DeviceAdminUser,
) -> None:
    """Delete a WiFi network."""
    service = WifiNetworkService(db)

    try:
        existing = await service.get(wifi_id, _org_id(current_user))
        assert_can_access_site(
            current_user, existing.site_id, detail=f"WiFi network {wifi_id} not found"
        )
        await service.delete(wifi_id, _org_id(current_user))
    except WifiNetworkNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"WiFi network {wifi_id} not found",
        )


@router.post("/wifi/{wifi_id}/enable", response_model=WifiNetworkResponse)
async def enable_wifi_network(
    wifi_id: UUID,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> WifiNetworkResponse:
    """Enable a WiFi network."""
    service = WifiNetworkService(db)

    try:
        _ex = await service.get(wifi_id, _org_id(current_user))
        assert_can_access_site(
            current_user, _ex.site_id, detail=f"WiFi network {wifi_id} not found"
        )
        network = await service.toggle_enabled(wifi_id, _org_id(current_user), True)
        return WifiNetworkResponse.model_validate(network)
    except WifiNetworkNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"WiFi network {wifi_id} not found",
        )


@router.post("/wifi/{wifi_id}/disable", response_model=WifiNetworkResponse)
async def disable_wifi_network(
    wifi_id: UUID,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> WifiNetworkResponse:
    """Disable a WiFi network."""
    service = WifiNetworkService(db)

    try:
        _ex = await service.get(wifi_id, _org_id(current_user))
        assert_can_access_site(
            current_user, _ex.site_id, detail=f"WiFi network {wifi_id} not found"
        )
        network = await service.toggle_enabled(wifi_id, _org_id(current_user), False)
        return WifiNetworkResponse.model_validate(network)
    except WifiNetworkNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"WiFi network {wifi_id} not found",
        )


# ============================================================================
# Switch Port Endpoints
# ============================================================================


@router.get("/devices/{device_id}/ports", response_model=list[SwitchPortResponse])
async def list_switch_ports(
    device_id: UUID,
    db: DBSession,
    current_user: DeviceReadUser,
) -> list[SwitchPortResponse]:
    """List all ports on a switch device."""
    service = SwitchPortService(db)

    try:
        ports = await service.list_by_device(device_id, _org_id(current_user))
        return [SwitchPortResponse.model_validate(p) for p in ports]
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )


@router.get("/devices/{device_id}/ports/{port_id}", response_model=SwitchPortResponse)
async def get_switch_port(
    device_id: UUID,
    port_id: UUID,
    db: DBSession,
    current_user: DeviceReadUser,
) -> SwitchPortResponse:
    """Get a specific switch port."""
    service = SwitchPortService(db)

    try:
        port = await service.get(port_id, device_id, _org_id(current_user))
        return SwitchPortResponse.model_validate(port)
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )
    except PortNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Port {port_id} not found",
        )


@router.put("/devices/{device_id}/ports/{port_id}", response_model=SwitchPortResponse)
async def update_switch_port(
    device_id: UUID,
    port_id: UUID,
    port: SwitchPortUpdate,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> SwitchPortResponse:
    """Update a switch port configuration."""
    service = SwitchPortService(db)

    try:
        updated = await service.update(
            port_id,
            device_id,
            _org_id(current_user),
            **port.model_dump(exclude_unset=True),
        )
        return SwitchPortResponse.model_validate(updated)
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )
    except PortNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Port {port_id} not found",
        )


@router.post("/devices/{device_id}/ports/{port_id}/poe/enable", response_model=SwitchPortResponse)
async def enable_poe(
    device_id: UUID,
    port_id: UUID,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> SwitchPortResponse:
    """Enable PoE on a switch port."""
    service = SwitchPortService(db)

    try:
        port = await service.set_poe(port_id, device_id, _org_id(current_user), True)
        return SwitchPortResponse.model_validate(port)
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )
    except PortNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Port {port_id} not found",
        )


@router.post("/devices/{device_id}/ports/{port_id}/poe/disable", response_model=SwitchPortResponse)
async def disable_poe(
    device_id: UUID,
    port_id: UUID,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> SwitchPortResponse:
    """Disable PoE on a switch port."""
    service = SwitchPortService(db)

    try:
        port = await service.set_poe(port_id, device_id, _org_id(current_user), False)
        return SwitchPortResponse.model_validate(port)
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )
    except PortNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Port {port_id} not found",
        )


@router.post("/devices/{device_id}/ports/{port_id}/enable", response_model=SwitchPortResponse)
async def enable_port(
    device_id: UUID,
    port_id: UUID,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> SwitchPortResponse:
    """Enable a switch port."""
    service = SwitchPortService(db)

    try:
        port = await service.set_enabled(port_id, device_id, _org_id(current_user), True)
        return SwitchPortResponse.model_validate(port)
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )
    except PortNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Port {port_id} not found",
        )


@router.post("/devices/{device_id}/ports/{port_id}/disable", response_model=SwitchPortResponse)
async def disable_port(
    device_id: UUID,
    port_id: UUID,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> SwitchPortResponse:
    """Disable a switch port."""
    service = SwitchPortService(db)

    try:
        port = await service.set_enabled(port_id, device_id, _org_id(current_user), False)
        return SwitchPortResponse.model_validate(port)
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )
    except PortNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Port {port_id} not found",
        )


# ============================================================================
# Network Client Endpoints
# ============================================================================


@router.get("/clients", response_model=NetworkClientListResponse)
async def list_network_clients(
    db: DBSession,
    current_user: DeviceReadUser,
    site_id: UUID | None = Query(None, description="Filter by site"),
    is_online: bool | None = Query(None, description="Filter by online status"),
    search: str | None = Query(None, description="Search by MAC, hostname, or IP"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> NetworkClientListResponse:
    """List all network clients for the current user's organization."""
    service = NetworkClientService(db)
    clients, total = await service.list(
        organization_id=_org_id(current_user),
        site_id=site_id,
        is_online=is_online,
        search=search,
        skip=skip,
        limit=limit,
        site_ids=_apply_site_limiting(current_user),
    )

    return NetworkClientListResponse(
        items=[NetworkClientResponse.model_validate(c) for c in clients],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/clients/{client_id}", response_model=NetworkClientResponse)
async def get_network_client(
    client_id: UUID,
    db: DBSession,
    current_user: DeviceReadUser,
) -> NetworkClientResponse:
    """Get a specific network client."""
    service = NetworkClientService(db)

    try:
        client = await service.get(client_id, _org_id(current_user))
        return NetworkClientResponse.model_validate(client)
    except ClientNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {client_id} not found",
        )


@router.put("/clients/{client_id}", response_model=NetworkClientResponse)
async def update_network_client(
    client_id: UUID,
    client: NetworkClientUpdate,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> NetworkClientResponse:
    """Update a network client."""
    service = NetworkClientService(db)

    try:
        updated = await service.update(
            client_id,
            _org_id(current_user),
            **client.model_dump(exclude_unset=True),
        )
        return NetworkClientResponse.model_validate(updated)
    except ClientNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {client_id} not found",
        )


@router.get("/clients/stats/summary")
async def get_client_stats(
    db: DBSession,
    current_user: DeviceReadUser,
    site_id: UUID | None = Query(None, description="Filter by site"),
) -> dict[str, Any]:
    """Get client statistics summary."""
    service = NetworkClientService(db)
    return await service.get_stats(
        _org_id(current_user), site_id, site_ids=_apply_site_limiting(current_user)
    )


# ============================================================================
# Network Device Endpoints
# ============================================================================


@router.get("/devices", response_model=NetworkDeviceListResponse)
async def list_network_devices(
    db: DBSession,
    current_user: DeviceReadUser,
    site_id: UUID | None = Query(None, description="Filter by site"),
    device_type: str | None = Query(None, description="Filter by device type"),
    status: str | None = Query(None, description="Filter by status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> NetworkDeviceListResponse:
    """List all network devices for the current user's organization."""
    service = NetworkDeviceService(db)
    # a site-limited user only sees their granted sites.
    site_ids = (
        current_user.accessible_site_ids
        if getattr(current_user, "is_site_limited", False)
        else None
    )
    devices, total = await service.list(
        organization_id=_org_id(current_user),
        site_id=site_id,
        device_type=device_type,
        status=status,
        skip=skip,
        limit=limit,
        site_ids=site_ids,
    )

    return NetworkDeviceListResponse(
        items=[NetworkDeviceResponse.model_validate(d) for d in devices],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/devices/{device_id}", response_model=NetworkDeviceResponse)
async def get_network_device(
    device_id: UUID,
    db: DBSession,
    current_user: DeviceReadUser,
) -> NetworkDeviceResponse:
    """Get a specific network device."""
    service = NetworkDeviceService(db)
    site_ids = (
        current_user.accessible_site_ids
        if getattr(current_user, "is_site_limited", False)
        else None
    )
    try:
        device = await service.get(device_id, _org_id(current_user), site_ids=site_ids)
        return NetworkDeviceResponse.model_validate(device)
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )


@router.get("/devices/stats/summary")
async def get_device_stats(
    db: DBSession,
    current_user: DeviceReadUser,
    site_id: UUID | None = Query(None, description="Filter by site"),
) -> dict[str, Any]:
    """Get device statistics summary."""
    service = NetworkDeviceService(db)
    return await service.get_stats(
        _org_id(current_user), site_id, site_ids=_apply_site_limiting(current_user)
    )


# ============================================================================
# Topology Endpoints
# ============================================================================


@router.get("/topology", response_model=TopologyResponse)
async def get_network_topology(
    db: DBSession,
    current_user: DeviceReadUser,
    site_id: UUID | None = Query(None, description="Filter by site"),
) -> TopologyResponse:
    """Get the network topology for the current user's organization."""
    service = TopologyService(db)
    topology = await service.get_topology(
        _org_id(current_user), site_id, site_ids=_apply_site_limiting(current_user)
    )

    return TopologyResponse(
        nodes=[TopologyNode(**n) for n in topology["nodes"]],
        links=[TopologyLink(**l) for l in topology["links"]],
    )


@router.post("/topology/refresh", status_code=status.HTTP_202_ACCEPTED)
async def refresh_topology(
    db: DBSession,
    current_user: DeviceWriteUser,
    site_id: UUID | None = Query(None, description="Filter by site"),
) -> dict[str, Any]:
    """Trigger a topology refresh (async task)."""
    # a site-limited operator may only refresh (discover) their granted
    # sites — an unscoped run would fan discovery across sibling sites.
    site_id = _scope_job_site_id(current_user, site_id)
    logger.info(
        f"Topology refresh requested by {current_user.user.email} "
        f"for org {current_user.organization_id}, site {site_id}"
    )
    from app.tasks.discovery import discover_all_devices

    # Scope to the caller's org (+ site) — never trigger a global,
    # all-tenant discovery from a tenant-facing route.
    task = discover_all_devices.delay(
        organization_id=str(_org_id(current_user)),
        site_id=str(site_id) if site_id else None,
    )
    return {"status": "accepted", "message": "Topology refresh started", "task_id": task.id}


# ============================================================================
# Network Summary & Statistics Endpoints
# ============================================================================


@router.get("/stats/summary", response_model=NetworkSummaryResponse)
async def get_network_summary(
    db: DBSession,
    current_user: DeviceReadUser,
    site_id: UUID | None = Query(None, description="Filter by site"),
) -> NetworkSummaryResponse:
    """Get comprehensive network summary statistics."""
    service = NetworkSummaryService(db)
    summary = await service.get_summary(
        _org_id(current_user), site_id, site_ids=_apply_site_limiting(current_user)
    )
    return NetworkSummaryResponse(**summary)


@router.get("/devices/{device_id}/traffic", response_model=list[TrafficStats])
async def get_device_traffic(
    device_id: UUID,
    db: DBSession,
    current_user: DeviceReadUser,
    period: str = Query("1h", description="Time period (1h, 6h, 24h, 7d, 30d)"),
) -> list[TrafficStats]:
    """Get traffic statistics for a device."""
    # Verify device exists and user has access
    service = NetworkDeviceService(db)
    try:
        await service.get(device_id, _org_id(current_user))
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    # Map period string to a timedelta for the query window
    from datetime import datetime, timedelta

    from app.services.analytics import PersistentAnalyticsService as MetricDataStore

    period_map = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    delta = period_map.get(period)
    if delta is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid period '{period}'. Must be one of: {', '.join(period_map)}",
        )

    # Choose granularity based on period to keep result set manageable
    granularity_map = {
        "1h": "1m",
        "6h": "5m",
        "24h": "15m",
        "7d": "1h",
        "30d": "1d",
    }
    granularity = granularity_map[period]

    end_time = datetime.now(UTC)
    start_time = end_time - delta
    filters = {"device_id": str(device_id)}

    # Query all four traffic metrics in parallel-ish fashion
    metric_names = ["device.rx_bytes", "device.tx_bytes", "device.rx_packets", "device.tx_packets"]
    results_by_metric: dict[str, dict[str, float]] = {}

    for metric_name in metric_names:
        try:
            rows = await MetricDataStore.query_metrics(
                session=db,
                metric_name=metric_name,
                start_time=start_time,
                end_time=end_time,
                granularity=granularity,
                aggregation="sum",
                filters=filters,
            )
            short_name = metric_name.split(".")[-1]  # e.g. "rx_bytes"
            for row in rows:
                ts = row["timestamp"]
                results_by_metric.setdefault(ts, {})[short_name] = int(row["value"].get("value", 0))
        except Exception as exc:
            logger.debug("Traffic metric query failed for %s: %s", metric_name, exc)

    # Merge into TrafficStats list sorted by timestamp
    traffic: list[TrafficStats] = []
    for ts in sorted(results_by_metric):
        vals = results_by_metric[ts]
        traffic.append(
            TrafficStats(
                timestamp=ts,
                rx_bytes=int(vals.get("rx_bytes", 0)),
                tx_bytes=int(vals.get("tx_bytes", 0)),
                rx_packets=int(vals.get("rx_packets", 0)),
                tx_packets=int(vals.get("tx_packets", 0)),
            )
        )

    return traffic


# ============================================================================
# Discovery Endpoints
# ============================================================================


@router.post("/discovery/start", status_code=status.HTTP_202_ACCEPTED)
async def start_discovery(
    db: DBSession,
    current_user: DeviceWriteUser,
    site_id: UUID | None = Query(None, description="Limit to site"),
    subnet: str | None = Query(None, description="Subnet to scan"),
) -> dict[str, Any]:
    """Start network device discovery (async task)."""
    # a site-limited operator may only discover their granted sites —
    # an unscoped run would fan discovery across sibling sites.
    site_id = _scope_job_site_id(current_user, site_id)
    logger.info(
        f"Discovery started by {current_user.user.email} "
        f"for org {current_user.organization_id}, site {site_id}, subnet {subnet}"
    )
    from app.tasks.discovery import discover_all_devices

    task = discover_all_devices.delay(
        organization_id=str(_org_id(current_user)),
        site_id=str(site_id) if site_id else None,
    )
    return {
        "status": "accepted",
        "message": "Discovery started",
        "task_id": task.id,
    }


@router.get("/discovery/status")
async def get_discovery_status(
    db: DBSession,
    current_user: DeviceReadUser,
    task_id: str = Query(..., description="Discovery task ID"),
) -> dict[str, Any]:
    """Get the status of a discovery task."""
    from celery.result import AsyncResult

    from app.core.celery_app import celery_app
    from app.tasks.base import get_task_progress

    # First check the in-memory progress store (populated by FreeSDN tasks)
    progress = get_task_progress(task_id)
    if progress is not None:
        result_data = progress.result or {}
        return {
            "task_id": progress.task_id,
            "status": progress.status,
            "progress": progress.progress,
            "devices_found": result_data.get("devices_found", 0)
            if isinstance(result_data, dict)
            else 0,
            "message": progress.message,
            "started_at": progress.started_at.isoformat() if progress.started_at else None,
            "completed_at": progress.completed_at.isoformat() if progress.completed_at else None,
        }

    # Fall back to the Celery result backend for tasks not tracked in-memory
    async_result = AsyncResult(task_id, app=celery_app)
    celery_state = async_result.state  # PENDING, STARTED, SUCCESS, FAILURE, etc.

    response: dict[str, Any] = {
        "task_id": task_id,
        "status": celery_state.lower(),
        "progress": 100 if celery_state == "SUCCESS" else 0,
        "devices_found": 0,
        "started_at": None,
        "completed_at": None,
    }

    if celery_state == "SUCCESS" and isinstance(async_result.result, dict):
        response["devices_found"] = async_result.result.get("devices_found", 0)
    elif celery_state == "FAILURE":
        response["message"] = str(async_result.result) if async_result.result else "Task failed"

    return response


# ============================================================================
# Device Action Endpoints
# ============================================================================


@router.post("/devices/{device_id}/reboot", status_code=status.HTTP_202_ACCEPTED)
async def reboot_device(
    device_id: UUID,
    db: DBSession,
    current_user: DeviceAdminUser,
) -> dict[str, Any]:
    """
    Reboot a network device.

    Requires admin permissions. The reboot is executed asynchronously.
    """
    service = NetworkDeviceService(db)

    try:
        device = await service.get(device_id, _org_id(current_user))
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    control_device_id = await _resolve_control_device_id(db, device_id, device)
    if not control_device_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} is not linked to a controllable inventory record",
        )

    control = DeviceControlService(db)
    action = await control.reboot_device(
        device_id=control_device_id,
        initiated_by=current_user.user.email,
    )
    if not action.success:
        raise HTTPException(
            status_code=_action_error_status(action.error),
            detail=action.message,
        )

    # log user_id, not email, to prevent log-driven enumeration.
    logger.info(
        "Reboot executed for device",
        extra={"device_id": str(device_id), "user_id": str(current_user.user.id)},
    )
    return {
        "status": "accepted",
        "message": action.message,
        "device_id": str(device_id),
    }


@router.post("/devices/{device_id}/locate", status_code=status.HTTP_200_OK)
async def locate_device(
    device_id: UUID,
    db: DBSession,
    current_user: DeviceWriteUser,
    duration: int = Query(30, ge=5, le=300, description="Duration in seconds"),
) -> dict[str, Any]:
    """
    Flash device LEDs to help locate it physically.

    Works on access points and some switches.
    """
    service = NetworkDeviceService(db)

    try:
        device = await service.get(device_id, _org_id(current_user))
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    control_device_id = await _resolve_control_device_id(db, device_id, device)
    if not control_device_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} is not linked to a controllable inventory record",
        )

    control = DeviceControlService(db)
    action = await control.locate_device(
        device_id=control_device_id,
        duration=duration,
        initiated_by=current_user.user.email,
    )
    if not action.success:
        raise HTTPException(
            status_code=_action_error_status(action.error),
            detail=action.message,
        )

    logger.info(
        "Locate executed for device",
        extra={"device_id": str(device_id), "user_id": str(current_user.user.id)},
    )
    return {
        "status": "success",
        "message": action.message,
        "device_id": str(device_id),
        "duration": duration,
    }


@router.post("/devices/{device_id}/ports/{port_id}/poe/cycle", status_code=status.HTTP_202_ACCEPTED)
async def cycle_poe_port(
    device_id: UUID,
    port_id: UUID,
    db: DBSession,
    current_user: DeviceWriteUser,
    duration: int = Query(5, ge=1, le=60, description="Off duration in seconds"),
) -> dict[str, Any]:
    """
    Cycle PoE power on a switch port.

    Disables PoE power for the specified duration, then re-enables it.
    Useful for rebooting PoE-powered devices like IP cameras, phones, or APs.
    """
    service = SwitchPortService(db)

    try:
        port = await service.get(port_id, device_id, _org_id(current_user))
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )
    except PortNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Port {port_id} not found",
        )

    if not port.is_poe_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PoE is not enabled on this port",
        )

    try:
        network_device = await NetworkDeviceService(db).get(device_id, _org_id(current_user))
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    control_device_id = await _resolve_control_device_id(db, device_id, network_device)
    if not control_device_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} is not linked to a controllable inventory record",
        )

    control = DeviceControlService(db)
    action = await control.cycle_poe(
        device_id=control_device_id,
        port=port.port_number,
        duration=duration,
        initiated_by=current_user.user.email,
    )
    if not action.success:
        raise HTTPException(
            status_code=_action_error_status(action.error),
            detail=action.message,
        )

    logger.info(
        "PoE cycle executed for port",
        extra={
            "port_number": port.port_number,
            "device_id": str(device_id),
            "user_id": str(current_user.user.id),
        },
    )
    return {
        "status": "accepted",
        "message": action.message,
        "device_id": str(device_id),
        "port_id": str(port_id),
        "port_number": port.port_number,
        "duration": duration,
    }


@router.post("/devices/{device_id}/sync", status_code=status.HTTP_202_ACCEPTED)
async def sync_device(
    device_id: UUID,
    db: DBSession,
    current_user: DeviceWriteUser,
) -> dict[str, Any]:
    """
    Sync device configuration and status from the controller.

    Forces an immediate sync of the device state from the management controller.
    """
    service = NetworkDeviceService(db)

    try:
        device = await service.get(device_id, _org_id(current_user))
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    from app.tasks.sync import sync_device_status

    control_device_id = await _resolve_control_device_id(db, device_id, device)
    if not control_device_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} is not linked to a controllable inventory record",
        )

    logger.info(
        "Sync requested for device",
        extra={"device_id": str(device_id), "user_id": str(current_user.user.id)},
    )
    try:
        task = sync_device_status.delay(str(control_device_id))
    except Exception as exc:
        logger.exception("Failed to enqueue sync task for device %s", device_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable",
        ) from exc

    return {
        "status": "accepted",
        "message": f"Sync started for {device.name}",
        "device_id": str(device_id),
        "task_id": task.id,
    }


@router.post("/sync/all", status_code=status.HTTP_202_ACCEPTED)
async def sync_all_devices(
    db: DBSession,
    current_user: DeviceWriteUser,
    site_id: UUID | None = Query(None, description="Limit to site"),
) -> dict[str, Any]:
    """
    Sync all devices from controllers.

    Forces an immediate sync of all device states from management controllers.
    """
    # full-sync is a write action against controllers/devices. A
    # site-limited operator may only sync their granted sites — an unscoped
    # run would push sync against sibling sites they were never granted.
    site_id = _scope_job_site_id(current_user, site_id)
    logger.info(
        f"Full sync requested by {current_user.user.email} "
        f"for org {current_user.organization_id}, site {site_id}"
    )

    from app.tasks.sync import sync_all_device_statuses

    try:
        task = sync_all_device_statuses.delay(
            organization_id=str(_org_id(current_user)),
            site_id=str(site_id) if site_id else None,
        )
    except Exception as exc:
        logger.exception("Failed to enqueue full sync task")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable",
        ) from exc

    return {
        "status": "accepted",
        "message": "Full device sync started",
        "task_id": task.id,
        "site_id": str(site_id) if site_id else None,
    }
