# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Network Management API
=====================================

VLAN / Network CRUD, WiFi / SSID CRUD, client management,
topology map, and network summary.

Frontend expects these routes under ``/network/``.
"""

from __future__ import annotations

import logging
from datetime import UTC
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.adapter_result import raise_for_adapter_result
from app.core.crypto import decrypt_credential, is_encrypted
from app.core.dependencies import (
    CurrentUser,
    get_current_active_user,
    require_permissions,
)
from app.core.security_utils import escape_like
from app.core.site_access import assert_can_access_site
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models.core import Controller, Site
from app.models.devices import (
    Device,
    DeviceClient,
    DevicePort,
    DeviceStatus,
    DeviceType,
)
from app.modules.network.models import (
    Network,
    TopologyLink,
    WifiNetwork,
)
from app.services.adapter_factory import get_adapter

logger = logging.getLogger(__name__)
router = APIRouter()


# =====================================================================
# Tenant-isolation helpers
# =====================================================================


def _org_id(user: Any) -> UUID:
    """Extract organization_id from the authenticated user or raise."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _org_site_filter(organization_id: UUID) -> dict[str, Any]:
    """Return a scalar sub-query of site IDs belonging to *organization_id*."""
    return (
        select(Site.id)
        .where(Site.organization_id == organization_id, Site.deleted_at.is_(None))
        .scalar_subquery()
    )


def _verify_site_grant(current_user: Any, site_id: Any, *, detail: str = "Not found") -> None:
    """Per-user site-grant gate for single-resource reads / writes / actions.

    Thin wrapper over :func:`app.core.site_access.assert_can_access_site` so every
    object-by-id endpoint in this module enforces the grant the same way after the
    org-level lookup. No-op for super_admin / org_admin and grant-less users.
    """
    assert_can_access_site(current_user, site_id, detail=detail)


# =====================================================================
# Pydantic schemas
# =====================================================================

# --- VLAN / Network ---


class VlanOut(BaseModel):
    id: str
    vlan_id: int
    name: str
    description: str | None = None
    site_id: str | None = None
    dhcp_enabled: bool = False
    dhcp_start: str | None = None
    dhcp_end: str | None = None
    gateway: str | None = None
    subnet_mask: str | None = None
    # Controller-sync envelope — present only when the local DB commit
    # succeeded but the downstream controller write did not.  Callers
    # that do not check these fields are unaffected (both default to the
    # happy-path values).
    controller_synced: bool = True
    controller_warning: str | None = None


class VlanCreate(BaseModel):
    # 802.1Q VLAN IDs are 1-4094. 0 and 4095 are reserved.
    vlan_id: int = Field(..., ge=1, le=4094)
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = Field(None, max_length=1000)
    site_id: str | None = Field(None, max_length=64)
    dhcp_enabled: bool = False
    dhcp_start: str | None = Field(None, max_length=45)
    dhcp_end: str | None = Field(None, max_length=45)
    gateway: str | None = Field(None, max_length=45)
    subnet_mask: str | None = Field(None, max_length=45)


class VlanUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = Field(None, max_length=1000)
    dhcp_enabled: bool | None = None
    dhcp_start: str | None = Field(None, max_length=45)
    dhcp_end: str | None = Field(None, max_length=45)
    gateway: str | None = Field(None, max_length=45)
    subnet_mask: str | None = Field(None, max_length=45)


class VlanListResponse(BaseModel):
    items: list[VlanOut]
    total: int
    skip: int
    limit: int


# --- VLAN Alignment ---


class ControllerVlanStatus(BaseModel):
    controller_id: str
    controller_name: str
    present: bool = False
    dhcp_enabled: bool = False
    gateway: str | None = None
    subnet: str | None = None
    network_id: str | None = None
    differs: bool = False  # True when present but config diverges from majority


class VlanAlignmentItem(BaseModel):
    vlan_id: int
    name: str
    controllers: list[ControllerVlanStatus]
    all_aligned: bool = False
    present_count: int = 0
    total_controllers: int = 0


class VlanAlignmentResponse(BaseModel):
    site_id: str
    site_name: str
    items: list[VlanAlignmentItem]
    total_vlans: int = 0
    total_controllers: int = 0
    alignment_score: float = 0.0


# --- VLAN Distribute ---


class VlanDistributeIn(BaseModel):
    source_network_id: str = Field(..., description="Network record to copy from")
    target_controller_ids: list[str] = Field(
        ..., min_length=1, description="Controllers to copy to"
    )


class VlanDistributeResult(BaseModel):
    controller_id: str
    controller_name: str
    success: bool
    message: str | None = None
    network_id: str | None = None


class VlanDistributeResponse(BaseModel):
    vlan_id: int
    vlan_name: str
    results: list[VlanDistributeResult]
    succeeded: int = 0
    failed: int = 0


# --- WiFi ---


class WifiNetworkOut(BaseModel):
    id: str
    ssid: str
    security: str = "wpa2_personal"
    vlan_id: int | None = None
    site_id: str | None = None
    hidden: bool = False
    enabled: bool = True
    band: str = "both"
    client_isolation: bool = False
    band_steering: bool = False
    fast_roaming: bool = False
    rate_limit_enabled: bool = False
    rate_limit_up: int | None = None
    rate_limit_down: int | None = None
    guest_network: bool = False
    wlan_group_name: str | None = None
    wlan_group_id: str | None = None
    external_id: str | None = None
    controller_id: str | None = None
    schedule_enabled: bool = False
    mac_filter_enabled: bool = False
    portal_enabled: bool = False
    # Controller-sync envelope — present only when the local DB commit
    # succeeded but the downstream controller write did not.
    controller_synced: bool = True
    controller_warning: str | None = None


# 802.11 SSID max is 32 chars; WPA2 PSK is 8-63 ASCII chars. WPA3 SAE
# allows up to 256 but vendor implementations cap at 63 for compat.
# Without these caps a 100 KB SSID/password was accepted and forwarded
# to the upstream controller adapter.
_WIFI_SECURITY = {
    "open",
    "wep",
    "wpa_personal",
    "wpa2_personal",
    "wpa3_personal",
    "wpa_wpa2_personal",
    "wpa2_wpa3_personal",
    "wpa2_enterprise",
    "wpa3_enterprise",
}
_WIFI_BAND = {"2.4ghz", "5ghz", "6ghz", "both", "all"}


def _validate_wifi_security(v: str | None) -> str | None:
    if v is None:
        return v
    if v not in _WIFI_SECURITY:
        raise ValueError(f"security must be one of: {sorted(_WIFI_SECURITY)}")
    return v


def _validate_wifi_band(v: str | None) -> str | None:
    if v is None:
        return v
    if v not in _WIFI_BAND:
        raise ValueError(f"band must be one of: {sorted(_WIFI_BAND)}")
    return v


class WifiNetworkCreate(BaseModel):
    ssid: str = Field(..., min_length=1, max_length=32)
    # WPA2 spec: 8-63 ASCII; allow shorter for open networks (handled
    # at security check). 63 is the WPA standard upper bound.
    password: str | None = Field(None, max_length=63)
    security: str = Field(default="wpa2_personal", max_length=32)
    vlan_id: int | None = Field(None, ge=1, le=4094)
    site_id: str | None = Field(None, max_length=64)
    hidden: bool = False
    enabled: bool = True
    band: str = Field(default="both", max_length=16)
    client_isolation: bool = False
    band_steering: bool = False
    fast_roaming: bool = False
    rate_limit_enabled: bool = False
    rate_limit_up: int | None = Field(None, ge=0, le=10_000_000)
    rate_limit_down: int | None = Field(None, ge=0, le=10_000_000)

    _v_security = field_validator("security")(
        classmethod(lambda _cls, v: _validate_wifi_security(v))
    )  # type: ignore[arg-type]
    _v_band = field_validator("band")(classmethod(lambda _cls, v: _validate_wifi_band(v)))  # type: ignore[arg-type]


class WifiNetworkUpdate(BaseModel):
    ssid: str | None = Field(None, min_length=1, max_length=32)
    password: str | None = Field(None, max_length=63)
    security: str | None = Field(None, max_length=32)
    vlan_id: int | None = Field(None, ge=1, le=4094)
    hidden: bool | None = None
    enabled: bool | None = None
    band: str | None = Field(None, max_length=16)
    client_isolation: bool | None = None
    band_steering: bool | None = None
    fast_roaming: bool | None = None
    rate_limit_enabled: bool | None = None
    rate_limit_up: int | None = Field(None, ge=0, le=10_000_000)
    rate_limit_down: int | None = Field(None, ge=0, le=10_000_000)

    _v_security = field_validator("security")(
        classmethod(lambda _cls, v: _validate_wifi_security(v))
    )  # type: ignore[arg-type]
    _v_band = field_validator("band")(classmethod(lambda _cls, v: _validate_wifi_band(v)))  # type: ignore[arg-type]


class WifiListResponse(BaseModel):
    items: list[WifiNetworkOut]
    total: int
    skip: int
    limit: int


class WifiToggleIn(BaseModel):
    enabled: bool


# --- Clients ---


class NetworkClientOut(BaseModel):
    id: str
    mac_address: str
    ip_address: str | None = None
    hostname: str | None = None
    display_name: str | None = None
    connection_type: str = "unknown"
    status: str = "unknown"
    blocked: bool = False
    connected_device_id: str | None = None
    ssid: str | None = None
    signal_strength: int | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    first_seen: str | None = None
    last_seen: str | None = None


class NetworkClientListResponse(BaseModel):
    items: list[NetworkClientOut]
    total: int
    skip: int
    limit: int


# --- Topology ---


class TopologyNodeOut(BaseModel):
    id: str
    name: str
    device_type: str
    ip_address: str | None = None
    status: str = "unknown"
    model: str | None = None
    vendor: str | None = None


class TopologyLinkOut(BaseModel):
    source: str
    target: str
    source_port: str | None = None
    target_port: str | None = None
    speed: str | None = None
    status: str = "up"


class NetworkTopologyOut(BaseModel):
    nodes: list[TopologyNodeOut]
    links: list[TopologyLinkOut]


# --- Summary ---


class DeviceSummary(BaseModel):
    total: int = 0
    online: int = 0
    offline: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)


class ClientSummary(BaseModel):
    total: int = 0
    online: int = 0
    wired: int = 0
    wireless: int = 0
    blocked: int = 0


class NetworkSummaryOut(BaseModel):
    devices: DeviceSummary = Field(default_factory=DeviceSummary)
    clients: ClientSummary = Field(default_factory=ClientSummary)
    total_vlans: int = 0
    total_wifi_networks: int = 0


# --- Network Devices ---


class NetworkDeviceOut(BaseModel):
    id: str
    name: str
    device_type: str
    model: str | None = None
    vendor: str | None = None
    firmware_version: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    status: str = "unknown"
    uptime: int | None = None
    site_id: str | None = None
    capabilities: dict[str, bool] | None = None


class NetworkDeviceListResponse(BaseModel):
    items: list[NetworkDeviceOut]
    total: int
    skip: int
    limit: int


# --- Switch Port Config (for /network/devices/{id}/ports) ---


class SwitchPortConfigOut(BaseModel):
    id: str
    device_id: str
    port_number: int
    name: str | None = None
    enabled: bool = True
    poe_enabled: bool = False
    native_vlan: int = 1
    tagged_vlans: list[int] = Field(default_factory=list)
    status: str = "unknown"
    speed: str | None = None
    duplex: str | None = None
    poe_power_draw: float | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0


class SwitchPortUpdate(BaseModel):
    # name capped to DB column width; tagged_vlans capped because a
    # 4094-element list (entire 802.1Q range) is unrealistic and a
    # 100k garbage list would otherwise reach the DB write.
    name: str | None = Field(None, max_length=128)
    enabled: bool | None = None
    poe_enabled: bool | None = None
    native_vlan: int | None = Field(None, ge=1, le=4094)
    tagged_vlans: list[int] | None = Field(None, max_length=64)


class PortVlanIn(BaseModel):
    """Body for /devices/{id}/ports/{n}/vlan — was bare ``dict``.

    Bare ``dict`` bypasses pydantic constraint enforcement entirely;
    a 100 KB ``data`` body would reach the setattr loop unchecked.
    Wrap with the same caps as ``SwitchPortUpdate``.
    """

    native_vlan: int | None = Field(None, ge=1, le=4094)
    tagged_vlans: list[int] | None = Field(None, max_length=64)


# =====================================================================
# Helper: build adapter for a controller
# =====================================================================


def _decrypt_if_needed(value: str | None) -> str:
    """Return plaintext value for encrypted controller secrets."""
    if not value:
        return ""
    if not is_encrypted(value):
        return value
    try:
        return decrypt_credential(value)
    except ValueError:
        return value


async def _get_adapter_for_controller(ctrl: Controller) -> dict[str, Any]:
    cloud_kwargs: dict[str, Any] = {}
    if ctrl.connection_mode == "cloud":
        cloud_kwargs = {
            "client_id": ctrl.client_id or "",
            "client_secret": _decrypt_if_needed(ctrl.client_secret),
            "omada_id": ctrl.omada_id or "",
            "cloud_region": ctrl.cloud_region or "us",
        }
    return get_adapter(
        controller_type=ctrl.controller_type,
        host=ctrl.host,
        username=ctrl.username or "",
        password=_decrypt_if_needed(ctrl.password),
        port=ctrl.port,
        use_ssl=ctrl.use_ssl,
        verify_ssl=ctrl.verify_ssl,
        mode=ctrl.connection_mode or "local",
        **cloud_kwargs,
    )


# =====================================================================
# VLAN / Network routes
# =====================================================================


@router.get("/vlans", response_model=VlanListResponse)
async def list_vlans(
    site_id: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    q = select(Network).where(
        Network.deleted_at.is_(None),
        tenant_filter(Network, _user),
    )
    if site_id:
        q = q.where(Network.site_id == site_id)

    total_q = select(func.count()).select_from(q.subquery())
    total = (await session.execute(total_q)).scalar() or 0

    q = q.offset(skip).limit(limit).order_by(Network.vlan_id)
    result = await session.execute(q)
    items = [
        VlanOut(
            id=str(n.id),
            vlan_id=n.vlan_id,
            name=n.name,
            description=n.description,
            site_id=str(n.site_id) if n.site_id else None,
            dhcp_enabled=n.dhcp_enabled,
            dhcp_start=n.dhcp_start,
            dhcp_end=n.dhcp_end,
            gateway=n.gateway,
            subnet_mask=n.subnet_mask,
        )
        for n in result.scalars().all()
    ]
    return VlanListResponse(items=items, total=total, skip=skip, limit=limit)


@router.get("/vlans/alignment", response_model=VlanAlignmentResponse)
async def get_vlan_alignment(
    site_id: str = Query(..., description="Site to check alignment for"),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Check VLAN alignment across controllers at a site.

    Groups all Network records by vlan_id for the given site,
    then shows which controllers have/lack each VLAN.
    Only useful when a site has 2+ controllers.
    """
    org_id = _org_id(_user)

    # Verify site belongs to org
    site_result = await session.execute(
        select(Site).where(
            Site.id == site_id, Site.organization_id == org_id, Site.deleted_at.is_(None)
        )
    )
    site = site_result.scalar_one_or_none()
    if not site:
        raise HTTPException(404, detail="Site not found")
    _verify_site_grant(_user, site.id, detail="Site not found")

    # Get all controllers at this site
    ctrl_result = await session.execute(
        select(Controller).where(
            Controller.site_id == site_id,
            Controller.deleted_at.is_(None),
        )
    )
    controllers = ctrl_result.scalars().all()

    # Get all VLANs at this site
    vlan_result = await session.execute(
        select(Network)
        .where(
            Network.site_id == site_id,
            Network.deleted_at.is_(None),
        )
        .order_by(Network.vlan_id)
    )
    vlans = vlan_result.scalars().all()

    # Group VLANs by vlan_id
    vlan_map: dict[int, dict] = {}
    for v in vlans:
        if v.vlan_id not in vlan_map:
            vlan_map[v.vlan_id] = {"name": v.name, "controllers": {}}
        if v.controller_id:
            vlan_map[v.vlan_id]["controllers"][str(v.controller_id)] = v

    # Build alignment items
    items = []
    total_cells = 0
    aligned_cells = 0
    for vid in sorted(vlan_map.keys()):
        info = vlan_map[vid]

        # Collect config fingerprints to detect differences among present VLANs
        present_configs: list[tuple[bool, str | None, str | None]] = []
        for ctrl in controllers:
            net = info["controllers"].get(str(ctrl.id))
            if net is not None:
                present_configs.append((net.dhcp_enabled, net.gateway, net.subnet))

        # Majority config (most common tuple) — used to flag outliers
        majority_config = None
        if present_configs:
            from collections import Counter

            majority_config = Counter(present_configs).most_common(1)[0][0]

        ctrl_statuses = []
        has_difference = False
        for ctrl in controllers:
            net = info["controllers"].get(str(ctrl.id))
            differs = False
            if net is not None and majority_config is not None:
                this_config = (net.dhcp_enabled, net.gateway, net.subnet)
                differs = this_config != majority_config
                if differs:
                    has_difference = True
            ctrl_statuses.append(
                ControllerVlanStatus(
                    controller_id=str(ctrl.id),
                    controller_name=ctrl.name,
                    present=net is not None,
                    dhcp_enabled=net.dhcp_enabled if net else False,
                    gateway=net.gateway if net else None,
                    subnet=net.subnet if net else None,
                    network_id=str(net.id) if net else None,
                    differs=differs,
                )
            )
            total_cells += 1
            if net is not None and not differs:
                aligned_cells += 1

        present = sum(1 for s in ctrl_statuses if s.present)
        items.append(
            VlanAlignmentItem(
                vlan_id=vid,
                name=info["name"],
                controllers=ctrl_statuses,
                all_aligned=present == len(controllers) and not has_difference,
                present_count=present,
                total_controllers=len(controllers),
            )
        )

    return VlanAlignmentResponse(
        site_id=str(site.id),
        site_name=site.name,
        items=items,
        total_vlans=len(items),
        total_controllers=len(controllers),
        alignment_score=aligned_cells / total_cells if total_cells > 0 else 1.0,
    )


@router.post("/vlans/distribute", response_model=VlanDistributeResponse)
async def distribute_vlan(
    data: VlanDistributeIn,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> dict[str, Any]:
    """Copy a VLAN from one controller to other controllers at the same site.

    Creates the VLAN on each target controller via the adapter, then
    creates matching Network records in the database.
    """
    org_id = _org_id(_user)

    # Load source network
    source_result = await session.execute(
        select(Network).where(
            Network.id == data.source_network_id,
            Network.deleted_at.is_(None),
            Network.site_id.in_(_org_site_filter(org_id)),
        )
    )
    source = source_result.scalar_one_or_none()
    if not source:
        raise HTTPException(404, detail="Source VLAN not found")
    _verify_site_grant(_user, source.site_id, detail="Source VLAN not found")

    # Load target controllers (must be same site AND same org as source)
    ctrl_result = await session.execute(
        select(Controller).where(
            Controller.id.in_(data.target_controller_ids),
            Controller.site_id == source.site_id,
            Controller.site_id.in_(_org_site_filter(org_id)),
            Controller.deleted_at.is_(None),
        )
    )
    targets = ctrl_result.scalars().all()
    if not targets:
        raise HTTPException(400, detail="No valid target controllers found at the same site")

    results: list[VlanDistributeResult] = []
    for ctrl in targets:
        try:
            adapter = await _get_adapter_for_controller(ctrl)

            # Push VLAN to controller via adapter
            vlan_payload: dict[str, Any] = {
                "name": source.name,
                "vlanId": source.vlan_id,
                "purpose": source.purpose or "Interface",
                "gateway": source.gateway,
                "subnet": source.subnet,
                "cidr": source.cidr,
                "dhcpEnable": source.dhcp_enabled,
            }

            async with adapter:
                adapter_result = await adapter.create_vlan(vlan_payload)

            if not getattr(adapter_result, "success", True):
                results.append(
                    VlanDistributeResult(
                        controller_id=str(ctrl.id),
                        controller_name=ctrl.name,
                        success=False,
                        message=getattr(adapter_result, "message", "Adapter error"),
                    )
                )
                continue

            # Create DB record
            ext_id = None
            val = getattr(adapter_result, "value", None)
            if isinstance(val, dict):
                ext_id = val.get("id")

            new_net = Network(
                controller_id=ctrl.id,
                site_id=source.site_id,
                external_id=ext_id,
                name=source.name,
                vlan_id=source.vlan_id,
                description=source.description,
                purpose=source.purpose,
                gateway=source.gateway,
                subnet=source.subnet,
                subnet_mask=source.subnet_mask,
                cidr=source.cidr,
                dhcp_enabled=source.dhcp_enabled,
                dhcp_start=source.dhcp_start,
                dhcp_end=source.dhcp_end,
            )
            session.add(new_net)
            await session.flush()

            results.append(
                VlanDistributeResult(
                    controller_id=str(ctrl.id),
                    controller_name=ctrl.name,
                    success=True,
                    message="VLAN created",
                    network_id=str(new_net.id),
                )
            )
        except Exception as e:
            logger.error(
                "Failed to distribute VLAN to controller %s: %s", ctrl.id, e, exc_info=True
            )
            results.append(
                VlanDistributeResult(
                    controller_id=str(ctrl.id),
                    controller_name=ctrl.name,
                    success=False,
                    message=str(e),
                )
            )

    await session.commit()

    return VlanDistributeResponse(
        vlan_id=source.vlan_id,
        vlan_name=source.name,
        results=results,
        succeeded=sum(1 for r in results if r.success),
        failed=sum(1 for r in results if not r.success),
    )


@router.get("/vlans/{vlan_id}", response_model=VlanOut)
async def get_vlan(
    vlan_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    result = await session.execute(
        select(Network).where(
            Network.id == vlan_id,
            Network.deleted_at.is_(None),
            Network.site_id.in_(_org_site_filter(org_id)),
        )
    )
    net = result.scalar_one_or_none()
    if not net:
        raise HTTPException(404, detail="VLAN not found")
    _verify_site_grant(_user, net.site_id, detail="VLAN not found")
    return VlanOut(
        id=str(net.id),
        vlan_id=net.vlan_id,
        name=net.name,
        description=net.description,
        site_id=str(net.site_id) if net.site_id else None,
        dhcp_enabled=net.dhcp_enabled,
        dhcp_start=net.dhcp_start,
        dhcp_end=net.dhcp_end,
        gateway=net.gateway,
        subnet_mask=net.subnet_mask,
    )


@router.post("/vlans", response_model=VlanOut, status_code=201)
async def create_vlan(
    data: VlanCreate,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> dict[str, Any]:
    """Create a VLAN. If a controller is associated, push to the controller too."""
    org_id = _org_id(_user)
    if data.site_id:
        site_check = await session.execute(
            select(Site.id).where(
                Site.id == data.site_id, Site.organization_id == org_id, Site.deleted_at.is_(None)
            )
        )
        if not site_check.scalar_one_or_none():
            raise HTTPException(403, detail="Site does not belong to your organization")
        _verify_site_grant(_user, data.site_id, detail="Site does not belong to your organization")
    net = Network(
        name=data.name,
        vlan_id=data.vlan_id,
        description=data.description,
        site_id=data.site_id,
        dhcp_enabled=data.dhcp_enabled,
        dhcp_start=data.dhcp_start,
        dhcp_end=data.dhcp_end,
        gateway=data.gateway,
        subnet_mask=data.subnet_mask,
    )
    session.add(net)
    await session.commit()
    await session.refresh(net)

    # Try pushing to controller if there's a site with a controller.
    # The helper returns a sync-status dict; a failed controller write is
    # surfaced in the response instead of being silently swallowed.
    sync = await _push_vlan_to_controller(session, net, action="create")

    return VlanOut(
        id=str(net.id),
        vlan_id=net.vlan_id,
        name=net.name,
        description=net.description,
        site_id=str(net.site_id) if net.site_id else None,
        dhcp_enabled=net.dhcp_enabled,
        dhcp_start=net.dhcp_start,
        dhcp_end=net.dhcp_end,
        gateway=net.gateway,
        subnet_mask=net.subnet_mask,
        **sync,
    )


@router.patch("/vlans/{vlan_id}", response_model=VlanOut)
async def update_vlan(
    vlan_id: str,
    data: VlanUpdate,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    result = await session.execute(
        select(Network).where(
            Network.id == vlan_id,
            Network.deleted_at.is_(None),
            Network.site_id.in_(_org_site_filter(org_id)),
        )
    )
    net = result.scalar_one_or_none()
    if not net:
        raise HTTPException(404, detail="VLAN not found")
    _verify_site_grant(_user, net.site_id, detail="VLAN not found")

    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(net, field, value)

    await session.commit()
    await session.refresh(net)

    # Push update to controller; surface any failure in the response.
    sync = await _push_vlan_to_controller(session, net, action="update")

    return VlanOut(
        id=str(net.id),
        vlan_id=net.vlan_id,
        name=net.name,
        description=net.description,
        site_id=str(net.site_id) if net.site_id else None,
        dhcp_enabled=net.dhcp_enabled,
        dhcp_start=net.dhcp_start,
        dhcp_end=net.dhcp_end,
        gateway=net.gateway,
        subnet_mask=net.subnet_mask,
        **sync,
    )


@router.delete("/vlans/{vlan_id}")
async def delete_vlan(
    vlan_id: str,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    result = await session.execute(
        select(Network).where(
            Network.id == vlan_id,
            Network.deleted_at.is_(None),
            Network.site_id.in_(_org_site_filter(org_id)),
        )
    )
    net = result.scalar_one_or_none()
    if not net:
        raise HTTPException(404, detail="VLAN not found")
    _verify_site_grant(_user, net.site_id, detail="VLAN not found")

    # Push delete to controller before soft-deleting locally so a
    # controller failure is captured and returned rather than swallowed.
    sync = await _push_vlan_to_controller(session, net, action="delete")

    from datetime import datetime

    net.deleted_at = datetime.now(UTC)
    await session.commit()
    return {"success": True, **sync}


async def _push_vlan_to_controller(
    session: AsyncSession, net: Network, action: str
) -> dict[str, Any]:
    """Push a VLAN change to the controller.

    Returns a dict with ``controller_synced`` (bool) and
    ``controller_warning`` (str | None).  When there is no controller
    configured the call is a no-op and ``controller_synced`` is True
    (nothing to sync).  On adapter failure the warning message is set so
    callers can surface it to the client without raising.
    """
    if not net.controller_id:
        return {"controller_synced": True, "controller_warning": None}
    try:
        ctrl_result = await session.execute(
            select(Controller).where(Controller.id == net.controller_id)
        )
        ctrl = ctrl_result.scalar_one_or_none()
        if not ctrl:
            return {"controller_synced": True, "controller_warning": None}

        adapter = await _get_adapter_for_controller(ctrl)
        result = None
        async with adapter:
            if action == "create":
                result = await adapter.create_vlan(
                    net.vlan_id, net.name, description=net.description
                )
            elif action == "update":
                result = await adapter.update_vlan(
                    net.external_id or str(net.vlan_id),
                    {
                        "name": net.name,
                        "description": net.description,
                    },
                )
            elif action == "delete":
                result = await adapter.delete_vlan(net.external_id or str(net.vlan_id))
        # CONV-001: Omada/base adapters return AdapterResult(success=False) WITHOUT
        # raising (controller rejection / read-only refusal), so inspect the result
        # — not just exceptions — before claiming controller_synced=True.
        if result is not None and not getattr(result, "success", True):
            warning = (
                getattr(result, "error", None)
                or getattr(result, "message", None)
                or f"controller rejected the VLAN {action}"
            )
            logger.warning("VLAN %s not synced to controller: %s", action, warning)
            return {"controller_synced": False, "controller_warning": warning}
        return {"controller_synced": True, "controller_warning": None}
    except Exception as e:
        warning = f"Local DB updated but controller write failed ({action}): {e}"
        logger.warning("Could not push VLAN %s to controller: %s", action, e)
        return {"controller_synced": False, "controller_warning": warning}


# =====================================================================
# WiFi / SSID routes
# =====================================================================


@router.get("/wifi", response_model=WifiListResponse)
async def list_wifi(
    site_id: str | None = Query(None),
    enabled: bool | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    q = select(WifiNetwork).where(
        WifiNetwork.deleted_at.is_(None),
        tenant_filter(WifiNetwork, _user),
    )
    if site_id:
        q = q.where(WifiNetwork.site_id == site_id)
    if enabled is not None:
        q = q.where(WifiNetwork.enabled == enabled)

    total_q = select(func.count()).select_from(q.subquery())
    total = (await session.execute(total_q)).scalar() or 0

    q = q.offset(skip).limit(limit).order_by(WifiNetwork.ssid)
    result = await session.execute(q)
    items = [_wifi_to_out(w) for w in result.scalars().all()]
    return WifiListResponse(items=items, total=total, skip=skip, limit=limit)


@router.get("/wifi/{wifi_id}", response_model=WifiNetworkOut)
async def get_wifi(
    wifi_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    result = await session.execute(
        select(WifiNetwork).where(
            WifiNetwork.id == wifi_id,
            WifiNetwork.deleted_at.is_(None),
            WifiNetwork.site_id.in_(_org_site_filter(org_id)),
        )
    )
    wifi = result.scalar_one_or_none()
    if not wifi:
        raise HTTPException(404, detail="WiFi network not found")
    _verify_site_grant(_user, wifi.site_id, detail="WiFi network not found")
    return _wifi_to_out(wifi)


@router.post("/wifi", response_model=WifiNetworkOut, status_code=201)
async def create_wifi(
    data: WifiNetworkCreate,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    if not data.site_id:
        raise HTTPException(422, detail="site_id is required")
    site_check = await session.execute(
        select(Site.id).where(
            Site.id == data.site_id, Site.organization_id == org_id, Site.deleted_at.is_(None)
        )
    )
    if not site_check.scalar_one_or_none():
        raise HTTPException(403, detail="Site does not belong to your organization")
    _verify_site_grant(_user, data.site_id, detail="Site does not belong to your organization")
    wifi = WifiNetwork(
        ssid=data.ssid,
        security=data.security,
        band=data.band,
        vlan_id=data.vlan_id,
        site_id=data.site_id,
        hidden=data.hidden,
        enabled=data.enabled,
        client_isolation=data.client_isolation,
        band_steering=data.band_steering,
        fast_roaming=data.fast_roaming,
        rate_limit_enabled=data.rate_limit_enabled,
        rate_limit_up=data.rate_limit_up,
        rate_limit_down=data.rate_limit_down,
    )
    session.add(wifi)
    await session.commit()
    await session.refresh(wifi)

    # Push to controller (honest sync envelope: local row is already committed)
    sync = await _push_wifi_to_controller(session, wifi, action="create", password=data.password)
    out = _wifi_to_out(wifi)
    out.controller_synced = sync["controller_synced"]
    out.controller_warning = sync["controller_warning"]
    return out


@router.patch("/wifi/{wifi_id}", response_model=WifiNetworkOut)
async def update_wifi(
    wifi_id: str,
    data: WifiNetworkUpdate,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    result = await session.execute(
        select(WifiNetwork).where(
            WifiNetwork.id == wifi_id,
            WifiNetwork.deleted_at.is_(None),
            WifiNetwork.site_id.in_(_org_site_filter(org_id)),
        )
    )
    wifi = result.scalar_one_or_none()
    if not wifi:
        raise HTTPException(404, detail="WiFi network not found")
    _verify_site_grant(_user, wifi.site_id, detail="WiFi network not found")

    update_data = data.model_dump(exclude_unset=True)
    password = update_data.pop("password", None)
    for field, value in update_data.items():
        setattr(wifi, field, value)

    await session.commit()
    await session.refresh(wifi)

    sync = await _push_wifi_to_controller(session, wifi, action="update", password=password)
    out = _wifi_to_out(wifi)
    out.controller_synced = sync["controller_synced"]
    out.controller_warning = sync["controller_warning"]
    return out


@router.delete("/wifi/{wifi_id}")
async def delete_wifi(
    wifi_id: str,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    result = await session.execute(
        select(WifiNetwork).where(
            WifiNetwork.id == wifi_id,
            WifiNetwork.deleted_at.is_(None),
            WifiNetwork.site_id.in_(_org_site_filter(org_id)),
        )
    )
    wifi = result.scalar_one_or_none()
    if not wifi:
        raise HTTPException(404, detail="WiFi network not found")
    _verify_site_grant(_user, wifi.site_id, detail="WiFi network not found")

    sync = await _push_wifi_to_controller(session, wifi, action="delete")

    from datetime import datetime

    wifi.deleted_at = datetime.now(UTC)
    await session.commit()
    # Surface controller_synced=False when the live SSID delete failed, so the
    # caller knows the SSID may still be live on the controller (orphan) even
    # though the local row is soft-deleted.
    return {"success": True, **sync}


@router.post("/wifi/{wifi_id}/toggle", response_model=WifiNetworkOut)
async def toggle_wifi(
    wifi_id: str,
    data: WifiToggleIn,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    result = await session.execute(
        select(WifiNetwork).where(
            WifiNetwork.id == wifi_id,
            WifiNetwork.deleted_at.is_(None),
            WifiNetwork.site_id.in_(_org_site_filter(org_id)),
        )
    )
    wifi = result.scalar_one_or_none()
    if not wifi:
        raise HTTPException(404, detail="WiFi network not found")
    _verify_site_grant(_user, wifi.site_id, detail="WiFi network not found")

    # Push the toggle to the controller BEFORE committing locally so that
    # a controller failure is surfaced rather than silently swallowed with
    # local state already diverged.
    ctrl_synced = True
    ctrl_warning: str | None = None
    if wifi.controller_id and wifi.external_id:
        try:
            ctrl_result = await session.execute(
                select(Controller).where(Controller.id == wifi.controller_id)
            )
            ctrl = ctrl_result.scalar_one_or_none()
            if ctrl:
                adapter = await _get_adapter_for_controller(ctrl)
                async with adapter:
                    toggle_result = await adapter.toggle_ssid(wifi.external_id, data.enabled)
                # CONV-001: AdapterResult(success=False) is returned non-throwing.
                if toggle_result is not None and not getattr(toggle_result, "success", True):
                    ctrl_synced = False
                    ctrl_warning = (
                        getattr(toggle_result, "error", None)
                        or getattr(toggle_result, "message", None)
                        or "controller rejected the SSID toggle"
                    )
                    logger.warning("SSID toggle not synced to controller: %s", ctrl_warning)
        except Exception as e:
            ctrl_synced = False
            ctrl_warning = f"Local DB updated but controller toggle failed: {e}"
            logger.warning("Could not toggle SSID on controller: %s", e)

    wifi.enabled = data.enabled
    await session.commit()
    await session.refresh(wifi)

    out = _wifi_to_out(wifi)
    out.controller_synced = ctrl_synced
    out.controller_warning = ctrl_warning
    return out


def _wifi_to_out(w: WifiNetwork) -> WifiNetworkOut:
    meta = w.wifi_metadata or {}
    return WifiNetworkOut(
        id=str(w.id),
        ssid=w.ssid,
        security=w.security,
        vlan_id=w.vlan_id,
        site_id=str(w.site_id) if w.site_id else None,
        hidden=w.hidden,
        enabled=w.enabled,
        band=w.band,
        client_isolation=w.client_isolation,
        band_steering=w.band_steering,
        fast_roaming=w.fast_roaming,
        rate_limit_enabled=w.rate_limit_enabled,
        rate_limit_up=w.rate_limit_up,
        rate_limit_down=w.rate_limit_down,
        guest_network=bool(meta.get("guest_network", False)),
        wlan_group_name=meta.get("wlan_group_name"),
        wlan_group_id=meta.get("wlan_group_id"),
        external_id=w.external_id,
        controller_id=str(w.controller_id) if w.controller_id else None,
        schedule_enabled=bool(meta.get("schedule_enabled", False)),
        mac_filter_enabled=bool(meta.get("mac_filter_enabled", False)),
        portal_enabled=bool(meta.get("portal_enabled", False)),
    )


async def _push_wifi_to_controller(
    session: AsyncSession,
    wifi: WifiNetwork,
    action: str,
    password: str | None = None,
) -> dict[str, Any]:
    ctrl_id = wifi.controller_id
    # Resolve controller from site if not set directly
    if not ctrl_id and wifi.site_id:
        site_result = await session.execute(
            select(Controller)
            .join(Site, Controller.site_id == Site.id)
            .where(Site.id == wifi.site_id)
        )
        ctrl = site_result.scalar_one_or_none()
        if ctrl:
            ctrl_id = ctrl.id
            wifi.controller_id = ctrl_id
            await session.flush()
    if not ctrl_id:
        return {"controller_synced": True, "controller_warning": None}
    try:
        ctrl_result = await session.execute(select(Controller).where(Controller.id == ctrl_id))
        ctrl = ctrl_result.scalar_one_or_none()
        if not ctrl:
            return {"controller_synced": True, "controller_warning": None}

        adapter = await _get_adapter_for_controller(ctrl)
        wlan_group_id = (wifi.wifi_metadata or {}).get("wlan_group_id")
        result: Any = None
        async with adapter:
            if action == "create":
                config: dict[str, Any] = {
                    "name": wifi.ssid,
                    "security": _map_security_to_omada(wifi.security),
                    "band": _map_band_to_omada(wifi.band),
                    "broadcast": not wifi.hidden,
                }
                if wifi.vlan_id:
                    config["vlanEnable"] = True
                    config["vlanId"] = wifi.vlan_id
                if password:
                    config["pskSetting"] = {
                        "securityKey": password,
                    }
                if wlan_group_id:
                    config["wlan_group_id"] = wlan_group_id
                result = await adapter.create_ssid(config)
                # Store external_id from controller response
                if result.success and result.data and isinstance(result.data, dict):
                    wifi.external_id = result.data.get("id")
                    await session.flush()
            elif action == "update":
                config = {}
                if wifi.ssid:
                    config["name"] = wifi.ssid
                if password:
                    config["pskSetting"] = {"securityKey": password}
                config["broadcast"] = not wifi.hidden
                config["security"] = _map_security_to_omada(wifi.security)
                config["band"] = _map_band_to_omada(wifi.band)
                if wlan_group_id:
                    config["wlan_group_id"] = wlan_group_id
                result = await adapter.update_ssid(wifi.external_id or "", config)
            elif action == "delete":
                result = await adapter.delete_ssid(
                    wifi.external_id or "",
                    wlan_id=wlan_group_id,
                )
        # CONV-001: adapters return AdapterResult(success=False) WITHOUT raising;
        # surface a failed controller write (incl. failed create) honestly instead
        # of reporting controller_synced=True.
        if result is not None and not getattr(result, "success", True):
            warning = (
                getattr(result, "error", None)
                or getattr(result, "message", None)
                or f"controller rejected the WiFi {action}"
            )
            logger.warning("WiFi %s not synced to controller: %s", action, warning)
            return {"controller_synced": False, "controller_warning": warning}
        return {"controller_synced": True, "controller_warning": None}
    except Exception as e:
        # Mirror _push_vlan_to_controller: the local DB row is already committed,
        # so surface the controller failure honestly (controller_synced=False)
        # instead of silently swallowing it and reporting an unqualified success.
        warning = f"Local DB updated but controller write failed ({action}): {e}"
        logger.warning("Could not push WiFi %s to controller: %s", action, e)
        return {"controller_synced": False, "controller_warning": warning}


def _map_security_to_omada(security: str) -> int:
    """Map FreeSDN security string → Omada security enum."""
    _map = {
        "open": 0,
        "wep": 1,
        "wpa_wpa2_personal": 3,
        "wpa2_personal": 3,
        "wpa2_wpa3_personal": 3,
        "wpa3_personal": 3,
        "wpa2_enterprise": 4,
        "wpa3_enterprise": 4,
    }
    return _map.get(security, 3)


def _map_band_to_omada(band: str) -> int:
    """Map FreeSDN band string → Omada band enum."""
    _map = {
        "2.4ghz": 1,
        "5ghz": 2,
        "both": 3,
        "all": 7,
        "6ghz": 7,
    }
    return _map.get(band, 3)


# =====================================================================
# Client routes
# =====================================================================


@router.get("/clients", response_model=NetworkClientListResponse)
async def list_clients(
    site_id: str | None = Query(None, max_length=64),
    connection_type: str | None = Query(None, max_length=16),
    status: str | None = Query(None, max_length=16),
    blocked: bool | None = Query(None),
    search: str | None = Query(None, max_length=256),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    dev_q = select(Device.id).where(
        tenant_filter(Device, _user),
    )
    # the ``site_id`` query param was declared but never used,
    # so the global site selector had no effect — the list always returned the
    # whole org's clients. Narrow to the selected site when supplied (an
    # out-of-org site UUID is still excluded by the org subquery above).
    if site_id:
        try:
            dev_q = dev_q.where(Device.site_id == UUID(site_id))
        except (ValueError, TypeError):
            pass
    org_devices = dev_q.scalar_subquery()
    q = select(DeviceClient).where(DeviceClient.device_id.in_(org_devices))
    if search:
        escaped_search = escape_like(search)
        q = q.where(
            DeviceClient.hostname.ilike(f"%{escaped_search}%", escape="\\")
            | DeviceClient.mac_address.ilike(f"%{escaped_search}%", escape="\\")
            | DeviceClient.ip_address.ilike(f"%{escaped_search}%", escape="\\")
        )
    if status == "online":
        q = q.where(DeviceClient.is_online.is_(True))
    elif status == "offline":
        q = q.where(DeviceClient.is_online.is_(False))
    if connection_type == "wireless":
        q = q.where(DeviceClient.ssid.isnot(None))
    elif connection_type == "wired":
        q = q.where(DeviceClient.ssid.is_(None))

    total_q = select(func.count()).select_from(q.subquery())
    total = (await session.execute(total_q)).scalar() or 0

    q = q.offset(skip).limit(limit).order_by(DeviceClient.last_seen.desc())
    result = await session.execute(q)
    items = [
        NetworkClientOut(
            id=str(c.id),
            mac_address=c.mac_address,
            ip_address=c.ip_address,
            hostname=c.hostname,
            display_name=c.hostname,
            connection_type="wireless" if c.ssid else "wired",
            status="online" if c.is_online else "offline",
            blocked=bool((c.client_metadata or {}).get("blocked")),
            connected_device_id=str(c.device_id),
            ssid=c.ssid,
            signal_strength=c.signal_dbm,
            rx_bytes=c.rx_bytes or 0,
            tx_bytes=c.tx_bytes or 0,
            first_seen=c.connected_at.isoformat() if c.connected_at else None,
            last_seen=c.last_seen.isoformat() if c.last_seen else None,
        )
        for c in result.scalars().all()
    ]
    return NetworkClientListResponse(items=items, total=total, skip=skip, limit=limit)


@router.get("/clients/{client_id}", response_model=NetworkClientOut)
async def get_client(
    client_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    org_devices = (
        select(Device.id)
        .where(
            tenant_filter(Device, _user),
        )
        .scalar_subquery()
    )
    result = await session.execute(
        select(DeviceClient).where(
            DeviceClient.id == client_id,
            DeviceClient.device_id.in_(org_devices),
        )
    )
    c = result.scalar_one_or_none()
    if not c:
        raise HTTPException(404, detail="Client not found")
    return NetworkClientOut(
        id=str(c.id),
        mac_address=c.mac_address,
        ip_address=c.ip_address,
        hostname=c.hostname,
        display_name=c.hostname,
        connection_type="wireless" if c.ssid else "wired",
        status="online" if c.is_online else "offline",
        blocked=bool((c.client_metadata or {}).get("blocked")),
        connected_device_id=str(c.device_id),
        ssid=c.ssid,
        signal_strength=c.signal_dbm,
        rx_bytes=c.rx_bytes or 0,
        tx_bytes=c.tx_bytes or 0,
        first_seen=c.connected_at.isoformat() if c.connected_at else None,
        last_seen=c.last_seen.isoformat() if c.last_seen else None,
    )


@router.post("/clients/{client_id}/block")
async def block_client(
    client_id: str,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("device:update")),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    org_devices = (
        select(Device.id).where(Device.site_id.in_(_org_site_filter(org_id))).scalar_subquery()
    )
    result = await session.execute(
        select(DeviceClient)
        .options(selectinload(DeviceClient.device))
        .where(
            DeviceClient.id == client_id,
            DeviceClient.device_id.in_(org_devices),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, detail="Client not found")
    _verify_site_grant(
        _user,
        client.device.site_id if client.device else None,
        detail="Client not found",
    )

    # Push to controller
    device = client.device
    block_result = None
    if device and device.controller_id:
        ctrl_result = await session.execute(
            select(Controller).where(Controller.id == device.controller_id)
        )
        ctrl = ctrl_result.scalar_one_or_none()
        if ctrl:
            try:
                adapter = await _get_adapter_for_controller(ctrl)
                async with adapter:
                    block_result = await adapter.block_client(client.mac_address)
            except Exception as e:
                # block is an ENFORCEMENT action: if the controller write was
                # attempted and failed, do NOT record a false "blocked" state or
                # report success — the client would stay reachable on the live
                # network while the UI claimed it was blocked. Surface the failure.
                logger.warning("Could not block client on controller: %s", e)
                raise HTTPException(
                    status_code=502,
                    detail="Could not block client on the controller; the client was NOT blocked",
                ) from e
    # CONV2-001: adapters also return AdapterResult(success=False) WITHOUT raising;
    # surface that before recording the blocked state (no-op when result is None).
    raise_for_adapter_result(block_result)

    meta = client.client_metadata or {}
    meta["blocked"] = True
    client.client_metadata = meta
    await session.commit()
    return {"success": True}


@router.post("/clients/{client_id}/unblock")
async def unblock_client(
    client_id: str,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("device:update")),
) -> dict[str, Any]:
    org_id = _org_id(_user)
    org_devices = (
        select(Device.id).where(Device.site_id.in_(_org_site_filter(org_id))).scalar_subquery()
    )
    result = await session.execute(
        select(DeviceClient)
        .options(selectinload(DeviceClient.device))
        .where(
            DeviceClient.id == client_id,
            DeviceClient.device_id.in_(org_devices),
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, detail="Client not found")
    _verify_site_grant(
        _user,
        client.device.site_id if client.device else None,
        detail="Client not found",
    )

    device = client.device
    unblock_result = None
    if device and device.controller_id:
        ctrl_result = await session.execute(
            select(Controller).where(Controller.id == device.controller_id)
        )
        ctrl = ctrl_result.scalar_one_or_none()
        if ctrl:
            try:
                adapter = await _get_adapter_for_controller(ctrl)
                async with adapter:
                    unblock_result = await adapter.unblock_client(client.mac_address)
            except Exception as e:
                # Symmetric to block: if the controller write was attempted and
                # failed, don't clear the "blocked" state or report success — the
                # client would stay blocked on the live network while the UI said
                # otherwise.
                logger.warning("Could not unblock client on controller: %s", e)
                raise HTTPException(
                    status_code=502,
                    detail="Could not unblock client on the controller; the client is still blocked",
                ) from e
    # CONV2-001: surface a non-throwing AdapterResult(success=False) too.
    raise_for_adapter_result(unblock_result)

    meta = client.client_metadata or {}
    meta["blocked"] = False
    client.client_metadata = meta
    await session.commit()
    return {"success": True}


# =====================================================================
# Network Devices
# =====================================================================


@router.get("/devices", response_model=NetworkDeviceListResponse)
async def list_network_devices(
    site_id: str | None = Query(None),
    device_type: str | None = Query(None),
    status: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    network_types = [
        DeviceType.SWITCH,
        DeviceType.ROUTER,
        DeviceType.ACCESS_POINT,
        DeviceType.GATEWAY,
        DeviceType.FIREWALL,
    ]
    q = select(Device).where(
        Device.device_type.in_(network_types),
        Device.deleted_at.is_(None),
        tenant_filter(Device, _user),
    )
    if site_id:
        q = q.where(Device.site_id == site_id)
    if device_type:
        q = q.where(Device.device_type == device_type)
    if status:
        q = q.where(Device.status == status)

    total_q = select(func.count()).select_from(q.subquery())
    total = (await session.execute(total_q)).scalar() or 0

    q = q.offset(skip).limit(limit).order_by(Device.name)
    result = await session.execute(q)
    items = [
        NetworkDeviceOut(
            id=str(d.id),
            name=d.name,
            device_type=d.device_type,
            model=d.model,
            vendor=d.manufacturer,
            firmware_version=d.firmware_version,
            ip_address=d.ip_address,
            mac_address=d.mac_address,
            status=d.status or "unknown",
            uptime=d.uptime_seconds,
            site_id=str(d.site_id) if d.site_id else None,
            capabilities=d.capabilities,
        )
        for d in result.scalars().all()
    ]
    return NetworkDeviceListResponse(items=items, total=total, skip=skip, limit=limit)


# =====================================================================
# Switch Ports (under /network/devices/{id}/ports)
# =====================================================================


@router.get("/devices/{device_id}/ports", response_model=list[SwitchPortConfigOut])
async def list_device_ports(
    device_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    # Verify the device belongs to the user's organization
    dev_check = await session.execute(
        select(Device.id).where(
            Device.id == device_id,
            tenant_filter(Device, _user),
        )
    )
    if not dev_check.scalar_one_or_none():
        raise HTTPException(404, detail="Device not found")
    result = await session.execute(
        select(DevicePort).where(DevicePort.device_id == device_id).order_by(DevicePort.port_number)
    )
    ports = result.scalars().all()
    return [
        SwitchPortConfigOut(
            id=str(p.id),
            device_id=str(p.device_id),
            port_number=p.port_number,
            name=p.name,
            enabled=p.is_enabled,
            poe_enabled=p.is_poe_enabled,
            native_vlan=p.vlan_id or 1,
            tagged_vlans=(p.port_metadata or {}).get("tagged_vlans")
            or (p.port_metadata or {}).get("taggedVlans")
            or [],
            status=p.status or "unknown",
            speed=f"{p.speed_mbps}Mbps" if p.speed_mbps else None,
            duplex=p.duplex,
            poe_power_draw=p.poe_power_watts,
            rx_bytes=p.rx_bytes or 0,
            tx_bytes=p.tx_bytes or 0,
        )
        for p in ports
    ]


@router.patch("/devices/{device_id}/ports/{port_number}", response_model=SwitchPortConfigOut)
async def update_device_port(
    device_id: str,
    port_number: int,
    data: SwitchPortUpdate,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("device:update")),
) -> dict[str, Any]:
    # Verify the device belongs to the user's organization
    dev_check = await session.execute(
        select(Device.id).where(
            Device.id == device_id,
            tenant_filter(Device, _user),
        )
    )
    if not dev_check.scalar_one_or_none():
        raise HTTPException(404, detail="Device not found")
    result = await session.execute(
        select(DevicePort).where(
            DevicePort.device_id == device_id,
            DevicePort.port_number == port_number,
        )
    )
    port = result.scalar_one_or_none()
    if not port:
        raise HTTPException(404, detail="Port not found")

    if data.name is not None:
        port.name = data.name
    if data.enabled is not None:
        port.is_enabled = data.enabled
    if data.poe_enabled is not None:
        port.is_poe_enabled = data.poe_enabled
    if data.native_vlan is not None:
        port.vlan_id = data.native_vlan

    await session.commit()
    await session.refresh(port)
    return SwitchPortConfigOut(
        id=str(port.id),
        device_id=str(port.device_id),
        port_number=port.port_number,
        name=port.name,
        enabled=port.is_enabled,
        poe_enabled=port.is_poe_enabled,
        native_vlan=port.vlan_id or 1,
        tagged_vlans=(port.port_metadata or {}).get("tagged_vlans", []),
        status=port.status or "unknown",
        speed=f"{port.speed_mbps}Mbps" if port.speed_mbps else None,
        duplex=port.duplex,
        poe_power_draw=port.poe_power_watts,
        rx_bytes=port.rx_bytes or 0,
        tx_bytes=port.tx_bytes or 0,
    )


@router.post("/devices/{device_id}/ports/{port_number}/poe")
async def set_device_port_poe(
    device_id: str,
    port_number: int,
    data: WifiToggleIn,  # reuse enabled field
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("device:update")),
) -> dict[str, Any]:
    dev_check = await session.execute(
        select(Device.id).where(
            Device.id == device_id,
            tenant_filter(Device, _user),
        )
    )
    if not dev_check.scalar_one_or_none():
        raise HTTPException(404, detail="Device not found")
    result = await session.execute(
        select(DevicePort).where(
            DevicePort.device_id == device_id,
            DevicePort.port_number == port_number,
        )
    )
    port = result.scalar_one_or_none()
    if not port:
        raise HTTPException(404, detail="Port not found")

    port.is_poe_enabled = data.enabled
    await session.commit()
    return {"success": True, "enabled": data.enabled}


@router.post("/devices/{device_id}/ports/{port_number}/vlan")
async def set_device_port_vlan(
    device_id: str,
    port_number: int,
    data: PortVlanIn,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> dict[str, Any]:
    dev_check = await session.execute(
        select(Device.id).where(
            Device.id == device_id,
            tenant_filter(Device, _user),
        )
    )
    if not dev_check.scalar_one_or_none():
        raise HTTPException(404, detail="Device not found")
    result = await session.execute(
        select(DevicePort).where(
            DevicePort.device_id == device_id,
            DevicePort.port_number == port_number,
        )
    )
    port = result.scalar_one_or_none()
    if not port:
        raise HTTPException(404, detail="Port not found")

    if data.native_vlan is not None:
        port.vlan_id = data.native_vlan
    if data.tagged_vlans is not None:
        meta = dict(port.port_metadata or {})
        meta["tagged_vlans"] = data.tagged_vlans
        port.port_metadata = meta
    await session.commit()
    return {"success": True}


# =====================================================================
# Topology
# =====================================================================


@router.get("/topology", response_model=NetworkTopologyOut)
async def get_topology(
    site_id: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    # Get all network devices
    network_types = [
        DeviceType.SWITCH,
        DeviceType.ROUTER,
        DeviceType.ACCESS_POINT,
        DeviceType.GATEWAY,
        DeviceType.FIREWALL,
    ]
    q = select(Device).where(
        Device.device_type.in_(network_types),
        Device.deleted_at.is_(None),
        tenant_filter(Device, _user),
    )
    if site_id:
        q = q.where(Device.site_id == site_id)
    result = await session.execute(q)
    devices = result.scalars().all()
    device_ids = [d.id for d in devices]

    nodes = [
        TopologyNodeOut(
            id=str(d.id),
            name=d.name,
            device_type=d.device_type,
            ip_address=d.ip_address,
            status=d.status or "unknown",
            model=d.model,
            vendor=d.manufacturer,
        )
        for d in devices
    ]

    # Get links
    links_result = await session.execute(
        select(TopologyLink).where(
            TopologyLink.source_device_id.in_(device_ids)
            | TopologyLink.target_device_id.in_(device_ids)
        )
    )
    topo_links = links_result.scalars().all()
    links = [
        TopologyLinkOut(
            source=str(l.source_device_id),
            target=str(l.target_device_id),
            source_port=l.source_port,
            target_port=l.target_port,
            speed=l.speed,
            status=l.status,
        )
        for l in topo_links
    ]

    return NetworkTopologyOut(nodes=nodes, links=links)


# =====================================================================
# Network Summary
# =====================================================================


@router.get("/summary", response_model=NetworkSummaryOut)
async def get_network_summary(
    site_id: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    # Device counts
    device_q = select(Device).where(
        Device.deleted_at.is_(None),
        tenant_filter(Device, _user),
    )
    if site_id:
        device_q = device_q.where(Device.site_id == site_id)
    device_result = await session.execute(device_q)
    all_devices = device_result.scalars().all()

    by_type: dict[str, int] = {}
    online = 0
    offline = 0
    for d in all_devices:
        by_type[d.device_type] = by_type.get(d.device_type, 0) + 1
        if d.status == DeviceStatus.ONLINE:
            online += 1
        elif d.status == DeviceStatus.OFFLINE:
            offline += 1

    # Client counts
    org_devices = (
        select(Device.id)
        .where(
            tenant_filter(Device, _user),
        )
        .scalar_subquery()
    )
    client_q = select(DeviceClient).where(DeviceClient.device_id.in_(org_devices))
    client_result = await session.execute(client_q)
    clients = client_result.scalars().all()
    online_clients = sum(1 for c in clients if c.is_online)
    wired = sum(1 for c in clients if not c.ssid)
    wireless = sum(1 for c in clients if c.ssid)
    blocked = sum(1 for c in clients if (c.client_metadata or {}).get("blocked"))

    # VLAN count
    vlan_q = (
        select(func.count())
        .select_from(Network)
        .where(
            Network.deleted_at.is_(None),
            tenant_filter(Network, _user),
        )
    )
    if site_id:
        vlan_q = vlan_q.where(Network.site_id == site_id)
    total_vlans = (await session.execute(vlan_q)).scalar() or 0

    # WiFi count
    wifi_q = (
        select(func.count())
        .select_from(WifiNetwork)
        .where(
            WifiNetwork.deleted_at.is_(None),
            tenant_filter(WifiNetwork, _user),
        )
    )
    if site_id:
        wifi_q = wifi_q.where(WifiNetwork.site_id == site_id)
    total_wifi = (await session.execute(wifi_q)).scalar() or 0

    return NetworkSummaryOut(
        devices=DeviceSummary(
            total=len(all_devices),
            online=online,
            offline=offline,
            by_type=by_type,
        ),
        clients=ClientSummary(
            total=len(clients),
            online=online_clients,
            wired=wired,
            wireless=wireless,
            blocked=blocked,
        ),
        total_vlans=total_vlans,
        total_wifi_networks=total_wifi,
    )
