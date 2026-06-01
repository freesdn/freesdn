# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Switch Management API
====================================

Full switch control: port listing, port configuration, PoE, STP,
speed/duplex, LAG groups, port profiles, and bulk operations.

Frontend expects these routes under ``/switches/``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import UTC
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.adapter_result import raise_for_adapter_result
from app.core.crypto import decrypt_credential, is_encrypted
from app.core.dependencies import (
    CurrentUser,
    require_permissions,
)
from app.core.security_utils import escape_like
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models.core import Site
from app.models.devices import (
    Device,
    DeviceClient,
    DevicePort,
    DeviceType,
    PortStatus,
)
from app.modules.network.models import LinkAggregationGroup, Network, PortProfile
from app.services.adapter_factory import get_adapter

logger = logging.getLogger(__name__)
router = APIRouter()


# =====================================================================
# Pydantic schemas
# =====================================================================


class SwitchSummaryOut(BaseModel):
    id: str
    name: str
    model: str | None = None
    model_version: str | None = None
    vendor: str | None = None
    serial_number: str | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    ipv6_address: str | None = None
    controller_connection_ip: str | None = None
    site_id: str | None = None
    site_name: str | None = None
    total_ports: int = 0
    poe_ports: int = 0
    sfp_ports: int = 0
    status: str = "unknown"
    uptime: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    temperature: float | None = None
    fan_status: str | None = None
    ports_up: int = 0
    ports_down: int = 0
    ports_disabled: int = 0
    poe_budget: float = 0.0
    poe_used: float = 0.0
    firmware_version: str | None = None
    hardware_version: str | None = None
    update_available: bool = False
    vlans_configured: int = 0
    connected_clients: int = 0


class AdapterActionResponse(BaseModel):
    """Shared response shape for adapter passthrough action endpoints.

    Used by every action that fires a write at the controller and
    returns a small ack-shaped dict (toggle port, PoE control, port
    profile apply, LAG CRUD, etc.). The shape mirrors the
    ``AdapterResult`` dataclass returned by the adapter layer:

    - ``success``: True when the adapter accepted the write
    - ``message``: human-readable description (e.g. ``"PoE enabled"``)
    - ``data``: free-form passthrough from the adapter for the
      specific operation (keys vary by vendor and operation)
    - ``error``: present only when ``success=False`` — vendor error text

    This is INTENTIONALLY a thin envelope. We don't try to lock down
    the vendor-specific ``data`` keys here because each adapter
    returns different fields per operation, and forcing a schema
    would force every vendor to a lowest-common-denominator dict.
    The envelope gives the OpenAPI generator (and TypeScript
    consumers) something to bind against while keeping the
    per-vendor flexibility we need.
    """

    success: bool = True
    message: str | None = None
    data: dict[str, Any] | None = None
    error: str | None = None


class VlanConfig(BaseModel):
    mode: str = "access"
    native_vlan: int = Field(default=1, ge=1, le=4094)
    tagged_vlans: list[int] = Field(default_factory=list)
    voice_vlan: int | None = Field(default=None, ge=1, le=4094)
    guest_vlan: int | None = Field(default=None, ge=1, le=4094)


class PoeConfig(BaseModel):
    enabled: bool = False
    mode: Literal["auto", "manual", "fixed"] = "auto"
    power_limit: float | None = Field(default=None, ge=0.0, le=95.0)
    priority: int = Field(default=0, ge=0, le=7)


class StpConfig(BaseModel):
    enabled: bool = True
    mode: Literal["rstp", "stp", "mstp"] = "rstp"
    guard: str | None = None
    bpdu_filter: bool = False
    bpdu_guard: bool = False


class SecurityConfig(BaseModel):
    enabled: bool = False
    mac_limit: int | None = Field(default=None, ge=1, le=4092)
    violation_action: Literal["restrict", "shutdown", "drop"] = "restrict"
    dot1x_enabled: bool = False
    dot1x_mode: Literal["auto", "force_auth", "force_unauth", "disable"] = "auto"


class PortStatusOut(BaseModel):
    link_status: str = "down"
    link_speed: int | None = None
    link_duplex: str | None = None
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_packets: int = 0
    rx_packets: int = 0
    tx_errors: int = 0
    rx_errors: int = 0
    tx_utilization: float = 0.0
    rx_utilization: float = 0.0
    poe_status: str | None = None
    poe_power_draw: float | None = None
    poe_class: int | None = None
    stp_state: str | None = None
    stp_role: str | None = None
    neighbor_device: str | None = None
    neighbor_port: str | None = None
    neighbor_ip: str | None = None
    sfp_vendor: str | None = None
    sfp_part_number: str | None = None
    sfp_serial: str | None = None
    sfp_type: str | None = None
    sfp_temperature: float | None = None
    sfp_tx_power: float | None = None
    sfp_rx_power: float | None = None
    sfp_wavelength: int | None = None


class SwitchPortOut(BaseModel):
    id: str
    device_id: str
    port_index: int
    port_type: str = "ethernet"
    name: str = ""
    description: str | None = None
    enabled: bool = True
    speed: str | None = None
    duplex: str | None = None
    auto_negotiation: bool = True
    mtu: int = 1500
    flow_control: bool = False
    vlan_config: VlanConfig | None = None
    poe_config: PoeConfig | None = None
    stp_config: StpConfig | None = None
    security_config: SecurityConfig | None = None
    status: PortStatusOut = Field(default_factory=PortStatusOut)
    last_status_change: str | None = None


class SwitchPortProfileOut(BaseModel):
    id: str
    name: str
    description: str | None = None
    profile_type: str = "custom"
    site_id: str | None = None
    controller_id: str | None = None
    native_vlan: int | None = None
    tagged_vlans: list[int] | None = None
    voice_vlan: int | None = None
    poe_enabled: bool | None = None
    stp_enabled: bool | None = None
    ports_using: int = 0
    created_at: str | None = None
    updated_at: str | None = None


class SwitchPortProfileCreate(BaseModel):
    """Create body for a DB-backed switch port profile."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    profile_type: str = Field("custom", max_length=50)
    site_id: str | None = None
    controller_id: str | None = None
    native_vlan: int | None = Field(None, ge=1, le=4094)
    tagged_vlans: list[int] | None = None
    voice_vlan: int | None = Field(None, ge=1, le=4094)
    poe_enabled: bool | None = None
    stp_enabled: bool | None = None

    @field_validator("tagged_vlans")
    @classmethod
    def _validate_tagged(cls, v: list[int] | None) -> list[int] | None:
        if v is None:
            return v
        for vid in v:
            if vid < 1 or vid > 4094:
                raise ValueError("tagged_vlans entries must be 1-4094")
        return v


class SwitchPortProfileUpdate(BaseModel):
    """Partial update body for a switch port profile."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    profile_type: str | None = Field(None, max_length=50)
    site_id: str | None = None
    controller_id: str | None = None
    native_vlan: int | None = Field(None, ge=1, le=4094)
    tagged_vlans: list[int] | None = None
    voice_vlan: int | None = Field(None, ge=1, le=4094)
    poe_enabled: bool | None = None
    stp_enabled: bool | None = None

    @field_validator("tagged_vlans")
    @classmethod
    def _validate_tagged(cls, v: list[int] | None) -> list[int] | None:
        if v is None:
            return v
        for vid in v:
            if vid < 1 or vid > 4094:
                raise ValueError("tagged_vlans entries must be 1-4094")
        return v


class SwitchLAGOut(BaseModel):
    id: str
    device_id: str
    name: str
    lag_id: int
    mode: str = "lacp"
    member_ports: list[int] = Field(default_factory=list)
    lacp_mode: str = "active"
    lacp_timeout: str = "long"
    status: str = "up"
    active_ports: int = 0
    aggregate_speed: int = 0


class LAGCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    mode: str = Field(default="lacp", pattern=r"^(lacp|static)$")
    # (sibling): cap the member list for input hygiene/parity.
    member_ports: list[int] = Field(..., min_length=1, max_length=500)
    lacp_mode: str = Field(default="active", pattern=r"^(active|passive)$")
    lacp_timeout: str = Field(default="long", pattern=r"^(long|short)$")


class LAGUpdateIn(BaseModel):
    name: str | None = Field(default=None, max_length=64)
    mode: str | None = Field(default=None, pattern=r"^(lacp|static)$")
    member_ports: list[int] | None = Field(default=None, max_length=500)
    lacp_mode: str | None = Field(default=None, pattern=r"^(active|passive)$")
    lacp_timeout: str | None = Field(default=None, pattern=r"^(long|short)$")


class VlanPortAssignment(BaseModel):
    port_index: int = Field(..., ge=0, le=127)
    native_vlan: int | None = Field(default=None, ge=1, le=4094)
    tagged_vlans: list[int] = Field(default_factory=list)


class BulkVlanAssignmentIn(BaseModel):
    # (sibling): this list fans out one live controller PATCH per
    # assignment (see bulk_assign_vlans), so bound it like the cli-profile batch.
    assignments: list[VlanPortAssignment] = Field(..., min_length=1, max_length=500)


class PortUpdateIn(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    speed: str | None = None
    duplex: str | None = None
    mtu: int | None = Field(default=None, ge=576, le=9216)
    flow_control: bool | None = None
    vlan_config: VlanConfig | None = None
    poe_config: PoeConfig | None = None
    stp_config: StpConfig | None = None
    security_config: SecurityConfig | None = None


class BulkPortUpdateIn(BaseModel):
    port_ids: list[str]
    updates: PortUpdateIn


class ApplyProfileIn(BaseModel):
    profile_id: str
    port_ids: list[str]


class ToggleIn(BaseModel):
    enabled: bool


# =====================================================================
# Helpers
# =====================================================================


def _org_id(user: CurrentUser) -> UUID:
    """Extract organization_id, raising 400 if missing."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _org_site_filter(organization_id: UUID) -> Any:
    """Subquery of site IDs for the given organization."""
    return (
        select(Site.id)
        .where(Site.organization_id == organization_id, Site.deleted_at.is_(None))
        .scalar_subquery()
    )


def _port_to_out(port: DevicePort) -> SwitchPortOut:
    """Convert a DevicePort ORM record to the SwitchPortOut shape."""
    meta = port.port_metadata or {}

    # Build VLAN config from metadata
    vlan_config = None
    native = port.vlan_id or meta.get("pvid") or meta.get("native_vlan") or 1
    tagged = meta.get("tagged_vlans") or meta.get("taggedVlans") or []
    if isinstance(tagged, list):
        vlan_config = VlanConfig(
            mode=meta.get("vlan_mode") or ("trunk" if tagged else "access"),
            native_vlan=native,
            tagged_vlans=tagged,
            voice_vlan=meta.get("voice_vlan_id") or meta.get("voiceVlan"),
        )

    # PoE config
    poe_config = None
    if port.is_poe_enabled or meta.get("poe_supported") or meta.get("poeSupported"):
        poe_config = PoeConfig(
            enabled=port.is_poe_enabled,
            mode=meta.get("poe_mode") or meta.get("poeMode") or "auto",
            power_limit=meta.get("poe_max_power") or meta.get("poePowerLimit"),
            priority=meta.get("poePriority", 0),
        )

    # STP config
    stp_config = None
    if meta.get("stp_enabled") is not None or meta.get("stpEnabled") is not None:
        stp_config = StpConfig(
            enabled=meta.get("stp_enabled")
            if meta.get("stp_enabled") is not None
            else meta.get("stpEnabled", True),
            mode=meta.get("stpMode") or "rstp",
            guard=meta.get("stpGuard"),
            bpdu_filter=meta.get("bpduFilter", False),
            bpdu_guard=meta.get("bpduGuard", False),
        )

    return SwitchPortOut(
        id=str(port.id),
        device_id=str(port.device_id),
        port_index=port.port_number,
        port_type=port.port_type or "ethernet",
        name=port.name or f"Port {port.port_number}",
        description=meta.get("description"),
        enabled=port.is_enabled,
        speed=f"{port.speed_mbps}Mbps"
        if port.speed_mbps
        else str(meta.get("speed", "auto"))
        if meta.get("speed") is not None
        else None,
        duplex=str(port.duplex) if port.duplex else None,
        auto_negotiation=meta.get("autoNegotiation", True),
        mtu=meta.get("mtu", 1500),
        flow_control=meta.get("flow_control_enabled") or meta.get("flowControl") or False,
        vlan_config=vlan_config,
        poe_config=poe_config,
        stp_config=stp_config,
        status=PortStatusOut(
            link_status="up" if port.status == PortStatus.UP else "down",
            link_speed=port.speed_mbps,
            link_duplex=port.duplex,
            tx_bytes=port.tx_bytes or 0,
            rx_bytes=port.rx_bytes or 0,
            tx_packets=port.tx_packets or 0,
            rx_packets=port.rx_packets or 0,
            tx_errors=meta.get("txErrors", 0),
            rx_errors=meta.get("rxErrors", 0),
            poe_status="delivering"
            if port.is_poe_enabled and (port.poe_power_watts or meta.get("poe_power"))
            else ("enabled" if port.is_poe_enabled else None),
            poe_power_draw=port.poe_power_watts or meta.get("poe_power"),
            poe_class=port.poe_class,
            stp_state=meta.get("stpState"),
            stp_role=meta.get("stpRole"),
            neighbor_device=meta.get("lldpNeighborDevice") or port.connected_mac,
            neighbor_port=meta.get("lldpNeighborPort"),
            neighbor_ip=meta.get("lldpNeighborIp"),
            sfp_vendor=meta.get("sfp_vendor") or meta.get("sfpVendor"),
            sfp_part_number=meta.get("sfp_part_number") or meta.get("sfpPartNumber"),
            sfp_serial=meta.get("sfp_serial") or meta.get("sfpSerialNumber"),
            sfp_type=meta.get("sfp_type") or meta.get("sfpType"),
            sfp_temperature=meta.get("sfp_temperature") or meta.get("sfpTemperature"),
            sfp_tx_power=meta.get("sfp_tx_power") or meta.get("sfpTxPower"),
            sfp_rx_power=meta.get("sfp_rx_power") or meta.get("sfpRxPower"),
            sfp_wavelength=meta.get("sfp_wavelength") or meta.get("sfpWavelength"),
        ),
    )


# Upper bound on free-form passthrough config dicts forwarded verbatim to a
# live controller (STP/ACL/IGMP/mirror/QoS/DHCP-snooping/PoE-schedule/port-
# profile). These bodies are intentionally unschematized so each vendor adapter
# keeps its own keys, but an *unbounded* dict is a DoS vector (the whole body is
# relayed to the device). The caps below are generous — orders of magnitude
# above any real vendor config — so every legitimate operator request passes,
# while a pathologically large/deep payload is rejected with 422 instead of
# being streamed at the controller.
_MAX_CONFIG_KEYS = 200
_MAX_CONFIG_DEPTH = 8


def _validate_passthrough_config(config: Any, _depth: int = 0) -> dict[str, Any]:
    """Bound a free-form adapter config body before relaying it to a device.

    Caps total key count and nesting depth (recursively). Returns the dict
    unchanged when within bounds; raises ``HTTPException(422)`` otherwise.
    Does not constrain *which* keys/values are allowed — that stays per-vendor.
    """
    if _depth > _MAX_CONFIG_DEPTH:
        raise HTTPException(422, detail="Config payload nested too deeply")
    if not isinstance(config, dict):
        # Adapter passthrough bodies are objects; reject non-dict roots early.
        if _depth == 0:
            raise HTTPException(422, detail="Config payload must be an object")
        return config  # nested non-dict leaf — nothing to bound
    if len(config) > _MAX_CONFIG_KEYS:
        raise HTTPException(422, detail="Config payload has too many keys")
    for value in config.values():
        if isinstance(value, dict):
            _validate_passthrough_config(value, _depth + 1)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _validate_passthrough_config(item, _depth + 1)
    return config


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


async def _get_adapter_for_device(device: Device) -> Any:
    """Create a connected adapter for a device's controller."""
    from app.services.adapter_base import GatewayServiceBase

    ctrl = device.controller
    if not ctrl:
        raise HTTPException(404, detail="Device has no controller")

    # SSRF gate — refuse hosts pointing at FreeSDN's loopback or
    # cloud metadata endpoints. Mirrors the central enforcement in
    # GatewayServiceBase so direct adapter callers stay consistent
    # with the gateway-feature path.
    GatewayServiceBase._validate_controller_host(ctrl.host or "")

    cloud_kwargs: dict[str, Any] = {}
    if ctrl.connection_mode == "cloud":
        cloud_kwargs = {
            "client_id": ctrl.client_id or "",
            "client_secret": _decrypt_if_needed(ctrl.client_secret),
            "omada_id": ctrl.omada_id or "",
            "cloud_region": ctrl.cloud_region or "us",
        }

    adapter = get_adapter(
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

    # Set the Omada site context for this device so API calls target the right site
    meta = device.device_metadata or {}
    omada_site_id = meta.get("_omada_site_id")
    if omada_site_id and hasattr(adapter, "set_active_site"):
        adapter.set_active_site(omada_site_id)

    return adapter


# =====================================================================
# Routes
# =====================================================================


class PaginatedSwitchResponse(BaseModel):
    items: list[SwitchSummaryOut]
    total: int
    page: int
    per_page: int


@router.get("/", response_model=PaginatedSwitchResponse)
async def list_switches(
    site_id: str | None = Query(None),
    status: str | None = Query(None),
    vendor: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """List all switches with aggregated port/PoE stats (paginated)."""
    # Tenant scoping (app.core.tenancy): the org filter (reached via
    # Site for this via-site model) AND the per-user site grant, in ONE canonical
    # helper instead of the hand-rolled block this replaces. Behavior-preserving:
    # an unscoped super sees all; org users see their org; a site-limited caller
    # sees only granted sites (and nothing if grant-less, fail-closed).
    base = select(Device).where(
        Device.device_type == DeviceType.SWITCH,
        Device.deleted_at.is_(None),
        tenant_filter(Device, _user),
    )
    if site_id:
        base = base.where(Device.site_id == site_id)
    if status:
        base = base.where(Device.status == status)
    if vendor:
        base = base.where(Device.manufacturer.ilike(f"%{escape_like(vendor)}%", escape="\\"))

    # Total count
    count_result = await session.execute(select(func.count()).select_from(base.subquery()))
    total = count_result.scalar() or 0

    # Paginated query with eager loading
    q = (
        base.options(selectinload(Device.site), selectinload(Device.ports))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    result = await session.execute(q)
    devices = result.scalars().all()

    # Batch: count clients per device (single query, avoids N+1)
    device_ids = [d.id for d in devices]
    clients_counts: dict[str, int] = {}
    if device_ids:
        cc_result = await session.execute(
            select(DeviceClient.device_id, func.count(DeviceClient.id))
            .where(DeviceClient.device_id.in_(device_ids))
            .group_by(DeviceClient.device_id)
        )
        clients_counts = {str(row[0]): row[1] for row in cc_result.all()}

    # Batch: count VLANs per controller (single query, avoids N+1)
    ctrl_ids = list({d.controller_id for d in devices if d.controller_id})
    vlans_by_ctrl: dict[str, int] = {}
    if ctrl_ids:
        vc_result = await session.execute(
            select(Network.controller_id, func.count(Network.id))
            .where(Network.controller_id.in_(ctrl_ids), Network.deleted_at.is_(None))
            .group_by(Network.controller_id)
        )
        vlans_by_ctrl = {str(row[0]): row[1] for row in vc_result.all()}

    out: list[SwitchSummaryOut] = []
    for d in devices:
        ports = d.ports or []
        poe_ports = [
            p
            for p in ports
            if p.is_poe_enabled
            or (p.port_metadata or {}).get("poe_supported")
            or (p.port_metadata or {}).get("poeSupported")
        ]
        sfp_ports = [p for p in ports if p.port_type in ("sfp", "sfp+", "qsfp")]
        meta = d.device_metadata or {}
        poe_budget = (
            meta.get("poeBudget") or meta.get("poeTotalPower") or meta.get("poe_budget") or 0
        )
        vlans_count = vlans_by_ctrl.get(str(d.controller_id), 0) if d.controller_id else 0
        if not vlans_count:
            vlans_count = len({p.vlan_id for p in ports if p.vlan_id})

        out.append(
            SwitchSummaryOut(
                id=str(d.id),
                name=d.name,
                model=d.model,
                model_version=meta.get("model_version") or meta.get("hardware_version"),
                vendor=d.manufacturer,
                serial_number=d.serial_number or meta.get("serial_number"),
                mac_address=d.mac_address,
                ip_address=d.ip_address,
                ipv6_address=meta.get("ipv6_address"),
                controller_connection_ip=meta.get("controller_connection_ip"),
                site_id=str(d.site_id) if d.site_id else None,
                site_name=d.site.name if d.site else None,
                total_ports=len(ports),
                poe_ports=len(poe_ports),
                sfp_ports=len(sfp_ports),
                status=d.status or "unknown",
                uptime=d.uptime_seconds or 0,
                cpu_usage=d.cpu_usage_percent or 0,
                memory_usage=d.memory_usage_percent or 0,
                temperature=d.temperature_celsius,
                ports_up=sum(1 for p in ports if p.status == PortStatus.UP),
                ports_down=sum(1 for p in ports if p.status == PortStatus.DOWN),
                ports_disabled=sum(1 for p in ports if p.status == PortStatus.DISABLED),
                poe_budget=poe_budget,
                poe_used=sum(p.poe_power_watts or 0 for p in poe_ports),
                firmware_version=d.firmware_version,
                hardware_version=meta.get("hardware_version"),
                update_available=bool(meta.get("firmwareUpdateAvailable")),
                vlans_configured=vlans_count,
                connected_clients=clients_counts.get(str(d.id), 0)
                or meta.get("client_count")
                or meta.get("clientNum")
                or 0,
            )
        )

    return PaginatedSwitchResponse(
        items=out,
        total=total,
        page=page,
        per_page=per_page,
    )


# ---------- Profiles ----------


def _profile_to_out(p: PortProfile) -> SwitchPortProfileOut:
    """Serialize a PortProfile ORM record to the API shape."""
    return SwitchPortProfileOut(
        id=str(p.id),
        name=p.name,
        description=p.description,
        profile_type=p.profile_type,
        site_id=str(p.site_id) if p.site_id else None,
        controller_id=str(p.controller_id) if p.controller_id else None,
        native_vlan=p.native_vlan,
        tagged_vlans=list(p.tagged_vlans) if p.tagged_vlans else None,
        voice_vlan=p.voice_vlan,
        poe_enabled=p.poe_enabled,
        stp_enabled=p.stp_enabled,
        ports_using=p.ports_using,
        created_at=p.created_at.isoformat() if p.created_at else None,
        updated_at=p.updated_at.isoformat() if p.updated_at else None,
    )


async def _assert_site_in_org(session: AsyncSession, site_id: str, org_id: UUID) -> None:
    """Verify a site_id belongs to the caller's org. Raises 404 otherwise."""
    res = await session.execute(
        select(Site.id).where(
            Site.id == site_id, Site.organization_id == org_id, Site.deleted_at.is_(None)
        )
    )
    if res.scalar_one_or_none() is None:
        raise HTTPException(404, detail="Site not found")


async def _assert_controller_in_org(
    session: AsyncSession, controller_id: str, org_id: UUID
) -> UUID | None:
    """Verify a controller_id belongs to the caller's org via its site.

    Returns the controller's ``site_id`` so callers can additionally enforce
    the per-user site grant on the referenced controller.
    """
    from app.models.core import Controller

    res = await session.execute(
        select(Controller.site_id)
        .join(Site, Controller.site_id == Site.id)
        .where(Controller.id == controller_id, Site.organization_id == org_id)
    )
    row = res.first()
    if row is None:
        raise HTTPException(404, detail="Controller not found")
    return row[0]


def _profile_org_scope(org_id: UUID) -> Any:
    """Visibility predicate for port profiles scoped to an org.

    A profile is visible to the org if it is attached to one of the org's
    sites, OR it is a site-less profile created by a user belonging to the
    org (so a "minimal body" profile with no ``site_id`` is not orphaned
    from its creator). super_admin scoping is handled by callers.
    """
    from sqlalchemy import or_

    from app.models.core import User

    org_user_ids = select(User.id).where(User.organization_id == org_id).scalar_subquery()
    return or_(
        PortProfile.site_id.in_(_org_site_filter(org_id)),
        and_(PortProfile.site_id.is_(None), PortProfile.created_by.in_(org_user_ids)),
    )


async def _get_profile_for_org(
    session: AsyncSession, profile_id: str, org_id: UUID, user: Any = None
) -> PortProfile:
    """Fetch a non-deleted PortProfile scoped to the caller's org.

        When ``user`` is supplied, additionally enforce the per-user site grant
    : a site-limited operator may neither read nor mutate a
        sibling-site profile, nor an org-wide (site-less) profile reserved for
        non-site-limited admins. 404 (no existence oracle).
    """
    res = await session.execute(
        select(PortProfile).where(
            PortProfile.id == profile_id,
            PortProfile.deleted_at.is_(None),
            _profile_org_scope(org_id),
        )
    )
    profile = res.scalar_one_or_none()
    if profile is None:
        raise HTTPException(404, detail="Profile not found")
    if user is not None and getattr(user, "is_site_limited", False):
        # Org-wide (site-less) profiles are admin-only for site-limited callers.
        if profile.site_id is None:
            raise HTTPException(404, detail="Profile not found")
        assert_can_access_site(user, profile.site_id, detail="Profile not found")
    return profile


@router.get("/profiles", response_model=list[SwitchPortProfileOut])
async def list_profiles(
    site_id: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """List port profiles."""
    org_id = _org_id(_user)
    q = select(PortProfile).where(
        PortProfile.deleted_at.is_(None),
        _profile_org_scope(org_id),
        # Per-user site grant: a site-limited operator only sees
        # profiles attached to a site they are granted. ``site_scope_filter``
        # yields ``site_id IN (granted)`` for site-limited users — which also
        # excludes org-wide / site-less profiles (``site_id IS NULL``), keeping
        # those visible only to non-site-limited admins. No-op otherwise.
        site_scope_filter(_user, PortProfile.site_id),
    )
    if site_id:
        q = q.where(PortProfile.site_id == site_id)
    result = await session.execute(q)
    profiles = result.scalars().all()
    return [_profile_to_out(p) for p in profiles]


@router.post("/profiles", response_model=SwitchPortProfileOut, status_code=201)
async def create_profile(
    data: SwitchPortProfileCreate,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Create a DB-backed switch port profile.

    Profiles are stored in ``network.port_profiles`` (not controller-backed):
    a reusable bag of VLAN/PoE/STP settings that the UI can apply to ports
    via the existing bulk/CLI-profile apply paths. Org-scoped through the
    referenced ``site_id``.
    """
    org_id = _org_id(_user)
    # Per-user site grant: a site-limited operator may only create
    # profiles attached to a site/controller they are granted, and may NOT
    # create an org-wide (site-less) profile — those are reserved for
    # non-site-limited admins, so a missing site_id must fail closed.
    if getattr(_user, "is_site_limited", False) and not data.site_id:
        raise HTTPException(404, detail="Site not found")
    if data.site_id:
        await _assert_site_in_org(session, data.site_id, org_id)
        assert_can_access_site(_user, UUID(data.site_id), detail="Site not found")
    if data.controller_id:
        ctrl_site_id = await _assert_controller_in_org(session, data.controller_id, org_id)
        assert_can_access_site(_user, ctrl_site_id, detail="Controller not found")

    profile = PortProfile(
        name=data.name,
        description=data.description,
        profile_type=data.profile_type or "custom",
        site_id=UUID(data.site_id) if data.site_id else None,
        controller_id=UUID(data.controller_id) if data.controller_id else None,
        native_vlan=data.native_vlan,
        tagged_vlans=data.tagged_vlans,
        voice_vlan=data.voice_vlan,
        poe_enabled=data.poe_enabled,
        stp_enabled=data.stp_enabled,
        ports_using=0,
        created_by=getattr(_user, "id", None),
        updated_by=getattr(_user, "id", None),
    )
    session.add(profile)
    await session.commit()
    await session.refresh(profile)
    return _profile_to_out(profile)


@router.put("/profiles/{profile_id}", response_model=SwitchPortProfileOut)
@router.patch("/profiles/{profile_id}", response_model=SwitchPortProfileOut)
async def update_profile(
    profile_id: str,
    data: SwitchPortProfileUpdate,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update a DB-backed switch port profile (partial)."""
    org_id = _org_id(_user)
    profile = await _get_profile_for_org(session, profile_id, org_id, _user)

    site_limited = getattr(_user, "is_site_limited", False)
    fields = data.model_dump(exclude_unset=True)
    if "site_id" in fields and fields["site_id"]:
        await _assert_site_in_org(session, fields["site_id"], org_id)
        # Per-user site grant: can't re-target a profile onto a
        # sibling site the caller cannot access.
        assert_can_access_site(_user, UUID(fields["site_id"]), detail="Site not found")
        profile.site_id = UUID(fields["site_id"])
        fields.pop("site_id")
    elif "site_id" in fields:
        # Pattern-completion (META-LESSON #3): a site-limited caller must not
        # promote a site-scoped profile to org-wide (site-less) to escape the
        # grant; explicit null/empty fails closed for them.
        if site_limited:
            raise HTTPException(404, detail="Site not found")
        fields.pop("site_id")
    if "controller_id" in fields and fields["controller_id"]:
        ctrl_site_id = await _assert_controller_in_org(session, fields["controller_id"], org_id)
        assert_can_access_site(_user, ctrl_site_id, detail="Controller not found")
        profile.controller_id = UUID(fields["controller_id"])
        fields.pop("controller_id")
    elif "controller_id" in fields:
        fields.pop("controller_id")

    for key, value in fields.items():
        setattr(profile, key, value)
    profile.updated_by = getattr(_user, "id", None)

    await session.commit()
    await session.refresh(profile)
    return _profile_to_out(profile)


@router.delete("/profiles/{profile_id}")
async def delete_profile(
    profile_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Soft-delete a DB-backed switch port profile."""
    from datetime import datetime

    org_id = _org_id(_user)
    profile = await _get_profile_for_org(session, profile_id, org_id, _user)
    profile.deleted_at = datetime.now(UTC)
    profile.updated_by = getattr(_user, "id", None)
    await session.commit()
    return {"success": True, "id": profile_id}


@router.get("/{switch_id}", response_model=SwitchSummaryOut)
async def get_switch(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get detailed info for a single switch."""
    org_id = _org_id(_user)
    result = await session.execute(
        select(Device)
        .options(selectinload(Device.site), selectinload(Device.ports))
        .where(
            Device.id == switch_id,
            Device.deleted_at.is_(None),
            Device.site_id.in_(_org_site_filter(org_id)),
        )
    )
    device = result.scalar_one_or_none()
    if not device or device.device_type != DeviceType.SWITCH:
        raise HTTPException(404, detail="Switch not found")
    # Per-user site grant: site-limited callers may not read sibling-site switches.
    assert_can_access_site(_user, device.site_id, detail="Switch not found")

    ports = device.ports or []
    poe_ports = [
        p
        for p in ports
        if p.is_poe_enabled
        or (p.port_metadata or {}).get("poe_supported")
        or (p.port_metadata or {}).get("poeSupported")
    ]
    sfp_ports = [p for p in ports if p.port_type in ("sfp", "sfp+", "qsfp")]
    meta = device.device_metadata or {}

    # Count VLANs: prefer network table count (from controller sync), fallback to port-based
    vlans_count = 0
    if device.controller_id:
        vlans_result = await session.execute(
            select(func.count(Network.id)).where(
                Network.controller_id == device.controller_id,
                Network.deleted_at.is_(None),
            )
        )
        vlans_count = vlans_result.scalar() or 0
    if not vlans_count:
        vlans_count = len({p.vlan_id for p in ports if p.vlan_id})

    # Count connected clients — DB first, fallback to controller-reported count
    clients_result = await session.execute(
        select(func.count(DeviceClient.id)).where(DeviceClient.device_id == device.id)
    )
    clients_count = clients_result.scalar() or 0
    if not clients_count:
        # Use controller-reported client count from device_metadata (set during sync)
        # clientNum is the raw Omada field; client_count is the normalized one
        clients_count = meta.get("client_count") or meta.get("clientNum") or 0

    # Determine fan status
    fan_info = meta.get("fan_status", [])
    if isinstance(fan_info, list) and fan_info:
        fan_status = (
            "Normal"
            if all(
                (
                    f.get("status", "").lower() in ("normal", "ok", "good")
                    if isinstance(f, dict)
                    else str(f).lower() in ("normal", "ok", "good")
                )
                for f in fan_info
            )
            else "Warning"
        )
    elif isinstance(fan_info, str):
        fan_status = fan_info
    else:
        fan_status = None

    return SwitchSummaryOut(
        id=str(device.id),
        name=device.name,
        model=device.model,
        model_version=meta.get("model_version") or meta.get("hardware_version"),
        vendor=device.manufacturer,
        serial_number=device.serial_number or meta.get("serial_number"),
        mac_address=device.mac_address,
        ip_address=device.ip_address,
        ipv6_address=meta.get("ipv6_address"),
        controller_connection_ip=meta.get("controller_connection_ip"),
        site_id=str(device.site_id) if device.site_id else None,
        site_name=device.site.name if device.site else None,
        total_ports=len(ports),
        poe_ports=len(poe_ports),
        sfp_ports=len(sfp_ports),
        status=device.status or "unknown",
        uptime=device.uptime_seconds or 0,
        cpu_usage=device.cpu_usage_percent or 0,
        memory_usage=device.memory_usage_percent or 0,
        temperature=device.temperature_celsius,
        fan_status=fan_status,
        ports_up=sum(1 for p in ports if p.status == PortStatus.UP),
        ports_down=sum(1 for p in ports if p.status == PortStatus.DOWN),
        ports_disabled=sum(1 for p in ports if p.status == PortStatus.DISABLED),
        poe_budget=meta.get("poe_budget_watts")
        or meta.get("poeBudget")
        or meta.get("poe_total_power")
        or meta.get("poeTotalPower")
        or 0,
        poe_used=sum(p.poe_power_watts or 0 for p in poe_ports),
        firmware_version=device.firmware_version,
        hardware_version=meta.get("hardware_version"),
        update_available=bool(meta.get("firmwareUpdateAvailable")),
        vlans_configured=vlans_count,
        connected_clients=clients_count,
    )


@router.post("/{switch_id}/refresh")
async def refresh_switch(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Refresh switch data by pulling live info from the controller.

    Syncs connected clients (from /clients API and MAC table) into the DB.
    """
    from datetime import datetime

    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)

    raw_clients: list[dict[str, Any]] = []
    mac_table_entries: list[dict[str, Any]] = []
    switch_detail: dict[str, Any] = {}

    try:
        async with adapter:
            # Fetch switch detail, clients, and MAC table in one session
            try:
                switch_detail = await adapter.get_switch_detail(device.mac_address)
            except Exception as e:
                logger.error("Refresh: get_switch_detail failed: %s", e)

            try:
                raw_clients = await adapter.get_clients()
            except Exception as e:
                logger.error("Refresh: get_clients failed: %s", e)

            try:
                mac_table_entries = await adapter.get_switch_mac_table(
                    device.mac_address,
                )
            except Exception as e:
                logger.error("Refresh: get_switch_mac_table failed: %s", e)
    except Exception as e:
        logger.error("Refresh adapter session error: %s", e, exc_info=True)

    # Update device metadata with fresh detail data
    if switch_detail:
        meta = dict(device.device_metadata or {})
        for key in (
            "cpu_usage",
            "memory_usage",
            "uptime",
            "firmware_version",
            "hardware_version",
            "serial_number",
            "client_count",
            "poe_budget_watts",
            "poe_consumed_watts",
            "poe_remaining_watts",
            "ipv6_address",
            "controller_connection_ip",
            "model_version",
            "fan_status",
            "poe_total_power",
        ):
            if switch_detail.get(key) is not None:
                meta[key] = switch_detail[key]
        device.device_metadata = meta

    dev_mac = (device.mac_address or "").upper().replace("-", ":").replace(".", ":")
    logger.info(
        "Refresh: device=%s dev_mac=%s clients_api=%d mac_table=%d",
        device.name,
        dev_mac,
        len(raw_clients),
        len(mac_table_entries),
    )

    # Load existing DeviceClient records for this device
    existing_result = await session.execute(
        select(DeviceClient).where(DeviceClient.device_id == device.id)
    )
    mac_map = {c.mac_address.upper(): c for c in existing_result.scalars().all() if c.mac_address}

    synced = 0

    # 1. Sync from /clients API (wired clients with switchMac matching this device)
    if raw_clients and dev_mac:
        for c in raw_clients:
            connected_dev = (
                (
                    c.get("ap_mac")
                    or c.get("apMac")
                    or c.get("switch_mac")
                    or c.get("switchMac")
                    or c.get("connectDevMac")
                    or ""
                )
                .upper()
                .replace("-", ":")
                .replace(".", ":")
            )
            if connected_dev != dev_mac:
                continue

            client_mac = (c.get("mac") or c.get("mac_address") or "").upper()
            if not client_mac:
                continue

            if client_mac in mac_map:
                dc = mac_map[client_mac]
            else:
                dc = DeviceClient(device_id=device.id, mac_address=client_mac)
                session.add(dc)
                mac_map[client_mac] = dc

            dc.device_id = device.id
            dc.hostname = c.get("hostname") or c.get("name")
            dc.ip_address = c.get("ip") or c.get("ip_address")
            dc.ssid = c.get("ssid")
            dc.is_online = True
            dc.last_seen = datetime.now(UTC)
            synced += 1

    # 2. Sync from MAC table (covers all devices learned on switch ports,
    #    including wireless clients behind APs connected to this switch)
    if mac_table_entries:
        for entry in mac_table_entries:
            client_mac = (
                (entry.get("mac_address") or entry.get("mac") or "")
                .upper()
                .replace("-", ":")
                .replace(".", ":")
            )
            if not client_mac or client_mac == dev_mac:
                continue  # Skip the switch's own MAC

            if client_mac in mac_map:
                continue  # Already synced from /clients API

            dc = DeviceClient(device_id=device.id, mac_address=client_mac)
            session.add(dc)
            mac_map[client_mac] = dc
            dc.is_online = True
            dc.last_seen = datetime.now(UTC)
            synced += 1

    await session.flush()

    clients_result = await session.execute(
        select(func.count(DeviceClient.id)).where(DeviceClient.device_id == device.id)
    )
    db_clients_count = clients_result.scalar() or 0
    # Use controller-reported count as fallback (more accurate for switches
    # since it counts all devices passing through, not just directly-connected)
    controller_clients = switch_detail.get("client_count", 0) if switch_detail else 0
    clients_count = db_clients_count or controller_clients

    return {
        "success": True,
        "clients_synced": synced,
        "connected_clients": clients_count,
        "mac_table_entries": len(mac_table_entries),
        "controller_reported_clients": controller_clients,
    }


# ---------- Ports ----------


@router.get("/{switch_id}/ports", response_model=list[SwitchPortOut])
async def list_switch_ports(
    switch_id: str,
    status: str | None = Query(None),
    vlan_id: int | None = Query(None),
    poe_enabled: bool | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """List all ports on a switch."""
    # Verify the switch belongs to the user's org + per-user site grant.
    await _get_switch(session, switch_id, _org_id(_user), _user)
    q = select(DevicePort).where(DevicePort.device_id == switch_id)
    if status:
        q = q.where(DevicePort.status == status)
    if vlan_id is not None:
        q = q.where(DevicePort.vlan_id == vlan_id)
    if poe_enabled is not None:
        q = q.where(DevicePort.is_poe_enabled == poe_enabled)

    q = q.order_by(DevicePort.port_number)
    result = await session.execute(q)
    ports = result.scalars().all()
    return [_port_to_out(p) for p in ports]


@router.get("/{switch_id}/ports/{port_index}", response_model=SwitchPortOut)
async def get_switch_port(
    switch_id: str,
    port_index: int,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get a single port on a switch."""
    # Verify switch belongs to user's org + per-user site grant.
    await _get_switch(session, switch_id, _org_id(_user), _user)
    result = await session.execute(
        select(DevicePort).where(
            DevicePort.device_id == switch_id,
            DevicePort.port_number == port_index,
        )
    )
    port = result.scalar_one_or_none()
    if not port:
        raise HTTPException(404, detail="Port not found")
    return _port_to_out(port)


@router.patch("/{switch_id}/ports/{port_index}", response_model=SwitchPortOut)
async def update_switch_port(
    switch_id: str,
    port_index: int = Path(..., ge=0, le=127),
    data: PortUpdateIn = ...,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """
    Update port configuration.

    Pushes changes to the controller then updates the DB record.
    """
    # Verify switch belongs to user's org + per-user site grant
    # (returns the device with its controller eager-loaded).
    device = await _get_switch(session, switch_id, _org_id(_user), _user)

    port_result = await session.execute(
        select(DevicePort).where(
            DevicePort.device_id == switch_id,
            DevicePort.port_number == port_index,
        )
    )
    port = port_result.scalar_one_or_none()
    if not port:
        raise HTTPException(404, detail="Port not found")

    # Push to controller
    adapter = await _get_adapter_for_device(device)
    config: dict[str, Any] = {}
    if data.name is not None:
        config["name"] = data.name
        port.name = data.name
    if data.enabled is not None:
        config["enabled"] = data.enabled
        port.is_enabled = data.enabled
    if data.speed is not None:
        config["speed"] = data.speed
    if data.duplex is not None:
        config["duplex"] = data.duplex
    if data.mtu is not None:
        config["mtu"] = data.mtu
    if data.flow_control is not None:
        config["flowControl"] = data.flow_control
    if data.vlan_config:
        config["pvid"] = data.vlan_config.native_vlan
        config["taggedVlans"] = data.vlan_config.tagged_vlans
        port.vlan_id = data.vlan_config.native_vlan
    if data.poe_config is not None:
        config["poeEnabled"] = data.poe_config.enabled
        port.is_poe_enabled = data.poe_config.enabled
    if data.stp_config is not None:
        config["stpEnabled"] = data.stp_config.enabled
        config["stpMode"] = data.stp_config.mode
        if data.stp_config.guard is not None:
            config["stpGuard"] = data.stp_config.guard
        config["bpduFilter"] = data.stp_config.bpdu_filter
        config["bpduGuard"] = data.stp_config.bpdu_guard
    if data.security_config is not None:
        dot1x_mode_map = {"auto": 1, "force_auth": 2, "force_unauth": 3, "disable": 0}
        if data.security_config.dot1x_enabled:
            config["dot1x"] = dot1x_mode_map[data.security_config.dot1x_mode]
        else:
            config["dot1x"] = 0
        if data.security_config.mac_limit is not None:
            config["macLimit"] = data.security_config.mac_limit
        if data.security_config.violation_action != "restrict":
            config["violationAction"] = data.security_config.violation_action

    try:
        async with adapter:
            cfg_result = await adapter.configure_switch_port(device.mac_address, port_index, config)
    except Exception as e:
        logger.error("Failed to push port config to controller: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    # CONV2-001: a non-throwing AdapterResult(success=False) must not be committed
    # as a successful port write.
    raise_for_adapter_result(cfg_result)

    await session.commit()
    await session.refresh(port)
    return _port_to_out(port)


@router.post("/{switch_id}/ports/bulk", response_model=list[SwitchPortOut])
async def bulk_update_ports(
    switch_id: str,
    data: BulkPortUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Bulk-update multiple ports on a switch."""
    # Verify switch belongs to user's org + per-user site grant.
    await _get_switch(session, switch_id, _org_id(_user), _user)
    result = await session.execute(
        select(DevicePort).where(
            DevicePort.device_id == switch_id,
            DevicePort.id.in_(data.port_ids),
        )
    )
    ports = result.scalars().all()
    if not ports:
        raise HTTPException(404, detail="No matching ports found")

    for port in ports:
        if data.updates.name is not None:
            port.name = data.updates.name
        if data.updates.enabled is not None:
            port.is_enabled = data.updates.enabled
        if data.updates.poe_config is not None:
            port.is_poe_enabled = data.updates.poe_config.enabled

    await session.commit()
    return [_port_to_out(p) for p in ports]


# ---------- Port Actions ----------


@router.post(
    "/{switch_id}/ports/{port_index}/toggle",
    response_model=AdapterActionResponse,
)
async def toggle_port(
    switch_id: str,
    port_index: int,
    data: ToggleIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> AdapterActionResponse:
    """Enable/disable a port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            toggle_result = await adapter.set_port_enabled(
                device.mac_address, port_index, data.enabled
            )
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    raise_for_adapter_result(toggle_result)  # CONV2-001

    # Update DB
    port_result = await session.execute(
        select(DevicePort).where(
            DevicePort.device_id == switch_id,
            DevicePort.port_number == port_index,
        )
    )
    port = port_result.scalar_one_or_none()
    if port:
        port.is_enabled = data.enabled
        port.status = PortStatus.UP if data.enabled else PortStatus.DISABLED
        await session.commit()

    return AdapterActionResponse(
        success=True,
        message=f"Port {port_index} {'enabled' if data.enabled else 'disabled'}",
        data={"enabled": data.enabled, "port_index": port_index},
    )


@router.post(
    "/{switch_id}/ports/{port_index}/poe",
    response_model=AdapterActionResponse,
)
async def toggle_port_poe(
    switch_id: str,
    port_index: int,
    data: ToggleIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> AdapterActionResponse:
    """Enable/disable PoE on a port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            poe_result = await adapter.set_port_poe(device.mac_address, port_index, data.enabled)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    raise_for_adapter_result(poe_result)  # CONV2-001

    port_result = await session.execute(
        select(DevicePort).where(
            DevicePort.device_id == switch_id,
            DevicePort.port_number == port_index,
        )
    )
    port = port_result.scalar_one_or_none()
    if port:
        port.is_poe_enabled = data.enabled
        await session.commit()

    return AdapterActionResponse(
        success=True,
        message=f"PoE {'enabled' if data.enabled else 'disabled'} on port {port_index}",
        data={"enabled": data.enabled, "port_index": port_index},
    )


@router.post(
    "/{switch_id}/ports/{port_index}/poe/cycle",
    response_model=AdapterActionResponse,
)
async def cycle_port_poe(
    switch_id: str,
    port_index: int,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> AdapterActionResponse:
    """Cycle PoE (disable → wait → re-enable)."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            cycle_result = await adapter.cycle_poe_port(device.mac_address, port_index)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    raise_for_adapter_result(cycle_result)  # CONV2-001
    return AdapterActionResponse(
        success=True,
        message=f"PoE cycled on port {port_index}",
        data={"port_index": port_index},
    )


@router.post("/{switch_id}/apply-profile")
async def apply_profile(
    switch_id: str,
    data: ApplyProfileIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Apply a port profile to selected ports."""
    org_id = _org_id(_user)
    # Verify switch belongs to user's org + per-user site grant (404 otherwise).
    await _get_switch(session, switch_id, org_id, _user)
    profile_result = await session.execute(
        select(PortProfile).where(
            PortProfile.id == data.profile_id,
            PortProfile.site_id.in_(_org_site_filter(org_id)),
        )
    )
    profile = profile_result.scalar_one_or_none()
    if not profile:
        raise HTTPException(404, detail="Profile not found")
    # Per-user site grant: site-limited callers may not apply a sibling-site profile.
    if profile.site_id:
        assert_can_access_site(_user, profile.site_id, detail="Profile not found")

    ports_result = await session.execute(
        select(DevicePort).where(
            DevicePort.device_id == switch_id,
            DevicePort.id.in_(data.port_ids),
        )
    )
    ports = ports_result.scalars().all()
    for port in ports:
        if profile.native_vlan is not None:
            port.vlan_id = profile.native_vlan
        if profile.poe_enabled is not None:
            port.is_poe_enabled = profile.poe_enabled

    profile.ports_using = len(ports)
    await session.commit()
    return {"success": True, "ports_updated": len(ports)}


# ---------- LAGs ----------


@router.get("/{switch_id}/lags", response_model=list[SwitchLAGOut])
async def list_lags(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """List LAG groups on a switch."""
    # Verify switch belongs to user's org + per-user site grant.
    await _get_switch(session, switch_id, _org_id(_user), _user)
    result = await session.execute(
        select(LinkAggregationGroup).where(
            LinkAggregationGroup.device_id == switch_id,
        )
    )
    lags = result.scalars().all()
    return [
        SwitchLAGOut(
            id=str(lg.id),
            device_id=str(lg.device_id),
            name=lg.name,
            lag_id=lg.lag_id,
            mode=lg.mode,
            member_ports=lg.member_ports or [],
            lacp_mode=lg.lacp_mode,
            lacp_timeout=lg.lacp_timeout,
            status=lg.status,
            active_ports=lg.active_ports,
            aggregate_speed=lg.aggregate_speed,
        )
        for lg in lags
    ]


@router.post("/{switch_id}/lags")
async def create_lag(
    switch_id: str,
    data: LAGCreateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Create a LAG group on a switch."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    config = data.model_dump(exclude_none=True)
    try:
        async with adapter:
            result = await adapter.create_switch_lag(device.mac_address, config)
    except Exception as e:
        logger.error("LAG create error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    if not result.success:
        raise_for_adapter_result(result)
    return {
        "success": True,
        "data": getattr(result, "value", None) or getattr(result, "data", None),
    }


@router.put("/{switch_id}/lags/{lag_id}")
async def update_lag(
    switch_id: str,
    lag_id: int,
    data: LAGUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update a LAG group on a switch."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    config = data.model_dump(exclude_none=True)
    try:
        async with adapter:
            result = await adapter.update_switch_lag(device.mac_address, lag_id, config)
    except Exception as e:
        logger.error("LAG update error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    if not result.success:
        raise_for_adapter_result(result)
    return {
        "success": True,
        "data": getattr(result, "value", None) or getattr(result, "data", None),
    }


@router.delete(
    "/{switch_id}/lags/{lag_id}",
    response_model=AdapterActionResponse,
)
async def delete_lag(
    switch_id: str,
    lag_id: int,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> AdapterActionResponse:
    """Delete a LAG group from a switch."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.delete_switch_lag(device.mac_address, lag_id)
    except Exception as e:
        logger.error("LAG delete error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    if not result.success:
        raise_for_adapter_result(result)
    return AdapterActionResponse(
        success=True,
        message=f"LAG {lag_id} deleted",
        data={"lag_id": lag_id},
    )


# ---------- Utility ----------


async def _get_device(
    session: AsyncSession,
    device_id: str,
    organization_id: UUID | None = None,
    current_user: Any = None,
) -> Device:
    conditions = [Device.id == device_id, Device.deleted_at.is_(None)]
    if organization_id:
        conditions.append(Device.site_id.in_(_org_site_filter(organization_id)))
    result = await session.execute(
        select(Device).options(selectinload(Device.controller)).where(*conditions)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, detail="Device not found")
    # Per-user site-grant: a site-limited caller may not reach sibling-site
    # devices in the same org. No-op for super_admin / org_admin.
    if current_user is not None:
        assert_can_access_site(current_user, device.site_id, detail="Device not found")
    return device


async def _get_switch(
    session: AsyncSession,
    device_id: str,
    organization_id: UUID | None = None,
    current_user: Any = None,
) -> Device:
    """Get device and verify it is a switch. Raises 404 otherwise."""
    device = await _get_device(session, device_id, organization_id, current_user)
    if device.device_type != DeviceType.SWITCH:
        raise HTTPException(404, detail="Device is not a switch")
    return device


# =====================================================================
# Network View & Config Endpoints
# =====================================================================


# ---------- VLANs / Networks ----------


@router.get("/{switch_id}/vlans")
async def get_switch_vlans(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get VLANs/networks configured on this switch's controller.

    Returns VLAN definitions with port membership counts computed from
    the switch's port data.
    """
    device = await _get_switch(session, switch_id, _org_id(_user), _user)

    # Get networks from the DB (synced from controller)
    networks_result = await session.execute(
        select(Network)
        .where(
            Network.controller_id == device.controller_id,
            Network.deleted_at.is_(None),
        )
        .order_by(Network.vlan_id)
    )
    networks = networks_result.scalars().all()

    # Get port data for counting membership
    ports_result = await session.execute(
        select(DevicePort).where(DevicePort.device_id == device.id)
    )
    ports = ports_result.scalars().all()

    vlans_out = []
    for net in networks:
        untagged = 0
        tagged = 0
        for p in ports:
            meta = p.port_metadata or {}
            if p.vlan_id == net.vlan_id or meta.get("native_vlan") == net.vlan_id:
                untagged += 1
            tag_list = meta.get("tagged_vlans") or []
            if net.vlan_id in tag_list:
                tagged += 1
        vlans_out.append(
            {
                "id": str(net.id),
                "vlan_id": net.vlan_id,
                "name": net.name,
                "description": net.description,
                "purpose": net.purpose,
                "gateway": net.gateway,
                "subnet": net.subnet,
                "cidr": net.cidr,
                "dhcp_enabled": net.dhcp_enabled,
                "untagged_ports": untagged,
                "tagged_ports": tagged,
            }
        )

    return vlans_out


@router.put("/{switch_id}/vlans/port-assignments")
async def bulk_vlan_port_assignment(
    switch_id: str,
    data: BulkVlanAssignmentIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Bulk assign VLAN memberships to ports.

    Each assignment specifies a port_index, optional native_vlan (untagged),
    and a list of tagged_vlans. The adapter applies these via per-port config updates.
    """
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)

    results: list[dict[str, Any]] = []
    try:
        async with adapter:
            for assignment in data.assignments:
                port_config: dict[str, Any] = {}
                if assignment.native_vlan is not None:
                    port_config["nativeNetworkId"] = assignment.native_vlan
                if assignment.tagged_vlans:
                    port_config["taggedNetworkIds"] = assignment.tagged_vlans
                try:
                    result = await adapter.update_switch_port_overrides(
                        device.mac_address,
                        assignment.port_index,
                        port_config,
                    )
                    results.append(
                        {
                            "port": assignment.port_index,
                            "success": result.success,
                            **({"error": result.message} if not result.success else {}),
                        }
                    )
                except Exception as e:
                    results.append(
                        {"port": assignment.port_index, "success": False, "error": str(e)}
                    )
    except Exception as e:
        logger.error("Bulk VLAN assignment error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    succeeded = sum(1 for r in results if r["success"])
    return {
        "success": succeeded > 0,
        "total_ports": len(data.assignments),
        "succeeded": succeeded,
        "failed": len(data.assignments) - succeeded,
        "results": results,
    }


# ---------- STP / RSTP ----------


@router.get("/{switch_id}/stp")
async def get_stp_config(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get STP/RSTP global config for the site."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            data = await adapter.get_switch_stp_config()
    except Exception as e:
        logger.error("STP config fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return data


@router.put("/{switch_id}/stp")
async def update_stp_config(
    switch_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update STP/RSTP global config (mode, priority, hello, max_age)."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.update_switch_stp_config(config)
    except Exception as e:
        logger.error("STP config update error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


# ---------- ACL Rules ----------


@router.get("/{switch_id}/acl")
async def get_acl_rules(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get ACL rules for a switch."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            rules = await adapter.get_switch_acl_rules(device.mac_address)
    except Exception as e:
        logger.error("ACL rules fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return rules


@router.post("/{switch_id}/acl")
async def create_acl_rule(
    switch_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Create an ACL rule on a switch."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.create_switch_acl_rule(device.mac_address, config)
    except Exception as e:
        logger.error("ACL rule create error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message, "data": result.data}


@router.put("/{switch_id}/acl/{rule_id}")
async def update_acl_rule(
    switch_id: str,
    rule_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update an ACL rule on a switch."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.update_switch_acl_rule(device.mac_address, rule_id, config)
    except Exception as e:
        logger.error("ACL rule update error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


@router.delete("/{switch_id}/acl/{rule_id}")
async def delete_acl_rule(
    switch_id: str,
    rule_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Delete an ACL rule from a switch."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.delete_switch_acl_rule(device.mac_address, rule_id)
    except Exception as e:
        logger.error("ACL rule delete error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


# ---------- IGMP Snooping ----------


@router.get("/{switch_id}/igmp")
async def get_igmp_config(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get IGMP snooping config for a switch."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            data = await adapter.get_switch_igmp_config(device.mac_address)
    except Exception as e:
        logger.error("IGMP config fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return data


@router.put("/{switch_id}/igmp")
async def update_igmp_config(
    switch_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update IGMP snooping config for a switch."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.update_switch_igmp_config(device.mac_address, config)
    except Exception as e:
        logger.error("IGMP config update error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


# ---------- Port Isolation ----------


@router.post("/{switch_id}/ports/{port_index}/isolation")
async def set_port_isolation(
    switch_id: str,
    port_index: int,
    data: ToggleIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Enable/disable port isolation on a switch port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.set_switch_port_isolation(
                device.mac_address, port_index, data.enabled
            )
    except Exception as e:
        logger.error("Port isolation error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "enabled": data.enabled}


# ---------- Port Mirroring ----------


@router.get("/{switch_id}/mirror")
async def get_mirror_config(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get port mirror config for a switch."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            data = await adapter.get_switch_mirror_config(device.mac_address)
    except Exception as e:
        logger.error("Mirror config fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return data


@router.put("/{switch_id}/mirror")
async def update_mirror_config(
    switch_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update port mirror config (session/source/dest)."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.update_switch_mirror_config(device.mac_address, config)
    except Exception as e:
        logger.error("Mirror config update error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


# ---------- Static Routes ----------


@router.get("/{switch_id}/routes")
async def get_static_routes(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get static routes (site-level, read-only from device perspective)."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            routes = await adapter.get_static_routes()
    except Exception as e:
        logger.error("Static routes fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return routes


# ---------- DHCP ----------


@router.get("/{switch_id}/dhcp")
async def get_dhcp_config(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get DHCP configuration for the site."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            data = await adapter.get_dhcp_config()
    except Exception as e:
        logger.error("DHCP config fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return data


@router.get("/{switch_id}/dhcp/snooping")
async def get_dhcp_snooping_config(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get DHCP snooping configuration."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            data = await adapter.get_dhcp_snooping_config()
    except Exception as e:
        logger.error("DHCP snooping config fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return data


@router.put("/{switch_id}/dhcp/snooping")
async def update_dhcp_snooping_config(
    switch_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update DHCP snooping configuration."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.update_dhcp_snooping_config(config)
    except Exception as e:
        logger.error("DHCP snooping update error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


# ---------- QoS ----------


@router.get("/{switch_id}/qos")
async def get_qos_config(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get site-level QoS configuration."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            data = await adapter.get_qos_config()
    except Exception as e:
        logger.error("QoS config fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return data


@router.put("/{switch_id}/qos")
async def update_qos_config(
    switch_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update site-level QoS configuration."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.update_qos_config(config)
    except Exception as e:
        logger.error("QoS config update error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


# ---------- MAC Address Table ----------


@router.get("/{switch_id}/mac-table")
async def get_mac_table(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get MAC address table from a switch."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            entries = await adapter.get_switch_mac_table(device.mac_address)
    except Exception as e:
        logger.error("MAC table fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    logger.info("MAC table for %s returned %d entries", device.name, len(entries) if entries else 0)
    return entries or []


# ---------- LLDP Neighbors ----------


@router.get("/{switch_id}/lldp")
async def get_lldp_neighbors(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get LLDP neighbor table from switch port metadata."""
    await _get_switch(session, switch_id, _org_id(_user), _user)
    # Pull LLDP data from stored port metadata
    port_result = await session.execute(select(DevicePort).where(DevicePort.device_id == switch_id))
    ports = port_result.scalars().all()
    neighbors = []
    for port in ports:
        meta = port.port_metadata or {}
        neighbor_device = meta.get("lldpNeighborDevice") or port.connected_mac
        if neighbor_device:
            neighbors.append(
                {
                    "port_index": port.port_number,
                    "port_name": port.port_name or f"Port {port.port_number}",
                    "neighbor_device": neighbor_device,
                    "neighbor_port": meta.get("lldpNeighborPort"),
                    "neighbor_ip": meta.get("lldpNeighborIp"),
                    "neighbor_mac": port.connected_mac,
                    "chassis_id": meta.get("lldpChassisId"),
                    "system_name": meta.get("lldpSystemName"),
                    "system_description": meta.get("lldpSystemDesc"),
                }
            )
    return neighbors


# ---------- Port LLDP Toggle ----------


@router.post("/{switch_id}/ports/{port_index}/lldp")
async def set_port_lldp(
    switch_id: str,
    port_index: int,
    data: ToggleIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Enable/disable LLDP-MED on a switch port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.set_switch_port_lldp(
                device.mac_address, port_index, data.enabled
            )
    except Exception as e:
        logger.error("Port LLDP toggle error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "enabled": data.enabled}


# ---------- Port Flow Control ----------


@router.post("/{switch_id}/ports/{port_index}/flow-control")
async def set_port_flow_control(
    switch_id: str,
    port_index: int,
    data: ToggleIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Enable/disable 802.3x flow control on a switch port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.set_switch_port_flow_control(
                device.mac_address, port_index, data.enabled
            )
    except Exception as e:
        logger.error("Port flow control error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "enabled": data.enabled}


# ---------- Port Speed/Duplex ----------


class SpeedDuplexIn(BaseModel):
    speed: str = "auto"
    duplex: str = "auto"


@router.post("/{switch_id}/ports/{port_index}/speed")
async def set_port_speed_duplex(
    switch_id: str,
    port_index: int,
    data: SpeedDuplexIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Set link speed/duplex on a switch port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.set_switch_port_speed_duplex(
                device.mac_address, port_index, data.speed, data.duplex
            )
    except Exception as e:
        logger.error("Port speed/duplex error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "speed": data.speed, "duplex": data.duplex}


# ---------- Port Loopback Detection ----------


@router.post("/{switch_id}/ports/{port_index}/loopback-detect")
async def set_port_loopback_detect(
    switch_id: str,
    port_index: int,
    data: ToggleIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Enable/disable loopback detection on a switch port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.set_switch_port_loopback_detect(
                device.mac_address, port_index, data.enabled
            )
    except Exception as e:
        logger.error("Port loopback detect error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "enabled": data.enabled}


# ---------- Device Events / Alerts ----------


@router.get("/{switch_id}/events")
async def get_device_events(
    switch_id: str,
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get recent events from the controller, filtered to this device."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            all_events = await adapter.get_events(limit=limit)
    except Exception as e:
        logger.error("Events fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    # Filter events to this device by MAC
    mac = device.mac_address
    device_events = [
        ev
        for ev in all_events
        if (isinstance(ev, dict) and ev.get("device_mac") == mac)
        or (hasattr(ev, "device_mac") and ev.device_mac == mac)
    ]
    # If no device-specific events found, return all (may be site-level)
    return device_events if device_events else all_events[:limit]


@router.get("/{switch_id}/alerts")
async def get_device_alerts(
    switch_id: str,
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get active alerts from the controller."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            alerts = await adapter.get_alerts(limit=limit)
    except Exception as e:
        logger.error("Alerts fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    mac = device.mac_address
    device_alerts = [
        a
        for a in alerts
        if (isinstance(a, dict) and a.get("device_mac") == mac)
        or (hasattr(a, "device_mac") and a.device_mac == mac)
    ]
    return device_alerts if device_alerts else alerts[:limit]


# ---------- Connected Clients ----------


@router.get("/{switch_id}/clients")
async def get_switch_clients(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get connected clients for a switch.

    Tries the adapter's switch-specific client method which attempts:
    1. Omada ``/switches/{mac}/clients`` endpoint (switch-scoped)
    2. Full client list filtered by switchMac + clients on downstream APs
    Falls back to DB DeviceClient records.
    """
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    raw_mac = (device.mac_address or "").upper().replace("-", ":").replace(".", ":")

    # --- Source 1: adapter switch-specific clients ---
    try:
        adapter = await _get_adapter_for_device(device)
        async with adapter:
            switch_clients = await adapter.get_switch_clients(raw_mac)
            if switch_clients:
                return switch_clients
    except Exception as e:
        logger.debug("Adapter switch clients failed: %s", e)

    # --- Source 3: DB DeviceClient records as fallback ---
    db_result = await session.execute(
        select(DeviceClient).where(
            DeviceClient.device_id == device.id,
            DeviceClient.is_online.is_(True),
        )
    )
    db_clients = db_result.scalars().all()
    if db_clients:
        return [
            {
                "mac_address": dc.mac_address,
                "name": dc.hostname,
                "hostname": dc.hostname,
                "ip_address": dc.ip_address,
                "connection_type": "wireless" if dc.ssid else "wired",
                "activity": (dc.tx_bytes or 0) + (dc.rx_bytes or 0),
                "last_seen": dc.last_seen.isoformat() if dc.last_seen else None,
            }
            for dc in db_clients
        ]

    return []


# =====================================================================
# Advanced Port Features
# =====================================================================


class BandwidthControlIn(BaseModel):
    """Per-port bandwidth/rate limiting."""

    bandwidth_ctrl_type: int = Field(0, description="0=off, 1=rate_limit")
    ingress_rate: int | None = Field(None, description="Ingress rate limit in kbps")
    egress_rate: int | None = Field(None, description="Egress rate limit in kbps")


@router.post("/{switch_id}/ports/{port_index}/bandwidth")
async def set_port_bandwidth(
    switch_id: str,
    port_index: int,
    data: BandwidthControlIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Set bandwidth control (rate limiting) on a switch port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    config: dict[str, Any] = {
        "bandWidthCtrlType": data.bandwidth_ctrl_type,
    }
    if data.ingress_rate is not None or data.egress_rate is not None:
        config["bandCtrl"] = {}
        if data.ingress_rate is not None:
            config["bandCtrl"]["ingressRate"] = data.ingress_rate
        if data.egress_rate is not None:
            config["bandCtrl"]["egressRate"] = data.egress_rate
    try:
        async with adapter:
            result = await adapter.set_switch_port_bandwidth(device.mac_address, port_index, config)
    except Exception as e:
        logger.error("Bandwidth control error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


class StormControlIn(BaseModel):
    """Per-port storm control thresholds."""

    broadcast_enabled: bool = False
    broadcast_rate: int | None = Field(None, description="Broadcast rate threshold (pps)")
    multicast_enabled: bool = False
    multicast_rate: int | None = Field(None, description="Multicast rate threshold (pps)")
    unknown_unicast_enabled: bool = False
    unknown_unicast_rate: int | None = Field(
        None, description="Unknown unicast rate threshold (pps)"
    )


@router.post("/{switch_id}/ports/{port_index}/storm-control")
async def set_port_storm_control(
    switch_id: str,
    port_index: int,
    data: StormControlIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Set storm control thresholds on a switch port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    config: dict[str, Any] = {
        "broadcastEnable": data.broadcast_enabled,
        "multicastEnable": data.multicast_enabled,
        "unknownUnicastEnable": data.unknown_unicast_enabled,
    }
    if data.broadcast_rate is not None:
        config["broadcastRate"] = data.broadcast_rate
    if data.multicast_rate is not None:
        config["multicastRate"] = data.multicast_rate
    if data.unknown_unicast_rate is not None:
        config["unknownUnicastRate"] = data.unknown_unicast_rate
    try:
        async with adapter:
            result = await adapter.set_switch_port_storm_control(
                device.mac_address, port_index, config
            )
    except Exception as e:
        logger.error("Storm control error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


# ---------- PoE Schedules (via adapter) ----------


@router.get("/{switch_id}/poe-schedules")
async def get_switch_poe_schedules(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get PoE schedules from the controller for this switch's site."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            schedules = await adapter.get_poe_schedules()
    except Exception as e:
        logger.error("PoE schedules fetch error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return schedules


@router.post("/{switch_id}/poe-schedules")
async def create_switch_poe_schedule(
    switch_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Create a PoE schedule on the controller."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.create_poe_schedule(config)
    except Exception as e:
        logger.error("PoE schedule create error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message, "data": result.data}


@router.put("/{switch_id}/poe-schedules/{schedule_id}")
async def update_switch_poe_schedule(
    switch_id: str,
    schedule_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update a PoE schedule on the controller."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.update_poe_schedule(schedule_id, config)
    except Exception as e:
        logger.error("PoE schedule update error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


@router.delete("/{switch_id}/poe-schedules/{schedule_id}")
async def delete_switch_poe_schedule(
    switch_id: str,
    schedule_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Delete a PoE schedule."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.delete_poe_schedule(schedule_id)
    except Exception as e:
        logger.error("PoE schedule delete error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {"success": result.success, "message": result.message}


# =====================================================================
# Diagnostics Tools
# =====================================================================


class CableTestIn(BaseModel):
    port: int = Field(..., description="Port number to test")


@router.post("/{switch_id}/diagnostics/cable-test")
async def run_cable_test(
    switch_id: str,
    data: CableTestIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Run cable diagnostic test on a switch port."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.run_cable_test(device.mac_address, data.port)
    except Exception as e:
        logger.error("Cable test error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {
        "success": result.success,
        "message": result.message,
        "data": result.data,
    }


_HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")


def _validate_diag_target(v: str) -> str:
    """Validate that target is a safe IP address or hostname (no SSRF)."""
    v = v.strip()
    if not v:
        raise ValueError("Target cannot be empty")
    if len(v) > 253:
        raise ValueError("Target too long")
    # Try parsing as IP first
    try:
        addr = ipaddress.ip_address(v)
        # Block loopback, link-local, and multicast — these are SSRF vectors
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            raise ValueError(f"Target address {v} is not allowed")
        return v
    except ValueError as ip_err:
        if "not allowed" in str(ip_err):
            raise
        pass  # Not an IP — try hostname
    # Validate as hostname
    if not _HOSTNAME_RE.match(v):
        raise ValueError("Target must be a valid IP address or hostname")
    # Block obvious internal hostnames
    lower = v.lower()
    if lower in ("localhost", "localhost.localdomain"):
        raise ValueError("Target 'localhost' is not allowed")
    return v


class PingIn(BaseModel):
    target: str = Field(..., description="Target IP or hostname")
    count: int = Field(5, ge=1, le=20, description="Number of pings")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_diag_target(v)


@router.post("/{switch_id}/diagnostics/ping")
async def run_ping_test(
    switch_id: str,
    data: PingIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Run ping from a device to a target host."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.run_ping(device.mac_address, data.target, data.count)
    except Exception as e:
        logger.error("Ping test error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {
        "success": result.success,
        "message": result.message,
        "data": result.data,
    }


class TracerouteIn(BaseModel):
    target: str = Field(..., description="Target IP or hostname")
    max_hops: int = Field(30, ge=1, le=64, description="Maximum number of hops")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_diag_target(v)


@router.post("/{switch_id}/diagnostics/traceroute")
async def run_traceroute_test(
    switch_id: str,
    data: TracerouteIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Run traceroute from a device to a target host."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.run_traceroute(device.mac_address, data.target, data.max_hops)
    except Exception as e:
        logger.error("Traceroute error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    return {
        "success": result.success,
        "message": result.message,
        "data": result.data,
    }


# =====================================================================
# Advanced Config (OUI VLAN, CLI Profiles)
# =====================================================================


_OUI_RE = re.compile(r"^[0-9A-Fa-f]{2}([:\-]?[0-9A-Fa-f]{2}){2}$")


class OUIVlanMappingIn(BaseModel):
    """OUI-to-VLAN mapping rule."""

    oui_prefix: str = Field(
        ..., min_length=6, max_length=8, description="OUI prefix (e.g. 'AA:BB:CC' or 'AABBCC')"
    )
    vlan_id: int = Field(..., ge=1, le=4094)
    description: str | None = None

    @field_validator("oui_prefix")
    @classmethod
    def validate_oui(cls, v: str) -> str:
        if not _OUI_RE.match(v):
            raise ValueError(
                "OUI prefix must be 6 hex characters, optionally separated by ':' or '-' (e.g. 'AA:BB:CC')"
            )
        return v


class OUIVlanApplyIn(BaseModel):
    """Apply OUI-based VLAN assignment to connected clients."""

    mappings: list[OUIVlanMappingIn]
    dry_run: bool = Field(False, description="Preview changes without applying")


@router.post("/{switch_id}/oui-vlan/apply")
async def apply_oui_vlan_assignment(
    switch_id: str,
    data: OUIVlanApplyIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Apply OUI-based VLAN assignment to switch ports based on connected client MAC addresses.

    For each connected client, check MAC against OUI mappings and configure
    the port's native VLAN accordingly.
    """
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)

    # Normalize OUI prefixes
    normalized_mappings: list[dict[str, Any]] = []
    for m in data.mappings:
        oui = m.oui_prefix.upper().replace(":", "").replace("-", "")[:6]
        normalized_mappings.append({"oui": oui, "vlan_id": m.vlan_id, "description": m.description})

    try:
        async with adapter:
            # Get connected clients
            all_clients = await adapter.get_clients()
            mac = device.mac_address
            switch_clients = [
                c for c in all_clients if (isinstance(c, dict) and c.get("switch_mac") == mac)
            ]

            # Match clients to OUI mappings
            changes: list[dict[str, Any]] = []
            for client in switch_clients:
                client_mac = (
                    (client.get("mac_address") or client.get("mac", ""))
                    .upper()
                    .replace(":", "")
                    .replace("-", "")
                )
                client_oui = client_mac[:6]
                for mapping in normalized_mappings:
                    if client_oui == mapping["oui"]:
                        port = client.get("switch_port")
                        if port is not None:
                            changes.append(
                                {
                                    "port": port,
                                    "mac": client.get("mac_address") or client.get("mac"),
                                    "name": client.get("name") or client.get("hostname"),
                                    "oui": mapping["oui"],
                                    "vlan_id": mapping["vlan_id"],
                                    "description": mapping["description"],
                                }
                            )
                        break

            if data.dry_run:
                return {"success": True, "dry_run": True, "changes": changes}

            # Apply VLAN changes via adapter method (no direct _client access)
            applied = 0
            for change in changes:
                try:
                    result = await adapter.update_switch_port_overrides(
                        device.mac_address,
                        change["port"],
                        {"nativeNetworkId": str(change["vlan_id"])},
                    )
                    if result.success:
                        applied += 1
                    else:
                        logger.warning(
                            "Failed to set VLAN %d on port %d: %s",
                            change["vlan_id"],
                            change["port"],
                            result.message,
                        )
                except Exception:
                    logger.warning(
                        "Failed to set VLAN %d on port %d", change["vlan_id"], change["port"]
                    )

    except Exception as e:
        logger.error("OUI VLAN assignment error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    return {"success": True, "changes": changes, "applied": applied}


# =====================================================================
# Running Config
# =====================================================================


@router.get("/{switch_id}/running-config")
async def get_running_config(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get the running configuration of a switch for backup/diff purposes."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.get_running_config(device.mac_address)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        # FSDN-M1: redact secret-bearing sections (dot1x/RADIUS, hotspot/captive-
        # portal, raw detail) before returning to a network:read caller — matching
        # the gateway get_controller_config _scrub path.
        from app.core.redaction import redact_secrets

        return redact_secrets(getattr(result, "value", result) or {})
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_running_config error for %s: %s", switch_id, e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


# =====================================================================
# Port Profiles CRUD
# =====================================================================


@router.get("/{switch_id}/port-profiles")
async def get_port_profiles(
    switch_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """List all port profiles available on this switch's controller."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.get_port_profiles()
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or []
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_port_profiles error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.post("/{switch_id}/port-profiles", status_code=201)
async def create_port_profile(
    switch_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Create a new port profile on the controller."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.create_port_profile(config)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("create_port_profile error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.put("/{switch_id}/port-profiles/{profile_id}")
async def update_port_profile(
    switch_id: str,
    profile_id: str,
    config: dict[str, Any],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update an existing port profile."""
    config = _validate_passthrough_config(config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.update_port_profile(profile_id, config)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("update_port_profile error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.delete("/{switch_id}/port-profiles/{profile_id}")
async def delete_port_profile(
    switch_id: str,
    profile_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Delete a port profile."""
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.delete_port_profile(profile_id)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("delete_port_profile error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


# =====================================================================
# CLI Profile Apply
# =====================================================================


class CLIProfileIn(BaseModel):
    """CLI configuration profile to apply to switch ports."""

    name: str = Field(..., description="Profile name")
    # bound the batch — matches the established sibling caps
    # (devices.py device_ids / poe.py port_ids both use max_length=500) so a
    # stray or hostile network:write caller cannot fan out unbounded live
    # controller PATCH calls. Items are non-negative and de-duplicated below.
    port_indices: list[int] = Field(
        ..., min_length=1, max_length=500, description="Target port numbers"
    )
    config: dict[str, Any] = Field(..., description="Port configuration to apply")

    @field_validator("port_indices")
    @classmethod
    def _bound_port_indices(cls, v: list[int]) -> list[int]:
        if any(p < 0 for p in v):
            raise ValueError("port_indices must be non-negative")
        # de-dup preserving order so duplicate elements don't multiply PATCH calls
        return list(dict.fromkeys(v))


@router.post("/{switch_id}/cli-profile/apply")
async def apply_cli_profile(
    switch_id: str,
    data: CLIProfileIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Apply a batch CLI configuration profile to multiple switch ports.

    Applies the given configuration dict to all specified ports using
    the adapter's port profile override mechanism.
    """
    # bound the free-form CLI config payload (key-count + nesting depth)
    # before relaying it to the switch — parity with the other passthrough sinks
    # (raises 422 if oversized). Operator-gated + staged downstream, so this is a
    # self-DoS-bound parity fix, not an injection gate.
    _validate_passthrough_config(data.config)
    device = await _get_switch(session, switch_id, _org_id(_user), _user)
    adapter = await _get_adapter_for_device(device)

    results: list[dict[str, Any]] = []
    try:
        async with adapter:
            for port_idx in data.port_indices:
                try:
                    result = await adapter.update_switch_port_overrides(
                        device.mac_address,
                        port_idx,
                        data.config,
                    )
                    results.append(
                        {
                            "port": port_idx,
                            "success": result.success,
                            **({"error": result.message} if not result.success else {}),
                        }
                    )
                except Exception as e:
                    results.append({"port": port_idx, "success": False, "error": str(e)})
    except Exception as e:
        logger.error("CLI profile apply error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    succeeded = sum(1 for r in results if r["success"])
    return {
        "success": succeeded > 0,
        "profile_name": data.name,
        "total_ports": len(data.port_indices),
        "succeeded": succeeded,
        "failed": len(data.port_indices) - succeeded,
        "results": results,
    }
