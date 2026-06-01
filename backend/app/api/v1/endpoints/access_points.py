# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Access Points Management API
============================================

Full AP control: listing, detail, radio config, SSID overrides,
mesh, LED, LAN port, RF scan, clients, adopt, locate, reboot.

Frontend expects these routes under ``/access-points/``.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.crypto import decrypt_credential, is_encrypted
from app.core.dependencies import (
    require_permissions,
)
from app.core.site_access import assert_can_access_site
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models.core import Site
from app.models.devices import (
    Device,
    DeviceStatus,
    DeviceType,
)
from app.services.adapter_factory import get_adapter

logger = logging.getLogger(__name__)
router = APIRouter()


# =====================================================================
# Schemas
# =====================================================================


class RadioOut(BaseModel):
    band: str | None = None
    channel: int | None = None
    channel_width: int | None = None
    tx_power: int | None = None
    tx_power_mode: str | None = None
    clients: int = 0


class APSummaryOut(BaseModel):
    id: str
    name: str
    model: str | None = None
    vendor: str | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    site_id: str | None = None
    site_name: str | None = None
    controller_id: str | None = None
    status: str = "unknown"
    firmware_version: str | None = None
    clients: int = 0
    uptime: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    mesh_enabled: bool = False
    led_enabled: bool | None = None
    radios: list[RadioOut] = Field(default_factory=list)
    update_available: bool = False


class APDetailOut(BaseModel):
    id: str
    name: str
    model: str | None = None
    vendor: str | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    serial_number: str | None = None
    site_id: str | None = None
    controller_id: str | None = None
    status: str = "unknown"
    firmware_version: str | None = None
    clients: int = 0
    uptime: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    mesh_enabled: bool = False
    led_enabled: bool | None = None
    radios: list[RadioOut] = Field(default_factory=list)
    lan_port_vlan_enabled: bool = False
    lan_port_vlan_id: int | None = None
    lan_port_poe_enabled: bool | None = None
    ssid_overrides: list[dict[str, Any]] = Field(default_factory=list)
    location: dict[str, Any] | None = None


class APClientOut(BaseModel):
    mac_address: str
    name: str | None = None
    ip_address: str | None = None
    ssid: str | None = None
    band: str | None = None
    signal: int | None = None
    rx_rate: float | None = None
    tx_rate: float | None = None
    download: int | None = None
    upload: int | None = None
    vlan_id: int | None = None
    uptime: int | None = None


class RadioUpdateIn(BaseModel):
    channel: int | None = None
    channel_width: int | None = None
    tx_power: int | None = None
    tx_power_mode: str | None = None


class LanPortUpdateIn(BaseModel):
    vlan_enable: bool | None = None
    vlan_id: int | None = None
    poe_enable: bool | None = None


class SSIDOverrideIn(BaseModel):
    ssid_id: str
    enabled: bool


class MeshUpdateIn(BaseModel):
    enabled: bool


class LEDUpdateIn(BaseModel):
    setting: int = Field(..., ge=0, le=2, description="0=off, 1=on, 2=site_settings")


class LocationUpdateIn(BaseModel):
    latitude: float
    longitude: float


class APNameUpdateIn(BaseModel):
    name: str


# =====================================================================
# Helpers
# =====================================================================


def _org_id(user: Any) -> Any:
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
    """Create adapter from device's controller credentials."""
    from app.services.adapter_base import GatewayServiceBase

    ctrl = device.controller
    if not ctrl:
        raise HTTPException(404, detail="Device has no controller")

    # SSRF gate — mirrors GatewayServiceBase enforcement so direct
    # adapter callers reject loopback / metadata hosts even on the
    # legacy switch/AP path.
    GatewayServiceBase._validate_controller_host(ctrl.host or "")

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


async def _get_ap(session: AsyncSession, ap_id: str, current_user: Any) -> Device:
    """Load AP device with controller eagerly loaded, scoped to org + site grant."""
    result = await session.execute(
        select(Device)
        .options(selectinload(Device.controller), selectinload(Device.site))
        .where(
            Device.id == ap_id,
            Device.device_type == DeviceType.ACCESS_POINT,
            Device.deleted_at.is_(None),
            Device.site_id.in_(_org_site_filter(_org_id(current_user))),
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, detail="Access point not found")
    # a site-limited user may only touch APs in granted sites.
    assert_can_access_site(current_user, device.site_id, detail="Access point not found")
    return device


def _device_to_summary(d: Device) -> APSummaryOut:
    """Convert a Device ORM record to APSummaryOut."""
    meta = d.device_metadata or {}
    radios_raw = meta.get("radios") or meta.get("radioConfig") or []
    radios = []
    if isinstance(radios_raw, list):
        for r in radios_raw:
            radios.append(
                RadioOut(
                    band=r.get("band"),
                    channel=r.get("channel"),
                    channel_width=r.get("channelWidth") or r.get("channel_width"),
                    tx_power=r.get("txPower") or r.get("tx_power"),
                    tx_power_mode=r.get("txPowerMode") or r.get("tx_power_mode"),
                    clients=r.get("clients", 0),
                )
            )

    # Build radios from per-band Omada fields when radioConfig / radios is absent
    if not radios:
        _CW_MAP = {"0": 20, "1": 20, "2": 40, "3": 20, "4": 40, "5": 80, "6": 80, "7": 160}
        for band_suffix, band_label in [
            ("2g", "2.4 GHz"),
            ("5g", "5 GHz"),
            ("5g2", "5 GHz-2"),
            ("6g", "6 GHz"),
        ]:
            rs = meta.get(f"radioSetting{band_suffix}")
            wp = meta.get(f"wp{band_suffix}")
            if not rs:
                continue
            if not rs.get("radioEnable", True):
                continue
            actual_ch = ""
            channel_int = 0
            if wp and wp.get("actualChannel"):
                actual_ch = str(wp["actualChannel"]).strip()
                try:
                    channel_int = int(actual_ch.split()[0])
                except (ValueError, IndexError):
                    channel_int = 0
            else:
                try:
                    channel_int = int(rs.get("channel", 0))
                except (ValueError, TypeError):
                    channel_int = 0
            cw_raw = str(rs.get("channelWidth", "0"))
            channel_width = _CW_MAP.get(cw_raw, int(cw_raw) if cw_raw.isdigit() else 0)
            if wp and wp.get("bandWidth"):
                bw_str = str(wp["bandWidth"]).replace("MHz", "").strip()
                if bw_str.isdigit():
                    channel_width = int(bw_str)
            radios.append(
                RadioOut(
                    band=band_label,
                    channel=channel_int,
                    channel_width=channel_width,
                    tx_power=rs.get("txPower"),
                    tx_power_mode=None,
                    clients=meta.get(f"clientNum{band_suffix}", 0),
                )
            )

    return APSummaryOut(
        id=str(d.id),
        name=d.name,
        model=d.model,
        vendor=d.manufacturer,
        mac_address=d.mac_address,
        ip_address=d.ip_address,
        site_id=str(d.site_id) if d.site_id else None,
        site_name=d.site.name if d.site else None,
        controller_id=str(d.controller_id) if d.controller_id else None,
        status=d.status or "unknown",
        firmware_version=d.firmware_version,
        clients=meta.get("clientNum") or meta.get("clients") or 0,
        uptime=d.uptime_seconds or meta.get("uptimeLong") or 0,
        cpu_usage=d.cpu_usage_percent or meta.get("cpuUtil") or 0,
        memory_usage=d.memory_usage_percent or meta.get("memUtil") or 0,
        mesh_enabled=meta.get("meshEnabled", False),
        led_enabled=meta.get("ledSetting") == 1 if meta.get("ledSetting") is not None else None,
        radios=radios,
        update_available=bool(meta.get("firmwareUpdateAvailable")),
    )


# =====================================================================
# Routes — List & Detail
# =====================================================================


class PaginatedAPResponse(BaseModel):
    items: list[APSummaryOut]
    total: int
    page: int
    per_page: int


@router.get("/", response_model=PaginatedAPResponse)
async def list_access_points(
    site_id: str | None = Query(None),
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """List all access points with radio/client summary (paginated)."""
    base = select(Device).where(
        Device.device_type == DeviceType.ACCESS_POINT,
        Device.deleted_at.is_(None),
        tenant_filter(Device, _user),  # org + per-user site grant
    )
    if site_id:
        base = base.where(Device.site_id == site_id)
    if status:
        base = base.where(Device.status == status)

    # Total count
    count_result = await session.execute(select(func.count()).select_from(base.subquery()))
    total = count_result.scalar() or 0

    # Paginated query with eager loading
    q = (
        base.options(
            selectinload(Device.site),
            selectinload(Device.controller),
        )
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    result = await session.execute(q)
    devices = result.scalars().all()

    return PaginatedAPResponse(
        items=[_device_to_summary(d) for d in devices],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{ap_id}", response_model=APDetailOut)
async def get_access_point(
    ap_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get detailed AP info including live data from controller."""
    device = await _get_ap(session, ap_id, _user)
    meta = device.device_metadata or {}

    # Try to fetch live detail from controller
    live_detail: dict[str, Any] = {}
    try:
        adapter = await _get_adapter_for_device(device)
        async with adapter:
            live_detail = await adapter.get_ap_detail(device.mac_address)
    except Exception as e:
        logger.warning("Could not fetch live AP detail for %s: %s", ap_id, e)

    # Merge live data with DB data
    radios_raw = live_detail.get("radios") or meta.get("radios") or meta.get("radioConfig") or []
    radios = []
    if isinstance(radios_raw, list):
        for r in radios_raw:
            radios.append(
                RadioOut(
                    band=r.get("band"),
                    channel=r.get("channel"),
                    channel_width=r.get("channelWidth") or r.get("channel_width"),
                    tx_power=r.get("txPower") or r.get("tx_power"),
                    tx_power_mode=r.get("txPowerMode") or r.get("tx_power_mode"),
                    clients=r.get("clients", 0),
                )
            )

    ssid_overrides: list[dict[str, Any]] = []
    try:
        adapter = await _get_adapter_for_device(device)
        async with adapter:
            ssid_overrides = await adapter.get_ap_ssid_overrides(device.mac_address)
    except Exception as e:
        logger.warning("Could not fetch live SSID overrides for %s: %s", ap_id, e)

    return APDetailOut(
        id=str(device.id),
        name=device.name,
        model=device.model,
        vendor=device.manufacturer,
        mac_address=device.mac_address,
        ip_address=device.ip_address,
        serial_number=device.serial_number,
        site_id=str(device.site_id) if device.site_id else None,
        controller_id=str(device.controller_id) if device.controller_id else None,
        status=live_detail.get("status") or device.status or "unknown",
        firmware_version=live_detail.get("firmware_version") or device.firmware_version,
        clients=live_detail.get("clients") or meta.get("clientNum") or 0,
        uptime=live_detail.get("uptime") or device.uptime_seconds or 0,
        cpu_usage=live_detail.get("cpu_usage") or device.cpu_usage_percent or 0,
        memory_usage=live_detail.get("memory_usage") or device.memory_usage_percent or 0,
        mesh_enabled=live_detail.get("mesh_enabled", meta.get("meshEnabled", False)),
        led_enabled=live_detail.get("led_enabled"),
        radios=radios,
        lan_port_vlan_enabled=live_detail.get("lan_port_vlan_enabled", False),
        lan_port_vlan_id=live_detail.get("lan_port_vlan_id"),
        lan_port_poe_enabled=live_detail.get("lan_port_poe_enabled"),
        ssid_overrides=ssid_overrides,
        location=meta.get("location"),
    )


# =====================================================================
# Routes — Clients
# =====================================================================


@router.get("/{ap_id}/clients", response_model=list[APClientOut])
async def get_ap_clients(
    ap_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get clients currently connected to this AP."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            clients = await adapter.get_ap_clients(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    return [
        APClientOut(
            mac_address=c.get("mac_address") or c.get("mac", ""),
            name=c.get("name") or c.get("hostname"),
            ip_address=c.get("ip_address") or c.get("ip"),
            ssid=c.get("ssid"),
            band=c.get("band"),
            signal=c.get("signal") or c.get("rssi"),
            rx_rate=c.get("rx_rate") or c.get("rxRate"),
            tx_rate=c.get("tx_rate") or c.get("txRate"),
            download=c.get("download"),
            upload=c.get("upload"),
            vlan_id=c.get("vlan_id") or c.get("vid"),
            uptime=c.get("uptime"),
        )
        for c in clients
    ]


# =====================================================================
# Routes — Radio Config
# =====================================================================


@router.get("/{ap_id}/radios", response_model=list[RadioOut])
async def get_ap_radios(
    ap_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get radio configuration for all bands on this AP."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            radios = await adapter.get_ap_radios(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    return [
        RadioOut(
            band=r.get("band"),
            channel=r.get("channel"),
            channel_width=r.get("channelWidth") or r.get("channel_width"),
            tx_power=r.get("txPower") or r.get("tx_power"),
            tx_power_mode=r.get("txPowerMode") or r.get("tx_power_mode"),
            clients=r.get("clients", 0),
        )
        for r in radios
    ]


@router.patch("/{ap_id}/radios/{band}")
async def update_ap_radio(
    ap_id: str,
    band: str,
    data: RadioUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update radio settings for a specific band (2g, 5g, 5g2, 6g)."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    config: dict[str, Any] = {}
    if data.channel is not None:
        config["channel"] = data.channel
    if data.channel_width is not None:
        config["channelWidth"] = data.channel_width
    if data.tx_power is not None:
        config["txPower"] = data.tx_power
    if data.tx_power_mode is not None:
        config["txPowerMode"] = data.tx_power_mode

    try:
        async with adapter:
            result = await adapter.update_ap_radio(device.mac_address, band, config)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("Radio update failed: %s", result.message)
        raise HTTPException(502, detail="Radio update failed")
    return {"success": True, "band": band}


# =====================================================================
# Routes — SSID Overrides
# =====================================================================


@router.get("/{ap_id}/ssid-overrides")
async def get_ap_ssid_overrides(
    ap_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get per-AP SSID overrides (which WLANs are enabled/disabled on this AP)."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            overrides = await adapter.get_ap_ssid_overrides(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    return overrides


@router.put("/{ap_id}/ssid-overrides")
async def update_ap_ssid_overrides(
    ap_id: str,
    overrides: list[SSIDOverrideIn],
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Set per-AP SSID overrides."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    payload = [{"ssidId": o.ssid_id, "enabled": o.enabled} for o in overrides]

    try:
        async with adapter:
            result = await adapter.update_ap_ssid_override(device.mac_address, payload)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("SSID override update failed: %s", result.message)
        raise HTTPException(502, detail="SSID override update failed")
    return {"success": True}


# =====================================================================
# Routes — LAN Port
# =====================================================================


@router.get("/{ap_id}/lan-port")
async def get_ap_lan_port(
    ap_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get AP LAN port settings (VLAN, PoE passthrough)."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            lan_port = await adapter.get_ap_lan_port(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    return lan_port


@router.patch("/{ap_id}/lan-port")
async def update_ap_lan_port(
    ap_id: str,
    data: LanPortUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update AP LAN port settings (VLAN tagging, PoE passthrough)."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    config: dict[str, Any] = {}
    if data.vlan_enable is not None:
        config["localVlanEnable"] = data.vlan_enable
    if data.vlan_id is not None:
        config["localVlanId"] = data.vlan_id
    if data.poe_enable is not None:
        config["poeEnable"] = data.poe_enable

    try:
        async with adapter:
            result = await adapter.configure_ap_lan_port(device.mac_address, config)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("LAN port update failed: %s", result.message)
        raise HTTPException(502, detail="LAN port update failed")
    return {"success": True}


# =====================================================================
# Routes — Mesh
# =====================================================================


@router.patch("/{ap_id}/mesh")
async def update_ap_mesh(
    ap_id: str,
    data: MeshUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Enable/disable mesh networking on this AP."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.set_ap_mesh(device.mac_address, data.enabled)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("Mesh update failed: %s", result.message)
        raise HTTPException(502, detail="Mesh update failed")
    return {"success": True, "mesh_enabled": data.enabled}


# =====================================================================
# Routes — LED
# =====================================================================


@router.patch("/{ap_id}/led")
async def update_ap_led(
    ap_id: str,
    data: LEDUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Set AP LED mode (0=off, 1=on, 2=site_settings)."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.set_device_led(device.mac_address, data.setting)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("LED update failed: %s", result.message)
        raise HTTPException(502, detail="LED update failed")
    return {"success": True, "led_setting": data.setting}


# =====================================================================
# Routes — Location
# =====================================================================


@router.patch("/{ap_id}/location")
async def update_ap_location(
    ap_id: str,
    data: LocationUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Set AP geographical location."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.set_ap_location(
                device.mac_address, data.latitude, data.longitude
            )
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("Location update failed: %s", result.message)
        raise HTTPException(502, detail="Location update failed")

    # Update DB metadata
    meta = dict(device.device_metadata or {})
    meta["location"] = {"latitude": data.latitude, "longitude": data.longitude}
    device.device_metadata = meta
    await session.commit()

    return {"success": True}


# =====================================================================
# Routes — RF Scan
# =====================================================================


@router.get("/{ap_id}/rf-scan")
async def get_ap_rf_scan(
    ap_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get RF scan results for this AP."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            scan = await adapter.get_ap_rf_scan(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    return scan


# =====================================================================
# Routes — Device Actions
# =====================================================================


@router.post("/{ap_id}/reboot")
async def reboot_ap(
    ap_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
    confirm: bool = False,
) -> Any:
    """Reboot this access point."""
    # rebooting disrupts the AP/site — require explicit confirm, matching
    # the device-reboot / forget_ap / upgrade-firmware gates.
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Rebooting disrupts the AP; pass confirm=true to proceed.",
        )
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.reboot_device(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("AP reboot failed: %s", result.message)
        raise HTTPException(502, detail="Reboot failed")
    return {"success": True, "message": f"Reboot initiated for {device.name}"}


@router.post("/{ap_id}/locate")
async def locate_ap(
    ap_id: str,
    duration: int = Query(30, ge=5, le=120),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Flash LEDs to physically locate the AP."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.locate_device(device.mac_address, duration)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("AP locate failed: %s", result.message)
        raise HTTPException(502, detail="Locate failed")
    return {"success": True, "duration": duration}


@router.post("/{ap_id}/adopt")
async def adopt_ap(
    ap_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Adopt a pending AP into the controller."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.adopt_device(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("AP adoption failed: %s", result.message)
        raise HTTPException(502, detail="Adoption failed")

    device.is_adopted = True
    device.status = DeviceStatus.ADOPTING
    await session.commit()

    return {"success": True, "message": f"Adoption initiated for {device.name}"}


@router.post("/{ap_id}/forget")
async def forget_ap(
    ap_id: str,
    confirmed: bool = Query(
        False,
        description="Must be true: forgetting an AP unadopts it and drops its config (irreversible).",
    ),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Forget (remove) this AP from the controller."""
    device = await _get_ap(session, ap_id, _user)
    # Catastrophic-op preflight: unadopting drops the AP's config and requires
    # re-adoption. Mirror the staged Omada preflight (bulk.device.forget is
    # CATASTROPHIC) — block on a single network:write toggle unless the caller
    # supplies an explicit second-factor confirmation.
    if not confirmed:
        raise HTTPException(
            status_code=409,
            detail=(
                "Forgetting an access point is irreversible (it is unadopted and its "
                "config is dropped; the device must be re-adopted). Re-issue with "
                "confirmed=true to proceed."
            ),
        )
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.forget_device(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("AP forget failed: %s", result.message)
        raise HTTPException(502, detail="Forget failed")

    device.is_adopted = False
    device.status = DeviceStatus.UNKNOWN
    await session.commit()

    return {"success": True, "message": f"Device {device.name} forgotten"}


@router.post("/{ap_id}/upgrade")
async def upgrade_ap_firmware(
    ap_id: str,
    confirmed: bool = Query(
        False,
        description="Must be true: flashing firmware reboots the AP and risks bricking it.",
    ),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("firmware:upgrade")),
) -> Any:
    """Trigger firmware upgrade on this AP."""
    device = await _get_ap(session, ap_id, _user)
    # Catastrophic-op preflight: a firmware flash reboots the AP and can brick it,
    # and is not undoable. Mirror the staged Omada preflight (firmware.upgrade is
    # CATASTROPHIC) — block unless the caller supplies an explicit confirmation.
    if not confirmed:
        raise HTTPException(
            status_code=409,
            detail=(
                "Flashing AP firmware reboots the device and can brick it (not undoable). "
                "Re-issue with confirmed=true to proceed."
            ),
        )
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.upgrade_firmware(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    if not result.success:
        logger.error("AP firmware upgrade failed: %s", result.message)
        raise HTTPException(502, detail="Firmware upgrade failed")
    return {"success": True, "message": f"Firmware upgrade initiated for {device.name}"}


@router.get("/{ap_id}/firmware")
async def get_ap_firmware_info(
    ap_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:read")),
) -> Any:
    """Get firmware update status for this AP."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            info = await adapter.get_firmware_info(device.mac_address)
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")

    return info


@router.patch("/{ap_id}/name")
async def update_ap_name(
    ap_id: str,
    data: APNameUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(require_permissions("network:write")),
) -> Any:
    """Update AP display name (pushes to controller)."""
    device = await _get_ap(session, ap_id, _user)
    adapter = await _get_adapter_for_device(device)
    site_id = None

    ctrl_synced = True
    ctrl_warning: str | None = None
    try:
        async with adapter:
            site_id = await adapter._ensure_site_id()
            if site_id:
                from app.adapters.omada.utils import normalize_mac

                mac = normalize_mac(device.mac_address)
                await adapter._client.update_ap(site_id, mac, {"name": data.name})
    except Exception as e:
        ctrl_synced = False
        ctrl_warning = f"Local DB updated but controller write failed: {e}"
        logger.warning("Failed to push name to controller: %s", e)

    device.name = data.name
    await session.commit()
    return {
        "success": True,
        "name": data.name,
        "controller_synced": ctrl_synced,
        "controller_warning": ctrl_warning,
    }
