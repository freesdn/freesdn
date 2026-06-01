# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - PoE Management API
=================================

Dedicated PoE-centric views: per-switch PoE budgets, per-port PoE
status, bulk PoE control, and PoE scheduling.

Frontend expects these routes under ``/poe/``.
"""

from __future__ import annotations

import logging
from datetime import UTC
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.adapter_result import raise_for_adapter_result
from app.core.crypto import decrypt_credential, is_encrypted
from app.core.dependencies import (
    get_current_active_user,
)
from app.core.site_access import assert_can_access_site
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models.core import Site
from app.models.devices import (
    Device,
    DevicePort,
    DeviceType,
)
from app.services.adapter_factory import get_adapter

logger = logging.getLogger(__name__)
router = APIRouter()


# =====================================================================
# Schemas
# =====================================================================


class PoESwitchSummaryOut(BaseModel):
    device_id: str
    device_name: str
    model: str | None = None
    power_budget: float = 0.0
    power_used: float = 0.0
    power_available: float = 0.0
    power_percentage: float = 0.0
    total_poe_ports: int = 0
    active_poe_ports: int = 0
    disabled_poe_ports: int = 0
    fault_poe_ports: int = 0
    near_budget: bool = False
    over_budget: bool = False


class PoEPortStatusOut(BaseModel):
    port_id: str
    port_index: int
    port_name: str
    device_id: str
    device_name: str
    poe_enabled: bool = False
    poe_mode: str = "auto"
    poe_status: str = "disabled"
    power_draw: float = 0.0
    power_limit: float = 0.0
    power_class: int | None = None
    voltage: float | None = None
    current: float | None = None
    pd_type: str | None = None


class PoEPortUpdateIn(BaseModel):
    poe_enabled: bool | None = None
    poe_mode: str | None = None
    power_limit: float | None = None
    priority: int | None = None


class PoEBulkUpdateIn(BaseModel):
    port_ids: list[str] = Field(..., max_length=500)
    poe_enabled: bool | None = None
    poe_mode: str | None = None
    power_limit: float | None = None


class PoEScheduleOut(BaseModel):
    id: str
    name: str
    description: str | None = None
    port_ids: list[str] = Field(default_factory=list)
    schedule_type: str = "daily"
    days_of_week: list[int] = Field(default_factory=list)
    start_time: str = "00:00"
    end_time: str = "23:59"
    action: str = "disable"
    is_enabled: bool = True
    affected_ports: int = 0
    next_trigger: str | None = None


# =====================================================================
# Helpers
# =====================================================================


def _org_id(user: Any) -> UUID:
    """Extract organization_id, raising 400 if missing."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _require_admin(user: Any) -> None:
    from app.models.core import UserRole

    # Scope ceiling: PoE writes (port config, power cycle,
    # bulk toggle, schedule CRUD) must not be reachable by a deliberately read-only
    # scoped key via its owner's raw role. Matches firmware/ztp/radius.
    if getattr(user, "is_scoped", False):
        raise HTTPException(
            status_code=403, detail="Scoped API keys cannot satisfy role-based gates"
        )
    if getattr(user, "role", None) not in (UserRole.ORG_ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=403, detail="Admin access required")


def _org_site_filter(organization_id: UUID) -> Any:
    """Subquery of site IDs for the given organization."""
    return (
        select(Site.id)
        .where(
            Site.organization_id == organization_id,
            Site.deleted_at.is_(None),
        )
        .scalar_subquery()
    )


def _build_port_status(port: DevicePort, device: Device) -> PoEPortStatusOut:
    meta = port.port_metadata or {}
    is_active = port.is_poe_enabled and (port.poe_power_watts or 0) > 0

    poe_status = "disabled"
    if port.is_poe_enabled:
        poe_status = "delivering" if is_active else "searching"
        if meta.get("poeFault"):
            poe_status = "fault"

    return PoEPortStatusOut(
        port_id=str(port.id),
        port_index=port.port_number,
        port_name=port.name or f"Port {port.port_number}",
        device_id=str(device.id),
        device_name=device.name,
        poe_enabled=port.is_poe_enabled,
        poe_mode=meta.get("poeMode") or "auto",
        poe_status=poe_status,
        power_draw=port.poe_power_watts or 0.0,
        power_limit=meta.get("poePowerLimit") or 30.0,
        power_class=port.poe_class,
        voltage=meta.get("poeVoltage"),
        current=meta.get("poeCurrent"),
        pd_type=meta.get("pdType"),
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
    ctrl = device.controller
    if not ctrl:
        raise HTTPException(404, detail="Device has no controller")

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
# Routes
# =====================================================================


@router.get("/devices", response_model=list[PoESwitchSummaryOut])
async def list_poe_switches(
    site_id: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """List switches / gateways with PoE budget summaries."""
    q = (
        select(Device)
        .options(selectinload(Device.ports))
        .where(
            Device.device_type.in_([DeviceType.SWITCH, DeviceType.GATEWAY]),
            Device.deleted_at.is_(None),
            tenant_filter(Device, _user),
        )
    )
    if site_id:
        q = q.where(Device.site_id == site_id)

    result = await session.execute(q)
    devices = result.scalars().all()

    out: list[PoESwitchSummaryOut] = []
    for d in devices:
        ports = d.ports or []
        poe_ports = [
            p for p in ports if p.is_poe_enabled or (p.port_metadata or {}).get("poeSupported")
        ]
        if not poe_ports:
            continue

        meta = d.device_metadata or {}
        budget = meta.get("poeBudget") or meta.get("poeTotalPower") or meta.get("poe_budget") or 0
        used = sum(p.poe_power_watts or 0 for p in poe_ports if p.is_poe_enabled)
        available = max(0, budget - used)
        pct = (used / budget * 100) if budget else 0

        active = sum(1 for p in poe_ports if p.is_poe_enabled and (p.poe_power_watts or 0) > 0)
        disabled = sum(1 for p in poe_ports if not p.is_poe_enabled)
        fault = sum(1 for p in poe_ports if (p.port_metadata or {}).get("poeFault"))

        out.append(
            PoESwitchSummaryOut(
                device_id=str(d.id),
                device_name=d.name,
                model=d.model,
                power_budget=budget,
                power_used=used,
                power_available=available,
                power_percentage=round(pct, 1),
                total_poe_ports=len(poe_ports),
                active_poe_ports=active,
                disabled_poe_ports=disabled,
                fault_poe_ports=fault,
                near_budget=80 <= pct < 100,
                over_budget=pct >= 100,
            )
        )

    return out


@router.get("/devices/{device_id}", response_model=PoESwitchSummaryOut)
async def get_poe_switch(
    device_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    org_id = _org_id(_user)
    result = await session.execute(
        select(Device)
        .options(selectinload(Device.ports))
        .where(
            Device.id == device_id,
            Device.deleted_at.is_(None),
            Device.site_id.in_(_org_site_filter(org_id)),
        )
    )
    d = result.scalar_one_or_none()
    if not d:
        raise HTTPException(404, detail="Device not found")
    # Per-user site grant: site-limited callers may not read sibling-site devices.
    assert_can_access_site(_user, d.site_id, detail="Device not found")

    ports = d.ports or []
    poe_ports = [
        p for p in ports if p.is_poe_enabled or (p.port_metadata or {}).get("poeSupported")
    ]
    meta = d.device_metadata or {}
    budget = meta.get("poeBudget") or meta.get("poeTotalPower") or 0
    used = sum(p.poe_power_watts or 0 for p in poe_ports if p.is_poe_enabled)
    pct = (used / budget * 100) if budget else 0

    return PoESwitchSummaryOut(
        device_id=str(d.id),
        device_name=d.name,
        model=d.model,
        power_budget=budget,
        power_used=used,
        power_available=max(0, budget - used),
        power_percentage=round(pct, 1),
        total_poe_ports=len(poe_ports),
        active_poe_ports=sum(
            1 for p in poe_ports if p.is_poe_enabled and (p.poe_power_watts or 0) > 0
        ),
        disabled_poe_ports=sum(1 for p in poe_ports if not p.is_poe_enabled),
        fault_poe_ports=sum(1 for p in poe_ports if (p.port_metadata or {}).get("poeFault")),
        near_budget=80 <= pct < 100,
        over_budget=pct >= 100,
    )


@router.get("/devices/{device_id}/ports", response_model=list[PoEPortStatusOut])
async def get_poe_device_ports(
    device_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """Get PoE status for all ports on a device."""
    org_id = _org_id(_user)
    dev_result = await session.execute(
        select(Device).where(
            Device.id == device_id,
            Device.deleted_at.is_(None),
            Device.site_id.in_(_org_site_filter(org_id)),
        )
    )
    device = dev_result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, detail="Device not found")
    # Per-user site grant: site-limited callers may not read sibling-site devices.
    assert_can_access_site(_user, device.site_id, detail="Device not found")

    result = await session.execute(
        select(DevicePort).where(DevicePort.device_id == device_id).order_by(DevicePort.port_number)
    )
    ports = result.scalars().all()
    return [
        _build_port_status(p, device)
        for p in ports
        if p.is_poe_enabled or (p.port_metadata or {}).get("poeSupported")
    ]


@router.get("/ports", response_model=list[PoEPortStatusOut])
async def list_poe_ports(
    site_id: str | None = Query(None),
    device_id: str | None = Query(None),
    status: str | None = Query(None),
    enabled: bool | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """List all PoE ports with optional filtering."""
    q = (
        select(DevicePort, Device)
        .join(Device, DevicePort.device_id == Device.id)
        .where(
            Device.deleted_at.is_(None),
            tenant_filter(Device, _user),
        )
    )
    if device_id:
        q = q.where(DevicePort.device_id == device_id)
    if site_id:
        q = q.where(Device.site_id == site_id)
    if enabled is not None:
        q = q.where(DevicePort.is_poe_enabled == enabled)

    q = q.order_by(Device.name, DevicePort.port_number)
    result = await session.execute(q)
    rows = result.all()

    out = []
    for port, device in rows:
        if not port.is_poe_enabled and not (port.port_metadata or {}).get("poeSupported"):
            continue
        ps = _build_port_status(port, device)
        if status and ps.poe_status != status:
            continue
        out.append(ps)

    return out


@router.patch("/ports/{port_id}")
async def update_poe_port(
    port_id: str,
    data: PoEPortUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """Update PoE settings for a port — pushes to controller then updates DB."""
    _require_admin(_user)
    org_id = _org_id(_user)
    result = await session.execute(
        select(DevicePort)
        .options(selectinload(DevicePort.device).selectinload(Device.controller))
        .where(DevicePort.id == port_id)
    )
    port = result.scalar_one_or_none()
    if not port:
        raise HTTPException(404, detail="Port not found")

    device = port.device
    if not device:
        raise HTTPException(404, detail="Port has no parent device")

    # Verify device belongs to user's org and is not deleted
    if device.deleted_at is not None:
        raise HTTPException(404, detail="Port not found")
    site_check = await session.execute(
        select(Site.id).where(
            Site.id == device.site_id, Site.organization_id == org_id, Site.deleted_at.is_(None)
        )
    )
    if not site_check.scalar_one_or_none():
        raise HTTPException(404, detail="Port not found")
    # Per-user site grant: site-limited callers may not mutate sibling-site ports.
    assert_can_access_site(_user, device.site_id, detail="Port not found")

    # Push to controller first
    adapter = await _get_adapter_for_device(device)
    omada_config: dict[str, Any] = {}
    if data.poe_enabled is not None:
        omada_config["poe"] = {"enable": data.poe_enabled}
    if data.poe_mode is not None:
        omada_config["poeMode"] = data.poe_mode
    if data.power_limit is not None:
        omada_config["poePowerLimit"] = data.power_limit

    if omada_config:
        try:
            async with adapter:
                poe_result = await adapter.configure_switch_port(
                    device.mac_address, port.port_number, omada_config
                )
        except Exception as e:
            logger.error("Failed to push PoE config to controller: %s", e, exc_info=True)
            raise HTTPException(502, detail="Controller error")
        # CONV2-001: a non-throwing AdapterResult(success=False) must not pass as a
        # successful PoE write (raise 502 before the DB is updated below).
        raise_for_adapter_result(poe_result)

    # Update DB after successful push
    if data.poe_enabled is not None:
        port.is_poe_enabled = data.poe_enabled

    meta = dict(port.port_metadata or {})
    if data.poe_mode is not None:
        meta["poeMode"] = data.poe_mode
    if data.power_limit is not None:
        meta["poePowerLimit"] = data.power_limit
    if data.priority is not None:
        meta["poePriority"] = data.priority
    port.port_metadata = meta

    await session.commit()
    return {"success": True}


@router.post("/ports/{port_id}/reset")
async def cycle_poe_port(
    port_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """Cycle PoE on a port (disable → wait → re-enable)."""
    _require_admin(_user)
    org_id = _org_id(_user)
    result = await session.execute(
        select(DevicePort)
        .options(selectinload(DevicePort.device).selectinload(Device.controller))
        .where(DevicePort.id == port_id)
    )
    port = result.scalar_one_or_none()
    if not port or not port.device:
        raise HTTPException(404, detail="Port not found")

    device = port.device
    # Verify device belongs to user's org and is not deleted
    if device.deleted_at is not None:
        raise HTTPException(404, detail="Port not found")
    site_check = await session.execute(
        select(Site.id).where(
            Site.id == device.site_id, Site.organization_id == org_id, Site.deleted_at.is_(None)
        )
    )
    if not site_check.scalar_one_or_none():
        raise HTTPException(404, detail="Port not found")
    # Per-user site grant: site-limited callers may not cycle sibling-site ports.
    assert_can_access_site(_user, device.site_id, detail="Port not found")
    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            cycle_result = await adapter.cycle_poe_port(device.mac_address, port.port_number)
    except Exception as e:
        logger.error("Failed to cycle PoE port: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller error")
    # CONV2-001: surface a non-throwing AdapterResult(success=False).
    raise_for_adapter_result(cycle_result)

    return {"success": True}


@router.post("/ports/bulk")
async def bulk_update_poe(
    data: PoEBulkUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """Bulk update PoE settings on multiple ports — pushes to controller."""
    _require_admin(_user)
    result = await session.execute(
        select(DevicePort)
        .options(selectinload(DevicePort.device).selectinload(Device.controller))
        .join(Device, DevicePort.device_id == Device.id)
        .where(
            DevicePort.id.in_(data.port_ids),
            tenant_filter(Device, _user),
        )
    )
    ports = result.scalars().all()
    if not ports:
        raise HTTPException(404, detail="No matching ports found")

    # Group ports by device for batch push
    from collections import defaultdict

    device_ports: dict[str, list[DevicePort]] = defaultdict(list)
    for port in ports:
        device_ports[str(port.device_id)].append(port)

    errors: list[str] = []
    succeeded_device_ids: set[str] = set()
    for device_id, device_port_list in device_ports.items():
        device = device_port_list[0].device
        if not device:
            continue
        adapter = await _get_adapter_for_device(device)
        try:
            async with adapter:
                for port in device_port_list:
                    omada_config: dict[str, Any] = {}
                    if data.poe_enabled is not None:
                        omada_config["poe"] = {"enable": data.poe_enabled}
                    if data.poe_mode is not None:
                        omada_config["poeMode"] = data.poe_mode
                    if data.power_limit is not None:
                        omada_config["poePowerLimit"] = data.power_limit
                    if omada_config:
                        bulk_result = await adapter.configure_switch_port(
                            device.mac_address, port.port_number, omada_config
                        )
                        # CONV2-001: a non-throwing AdapterResult(success=False)
                        # must drop this device from the succeeded set (raises into
                        # the except below), not be recorded as a success.
                        raise_for_adapter_result(bulk_result)
            succeeded_device_ids.add(device_id)
        except Exception as e:
            errors.append(f"Device {device.name}: controller push failed")
            logger.warning("Bulk PoE push failed for device %s: %s", device.name, e)

    # Update DB only for ports whose device push succeeded
    updated_count = 0
    for port in ports:
        if str(port.device_id) not in succeeded_device_ids:
            continue
        if data.poe_enabled is not None:
            port.is_poe_enabled = data.poe_enabled
        meta = dict(port.port_metadata or {})
        if data.poe_mode is not None:
            meta["poeMode"] = data.poe_mode
        if data.power_limit is not None:
            meta["poePowerLimit"] = data.power_limit
        port.port_metadata = meta
        updated_count += 1

    await session.commit()
    resp: dict[str, Any] = {"success": len(errors) == 0, "ports_updated": updated_count}
    if errors:
        resp["warnings"] = errors
    return resp


# =====================================================================
# Schedule Schemas
# =====================================================================


class PoEScheduleCreateIn(BaseModel):
    name: str = Field(..., max_length=255)
    enabled: bool = True
    device_id: str | None = None
    device_group_id: str | None = None
    port_numbers: list[int] = Field(default_factory=list, max_length=128)
    power_off_time: str = Field(..., pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    power_on_time: str = Field(..., pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    days_of_week: list[int] = Field(default_factory=list)
    timezone: str = "UTC"

    @field_validator("port_numbers", mode="before")
    @classmethod
    def validate_port_numbers(cls, v: Any) -> Any:
        if v:
            for port in v:
                if not isinstance(port, int) or port < 1 or port > 256:
                    raise ValueError(f"port_numbers values must be integers 1-256, got {port}")
        return v

    @field_validator("days_of_week", mode="before")
    @classmethod
    def validate_days_of_week(cls, v: Any) -> Any:
        if v:
            for day in v:
                if not isinstance(day, int) or day < 0 or day > 6:
                    raise ValueError(f"days_of_week values must be integers 0-6, got {day}")
        return v

    @field_validator("timezone", mode="before")
    @classmethod
    def validate_timezone(cls, v: Any) -> Any:
        import zoneinfo

        if v and v not in zoneinfo.available_timezones():
            raise ValueError(f"Invalid timezone: {v}")
        return v

    @model_validator(mode="after")
    def validate_times_differ(self) -> PoEScheduleCreateIn:
        if self.power_off_time == self.power_on_time:
            raise ValueError("power_off_time and power_on_time must be different")
        return self


class PoEScheduleUpdateIn(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    device_id: str | None = None
    device_group_id: str | None = None
    port_numbers: list[int] | None = None
    power_off_time: str | None = Field(None, pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    power_on_time: str | None = Field(None, pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    days_of_week: list[int] | None = None
    timezone: str | None = None

    @field_validator("port_numbers", mode="before")
    @classmethod
    def validate_port_numbers(cls, v: Any) -> Any:
        if v:
            for port in v:
                if not isinstance(port, int) or port < 1 or port > 256:
                    raise ValueError(f"port_numbers values must be integers 1-256, got {port}")
        return v

    @field_validator("days_of_week", mode="before")
    @classmethod
    def validate_days_of_week(cls, v: Any) -> Any:
        if v:
            for day in v:
                if not isinstance(day, int) or day < 0 or day > 6:
                    raise ValueError(f"days_of_week values must be integers 0-6, got {day}")
        return v

    @field_validator("timezone", mode="before")
    @classmethod
    def validate_timezone(cls, v: Any) -> Any:
        import zoneinfo

        if v and v not in zoneinfo.available_timezones():
            raise ValueError(f"Invalid timezone: {v}")
        return v

    @model_validator(mode="after")
    def validate_times_differ(self) -> PoEScheduleUpdateIn:
        if self.power_off_time is not None and self.power_on_time is not None:
            if self.power_off_time == self.power_on_time:
                raise ValueError("power_off_time and power_on_time must be different")
        return self


class PoEScheduleDetailOut(BaseModel):
    id: str
    name: str
    enabled: bool = True
    device_id: str | None = None
    device_group_id: str | None = None
    port_numbers: list[int] = Field(default_factory=list)
    power_off_time: str
    power_on_time: str
    days_of_week: list[int] = Field(default_factory=list)
    timezone: str = "UTC"
    last_action: str | None = None
    last_action_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


# =====================================================================
# Schedule Routes
# =====================================================================


@router.get("/schedules", response_model=list[PoEScheduleDetailOut])
async def list_poe_schedules(
    site_id: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """List all PoE schedules for the user's organization."""
    from sqlalchemy import or_

    from app.models.poe import PoESchedule

    org_id = _org_id(_user)
    q = (
        select(PoESchedule)
        .where(
            PoESchedule.organization_id == org_id,
            PoESchedule.deleted_at.is_(None),
        )
        .order_by(PoESchedule.name)
    )
    # Per-user site grant: a PoE schedule has a site dimension only
    # through its target device. A site-limited operator may only see schedules
    # whose target device lives in a site they are granted. Org-wide /
    # device-group schedules (no single device_id) carry no site binding and
    # are reserved for non-site-limited admins — fail them closed here so a
    # site-limited operator cannot enumerate sibling-site device schedules.
    if getattr(_user, "is_site_limited", False):
        granted = list(getattr(_user, "accessible_site_ids", None) or [])
        granted_devices = (
            select(Device.id).where(Device.site_id.in_(granted)).scalar_subquery()
            if granted
            else select(Device.id).where(Device.id.is_(None)).scalar_subquery()
        )
        q = q.where(PoESchedule.device_id.in_(granted_devices))
    if site_id:
        # A schedule has a site dimension only through its target device.
        # Keep device-targeted schedules for this site, plus org-wide /
        # device-group schedules (no single device_id) which aren't site-bound.
        site_devices = select(Device.id).where(Device.site_id == site_id).scalar_subquery()
        q = q.where(
            or_(
                PoESchedule.device_id.in_(site_devices),
                PoESchedule.device_id.is_(None),
            )
        )
    result = await session.execute(q)
    schedules = result.scalars().all()

    return [
        PoEScheduleDetailOut(
            id=str(s.id),
            name=s.name,
            enabled=s.enabled,
            device_id=str(s.device_id) if s.device_id else None,
            device_group_id=str(s.device_group_id) if s.device_group_id else None,
            port_numbers=s.port_numbers or [],
            power_off_time=s.power_off_time,
            power_on_time=s.power_on_time,
            days_of_week=s.days_of_week or [],
            timezone=s.timezone or "UTC",
            last_action=s.last_action,
            last_action_at=s.last_action_at.isoformat() if s.last_action_at else None,
            created_at=s.created_at.isoformat() if s.created_at else None,
            updated_at=s.updated_at.isoformat() if s.updated_at else None,
        )
        for s in schedules
    ]


@router.post("/schedules", response_model=PoEScheduleDetailOut, status_code=201)
async def create_poe_schedule(
    data: PoEScheduleCreateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """Create a new PoE schedule."""
    _require_admin(_user)
    from app.models.enterprise import DeviceGroup
    from app.models.poe import PoESchedule

    org_id = _org_id(_user)

    # Validate device ownership
    if data.device_id:
        dev_check = await session.execute(
            select(Device.id)
            .join(Site, Device.site_id == Site.id)
            .where(Device.id == data.device_id, Site.organization_id == org_id)
        )
        if not dev_check.scalar_one_or_none():
            raise HTTPException(404, detail="Device not found")

    # Validate device group ownership
    if data.device_group_id:
        group_check = await session.execute(
            select(DeviceGroup.id).where(
                DeviceGroup.id == data.device_group_id,
                DeviceGroup.organization_id == org_id,
            )
        )
        if not group_check.scalar_one_or_none():
            raise HTTPException(404, detail="Device group not found")

    schedule = PoESchedule(
        organization_id=org_id,
        name=data.name,
        enabled=data.enabled,
        device_id=data.device_id,
        device_group_id=data.device_group_id,
        port_numbers=data.port_numbers,
        power_off_time=data.power_off_time,
        power_on_time=data.power_on_time,
        days_of_week=data.days_of_week,
        timezone=data.timezone,
    )
    session.add(schedule)
    await session.commit()

    return PoEScheduleDetailOut(
        id=str(schedule.id),
        name=schedule.name,
        enabled=schedule.enabled,
        device_id=str(schedule.device_id) if schedule.device_id else None,
        device_group_id=str(schedule.device_group_id) if schedule.device_group_id else None,
        port_numbers=schedule.port_numbers or [],
        power_off_time=schedule.power_off_time,
        power_on_time=schedule.power_on_time,
        days_of_week=schedule.days_of_week or [],
        timezone=schedule.timezone or "UTC",
        last_action=schedule.last_action,
        last_action_at=None,
        created_at=schedule.created_at.isoformat() if schedule.created_at else None,
        updated_at=schedule.updated_at.isoformat() if schedule.updated_at else None,
    )


@router.put("/schedules/{schedule_id}", response_model=PoEScheduleDetailOut)
async def update_poe_schedule(
    schedule_id: str,
    data: PoEScheduleUpdateIn,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> Any:
    """Update an existing PoE schedule."""
    _require_admin(_user)
    from app.models.enterprise import DeviceGroup
    from app.models.poe import PoESchedule

    org_id = _org_id(_user)

    result = await session.execute(
        select(PoESchedule).where(
            PoESchedule.id == schedule_id,
            PoESchedule.organization_id == org_id,
            PoESchedule.deleted_at.is_(None),
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(404, detail="Schedule not found")

    # Validate device ownership if being updated
    if data.device_id is not None:
        dev_check = await session.execute(
            select(Device.id)
            .join(Site, Device.site_id == Site.id)
            .where(Device.id == data.device_id, Site.organization_id == org_id)
        )
        if not dev_check.scalar_one_or_none():
            raise HTTPException(404, detail="Device not found")

    # Validate device group ownership if being updated
    if data.device_group_id is not None:
        group_check = await session.execute(
            select(DeviceGroup.id).where(
                DeviceGroup.id == data.device_group_id,
                DeviceGroup.organization_id == org_id,
            )
        )
        if not group_check.scalar_one_or_none():
            raise HTTPException(404, detail="Device group not found")

    # Apply updates
    if data.name is not None:
        schedule.name = data.name
    if data.enabled is not None:
        schedule.enabled = data.enabled
    if data.device_id is not None:
        schedule.device_id = data.device_id
    if data.device_group_id is not None:
        schedule.device_group_id = data.device_group_id
    if data.port_numbers is not None:
        schedule.port_numbers = data.port_numbers
    if data.power_off_time is not None:
        schedule.power_off_time = data.power_off_time
    if data.power_on_time is not None:
        schedule.power_on_time = data.power_on_time
    if data.days_of_week is not None:
        schedule.days_of_week = data.days_of_week
    if data.timezone is not None:
        schedule.timezone = data.timezone

    await session.commit()

    return PoEScheduleDetailOut(
        id=str(schedule.id),
        name=schedule.name,
        enabled=schedule.enabled,
        device_id=str(schedule.device_id) if schedule.device_id else None,
        device_group_id=str(schedule.device_group_id) if schedule.device_group_id else None,
        port_numbers=schedule.port_numbers or [],
        power_off_time=schedule.power_off_time,
        power_on_time=schedule.power_on_time,
        days_of_week=schedule.days_of_week or [],
        timezone=schedule.timezone or "UTC",
        last_action=schedule.last_action,
        last_action_at=schedule.last_action_at.isoformat() if schedule.last_action_at else None,
        created_at=schedule.created_at.isoformat() if schedule.created_at else None,
        updated_at=schedule.updated_at.isoformat() if schedule.updated_at else None,
    )


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_poe_schedule(
    schedule_id: str,
    session: AsyncSession = Depends(get_session),
    _user: Any = Depends(get_current_active_user),
) -> None:
    """Soft-delete a PoE schedule."""
    _require_admin(_user)
    from datetime import datetime

    from app.models.poe import PoESchedule

    org_id = _org_id(_user)

    result = await session.execute(
        select(PoESchedule).where(
            PoESchedule.id == schedule_id,
            PoESchedule.organization_id == org_id,
            PoESchedule.deleted_at.is_(None),
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(404, detail="Schedule not found")

    schedule.deleted_at = datetime.now(UTC)
    await session.commit()

    return None
