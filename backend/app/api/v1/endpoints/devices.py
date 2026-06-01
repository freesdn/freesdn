# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device Endpoints
==============================

Read, update, and query operations for devices.
Devices are created via controller sync, not directly.
"""

import logging
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.adapters.exceptions import AdapterError
from app.core.adapter_result import raise_for_adapter_result
from app.core.dependencies import (
    CurrentUser,
    is_unscoped_superuser,
    require_permissions,
)
from app.core.security_utils import escape_like
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models import (
    Device,
    DeviceClient,
    DevicePort,
    DeviceStatus,
    PortStatus,
    Site,
)
from app.schemas import (
    DeviceResponse,
    DeviceStats,
    DeviceUpdate,
    DeviceWithStats,
    PaginatedResponse,
)
from app.services.adapter_factory import get_adapter

logger = logging.getLogger(__name__)

router = APIRouter()


# ===========================================
# List Devices
# ===========================================


@router.get("/", response_model=PaginatedResponse[DeviceWithStats])
async def list_devices(
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
    controller_id: UUID | None = None,
    device_type: str | None = None,
    status: str | None = None,
    is_active: bool | None = None,
    search: str | None = Query(None, max_length=256),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=500),
) -> Any:
    """
    List devices with filtering and pagination.

    Filters:
    - site_id: Filter by site
    - controller_id: Filter by controller
    - device_type: Filter by type (switch, camera, etc.)
    - status: Filter by status (online, offline, etc.)
    - is_active: Filter by active status
    - search: Search by name, IP, or MAC address
    """
    # Build base query
    query = select(Device).where(Device.deleted_at.is_(None))

    # Tenant scoping (app.core.tenancy): the org filter (reached via
    # Site for this via-site model) AND the per-user site grant, in ONE canonical
    # helper instead of the hand-rolled block this replaces. Behavior-preserving:
    # an unscoped super sees all; org users see their org; a site-limited caller
    # sees only granted sites (and nothing if grant-less, fail-closed).
    query = query.where(tenant_filter(Device, current_user))

    # Apply filters
    if site_id:
        query = query.where(Device.site_id == site_id)

    if controller_id:
        query = query.where(Device.controller_id == controller_id)

    if device_type:
        query = query.where(Device.device_type == device_type)

    if status:
        query = query.where(Device.status == status)

    if is_active is not None:
        query = query.where(Device.is_active == is_active)

    if search:
        escaped = escape_like(search)
        search_pattern = f"%{escaped}%"
        query = query.where(
            (Device.name.ilike(search_pattern, escape="\\"))
            | (Device.ip_address.ilike(search_pattern, escape="\\"))
            | (Device.mac_address.ilike(search_pattern, escape="\\"))
        )

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await session.scalar(count_query) or 0

    # Apply pagination and eager loading to prevent N+1 queries
    query = (
        query.options(
            selectinload(Device.site),
            selectinload(Device.controller),
        )
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    query = query.order_by(Device.name)

    result = await session.execute(query)
    devices = result.scalars().all()

    # Port / client counts for the Ports column + CSV export.
    # Two set-based grouped queries over JUST this page's device IDs
    # (not an N+1 loop) — constant query count regardless of page size.
    device_ids = [d.id for d in devices]
    port_counts: dict[UUID, tuple[int, int]] = {}
    client_counts: dict[UUID, int] = {}
    if device_ids:
        port_rows = await session.execute(
            select(
                DevicePort.device_id,
                func.count().label("total"),
                func.count(case((DevicePort.status == PortStatus.UP.value, 1))).label("active"),
            )
            .where(DevicePort.device_id.in_(device_ids))
            .group_by(DevicePort.device_id)
        )
        for did, total_ports, active_ports in port_rows.all():
            port_counts[did] = (int(total_ports), int(active_ports))

        client_rows = await session.execute(
            select(
                DeviceClient.device_id,
                func.count(case((DeviceClient.is_online.is_(True), 1))).label("online"),
            )
            .where(DeviceClient.device_id.in_(device_ids))
            .group_by(DeviceClient.device_id)
        )
        for did, online_clients in client_rows.all():
            client_counts[did] = int(online_clients)

    items: list[DeviceWithStats] = []
    for device in devices:
        total_ports, active_ports = port_counts.get(device.id, (0, 0))
        base = DeviceResponse.model_validate(device, from_attributes=True)
        items.append(
            DeviceWithStats(
                **base.model_dump(),
                port_count=total_ports,
                active_port_count=active_ports,
                client_count=client_counts.get(device.id, 0),
                metadata=device.device_metadata or {},
                capabilities=device.capabilities or {},
            )
        )

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page,
    )


# ===========================================
# Get Single Device
# ===========================================


@router.get("/{device_id}", response_model=DeviceWithStats)
async def get_device(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a single device by ID with detailed stats."""
    result = await session.execute(
        select(Device)
        .options(
            selectinload(Device.site),
            selectinload(Device.controller),
            selectinload(Device.ports),
        )
        .where(Device.id == device_id, Device.deleted_at.is_(None))
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if device.site.organization_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this device",
            )
        # Site-access enforcement: a site-limited user
        # can only see devices in their granted sites.
        if not current_user.can_access_site(device.site_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found",
            )

    # Calculate stats
    port_count = len(device.ports) if device.ports else 0
    active_port_count = sum(1 for p in device.ports if p.status == "up") if device.ports else 0

    # Build response from ORM model
    base = DeviceResponse.model_validate(device, from_attributes=True)
    return DeviceWithStats(
        **base.model_dump(),
        port_count=port_count,
        active_port_count=active_port_count,
        client_count=0,
    )


# ===========================================
# Update Device
# ===========================================


@router.patch("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: UUID,
    device_data: DeviceUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:update"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Update device properties.

    Note: Core device data (MAC, IP, etc.) is managed by controller sync.
    This endpoint allows updating user-editable fields like name, location, notes.
    """
    result = await session.execute(
        select(Device)
        .options(selectinload(Device.site))
        .where(Device.id == device_id, Device.deleted_at.is_(None))
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if device.site.organization_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this device",
            )
        # Site-access enforcement: a site-limited user
        # cannot modify a device outside their granted sites.
        if not current_user.can_access_site(device.site_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found",
            )

    # Update fields
    update_data = device_data.model_dump(exclude_unset=True)

    # IDOR guard: a caller can only attach a credential that belongs to
    # their own organization. Without this an org_admin could point a
    # device at another tenant's credential by guessing its UUID.
    if "credential_id" in update_data and update_data["credential_id"] is not None:
        from app.models.core import Credential

        cred = (
            await session.execute(
                select(Credential).where(
                    Credential.id == update_data["credential_id"],
                    Credential.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        cred_org = getattr(cred, "organization_id", None) if cred else None
        if cred is None or (
            not is_unscoped_superuser(current_user) and cred_org != current_user.organization_id
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found",
            )

    for field, value in update_data.items():
        setattr(device, field, value)

    await session.commit()
    await session.refresh(device)

    return device


# ===========================================
# Delete Device
# ===========================================


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:delete"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """
    Soft-delete a device.

    Note: Device may be re-created on next controller sync.
    """
    result = await session.execute(
        select(Device)
        .options(selectinload(Device.site))
        .where(Device.id == device_id, Device.deleted_at.is_(None))
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if device.site.organization_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this device",
            )
        # Site-access enforcement.
        if not current_user.can_access_site(device.site_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found",
            )

    # Soft delete
    device.deleted_at = datetime.now(UTC)

    return None


# ===========================================
# Helpers
# ===========================================


async def _get_adapter_for_device(device: Device) -> Any:
    """Create adapter from device's controller credentials."""
    ctrl = device.controller
    if not ctrl:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device has no controller",
        )

    # Decrypt password if stored encrypted
    password = ctrl.password or ""
    try:
        from app.core.crypto import decrypt_credential, is_encrypted

        if password and is_encrypted(password):
            password = decrypt_credential(password)
    except Exception:
        pass  # Use as-is if decryption fails

    cloud_kwargs: dict[str, Any] = {}
    if ctrl.connection_mode == "cloud":
        client_secret = ctrl.client_secret or ""
        try:
            if client_secret and is_encrypted(client_secret):
                client_secret = decrypt_credential(client_secret)
        except Exception:
            pass
        cloud_kwargs = {
            "client_id": ctrl.client_id or "",
            "client_secret": client_secret,
            "omada_id": ctrl.omada_id or "",
            "cloud_region": ctrl.cloud_region or "us",
        }

    return get_adapter(
        controller_type=ctrl.controller_type,
        host=ctrl.host,
        username=ctrl.username or "",
        password=password,
        port=ctrl.port,
        use_ssl=ctrl.use_ssl,
        verify_ssl=ctrl.verify_ssl,
        mode=ctrl.connection_mode or "local",
        **cloud_kwargs,
    )


async def _load_device(
    device_id: UUID,
    current_user: CurrentUser,
    session: AsyncSession,
) -> Device:
    """Load device with controller + site, checking access."""
    result = await session.execute(
        select(Device)
        .options(selectinload(Device.site), selectinload(Device.controller))
        .where(Device.id == device_id, Device.deleted_at.is_(None))
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if not is_unscoped_superuser(current_user):
        if device.site.organization_id != current_user.organization_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        # a site-limited user (>=1 UserSiteAccess grant, not org_admin+)
        # may only touch devices in their granted sites. The read/CRUD handlers
        # (get/update/delete) enforce this, but the privileged ACTION handlers
        # (reboot/locate/led/adopt/forget/upgrade) + batch reached the device only
        # through _load_device, which checked org but NOT site — letting a
        # site-limited operator control out-of-scope devices. Enforce
        # it here so every action path inherits the boundary.
        if not current_user.can_access_site(device.site_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


# ===========================================
# Device Actions
# ===========================================


class LEDSettingIn(BaseModel):
    setting: int = Field(..., ge=0, le=2, description="0=off, 1=on, 2=site_settings")


class BatchActionIn(BaseModel):
    # Cap to keep the IN(...) build bounded and prevent a 100k-UUID
    # batch from monopolizing adapter connections / worker time.
    # Real-world batch ops are tens of devices, not thousands.
    device_ids: list[UUID] = Field(..., min_length=1, max_length=500)


# ===========================================
# Batch Actions — MUST be registered BEFORE /{device_id}/... routes
# so FastAPI doesn't match "batch" as a UUID-shaped device_id and
# blackhole the request into the per-device handler with a 422.
# ===========================================


@router.post("/batch/reboot")
async def batch_reboot_devices(
    data: BatchActionIn,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    confirm: bool = Query(False, description="Must be true — rebooting a fleet disrupts the site."),
) -> dict[str, Any]:
    """Batch reboot multiple devices."""
    # FSDN-DW-BULK-REBOOT: fleet reboot is a site-wide outage; require confirmation.
    if not confirm:
        raise HTTPException(
            400, detail="Bulk reboot disrupts the fleet; pass confirm=true to proceed."
        )
    return await _batch_action(data.device_ids, "reboot_device", current_user, session)


@router.post("/batch/upgrade")
async def batch_upgrade_firmware(
    data: BatchActionIn,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firmware:upgrade"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    confirm: bool = Query(False, description="Must be true — a bad fleet flash can brick devices."),
) -> dict[str, Any]:
    """Batch firmware upgrade for multiple devices.

    Gated on the super_admin-only ``firmware:upgrade`` permission (org/site_admin
    deliberately excluded — a bad fleet flash can brick devices), matching
    controllers.batch_firmware_upgrade and the modern firmware paths. ``device:admin``
    is held by site/org admins, so the prior gate let them batch-flash a fleet.
    """
    # a fleet firmware flash is irreversible — require explicit
    # confirmation, matching the batch-reboot sibling.
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Batch firmware flash can brick devices. Re-issue with confirm=true.",
        )
    return await _batch_action(data.device_ids, "upgrade_firmware", current_user, session)


async def _batch_action(
    device_ids: list[UUID],
    action: str,
    current_user: CurrentUser,
    session: AsyncSession,
) -> dict[str, Any]:
    """
    Execute a batch device action efficiently.

    Loads all devices in one query, groups by controller, and reuses
    a single adapter connection per controller instead of N separate ones.
    """
    # Single query to load all requested devices with controller + site
    result = await session.execute(
        select(Device)
        .options(selectinload(Device.site), selectinload(Device.controller))
        .where(
            Device.id.in_(device_ids),
            Device.deleted_at.is_(None),
        )
    )
    devices_by_id = {d.id: d for d in result.scalars().all()}

    # Access checks + group by controller
    from collections import defaultdict

    ctrl_groups: dict[UUID | None, list[Device]] = defaultdict(list)
    results: list[dict[str, Any]] = []

    for did in device_ids:
        device = devices_by_id.get(did)
        if not device:
            results.append({"device_id": str(did), "success": False, "message": "Device not found"})
            continue
        if not is_unscoped_superuser(current_user):
            if device.site.organization_id != current_user.organization_id:
                results.append(
                    {"device_id": str(did), "success": False, "message": "Access denied"}
                )
                continue
            # site boundary on batch actions too.
            if not current_user.can_access_site(device.site_id):
                results.append(
                    {"device_id": str(did), "success": False, "message": "Access denied"}
                )
                continue
        if not device.controller_id:
            results.append(
                {
                    "device_id": str(did),
                    "success": False,
                    "message": "Device not managed by a controller",
                }
            )
            continue
        ctrl_groups[device.controller_id].append(device)

    # Execute per-controller group (one adapter per controller)
    for _ctrl_id, group in ctrl_groups.items():
        try:
            adapter = await _get_adapter_for_device(group[0])
            async with adapter:
                for device in group:
                    try:
                        method = getattr(adapter, action)
                        r = await method(device.mac_address)
                        results.append(
                            {
                                "device_id": str(device.id),
                                "success": r.success,
                                "message": r.message,
                            }
                        )
                    except Exception as e:
                        results.append(
                            {"device_id": str(device.id), "success": False, "message": str(e)}
                        )
        except Exception as e:
            for device in group:
                results.append(
                    {
                        "device_id": str(device.id),
                        "success": False,
                        "message": f"Controller error: {e}",
                    }
                )

    return {"results": results}


@router.post("/{device_id}/reboot")
async def reboot_device(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:reboot"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    confirm: bool = False,
) -> dict[str, Any]:
    """Reboot a device via its controller."""
    # rebooting disrupts the device/site — require an explicit
    # confirm (matching the batch-reboot gate). A default operator holds
    # device:reboot, so this is the destructive-action acknowledgement.
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rebooting disrupts the device; pass confirm=true to proceed.",
        )
    device = await _load_device(device_id, current_user, session)

    if not device.controller_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Device not managed by a controller"
        )

    adapter = await _get_adapter_for_device(device)
    try:
        async with adapter:
            result = await adapter.reboot_device(device.mac_address)
    except AdapterError:
        raise  # middleware maps AdapterReadOnlyError->403, ConfirmationRequired->409, conn/auth->502/503
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Controller error")

    if not result.success:
        logger.error("Device reboot failed: %s", result.message)
        raise_for_adapter_result(result)

    # log user_id + device_id instead of email + device name.
    _uid = str(current_user.user.id) if hasattr(current_user, "user") else None
    logger.warning(
        "Device reboot executed",
        extra={"user_id": _uid, "device_id": str(device.id)},
    )
    return {"success": True, "message": "Reboot command sent", "device_id": str(device_id)}


@router.post("/{device_id}/locate")
async def locate_device(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:action"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    duration: int = Query(30, ge=5, le=120),
) -> dict[str, Any]:
    """Flash LEDs to physically locate a device (APs only)."""
    device = await _load_device(device_id, current_user, session)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.locate_device(device.mac_address, duration)
    except AdapterError:
        raise  # middleware maps AdapterReadOnlyError->403, ConfirmationRequired->409, conn/auth->502/503
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Controller error")

    if not result.success:
        logger.error("Device locate failed: %s", result.message)
        raise_for_adapter_result(result)
    return {"success": True, "device_id": str(device_id), "duration": duration}


@router.patch("/{device_id}/led")
async def set_device_led(
    device_id: UUID,
    data: LEDSettingIn,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:action"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Set device LED mode (0=off, 1=on, 2=site_settings)."""
    device = await _load_device(device_id, current_user, session)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.set_device_led(device.mac_address, data.setting)
    except AdapterError:
        raise  # middleware maps AdapterReadOnlyError->403, ConfirmationRequired->409, conn/auth->502/503
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Controller error")

    if not result.success:
        logger.error("Device LED update failed: %s", result.message)
        raise_for_adapter_result(result)
    return {"success": True, "device_id": str(device_id), "led_setting": data.setting}


@router.post("/{device_id}/adopt")
async def adopt_device(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Adopt a pending device into the controller."""
    device = await _load_device(device_id, current_user, session)
    # Serialize concurrent adopts of the SAME device (mirrors discovery.py's
    # FOR UPDATE): lock the row + re-read is_adopted so a second concurrent
    # request waits, then bails with 409 — instead of both firing adopt at the
    # controller and causing a duplicate enrollment / ownership conflict.
    await session.execute(
        select(Device)
        .where(Device.id == device.id, Device.deleted_at.is_(None))
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if device.is_adopted:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device already adopted")
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.adopt_device(device.mac_address)
    except AdapterError:
        raise  # middleware maps AdapterReadOnlyError->403, ConfirmationRequired->409, conn/auth->502/503
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Controller error")

    if not result.success:
        logger.error("Device adoption failed: %s", result.message)
        raise_for_adapter_result(result)

    device.is_adopted = True
    device.status = DeviceStatus.ADOPTING
    device.adopted_at = datetime.now(UTC)
    await session.commit()

    return {
        "success": True,
        "message": f"Adoption initiated for {device.name}",
        "device_id": str(device_id),
    }


@router.post("/{device_id}/forget")
async def forget_device(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    confirm: bool = False,
) -> dict[str, Any]:
    """Forget (remove) device from the controller."""
    # forgetting/unadopting a device is irreversible — require an explicit
    # confirm, matching the access_points forget_ap (confirmed=true) gate.
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Forgetting a device unadopts it (irreversible); pass confirm=true to proceed.",
        )
    device = await _load_device(device_id, current_user, session)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.forget_device(device.mac_address)
    except AdapterError:
        raise  # middleware maps AdapterReadOnlyError->403, ConfirmationRequired->409, conn/auth->502/503
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Controller error")

    if not result.success:
        logger.error("Device forget failed: %s", result.message)
        raise_for_adapter_result(result)

    device.is_adopted = False
    device.status = DeviceStatus.UNKNOWN
    await session.commit()

    return {
        "success": True,
        "message": f"Device {device.name} forgotten",
        "device_id": str(device_id),
    }


@router.post("/{device_id}/upgrade")
async def upgrade_device_firmware(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firmware:upgrade"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    confirm: bool = Query(
        False, description="Must be true — firmware flashing can brick the device."
    ),
) -> dict[str, Any]:
    """Trigger firmware upgrade for a device (super_admin-only firmware:upgrade)."""
    # firmware flashing reboots the device and is irreversible —
    # require an explicit confirmation, matching the AP-upgrade + batch-reboot
    # sibling gates (the upgrade paths were the only destructive ops missing it).
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Firmware flash reboots the device and can brick it. Re-issue with confirm=true.",
        )
    device = await _load_device(device_id, current_user, session)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            result = await adapter.upgrade_firmware(device.mac_address)
    except AdapterError:
        raise  # middleware maps AdapterReadOnlyError->403, ConfirmationRequired->409, conn/auth->502/503
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Controller error")

    if not result.success:
        logger.error("Device firmware upgrade failed: %s", result.message)
        raise_for_adapter_result(result)
    return {
        "success": True,
        "message": f"Firmware upgrade initiated for {device.name}",
        "device_id": str(device_id),
    }


@router.get("/{device_id}/firmware")
async def get_device_firmware_info(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Get firmware update availability for a device."""
    device = await _load_device(device_id, current_user, session)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            info = await adapter.get_firmware_info(device.mac_address)
    except AdapterError:
        raise  # middleware maps AdapterReadOnlyError->403, ConfirmationRequired->409, conn/auth->502/503
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Controller error")
    return info


@router.get("/{device_id}/metrics")
async def get_device_metrics(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Get real-time device metrics (CPU, memory, traffic)."""
    device = await _load_device(device_id, current_user, session)
    adapter = await _get_adapter_for_device(device)

    try:
        async with adapter:
            metrics = await adapter.get_device_metrics(device.mac_address)
    except AdapterError:
        raise  # middleware maps AdapterReadOnlyError->403, ConfirmationRequired->409, conn/auth->502/503
    except Exception as e:
        logger.error("Controller communication error: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Controller error")
    return metrics


# ===========================================
# Device Capabilities
# ===========================================

# Default capabilities by device type
_TYPE_CAPS: dict[str, dict[str, bool]] = {
    "switch": {
        "can_poe_control": True,
        "can_poe_status": True,
        "can_port_control": True,
        "can_port_status": True,
        "can_port_config": True,
        "can_vlan_config": True,
        "can_ssid_control": False,
        "can_client_list": True,
        "can_firmware_update": True,
        "can_backup": True,
        "can_reboot": True,
    },
    "access_point": {
        "can_poe_control": False,
        "can_poe_status": False,
        "can_port_control": False,
        "can_port_status": False,
        "can_port_config": False,
        "can_vlan_config": False,
        "can_ssid_control": True,
        "can_client_list": True,
        "can_firmware_update": True,
        "can_backup": True,
        "can_reboot": True,
    },
    "gateway": {
        "can_poe_control": False,
        "can_poe_status": False,
        "can_port_control": True,
        "can_port_status": True,
        "can_port_config": True,
        "can_vlan_config": True,
        "can_ssid_control": False,
        "can_client_list": True,
        "can_firmware_update": True,
        "can_backup": True,
        "can_reboot": True,
    },
    "router": {
        "can_poe_control": False,
        "can_poe_status": False,
        "can_port_control": True,
        "can_port_status": True,
        "can_port_config": True,
        "can_vlan_config": True,
        "can_ssid_control": False,
        "can_client_list": True,
        "can_firmware_update": True,
        "can_backup": True,
        "can_reboot": True,
    },
}

# Fallback (all false)
_DEFAULT_CAPS: dict[str, bool] = {
    "can_poe_control": False,
    "can_poe_status": False,
    "can_port_control": False,
    "can_port_status": False,
    "can_port_config": False,
    "can_vlan_config": False,
    "can_ssid_control": False,
    "can_client_list": False,
    "can_firmware_update": False,
    "can_backup": False,
    "can_reboot": True,
}


@router.get("/{device_id}/capabilities")
async def get_device_capabilities(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """
    Return device capabilities for feature-gating in the UI.

    Merges default type-based capabilities with any stored overrides
    in the device's ``capabilities`` JSONB column.
    """
    device = await _load_device(device_id, current_user, session)

    stored: dict[str, Any] = device.capabilities or {}
    type_caps = _TYPE_CAPS.get(device.device_type, _DEFAULT_CAPS)

    # Build per-capability detail dicts
    driver_base_caps: dict[str, dict[str, Any]] = {}
    effective_caps: dict[str, dict[str, Any]] = {}
    for key, default_val in type_caps.items():
        cap_key = key.replace("can_", "")
        supported = stored.get(key, default_val)
        detail = {
            "supported": bool(supported),
            "can_write": bool(supported),
        }
        driver_base_caps[cap_key] = detail
        effective_caps[cap_key] = detail

    # Merge any extra keys from stored capabilities
    for key, val in stored.items():
        cap_key = key.replace("can_", "") if key.startswith("can_") else key
        if cap_key not in effective_caps:
            detail = {
                "supported": bool(val),
                "can_write": bool(val),
            }
            driver_base_caps[cap_key] = detail
            effective_caps[cap_key] = detail

    # Build boolean convenience fields
    booleans = {k: stored.get(k, type_caps.get(k, v)) for k, v in _DEFAULT_CAPS.items()}

    supported_count = sum(1 for d in effective_caps.values() if d["supported"])

    return {
        "device_id": str(device.id),
        "model": device.model or "",
        "vendor": device.manufacturer or "",
        "firmware_version": device.firmware_version,
        "driver_base_caps": driver_base_caps,
        "profile_restrictions": {},
        "effective_caps": effective_caps,
        **booleans,
        "total_capabilities": len(effective_caps),
        "supported_capabilities": supported_count,
        "restricted_capabilities": 0,
    }


# ===========================================
# Device Statistics
# ===========================================


@router.get("/stats/summary", response_model=DeviceStats)
async def get_device_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
) -> Any:
    """Get device statistics summary."""
    # a site-limited user (>=1 explicit grant) must only
    # see aggregates over their granted sites — the list/get/action handlers
    # already enforce this, but this stat endpoint previously scoped by
    # organization_id ONLY, leaking org-wide device counts to a site-limited
    # operator. Assert any explicit site_id and AND in the per-user grant filter.
    assert_can_access_site(current_user, site_id, detail="Not found")

    # Build base filter
    base_filter = [Device.deleted_at.is_(None), site_scope_filter(current_user, Device.site_id)]

    if not is_unscoped_superuser(current_user):
        base_filter.append(
            Device.site_id.in_(
                select(Site.id).where(
                    Site.organization_id == current_user.organization_id,
                    Site.deleted_at.is_(None),
                )
            )
        )

    if site_id:
        base_filter.append(Device.site_id == site_id)

    # Single aggregation query — counts by (device_type, status)
    agg_q = (
        select(
            Device.device_type,
            Device.status,
            func.count().label("cnt"),
        )
        .where(*base_filter)
        .group_by(Device.device_type, Device.status)
    )
    rows = (await session.execute(agg_q)).all()

    total = 0
    online = 0
    offline = 0
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for device_type, device_status, cnt in rows:
        total += cnt
        if device_status == DeviceStatus.ONLINE.value:
            online += cnt
        elif device_status == DeviceStatus.OFFLINE.value:
            offline += cnt
        by_type[device_type] = by_type.get(device_type, 0) + cnt
        by_status[device_status] = by_status.get(device_status, 0) + cnt

    return DeviceStats(
        total_devices=total,
        online_devices=online,
        offline_devices=offline,
        by_type=by_type,
        by_status=by_status,
    )
