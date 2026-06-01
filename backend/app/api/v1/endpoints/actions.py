# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device Actions Endpoints
======================================

API endpoints for device-specific actions:
- PoE control (cycle, enable, disable)
- SSID management
- Camera snapshots/RTSP
- Device reboot
"""

import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.hikvision import HikvisionAdapter
from app.adapters.omada import OmadaAdapter
from app.core.crypto import decrypt_credential
from app.core.dependencies import (
    CurrentUser,
    is_unscoped_superuser,
    require_permissions,
)
from app.core.events import device_event, get_event_bus
from app.core.security_utils import sanitize_filename
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.models import Controller, Device, Site
from app.modules.cameras.models import Camera

logger = logging.getLogger(__name__)
router = APIRouter()


# ===========================================
# Request/Response Models
# ===========================================


class PoECycleRequest(BaseModel):
    device_id: UUID = Field(..., description="Switch device ID")
    port: int = Field(..., ge=1, le=48, description="Port number to cycle")
    duration: int = Field(5, ge=1, le=30, description="Off duration in seconds")


class SSIDToggleRequest(BaseModel):
    controller_id: UUID = Field(..., description="Controller ID")
    ssid_name: str = Field(..., description="SSID name to toggle")
    enabled: bool = Field(..., description="Enable or disable SSID")


class CameraSnapshotRequest(BaseModel):
    device_id: UUID = Field(..., description="Camera device ID")
    stream: str = Field("main", description="Stream type: main or sub")


class DeviceRebootRequest(BaseModel):
    device_id: UUID = Field(..., description="Device ID to reboot")


class ActionResponse(BaseModel):
    success: bool
    message: str
    data: dict[str, Any] | None = None


# ===========================================
# Helper Functions
# ===========================================


async def get_device_with_access(
    device_id: UUID,
    current_user: CurrentUser,
    session: AsyncSession,
    device_type: str | None = None,
) -> Device:
    """Get device with access verification."""
    query = select(Device).where(Device.id == device_id, Device.deleted_at.is_(None))

    # a SCOPED super_admin key must stay within its org scope — only an
    # UNSCOPED super_admin skips the org filter; a scoped key (or any non-super
    # caller) is org-bounded.
    if not is_unscoped_superuser(current_user):
        query = query.join(Site).where(Site.organization_id == current_user.organization_id)

    result = await session.execute(query)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    # a site-limited caller may not act on a device in a
    # sibling site that is not in their grant list.  Uses 404 to avoid an
    # existence oracle, matching the convention in devices.py:_load_device.
    assert_can_access_site(current_user, device.site_id, detail="Device not found")

    if device_type and device.device_type.value != device_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Device is not a {device_type}"
        )

    return device


async def get_controller_with_access(
    controller_id: UUID, current_user: CurrentUser, session: AsyncSession
) -> Controller:
    """Get controller with access verification."""
    query = select(Controller).where(
        Controller.id == controller_id, Controller.deleted_at.is_(None)
    )

    # a SCOPED super_admin key stays org-bounded; only an UNSCOPED
    # super_admin skips the org filter.
    if not is_unscoped_superuser(current_user):
        query = query.join(Site).where(Site.organization_id == current_user.organization_id)

    result = await session.execute(query)
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Controller not found")

    # a site-limited caller may not act on a controller in a sibling
    # site outside their grant list.  assert_can_access_site is a safe no-op
    # when controller.site_id is None (org-level controller).
    assert_can_access_site(current_user, controller.site_id, detail="Controller not found")

    return controller


def create_adapter(controller: Controller) -> Any:
    """Create adapter for a controller."""
    adapters = {
        "omada": OmadaAdapter,
        "tplink_omada": OmadaAdapter,
        "hikvision": HikvisionAdapter,
    }

    adapter_class = adapters.get(controller.type.lower())
    if not adapter_class:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No adapter for controller type: {controller.type}",
        )

    return adapter_class(
        host=controller.host, username=controller.username, password=controller.password
    )


# ===========================================
# PoE Actions
# ===========================================


@router.post("/poe/cycle", response_model=ActionResponse)
async def cycle_poe_port(
    request: PoECycleRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:action"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Cycle PoE power on a switch port.

    Temporarily disables PoE on the specified port and re-enables it.
    Useful for rebooting PoE-powered devices.
    """
    device = await get_device_with_access(request.device_id, current_user, session, "switch")

    # Get the controller for this device
    controller_result = await session.execute(
        select(Controller).where(
            Controller.id == device.controller_id, Controller.deleted_at.is_(None)
        )
    )
    controller = controller_result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Device controller not found"
        )

    try:
        adapter = create_adapter(controller)
        await adapter.connect()

        try:
            result = await adapter.cycle_poe_port(
                device_id=str(device.external_id or device.id),
                port=request.port,
                duration=request.duration,
            )
            # Honest failure (don't publish a success event / return success=true
            # when the switch refused the write).
            if result is not None and not getattr(result, "success", True):
                return ActionResponse(
                    success=False,
                    message=(
                        getattr(result, "error", None)
                        or getattr(result, "message", None)
                        or f"Switch refused the PoE cycle on port {request.port}"
                    ),
                    data={"device_id": str(device.id), "port": request.port},
                )

            logger.info(
                f"User {current_user.user.email} cycled PoE on port {request.port} "
                f"of device {device.name}"
            )

            # Publish event
            event_bus = get_event_bus()
            from app.core.events import org_id_for_site

            org_id = await org_id_for_site(session, device.site_id)
            await event_bus.publish(
                device_event(
                    "action.poe_cycle",
                    device_id=str(device.id),
                    site_id=str(device.site_id),
                    organization_id=org_id,
                    port=request.port,
                    user=current_user.user.email,
                )
            )

            return ActionResponse(
                success=True,
                message=f"PoE cycled on port {request.port} of {device.name}",
                data={"device_id": str(device.id), "port": request.port},
            )
        finally:
            await adapter.disconnect()

    except Exception as e:
        logger.error("PoE cycle failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to cycle PoE"
        )


# ===========================================
# SSID Actions
# ===========================================


@router.post("/wifi/ssid/toggle", response_model=ActionResponse)
async def toggle_ssid(
    request: SSIDToggleRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:action"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Enable or disable an SSID on a controller.
    """
    controller = await get_controller_with_access(request.controller_id, current_user, session)

    try:
        adapter = create_adapter(controller)
        await adapter.connect()

        try:
            result = await adapter.toggle_ssid(request.ssid_name, request.enabled)
            # Honest failure: the adapter returns AdapterResult(success=False) when
            # the controller refuses the write (read-only gate, rejection, auth/
            # timeout) WITHOUT raising. Don't report success=true in that case.
            if result is not None and not getattr(result, "success", True):
                return ActionResponse(
                    success=False,
                    message=(
                        getattr(result, "error", None)
                        or getattr(result, "message", None)
                        or f"Controller refused the SSID change on {controller.name}"
                    ),
                    data={
                        "controller_id": str(controller.id),
                        "ssid": request.ssid_name,
                        "enabled": request.enabled,
                    },
                )

            action = "enabled" if request.enabled else "disabled"
            logger.info(
                f"User {current_user.user.email} {action} SSID '{request.ssid_name}' "
                f"on controller {controller.name}"
            )

            return ActionResponse(
                success=True,
                message=f"SSID '{request.ssid_name}' {action} on {controller.name}",
                data={
                    "controller_id": str(controller.id),
                    "ssid": request.ssid_name,
                    "enabled": request.enabled,
                },
            )
        finally:
            await adapter.disconnect()

    except Exception as e:
        logger.error("SSID toggle failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to toggle SSID"
        )


async def _resolve_camera_credentials(
    device: Device,
    session: AsyncSession,
    current_user: CurrentUser,
) -> tuple[str, str, str]:
    """Resolve camera host, username, and password from the Camera model.

    Returns (host, username, password).
    Raises HTTPException if no Camera record or credentials are found.
    """
    # scope the Camera lookup to the caller's org AND the device's
    # site so a user cannot resolve credentials for a camera they do not own.
    camera_result = await session.execute(
        select(Camera).where(
            Camera.ip_address == device.ip_address,
            Camera.organization_id == current_user.organization_id,
            Camera.site_id == device.site_id,
            Camera.deleted_at.is_(None),
        )
    )
    camera = camera_result.scalar_one_or_none()

    if not camera or not camera.password_encrypted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No credentials available for this camera",
        )

    return (
        camera.ip_address,
        camera.username or "admin",
        decrypt_credential(camera.password_encrypted),
    )


# ===========================================
# Camera Actions
# ===========================================


@router.post("/camera/snapshot")
async def get_camera_snapshot(
    request: CameraSnapshotRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:action"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Capture a snapshot from an IP camera.

    Returns the image directly as JPEG.
    """
    device = await get_device_with_access(request.device_id, current_user, session, "camera")

    # Get controller for adapter info (or use device directly for standalone cameras)
    if device.controller_id:
        controller_result = await session.execute(
            select(Controller).where(
                Controller.id == device.controller_id, Controller.deleted_at.is_(None)
            )
        )
        controller = controller_result.scalar_one_or_none()
        if controller:
            adapter = create_adapter(controller)
        else:
            host, username, password = await _resolve_camera_credentials(
                device, session, current_user
            )
            adapter = HikvisionAdapter(host=host, username=username, password=password)
    else:
        host, username, password = await _resolve_camera_credentials(device, session, current_user)
        adapter = HikvisionAdapter(host=host, username=username, password=password)

    try:
        await adapter.connect()

        try:
            image_data = await adapter.get_snapshot(
                device_id=str(device.external_id or device.id), stream=request.stream
            )

            # log user_id + device_id instead of email + device name.
            logger.info(
                "Camera snapshot captured",
                extra={
                    "user_id": str(current_user.user.id),
                    "device_id": str(device.id),
                },
            )

            safe_name = sanitize_filename(device.name)
            return StreamingResponse(
                iter([image_data]),
                media_type="image/jpeg",
                headers={"Content-Disposition": f'inline; filename="{safe_name}_snapshot.jpg"'},
            )
        finally:
            await adapter.disconnect()

    except Exception as e:
        logger.error("Snapshot capture failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to capture snapshot"
        )


@router.get("/camera/{device_id}/rtsp", response_model=ActionResponse)
async def get_camera_rtsp_url(
    device_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:action"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    stream: str = "main",
) -> Any:
    """
    Get RTSP URL for a camera stream.
    """
    device = await get_device_with_access(device_id, current_user, session, "camera")

    # Build RTSP URL based on vendor — never embed credentials in the URL.
    vendor = (device.manufacturer or "").lower()
    if vendor == "hikvision":
        channel = "101" if stream == "main" else "102"
        rtsp_url = f"rtsp://{device.ip_address}:554/Streaming/channels/{channel}"
    else:
        # Generic RTSP URL pattern
        rtsp_url = f"rtsp://{device.ip_address}:554/stream1"

    return ActionResponse(
        success=True,
        message=f"RTSP URL for {device.name}",
        data={
            "device_id": str(device.id),
            "stream": stream,
            "rtsp_url": rtsp_url,
            "requires_auth": True,
        },
    )


# ===========================================
# Device Reboot
# ===========================================


@router.post("/reboot", response_model=ActionResponse)
async def reboot_device(
    request: DeviceRebootRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("device:admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    confirm: bool = Query(False, description="Must be true — rebooting disrupts the device."),
) -> Any:
    """
    Reboot a device (requires admin permission).
    """
    # parity with the canonical POST /devices/{id}/reboot, which
    # requires an explicit confirm — this actions-module sibling was missing it.
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rebooting disrupts the device; pass confirm=true.",
        )
    device = await get_device_with_access(request.device_id, current_user, session)

    if not device.controller_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Device is not managed by a controller"
        )

    controller_result = await session.execute(
        select(Controller).where(
            Controller.id == device.controller_id, Controller.deleted_at.is_(None)
        )
    )
    controller = controller_result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Device controller not found"
        )

    try:
        adapter = create_adapter(controller)
        await adapter.connect()

        try:
            result = await adapter.reboot_device(str(device.external_id or device.id))
            # Honest failure (don't publish a reboot event / return success=true
            # when the controller rejected/failed the reboot).
            if result is not None and not getattr(result, "success", True):
                return ActionResponse(
                    success=False,
                    message=(
                        getattr(result, "error", None)
                        or getattr(result, "message", None)
                        or f"Controller refused the reboot for {device.name}"
                    ),
                    data={"device_id": str(device.id)},
                )

            logger.warning(f"User {current_user.user.email} rebooted device {device.name}")

            # Publish event
            event_bus = get_event_bus()
            from app.core.events import org_id_for_site

            org_id = await org_id_for_site(session, device.site_id)
            await event_bus.publish(
                device_event(
                    "action.reboot",
                    device_id=str(device.id),
                    site_id=str(device.site_id),
                    organization_id=org_id,
                    user=current_user.user.email,
                )
            )

            return ActionResponse(
                success=True,
                message=f"Reboot initiated for {device.name}",
                data={"device_id": str(device.id)},
            )
        finally:
            await adapter.disconnect()

    except Exception as e:
        logger.error("Device reboot failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to reboot device"
        )
