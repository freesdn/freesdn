# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device Control Service
=====================================

Unified interface for device control operations including:
- Device actions (reboot, locate, factory reset)
- PoE port control
- SSID/Wireless management
- Port configuration
- Configuration backup/restore
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult, BaseAdapter
from app.adapters.capabilities import Capability
from app.adapters.exceptions import (
    AdapterError,
)
from app.adapters.registry import adapter_registry
from app.core.events import device_event, get_event_bus
from app.models import Controller, Device

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================


class ActionType(StrEnum):
    """Types of device actions."""

    # General
    REBOOT = "reboot"
    LOCATE = "locate"
    FACTORY_RESET = "factory_reset"

    # PoE
    POE_ENABLE = "poe_enable"
    POE_DISABLE = "poe_disable"
    POE_CYCLE = "poe_cycle"

    # Ports
    PORT_ENABLE = "port_enable"
    PORT_DISABLE = "port_disable"
    PORT_CONFIGURE = "port_configure"

    # WiFi
    SSID_ENABLE = "ssid_enable"
    SSID_DISABLE = "ssid_disable"
    SSID_UPDATE = "ssid_update"
    CLIENT_DISCONNECT = "client_disconnect"
    CLIENT_BLOCK = "client_block"
    CLIENT_UNBLOCK = "client_unblock"

    # Camera
    CAMERA_SNAPSHOT = "camera_snapshot"
    CAMERA_PTZ = "camera_ptz"
    CAMERA_REBOOT = "camera_reboot"

    # Configuration
    CONFIG_BACKUP = "config_backup"
    CONFIG_RESTORE = "config_restore"

    # Firmware
    FIRMWARE_CHECK = "firmware_check"
    FIRMWARE_UPGRADE = "firmware_upgrade"


# Action to capability mapping
ACTION_CAPABILITIES: dict[ActionType, Capability] = {
    ActionType.REBOOT: Capability.DEVICE_REBOOT,
    ActionType.LOCATE: Capability.DEVICE_LOCATE,
    ActionType.FACTORY_RESET: Capability.DEVICE_FACTORY_RESET,
    ActionType.POE_ENABLE: Capability.POE_CONTROL,
    ActionType.POE_DISABLE: Capability.POE_CONTROL,
    ActionType.POE_CYCLE: Capability.POE_CONTROL,
    ActionType.PORT_ENABLE: Capability.SWITCH_PORT_CONFIG,
    ActionType.PORT_DISABLE: Capability.SWITCH_PORT_CONFIG,
    ActionType.PORT_CONFIGURE: Capability.SWITCH_PORT_CONFIG,
    ActionType.SSID_ENABLE: Capability.WIFI_SSID_MANAGEMENT,
    ActionType.SSID_DISABLE: Capability.WIFI_SSID_MANAGEMENT,
    ActionType.SSID_UPDATE: Capability.WIFI_SSID_MANAGEMENT,
    ActionType.CLIENT_DISCONNECT: Capability.WIFI_CLIENT_KICK,
    ActionType.CLIENT_BLOCK: Capability.WIFI_CLIENT_BLOCK,
    ActionType.CLIENT_UNBLOCK: Capability.WIFI_CLIENT_BLOCK,
    ActionType.CAMERA_SNAPSHOT: Capability.CAMERA_SNAPSHOT,
    ActionType.CAMERA_PTZ: Capability.CAMERA_PTZ,
    ActionType.CAMERA_REBOOT: Capability.DEVICE_REBOOT,
    ActionType.CONFIG_BACKUP: Capability.DEVICE_BACKUP,
    ActionType.CONFIG_RESTORE: Capability.DEVICE_RESTORE,
    ActionType.FIRMWARE_CHECK: Capability.DEVICE_FIRMWARE_CHECK,
    ActionType.FIRMWARE_UPGRADE: Capability.DEVICE_FIRMWARE_UPGRADE,
}


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ActionRequest:
    """Request for a device action."""

    device_id: UUID
    action_type: ActionType
    parameters: dict[str, Any] = field(default_factory=dict)
    initiated_by: str = "system"


@dataclass
class ActionResponse:
    """Response from a device action."""

    success: bool
    message: str
    action_type: ActionType
    device_id: UUID
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_ms: float = 0

    def complete(self) -> None:
        """Mark the action as complete and calculate duration."""
        self.completed_at = datetime.now(UTC)
        if self.started_at:
            delta = self.completed_at - self.started_at
            self.duration_ms = delta.total_seconds() * 1000


# =============================================================================
# Device Control Service
# =============================================================================


class DeviceControlService:
    """
    Unified device control service.

    Handles all device control operations through the appropriate adapter,
    with proper error handling, logging, and event publishing.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.event_bus = get_event_bus()

    # =========================================================================
    # Core Methods
    # =========================================================================

    async def get_device(self, device_id: UUID) -> Device | None:
        """Get a device by ID."""
        result = await self.db.execute(
            select(Device).where(Device.id == device_id, Device.deleted_at.is_(None))
        )
        return result.scalar_one_or_none()

    async def get_controller(self, controller_id: UUID) -> Controller | None:
        """Get a controller by ID."""
        result = await self.db.execute(
            select(Controller).where(
                Controller.id == controller_id, Controller.deleted_at.is_(None)
            )
        )
        return result.scalar_one_or_none()

    async def get_adapter_for_device(self, device: Device) -> BaseAdapter | None:
        """
        Get the appropriate adapter instance for a device.

        Handles both controller-managed and standalone devices.
        Forwards all connection config (SSL, cloud credentials, etc.) to the adapter.
        """
        if device.controller_id:
            controller = await self.get_controller(device.controller_id)
            if not controller:
                return None

            adapter_id = controller.type.lower()

            # Build kwargs from controller config for adapter factory
            kwargs: dict[str, Any] = {
                "port": controller.port,
                "use_ssl": controller.use_ssl,
                "verify_ssl": controller.verify_ssl,
            }

            # Forward cloud-mode config if present
            if controller.connection_mode == "cloud":
                kwargs["mode"] = "cloud"
                if controller.client_id:
                    kwargs["client_id"] = controller.client_id
                if controller.client_secret:
                    kwargs["client_secret"] = controller.client_secret
                if controller.omada_id:
                    kwargs["omada_id"] = controller.omada_id
                if controller.cloud_region:
                    kwargs["cloud_region"] = controller.cloud_region
            else:
                kwargs["mode"] = "local"

            try:
                return adapter_registry.create_adapter(
                    adapter_id=adapter_id,
                    host=controller.host,
                    username=controller.username or "",
                    password=controller.password or "",
                    **kwargs,
                )
            except Exception as e:
                logger.error("Failed to create adapter %s: %s", adapter_id, e)
                return None

        # Standalone device - try to find adapter by vendor
        adapter_vendor = getattr(device, "vendor", None) or getattr(device, "manufacturer", None)
        adapter_id = adapter_vendor.lower() if adapter_vendor else None
        if adapter_id and device.ip_address:
            try:
                return adapter_registry.create_adapter(
                    adapter_id=adapter_id,
                    host=device.ip_address,
                    username=getattr(device, "username", "") or "",
                    password=getattr(device, "password", "") or "",
                )
            except Exception as e:
                logger.error("Failed to create adapter for standalone device: %s", e)

        return None

    def check_capability(
        self,
        adapter: BaseAdapter,
        action_type: ActionType,
        device: Device | None = None,
    ) -> bool:
        """Check if the adapter supports the required capability."""
        required_cap = ACTION_CAPABILITIES.get(action_type)
        if not required_cap:
            return True  # No specific capability required

        device_type = str(device.device_type).lower() if device and device.device_type else None
        return adapter.has_capability(required_cap, device_type=device_type)

    # =========================================================================
    # Action Execution
    # =========================================================================

    async def execute_action(self, request: ActionRequest) -> ActionResponse:
        """
        Execute a device action.

        Main entry point for all device control operations.
        """
        response = ActionResponse(
            success=False,
            message="",
            action_type=request.action_type,
            device_id=request.device_id,
        )

        try:
            # Get device
            device = await self.get_device(request.device_id)
            if not device:
                response.message = "Device not found"
                response.error = "device_not_found"
                response.complete()
                return response

            # Get adapter
            adapter = await self.get_adapter_for_device(device)
            if not adapter:
                response.message = "No compatible adapter found"
                response.error = "no_adapter"
                response.complete()
                return response

            # Check capability
            if not self.check_capability(adapter, request.action_type, device):
                cap = ACTION_CAPABILITIES.get(request.action_type)
                response.message = f"Device does not support {cap.value if cap else 'this action'}"
                response.error = "capability_not_supported"
                response.complete()
                return response

            # Execute action
            async with adapter:
                result = await self._execute_action_with_adapter(adapter, device, request)

            response.success = result.success
            response.message = (
                result.message
                or ("Success" if result.success else result.error)
                or ("Success" if result.success else "Failed")
            )
            response.data = result.data or {}
            response.error = result.error

            # Publish event
            from app.core.events import org_id_for_site

            org_id = await org_id_for_site(self.db, device.site_id)
            await self.event_bus.publish(
                device_event(
                    "action_completed" if response.success else "action_failed",
                    device_id=str(device.id),
                    site_id=str(device.site_id) if device.site_id else None,
                    organization_id=org_id,
                    device_name=device.name,
                    action=request.action_type.value,
                    success=response.success,
                    message=response.message,
                )
            )

        except AdapterError as e:
            logger.error("Adapter error for action %s: %s", request.action_type, e)
            response.message = str(e)
            response.error = e.__class__.__name__
        except Exception as e:
            logger.exception("Action failed: %s on %s", request.action_type, request.device_id)
            response.message = f"Action failed: {str(e)}"
            response.error = str(e)

        response.complete()
        return response

    async def _execute_action_with_adapter(
        self,
        adapter: BaseAdapter,
        device: Device,
        request: ActionRequest,
    ) -> AdapterResult:
        """Execute the specific action with the adapter."""
        action_type = request.action_type
        params = request.parameters

        # Device identifier for adapter calls
        device_id = device.external_id or str(device.id)

        # Route to appropriate method
        match action_type:
            # General actions
            case ActionType.REBOOT:
                return await adapter.reboot_device(device_id)
            case ActionType.LOCATE:
                duration = params.get("duration", 30)
                return await adapter.locate_device(device_id, duration)
            case ActionType.FACTORY_RESET:
                confirm = params.get("confirm", False)
                if not confirm:
                    return AdapterResult(success=False, error="Factory reset requires confirmation")
                return await adapter.factory_reset(device_id)

            # PoE actions
            case ActionType.POE_ENABLE:
                port = params.get("port")
                if port is None:
                    return AdapterResult(success=False, error="Port required")
                return await adapter.set_port_poe(device_id, port, True)
            case ActionType.POE_DISABLE:
                port = params.get("port")
                if port is None:
                    return AdapterResult(success=False, error="Port required")
                return await adapter.set_port_poe(device_id, port, False)
            case ActionType.POE_CYCLE:
                port = params.get("port")
                duration = params.get("duration", 5)
                if port is None:
                    return AdapterResult(success=False, error="Port required")
                return await adapter.cycle_poe_port(device_id, port, duration)

            # Port actions
            case ActionType.PORT_ENABLE:
                port = params.get("port")
                if port is None:
                    return AdapterResult(success=False, error="Port required")
                return await adapter.set_port_enabled(device_id, port, True)
            case ActionType.PORT_DISABLE:
                port = params.get("port")
                if port is None:
                    return AdapterResult(success=False, error="Port required")
                return await adapter.set_port_enabled(device_id, port, False)
            case ActionType.PORT_CONFIGURE:
                port = params.get("port")
                config = params.get("config")
                if port is None:
                    return AdapterResult(success=False, error="Port required")
                if not isinstance(config, dict):
                    return AdapterResult(success=False, error="Port config required")
                configure_port = getattr(adapter, "configure_switch_port", None)
                if callable(configure_port):
                    return await configure_port(device_id, port, config)
                return AdapterResult(success=False, error="Port configuration not supported")

            # WiFi actions
            case ActionType.SSID_ENABLE:
                ssid_id = params.get("ssid_id")
                if not ssid_id:
                    return AdapterResult(success=False, error="SSID ID required")
                return await adapter.toggle_ssid(ssid_id, True)
            case ActionType.SSID_DISABLE:
                ssid_id = params.get("ssid_id")
                if not ssid_id:
                    return AdapterResult(success=False, error="SSID ID required")
                return await adapter.toggle_ssid(ssid_id, False)
            case ActionType.SSID_UPDATE:
                ssid_id = params.get("ssid_id")
                if not ssid_id:
                    return AdapterResult(success=False, error="SSID ID required")
                config = params.get("config")
                if not isinstance(config, dict):
                    return AdapterResult(success=False, error="SSID config required")
                update_ssid = getattr(adapter, "update_ssid", None)
                if callable(update_ssid):
                    return await update_ssid(ssid_id, config)
                return AdapterResult(success=False, error="SSID update not supported")
            case ActionType.CLIENT_DISCONNECT:
                client_mac = params.get("client_mac")
                if not client_mac:
                    return AdapterResult(success=False, error="Client MAC required")
                return await adapter.kick_client(client_mac)
            case ActionType.CLIENT_BLOCK:
                client_mac = params.get("client_mac")
                if not client_mac:
                    return AdapterResult(success=False, error="Client MAC required")
                return await adapter.block_client(client_mac)
            case ActionType.CLIENT_UNBLOCK:
                client_mac = params.get("client_mac")
                if not client_mac:
                    return AdapterResult(success=False, error="Client MAC required")
                return await adapter.unblock_client(client_mac)

            # Camera actions
            case ActionType.CAMERA_SNAPSHOT:
                return await adapter.get_snapshot(device_id)
            case ActionType.CAMERA_PTZ:
                command = params.get("command")
                speed = params.get("speed", 50)
                return await adapter.ptz_control(device_id, command, speed)
            case ActionType.CAMERA_REBOOT:
                return await adapter.reboot_device(device_id)

            # Firmware actions
            case ActionType.FIRMWARE_CHECK:
                get_firmware_info = getattr(adapter, "get_firmware_info", None)
                if callable(get_firmware_info):
                    return AdapterResult.ok(await get_firmware_info(device_id))
                return AdapterResult(success=False, error="Firmware check not supported")
            case ActionType.FIRMWARE_UPGRADE:
                upgrade_firmware = getattr(adapter, "upgrade_firmware", None)
                if callable(upgrade_firmware):
                    return await upgrade_firmware(device_id)
                return AdapterResult(success=False, error="Firmware upgrade not supported")

            # Configuration actions
            case ActionType.CONFIG_BACKUP:
                backup_config = getattr(adapter, "backup_config", None)
                if callable(backup_config):
                    return await backup_config(device_id)
                return AdapterResult(success=False, error="Configuration backup not supported")
            case ActionType.CONFIG_RESTORE:
                backup_id = params.get("backup_id")
                if not backup_id:
                    return AdapterResult(success=False, error="Backup ID required")
                restore_config = getattr(adapter, "restore_config", None)
                if callable(restore_config):
                    return await restore_config(device_id, backup_id)
                return AdapterResult(success=False, error="Configuration restore not supported")

            case _:
                return AdapterResult(success=False, error=f"Unknown action type: {action_type}")

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    async def reboot_device(self, device_id: UUID, initiated_by: str = "api") -> ActionResponse:
        """Reboot a device."""
        return await self.execute_action(
            ActionRequest(
                device_id=device_id,
                action_type=ActionType.REBOOT,
                initiated_by=initiated_by,
            )
        )

    async def locate_device(
        self,
        device_id: UUID,
        duration: int = 30,
        initiated_by: str = "api",
    ) -> ActionResponse:
        """Blink LED on a device for identification."""
        return await self.execute_action(
            ActionRequest(
                device_id=device_id,
                action_type=ActionType.LOCATE,
                parameters={"duration": duration},
                initiated_by=initiated_by,
            )
        )

    async def set_poe_state(
        self,
        device_id: UUID,
        port: int,
        enabled: bool,
        initiated_by: str = "api",
    ) -> ActionResponse:
        """Enable or disable PoE on a port."""
        return await self.execute_action(
            ActionRequest(
                device_id=device_id,
                action_type=ActionType.POE_ENABLE if enabled else ActionType.POE_DISABLE,
                parameters={"port": port},
                initiated_by=initiated_by,
            )
        )

    async def cycle_poe(
        self,
        device_id: UUID,
        port: int,
        duration: int = 5,
        initiated_by: str = "api",
    ) -> ActionResponse:
        """Cycle PoE power on a port."""
        return await self.execute_action(
            ActionRequest(
                device_id=device_id,
                action_type=ActionType.POE_CYCLE,
                parameters={"port": port, "duration": duration},
                initiated_by=initiated_by,
            )
        )

    async def get_camera_snapshot(
        self,
        device_id: UUID,
        initiated_by: str = "api",
    ) -> ActionResponse:
        """Get a snapshot from a camera."""
        return await self.execute_action(
            ActionRequest(
                device_id=device_id,
                action_type=ActionType.CAMERA_SNAPSHOT,
                initiated_by=initiated_by,
            )
        )

    async def ptz_control(
        self,
        device_id: UUID,
        command: str,
        speed: int = 50,
        initiated_by: str = "api",
    ) -> ActionResponse:
        """Control camera PTZ."""
        return await self.execute_action(
            ActionRequest(
                device_id=device_id,
                action_type=ActionType.CAMERA_PTZ,
                parameters={"command": command, "speed": speed},
                initiated_by=initiated_by,
            )
        )

    # =========================================================================
    # Bulk Operations
    # =========================================================================

    async def bulk_execute(
        self,
        device_ids: list[UUID],
        action_type: ActionType,
        parameters: dict[str, Any] | None = None,
        initiated_by: str = "api",
    ) -> list[ActionResponse]:
        """
        Execute an action on multiple devices.
        """
        responses = []
        for device_id in device_ids:
            response = await self.execute_action(
                ActionRequest(
                    device_id=device_id,
                    action_type=action_type,
                    parameters=parameters or {},
                    initiated_by=initiated_by,
                )
            )
            responses.append(response)
        return responses

    async def bulk_reboot(
        self,
        device_ids: list[UUID],
        initiated_by: str = "api",
    ) -> list[ActionResponse]:
        """Reboot multiple devices."""
        return await self.bulk_execute(
            device_ids=device_ids,
            action_type=ActionType.REBOOT,
            initiated_by=initiated_by,
        )
