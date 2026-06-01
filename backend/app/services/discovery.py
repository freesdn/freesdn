# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Discovery Service
================================

Coordinates device discovery across all controllers.
"""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterDevice, BaseAdapter
from app.adapters.hikvision import HikvisionAdapter
from app.adapters.mikrotik import MikroTikAdapter
from app.adapters.omada import OmadaAdapter
from app.adapters.opnsense import OPNsenseAdapter
from app.adapters.pfsense import PfSenseAdapter
from app.adapters.proxmox import ProxmoxAdapter
from app.core.events import device_event, discovery_event, get_event_bus, org_id_for_site
from app.db.models import Controller, Device, DeviceStatus, DeviceType

logger = logging.getLogger(__name__)


class DiscoveryError(Exception):
    """Discovery-related errors."""

    pass


class DiscoveryService:
    """
    Service for coordinating device discovery across controllers.

    Handles:
    - Connecting to controllers via adapters
    - Discovering devices from each controller
    - Syncing discovered devices to database
    - Broadcasting events for real-time updates
    """

    ADAPTER_MAP = {
        "omada": OmadaAdapter,
        "tplink_omada": OmadaAdapter,
        "hikvision": HikvisionAdapter,
        "opnsense": OPNsenseAdapter,
        "pfsense": PfSenseAdapter,
        "mikrotik": MikroTikAdapter,
        "proxmox": ProxmoxAdapter,
    }

    def __init__(self, db: AsyncSession):
        self.db = db
        self.event_bus = get_event_bus()

    def _create_adapter(self, controller: Controller) -> BaseAdapter:
        """Create adapter instance for a controller."""
        adapter_class = self.ADAPTER_MAP.get(controller.type.lower())
        if not adapter_class:
            raise DiscoveryError(f"Unknown controller type: {controller.type}")

        kwargs: dict[str, Any] = {
            "host": controller.host,
            "username": controller.username,
            "password": controller.password,
            "port": controller.port,
            "use_ssl": controller.use_ssl,
            "verify_ssl": controller.verify_ssl,
            "mode": controller.connection_mode,
        }
        # Pass cloud-specific fields if present
        if controller.client_id:
            kwargs["client_id"] = controller.client_id
        if controller.client_secret:
            kwargs["client_secret"] = controller.client_secret
        if controller.omada_id:
            kwargs["omada_id"] = controller.omada_id
        if controller.cloud_region:
            kwargs["cloud_region"] = controller.cloud_region

        # Proxmox API token auth
        if controller.type.lower() == "proxmox":
            config = controller.config or {}
            token_id = config.get("token_id", "")
            if token_id:
                kwargs["token_id"] = token_id
                kwargs["token_secret"] = config.get("token_secret", "")
            kwargs["realm"] = config.get("realm", "pam")

        return adapter_class(**kwargs)

    async def discover_controller(self, controller_id: UUID) -> dict[str, Any]:
        """
        Discover all devices from a specific controller.

        Returns discovery statistics.
        """
        # Get controller
        result = await self.db.execute(select(Controller).where(Controller.id == controller_id))
        controller = result.scalar_one_or_none()
        if not controller:
            raise DiscoveryError(f"Controller {controller_id} not found")

        logger.info("Starting discovery for controller: %s", controller.name)

        # Publish start event
        ctrl_org_id = await org_id_for_site(self.db, controller.site_id)
        await self.event_bus.publish(
            discovery_event(
                "started",
                organization_id=ctrl_org_id,
                controller_id=str(controller_id),
                controller_name=controller.name,
            )
        )

        try:
            # Create and connect adapter
            adapter = self._create_adapter(controller)
            await adapter.connect()

            try:
                # Discover devices
                discovered = await adapter.get_devices()
                logger.info("Discovered %d devices from %s", len(discovered), controller.name)

                # Process devices
                stats = await self._process_devices(discovered, controller_id, controller.site_id)

                # Update controller
                controller.last_sync = datetime.now(UTC)
                controller.status = "online"
                await self.db.commit()

                # Publish completion event
                await self.event_bus.publish(
                    discovery_event(
                        "completed",
                        organization_id=ctrl_org_id,
                        controller_id=str(controller_id),
                        controller_name=controller.name,
                        stats=stats,
                    )
                )

                return stats
            finally:
                await adapter.disconnect()

        except Exception as e:
            logger.error("Discovery failed for %s: %s", controller.name, e)
            controller.status = "error"
            await self.db.commit()

            await self.event_bus.publish(
                discovery_event(
                    "failed",
                    organization_id=ctrl_org_id,
                    controller_id=str(controller_id),
                    error=str(e),
                )
            )
            raise

    async def discover_all(
        self,
        site_id: UUID | None = None,
        *,
        organization_id: UUID | None = None,
        site_ids: list[UUID] | set[UUID] | None = None,
    ) -> dict[str, Any]:
        """
        Discover devices from all controllers (optionally filtered by site).

        SECURITY: ``organization_id`` and ``site_ids`` scope the
        controller set so a user-triggered "discover all" never opens adapters
        against another tenant's controllers (org scope) or against sibling
        sites a site-limited caller was not granted (per-user site grant).
        ``organization_id=None`` is the unscoped system/maintenance path; the
        endpoint always passes the caller's org + accessible-site set so the
        public surface is fail-closed.
        """
        from app.db.models import Site

        query = select(Controller).where(Controller.status != "disabled")
        if organization_id is not None:
            # Scope to the caller's org via the controller's Site, so a
            # non-superuser run can never reach another tenant's controllers.
            query = query.join(Site, Controller.site_id == Site.id).where(
                Site.organization_id == organization_id,
                Site.deleted_at.is_(None),
            )
        if site_ids is not None:
            # Per-user site grant: a site-limited caller only discovers the
            # controllers in their granted sites. An empty set fails closed.
            query = query.where(Controller.site_id.in_(list(site_ids)))
        if site_id:
            query = query.where(Controller.site_id == site_id)

        result = await self.db.execute(query)
        controllers = result.scalars().all()

        total_stats = {
            "controllers": len(controllers),
            "total_devices": 0,
            "new_devices": 0,
            "updated_devices": 0,
            "failed_controllers": 0,
            "errors": [],
        }

        for controller in controllers:
            try:
                stats = await self.discover_controller(controller.id)
                total_stats["total_devices"] += stats["total"]
                total_stats["new_devices"] += stats["new"]
                total_stats["updated_devices"] += stats["updated"]
            except Exception as e:
                total_stats["failed_controllers"] += 1
                total_stats["errors"].append({"controller": controller.name, "error": str(e)})

        return total_stats

    async def _process_devices(
        self, devices: list[AdapterDevice], controller_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        """Process discovered devices and sync to database."""
        stats = {"total": len(devices), "new": 0, "updated": 0, "unchanged": 0, "errors": []}

        # Batch-load existing devices to avoid N+1 queries per device
        existing_by_mac, existing_by_serial = await self._batch_load_existing_devices(devices)

        for device_data in devices:
            try:
                # Look up existing device from pre-loaded maps
                existing = None
                if device_data.mac and device_data.mac in existing_by_mac:
                    existing = existing_by_mac[device_data.mac]
                elif device_data.serial and device_data.serial in existing_by_serial:
                    existing = existing_by_serial[device_data.serial]

                if existing:
                    changed = await self._update_device(existing, device_data)
                    stats["updated" if changed else "unchanged"] += 1
                else:
                    await self._create_device(device_data, controller_id, site_id)
                    stats["new"] += 1

            except Exception as e:
                logger.error("Failed to process device %s: %s", device_data.name, e)
                stats["errors"].append({"device": device_data.name, "error": str(e)})

        await self.db.commit()
        return stats

    async def _batch_load_existing_devices(
        self, devices: list[AdapterDevice]
    ) -> tuple[dict[str, Device], dict[str, Device]]:
        """Batch-load existing devices by MAC and serial in a single query."""
        macs = [d.mac for d in devices if d.mac]
        serials = [d.serial for d in devices if d.serial]

        existing_by_mac: dict[str, Device] = {}
        existing_by_serial: dict[str, Device] = {}

        if not macs and not serials:
            return existing_by_mac, existing_by_serial

        conditions = []
        if macs:
            conditions.append(Device.mac_address.in_(macs))
        if serials:
            conditions.append(Device.serial_number.in_(serials))

        result = await self.db.execute(
            select(Device).where(or_(*conditions), Device.deleted_at.is_(None))
        )
        for device in result.scalars().all():
            if device.mac_address:
                existing_by_mac[device.mac_address] = device
            if device.serial_number:
                existing_by_serial[device.serial_number] = device

        return existing_by_mac, existing_by_serial

    async def _find_existing_device(self, data: AdapterDevice) -> Device | None:
        """Find existing device by MAC or serial."""
        if data.mac:
            result = await self.db.execute(
                select(Device).where(Device.mac_address == data.mac, Device.deleted_at.is_(None))
            )
            device = result.scalar_one_or_none()
            if device:
                return device

        if data.serial:
            result = await self.db.execute(
                select(Device).where(
                    Device.serial_number == data.serial, Device.deleted_at.is_(None)
                )
            )
            return result.scalar_one_or_none()

        return None

    async def _create_device(
        self, data: AdapterDevice, controller_id: UUID, site_id: UUID
    ) -> Device:
        """Create new device in database."""
        device = Device(
            site_id=site_id,
            controller_id=controller_id,
            vendor=data.vendor,
            model=data.model,
            device_type=DeviceType(data.device_type) if data.device_type else DeviceType.UNKNOWN,
            serial=data.serial,
            mac=data.mac,
            ip=data.ip,
            name=data.name,
            hostname=data.hostname,
            status=DeviceStatus(data.status) if data.status else DeviceStatus.UNKNOWN,
            firmware_version=data.firmware_version,
            capabilities=data.capabilities,
            vendor_data=data.vendor_data,
            last_seen=datetime.now(UTC),
            discovered_at=datetime.now(UTC),
        )

        self.db.add(device)
        await self.db.flush()

        logger.info("Created device: %s (%s)", device.name, device.device_type)

        # Publish device discovered event
        discovered_org_id = await org_id_for_site(self.db, site_id)
        await self.event_bus.publish(
            device_event(
                "discovered",
                device_id=str(device.id),
                site_id=str(site_id),
                organization_id=discovered_org_id,
                name=device.name,
                device_type=device.device_type.value,
                vendor=device.vendor,
            )
        )

        return device

    async def _update_device(self, device: Device, data: AdapterDevice) -> bool:
        """Update existing device with new data. Returns True if changed."""
        changed = False
        prev_status = device.status

        # Update mutable fields
        for field, value in [
            ("name", data.name),
            ("ip", data.ip),
            ("firmware_version", data.firmware_version),
            ("capabilities", data.capabilities),
            ("vendor_data", data.vendor_data),
        ]:
            if value and getattr(device, field) != value:
                setattr(device, field, value)
                changed = True

        # Handle status change
        new_status = DeviceStatus(data.status) if data.status else device.status
        if device.status != new_status:
            device.status = new_status
            changed = True

            update_org_id = await org_id_for_site(self.db, device.site_id)
            await self.event_bus.publish(
                device_event(
                    "status.changed",
                    device_id=str(device.id),
                    site_id=str(device.site_id),
                    organization_id=update_org_id,
                    name=device.name,
                    previous_status=prev_status.value,
                    new_status=new_status.value,
                )
            )

        device.last_seen = datetime.now(UTC)

        if changed:
            updated_org_id = await org_id_for_site(self.db, device.site_id)
            await self.event_bus.publish(
                device_event(
                    "updated",
                    device_id=str(device.id),
                    site_id=str(device.site_id),
                    organization_id=updated_org_id,
                    name=device.name,
                )
            )

        return changed
