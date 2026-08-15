# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device Sync Tasks
===============================

Celery tasks for syncing device state and configuration.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.celery_app import celery_app
from app.core.crypto import decrypt_credential, is_encrypted
from app.core.events import EventType, org_id_for_site, publish_device_event
from app.db.models import Controller, ControllerStatus, Device, DeviceStatus
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.services.adapter_factory import get_adapter

logger = logging.getLogger(__name__)


def _decrypt_if_needed(value: str | None) -> str:
    """Return plaintext for encrypted controller secrets.

    Raises ValueError if decryption fails — callers should handle this
    to avoid connecting with empty/invalid credentials.
    """
    if not value:
        return ""
    if not is_encrypted(value):
        return value
    try:
        return decrypt_credential(value)
    except ValueError:
        logger.error("Failed to decrypt credential — encryption key may have changed")
        raise


async def _sync_device_status(device_id: str) -> dict[str, Any]:
    """
    Sync status for a specific device.

    Returns:
        Sync result with updated status.
    """
    async with AsyncSessionLocal() as session:
        # Get device with controller
        result = await session.execute(
            select(Device)
            .options(
                selectinload(Device.controller),
                selectinload(Device.site),
            )
            .where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()

        if not device:
            return {
                "success": False,
                "error": f"Device {device_id} not found",
            }

        if not device.controller:
            return {
                "success": False,
                "error": f"Device {device_id} has no controller",
            }

        try:
            # Build adapter kwargs from controller model
            ctrl = device.controller
            adapter_kwargs: dict[str, Any] = {
                "port": ctrl.port,
                "use_ssl": ctrl.use_ssl,
                "verify_ssl": ctrl.verify_ssl,
                "mode": ctrl.connection_mode,
            }

            if ctrl.connection_mode == "cloud":
                adapter_kwargs["client_id"] = ctrl.client_id or ""
                adapter_kwargs["client_secret"] = _decrypt_if_needed(ctrl.client_secret)
                adapter_kwargs["omada_id"] = ctrl.omada_id or ""
                adapter_kwargs["cloud_region"] = ctrl.cloud_region or ""

            adapter = get_adapter(
                ctrl.controller_type,
                host=ctrl.host,
                username=ctrl.username or "",
                password=_decrypt_if_needed(ctrl.password),
                **adapter_kwargs,
            )

            async with adapter:
                # Get device status
                status_data = await adapter.get_device_status(device.mac_address)

            if status_data:
                old_status = device.status
                new_status = status_data.get("status", device.status)

                # Update device
                device.status = new_status
                device.last_seen = datetime.now(UTC)

                if "ip_address" in status_data:
                    device.ip_address = status_data["ip_address"]
                if "uptime" in status_data:
                    device.uptime_seconds = status_data["uptime"]

                await session.commit()

                # Publish event if status changed
                if old_status != new_status:
                    org_id = await org_id_for_site(session, device.site_id)
                    await publish_device_event(
                        EventType.DEVICE_STATUS_CHANGED,
                        device_id=str(device.id),
                        data={
                            "name": device.name,
                            "old_status": old_status,
                            "new_status": new_status,
                        },
                        device_type=device.device_type,
                        controller_id=str(device.controller_id),
                        site_id=str(device.site_id) if device.site_id else None,
                        organization_id=org_id,
                    )

                return {
                    "success": True,
                    "device_id": str(device.id),
                    "device_name": device.name,
                    "status": new_status,
                    "status_changed": old_status != new_status,
                }
            else:
                # Device not found in controller - mark as offline
                if device.status != DeviceStatus.OFFLINE:
                    old_status = device.status
                    device.status = DeviceStatus.OFFLINE
                    await session.commit()

                    org_id = await org_id_for_site(session, device.site_id)
                    await publish_device_event(
                        EventType.DEVICE_STATUS_CHANGED,
                        device_id=str(device.id),
                        data={
                            "name": device.name,
                            "old_status": old_status,
                            "new_status": DeviceStatus.OFFLINE,
                        },
                        device_type=device.device_type,
                        controller_id=str(device.controller_id),
                        site_id=str(device.site_id) if device.site_id else None,
                        organization_id=org_id,
                    )

                return {
                    "success": True,
                    "device_id": str(device.id),
                    "device_name": device.name,
                    "status": DeviceStatus.OFFLINE,
                    "message": "Device not found in controller",
                }

        except Exception as e:
            logger.exception("Error syncing device %s", device_id)
            return {
                "success": False,
                "device_id": str(device.id),
                "error": str(e),
            }


@celery_app.task(bind=True, max_retries=2, soft_time_limit=120, time_limit=150)
def sync_device_status(self, device_id: str) -> dict[str, Any]:
    """
    Celery task to sync status for a specific device.
    """
    try:
        return asyncio.run(_sync_device_status(device_id))
    except Exception as e:
        logger.exception("Sync task failed for device %s", device_id)
        raise self.retry(exc=e, countdown=30)


_DEVICE_SYNC_CONCURRENCY = 5  # Max controllers synced in parallel


async def _sync_all_device_statuses(
    organization_id: str | None = None,
    site_id: str | None = None,
) -> dict[str, Any]:
    """Sync status for all devices, grouped by controller.

    Instead of creating one adapter per device (N+1), we open one adapter
    per controller and sync all its devices through that single connection.
    Controllers marked UNREACHABLE are skipped entirely.

    When ``organization_id`` is given (user-triggered full sync), only that
    tenant's devices are synced — a user can't drive sync against every
    other tenant's controllers. ``None`` is the scheduled maintenance run.
    """
    from uuid import UUID as _UUID

    async with AsyncSessionLocal() as session:
        # Load devices grouped with their controller, skip unreachable controllers
        q = (
            select(Device)
            .options(selectinload(Device.controller))
            .join(Controller, Device.controller_id == Controller.id)
            .where(
                Device.controller_id.isnot(None),
                Controller.deleted_at.is_(None),
                Controller.is_active.is_(True),
                Controller.sync_enabled.is_(True),
                Controller.status != ControllerStatus.UNREACHABLE,
            )
        )
        if organization_id:
            from app.db.models import Site

            q = q.join(Site, Device.site_id == Site.id).where(
                Site.organization_id == _UUID(organization_id),
                Site.deleted_at.is_(None),
            )
            if site_id:
                q = q.where(Device.site_id == _UUID(site_id))
        result = await session.execute(q)
        devices = result.scalars().all()

        if not devices:
            return {
                "success": True,
                "message": "No devices to sync (or all controllers unreachable)",
                "devices_processed": 0,
                "devices_successful": 0,
                "devices_failed": 0,
                "status_changes": 0,
            }

        # Group devices by controller_id
        from collections import defaultdict

        by_controller: dict[str, list[Device]] = defaultdict(list)
        for dev in devices:
            by_controller[str(dev.controller_id)].append(dev)

    # Sync all devices for one controller through a single adapter connection
    semaphore = asyncio.Semaphore(_DEVICE_SYNC_CONCURRENCY)

    async def _sync_controller_devices(ctrl_id: str, devs: list[Device]) -> list[dict[str, Any]]:
        async with semaphore:
            ctrl = devs[0].controller
            results_list: list[dict[str, Any]] = []
            try:
                cloud_kwargs: dict[str, Any] = {}
                if ctrl.connection_mode == "cloud":
                    cloud_kwargs = {
                        "client_id": ctrl.client_id or "",
                        "client_secret": _decrypt_if_needed(ctrl.client_secret),
                        "omada_id": ctrl.omada_id or "",
                        "cloud_region": ctrl.cloud_region or "",
                    }
                adapter = get_adapter(
                    ctrl.controller_type,
                    host=ctrl.host,
                    username=ctrl.username or "",
                    password=_decrypt_if_needed(ctrl.password),
                    port=ctrl.port,
                    use_ssl=ctrl.use_ssl,
                    verify_ssl=ctrl.verify_ssl,
                    mode=ctrl.connection_mode or "local",
                    **cloud_kwargs,
                )

                async with adapter:
                    for dev in devs:
                        try:
                            status_data = await adapter.get_device_status(dev.mac_address)
                            async with AsyncSessionLocal() as sess:
                                d = await sess.get(Device, dev.id)
                                if not d:
                                    results_list.append(
                                        {
                                            "success": False,
                                            "device_id": str(dev.id),
                                            "error": "not found",
                                        }
                                    )
                                    continue
                                old_status = d.status
                                if status_data:
                                    new_status = status_data.get("status", d.status)
                                    d.status = new_status
                                    d.last_seen = datetime.now(UTC)
                                    if "ip_address" in status_data:
                                        d.ip_address = status_data["ip_address"]
                                    if "uptime" in status_data:
                                        d.uptime_seconds = status_data["uptime"]
                                else:
                                    new_status = DeviceStatus.OFFLINE
                                    d.status = DeviceStatus.OFFLINE
                                await sess.commit()

                                if old_status != new_status:
                                    d_org_id = await org_id_for_site(sess, d.site_id)
                                    await publish_device_event(
                                        EventType.DEVICE_STATUS_CHANGED,
                                        device_id=str(d.id),
                                        data={
                                            "name": d.name,
                                            "old_status": old_status,
                                            "new_status": new_status,
                                        },
                                        device_type=d.device_type,
                                        controller_id=str(d.controller_id),
                                        site_id=str(d.site_id) if d.site_id else None,
                                        organization_id=d_org_id,
                                    )

                                results_list.append(
                                    {
                                        "success": True,
                                        "device_id": str(d.id),
                                        "status": new_status,
                                        "status_changed": old_status != new_status,
                                    }
                                )
                        except Exception as e:
                            logger.error("Error syncing device %s: %s", dev.id, e)
                            results_list.append(
                                {"success": False, "device_id": str(dev.id), "error": str(e)}
                            )

            except Exception as e:
                # Connection failed — mark all devices for this controller as failed
                logger.error("Controller %s unreachable during sync: %s", ctrl_id, e)
                for dev in devs:
                    results_list.append(
                        {"success": False, "device_id": str(dev.id), "error": str(e)}
                    )

            return results_list

    # Run all controllers in parallel (bounded)
    all_results = await asyncio.gather(
        *(_sync_controller_devices(cid, devs) for cid, devs in by_controller.items()),
        return_exceptions=True,
    )

    # Flatten results
    flat: list[dict[str, Any]] = []
    total_devices = sum(len(devs) for devs in by_controller.values())
    for r in all_results:
        if isinstance(r, BaseException):
            logger.error("Controller sync raised exception: %s", r)
        elif isinstance(r, list):
            flat.extend(r)

    successful = [r for r in flat if r.get("success")]
    failed = [r for r in flat if not r.get("success")]
    status_changes = [r for r in successful if r.get("status_changed")]

    return {
        "success": True,
        "devices_processed": total_devices,
        "devices_successful": len(successful),
        "devices_failed": len(failed),
        "status_changes": len(status_changes),
    }


@celery_app.task(soft_time_limit=300, time_limit=360)
def sync_all_device_statuses(
    organization_id: str | None = None,
    site_id: str | None = None,
) -> dict[str, Any]:
    """
    Celery task to sync status for all devices.

    Scheduled (no args) → every-minute all-tenant maintenance. User
    routes pass ``organization_id`` (+ optional ``site_id``) to scope the
    sync to that tenant. The solo-lock key is per-org when scoped so a
    tenant's full-sync isn't starved by the global beat.
    """
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    lock_name = (
        f"sync_all_device_statuses:{organization_id}"
        if organization_id
        else "sync_all_device_statuses"
    )
    if not acquire_solo_lock(lock_name, ttl_seconds=120):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_sync_all_device_statuses(organization_id, site_id))
    finally:
        release_solo_lock(lock_name)


async def _mark_stale_devices_offline() -> dict[str, Any]:
    """Mark devices as offline if not seen recently.

    Devices whose status is managed by a dedicated module sync task
    (VoIP phones, NVRs, cameras) are excluded – their authoritative
    status comes from the module-level poller, not from last_seen age.
    """
    MODULE_MANAGED_TYPES = {"voip_phone", "camera", "firewall"}
    stale_threshold = datetime.now(UTC) - timedelta(minutes=30)

    async with AsyncSessionLocal() as session:
        # Find stale devices that are not already offline
        result = await session.execute(
            select(Device).where(
                Device.last_seen < stale_threshold,
                Device.status != DeviceStatus.OFFLINE,
                Device.device_type.notin_(MODULE_MANAGED_TYPES),
            )
        )
        stale_devices = result.scalars().all()

        if not stale_devices:
            return {
                "success": True,
                "devices_marked_offline": 0,
            }

        marked_count = 0
        for device in stale_devices:
            old_status = device.status
            device.status = DeviceStatus.OFFLINE
            marked_count += 1

            stale_org_id = await org_id_for_site(session, device.site_id)
            await publish_device_event(
                EventType.DEVICE_STATUS_CHANGED,
                device_id=str(device.id),
                data={
                    "name": device.name,
                    "old_status": old_status,
                    "new_status": DeviceStatus.OFFLINE,
                    "reason": "stale",
                },
                device_type=device.device_type,
                controller_id=str(device.controller_id) if device.controller_id else None,
                site_id=str(device.site_id) if device.site_id else None,
                organization_id=stale_org_id,
            )

        await session.commit()

        return {
            "success": True,
            "devices_marked_offline": marked_count,
        }


@celery_app.task(soft_time_limit=120, time_limit=180)
def mark_stale_devices_offline() -> dict[str, Any]:
    """
    Celery task to mark stale devices as offline.

    Run every minute to detect devices that haven't been seen recently.
    Uses solo-lock to prevent overlapping runs across workers.
    """
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    if not acquire_solo_lock("mark_stale_devices_offline", ttl_seconds=90):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_mark_stale_devices_offline())
    finally:
        release_solo_lock("mark_stale_devices_offline")


# ===========================================
# Configuration Sync Tasks
# ===========================================


async def _sync_device_config(device_id: str) -> dict[str, Any]:
    """Sync full configuration for a device."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Device).options(selectinload(Device.controller)).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()

        if not device or not device.controller:
            return {"success": False, "error": "Device or controller not found"}

        try:
            controller = device.controller
            cloud_kwargs = {}
            if controller.connection_mode == "cloud":
                cloud_kwargs = {
                    "client_id": controller.client_id or "",
                    "client_secret": _decrypt_if_needed(controller.client_secret),
                    "omada_id": controller.omada_id or "",
                    "cloud_region": controller.cloud_region or "us",
                }
            adapter = get_adapter(
                controller_type=controller.controller_type,
                host=controller.host,
                username=controller.username or "",
                password=_decrypt_if_needed(controller.password),
                port=controller.port,
                use_ssl=controller.use_ssl,
                verify_ssl=controller.verify_ssl,
                mode=controller.connection_mode or "local",
                **cloud_kwargs,
            )

            async with adapter:
                config = await adapter.get_device_config(device.mac_address)

            if config:
                device.device_metadata = config
                device.last_seen = datetime.now(UTC)
                await session.commit()

                return {
                    "success": True,
                    "device_id": str(device.id),
                    "config_keys": list(config.keys()) if isinstance(config, dict) else [],
                }

            return {
                "success": False,
                "error": "No configuration returned",
            }

        except Exception as e:
            logger.exception("Error syncing config for device %s", device_id)
            return {"success": False, "error": str(e)}


@celery_app.task(soft_time_limit=180, time_limit=240)
def sync_device_config(device_id: str) -> dict[str, Any]:
    """Celery task to sync configuration for a specific device."""
    return asyncio.run(_sync_device_config(device_id))


# =============================================================================
# Controller Health Check
# =============================================================================


async def _check_controller_health() -> dict[str, Any]:
    """
    Check reachability / health of all controllers.
    Marks controllers unreachable or reachable and publishes events.
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Controller).where(
                Controller.deleted_at.is_(None),
                Controller.is_active.is_(True),
                Controller.sync_enabled.is_(True),
            )
        )
        controllers = result.scalars().all()

        checked = 0
        unreachable = 0

        for ctrl in controllers:
            checked += 1
            try:
                cloud_kwargs = {}
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
                async with adapter:
                    # Simple connectivity probe – get system info / device list
                    await adapter.get_devices()
                if ctrl.status != ControllerStatus.CONNECTED:
                    ctrl.status = ControllerStatus.CONNECTED
                    ctrl.last_sync = datetime.now(UTC)
            except Exception as e:
                unreachable += 1
                logger.warning("Controller %s (%s) unreachable: %s", ctrl.name, ctrl.host, e)
                if ctrl.status != ControllerStatus.UNREACHABLE:
                    ctrl.status = ControllerStatus.UNREACHABLE
                    ctrl.last_error = str(e)

        await session.commit()

        return {
            "success": True,
            "checked": checked,
            "unreachable": unreachable,
        }


@celery_app.task(
    bind=True, name="sync.check_controller_health", soft_time_limit=300, time_limit=360
)
def check_controller_health(self) -> dict[str, Any]:
    """Celery task: periodic controller health check.

    Uses a solo-lock so overlapping beat runs (a slow/partitioned set of
    controllers can push one run past the 2-minute interval) don't
    double-probe every controller across workers.
    """
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    if not acquire_solo_lock("sync.check_controller_health", ttl_seconds=180):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_check_controller_health())
    finally:
        release_solo_lock("sync.check_controller_health")


# =============================================================================
# Module Device Sync (NVRs, Phones, Firewalls → core devices table)
# =============================================================================


async def _ensure_modules_loaded() -> None:
    """Lazily populate the module registry if it's empty.

    Celery's prefork pool forks child worker processes that run tasks;
    the ``worker_ready`` signal that loads modules fires only in the
    MainProcess, so a child can execute a device-sync task against an
    EMPTY registry → ``synced_by_source: {}`` and zero devices
    materialized (this is exactly why Proxmox hypervisor devices never
    appeared via the periodic/incremental sync). Loading here makes the
    sync tasks self-sufficient regardless of which process runs them.
    """
    from app.modules.registry import module_registry

    if module_registry.modules:
        return
    try:
        from app.modules.loader import ModuleLoader

        loader = ModuleLoader()
        if loader.discover_modules():
            await loader.load_all_modules()
        logger.info(
            "Lazy-loaded %d module(s) for device sync: %s",
            len(module_registry.modules),
            list(module_registry.modules.keys()),
        )
    except Exception:
        logger.warning(
            "Failed to lazy-load modules in device-sync task",
            exc_info=True,
        )


async def _sync_module_devices() -> dict[str, Any]:
    """
    Sync module-managed devices (NVRs, VoIP phones, firewall gateways) into the
    core devices.devices table AND update their DeviceFirmwareStatus records so
    they appear in the unified Device Inventory, Network Topology, and Firmware
    Management views.
    """
    from app.services.device_sync import DeviceSyncService
    from app.services.firmware import PersistentFirmwareService as fw_svc

    await _ensure_modules_loaded()
    async with AsyncSessionLocal() as session:
        try:
            sync_result = await DeviceSyncService.sync_all(session)
            fw_result = await fw_svc.check_updates(session)
            await session.commit()
            logger.info("Module device sync: %s", sync_result)
            return {"success": True, **sync_result, "firmware": fw_result}
        except Exception as e:
            await session.rollback()
            logger.exception("Module device sync failed: %s", e)
            return {"success": False, "error": str(e)}


@celery_app.task(name="sync.sync_module_devices", soft_time_limit=300, time_limit=360)
def sync_module_devices() -> dict[str, Any]:
    """
    Celery task: full device-registry sync (all modules).
    Runs as a periodic safety-net every 15 minutes.
    """
    return asyncio.run(_sync_module_devices())


# =============================================================================
# Incremental Device Sync (event-driven, single module)
# =============================================================================


async def _sync_module_incremental(module_id: str) -> dict[str, Any]:
    """Sync devices for a single module — called after CRUD events."""
    from app.services.device_sync import DeviceSyncService
    from app.services.firmware import PersistentFirmwareService as fw_svc

    await _ensure_modules_loaded()
    async with AsyncSessionLocal() as session:
        try:
            sync_result = await DeviceSyncService.sync_module(session, module_id)
            fw_result = await fw_svc.check_updates(session)
            await session.commit()
            logger.info("Incremental device sync [%s]: %s", module_id, sync_result)
            return {**sync_result, "firmware": fw_result}
        except Exception as e:
            await session.rollback()
            logger.exception("Incremental device sync failed [%s]: %s", module_id, e)
            return {"success": False, "module": module_id, "error": str(e)}


@celery_app.task(name="sync.sync_module_incremental", soft_time_limit=120, time_limit=180)
def sync_module_incremental(module_id: str) -> dict[str, Any]:
    """
    Celery task: event-driven incremental sync for one module.
    Triggered by CRUD operations with 5-second debounce.
    """
    return asyncio.run(_sync_module_incremental(module_id))
