# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Metrics Collection Tasks
======================================

Celery tasks for collecting device and system metrics.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.celery_app import celery_app
from app.core.crypto import decrypt_credential, is_encrypted
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.services.adapter_factory import get_adapter
from app.tasks.base import FreeSDNTask

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


# ===========================================
# Helper Functions
# ===========================================


async def _collect_device_metrics(device_id: str) -> dict[str, Any]:
    """
    Collect metrics for a single device.

    Returns:
        Metrics data or error info
    """
    from app.db.models import Device

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Device).options(selectinload(Device.controller)).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()

        if not device:
            return {"success": False, "error": "Device not found"}

        if not device.controller:
            return {"success": False, "error": "Device has no controller"}

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
                # Get device metrics
                metrics = await adapter.get_device_metrics(device.mac_address)

            if metrics:
                # Store metrics in TimescaleDB (if metrics table exists)
                # For now, just return the metrics
                metrics_data = metrics.to_dict() if hasattr(metrics, "to_dict") else metrics
                return {
                    "success": True,
                    "device_id": str(device.id),
                    "device_name": device.name,
                    "metrics": metrics_data,
                    "collected_at": datetime.now(UTC).isoformat(),
                }
            else:
                return {
                    "success": True,
                    "device_id": str(device.id),
                    "device_name": device.name,
                    "metrics": {},
                    "message": "No metrics available",
                }

        except Exception as e:
            logger.exception("Error collecting metrics for device %s", device_id)
            return {
                "success": False,
                "device_id": str(device.id),
                "error": str(e),
            }


async def _collect_controller_metrics(controller_id: str) -> dict[str, Any]:
    """
    Collect metrics for a controller.

    Returns:
        Controller metrics or error info
    """
    from app.db.models import Controller

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Controller).where(Controller.id == controller_id))
        controller = result.scalar_one_or_none()

        if not controller:
            return {"success": False, "error": "Controller not found"}

        if not controller.is_active:
            return {"success": False, "error": "Controller is disabled"}

        try:
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
                # Get system info/metrics from controller
                metrics = await adapter.get_system_info()

            return {
                "success": True,
                "controller_id": str(controller.id),
                "controller_name": controller.name,
                "metrics": metrics or {},
                "collected_at": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            logger.exception("Error collecting controller metrics: %s", controller_id)
            return {
                "success": False,
                "controller_id": str(controller.id),
                "error": str(e),
            }


# ===========================================
# Celery Tasks
# ===========================================


@celery_app.task(bind=True, base=FreeSDNTask, max_retries=2, soft_time_limit=60, time_limit=90)  # type: ignore[misc]
def collect_device_metrics(self: Any, device_id: str) -> dict[str, Any]:
    """Collect metrics for a single device."""
    return asyncio.run(_collect_device_metrics(device_id))


@celery_app.task(bind=True, base=FreeSDNTask, max_retries=2, soft_time_limit=60, time_limit=90)  # type: ignore[misc]
def collect_controller_metrics(self: Any, controller_id: str) -> dict[str, Any]:
    """Collect metrics for a controller."""
    return asyncio.run(_collect_controller_metrics(controller_id))


@celery_app.task(bind=True, base=FreeSDNTask, soft_time_limit=300, time_limit=360)  # type: ignore[misc]
def collect_all_device_metrics(self: Any) -> dict[str, Any]:
    """
    Collect metrics from all online devices.

    This is a periodic task that runs every 5 minutes.
    Uses solo-lock to prevent overlapping runs across workers.
    """
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    if not acquire_solo_lock("collect_all_device_metrics", ttl_seconds=300):
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:

        async def _run() -> dict[str, Any]:
            from app.db.models import Controller, ControllerStatus, Device, DeviceStatus

            async with AsyncSessionLocal() as session:
                # Get all online devices whose controller is currently
                # reachable. Skipping devices behind an UNREACHABLE/ERROR (or
                # deactivated/sync-disabled) controller avoids queuing a
                # per-device adapter login against a box we already know is
                # down every 5-minute cycle. Devices with no controller
                # (module-managed) are still included.
                result = await session.execute(
                    select(Device)
                    .outerjoin(Controller, Device.controller_id == Controller.id)
                    .where(Device.status == DeviceStatus.ONLINE)
                    .where(Device.deleted_at.is_(None))
                    .where(
                        Device.controller_id.is_(None)
                        | (
                            Controller.deleted_at.is_(None)
                            & Controller.is_active.is_(True)
                            & Controller.sync_enabled.is_(True)
                            & Controller.status.notin_(
                                [ControllerStatus.UNREACHABLE, ControllerStatus.ERROR]
                            )
                        )
                    )
                )
                devices = result.scalars().all()

                total = len(devices)
                if total == 0:
                    return {
                        "success": True,
                        "message": "No online devices to collect metrics from",
                        "collected": 0,
                    }

                # Update progress
                self.update_progress(0, total, "Starting metrics collection...")

                collected = 0
                errors = 0

                for i, device in enumerate(devices, 1):
                    # Queue individual device metrics collection
                    collect_device_metrics.delay(str(device.id))
                    collected += 1

                    self.update_progress(i, total, f"Queued metrics collection for {device.name}")

                return {
                    "success": True,
                    "total_devices": total,
                    "queued": collected,
                    "errors": errors,
                }

        return asyncio.run(_run())
    finally:
        release_solo_lock("collect_all_device_metrics")


@celery_app.task(bind=True, base=FreeSDNTask, soft_time_limit=60, time_limit=90)  # type: ignore[misc]
def collect_site_metrics(self: Any, site_id: str) -> dict[str, Any]:
    """
    Collect aggregated metrics for a site.

    Returns:
        Aggregated site metrics
    """

    async def _run() -> dict[str, Any]:
        from sqlalchemy import func

        from app.db.models import Device, Site

        async with AsyncSessionLocal() as session:
            # Get site
            site = await session.get(Site, site_id)
            if not site:
                return {"success": False, "error": "Site not found"}

            # Get device counts by status
            result = await session.execute(
                select(Device.status, func.count(Device.id).label("count"))
                .where(Device.site_id == site_id)
                .where(Device.deleted_at.is_(None))
                .group_by(Device.status)
            )
            status_counts = {row.status.value: row.count for row in result}

            # Get device counts by type
            result = await session.execute(
                select(Device.device_type, func.count(Device.id).label("count"))
                .where(Device.site_id == site_id)
                .where(Device.deleted_at.is_(None))
                .group_by(Device.device_type)
            )
            type_counts = {row.device_type: row.count for row in result}

            return {
                "success": True,
                "site_id": str(site.id),
                "site_name": site.name,
                "metrics": {
                    "devices_by_status": status_counts,
                    "devices_by_type": type_counts,
                    "total_devices": sum(status_counts.values()),
                    "online_devices": status_counts.get("online", 0),
                    "offline_devices": status_counts.get("offline", 0),
                },
                "collected_at": datetime.now(UTC).isoformat(),
            }

    return asyncio.run(_run())
