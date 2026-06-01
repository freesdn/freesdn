# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device Discovery Tasks
====================================

Celery tasks for discovering devices from controllers.
"""

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from app.core.celery_app import celery_app
from app.core.crypto import decrypt_credential, is_encrypted
from app.core.events import EventType, publish_controller_event, publish_device_event
from app.db.models import Controller, ControllerStatus, Device
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.services.adapter_factory import get_adapter
from app.services.controller_sync import deep_sync_controller

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


def _macless_key(serial: str | None, ip: str | None, name: str | None) -> str:
    """Stable per-controller dedup key for a MAC-less device.

    Adapters that model the controller itself as a single device (firewall /
    gateway "self" device) emit it with an empty MAC, so the MAC dedup can't
    match it. Fall back to the first stable identifier — serial, then IP, then
    name — so the row updates in place across syncs instead of duplicating.
    """
    return (serial or ip or name or "").strip().lower()


def _resolve_device_site_id(
    device_data: Any,
    controller: Controller,
    site_mappings: dict[str, str],
) -> UUID | None:
    """Resolve the FreeSdn site_id for a discovered device.

    Uses the Omada site mapping stored on the controller to assign
    devices to the correct FreeSdn site.  Falls back to the
    controller's default ``site_id`` when no mapping exists.

    ``device_data`` may be a ``DiscoveredDevice`` (with ``raw_data``),
    an ``AdapterDevice`` (with ``vendor_data``), or a plain dict.
    """
    if site_mappings:
        # Extract the raw / vendor blob from any format
        raw: dict[str, Any] = {}
        if hasattr(device_data, "raw_data"):
            raw = device_data.raw_data or {}
        elif hasattr(device_data, "vendor_data"):
            raw = device_data.vendor_data or {}
        elif isinstance(device_data, dict):
            raw = (
                device_data.get("raw_data")
                or device_data.get("raw_config")
                or device_data.get("vendor_data")
                or {}
            )

        omada_site_id = raw.get("_omada_site_id")
        if omada_site_id and omada_site_id in site_mappings:
            try:
                return UUID(site_mappings[omada_site_id])
            except (ValueError, AttributeError):
                logger.warning(
                    "Invalid UUID in site_mappings for omada_site %s: %s",
                    omada_site_id,
                    site_mappings[omada_site_id],
                )

    return controller.site_id


async def _discover_devices_for_controller(controller_id: str) -> dict[str, Any]:
    """Per-controller solo-locked wrapper around the discovery impl.

    A single Omada sync is slow (minutes), and a user who clicks "Sync Now"
    repeatedly — or a manual sync overlapping the scheduled one — would run two
    discoveries for the SAME controller concurrently. The device dedup uses
    ``with_for_update(skip_locked=True)``, so the second run skips the first's
    in-flight (locked) rows, fails to see them, and INSERTS duplicate device
    records (no DB unique constraint catches it). One discovery per controller
    at a time eliminates the race; an overlapping call returns early.
    """
    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    lock_key = f"discover_devices:{controller_id}"
    if not acquire_solo_lock(lock_key, ttl_seconds=720):
        logger.info("Discovery already running for controller %s; skipping overlap", controller_id)
        return {
            "success": True,
            "skipped": True,
            "reason": "already_running",
            "controller_id": controller_id,
        }
    try:
        return await _discover_devices_for_controller_impl(controller_id)
    finally:
        release_solo_lock(lock_key)


async def _discover_devices_for_controller_impl(controller_id: str) -> dict[str, Any]:
    """
    Discover devices from a specific controller.

    Returns:
        Discovery result with counts and any errors.
    """
    async with AsyncSessionLocal() as session:
        # Get controller with site info
        result = await session.execute(
            select(Controller)
            .options(selectinload(Controller.site))
            .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
        )
        controller = result.scalar_one_or_none()

        if not controller:
            return {
                "success": False,
                "error": f"Controller {controller_id} not found",
            }

        if not controller.is_active:
            return {
                "success": False,
                "error": f"Controller {controller_id} is disabled",
            }

        # Publish sync started event
        await publish_controller_event(
            EventType.CONTROLLER_SYNC_STARTED,
            controller_id=controller_id,
            data={"controller_name": controller.name},
            controller_type=controller.type,
            site_id=controller.site_id,
            organization_id=controller.site.organization_id if controller.site else None,
        )

        sync_start = time.monotonic()
        try:
            # Build adapter kwargs from controller model
            adapter_kwargs: dict[str, Any] = {
                "port": controller.port,
                "use_ssl": controller.use_ssl,
                "verify_ssl": controller.verify_ssl,
                "mode": controller.connection_mode,
            }

            # Add cloud credentials when in cloud mode
            if controller.connection_mode == "cloud":
                adapter_kwargs["client_id"] = controller.client_id or ""
                adapter_kwargs["client_secret"] = _decrypt_if_needed(controller.client_secret)
                adapter_kwargs["omada_id"] = controller.omada_id or ""
                adapter_kwargs["cloud_region"] = controller.cloud_region or ""

            # Create properly configured adapter (credentials in __init__)
            adapter = get_adapter(
                controller.type,
                host=controller.host,
                username=controller.username or "",
                password=_decrypt_if_needed(controller.password),
                **adapter_kwargs,
            )

            # Connect and discover using async context manager
            async with adapter:
                # Get site mappings for multi-site resolution
                site_mappings: dict[str, str] = controller.site_mappings or {}

                # Discover devices (returns DiscoveredDevice objects)
                discovered_devices = await adapter.discover_devices()

            # Track counts
            created_count = 0
            updated_count = 0

            # Pre-load all live devices by MAC to avoid N+1 queries.
            # MACs are stored uppercase (normalized on create/update) so we
            # can query directly without func.upper(), allowing index usage.
            all_macs = [d.mac_address.upper() for d in discovered_devices if d.mac_address]
            existing_devices_map: dict[str, Device] = {}
            if all_macs:
                existing_result = await session.execute(
                    select(Device)
                    .where(
                        Device.mac_address.in_(all_macs),
                        Device.deleted_at.is_(None),
                    )
                    .with_for_update(skip_locked=True)
                )
                for dev in existing_result.scalars().all():
                    key = dev.mac_address.upper() if dev.mac_address else ""
                    if key and key not in existing_devices_map:
                        existing_devices_map[key] = dev

            # Pre-load this controller's MAC-LESS live devices, keyed by a stable
            # fallback. Adapters that model the controller itself as a single
            # device (firewall/gateway "self" device) emit it every sync with an
            # empty MAC; the MAC dedup above can't match an empty key, so without
            # this each sync INSERTed another copy (e.g. OPNsense → N× "192.168.x.1").
            macless_map: dict[str, Device] = {}
            macless_existing = await session.execute(
                select(Device)
                .where(
                    Device.controller_id == controller.id,
                    Device.deleted_at.is_(None),
                    or_(Device.mac_address.is_(None), Device.mac_address == ""),
                )
                .with_for_update(skip_locked=True)
            )
            for dev in macless_existing.scalars().all():
                fkey = _macless_key(dev.serial_number, dev.ip_address, dev.name)
                if fkey and fkey not in macless_map:
                    macless_map[fkey] = dev

            # Process discovered devices (DiscoveredDevice objects)
            for device_data in discovered_devices:
                # Hypervisor devices are materialized exclusively by the
                # hypervisor module's DeviceSource (ProxmoxNode → Device),
                # which carries the node's rich state AND stamps the
                # management IP. The generic discovery path here only sees
                # a pseudo-MAC ("proxmox-<node>") and no IP, so letting it
                # create the device produced an IP-less DUPLICATE that
                # never correlated with agent discovery. Skip it — the
                # module owns this device type. (See sync.sync_module_*.)
                if getattr(device_data, "device_type", None) == "hypervisor":
                    continue

                # Resolve target FreeSdn site via site mappings
                # DiscoveredDevice stores _omada_site_id in raw_data
                resolved_site_id = _resolve_device_site_id(
                    device_data,
                    controller,
                    site_mappings,
                )
                resolved_site_str = str(resolved_site_id) if resolved_site_id else None

                mac_address = device_data.mac_address
                mac_upper = mac_address.upper() if mac_address else ""

                # Global dedup: lookup pre-loaded device by MAC (case-insensitive).
                # MAC-less devices fall back to a per-controller stable key
                # (serial → ip → name) so a controller's "self" device updates in
                # place instead of duplicating on every sync.
                macless_key = ""
                if mac_upper:
                    existing_device = existing_devices_map.get(mac_upper)
                else:
                    macless_key = _macless_key(
                        device_data.serial_number, device_data.ip_address, device_data.name
                    )
                    existing_device = macless_map.get(macless_key) if macless_key else None

                if existing_device:
                    # Reassign to current controller if it was orphaned
                    if existing_device.controller_id != controller.id:
                        existing_device.controller_id = controller.id
                    # Normalize MAC to uppercase for consistent indexing
                    if mac_upper and existing_device.mac_address != mac_upper:
                        existing_device.mac_address = mac_upper
                    # Update existing device
                    existing_device.name = device_data.name
                    existing_device.ip_address = device_data.ip_address
                    existing_device.model = device_data.model
                    existing_device.firmware_version = device_data.firmware_version
                    existing_device.status = device_data.status
                    # Merge device_metadata so we keep PoE budget, capabilities etc.
                    if device_data.raw_data:
                        old_meta = existing_device.device_metadata or {}
                        old_meta.update(device_data.raw_data)
                        existing_device.device_metadata = old_meta
                        # Populate runtime stats from raw Omada data
                        if device_data.raw_data.get("uptimeLong"):
                            existing_device.uptime_seconds = device_data.raw_data["uptimeLong"]
                        if device_data.raw_data.get("cpuUtil") is not None:
                            existing_device.cpu_usage_percent = device_data.raw_data["cpuUtil"]
                        if device_data.raw_data.get("memUtil") is not None:
                            existing_device.memory_usage_percent = device_data.raw_data["memUtil"]

                    # Update site_id if mapping resolved differently
                    if resolved_site_id and existing_device.site_id != resolved_site_id:
                        existing_device.site_id = resolved_site_id

                    existing_device.last_seen = datetime.now(UTC)
                    updated_count += 1

                    await publish_device_event(
                        EventType.DEVICE_UPDATED,
                        device_id=str(existing_device.id),
                        data={"name": existing_device.name, "status": existing_device.status},
                        device_type=existing_device.device_type,
                        controller_id=str(controller.id),
                        site_id=resolved_site_str,
                        organization_id=str(controller.site.organization_id)
                        if controller.site
                        else None,
                    )
                else:
                    # Create new device from DiscoveredDevice
                    raw = device_data.raw_data or {}
                    new_device = Device(
                        controller_id=controller.id,
                        site_id=resolved_site_id,
                        name=device_data.name,
                        device_type=device_data.device_type,
                        model=device_data.model,
                        manufacturer=device_data.vendor,
                        # Normalize an absent MAC to NULL (never "") so the
                        # partial unique index and the MAC-less fallback agree.
                        mac_address=(mac_upper or mac_address) or None,
                        ip_address=device_data.ip_address,
                        firmware_version=device_data.firmware_version,
                        status=device_data.status,
                        serial_number=device_data.serial_number,
                        is_adopted=False,
                        last_seen=datetime.now(UTC),
                        device_metadata=device_data.raw_data,
                        uptime_seconds=raw.get("uptimeLong"),
                        cpu_usage_percent=raw.get("cpuUtil"),
                        memory_usage_percent=raw.get("memUtil"),
                    )
                    # Concurrency: up to 5 controllers discover in parallel, each
                    # in its own session. The same physical MAC seen by two
                    # controllers in one wave (roaming / shared uplink) makes both
                    # miss the dedup and both INSERT — the partial unique index
                    # uq_devices_mac_alive then raises IntegrityError on the 2nd
                    # flush. Isolate the flush in a SAVEPOINT so a collision can't
                    # poison the whole controller's batch; on conflict, re-query
                    # the now-visible row and update it instead.
                    try:
                        async with session.begin_nested():
                            session.add(new_device)
                            await session.flush()
                    except IntegrityError:
                        conflict = await session.execute(
                            select(Device)
                            .where(
                                Device.mac_address == (mac_upper or mac_address),
                                Device.deleted_at.is_(None),
                            )
                            .with_for_update()
                        )
                        winner = conflict.scalar_one_or_none()
                        if winner is not None:
                            winner.controller_id = controller.id
                            winner.name = device_data.name
                            winner.ip_address = device_data.ip_address
                            winner.model = device_data.model
                            winner.firmware_version = device_data.firmware_version
                            winner.status = device_data.status
                            if resolved_site_id and winner.site_id != resolved_site_id:
                                winner.site_id = resolved_site_id
                            winner.last_seen = datetime.now(UTC)
                            updated_count += 1
                        # Skip the create-only DEVICE_DISCOVERED event + ZTP eval —
                        # this MAC was already created (and evaluated) by the
                        # winning controller in this wave.
                        continue
                    created_count += 1
                    # Register a freshly-created MAC-less device so a second
                    # MAC-less entry with the same fallback key in THIS batch
                    # updates it instead of inserting another copy (no unique
                    # index guards the MAC-less path).
                    if not mac_upper and macless_key:
                        macless_map[macless_key] = new_device

                    await publish_device_event(
                        EventType.DEVICE_DISCOVERED,
                        device_id=str(new_device.id),
                        data={
                            "name": new_device.name,
                            "type": new_device.device_type,
                            "mac_address": new_device.mac_address,
                        },
                        device_type=new_device.device_type,
                        controller_id=str(controller.id),
                        site_id=resolved_site_str,
                        organization_id=str(controller.site.organization_id)
                        if controller.site
                        else None,
                    )

                    # ZTP: evaluate new device against adoption rules
                    try:
                        from app.services.ztp import ZTPEngine

                        ztp = ZTPEngine()
                        adoption_job = await ztp.evaluate_device(new_device, session)
                        if adoption_job:
                            logger.info(
                                "ZTP: adoption job %s created for device %s (trigger=%s)",
                                adoption_job.id,
                                new_device.name,
                                adoption_job.triggered_by,
                            )
                    except Exception:
                        logger.debug("ZTP evaluation failed for %s", new_device.name, exc_info=True)

            # Dispatch any pending adoption jobs after commit
            adoption_jobs_to_dispatch: list[str] = []
            try:
                from app.models.ztp import AdoptionJob, AdoptionJobStatus

                aj_result = await session.execute(
                    select(AdoptionJob.id).where(
                        AdoptionJob.status == AdoptionJobStatus.PENDING,
                        AdoptionJob.device_id.in_(
                            select(Device.id).where(Device.controller_id == controller.id)
                        ),
                    )
                )
                adoption_jobs_to_dispatch = [str(jid) for jid in aj_result.scalars().all()]
            except Exception:
                logger.warning(
                    "Failed to query pending adoption jobs for controller %s",
                    controller.id,
                    exc_info=True,
                )

            # Update controller status
            controller.last_sync = datetime.now(UTC)
            controller.status = ControllerStatus.CONNECTED
            controller.last_error = None

            await session.commit()

            # Dispatch ZTP adoption jobs (after commit so device IDs are stable)
            if adoption_jobs_to_dispatch:
                from app.tasks.adoption import execute_adoption

                for job_id in adoption_jobs_to_dispatch:
                    execute_adoption.delay(job_id)
                logger.info("ZTP: dispatched %d adoption jobs", len(adoption_jobs_to_dispatch))

            # --- Deep sync: import ports, VLANs, SSIDs, LAGs, topology, clients ---
            deep_sync_summary: dict[str, Any] = {}
            try:
                deep_adapter = get_adapter(
                    controller.type,
                    host=controller.host,
                    username=controller.username or "",
                    password=_decrypt_if_needed(controller.password),
                    **adapter_kwargs,
                )
                async with deep_adapter:
                    deep_sync_summary = await deep_sync_controller(
                        session,
                        deep_adapter,
                        controller,
                        site_id=controller.site_id,
                    )
                await session.commit()
                logger.info(
                    "Deep sync completed for controller %s: %s",
                    controller.name,
                    {
                        k: v
                        for k, v in deep_sync_summary.items()
                        if k not in ("controller_id", "site_id")
                    },
                )
            except Exception:
                logger.exception(
                    "Deep sync failed for controller %s (device discovery still succeeded)",
                    controller.name,
                )
                await session.rollback()

            # Publish sync completed event
            await publish_controller_event(
                EventType.CONTROLLER_SYNC_COMPLETED,
                controller_id=str(controller.id),
                data={
                    "controller_name": controller.name,
                    "devices_discovered": len(discovered_devices),
                    "devices_created": created_count,
                    "devices_updated": updated_count,
                },
                controller_type=controller.type,
                site_id=str(controller.site_id) if controller.site_id else None,
                organization_id=str(controller.site.organization_id) if controller.site else None,
            )

            # Track sync duration
            sync_duration = round(time.monotonic() - sync_start, 2)
            config = dict(controller.config or {})
            config["last_sync_duration_seconds"] = sync_duration
            controller.config = config
            await session.commit()

            return {
                "success": True,
                "controller_id": str(controller.id),
                "controller_name": controller.name,
                "devices_discovered": len(discovered_devices),
                "devices_created": created_count,
                "devices_updated": updated_count,
                "sync_duration_seconds": sync_duration,
                "deep_sync": deep_sync_summary,
            }

        except Exception as e:
            logger.exception("Error discovering devices from controller %s", controller_id)

            # Update controller status + error history
            controller.status = ControllerStatus.ERROR
            controller.last_error = str(e)
            config = dict(controller.config or {})
            error_history = config.get("error_history", [])
            error_history.insert(
                0,
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "error": str(e)[:500],
                },
            )
            config["error_history"] = error_history[:10]  # Keep last 10
            config["last_sync_duration_seconds"] = round(time.monotonic() - sync_start, 2)
            controller.config = config
            await session.commit()

            # Publish sync failed event
            await publish_controller_event(
                EventType.CONTROLLER_SYNC_FAILED,
                controller_id=str(controller.id),
                data={
                    "controller_name": controller.name,
                    "error": str(e),
                },
                controller_type=controller.type,
                site_id=str(controller.site_id) if controller.site_id else None,
                organization_id=str(controller.site.organization_id) if controller.site else None,
            )

            return {
                "success": False,
                "controller_id": str(controller.id),
                "error": str(e),
            }


@celery_app.task(bind=True, max_retries=3, soft_time_limit=600, time_limit=720)
def discover_devices_for_controller(self: Any, controller_id: str) -> dict[str, Any]:
    """
    Celery task to discover devices from a specific controller.

    Args:
        controller_id: UUID of the controller to sync

    Returns:
        Discovery result dictionary
    """
    try:
        return asyncio.run(_discover_devices_for_controller(controller_id))
    except Exception as e:
        logger.exception("Discovery task failed for controller %s", controller_id)
        raise self.retry(exc=e, countdown=60 * (self.request.retries + 1))


_CONTROLLER_CONCURRENCY = 5  # Max controllers synced in parallel


async def _discover_all_devices(
    organization_id: str | None = None,
    site_id: str | None = None,
) -> dict[str, Any]:
    """Discover devices from enabled controllers with bounded concurrency.

    When ``organization_id`` is given (user-triggered run), the controller
    set is scoped to that org via the controller's Site — so a tenant's
    "refresh/discovery" never opens adapters against every other tenant's
    controllers. ``organization_id=None`` is the scheduled all-tenant
    maintenance beat.
    """
    from uuid import UUID as _UUID

    from app.db.models import Site

    async with AsyncSessionLocal() as session:
        # Get enabled, non-deleted controllers (org/site scoped if asked)
        q = select(Controller.id).where(
            Controller.is_active,
            Controller.deleted_at.is_(None),
        )
        if organization_id:
            q = q.join(Site, Controller.site_id == Site.id).where(
                Site.organization_id == _UUID(organization_id),
                Site.deleted_at.is_(None),
            )
            if site_id:
                q = q.where(Controller.site_id == _UUID(site_id))
        result = await session.execute(q)
        controller_ids = [str(cid) for cid in result.scalars().all()]

        if not controller_ids:
            return {
                "success": True,
                "message": "No enabled controllers found",
                "controllers_processed": 0,
            }

    # Bounded concurrency: sync up to N controllers in parallel
    semaphore = asyncio.Semaphore(_CONTROLLER_CONCURRENCY)

    async def _sync_one(cid: str) -> dict[str, Any]:
        async with semaphore:
            return await _discover_devices_for_controller(cid)

    tasks = [asyncio.create_task(_sync_one(cid)) for cid in controller_ids]
    results: list[dict[str, Any] | BaseException] = await asyncio.gather(
        *tasks, return_exceptions=True
    )

    # Separate successes, failures, and exceptions
    successful = [r for r in results if isinstance(r, dict) and r.get("success")]
    failed = [r for r in results if isinstance(r, dict) and not r.get("success")]
    exceptions = [r for r in results if isinstance(r, BaseException)]
    for exc in exceptions:
        logger.error("Controller discovery task raised exception: %s", exc)

    total_discovered = sum(r.get("devices_discovered", 0) for r in successful)
    total_created = sum(r.get("devices_created", 0) for r in successful)
    total_updated = sum(r.get("devices_updated", 0) for r in successful)

    return {
        "success": True,
        "controllers_processed": len(controller_ids),
        "controllers_successful": len(successful),
        "controllers_failed": len(failed),
        "total_devices_discovered": total_discovered,
        "total_devices_created": total_created,
        "total_devices_updated": total_updated,
        "failures": [
            {"controller_id": r.get("controller_id"), "error": r.get("error")} for r in failed
        ],
    }


_DISCOVERY_LOCK_KEY = "freesdn:discovery:running"
_DISCOVERY_LOCK_TTL = 900  # seconds — auto-expire stuck lock


def _acquire_discovery_lock(lock_key: str = _DISCOVERY_LOCK_KEY) -> bool:
    """Acquire a Redis-based distributed lock for discovery.

    Returns True if the lock was acquired, False if discovery is
    already running (on this or any other Celery worker).
    Falls back to always-acquire if Redis is unavailable.
    """
    try:
        from app.core.redis_client import get_sync_redis

        client = get_sync_redis()
        acquired = client.set(
            lock_key,
            "1",
            nx=True,
            ex=_DISCOVERY_LOCK_TTL,
        )
        client.close()
        return bool(acquired)
    except Exception:
        logger.warning(
            "Redis unavailable for discovery lock — allowing run (fallback)",
            exc_info=True,
        )
        return True


def _release_discovery_lock(lock_key: str = _DISCOVERY_LOCK_KEY) -> None:
    """Release the Redis-based distributed lock for discovery."""
    try:
        from app.core.redis_client import get_sync_redis

        client = get_sync_redis()
        client.delete(lock_key)
        client.close()
    except Exception:
        logger.warning("Failed to release discovery lock in Redis", exc_info=True)


@celery_app.task(soft_time_limit=600, time_limit=900)
def discover_all_devices(
    organization_id: str | None = None,
    site_id: str | None = None,
) -> dict[str, Any]:
    """
    Celery task to discover devices from enabled controllers.

    Scheduled (no args) → all-tenant maintenance. User-triggered routes
    pass ``organization_id`` (+ optional ``site_id``) so the run only
    touches that tenant's controllers.

    Uses a Redis-based distributed lock (SET NX EX). The lock key is
    per-org when scoped, so one tenant's discovery doesn't block another's
    (or get skipped by the global beat). Lock auto-expires after
    _DISCOVERY_LOCK_TTL to recover from stuck/crashed workers.
    """
    lock_key = (
        f"{_DISCOVERY_LOCK_KEY}:{organization_id}" if organization_id else _DISCOVERY_LOCK_KEY
    )
    if not _acquire_discovery_lock(lock_key):
        logger.info("Discovery already running (lock=%s) — skipping", lock_key)
        return {"success": True, "skipped": True, "reason": "already_running"}

    try:
        return asyncio.run(_discover_all_devices(organization_id, site_id))
    finally:
        _release_discovery_lock(lock_key)


@celery_app.task(soft_time_limit=120, time_limit=180)
def discovery_health_check() -> dict[str, Any]:
    """Health check task for the discovery system."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "discovery",
    }
