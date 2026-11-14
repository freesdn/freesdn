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

from app.adapters.base import AdapterResult
from app.core.celery_app import celery_app
from app.core.events import (
    EventType,
    org_id_for_site,
    publish_controller_event,
    publish_device_event,
)
from app.db.models import Controller, ControllerStatus, Device, DeviceStatus
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.models.devices import normalize_device_status
from app.services.adapter_factory import adapter_device_id, build_adapter_for_controller

logger = logging.getLogger(__name__)


def _status_payload(raw: Any) -> dict[str, Any]:
    """``get_device_status``'s answer as a dict.

    Most adapters return a dict. OPNsense, pfSense, MikroTik and OpenWrt return
    an ``AdapterResult``, and the sync called ``.get()`` on it, so every status
    poll of those appliances raised AttributeError. A successful result means
    the appliance answered, which is all its status payload says about
    reachability; a failed one is raised so the poll is recorded as failed and
    the device's status is left alone.
    """
    if isinstance(raw, AdapterResult):
        if not raw.success:
            raise RuntimeError(raw.error or raw.message or "adapter reported a failure")
        return {"status": DeviceStatus.ONLINE}
    return raw if isinstance(raw, dict) else {}


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
            # One assembly point for controller credentials (see
            # build_adapter_for_controller): the per-task copies here passed no
            # Proxmox API token, so a token-authenticated controller failed
            # every one of these paths while discovery succeeded.
            adapter = build_adapter_for_controller(device.controller)

            ident = adapter_device_id(device, device.controller.controller_type)
            if ident is None:
                return {
                    "success": False,
                    "device_id": str(device.id),
                    "error": "Device has no identifier its controller's adapter can resolve",
                }

            async with adapter:
                # Get device status
                status_data = _status_payload(await adapter.get_device_status(ident))

            if status_data:
                old_status = device.status
                # get_device_status returns HEALTH ("ok"/"warning"/"error"),
                # not DeviceStatus. Writing it raw made a healthy appliance
                # count as offline.
                new_status = normalize_device_status(status_data.get("status", device.status))

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

    from app.core.device_breaker import CLOSED, controller_breaker, controller_key
    from app.core.device_slot import controller_slot_key, device_slots

    # Sync all devices for one controller through a single adapter connection
    semaphore = asyncio.Semaphore(_DEVICE_SYNC_CONCURRENCY)

    def _skipped(devs: list[Device], reason: str) -> list[dict[str, Any]]:
        return [
            {"success": False, "skipped": True, "device_id": str(d.id), "error": reason}
            for d in devs
        ]

    async def _sync_group(slot_key: str, members: list[list[Device]]) -> list[dict[str, Any]]:
        """Controllers on one box share its slot: one turn, one after another."""
        async with semaphore:
            out: list[dict[str, Any]] = []
            live = []
            for devs in members:
                ctrl = devs[0].controller
                if controller_breaker.peek(controller_key(ctrl.id)) != CLOSED:
                    # The health check found it unreachable; it probes, we wait.
                    out.extend(_skipped(devs, "Polling paused: controller unreachable"))
                else:
                    live.append(devs)
            if not live:
                return out
            lease = await device_slots.acquire(slot_key, "device status sync")
            if lease is None:
                reason = await device_slots.abusy_reason(slot_key)
                for devs in live:
                    out.extend(_skipped(devs, reason))
                return out
            try:
                for devs in live:
                    out.extend(await _sync_controller_devices(devs))
            finally:
                await device_slots.arelease(lease)
            return out

    async def _sync_controller_devices(devs: list[Device]) -> list[dict[str, Any]]:
        ctrl = devs[0].controller
        ctrl_id = str(ctrl.id)
        results_list: list[dict[str, Any]] = []
        try:
            adapter = build_adapter_for_controller(ctrl)

            async with adapter:
                for dev in devs:
                    ident = adapter_device_id(dev, ctrl.controller_type)
                    if ident is None:
                        results_list.append(
                            {
                                "success": False,
                                "device_id": str(dev.id),
                                "error": "no identifier its adapter can resolve",
                            }
                        )
                        continue
                    try:
                        status_data = _status_payload(await adapter.get_device_status(ident))
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
                                new_status = normalize_device_status(
                                    status_data.get("status", d.status)
                                )
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
                results_list.append({"success": False, "device_id": str(dev.id), "error": str(e)})

        return results_list

    # Run all controllers in parallel (bounded), one turn per device slot
    groups: dict[str, list[list[Device]]] = defaultdict(list)
    for devs in by_controller.values():
        groups[controller_slot_key(devs[0].controller)].append(devs)
    all_results = await asyncio.gather(
        *(_sync_group(key, members) for key, members in groups.items()),
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
    skipped = [r for r in flat if r.get("skipped")]
    failed = [r for r in flat if not r.get("success") and not r.get("skipped")]
    status_changes = [r for r in successful if r.get("status_changed")]

    return {
        "success": True,
        "devices_processed": total_devices,
        "devices_successful": len(successful),
        "devices_failed": len(failed),
        "devices_skipped": len(skipped),
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
    lock_token = acquire_solo_lock(lock_name, ttl_seconds=360)
    if not lock_token:
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_sync_all_device_statuses(organization_id, site_id))
    finally:
        release_solo_lock(lock_name, lock_token)


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

    lock_token = acquire_solo_lock("mark_stale_devices_offline", ttl_seconds=180)
    if not lock_token:
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_mark_stale_devices_offline())
    finally:
        release_solo_lock("mark_stale_devices_offline", lock_token)


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
            adapter = build_adapter_for_controller(device.controller)

            ident = adapter_device_id(device, device.controller.controller_type)
            if ident is None:
                return {"success": False, "error": "Device has no adapter identifier"}

            async with adapter:
                config = await adapter.get_device_config(ident)

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


#: One controller's probe: connect (= log in / open the session) and disconnect.
_HEALTH_PROBE_TIMEOUT = 30.0
_HEALTH_PROBE_CONCURRENCY = 5
#: The health check owns REACHABILITY only. A probe that succeeds moves these to
#: CONNECTED; it leaves ERROR and SYNCING alone, because discovery sets those
#: about a reachable controller and only discovery can clear them.
_RECOVERABLE_STATUSES = frozenset(
    {
        ControllerStatus.UNREACHABLE,
        ControllerStatus.DISCONNECTED,
        ControllerStatus.UNKNOWN,
    }
)


#: What one probe costs the controller, per type. A probe used to be a full
#: login and logout every run (2 minutes), whatever the type: about 720 logins
#: a day per controller, each in the controller's own log.
#:
#: * Omada (local): the login session is KEPT between probes, in this process's
#:   memory only, and a probe asks ``loginStatus`` (never creates a session);
#:   it logs in again only when the controller says the session is gone.
#: * OPNsense, pfSense, MikroTik, Hikvision, Grandstream and Proxmox with an API
#:   token authenticate every request (API key, HTTP auth or token header): a
#:   probe is one authenticated read and opens no session, so they stay on
#:   every run.
#: * Everything that has to log in for a probe (UniFi and UniFi Protect, Omada
#:   cloud, OpenWrt's ubus session, Proxmox with a password ticket, TrueNAS's
#:   API-key session, FreePBX, ONVIF's multi-call handshake) is probed at most
#:   every ``CONTROLLER_LOGIN_PROBE_INTERVAL_SECONDS`` (300 s by default).
_STATELESS_PROBE_TYPES = frozenset({"opnsense", "pfsense", "mikrotik", "hikvision", "grandstream"})

#: Omada sessions kept between probes: {key: session_state()}. Process memory on
#: purpose; a session cookie is a credential and is never written to Valkey.
_KEPT_OMADA_SESSIONS: dict[str, dict[str, Any]] = {}

_PROBE_WINDOW_PREFIX = "freesdn:ctrlprobe:"


def _probe_spacing(ctrl: Any) -> float:
    """Seconds between two probes of ``ctrl`` (0: every run). See above."""
    from app.core.config import settings

    kind = str(getattr(ctrl, "controller_type", "") or "").lower()
    if kind in _STATELESS_PROBE_TYPES:
        return 0.0
    if kind in ("omada", "tplink_omada"):
        mode = str(getattr(ctrl, "connection_mode", "local") or "local").lower()
        return 0.0 if mode != "cloud" else float(settings.CONTROLLER_LOGIN_PROBE_INTERVAL_SECONDS)
    if kind in ("proxmox", "pve") and (getattr(ctrl, "config", None) or {}).get("token_id"):
        return 0.0
    return float(settings.CONTROLLER_LOGIN_PROBE_INTERVAL_SECONDS)


def _claim_probe_window(controller_id: Any, seconds: float) -> bool:
    """Whether a probe of this controller may run now (shared by every worker).

    Fails open: with Valkey unavailable the probe runs, as before.
    """
    if seconds <= 0:
        return True
    try:
        from app.core.celery_app import _get_solo_redis

        key = f"{_PROBE_WINDOW_PREFIX}{controller_id}"
        return bool(_get_solo_redis().set(key, "1", nx=True, ex=max(1, int(seconds) - 5)))
    except Exception:  # noqa: BLE001
        return True


def _omada_session_key(client: Any) -> str:
    """The kept session belongs to one controller address AND one stored login,
    so a changed password or address starts a new one."""
    import hashlib

    config = client.config
    raw = f"{client.base_url}|{config.username}|{config.password}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def _probe_controller(adapter: Any) -> str | None:
    """Can we reach and log in to the controller? ``None`` on success, else why not."""
    return (await _probe_controller_outcome(adapter))[0]


async def _probe_omada_keeping_session(adapter: Any) -> tuple[str | None, bool]:
    """The Omada probe without a login per run (see ``_KEPT_OMADA_SESSIONS``)."""
    from app.adapters import io_policy

    client = adapter._client
    key = _omada_session_key(client)
    try:
        kept = _KEPT_OMADA_SESSIONS.get(key)
        if kept is not None:
            if await asyncio.wait_for(client.resume_session(kept), timeout=_HEALTH_PROBE_TIMEOUT):
                return None, False  # it answered, still logged in: no login sent
            _KEPT_OMADA_SESSIONS.pop(key, None)  # logged out: log in again below
        connected = await asyncio.wait_for(adapter.connect(), timeout=_HEALTH_PROBE_TIMEOUT)
        if connected is False:
            return "connect returned False", False
        state = client.session_state()
        if state is not None:
            _KEPT_OMADA_SESSIONS[key] = state
        return None, False
    except Exception as e:  # noqa: BLE001 - every failure is a probe result
        _KEPT_OMADA_SESSIONS.pop(key, None)
        detail = str(e)
        text = (f"{type(e).__name__}: {detail}" if detail else type(e).__name__)[:500]
        return text, io_policy.is_device_failure(e)
    finally:
        # Never log out: the session is what the next probe resumes.
        try:
            await asyncio.wait_for(client.close_keeping_session(), timeout=10.0)
        except Exception:  # noqa: BLE001
            pass


async def _probe_controller_outcome(adapter: Any) -> tuple[str | None, bool]:
    """``(why it failed or None, whether the controller itself did not answer)``.

    A probe is the adapter's own connect -- for Omada the login, for Proxmox
    the ticket or token check, for TrueNAS the authenticated WebSocket -- under
    one deadline. It used to be ``adapter.get_devices()``, i.e. a FULL device
    discovery of every controller every 2 minutes, run one controller after
    another: a slow or recovering controller made the whole check overrun
    while a recovered one waited its turn (2026-11 soak: Omada stayed
    "unreachable" ~10 minutes after it answered again).
    """
    from app.adapters import io_policy
    from app.adapters.omada.adapter import OmadaAdapter

    if isinstance(adapter, OmadaAdapter) and adapter.connection_mode != "cloud":
        return await _probe_omada_keeping_session(adapter)
    try:
        connected = await asyncio.wait_for(adapter.connect(), timeout=_HEALTH_PROBE_TIMEOUT)
    except Exception as e:  # noqa: BLE001 - every failure is a probe result
        detail = str(e)
        text = (f"{type(e).__name__}: {detail}" if detail else type(e).__name__)[:500]
        return text, io_policy.is_device_failure(e)
    finally:
        try:
            await asyncio.wait_for(adapter.disconnect(), timeout=10.0)
        except Exception:  # noqa: BLE001
            pass
    if connected is False:
        return "connect returned False", False
    return None, False


async def _check_controller_health() -> dict[str, Any]:
    """Probe every active controller; mark it unreachable or connected.

    No database transaction is open while any controller is contacted: the
    rows are read and the session closed, the probes run concurrently (bounded)
    with a per-controller deadline, then the outcomes are written in one short
    transaction. So a controller that answers again flips back to CONNECTED on
    the very next run, whatever the others are doing.
    """
    from app.core.device_breaker import controller_breaker, controller_key
    from app.core.device_slot import controller_slot_key, device_slots
    from app.services.adapter_factory import build_adapter_for_controller

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Controller).where(
                Controller.deleted_at.is_(None),
                Controller.is_active.is_(True),
                Controller.sync_enabled.is_(True),
            )
        )
        targets: list[tuple[Any, str, str, Any, str]] = []
        build_failures: dict[Any, str] = {}
        spacing: dict[Any, float] = {}
        for ctrl in result.scalars().all():
            try:
                adapter = build_adapter_for_controller(ctrl)
            except Exception as e:  # noqa: BLE001 - e.g. a secret that no longer decrypts
                build_failures[ctrl.id] = f"{type(e).__name__}: {e}"[:500]
                continue
            targets.append((ctrl.id, ctrl.name, ctrl.host, adapter, controller_slot_key(ctrl)))
            spacing[ctrl.id] = _probe_spacing(ctrl)

    # Controllers on one box (two services on one host) share its slot, so they
    # are probed one after another inside one turn instead of racing for it.
    groups: dict[str, list[tuple[Any, str, str, Any, str]]] = {}
    for target in targets:
        groups.setdefault(target[4], []).append(target)

    semaphore = asyncio.Semaphore(_HEALTH_PROBE_CONCURRENCY)
    failures: dict[Any, str | None] = {}
    skipped: dict[Any, str] = {}

    async def _group(slot_key: str, members: list[tuple[Any, str, str, Any, str]]) -> None:
        async with semaphore:
            lease = await device_slots.acquire(slot_key, "controller health check")
            if lease is None:
                # Discovery, a status sync or a monitor is talking to it right
                # now: that answer is as good as a probe. Try again next run.
                reason = await device_slots.abusy_reason(slot_key)
                for cid, *_ in members:
                    skipped[cid] = reason
                return
            try:
                for cid, _name, _host, adapter, _key in members:
                    if not _claim_probe_window(cid, spacing.get(cid, 0.0)):
                        # A probe of this type is a login; the last one was less
                        # than its interval ago, and its answer stands.
                        skipped[cid] = "probed recently"
                        continue
                    gate = controller_breaker.check(controller_key(cid))
                    if not gate.allowed:
                        skipped[cid] = gate.skip_message()
                        continue
                    error, device_failure = await _probe_controller_outcome(adapter)
                    failures[cid] = error
                    if error is None or not device_failure:
                        # It answered (perhaps refusing the login): reachable.
                        controller_breaker.record_success(controller_key(cid))
                    else:
                        controller_breaker.record_failure(controller_key(cid), error)
            finally:
                await device_slots.arelease(lease)

    await asyncio.gather(*(_group(key, members) for key, members in groups.items()))
    failures.update(build_failures)
    names = {cid: (name, host) for cid, name, host, _, _ in targets}

    unreachable = 0
    recovered = 0
    # (controller, event type, payload) to announce once the new status is
    # committed. Nothing used to announce it at all: a controller dropping off
    # the network flipped a status column and was otherwise silent.
    transitions: list[tuple[Any, str, dict[str, Any]]] = []
    async with AsyncSessionLocal() as session:
        rows = (
            (await session.execute(select(Controller).where(Controller.id.in_(list(failures)))))
            .scalars()
            .all()
        )
        for ctrl in rows:
            if ctrl.id not in failures:
                continue  # not probed this run (busy or paused): nothing learned
            error = failures.get(ctrl.id)
            previous = ctrl.status
            if error is None:
                if ctrl.status in _RECOVERABLE_STATUSES or ctrl.status is None:
                    ctrl.status = ControllerStatus.CONNECTED
                    ctrl.last_error = None
                    recovered += 1
                    if previous == ControllerStatus.UNREACHABLE:
                        transitions.append(
                            (ctrl, EventType.CONTROLLER_RECOVERED, {"previous_status": previous})
                        )
                continue
            unreachable += 1
            name, host = names.get(ctrl.id, (ctrl.name, ctrl.host))
            logger.warning("Controller %s (%s) unreachable: %s", name, host, error)
            if ctrl.status != ControllerStatus.UNREACHABLE:
                transitions.append(
                    (
                        ctrl,
                        EventType.CONTROLLER_UNREACHABLE,
                        # The class name only: adapter exception text can carry
                        # hostnames, URLs or response bodies.
                        {"previous_status": previous, "error": error.split(":", 1)[0]},
                    )
                )
            if ctrl.status != ControllerStatus.UNREACHABLE or ctrl.last_error != error:
                ctrl.status = ControllerStatus.UNREACHABLE
                ctrl.last_error = error
        await session.commit()

        for ctrl, event_type, extra in transitions:
            try:
                await publish_controller_event(
                    event_type,
                    controller_id=str(ctrl.id),
                    organization_id=await org_id_for_site(session, ctrl.site_id),
                    name=ctrl.name,
                    controller_type=ctrl.controller_type,
                    site_id=str(ctrl.site_id) if ctrl.site_id else None,
                    **{k: str(getattr(v, "value", v)) for k, v in extra.items()},
                )
            except Exception:  # noqa: BLE001 - the status change is already stored
                logger.warning("Could not publish %s for %s", event_type, ctrl.id, exc_info=True)

    return {
        "success": True,
        "checked": len(failures),
        "unreachable": unreachable,
        "recovered": recovered,
        "skipped": len(skipped),
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

    lock_token = acquire_solo_lock("sync.check_controller_health", ttl_seconds=360)
    if not lock_token:
        return {"success": True, "skipped": True, "reason": "already_running"}
    try:
        return asyncio.run(_check_controller_health())
    finally:
        release_solo_lock("sync.check_controller_health", lock_token)


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
