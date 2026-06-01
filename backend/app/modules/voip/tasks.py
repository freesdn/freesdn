# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VoIP Module Celery Tasks
========================================

Background tasks for VoIP operations:
  - Periodic phone fleet sync (via Grandstream adapter)
  - CDR sync from PBX (via FreePBX adapter)
  - Extension state polling
  - Phone provisioning file generation (via ProvisioningService)
  - Network discovery scan (via discovery scanner)
  - Phone health check
  - Firmware compliance check
"""

import contextlib
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from celery import shared_task

logger = logging.getLogger(__name__)


def _get_adapter(vendor: str, host: str, username: str, password: str, **kwargs):
    """Create an adapter instance by vendor name."""
    from app.adapters.registry import adapter_registry

    return adapter_registry.create_adapter(vendor, host, username, password, **kwargs)


def _phone_creds(phone) -> tuple[str, str]:
    """Extract adapter credentials from phone settings JSONB."""
    settings = phone.settings or {}
    return (
        settings.get("username", "admin"),
        settings.get("password", "admin"),
    )


async def _sync_phone_shadow_status(
    session, phone_id, status: str, last_seen=None, uptime_seconds=None
) -> None:
    """
    Keep the devices.devices shadow row in sync with the voip.phones record.

    Called after every phone poll so the Device Inventory always reflects
    the latest reachability result from the VoIP module.
    """
    from sqlalchemy import select as sa_select

    from app.models.devices import Device

    ext_id = f"voip_phone:{phone_id}"
    row = (
        (await session.execute(sa_select(Device).where(Device.external_id == ext_id)))
        .scalars()
        .first()
    )
    if row:
        status_map = {
            "online": "online",
            "registered": "online",
            "offline": "offline",
            "ringing": "online",
            "in_call": "online",
            "error": "error",
        }
        row.status = status_map.get(status, status)
        if last_seen is not None:
            row.last_seen = last_seen
        elif status in ("online", "registered"):
            from datetime import datetime

            row.last_seen = datetime.now(UTC)
        if uptime_seconds is not None:
            row.uptime_seconds = uptime_seconds


# Don't flip a phone OFFLINE on a single failed poll — a brief blip, a busy
# call, or an auth-challenge timeout shouldn't churn the fleet. Require N
# consecutive failures OR a last_seen older than the grace window before we
# trust the offline verdict (mirrors the 30-min stale grace the core
# mark_stale_devices_offline sweep uses, from which voip_phone is excluded).
_PHONE_OFFLINE_FAIL_THRESHOLD = 3
_PHONE_OFFLINE_GRACE = timedelta(minutes=15)


def _should_mark_phone_offline(phone) -> bool:
    """Decide whether a poll failure should flip the phone offline now.

    Returns True only once the phone has failed ``_PHONE_OFFLINE_FAIL_THRESHOLD``
    consecutive polls OR has not been seen within ``_PHONE_OFFLINE_GRACE``.
    Otherwise the prior status is retained (the caller increments the counter).
    Already-offline phones stay offline.
    """
    if phone.status == "offline":
        return True
    settings = phone.settings or {}
    fail_count = int(settings.get("_health_fail_count", 0)) + 1
    if fail_count >= _PHONE_OFFLINE_FAIL_THRESHOLD:
        return True
    last_seen = phone.last_seen
    return last_seen is None or (datetime.now(UTC) - last_seen) > _PHONE_OFFLINE_GRACE


def _bump_phone_fail_count(phone) -> None:
    """Record one consecutive poll failure in the phone's settings JSONB."""
    from sqlalchemy.orm.attributes import flag_modified

    settings = dict(phone.settings or {})
    settings["_health_fail_count"] = int(settings.get("_health_fail_count", 0)) + 1
    phone.settings = settings
    flag_modified(phone, "settings")


def _reset_phone_fail_count(phone) -> None:
    """Clear the consecutive-failure counter after a successful poll."""
    from sqlalchemy.orm.attributes import flag_modified

    settings = phone.settings or {}
    if settings.get("_health_fail_count"):
        settings = dict(settings)
        settings["_health_fail_count"] = 0
        phone.settings = settings
        flag_modified(phone, "settings")


def _pbx_creds(pbx) -> tuple[str, str]:
    """Extract adapter credentials from PBX settings JSONB."""
    settings = pbx.settings or {}
    return (
        settings.get("api_username", ""),
        settings.get("api_password", ""),
    )


# =============================================================================
# Phone Fleet Sync
# =============================================================================


@shared_task(
    bind=True,
    name="voip.sync_phones",
    max_retries=3,
    default_retry_delay=60,
)
def sync_phones(self, site_id: str | None = None) -> dict:
    """
    Sync phone fleet status from Grandstream adapter.

    Contacts all registered phones, updates online/offline status,
    firmware versions, and SIP registration state in the database.
    """
    import asyncio

    async def run_sync():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)
            phones, _ = await service.list_phones(
                site_id=UUID(site_id) if site_id else None,
                lifecycle_state="managed",
                limit=1000,
            )

            synced = 0
            errors = 0

            # Group phones by IP for batch probes  (one adapter per phone)
            for phone in phones:
                if not phone.ip_address:
                    continue
                try:
                    vendor = (phone.vendor or "grandstream").lower()
                    uname, pwd = _phone_creds(phone)
                    adapter = _get_adapter(
                        vendor,
                        host=phone.ip_address,
                        username=uname,
                        password=pwd,
                    )
                    async with adapter:
                        status_data = await adapter.get_device_status(phone.mac_address or "")
                    # Update phone from adapter response
                    update: dict = {"last_seen": datetime.now(UTC)}
                    if status_data and isinstance(status_data, dict):
                        sd = status_data.get("data", status_data)
                        if "firmware_version" in sd:
                            update["firmware_version"] = sd["firmware_version"]
                        if "uptime" in sd:
                            update["uptime_seconds"] = sd["uptime"]
                        if "sip_registered" in sd:
                            update["sip_registered"] = sd["sip_registered"]
                        update["status"] = "online"
                        # Good poll — clear the consecutive-failure counter and
                        # refresh last_seen directly (update_phone won't persist
                        # these non-mutable fields).
                        _reset_phone_fail_count(phone)
                        phone.last_seen = update["last_seen"]
                    else:
                        # Empty/non-dict response is a soft failure: only flip
                        # offline once we're past the consecutive-failure /
                        # grace gate, otherwise retain the prior status.
                        if _should_mark_phone_offline(phone):
                            update["status"] = "offline"
                        else:
                            update["status"] = phone.status
                        _bump_phone_fail_count(phone)

                    await service.update_phone(phone.id, update)
                    synced += 1

                    # Sync shadow row in devices.devices — only mirror offline
                    # once the phone row itself has actually flipped offline.
                    await _sync_phone_shadow_status(
                        session,
                        phone.id,
                        update.get("status", "online"),
                        update.get("last_seen"),
                        uptime_seconds=update.get("uptime_seconds"),
                    )
                except Exception as exc:
                    logger.warning(
                        "Phone sync failed for %s (%s): %s",
                        phone.mac_address,
                        phone.ip_address,
                        exc,
                    )
                    errors += 1
                    # Transient poll failure: apply the consecutive-failure /
                    # last_seen grace gate before flipping offline so a single
                    # blip doesn't flap the phone row (and its shadow Device row).
                    try:
                        if _should_mark_phone_offline(phone):
                            await service.update_phone(phone.id, {"status": "offline"})
                            await _sync_phone_shadow_status(session, phone.id, "offline")
                        _bump_phone_fail_count(phone)
                    except Exception:
                        pass

            await session.commit()
            return {
                "status": "success",
                "synced": synced,
                "errors": errors,
                "total": len(phones),
            }

    return asyncio.run(run_sync())


# =============================================================================
# CDR Sync
# =============================================================================


@shared_task(
    bind=True,
    name="voip.sync_cdr",
    max_retries=3,
    default_retry_delay=120,
)
def sync_cdr(self, pbx_id: str) -> dict:
    """
    Sync Call Detail Records from a PBX.

    Pulls CDR from FreePBX REST API and inserts new records
    into the FreeSDN call_log table.
    """
    import asyncio

    async def run_cdr_sync():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)

            try:
                pbx = await service.get_pbx(UUID(pbx_id))
            except Exception:
                return {"status": "error", "reason": f"PBX {pbx_id} not found"}

            # Create adapter from PBX settings
            api_user, api_pass = _pbx_creds(pbx)
            adapter = _get_adapter(
                pbx.pbx_type or "freepbx",
                host=pbx.ip_address,
                username=api_user,
                password=api_pass,
            )

            new_records = 0
            try:
                async with adapter:
                    await adapter.discover_devices()
                    # For PBX adapters, CDR comes from a dedicated method.
                    if hasattr(adapter, "search_call_logs"):
                        # The adapter expects ``start_date`` (YYYY-MM-DD), not
                        # ``start_time``, and returns an AdapterResult envelope —
                        # both were wrong here, so every sync errored before it
                        # could reach the (previously missing) create_call_log.
                        since = pbx.last_sync_at
                        cdr_result = await adapter.search_call_logs(
                            start_date=since.strftime("%Y-%m-%d") if since else None,
                        )
                        # Tolerate both the AdapterResult envelope and a bare list.
                        if hasattr(cdr_result, "data"):
                            records = (
                                cdr_result.data if getattr(cdr_result, "success", True) else []
                            )
                        else:
                            records = cdr_result
                        for record in records or []:
                            if isinstance(record, dict):
                                await service.create_call_log(pbx_id=UUID(pbx_id), **record)
                                new_records += 1
            except Exception as exc:
                logger.warning("CDR sync failed for PBX %s: %s", pbx_id, exc)
                return {
                    "status": "partial",
                    "pbx_id": pbx_id,
                    "error": f"CDR sync failed ({type(exc).__name__})",
                }

            await session.commit()
            return {
                "status": "success",
                "pbx_id": pbx_id,
                "new_records": new_records,
            }

    return asyncio.run(run_cdr_sync())


# =============================================================================
# Extension Sync
# =============================================================================


@shared_task(
    bind=True,
    name="voip.sync_extensions",
    max_retries=3,
    default_retry_delay=60,
)
def sync_extensions(self, pbx_id: str) -> dict:
    """
    Sync extension list from a PBX into the FreeSDN database.
    """
    import asyncio

    async def run_ext_sync():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)

            try:
                pbx = await service.get_pbx(UUID(pbx_id))
            except Exception:
                return {"status": "error", "reason": f"PBX {pbx_id} not found"}

            api_user, api_pass = _pbx_creds(pbx)
            adapter = _get_adapter(
                pbx.pbx_type or "freepbx",
                host=pbx.ip_address,
                username=api_user,
                password=api_pass,
            )

            added = updated = removed = 0
            try:
                async with adapter:
                    if hasattr(adapter, "list_extensions"):
                        remote_exts = await adapter.list_extensions()
                        # Upsert each extension
                        db_exts, _ = await service.list_extensions(
                            pbx_id=UUID(pbx_id),
                            limit=5000,
                        )
                        db_ext_map = {e.extension_number: e for e in db_exts}

                        for ext in remote_exts:
                            ext_num = str(ext.get("extension", ext.get("number", "")))
                            if ext_num in db_ext_map:
                                updated += 1
                            else:
                                await service.create_extension(
                                    pbx_id=UUID(pbx_id),
                                    extension_number=ext_num,
                                    display_name=ext.get("name", ext_num),
                                    ext_type=ext.get("type", "sip"),
                                )
                                added += 1
            except Exception as exc:
                logger.warning("Extension sync failed for PBX %s: %s", pbx_id, exc)
                return {
                    "status": "partial",
                    "pbx_id": pbx_id,
                    "error": f"Extension sync failed ({type(exc).__name__})",
                }

            await session.commit()
            return {
                "status": "success",
                "pbx_id": pbx_id,
                "added": added,
                "updated": updated,
                "removed": removed,
            }

    return asyncio.run(run_ext_sync())


# =============================================================================
# Provisioning (uses ProvisioningService)
# =============================================================================


@shared_task(
    bind=True,
    name="voip.generate_provisioning_files",
    max_retries=2,
    default_retry_delay=30,
)
def generate_provisioning_files(
    self,
    site_id: str | None = None,
    phone_ids: list[str] | None = None,
) -> dict:
    """
    Generate XML provisioning files via ProvisioningService.

    If ``phone_ids`` is None, generates for all managed phones in the site.
    """
    import asyncio

    async def run_provision():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.provisioning import ProvisioningService

            prov = ProvisioningService(session)

            ids = [UUID(pid) for pid in phone_ids] if phone_ids else None
            sid = UUID(site_id) if site_id else None

            result = await prov.bulk_generate_configs(
                phone_ids=ids,
                site_id=sid,
            )
            await session.commit()
            return {
                "status": "success",
                "total": result["total"],
                "generated": result["generated"],
                "changed": result.get("changed", 0),
                "errors": result["errors"],
            }

    return asyncio.run(run_provision())


# =============================================================================
# Extension State Polling
# =============================================================================


@shared_task(name="voip.poll_extension_states")
def poll_extension_states() -> dict:
    """
    Poll extension states from all connected PBX systems.

    Run frequently (Celery beat every 30s) for live dashboard updates.
    """
    import asyncio

    async def run_poll():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)
            pbx_list, total = await service.list_pbx_systems(limit=200)
            if total > len(pbx_list):
                # Don't silently drop PBXes past the cap — make it visible.
                logger.warning(
                    "poll_extension_states: %d PBX systems but only polling %d "
                    "(page cap); some will not be polled this beat",
                    total,
                    len(pbx_list),
                )

            # Bounded concurrency: poll up to N PBXes at once instead of
            # strictly sequentially, so the run finishes well inside the beat
            # interval on larger fleets. Each poll builds its own per-PBX
            # adapter (no shared socket), so concurrency is safe; the semaphore
            # just caps simultaneous connections.
            sem = asyncio.Semaphore(5)

            async def _poll_one(pbx) -> int:
                async with sem:
                    try:
                        api_user, api_pass = _pbx_creds(pbx)
                        adapter = _get_adapter(
                            pbx.pbx_type or "freepbx",
                            host=pbx.ip_address,
                            username=api_user,
                            password=api_pass,
                        )
                        async with adapter:
                            if hasattr(adapter, "get_extension_states"):
                                states = await adapter.get_extension_states()
                                return len(states) if states else 0
                    except Exception as exc:
                        logger.debug("Extension poll failed for PBX %s: %s", pbx.id, exc)
                    return 0

            counts = await asyncio.gather(*(_poll_one(p) for p in pbx_list))
            return {"status": "success", "polled": sum(counts)}

    return asyncio.run(run_poll())


# =============================================================================
# Phone Reboot
# =============================================================================


@shared_task(
    bind=True,
    name="voip.reboot_phone",
    max_retries=2,
    default_retry_delay=10,
)
def reboot_phone(self, phone_id: str) -> dict:
    """Reboot a single phone via its vendor adapter."""
    import asyncio

    async def run_reboot():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)
            try:
                phone = await service.get_phone(UUID(phone_id))
            except Exception:
                return {"status": "error", "reason": f"Phone {phone_id} not found"}

            if not phone.ip_address:
                return {"status": "error", "reason": "Phone has no IP address"}

            vendor = (phone.vendor or "grandstream").lower()
            uname, pwd = _phone_creds(phone)
            adapter = _get_adapter(
                vendor,
                host=phone.ip_address,
                username=uname,
                password=pwd,
            )

            try:
                async with adapter:
                    adapter.add_phone(phone.ip_address, mac=phone.mac_address or "")
                    result = await adapter.reboot_phone(phone.mac_address or "")
                    return {
                        "status": "success",
                        "phone_id": phone_id,
                        "adapter_result": result.success if result else False,
                    }
            except Exception as exc:
                logger.warning("Reboot failed for phone %s: %s", phone_id, exc)
                return {
                    "status": "error",
                    "phone_id": phone_id,
                    "error": f"Reboot failed ({type(exc).__name__})",
                }

    return asyncio.run(run_reboot())


# =============================================================================
# Network Discovery Scan
# =============================================================================


@shared_task(
    bind=True,
    name="voip.run_discovery_scan",
    max_retries=1,
    default_retry_delay=30,
    time_limit=600,  # 10 minute hard limit
    soft_time_limit=540,
)
def run_discovery_scan_task(self, scan_id: str, transient_creds: dict | None = None) -> dict:
    """
    Run a network discovery scan for VoIP devices.

    Dispatched from the /discovery/scan endpoint. Updates the
    DiscoveryScan record with progress and results as they come in.

    Args:
        scan_id: UUID of the DiscoveryScan record.
        transient_creds: Optional dict with ``username`` and encrypted
            ``password``.  Passed transiently from the API — never
            persisted in the DB.
    """
    import asyncio

    async def run_scan():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.discovery import run_discovery_scan
            from app.modules.voip.models import ScanStatus
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)

            try:
                scan = await service.get_discovery_scan(UUID(scan_id))
            except Exception:
                return {"status": "error", "reason": f"Scan {scan_id} not found"}

            # Mark scan as running
            scan.status = ScanStatus.RUNNING.value
            scan.started_at = datetime.now(UTC)
            scan.metadata_json = {
                **(scan.metadata_json or {}),
                "progress": {
                    "phase": "starting",
                    "percent": 0,
                    "message": "Initializing scan...",
                    "devices_found": 0,
                    "log": [],
                },
            }
            await session.commit()

            # Progress callback — writes to DB so frontend can poll
            async def on_progress(phase: str, detail: dict):
                meta = scan.metadata_json or {}
                prog = meta.get("progress", {})
                log = prog.get("log", [])

                # Map phase → percent + message
                phase_map = {
                    "init": (
                        2,
                        f"Scanning {detail.get('total_hosts', 0)} hosts on {detail.get('subnet', '')}",
                    ),
                    "arp_start": (5, "ARP sweep — populating ARP table..."),
                    "arp_done": (
                        30,
                        f"ARP complete — {detail.get('found', 0)} VoIP devices found via MAC OUI",
                    ),
                    "http_start": (
                        35,
                        f"HTTP probe — checking {detail.get('hosts_to_probe', 0)} hosts for phone web UIs...",
                    ),
                    "http_progress": (
                        35 + int(25 * detail.get("probed", 0) / max(detail.get("total", 1), 1)),
                        f"HTTP probing... {detail.get('probed', 0)}/{detail.get('total', 0)} hosts",
                    ),
                    "http_done": (
                        60,
                        f"HTTP complete — {detail.get('found', 0)} phone web UIs detected",
                    ),
                    "sip_start": (
                        65,
                        f"SIP OPTIONS — probing {detail.get('hosts_to_probe', 0)} endpoints...",
                    ),
                    "sip_progress": (
                        65 + int(25 * detail.get("probed", 0) / max(detail.get("total", 1), 1)),
                        f"SIP probing... {detail.get('probed', 0)}/{detail.get('total', 0)} hosts",
                    ),
                    "sip_done": (
                        90,
                        f"SIP complete — {detail.get('found', 0)} SIP devices responded",
                    ),
                    "complete": (
                        100,
                        f"Scan complete — {detail.get('total_devices', 0)} devices found in {detail.get('elapsed', 0)}s",
                    ),
                }

                percent, message = phase_map.get(phase, (prog.get("percent", 0), phase))

                # Append to log
                log.append(
                    {
                        "ts": datetime.now(UTC).isoformat(),
                        "phase": phase,
                        "message": message,
                    }
                )
                # Keep last 50 log entries
                log = log[-50:]

                # Collect live device list
                devices = detail.get("devices", prog.get("devices", []))

                prog.update(
                    {
                        "phase": phase,
                        "percent": percent,
                        "message": message,
                        "devices_found": detail.get("total_devices", prog.get("devices_found", 0)),
                        "log": log,
                        "devices": devices,
                    }
                )
                meta["progress"] = prog
                scan.metadata_json = meta
                scan.devices_found = prog["devices_found"]
                # Force SQLAlchemy to detect the JSONB mutation
                from sqlalchemy.orm.attributes import flag_modified

                flag_modified(scan, "metadata_json")
                await session.commit()

            try:
                subnet = scan.subnet or "192.168.1.0/24"
                scan_type = scan.scan_type or "full"

                # Use transient credentials passed from the API (not persisted in DB)
                scan_credentials = None
                if transient_creds and isinstance(transient_creds, dict):
                    from app.core.crypto import decrypt_credential, is_encrypted

                    raw_pw = transient_creds.get("password", "admin")
                    if is_encrypted(raw_pw):
                        raw_pw = decrypt_credential(raw_pw)
                    scan_credentials = {
                        "username": transient_creds.get("username", "admin"),
                        "password": raw_pw,
                    }

                discovered = await run_discovery_scan(
                    subnet=subnet,
                    scan_type=scan_type,
                    on_progress=on_progress,
                    credentials=scan_credentials,
                )

                # Check if scan was cancelled during execution
                await session.refresh(scan, ["status"])
                if scan.status == ScanStatus.CANCELLED.value:
                    return {"status": "cancelled", "scan_id": scan_id}

                # Batch-upsert discovered devices into the phones table
                # (single commit at end instead of N+1 per-device commits)
                new_count = 0
                updated_count = 0
                metadata = scan.metadata_json or {}
                upserted_phones = []

                for device in discovered:
                    phone, is_new = await service.upsert_discovered_phone(
                        ip_address=device.ip_address,
                        mac_address=device.mac_address,
                        vendor=device.vendor,
                        model=device.model,
                        firmware_version=device.firmware_version,
                        discovery_method=",".join(device.discovery_methods),
                        site_id=scan.site_id,
                        sip_registered=device.sip_registered,
                        sip_account=device.sip_account,
                        sip_registrar=device.sip_registrar,
                        authenticated=device.authenticated,
                        raw_data=device.raw_data,
                    )
                    if is_new:
                        new_count += 1
                    else:
                        updated_count += 1
                    upserted_phones.append((phone, is_new))

                # Auto-onboard if requested
                auto_onboard = metadata.get("auto_onboard", False)
                template_id = metadata.get("config_template_id")

                if auto_onboard and template_id:
                    for phone, _is_new in upserted_phones:
                        try:
                            if phone and phone.lifecycle_state == "discovered":
                                await service.onboard_phone(
                                    phone_id=phone.id,
                                    config_template_id=UUID(template_id),
                                )
                        except Exception:
                            pass

                # Final update
                scan.status = ScanStatus.COMPLETED.value
                scan.completed_at = datetime.now(UTC)
                scan.devices_found = new_count + updated_count
                scan.new_devices = new_count
                scan.updated_devices = updated_count
                scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
                # ``discovered`` and ``upserted_phones`` are built in the same
                # loop above with 1:1 correspondence, so they zip cleanly. Carry
                # the upserted phone id (+ is_new) into each result row so the
                # Discovery results dialog "View" button can navigate to it.
                scan.results = [
                    {
                        "ip": d.ip_address,
                        "mac": d.mac_address,
                        "vendor": d.vendor,
                        "model": d.model,
                        "firmware": d.firmware_version,
                        "methods": d.discovery_methods,
                        "sip_registered": d.sip_registered,
                        "sip_account": d.sip_account,
                        "sip_registrar": d.sip_registrar,
                        "authenticated": d.authenticated,
                        "phone_id": str(phone.id) if phone is not None else None,
                        "is_new": is_new,
                    }
                    for d, (phone, is_new) in zip(discovered, upserted_phones, strict=True)
                ]
                # Final progress
                meta = scan.metadata_json or {}
                meta["progress"] = {
                    "phase": "done",
                    "percent": 100,
                    "message": f"Complete — {scan.devices_found} devices ({new_count} new, {updated_count} updated)",
                    "devices_found": scan.devices_found,
                    "log": meta.get("progress", {}).get("log", []),
                    "devices": scan.results,
                }
                scan.metadata_json = meta
                from sqlalchemy.orm.attributes import flag_modified

                flag_modified(scan, "metadata_json")
                await session.commit()

                return {
                    "status": "success",
                    "scan_id": scan_id,
                    "found": new_count + updated_count,
                    "new": new_count,
                    "updated": updated_count,
                }

            except Exception as exc:
                logger.exception("Discovery scan %s failed: %s", scan_id, exc)
                scan.status = ScanStatus.FAILED.value
                scan.completed_at = datetime.now(UTC)
                scan.error_message = str(exc)
                meta = scan.metadata_json or {}
                meta["progress"] = {
                    "phase": "error",
                    "percent": 0,
                    "message": f"Scan failed: {exc}",
                    "devices_found": 0,
                    "log": meta.get("progress", {}).get("log", []),
                    "devices": [],
                }
                scan.metadata_json = meta
                scan.results = [{"error": f"Scan failed ({type(exc).__name__})"}]
                from sqlalchemy.orm.attributes import flag_modified

                flag_modified(scan, "metadata_json")
                await session.commit()
                return {
                    "status": "error",
                    "scan_id": scan_id,
                    "error": f"Scan failed ({type(exc).__name__})",
                }

    return asyncio.run(run_scan())


# =============================================================================
# Phone Health Check
# =============================================================================


@shared_task(name="voip.health_check")
def health_check(site_id: str | None = None) -> dict:
    """
    Run a health check across all managed phones.

    Updates status, SIP registration, uptime, CPU/memory metrics.
    Should be run by Celery beat every 5 minutes.
    """
    import asyncio

    async def run_health():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)
            phones, _ = await service.list_phones(
                site_id=UUID(site_id) if site_id else None,
                lifecycle_state="managed",
                limit=2000,
            )

            healthy = 0
            degraded = 0
            offline = 0

            for phone in phones:
                if not phone.ip_address:
                    offline += 1
                    continue

                try:
                    vendor = (phone.vendor or "grandstream").lower()
                    uname, pwd = _phone_creds(phone)
                    adapter = _get_adapter(
                        vendor,
                        host=phone.ip_address,
                        username=uname,
                        password=pwd,
                    )
                    async with adapter:
                        status_data = await adapter.get_device_status(phone.mac_address or "")

                    update: dict = {"last_seen": datetime.now(UTC)}
                    if status_data and isinstance(status_data, dict):
                        sd = status_data.get("data", status_data)
                        update["status"] = "online"
                        update["sip_registered"] = sd.get("sip_registered", False)
                        if "uptime" in sd:
                            update["uptime_seconds"] = sd["uptime"]
                        if "cpu_usage" in sd:
                            update["cpu_usage"] = sd["cpu_usage"]
                        if "memory_usage" in sd:
                            update["memory_usage"] = sd["memory_usage"]
                        if "firmware_version" in sd:
                            update["firmware_version"] = sd["firmware_version"]

                        if not sd.get("sip_registered", True):
                            update["status"] = "warning"
                            degraded += 1
                        else:
                            healthy += 1
                        # Reachable — clear the consecutive-failure counter and
                        # refresh last_seen (update_phone won't persist these).
                        _reset_phone_fail_count(phone)
                        phone.last_seen = update["last_seen"]
                    else:
                        # Empty/non-dict response is a soft failure: respect the
                        # consecutive-failure / grace gate before flipping offline.
                        if _should_mark_phone_offline(phone):
                            update["status"] = "offline"
                            offline += 1
                        else:
                            update["status"] = phone.status
                        _bump_phone_fail_count(phone)

                    await service.update_phone(phone.id, update)

                except Exception as exc:
                    logger.debug("Health check failed for %s: %s", phone.id, exc)
                    # Transient failure: only flip offline once past the grace
                    # gate so a single blip doesn't flap the phone row.
                    with contextlib.suppress(Exception):
                        if _should_mark_phone_offline(phone):
                            await service.update_phone(phone.id, {"status": "offline"})
                            offline += 1
                        _bump_phone_fail_count(phone)

            await session.commit()
            return {
                "status": "success",
                "total": len(phones),
                "healthy": healthy,
                "degraded": degraded,
                "offline": offline,
            }

    return asyncio.run(run_health())


# =============================================================================
# Firmware Compliance Check
# =============================================================================


@shared_task(name="voip.check_firmware_compliance")
def check_firmware_compliance(site_id: str | None = None) -> dict:
    """
    Check firmware compliance across the fleet.

    Compares phone firmware versions against registered firmware tracks
    and generates a compliance report. Run daily by Celery beat.
    """
    import asyncio

    async def run_check():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)
            sid = UUID(site_id) if site_id else None

            report = await service.get_firmware_compliance(site_id=sid)

            total_compliant = sum(r["compliant"] for r in report)
            total_non_compliant = sum(r["non_compliant"] for r in report)

            return {
                "status": "success",
                "compliant": total_compliant,
                "non_compliant": total_non_compliant,
                "groups": len(report),
            }

    return asyncio.run(run_check())


# =============================================================================
# Bulk Reboot
# =============================================================================


@shared_task(
    bind=True,
    name="voip.bulk_reboot",
    time_limit=300,
)
def bulk_reboot(self, phone_ids: list[str]) -> dict:
    """Reboot multiple phones in sequence with rate limiting."""
    import asyncio

    async def run_bulk():
        from app.db.session import celery_session_factory

        async with celery_session_factory() as session:
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)
            succeeded = 0
            failed = 0

            for pid in phone_ids:
                try:
                    phone = await service.get_phone(UUID(pid))
                    if not phone or not phone.ip_address:
                        failed += 1
                        continue

                    vendor = (phone.vendor or "grandstream").lower()
                    uname, pwd = _phone_creds(phone)
                    adapter = _get_adapter(
                        vendor,
                        host=phone.ip_address,
                        username=uname,
                        password=pwd,
                    )
                    async with adapter:
                        adapter.add_phone(phone.ip_address, mac=phone.mac_address or "")
                        await adapter.reboot_phone(phone.mac_address or "")
                    succeeded += 1
                except Exception as exc:
                    logger.warning("Bulk reboot failed for %s: %s", pid, exc)
                    failed += 1

                # Rate limit: 500ms between reboots
                await asyncio.sleep(0.5)

            return {
                "status": "success",
                "total": len(phone_ids),
                "succeeded": succeeded,
                "failed": failed,
            }

    return asyncio.run(run_bulk())


# ═══════════════════════════════════════════════════════════════════════════
# Full PBX sync with interactive progress (canonical async-progress template)
# ═══════════════════════════════════════════════════════════════════════════
#
# Architecture:
#   API endpoint  → sync_pbx_full.delay(pbx_id)  →  returns task_id (202)
#   Celery task   → service.sync_pbx(progress_callback=_emit_progress)
#   Each stage    → publish_adapter_event("pbx.sync.progress", ...)
#                 → fans out to WebSocket subscribers
#   Frontend      → useWebSocket() filter on adapter_id == pbx:<uuid>
#                 → interactive progress bar with per-resource counts
#
# This is the reference pattern other long-running adapter operations
# should follow (Omada full controller sync, Proxmox cluster scan, etc.).


def _emit_pbx_sync_event(
    pbx_id: str,
    event_type: str,
    payload: dict,
    organization_id: str | None = None,
) -> None:
    """Publish a ``pbx.sync.*`` event from inside a Celery task.

    Celery tasks run in a different process from the API. The in-process
    ``EventBus`` only fans events to handlers registered IN THE SAME
    process — the API's WebSocket forwarder (which lives in the FastAPI
    process) only sees events that arrive over Redis pub/sub.

    The bus's ``connect()`` sets up that Redis publish, but it's not
    auto-called in Celery worker context. To avoid the lifecycle dance
    of repeatedly connecting/disconnecting a fresh asyncio loop on every
    progress tick, we publish DIRECTLY to the same Redis channel the
    API's subscriber listens on:

        channel = "freesdn:events:<category>:<org_id|system>"
        payload = JSON-serialised :meth:`Event.to_dict` (so the API's
                  subscriber decodes it back into an Event identical to
                  what the bus would have produced).

    Best-effort — any failure logs at DEBUG and the sync continues.
    The actual sync work has already succeeded by the time we emit;
    losing the WebSocket event just means the operator's progress bar
    won't tick, not that the device write failed.
    """
    import json
    import logging
    from datetime import UTC, datetime
    from uuid import uuid4

    try:
        from app.core.events import EventCategory, EventPriority

        category = EventCategory.DEVICE
        priority = EventPriority.NORMAL

        # Same payload shape the bus would build for publish_adapter_event,
        # plus pbx_id so frontend handlers can filter to a specific PBX
        # without parsing the adapter_id slug.
        full_payload = {
            **(payload or {}),
            "adapter_id": f"pbx:{pbx_id}",
            "pbx_id": pbx_id,
        }

        # ``Event.to_dict`` would JSON-serialise the datetime/enum
        # fields. We mirror that shape here without importing the
        # dataclass (avoids loading the whole bus on every emit).
        envelope = {
            "id": str(uuid4()),
            "event_type": event_type,
            "category": category.value,
            "priority": priority.value,
            "payload": full_payload,
            "timestamp": datetime.now(UTC).isoformat(),
            "organization_id": organization_id,
            "site_id": None,
            "user_id": None,
            "correlation_id": None,
            "source": f"adapter:pbx:{pbx_id}",
        }

        # Publish to the same Redis channel the API subscriber listens
        # on. The API decodes the envelope back into an Event and fans
        # it to WebSocket clients filtered by organization_id.
        from app.core.redis_client import get_sync_redis  # Sentinel-aware sync client

        r = get_sync_redis()
        try:
            org_scope = organization_id or "system"
            channel = f"freesdn:events:{category.value}:{org_scope}"
            r.publish(channel, json.dumps(envelope))
        finally:
            try:
                r.close()
            except Exception:
                pass
    except Exception:
        logging.getLogger(__name__).debug(
            "pbx.sync.%s publish skipped for pbx=%s",
            event_type,
            pbx_id,
            exc_info=True,
        )


@shared_task(
    bind=True,
    name="voip.sync_pbx_full",
    max_retries=0,  # operator-triggered; auto-retry would double-sync
    soft_time_limit=300,  # 5min soft cap; FreePBX REST hits 23 endpoints
    time_limit=360,
)
def sync_pbx_full(
    self,
    pbx_id: str,
    organization_id: str | None = None,
    actor_id: str | None = None,
) -> dict:
    """Background PBX sync with per-stage WebSocket progress events.

    Replaces the blocking ``POST /voip/pbx/{id}/sync`` path. The API
    endpoint dispatches this task and returns the Celery ``task_id``
    immediately so the browser tab never hangs. Operators see live
    progress through the ``pbx.sync.*`` event taxonomy:

        pbx.sync.started     — task picked up by worker
        pbx.sync.progress    — per-stage update with
                               ``{stage, current, total, percent, message, data}``
        pbx.sync.completed   — final summary with per-resource counts
        pbx.sync.failed      — error with adapter-level message

    All events carry ``adapter_id="pbx:<uuid>"`` so the frontend can
    filter by PBX without cross-tenant noise (organization_id is also
    set on the event itself).
    """
    import asyncio

    task_id = self.request.id

    _emit_pbx_sync_event(
        pbx_id,
        "pbx.sync.started",
        {"task_id": task_id, "actor_id": actor_id},
        organization_id,
    )

    def _on_progress(stage: str, current: int, total: int, message: str | None, data: dict) -> None:
        _emit_pbx_sync_event(
            pbx_id,
            "pbx.sync.progress",
            {
                "task_id": task_id,
                "stage": stage,
                "current": current,
                "total": total,
                "percent": int((current / total) * 100) if total else 0,
                "message": message,
                "data": data,
            },
            organization_id,
        )
        # Also write to Celery's own task state so /task-status
        # polling endpoints can read it without the event bus.
        try:
            self.update_state(
                state="PROGRESS",
                meta={
                    "stage": stage,
                    "current": current,
                    "total": total,
                    "message": message,
                    "data": data,
                },
            )
        except Exception:
            pass

    async def _run_sync():
        from app.db.session import celery_session_factory
        from app.modules.voip.service import VoIPService

        async with celery_session_factory() as session:
            service = VoIPService(session)
            if organization_id:
                service.organization_id = UUID(organization_id)
            return await service.sync_pbx(
                UUID(pbx_id),
                progress_callback=_on_progress,
            )

    try:
        result = asyncio.run(_run_sync())
        # service.sync_pbx returns a dict instead of raising on
        # adapter-layer failure (so partial success can still ship a
        # summary). Translate that into the right event so the
        # frontend doesn't show "success" for a failed sync.
        inner_status = (result or {}).get("status", "success")
        if inner_status == "failed":
            _emit_pbx_sync_event(
                pbx_id,
                "pbx.sync.failed",
                {
                    "task_id": task_id,
                    "error": (result or {}).get("message", "Sync reported failed"),
                    "errors": (result or {}).get("errors", []),
                    "partial_summary": {
                        "extensions_synced": (result or {}).get("extensions_synced", 0),
                        "ring_groups_synced": (result or {}).get("ring_groups_synced", 0),
                        "trunks_found": (result or {}).get("trunks_found", 0),
                    },
                },
                organization_id,
            )
        else:
            _emit_pbx_sync_event(
                pbx_id,
                "pbx.sync.completed",
                {"task_id": task_id, "result": result},
                organization_id,
            )
        return result
    except Exception as exc:
        err_msg = str(exc) or type(exc).__name__
        logger.error("sync_pbx_full failed for pbx=%s: %s", pbx_id, err_msg, exc_info=True)
        _emit_pbx_sync_event(
            pbx_id,
            "pbx.sync.failed",
            {"task_id": task_id, "error": err_msg},
            organization_id,
        )
        raise
