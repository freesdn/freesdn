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
from typing import Any
from uuid import UUID

from celery import shared_task

logger = logging.getLogger(__name__)


def _get_adapter(vendor: str, host: str, username: str, password: str, **kwargs):
    """Create an adapter instance by vendor name."""
    from app.adapters.registry import adapter_registry

    return adapter_registry.create_adapter(vendor, host, username, password, **kwargs)


def _phone_creds(phone) -> tuple[str, str] | None:
    """The phone's saved admin login, or None when none is saved.

    ``VoIPService.save_phone_credentials`` stores ``web_username`` and a
    Fernet-encrypted ``web_password``. These tasks used to read ``username`` /
    ``password``, which nothing writes, and fall back to ``admin``/``admin``, so
    every poll tried the factory default against the phone instead of the login
    the operator saved. Rows written before that change may carry the plain
    keys, so they are still honoured. A default is never guessed: a wrong guess
    every five minutes is how a phone locks its admin account.
    """
    from app.core.crypto import decrypt_credential, is_encrypted

    settings = phone.settings or {}
    password = settings.get("web_password") or settings.get("password")
    if not password:
        return None
    if is_encrypted(password):
        password = decrypt_credential(password)
    username = settings.get("web_username") or settings.get("username") or "admin"
    return username, password


#: Phones an operator has adopted. Onboarding moves a phone to "onboarding" and
#: nothing moves it on to "managed" (mark_phone_managed has no caller, and under
#: ADAPTER_READ_ONLY a phone cannot be provisioned at all), so polling only
#: "managed" phones polled none: status, SIP registration and uptime froze at
#: whatever the discovery scan saw.
_POLLED_LIFECYCLE_STATES = ("managed", "onboarding")


async def _adopted_phones(service, site_id: str | None, limit: int) -> list:
    phones: list = []
    for state in _POLLED_LIFECYCLE_STATES:
        batch, _ = await service.list_phones(
            site_id=UUID(site_id) if site_id else None,
            lifecycle_state=state,
            limit=limit,
        )
        phones.extend(batch)
    return phones


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


def _pbx_adapter(pbx):
    """Build the adapter for a saved PBX the same way the UI and staging do.

    These tasks used to read ``settings.api_username`` / ``settings.api_password``
    and hand them to the generic registry. The password moved to the encrypted
    ``web_password_enc`` column long ago, so every task logged in with an empty
    password, and no AMI or ARI login was ever passed, so the AMI fallback that
    extension listing and state polling depend on could not connect either.

    ``build_freepbx_adapter_from_pbx`` is the one place that knows the column
    precedence, the AMI/ARI logins, OAuth2 vs web session and the TLS
    acknowledgement gate; using it here means a task authenticates exactly as an
    operator's click does. Returns ``None`` for PBX types it cannot build.
    """
    if (pbx.pbx_type or "freepbx") not in ("freepbx", "asterisk"):
        return None
    from app.modules.voip.adapter_factory import build_freepbx_adapter_from_pbx

    return build_freepbx_adapter_from_pbx(pbx)


def _result_list(result) -> list:
    """Unwrap an ``AdapterResult`` (or a bare list) into a list of records.

    The FreePBX adapter returns ``AdapterResult`` envelopes. Iterating the
    envelope itself, as ``sync_extensions`` did, raises before any record is
    read; a failed result is an empty batch, not an exception.
    """
    if result is None:
        return []
    if hasattr(result, "success"):
        if not result.success:
            return []
        result = result.data
    if isinstance(result, list):
        return result
    return []


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
            phones = await _adopted_phones(service, site_id, limit=1000)

            synced = 0
            errors = 0
            no_credentials = 0

            # Group phones by IP for batch probes  (one adapter per phone)
            for phone in phones:
                if not phone.ip_address:
                    continue
                creds = _phone_creds(phone)
                if creds is None:
                    # Not knowing the login says nothing about the phone, so
                    # leave its status alone rather than counting a failure.
                    no_credentials += 1
                    continue
                uname, pwd = creds
                try:
                    vendor = (phone.vendor or "grandstream").lower()
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
                "no_credentials": no_credentials,
                "total": len(phones),
            }

    return asyncio.run(run_sync())


# =============================================================================
# CDR Sync
# =============================================================================


# Bounds for one CDR sync of one PBX. The first sync of a PBX imports at most
# the last CDR_BACKFILL_DAYS; a PBX that fell behind catches up at most
# CDR_MAX_DAYS_PER_RUN days per run; each day is one bounded request.
CDR_BACKFILL_DAYS = 7
CDR_MAX_DAYS_PER_RUN = 8
CDR_MAX_RECORDS_PER_DAY = 2000


def _call_direction(record: dict, extensions: set[str]) -> str:
    """inbound / outbound / internal from the PBX's own extension numbers."""
    src = str(record.get("cnum") or record.get("src") or "")
    dst = str(record.get("dst") or "")
    if src in extensions and dst in extensions:
        return "internal"
    if src in extensions:
        return "outbound"
    return "inbound"


def _record_cdr_state(pbx, **state) -> None:
    """Keep the last sync outcome on the PBX row, where the API returns it.

    Without it a PBX that cannot provide call history and a PBX on which nobody
    made a call look identical: an empty Call History page.
    """
    from sqlalchemy.orm.attributes import flag_modified

    settings = dict(pbx.settings or {})
    settings["cdr_sync"] = {"last_run_at": datetime.now(UTC).isoformat(), **state}
    pbx.settings = settings
    flag_modified(pbx, "settings")


async def _sync_cdr_for_pbx(pbx_id: str) -> dict:
    """Import new call detail records for one PBX into voip.call_logs.

    Incremental: resumes from the newest stored call (that day is re-read, and
    ``create_call_log`` skips a ``unique_id`` it already has, so re-reads and
    retries never duplicate). Bounded by the constants above.
    """
    from sqlalchemy import func, select

    from app.db.session import celery_session_factory
    from app.modules.voip.models import CallLog, Extension
    from app.modules.voip.service import VoIPService

    async with celery_session_factory() as session:
        service = VoIPService(session)
        try:
            pbx = await service.get_pbx(UUID(pbx_id))
        except Exception:
            return {"status": "error", "reason": f"PBX {pbx_id} not found"}

        adapter = _pbx_adapter(pbx)
        if adapter is None:
            return {"status": "skipped", "reason": f"no adapter for {pbx.pbx_type}"}
        # Only the OAuth2 Admin API serves CDR. Do not log in to a PBX just to
        # be told so every fifteen minutes.
        has_api_app = getattr(pbx, "api_client_id", None) and getattr(
            pbx, "api_client_secret_enc", None
        )
        if not has_api_app:
            reason = (
                "This PBX is connected with a web session; call history needs a "
                "FreePBX Admin API (OAuth2) application on the connection"
            )
            _record_cdr_state(pbx, status="unsupported", imported=0, error=reason)
            await session.commit()
            return {"status": "unsupported", "pbx_id": pbx_id, "reason": reason}

        newest = await session.scalar(
            select(func.max(CallLog.start_time)).where(CallLog.pbx_id == pbx.id)
        )
        today = datetime.now(UTC).date()
        first_day = newest.date() if newest else today - timedelta(days=CDR_BACKFILL_DAYS)
        days = [
            first_day + timedelta(days=i)
            for i in range(CDR_MAX_DAYS_PER_RUN)
            if first_day + timedelta(days=i) <= today
        ]
        extensions = {
            str(n)
            for n in (
                await session.execute(
                    select(Extension.extension_number).where(
                        Extension.pbx_id == pbx.id, Extension.deleted_at.is_(None)
                    )
                )
            ).scalars()
        }

        imported = 0
        truncated: list[str] = []
        status, error = "ok", None
        # One request group per PBX across every poller and process
        # (app/core/device_slot.py): a PBX another poller or a page is reading is
        # left to the next run, and its last sync outcome stands.
        from app.core.device_poll import device_poll
        from app.core.device_slot import pbx_slot_key

        async with device_poll(
            slot_key=pbx_slot_key(pbx), breaker=None, breaker_key=None, holder="CDR sync"
        ) as turn:
            if turn.skipped:
                return {"status": "skipped", "pbx_id": pbx_id, "reason": turn.reason}
            try:
                async with adapter:
                    for day in days:
                        stamp = day.isoformat()
                        result = await adapter.search_call_logs(
                            start_date=stamp, end_date=stamp, limit=CDR_MAX_RECORDS_PER_DAY
                        )
                        if not getattr(result, "success", False):
                            code = getattr(result, "error_code", None)
                            status = "unsupported" if code == "NOT_SUPPORTED" else "error"
                            error = str(getattr(result, "error", "") or "CDR read failed")[:300]
                            break
                        rows = [r for r in (result.data or []) if isinstance(r, dict)]
                        if len(rows) >= CDR_MAX_RECORDS_PER_DAY:
                            truncated.append(stamp)
                        for record in rows:
                            record = dict(record)
                            record.setdefault("direction", _call_direction(record, extensions))
                            call = await service.create_call_log(pbx_id=pbx.id, **record)
                            if call in session.new:
                                imported += 1
                        # Flush per day so the next day's dedupe sees these rows.
                        await session.flush()
            except Exception as exc:
                logger.warning("CDR sync failed for PBX %s: %s", pbx_id, type(exc).__name__)
                status, error = "error", f"CDR sync failed ({type(exc).__name__})"
                turn.failed(exc)

        _record_cdr_state(
            pbx,
            status=status,
            imported=imported,
            error=error,
            through=days[-1].isoformat() if days else None,
            truncated_days=truncated,
        )
        await session.commit()
        return {"status": status, "pbx_id": pbx_id, "new_records": imported, "error": error}


@shared_task(
    bind=True,
    name="voip.sync_cdr",
    max_retries=3,
    default_retry_delay=120,
    soft_time_limit=540,
    time_limit=600,
)
def sync_cdr(self, pbx_id: str) -> dict:
    """Import new call detail records from one PBX (see ``_sync_cdr_for_pbx``).

    One run per PBX at a time: two overlapping runs would both read the same
    day before either stored it.
    """
    import asyncio

    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    lock = f"voip.sync_cdr:{pbx_id}"
    token = acquire_solo_lock(lock, ttl_seconds=600)
    if not token:
        return {"status": "skipped", "pbx_id": pbx_id, "reason": "already_running"}
    try:
        return asyncio.run(_sync_cdr_for_pbx(pbx_id))
    finally:
        release_solo_lock(lock, token)


@shared_task(name="voip.sync_all_cdr", soft_time_limit=60, time_limit=90)
def sync_all_cdr() -> dict:
    """Beat entry: queue a CDR sync for every active FreePBX/Asterisk PBX.

    ``voip.sync_cdr`` was registered and never scheduled, so stored call history
    (the Call History page and its stats) stayed empty on every install.
    """
    import asyncio

    async def _pbx_ids() -> list[str]:
        from sqlalchemy import select

        from app.db.session import celery_session_factory
        from app.models.core import Site
        from app.modules.enablement import is_module_explicitly_disabled
        from app.modules.voip.models import PBX

        async with celery_session_factory() as session:
            rows = (
                await session.execute(
                    select(PBX.id, Site.organization_id)
                    .join(Site, PBX.site_id == Site.id)
                    .where(
                        PBX.deleted_at.is_(None),
                        PBX.is_active.is_(True),
                        PBX.pbx_type.in_(("freepbx", "asterisk")),
                        Site.alive(),
                    )
                )
            ).all()
            # An organization that switched the VoIP module off is not polled:
            # disabling a module must stop its background work, not only its UI.
            disabled = {
                org
                for org in {row[1] for row in rows}
                if await is_module_explicitly_disabled(session, org, "voip")
            }
            return [str(pbx_id) for pbx_id, org in rows if org not in disabled]

    ids = asyncio.run(_pbx_ids())
    for pbx_id in ids:
        # No queue=: routes to "default", which every tier consumes.
        sync_cdr.apply_async(args=[pbx_id], expires=840)
    return {"dispatched": len(ids)}


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

            adapter = _pbx_adapter(pbx)
            if adapter is None:
                return {"status": "skipped", "reason": f"no adapter for {pbx.pbx_type}"}

            added = updated = removed = 0
            try:
                async with adapter:
                    if hasattr(adapter, "list_extensions"):
                        remote_exts = _result_list(await adapter.list_extensions())
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
                        adapter = _pbx_adapter(pbx)
                        if adapter is None:
                            return 0
                        async with adapter:
                            # The adapter has no extension-state method of its
                            # own (BaseAdapter stubs get_* to NOT_SUPPORTED);
                            # the states come from its AMI client.
                            ami = getattr(adapter, "_ami", None)
                            if ami is not None and getattr(ami, "connected", False):
                                states = await ami.get_extension_states()
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

            creds = _phone_creds(phone)
            if creds is None:
                return {
                    "status": "error",
                    "reason": "Phone has no saved admin credentials; save them on the phone first",
                }
            uname, pwd = creds
            vendor = (phone.vendor or "grandstream").lower()
            adapter = _get_adapter(
                vendor,
                host=phone.ip_address,
                username=uname,
                password=pwd,
            )

            try:
                from sqlalchemy import select as _select

                from app.core.device_slot import phone_slot_key
                from app.models.core import Site as _Site
                from app.services.device_writes import audited_device_action

                phone_org = (
                    await session.execute(
                        _select(_Site.organization_id).where(
                            _Site.id == getattr(phone, "site_id", None)
                        )
                    )
                ).scalar_one_or_none()

                async def _reboot() -> Any:
                    # Login and reboot are one request group, inside the
                    # phone's turn, so neither lands on a health poll.
                    async with adapter:
                        adapter.add_phone(phone.ip_address, mac=phone.mac_address or "")
                        return await adapter.reboot_phone(phone.mac_address or "")

                result = await audited_device_action(
                    session,
                    action="reboot_phone",
                    target_type="device",
                    target_id=phone.id,
                    target_name=f"phone {phone.ip_address}",
                    organization_id=phone_org,
                    site_id=getattr(phone, "site_id", None),
                    actor_id=None,
                    parameters={"phone_ip": phone.ip_address},
                    perform=_reboot,
                    slot_key=phone_slot_key(phone),
                )
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
def run_discovery_scan_task(
    self,
    scan_id: str,
    transient_creds: dict | None = None,
    try_default_credentials: bool = False,
) -> dict:
    """
    Run a network discovery scan for VoIP devices.

    Dispatched from the /discovery/scan endpoint. Updates the
    DiscoveryScan record with progress and results as they come in.

    Args:
        scan_id: UUID of the DiscoveryScan record.
        transient_creds: Optional dict with ``username`` and encrypted
            ``password``.  Passed transiently from the API — never
            persisted in the DB. Without them phones are only identified.
        try_default_credentials: the operator's explicit opt-in to also try
            the phones' factory default login.
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
                # Never fill in a default: a missing username or password
                # means "identify only", unless the operator opted in below.
                scan_credentials = None
                if transient_creds and isinstance(transient_creds, dict):
                    from app.core.crypto import decrypt_credential, is_encrypted

                    raw_user = transient_creds.get("username")
                    raw_pw = transient_creds.get("password")
                    if raw_pw and is_encrypted(raw_pw):
                        raw_pw = decrypt_credential(raw_pw)
                    if raw_user and raw_pw:
                        scan_credentials = {"username": raw_user, "password": raw_pw}

                discovered = await run_discovery_scan(
                    subnet=subnet,
                    scan_type=scan_type,
                    on_progress=on_progress,
                    credentials=scan_credentials,
                    try_default_credentials=bool(try_default_credentials),
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


#: ``_poll_phone_status`` could not read the phone.
_POLL_FAILED = object()


async def _poll_phone_status(turn, phone, username: str, password: str):
    """One login and one status read, or ``_POLL_FAILED``."""
    try:
        vendor = (phone.vendor or "grandstream").lower()
        adapter = _get_adapter(vendor, host=phone.ip_address, username=username, password=password)
        async with adapter:
            return await adapter.get_device_status(phone.mac_address or "")
    except Exception as exc:
        # WARNING, not DEBUG: at DEBUG a fleet whose every poll failed produced
        # no log line at all.
        logger.warning(
            "Phone health check failed for %s (%s): %s",
            phone.id,
            phone.ip_address,
            type(exc).__name__,
        )
        turn.failed(exc)
        return _POLL_FAILED


async def _sites_with_voip_disabled(session, phones) -> set:
    """Sites of organizations that explicitly switched the VoIP module off."""
    from sqlalchemy import select

    from app.models.core import Site
    from app.modules.poll_gate import orgs_with_module_disabled

    # freesdn:include-deleted -- the organization of a polled phone's site
    # decides the module gate whether or not the site row was soft-deleted.
    site_ids = {getattr(p, "site_id", None) for p in phones} - {None}
    if not site_ids:
        return set()
    rows = (
        await session.execute(select(Site.id, Site.organization_id).where(Site.id.in_(site_ids)))
    ).all()
    disabled = await orgs_with_module_disabled(session, "voip", {org for _, org in rows})
    return {sid for sid, org in rows if org in disabled}


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
            from app.core.device_breaker import phone_breaker, phone_key
            from app.core.device_poll import device_poll
            from app.core.device_slot import phone_slot_key
            from app.modules.voip.service import VoIPService

            service = VoIPService(session)
            phones = await _adopted_phones(service, site_id, limit=2000)
            # An organization that switched the VoIP module off is not polled.
            disabled_sites = await _sites_with_voip_disabled(session, phones)

            healthy = 0
            degraded = 0
            offline = 0
            no_credentials = 0
            skipped = 0

            for phone in phones:
                if getattr(phone, "site_id", None) in disabled_sites:
                    continue
                if not phone.ip_address:
                    offline += 1
                    continue
                creds = _phone_creds(phone)
                if creds is None:
                    # Unknown login is not evidence the phone is down: leave its
                    # status alone instead of letting the grace gate flip it.
                    no_credentials += 1
                    continue
                uname, pwd = creds

                # Nothing below holds a database transaction while the phone
                # answers: what the loop changed so far is committed here, and
                # this phone's update is written after its reply.
                await session.commit()
                # The phone's shared breaker and device slot: a phone that does
                # not answer is not logged into every 5 minutes, and one that a
                # discovery scan or a UI read is talking to keeps its status.
                async with device_poll(
                    slot_key=phone_slot_key(phone),
                    breaker=phone_breaker,
                    breaker_key=phone_key(phone.id),
                    holder="phone health check",
                ) as turn:
                    if turn.skipped:
                        skipped += 1
                        continue
                    status_data = await _poll_phone_status(turn, phone, uname, pwd)
                if status_data is _POLL_FAILED:
                    # Transient failure: only flip offline once past the grace
                    # gate so a single blip doesn't flap the phone row.
                    with contextlib.suppress(Exception):
                        if _should_mark_phone_offline(phone):
                            await service.update_phone(phone.id, {"status": "offline"})
                            offline += 1
                        _bump_phone_fail_count(phone)
                    continue

                try:
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

                        # A reachable phone that is not SIP-registered stays
                        # "online"; sip_registered=False above records the
                        # registration problem. This used to write "warning",
                        # which is not a PhoneStatus, so the phone pages counted
                        # the phone as neither online nor offline.
                        if not sd.get("sip_registered", True):
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
                    logger.warning(
                        "Phone health update failed for %s: %s", phone.id, type(exc).__name__
                    )

            await session.commit()
            return {
                "status": "success",
                "total": len(phones),
                "healthy": healthy,
                "degraded": degraded,
                "offline": offline,
                "no_credentials": no_credentials,
                "skipped": skipped,
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
                    creds = _phone_creds(phone)
                    if creds is None:
                        logger.warning("Bulk reboot skipped %s: no saved admin credentials", pid)
                        failed += 1
                        continue
                    uname, pwd = creds

                    vendor = (phone.vendor or "grandstream").lower()
                    adapter = _get_adapter(
                        vendor,
                        host=phone.ip_address,
                        username=uname,
                        password=pwd,
                    )
                    from app.core.device_slot import phone_slot_key
                    from app.services.device_writes import audited_device_action

                    async def _reboot(
                        adapter: Any = adapter,
                        ip: str = phone.ip_address,
                        mac: str = phone.mac_address or "",
                    ) -> Any:
                        async with adapter:
                            adapter.add_phone(ip, mac=mac)
                            return await adapter.reboot_phone(mac)

                    await audited_device_action(
                        session,
                        action="reboot_phone",
                        target_type="device",
                        target_id=phone.id,
                        target_name=f"phone {phone.ip_address}",
                        organization_id=None,
                        site_id=getattr(phone, "site_id", None),
                        actor_id=None,
                        parameters={"phone_ip": phone.ip_address, "bulk": True},
                        perform=_reboot,
                        slot_key=phone_slot_key(phone),
                    )
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
