# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Unified Device Sync Service
==========================================

Batch-optimized, security-hardened engine that syncs module-managed devices
(NVRs, phones, firewalls, plugin devices) into the core ``devices.devices``
table.  Replaces the 3 hard-coded sync functions previously in firmware.py.

Entry points:
- ``sync_all(session)``   — iterate every loaded module, batch-upsert
- ``upsert_single(...)``  — atomic single-device upsert (for plugin SDK)

Security layers:
- Atomic ``ON CONFLICT`` upsert (no check-then-act race)
- Distributed sync lock (``DeviceSyncLock``)
- Plugin prefix namespacing  (``plugin.{id}:``)
- Input validation (MAC, IP, string lengths, JSONB size/depth)
- SSRF IP blocking for plugin sources
- Per-source device count cap
- Site-ID validation against DB
- Model class type-check
- Device-type whitelist
- Circuit breaker per module
- Audit trail (summary + per-device for plugins)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.devices import Device
from app.models.sync_lock import DeviceSyncLock
from app.modules.base import DeviceSource

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOCK_TTL_SECONDS = 300  # 5 minutes
MAX_CONSECUTIVE_FAILURES = 3
COOLDOWN_SECONDS = 300
MAX_NAME_LENGTH = 255
MAX_STRING_LENGTH = 100
MAX_METADATA_BYTES = 51_200  # 50 KB
MAX_METADATA_DEPTH = 5
MAX_PLUGIN_DEVICES = 1_000

ALLOWED_DEVICE_TYPES = frozenset(
    {
        "switch",
        "router",
        "access_point",
        "gateway",
        "firewall",
        "camera",
        "nvr",
        "dvr",
        "access_control",
        "intercom",
        "voip_phone",
        "pbx",
        "server",
        "hypervisor",
        "iot",
        "sensor",
        "other",
    }
)

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]

# Reuse existing validators from schemas
from app.schemas.devices import _IP4_RE, _IP6_RE, _MAC_RE  # noqa: E402

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Circuit-breaker state (in-memory, resets on worker restart)
_failure_counts: dict[str, int] = {}
_cooldown_until: dict[str, datetime] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitize_log_safe(value: str) -> str:
    """Strip ANSI escapes and non-printable control chars."""
    value = _ANSI_RE.sub("", value)
    return "".join(c for c in value if c == " " or c.isprintable()).strip()


def _is_safe_ip(ip_str: str) -> bool:
    """Return False if IP is in a blocked (internal/loopback) range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in BLOCKED_NETWORKS)
    except ValueError:
        return False


def _validate_metadata(data: Any) -> dict[str, Any] | None:
    """Validate JSONB payload size and nesting depth."""
    if data is None:
        return None
    if not isinstance(data, dict):
        return None
    try:
        serialized = json.dumps(data, default=str)
    except (TypeError, ValueError):
        return None
    if len(serialized) > MAX_METADATA_BYTES:
        logger.warning(
            "Metadata exceeds %d bytes (%d), rejecting", MAX_METADATA_BYTES, len(serialized)
        )
        return None

    def _check_depth(obj: Any, depth: int = 0) -> None:
        if depth > MAX_METADATA_DEPTH:
            raise ValueError("too deep")
        if isinstance(obj, dict):
            for v in obj.values():
                _check_depth(v, depth + 1)
        elif isinstance(obj, list):
            for v in obj:
                _check_depth(v, depth + 1)

    try:
        _check_depth(data)
    except ValueError:
        logger.warning("Metadata exceeds max nesting depth %d", MAX_METADATA_DEPTH)
        return None
    return data


def _sanitize_fields(
    fields: dict[str, Any],
    source: DeviceSource,
    *,
    is_plugin: bool = False,
) -> dict[str, Any]:
    """Validate and sanitize extracted field values."""
    clean: dict[str, Any] = {}
    for key, val in fields.items():
        if val is None:
            clean[key] = None
            continue
        if key == "mac_address" and not _MAC_RE.match(str(val)):
            logger.warning("Source %s: invalid MAC '%s'", source.external_id_prefix, val)
            continue
        if key == "ip_address":
            s = str(val)
            if not (_IP4_RE.match(s) or _IP6_RE.match(s)):
                logger.warning("Source %s: invalid IP '%s'", source.external_id_prefix, val)
                continue
            if is_plugin and not _is_safe_ip(s):
                logger.warning(
                    "Plugin source %s: blocked internal IP '%s'", source.external_id_prefix, val
                )
                continue
        if key == "name":
            val = _sanitize_log_safe(str(val))[:MAX_NAME_LENGTH]
        if key in ("serial_number", "manufacturer", "model"):
            val = _sanitize_log_safe(str(val))[:MAX_STRING_LENGTH]
        clean[key] = val
    return clean


def _extract_fields(row: Any, source: DeviceSource) -> dict[str, Any]:
    return {
        device_field: getattr(row, source_attr, None)
        for device_field, source_attr in source.field_map.items()
    }


def _resolve_status(row: Any, source: DeviceSource) -> str:
    if source.status_is_boolean:
        return "online" if getattr(row, source.status_field, False) else "offline"
    raw = getattr(row, source.status_field, None) or ""
    return source.status_map.get(str(raw), source.default_status)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class DeviceSyncService:
    """Centralized device sync engine — batch-optimized + security-hardened."""

    # ------------------------------------------------------------------
    # Public: sync all modules
    # ------------------------------------------------------------------

    @staticmethod
    async def sync_all(session: AsyncSession) -> dict[str, Any]:
        """Iterate all loaded modules/plugins, batch-upsert their devices."""
        from app.modules.registry import module_registry
        from app.plugins.sdk import FreeSDNPlugin

        now = datetime.now(UTC)

        # --- Acquire distributed lock (atomic) ---
        await session.execute(delete(DeviceSyncLock).where(DeviceSyncLock.expires_at < now))

        lock = DeviceSyncLock(
            lock_key="device_sync",
            locked_by=f"worker-{uuid4().hex[:8]}",
            locked_at=now,
            expires_at=now + timedelta(seconds=LOCK_TTL_SECONDS),
        )
        session.add(lock)
        try:
            await session.flush()
        except IntegrityError:
            await session.rollback()
            return {"success": False, "reason": "sync already in progress"}

        results: dict[str, int] = {}
        errors: dict[str, str] = {}
        new_count = 0

        # Pre-load valid site IDs for validation, keyed by owning org so that
        # a source row's resolved site can be scoped to the row's own
        # organization (no cross-tenant placement, no cross-tenant fallback).
        from app.models.core import Site

        site_org_map: dict[UUID, UUID] = {
            row.id: row.organization_id
            for row in (
                await session.execute(
                    select(Site.id, Site.organization_id).where(Site.deleted_at.is_(None))
                )
            )
        }
        valid_site_ids: set[UUID] = set(site_org_map)
        fallback_site_id = next(iter(valid_site_ids), None)

        try:
            for module in module_registry.modules.values():
                module_id = module.id

                # Circuit breaker
                if module_id in _cooldown_until and now < _cooldown_until[module_id]:
                    logger.info("Module %s in cooldown — skipping", module_id)
                    results[module_id] = 0
                    continue

                is_plugin = isinstance(module, FreeSDNPlugin)

                try:
                    # Allow modules to refresh their data from external
                    # systems (e.g. Proxmox API) before we read the tables.
                    await module.pre_device_sync(session)

                    sources = module.get_device_sources()
                    for source in sources:
                        # Validate model class
                        if not isinstance(source.model, type) or not hasattr(
                            source.model, "__tablename__"
                        ):
                            logger.error(
                                "Module %s: model %s is not a SQLAlchemy model — skipped",
                                module_id,
                                source.model,
                            )
                            continue

                        # Validate device type
                        if source.device_type not in ALLOWED_DEVICE_TYPES:
                            logger.error(
                                "Module %s: device_type '%s' not allowed — skipped",
                                module_id,
                                source.device_type,
                            )
                            continue

                        # Enforce plugin prefix namespacing
                        if is_plugin:
                            expected_prefix = f"plugin.{module_id}"
                            if not source.external_id_prefix.startswith(expected_prefix):
                                logger.error(
                                    "Plugin %s: prefix '%s' must start with '%s' — skipped",
                                    module_id,
                                    source.external_id_prefix,
                                    expected_prefix,
                                )
                                continue

                        key = f"{module_id}:{source.external_id_prefix}"
                        # Use a SAVEPOINT so a single source failure doesn't
                        # poison the whole transaction for other modules.
                        async with session.begin_nested():
                            count, created = await DeviceSyncService._sync_source_batch(
                                session,
                                source,
                                valid_site_ids,
                                fallback_site_id,
                                site_org_map,
                                is_plugin=is_plugin,
                            )
                        results[key] = count
                        new_count += created

                    # Success → reset circuit breaker
                    _failure_counts.pop(module_id, None)
                    _cooldown_until.pop(module_id, None)

                except Exception as exc:
                    errors[module_id] = str(exc)
                    logger.exception("Device sync failed for module %s", module_id)
                    _failure_counts[module_id] = _failure_counts.get(module_id, 0) + 1
                    if _failure_counts[module_id] >= MAX_CONSECUTIVE_FAILURES:
                        _cooldown_until[module_id] = now + timedelta(seconds=COOLDOWN_SECONDS)
                        logger.warning(
                            "Module %s: %d failures, entering %ds cooldown",
                            module_id,
                            MAX_CONSECUTIVE_FAILURES,
                            COOLDOWN_SECONDS,
                        )

            await session.flush()
        finally:
            # Release lock
            await session.execute(
                delete(DeviceSyncLock).where(DeviceSyncLock.lock_key == "device_sync")
            )

        total = sum(results.values())

        # Audit summary
        try:
            from app.services.audit import AuditAction, AuditService, ResourceType

            audit = AuditService(session)
            await audit.log(
                action=AuditAction.UPDATE,
                resource_type=ResourceType.DEVICE,
                actor_type="system",
                actor_name="device_sync",
                tags=["device_sync", "automated"],
                extra_metadata={
                    "synced_by_source": results,
                    "total": total,
                    "errors": errors,
                    "new_devices_created": new_count,
                },
            )
        except Exception:
            logger.debug("Audit log for device sync failed", exc_info=True)

        return {
            "success": True,
            "synced_by_source": results,
            "total": total,
            "new_devices": new_count,
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # Batch sync for one DeviceSource
    # ------------------------------------------------------------------

    @staticmethod
    async def _sync_source_batch(
        session: AsyncSession,
        source: DeviceSource,
        valid_site_ids: set[UUID],
        fallback_site_id: UUID | None,
        site_org_map: dict[UUID, UUID] | None = None,
        *,
        is_plugin: bool = False,
    ) -> tuple[int, int]:
        """Batch-upsert one source.  Returns (total_synced, new_created)."""
        site_org_map = site_org_map or {}

        # 1. Load source rows
        query = select(source.model)
        if source.soft_delete_column:
            col = getattr(source.model, source.soft_delete_column, None)
            if col is not None:
                query = query.where(col.is_(None))
        source_rows = (await session.execute(query)).scalars().all()

        if not source_rows:
            return 0, 0

        # 2. Enforce device count cap
        effective_limit = (
            min(source.max_devices, MAX_PLUGIN_DEVICES) if is_plugin else source.max_devices
        )
        if len(source_rows) > effective_limit:
            logger.error(
                "Source %s: %d devices exceeds limit %d — truncating",
                source.external_id_prefix,
                len(source_rows),
                effective_limit,
            )
            source_rows = source_rows[:effective_limit]

        # 3. Load existing shadow devices for this prefix (batch, not N+1)
        prefix_pattern = f"{source.external_id_prefix}:%"
        existing_result = await session.execute(
            select(Device.external_id).where(
                Device.external_id.like(prefix_pattern), Device.deleted_at.is_(None)
            )
        )
        existing_ext_ids: set[str] = {row[0] for row in existing_result}

        # 4. Atomic upsert each row
        created = 0
        for row in source_rows:
            ext_id = f"{source.external_id_prefix}:{row.id}"
            raw_fields = _extract_fields(row, source)
            fields = _sanitize_fields(raw_fields, source, is_plugin=is_plugin)
            status = _resolve_status(row, source)
            name = (
                source.name_resolver(row) if source.name_resolver else fields.get("name")
            ) or "Unknown"
            name = _sanitize_log_safe(str(name))[:MAX_NAME_LENGTH]
            manufacturer = fields.get("manufacturer") or source.default_manufacturer
            if manufacturer:
                manufacturer = _sanitize_log_safe(str(manufacturer))[:MAX_STRING_LENGTH]

            # Resolve site_id.
            #
            # If the source row carries its own ``organization_id`` (most do),
            # scope BOTH validation and the fallback to that org's sites so a
            # shadow device can never be parented to a foreign tenant's site
            # (and the catch-all fallback never crosses org boundaries). Rows
            # without an org column (e.g. site-anchored models) keep the
            # global behavior.
            # FSDN-SG-002: honor BOTH tenant-column conventions. Most source
            # models name it ``organization_id``, but some (e.g. firewall
            # GatewayConnection) name it ``org_id``. Reading only the former
            # silently dropped those rows into the GLOBAL else-branch below,
            # letting a null-site gateway be parented under an arbitrary
            # (possibly cross-tenant) fallback site. Falling back to ``org_id``
            # keeps the allowed-site set scoped to the row's own org.
            row_org_id = getattr(row, "organization_id", None) or getattr(row, "org_id", None)
            if row_org_id is not None:
                allowed_site_ids = {sid for sid, oid in site_org_map.items() if oid == row_org_id}
                row_fallback_site_id = next(iter(allowed_site_ids), None)
            else:
                allowed_site_ids = valid_site_ids
                row_fallback_site_id = fallback_site_id

            site_id = fields.get("site_id")
            if source.site_id_resolver:
                site_id = source.site_id_resolver(row, row_fallback_site_id)
            if site_id and site_id not in allowed_site_ids:
                logger.warning(
                    "Source %s: invalid or out-of-tenant site_id %s, using fallback",
                    source.external_id_prefix,
                    site_id,
                )
                site_id = row_fallback_site_id
            if not site_id:
                site_id = row_fallback_site_id

            if not site_id:
                logger.warning(
                    "Source %s: no valid site_id available, skipping device",
                    source.external_id_prefix,
                )
                continue

            values: dict[str, Any] = {
                "name": name,
                "device_type": source.device_type,
                "manufacturer": manufacturer,
                "status": status,
                "external_id": ext_id,
                "site_id": site_id,
                "is_active": True,
                "is_managed": True,
                "lifecycle_state": "managed",
                # Re-adopt: if a device with this external_id was soft-deleted and
                # reappears in the source, the on_conflict update must clear
                # deleted_at — otherwise it stays hidden forever (the external_id
                # unique index is keyed on external_id, so the same row is reused).
                "deleted_at": None,
            }
            # Add optional fields
            for f in (
                "model",
                "firmware_version",
                "ip_address",
                "mac_address",
                "serial_number",
                "last_seen",
            ):
                if f in fields and fields[f] is not None:
                    values[f] = fields[f]

            # Track new devices
            if ext_id not in existing_ext_ids:
                created += 1
                existing_ext_ids.add(ext_id)

            stmt = pg_insert(Device.__table__).values(**values)
            stmt = stmt.on_conflict_do_update(
                index_elements=["external_id"],
                index_where=text("external_id IS NOT NULL"),
                set_={k: v for k, v in values.items() if k != "external_id"},
            )
            await session.execute(stmt)

        return len(source_rows), created

    # ------------------------------------------------------------------
    # Single-device upsert (used by DeviceSDK.register_device)
    # ------------------------------------------------------------------

    @staticmethod
    async def upsert_single(
        session: AsyncSession,
        *,
        external_id: str,
        name: str,
        device_type: str,
        site_id: UUID,
        manufacturer: str | None = None,
        model: str | None = None,
        firmware_version: str | None = None,
        ip_address: str | None = None,
        mac_address: str | None = None,
        serial_number: str | None = None,
        status: str = "unknown",
    ) -> UUID:
        """Atomic upsert of a single device row. Returns the device ID."""
        values: dict[str, Any] = {
            "name": _sanitize_log_safe(name)[:MAX_NAME_LENGTH],
            "device_type": device_type,
            "manufacturer": _sanitize_log_safe(manufacturer or "Unknown")[:MAX_STRING_LENGTH],
            "status": status,
            "external_id": external_id,
            "site_id": site_id,
            "is_active": True,
            "is_managed": True,
            "lifecycle_state": "managed",
        }
        if model:
            values["model"] = _sanitize_log_safe(model)[:MAX_STRING_LENGTH]
        if firmware_version:
            values["firmware_version"] = _sanitize_log_safe(firmware_version)[:50]
        if ip_address:
            values["ip_address"] = ip_address
        if mac_address:
            values["mac_address"] = mac_address
        if serial_number:
            values["serial_number"] = _sanitize_log_safe(serial_number)[:MAX_STRING_LENGTH]

        stmt = pg_insert(Device.__table__).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["external_id"],
            index_where=text("external_id IS NOT NULL"),
            set_={k: v for k, v in values.items() if k != "external_id"},
        ).returning(Device.__table__.c.id)
        result = await session.execute(stmt)
        return result.scalar_one()

    # ------------------------------------------------------------------
    # Incremental: sync a single module by ID
    # ------------------------------------------------------------------

    @staticmethod
    async def sync_module(session: AsyncSession, module_id: str) -> dict[str, Any]:
        """
        Sync devices for a single module only.

        Much lighter than ``sync_all`` — no distributed lock needed because
        the debounce key in Redis already prevents overlapping calls for the
        same module.  Called by the event-driven trigger after CRUD ops.
        """
        from app.modules.registry import module_registry

        module = module_registry.modules.get(module_id)
        if module is None:
            return {"success": False, "reason": f"module {module_id} not loaded"}

        from app.models.core import Site

        site_org_map: dict[UUID, UUID] = {
            row.id: row.organization_id
            for row in (
                await session.execute(
                    select(Site.id, Site.organization_id).where(Site.deleted_at.is_(None))
                )
            )
        }
        valid_site_ids: set[UUID] = set(site_org_map)
        fallback_site_id = next(iter(valid_site_ids), None)

        results: dict[str, int] = {}
        new_count = 0

        # Allow module to refresh from external systems first
        await module.pre_device_sync(session)

        sources = module.get_device_sources()
        for source in sources:
            if not isinstance(source.model, type) or not hasattr(source.model, "__tablename__"):
                continue
            if source.device_type not in ALLOWED_DEVICE_TYPES:
                continue

            key = f"{module_id}:{source.external_id_prefix}"
            async with session.begin_nested():
                count, created = await DeviceSyncService._sync_source_batch(
                    session,
                    source,
                    valid_site_ids,
                    fallback_site_id,
                    site_org_map,
                )
            results[key] = count
            new_count += created

        await session.flush()

        total = sum(results.values())
        return {
            "success": True,
            "module": module_id,
            "synced_by_source": results,
            "total": total,
            "new_devices": new_count,
        }

    # ------------------------------------------------------------------
    # Remove shadow device when source entity is deleted
    # ------------------------------------------------------------------

    @staticmethod
    async def remove_device(
        session: AsyncSession,
        *,
        external_id_prefix: str,
        source_id: UUID,
    ) -> bool:
        """
        Soft-delete the shadow device in ``devices.devices`` when the source
        entity (NVR, phone, gateway, etc.) is deleted.

        Returns True if a device was found and marked deleted.
        """
        ext_id = f"{external_id_prefix}:{source_id}"
        result = await session.execute(
            select(Device).where(Device.external_id == ext_id, Device.deleted_at.is_(None))
        )
        device = result.scalar_one_or_none()
        if device is None:
            return False

        device.is_active = False
        device.status = "offline"
        device.deleted_at = datetime.now(UTC)
        logger.info("Shadow device removed: %s (%s)", device.name, ext_id)
        return True


# ---------------------------------------------------------------------------
# Event-driven sync trigger (debounced via Redis)
# ---------------------------------------------------------------------------

DEBOUNCE_SECONDS = 5  # Coalesce rapid CRUD ops into one sync


def trigger_device_registry_sync(module_id: str) -> None:
    """
    Schedule an incremental device-registry sync for *one* module.

    Uses a Redis SET NX key with TTL as a debounce — if the key already
    exists, the task is already queued and we skip.  This prevents
    hammering the DB when 50 NVRs are bulk-imported in quick succession.

    Safe to call from any async or sync context (fires a Celery task).
    """
    from app.core.redis_client import get_sync_redis

    r = get_sync_redis()
    key = f"freesdn:device_sync_pending:{module_id}"

    # SET NX — only one task per module within the debounce window
    if r.set(key, "1", nx=True, ex=DEBOUNCE_SECONDS):
        from app.core.celery_app import celery_app

        celery_app.send_task(
            "sync.sync_module_incremental",
            args=[module_id],
            countdown=DEBOUNCE_SECONDS,
            queue="sync",
        )
        logger.debug(
            "Queued incremental sync for module %s (debounce %ds)", module_id, DEBOUNCE_SECONDS
        )
    r.close()
