# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Network device configuration backup (Oxidized-style, READ-ONLY)
========================================================================

Scheduled, versioned, diffable, encrypted-at-rest snapshots of each device's
running configuration, for vendors whose adapter can EXPORT it read-only:

* OPNsense -- ``config.xml`` via ``GET /api/core/backup/download/this``
* OpenWrt  -- the LuCI sysupgrade archive via ``/cgi-bin/cgi-backup``

Being a gentle neighbour is the point (a full config.xml download on every 5-
minute sync helped wedge a production OPNsense):

* daily by default, per-target ``interval_hours`` (6..168), with jitter, and the
  first export of a newly seen device spread over 10-70 minutes;
* at most ONE export per device at a time (a lease row-claim; a crashed worker's
  lease expires and the provisional next run is an hour out, not minutes);
* a hard 120 s budget per export; failures back off 1h, 2h, 4h ... up to the
  interval, never retried in a loop;
* a gateway whose polling is paused (``sync_enabled = false``) is never contacted;
* never part of a sync, and manual captures refuse within 10 minutes of the last.

The export is stored only when it differs from the newest version (keyed HMAC
of the normalized content), Fernet-encrypted (instance SECRET_KEY) over zlib.
Nothing here logs configuration content or device-supplied error text, and
nothing restores: there is no write path in this module.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

from sqlalchemy import delete, false, func, or_, select, true, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult

from app.modules.backup.models import DeviceConfigBackupTarget, DeviceConfigSnapshot
from app.modules.poll_gate import module_not_disabled
from app.services.device_config_render import (
    MAX_EXPORT_BYTES,
    OPENWRT_SYSUPGRADE,
    OPNSENSE_XML,
    ConfigFormatError,
    content_digest,
    diff_summary,
    normalize_export,
    redacted_diff,
    render_redacted,
)

logger = logging.getLogger(__name__)

SOURCE_GATEWAY = "gateway"
GATEWAY_FORMATS = {"opnsense": OPNSENSE_XML, "openwrt": OPENWRT_SYSUPGRADE}

CAPTURE_TIMEOUT_SECONDS = 120
#: A capture that finds the device busy (another poller holds its slot) or its
#: breaker open tries again this many seconds later, without counting a failure.
DEFER_SECONDS = (600, 1200)


def _default_interval_hours() -> int:
    """CONFIG_BACKUP_INTERVAL_HOURS, clamped to the per-target range."""
    from app.core.config import settings

    low, high = INTERVAL_HOURS_RANGE
    return max(low, min(high, int(settings.CONFIG_BACKUP_INTERVAL_HOURS)))


LEASE_SECONDS = 600
CRASH_RETRY_SECONDS = 3600
MANUAL_MIN_SECONDS = 600
FIRST_CAPTURE_SPREAD = (600, 4200)
FAILURE_BACKOFF_SECONDS = 3600
DISPATCH_LIMIT = 20
INTERVAL_HOURS_RANGE = (6, 168)
RETENTION_RANGE = (1, 365)


class CaptureRefused(Exception):
    """A manual capture was refused before any device contact."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class SnapshotUnavailable(Exception):
    """Stored ciphertext cannot be opened (SECRET_KEY changed or damaged row)."""


class ExportFailed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# ── encryption at rest ─────────────────────────────────────────────────────


def seal(raw: bytes) -> bytes:
    from app.core.crypto import _get_fernet

    return _get_fernet().encrypt(zlib.compress(raw, 6))


def unseal(token: bytes) -> bytes:
    from cryptography.fernet import InvalidToken

    from app.core.crypto import _get_fernet

    try:
        compressed = _get_fernet().decrypt(bytes(token))
    except (InvalidToken, TypeError, ValueError):
        raise SnapshotUnavailable() from None
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(compressed, MAX_EXPORT_BYTES + 1)
    except zlib.error:
        raise SnapshotUnavailable() from None
    if len(raw) > MAX_EXPORT_BYTES or inflater.unconsumed_tail:
        raise SnapshotUnavailable()
    return raw


# ── scheduling helpers ─────────────────────────────────────────────────────


def first_capture_delay(source_id: UUID) -> timedelta:
    """Deterministic per device, so a fleet added at once is spread out."""
    low, high = FIRST_CAPTURE_SPREAD
    spread = int.from_bytes(hashlib.sha256(source_id.bytes).digest()[:4], "big")
    return timedelta(seconds=low + spread % (high - low))


def next_success_due(now: datetime, interval_hours: int) -> datetime:
    interval = interval_hours * 3600
    return now + timedelta(seconds=interval + random.uniform(0, interval * 0.1))  # noqa: S311


def next_failure_due(now: datetime, interval_hours: int, failures: int) -> datetime:
    backoff = FAILURE_BACKOFF_SECONDS * 2 ** max(0, min(failures - 1, 8))
    return now + timedelta(seconds=min(backoff, interval_hours * 3600))


def _active_org(org_column: Any) -> Any:
    """Same rule GatewayService applies: never touch a device of a deleted or
    deactivated organization."""
    from sqlalchemy import exists

    from app.models.core import Organization

    return exists().where(
        Organization.id == org_column,
        Organization.deleted_at.is_(None),
        Organization.is_active.is_(True),
    )


@dataclass(frozen=True)
class Claim:
    target_id: UUID
    token: UUID


class DeviceConfigBackupService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ── target discovery ────────────────────────────────────────────────

    async def sync_targets(self, now: datetime | None = None) -> dict[str, int]:
        """Make sure every exportable gateway has a target; flag removed ones."""
        from app.modules.firewall.models import GatewayConnection

        now = now or datetime.now(UTC)
        gateways = (
            await self.session.execute(
                select(GatewayConnection).where(
                    GatewayConnection.deleted_at.is_(None),
                    GatewayConnection.vendor.in_(tuple(GATEWAY_FORMATS)),
                    _active_org(GatewayConnection.org_id),
                )
            )
        ).scalars()
        seen: set[UUID] = set()
        added = 0
        for gw in gateways:
            seen.add(gw.id)
            result = await self.session.execute(
                pg_insert(DeviceConfigBackupTarget)
                .values(
                    id=uuid4(),
                    organization_id=gw.org_id,
                    site_id=gw.site_id,
                    source_kind=SOURCE_GATEWAY,
                    source_id=gw.id,
                    vendor=gw.vendor,
                    display_name=gw.name[:255],
                    enabled=True,
                    interval_hours=_default_interval_hours(),
                    retention_versions=30,
                    next_due_at=now + first_capture_delay(gw.id),
                    last_status="never",
                    consecutive_failures=0,
                )
                .on_conflict_do_nothing(constraint="uq_bak_cfg_target_source")
            )
            if cast("CursorResult[Any]", result).rowcount:
                added += 1
                continue
            # Keep the listing truthful when a gateway is renamed or moved.
            await self.session.execute(
                update(DeviceConfigBackupTarget)
                .where(
                    DeviceConfigBackupTarget.source_kind == SOURCE_GATEWAY,
                    DeviceConfigBackupTarget.source_id == gw.id,
                )
                .values(
                    organization_id=gw.org_id,
                    site_id=gw.site_id,
                    vendor=gw.vendor,
                    display_name=gw.name[:255],
                )
            )
        removed = await self.session.execute(
            update(DeviceConfigBackupTarget)
            .where(
                DeviceConfigBackupTarget.source_kind == SOURCE_GATEWAY,
                DeviceConfigBackupTarget.source_id.not_in(seen) if seen else true(),
                DeviceConfigBackupTarget.last_status != "source_removed",
            )
            .values(last_status="source_removed", next_due_at=None)
        )
        # A gateway that came back (restored) is scheduled again.
        revived = await self.session.execute(
            update(DeviceConfigBackupTarget)
            .where(
                DeviceConfigBackupTarget.source_kind == SOURCE_GATEWAY,
                DeviceConfigBackupTarget.source_id.in_(seen) if seen else false(),
                DeviceConfigBackupTarget.last_status == "source_removed",
            )
            .values(
                last_status="never", next_due_at=now + timedelta(seconds=FIRST_CAPTURE_SPREAD[0])
            )
        )
        return {
            "added": added,
            "removed": cast("CursorResult[Any]", removed).rowcount,
            "revived": cast("CursorResult[Any]", revived).rowcount,
        }

    # ── single-flight claims ───────────────────────────────────────────

    async def claim_due(
        self, now: datetime | None = None, limit: int = DISPATCH_LIMIT
    ) -> list[Claim]:
        """Lease up to ``limit`` due targets. A lease blocks every other export of
        that device; the provisional next run is an hour out in case the worker
        dies mid-export (completion always overwrites it)."""
        now = now or datetime.now(UTC)
        ids = (
            await self.session.execute(
                select(DeviceConfigBackupTarget.id)
                .where(
                    DeviceConfigBackupTarget.enabled.is_(True),
                    DeviceConfigBackupTarget.next_due_at.is_not(None),
                    DeviceConfigBackupTarget.next_due_at <= now,
                    # Disabling the Firewall module stops the scheduled exports
                    # of that organization's gateways along with its polling.
                    module_not_disabled(DeviceConfigBackupTarget.organization_id, "firewall"),
                    or_(
                        DeviceConfigBackupTarget.lease_until.is_(None),
                        DeviceConfigBackupTarget.lease_until < now,
                    ),
                )
                .order_by(DeviceConfigBackupTarget.next_due_at)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        ).scalars()
        claims = []
        for target_id in list(ids):
            token = uuid4()
            await self.session.execute(
                update(DeviceConfigBackupTarget)
                .where(DeviceConfigBackupTarget.id == target_id)
                .values(
                    lease_until=now + timedelta(seconds=LEASE_SECONDS),
                    lease_token=token,
                    next_due_at=now + timedelta(seconds=CRASH_RETRY_SECONDS),
                )
            )
            claims.append(Claim(target_id, token))
        return claims

    async def claim_manual(
        self, target: DeviceConfigBackupTarget, now: datetime | None = None
    ) -> Claim:
        now = now or datetime.now(UTC)
        if target.last_status == "source_removed":
            raise CaptureRefused(409, "The device behind this backup target no longer exists")
        if target.last_attempt_at and (now - target.last_attempt_at).total_seconds() < (
            MANUAL_MIN_SECONDS
        ):
            raise CaptureRefused(
                429, "This device was exported less than 10 minutes ago; try again later"
            )
        token = uuid4()
        claimed = await self.session.execute(
            update(DeviceConfigBackupTarget)
            .where(
                DeviceConfigBackupTarget.id == target.id,
                or_(
                    DeviceConfigBackupTarget.lease_until.is_(None),
                    DeviceConfigBackupTarget.lease_until < now,
                ),
            )
            .values(lease_until=now + timedelta(seconds=LEASE_SECONDS), lease_token=token)
            .returning(DeviceConfigBackupTarget.id)
        )
        if claimed.first() is None:
            raise CaptureRefused(409, "An export of this device is already running")
        return Claim(target.id, token)

    # ── capture ────────────────────────────────────────────────────────

    async def _export_gateway(self, gw: Any, fmt: str) -> bytes:
        """The ONLY device contact: one read-only export through the adapter."""
        from app.adapters.base import AdapterResult
        from app.adapters.exceptions import AdapterAuthenticationError, AdapterConnectionError
        from app.modules.firewall.gateway_service import GatewayService

        adapter = GatewayService(self.session)._build_adapter(gw)
        try:
            await adapter.connect()
            result = await adapter.download_config()
        except AdapterAuthenticationError:
            raise ExportFailed("auth_failed") from None
        except AdapterConnectionError:
            raise ExportFailed("unreachable") from None
        finally:
            try:
                await adapter.disconnect()
            except Exception:  # noqa: BLE001 - a failed close must not mask the outcome
                logger.debug("Config export adapter close failed")
        if not isinstance(result, AdapterResult) or result.success is not True:
            code = getattr(result, "error_code", None)
            if code in ("NOT_SUPPORTED", "NOT_IMPLEMENTED"):
                raise ExportFailed("unsupported")
            raise ExportFailed("export_failed")
        data = result.data if isinstance(result.data, dict) else {}
        config_xml = data.get("config_xml")
        if fmt == OPNSENSE_XML and isinstance(config_xml, str):
            return config_xml.encode("utf-8")
        backup_data = data.get("backup_data")
        if (
            fmt == OPENWRT_SYSUPGRADE
            and isinstance(backup_data, bytes)
            and data.get("format") == "tar.gz"
        ):
            return backup_data
        raise ExportFailed("invalid_content")

    async def _release(self, target: DeviceConfigBackupTarget, **values: Any) -> None:
        await self.session.execute(
            update(DeviceConfigBackupTarget)
            .where(DeviceConfigBackupTarget.id == target.id)
            .values(lease_until=None, lease_token=None, **values)
        )

    async def capture(
        self,
        claim: Claim,
        *,
        trigger: str = "scheduled",
        user_id: UUID | None = None,
        exporter: Any = None,
    ) -> str:
        """Export once, store if changed. Commits; returns the outcome status.

        ``exporter`` (tests) replaces the device call: ``await exporter(gw, fmt)``.
        """
        from app.modules.firewall.models import GatewayConnection

        target = await self.session.get(
            DeviceConfigBackupTarget, claim.target_id, populate_existing=True
        )
        if target is None or target.lease_token != claim.token:
            return "lease_lost"
        now = datetime.now(UTC)
        fmt = GATEWAY_FORMATS.get(target.vendor) if target.source_kind == SOURCE_GATEWAY else None
        if fmt is None:
            await self._release(
                target, last_attempt_at=now, last_status="unsupported", next_due_at=None
            )
            await self.session.commit()
            return "unsupported"
        gw = (
            await self.session.execute(
                select(GatewayConnection).where(
                    GatewayConnection.id == target.source_id,
                    GatewayConnection.org_id == target.organization_id,
                    GatewayConnection.deleted_at.is_(None),
                    _active_org(GatewayConnection.org_id),
                )
            )
        ).scalar_one_or_none()
        if gw is None:
            await self._release(target, last_status="source_removed", next_due_at=None)
            await self.session.commit()
            return "source_removed"
        if not gw.sync_enabled:
            # The operator paused all polling of this gateway: do not touch it.
            await self._release(
                target,
                last_status="paused",
                next_due_at=next_success_due(now, target.interval_hours),
            )
            await self.session.commit()
            return "paused"
        interval_hours = target.interval_hours
        failures = target.consecutive_failures
        # A scheduled export leaves a gateway the polls found unresponsive alone
        # (its shared breaker is open); an operator's explicit request does not.
        from app.core.device_breaker import CLOSED, gateway_breaker, gateway_key

        if trigger != "manual" and gateway_breaker.peek(gateway_key(gw.id)) != CLOSED:
            return await self._defer(target, "polling paused by the gateway's breaker")
        # One request group per device: never export while the full sync, the
        # health poll, a drift check or a UI read is talking to the box. An
        # operator's request waits briefly; the schedule just comes back later.
        from app.core.config import settings
        from app.core.device_slot import device_slots, gateway_slot_key

        slot_key = gateway_slot_key(gw)
        lease = await device_slots.acquire(
            slot_key,
            "config backup",
            wait=float(settings.DEVICE_UI_READ_MAX_WAIT_SECONDS) if trigger == "manual" else 0.0,
        )
        if lease is None:
            return await self._defer(target, await device_slots.abusy_reason(slot_key))
        try:
            await self.session.execute(
                update(DeviceConfigBackupTarget)
                .where(DeviceConfigBackupTarget.id == target.id)
                .values(last_attempt_at=now)
            )
            # End the transaction before the network round-trip; no row lock or
            # idle-in-transaction connection is held while the device answers.
            await self.session.commit()
            try:
                async with asyncio.timeout(CAPTURE_TIMEOUT_SECONDS):
                    payload = await (exporter or self._export_gateway)(gw, fmt)
                normalized = normalize_export(fmt, payload)
            except ExportFailed as exc:
                return await self._record_failure(target, exc.code, interval_hours, failures)
            except TimeoutError:
                return await self._record_failure(target, "timeout", interval_hours, failures)
            except ConfigFormatError:
                return await self._record_failure(
                    target, "invalid_content", interval_hours, failures
                )
            except Exception as exc:  # noqa: BLE001 - device errors may carry secrets; keep the type only
                logger.warning(
                    "Config export failed for target %s (%s)", target.id, type(exc).__name__
                )
                return await self._record_failure(target, "export_failed", interval_hours, failures)
        finally:
            await device_slots.arelease(lease)
        return await self._store(target, normalized, payload, trigger, user_id)

    async def _defer(self, target: DeviceConfigBackupTarget, reason: str) -> str:
        """Try again in 10-20 minutes; not a failure, nothing was sent."""
        now = datetime.now(UTC)
        await self._release(
            target,
            next_due_at=now + timedelta(seconds=random.uniform(*DEFER_SECONDS)),  # noqa: S311
        )
        await self.session.commit()
        logger.info("Config export of target %s deferred: %s", target.id, reason)
        return "deferred"

    async def _record_failure(
        self, target: DeviceConfigBackupTarget, code: str, interval_hours: int, failures: int
    ) -> str:
        now = datetime.now(UTC)
        await self._release(
            target,
            last_status="failed",
            last_error_code=code,
            consecutive_failures=failures + 1,
            next_due_at=next_failure_due(now, interval_hours, failures + 1),
        )
        await self.session.commit()
        logger.info("Config export of target %s failed: %s", target.id, code)
        return "failed"

    async def _store(
        self,
        target: DeviceConfigBackupTarget,
        normalized: Any,
        payload: bytes,
        trigger: str,
        user_id: UUID | None,
    ) -> str:
        now = datetime.now(UTC)
        digest = content_digest(normalized.identity)
        latest = (
            await self.session.execute(
                select(DeviceConfigSnapshot)
                .where(DeviceConfigSnapshot.target_id == target.id)
                .order_by(DeviceConfigSnapshot.version.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        done = {
            "last_success_at": now,
            "last_error_code": None,
            "consecutive_failures": 0,
            "next_due_at": next_success_due(now, target.interval_hours),
        }
        if latest is not None and latest.content_digest == digest:
            await self._release(target, last_status="unchanged", **done)
            await self.session.commit()
            return "unchanged"
        summary: dict[str, int] | None = None
        if latest is not None:
            try:
                older = render_redacted(latest.format, unseal(latest.ciphertext))
                newer = render_redacted(normalized.format, payload)
                summary = diff_summary(
                    redacted_diff(older, newer, older_label="a", newer_label="b")[0]
                )
            except (SnapshotUnavailable, ConfigFormatError):
                summary = None
        version = (latest.version + 1) if latest is not None else 1
        self.session.add(
            DeviceConfigSnapshot(
                organization_id=target.organization_id,
                site_id=target.site_id,
                target_id=target.id,
                version=version,
                captured_at=now,
                format=normalized.format,
                size_bytes=len(payload),
                content_digest=digest,
                ciphertext=seal(payload),
                trigger=trigger,
                created_by_id=user_id,
                summary=summary,
            )
        )
        await self.session.flush()
        # Retention counts versions, newest kept first; the newest is never pruned.
        keep = max(RETENTION_RANGE[0], target.retention_versions)
        await self.session.execute(
            delete(DeviceConfigSnapshot).where(
                DeviceConfigSnapshot.target_id == target.id,
                DeviceConfigSnapshot.version <= version - keep,
            )
        )
        await self._release(target, last_status="changed", last_changed_at=now, **done)
        await self.session.commit()
        return "changed"

    # ── reads (API) ────────────────────────────────────────────────────

    async def latest_versions(self, target_ids: list[UUID]) -> dict[UUID, tuple[int, datetime]]:
        if not target_ids:
            return {}
        rows = await self.session.execute(
            select(
                DeviceConfigSnapshot.target_id,
                func.max(DeviceConfigSnapshot.version),
                func.max(DeviceConfigSnapshot.captured_at),
            )
            .where(DeviceConfigSnapshot.target_id.in_(target_ids))
            .group_by(DeviceConfigSnapshot.target_id)
        )
        return {row[0]: (row[1], row[2]) for row in rows}

    async def versions(self, target_id: UUID) -> list[DeviceConfigSnapshot]:
        rows = await self.session.execute(
            select(DeviceConfigSnapshot)
            .where(DeviceConfigSnapshot.target_id == target_id)
            .order_by(DeviceConfigSnapshot.version.desc())
        )
        return list(rows.scalars())

    async def snapshot(self, target_id: UUID, version: int) -> DeviceConfigSnapshot | None:
        return (
            await self.session.execute(
                select(DeviceConfigSnapshot).where(
                    DeviceConfigSnapshot.target_id == target_id,
                    DeviceConfigSnapshot.version == version,
                )
            )
        ).scalar_one_or_none()

    async def previous(self, target_id: UUID, version: int) -> DeviceConfigSnapshot | None:
        return (
            await self.session.execute(
                select(DeviceConfigSnapshot)
                .where(
                    DeviceConfigSnapshot.target_id == target_id,
                    DeviceConfigSnapshot.version < version,
                )
                .order_by(DeviceConfigSnapshot.version.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    @staticmethod
    def redacted(snapshot: DeviceConfigSnapshot) -> str:
        return render_redacted(snapshot.format, unseal(snapshot.ciphertext))
