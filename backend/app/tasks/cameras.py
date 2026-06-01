# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Camera Health Polling Tasks
==========================================

Periodic Celery tasks for:
  - Polling camera channel health (bitrate, codec, resolution, FPS)
  - Storing CameraHealthSnapshot records for sparklines & alerting
  - Polling NVR alert streams and ingesting CameraEvent records
"""

import asyncio
import contextlib
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.modules.cameras.event_types import PUSH_ALERT_TYPES, normalize_event_type
from app.tasks.base import async_task

logger = logging.getLogger(__name__)


# =========================================================================
# Camera Health Polling
# =========================================================================


async def _poll_single_nvr_health(nvr_id: UUID) -> dict[str, Any]:
    """
    Poll all cameras attached to a single NVR and store health snapshots.

    For each camera:
      1) Connect to its NVR adapter
      2) Call ``get_channel_track_info(channel)``
      3) Call ``get_channel_status_list()`` for online/offline
      4) Insert a ``CameraHealthSnapshot`` row
    """
    from app.adapters.hikvision.adapter import HikvisionAdapter
    from app.core.crypto import decrypt_credential
    from app.modules.cameras.models import NVR as NVRModel
    from app.modules.cameras.models import Camera, CameraHealthSnapshot

    saved = 0
    errors = 0

    async with AsyncSessionLocal() as session:
        nvr = await session.get(NVRModel, nvr_id)
        if not nvr:
            return {"nvr_id": str(nvr_id), "error": "NVR not found"}

        if not nvr.username or not nvr.password_encrypted:
            return {"nvr_id": str(nvr_id), "error": "NVR has no credentials"}

        password = decrypt_credential(nvr.password_encrypted)
        adapter = HikvisionAdapter(
            host=nvr.ip_address,
            username=nvr.username,
            password=password,
            port=nvr.port,
        )

        try:
            await adapter.connect()

            # Get channel online/offline map
            channel_status_list = await adapter.get_channel_status_list()
            online_map: dict[int, bool] = {}
            for ch in channel_status_list:
                ch_id = ch.get("id")
                if ch_id is not None:
                    online_map[ch_id] = ch.get("online", False)

            # Load all cameras attached to this NVR
            result = await session.execute(
                select(Camera).where(
                    Camera.nvr_id == nvr_id,
                    Camera.deleted_at.is_(None),
                )
            )
            cameras = result.scalars().all()

            for cam in cameras:
                channel = cam.channel_id or 1
                try:
                    track_info = await adapter.get_channel_track_info(channel=channel)
                    if "error" in track_info:
                        errors += 1
                        continue

                    tracks = track_info.get("tracks", [])
                    main_track = tracks[0] if tracks else {}

                    is_online = online_map.get(channel, True)

                    snapshot = CameraHealthSnapshot(
                        organization_id=nvr.organization_id,
                        camera_id=cam.id,
                        captured_at=datetime.now(UTC),
                        bitrate_kbps=main_track.get("bitrate_kbps"),
                        frame_rate=main_track.get("frame_rate"),
                        codec=main_track.get("codec"),
                        resolution_width=main_track.get("resolution_width"),
                        resolution_height=main_track.get("resolution_height"),
                        is_online=is_online,
                    )
                    session.add(snapshot)
                    saved += 1
                except Exception as exc:
                    logger.warning(
                        "Health poll failed for camera %s (ch %s): %s",
                        cam.id,
                        channel,
                        exc,
                    )
                    errors += 1

            await session.commit()

        except Exception as exc:
            logger.error("Failed to poll NVR %s: %s", nvr_id, exc)
            return {"nvr_id": str(nvr_id), "error": "Health poll failed", "saved": 0, "errors": 1}
        finally:
            await adapter.disconnect()

    return {"nvr_id": str(nvr_id), "saved": saved, "errors": errors}


async def _poll_all_camera_health() -> dict[str, Any]:
    """
    Iterate every NVR and poll health for all attached cameras.
    """
    from app.modules.cameras.models import NVR as NVRModel

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(NVRModel.id).where(
                NVRModel.deleted_at.is_(None),
            )
        )
        nvr_ids = [row[0] for row in result.all()]

    # Poll NVRs concurrently (bounded to avoid overload)
    sem = asyncio.Semaphore(4)

    async def _bounded_poll(nid: UUID) -> dict[str, Any]:
        async with sem:
            try:
                return await _poll_single_nvr_health(nid)
            except Exception as exc:
                logger.error("Health poll error for NVR %s: %s", nid, exc)
                return {"nvr_id": str(nid), "error": "Health poll failed", "saved": 0, "errors": 1}

    results = await asyncio.gather(
        *[_bounded_poll(nid) for nid in nvr_ids],
        return_exceptions=True,
    )

    # Log any unexpected exceptions from gather
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            logger.error("Unexpected error polling NVR %s: %s", nvr_ids[i], r)
            results[i] = {
                "nvr_id": str(nvr_ids[i]),
                "error": "Unexpected poll failure",
                "saved": 0,
                "errors": 1,
            }

    total_saved = sum(r.get("saved", 0) for r in results if isinstance(r, dict))
    total_errors = sum(r.get("errors", 0) for r in results if isinstance(r, dict))
    logger.info(
        "Camera health poll complete: %d NVRs, %d snapshots saved, %d errors",
        len(nvr_ids),
        total_saved,
        total_errors,
    )
    return {
        "nvrs_polled": len(nvr_ids),
        "snapshots_saved": total_saved,
        "errors": total_errors,
        "details": results,
    }


@celery_app.task(  # type: ignore[untyped-decorator]
    name="cameras.poll_camera_health",
    bind=True,
    max_retries=1,
    soft_time_limit=120,
    time_limit=180,
)
@async_task
async def poll_camera_health(self: Any) -> dict[str, Any]:
    """
    Periodic task: poll health metrics for all NVR-attached cameras.
    Runs every 60 seconds via beat_schedule.
    """
    return await _poll_all_camera_health()


# =========================================================================
# Health Snapshot Cleanup
# =========================================================================


async def _cleanup_old_health_snapshots(max_age_hours: int = 72) -> int:
    """Delete health snapshots older than ``max_age_hours``."""
    from datetime import timedelta

    from sqlalchemy import delete

    from app.modules.cameras.models import CameraHealthSnapshot

    cutoff = datetime.now(UTC) - timedelta(hours=max_age_hours)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            delete(CameraHealthSnapshot).where(
                CameraHealthSnapshot.captured_at < cutoff,
            )
        )
        await session.commit()
        deleted: int = result.rowcount  # type: ignore[attr-defined]
        logger.info("Cleaned up %d old health snapshots (older than %dh)", deleted, max_age_hours)
        return deleted


@celery_app.task(  # type: ignore[untyped-decorator]
    name="cameras.cleanup_health_snapshots",
    bind=True,
    max_retries=1,
    soft_time_limit=60,
    time_limit=120,
)
@async_task
async def cleanup_health_snapshots(self: Any) -> dict[str, Any]:
    """Remove health snapshots older than 72 hours (daily)."""
    deleted = await _cleanup_old_health_snapshots(max_age_hours=72)
    return {"deleted": deleted}


async def _cleanup_old_camera_events(max_age_days: int = 90) -> int:
    """Delete camera events older than ``max_age_days``.

    The cameras.camera_events table grows unbounded as NVRs stream alerts; the
    platform-level cleanup_old_events task only prunes the analytics EventRecord
    table, not this one. Bound it here (default 90d retention) to avoid Postgres
    bloat and to satisfy data-minimisation requirements.
    """
    from datetime import timedelta

    from sqlalchemy import delete

    from app.modules.cameras.models import CameraEvent

    cutoff = datetime.now(UTC) - timedelta(days=max_age_days)

    async with AsyncSessionLocal() as session:
        result = await session.execute(delete(CameraEvent).where(CameraEvent.timestamp < cutoff))
        await session.commit()
        deleted: int = result.rowcount  # type: ignore[attr-defined]
        logger.info("Cleaned up %d camera events older than %dd", deleted, max_age_days)
        return deleted


@celery_app.task(  # type: ignore[untyped-decorator]
    name="cameras.cleanup_camera_events",
    bind=True,
    max_retries=1,
    soft_time_limit=120,
    time_limit=180,
)
@async_task
async def cleanup_camera_events(self: Any) -> dict[str, Any]:
    """Remove camera events older than the retention window (daily)."""
    from app.core.config import settings

    days = int(getattr(settings, "CAMERA_EVENT_RETENTION_DAYS", 90) or 90)
    deleted = await _cleanup_old_camera_events(max_age_days=days)
    return {"deleted": deleted}


# =========================================================================
# Evidence Archive (legal hold) — copy a clip off the NVR to durable storage
# =========================================================================


async def _archive_evidence(archive_id: UUID) -> dict[str, Any]:
    """Export the held time-window off the NVR to EVIDENCE_DIR, hashing as we go,
    and stamp the EvidenceArchive row ready/failed. Runs in a Celery worker."""
    import hashlib
    import os

    from sqlalchemy.orm.exc import StaleDataError

    from app.adapters.hikvision.adapter import HikvisionAdapter
    from app.core.config import settings
    from app.core.crypto import decrypt_credential
    from app.modules.cameras.models import NVR as NVRModel
    from app.modules.cameras.models import Camera, EvidenceArchive

    async with AsyncSessionLocal() as session:
        arch = await session.get(EvidenceArchive, archive_id)
        if arch is None:
            return {"archive_id": str(archive_id), "error": "not found"}
        cam = await session.get(Camera, arch.camera_id)
        nvr = await session.get(NVRModel, cam.nvr_id) if cam and cam.nvr_id else None
        if cam is None or nvr is None or not nvr.password_encrypted:
            arch.status = "failed"
            arch.error = "camera/NVR not found or missing credentials"
            await session.commit()
            return {"archive_id": str(archive_id), "status": "failed"}

        arch.status = "archiving"
        await session.commit()

        os.makedirs(settings.EVIDENCE_DIR, exist_ok=True)
        path = os.path.join(settings.EVIDENCE_DIR, f"{archive_id}.mp4")
        sha = hashlib.sha256()
        size = 0
        adapter = HikvisionAdapter(
            host=nvr.ip_address,
            username=nvr.username,
            password=decrypt_credential(nvr.password_encrypted),
            port=nvr.port,
        )
        ch = cam.channel_id or 1
        start_iso = arch.start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = arch.end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        cancelled = False
        try:
            await adapter.connect()
            with open(path, "wb") as f:
                if arch.watermarked:
                    overlay = (
                        f"{arch.camera_name or cam.name}  EVIDENCE "
                        f"{datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}  id {str(archive_id)[:8]}"
                    )
                    gen = adapter.stream_clip_watermarked(
                        channel=ch, start_iso=start_iso, end_iso=end_iso, overlay_text=overlay
                    )
                else:
                    gen = adapter.stream_video_clip(
                        playback_uri=f"rtsp://0.0.0.0/Streaming/tracks/{ch}01",
                        start_time=start_iso,
                        end_time=end_iso,
                    )
                async for chunk in gen:
                    f.write(chunk)
                    sha.update(chunk)
                    size += len(chunk)
            if size < 1024:
                raise RuntimeError("export produced no decodable footage for this window")
            arch.status = "ready"
            arch.file_path = path
            arch.file_size = size
            arch.sha256 = sha.hexdigest()
            arch.completed_at = datetime.now(UTC)
        except Exception as exc:
            logger.warning("Evidence archive %s failed: %s", archive_id, exc)
            arch.status = "failed"
            arch.error = str(exc)[:500]
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()
            # The row may have been deleted concurrently (e.g. an operator DELETEd
            # it while it was still 'pending', before the status guard could see
            # 'archiving'). Committing a dirty-but-deleted row raises StaleDataError
            # (UPDATE matched 0 rows). Tolerate it: roll back and clean the partial
            # file so neither the task crashes nor the file leaks.
            try:
                await session.commit()
            except StaleDataError:
                await session.rollback()
                with contextlib.suppress(OSError):
                    if os.path.exists(path):
                        os.remove(path)
                logger.info(
                    "Evidence archive %s row vanished during export — cleaned partial file",
                    archive_id,
                )
                cancelled = True
        # Return AFTER the finally (PEP 765): a `return` inside a `finally` would
        # swallow a propagating exception (e.g. task CancelledError) if commit()
        # also raised, so we hoist it out and branch on the flag instead.
        if cancelled:
            return {"archive_id": str(archive_id), "status": "cancelled", "bytes": 0}
        return {"archive_id": str(archive_id), "status": arch.status, "bytes": size}


@celery_app.task(  # type: ignore[untyped-decorator]
    name="cameras.archive_evidence",
    bind=True,
    max_retries=0,
    soft_time_limit=4 * 3600 + 120,
    time_limit=4 * 3600 + 300,
)
@async_task
async def archive_evidence(self: Any, archive_id: str) -> dict[str, Any]:
    """Export + persist + hash a legal-hold clip (dispatched on demand)."""
    return await _archive_evidence(UUID(archive_id))


# =========================================================================
# NVR Alert Stream Ingestion
# =========================================================================

# Smart-detection alert types that warrant a push/dispatch live the canonical
# taxonomy in event_types.py (motion/video-loss are too chatty to push — they
# stay queryable in the Review feed). Raw vendor strings are normalized into the
# canonical set at ingest, so the dispatch gate, the Fabric event catalog, and
# the frontend all agree (and Hikvision's ``linedetection`` is finally
# recognized as line crossing instead of being silently dropped).
_PUSH_ALERT_TYPES = PUSH_ALERT_TYPES


def _alert_dedup_key(camera_id: Any, event_type: str, ts: datetime) -> tuple[Any, str, datetime]:
    """Stable identity for one physical alert, used to suppress the duplicates the
    NVR's alertStream re-returns on every poll. The timestamp is normalized to
    naive-UTC truncated to whole seconds so a tz-aware re-read and the original
    (Hikvision dateTime is second-precision) collapse to the same key.
    """
    t = ts.astimezone(UTC).replace(tzinfo=None) if ts.tzinfo is not None else ts
    return (camera_id, event_type, t.replace(microsecond=0))


async def _maybe_push_alerts(session: Any, nvr: Any, alert_count: int, sample: str | None) -> None:
    """Fan a single summary push out to the NVR's org when smart-detection
    alerts were just ingested. Never raises into the ingestion path; a no-op
    when push is unconfigured."""
    if alert_count <= 0:
        return
    try:
        from app.modules.cameras.push_service import PushService, push_enabled

        if not push_enabled():
            return
        nvr_name = getattr(nvr, "name", None) or "an NVR"
        plural = "s" if alert_count != 1 else ""
        # Scope the fan-out to users who may access the NVR's site: a
        # site-limited operator without a grant for this site must NOT receive a
        # push referencing a sibling-site camera. ``site_id=None`` (NVR with no
        # site) preserves the legacy org-wide fan.
        await PushService(session).send_to_org(
            nvr.organization_id,
            {
                "title": f"FreeSDN — {alert_count} camera alert{plural}",
                "body": f"{(sample or 'Alert').replace('_', ' ').title()} on {nvr_name}",
                "url": "/cameras/events",
                "tag": "freesdn-camera-alerts",
            },
            site_id=getattr(nvr, "site_id", None),
        )
    except Exception as exc:  # pragma: no cover - dispatch must never break ingest
        logger.warning("Alert push dispatch failed for NVR %s: %s", getattr(nvr, "id", "?"), exc)


async def _dispatch_alerts(session: Any, nvr: Any, alerts: list[dict[str, Any]]) -> None:
    """Route freshly-ingested smart-detection alerts through the platform's
    notification fabric (the camera_events row is already persisted):

      1. Publish each as a first-class SECURITY event on the event bus. This is
         the integration point that feeds the AUTOMATION ENGINE (operators route
         to email / webhook / Slack / Teams / SIEM via automation rules), the
         WebSocket live feed, and plugins — i.e. alerts reach people through the
         same fabric the rest of the platform uses, not just browser push.
      2. Create an in-app notification (one summary) for the org's active users
         so there's a zero-config bell even without an automation rule.
      3. Browser WebPush (existing) for subscribed devices.

    Best-effort throughout — a dispatch failure must never break ingestion.
    """
    if not alerts:
        return
    org_id = nvr.organization_id
    nvr_name = getattr(nvr, "name", None) or "an NVR"

    # 1) Event bus → automation rules (email/webhook/Slack/SIEM), live WS, plugins.
    #    AND persist each to the platform EventRecord store (LogDB) so camera
    #    alerts show up in the org-wide Events analytics + Log Explorer the same
    #    way every other subsystem's events do — not just on the live bus.
    nvr_site_id = getattr(nvr, "site_id", None)
    try:
        from app.core.events import Event, EventCategory, EventPriority, get_event_bus

        bus = get_event_bus()

        # Try to open a LogDB session for durable persistence. If LogDB isn't
        # configured we still publish to the bus (degrade gracefully).
        logdb_ctx = None
        try:
            from app.db.session import get_logdb_celery_factory

            logdb_ctx = get_logdb_celery_factory()()
        except Exception:
            logdb_ctx = None

        event_service = None
        if logdb_ctx is not None:
            from app.services.event_service import EventService

            log_session = await logdb_ctx.__aenter__()
            event_service = EventService(log_session)

        try:
            events = []
            for a in alerts:
                event = Event(
                    event_type=f"camera.alert.{str(a['event_type']).lower()}",
                    category=EventCategory.SECURITY,
                    priority=EventPriority.HIGH,
                    source="cameras",
                    organization_id=str(org_id) if org_id else None,
                    payload={
                        "camera_id": str(a["camera_id"]),
                        "camera_name": a["camera_name"],
                        "nvr_id": str(getattr(nvr, "id", "")),
                        "nvr_name": nvr_name,
                        # site_id lets the WS per-connection site filter match
                        # camera alerts the same way camera.status.* events do.
                        "site_id": str(nvr_site_id) if nvr_site_id else None,
                        "event_type": a["event_type"],
                        "timestamp": a["timestamp"],
                    },
                )
                events.append(event)
                # Persist (flush) the EventRecord first; do NOT publish yet.
                if event_service is not None:
                    await event_service.persist_event(
                        event, organization_id=org_id, site_id=nvr_site_id
                    )
            # Commit the durable records BEFORE any bus fan-out, so a persistence
            # failure can never leave already-dispatched events unrecorded (the
            # safe direction for a best-effort mirror).
            if event_service is not None:
                await log_session.commit()
            for event in events:
                await bus.publish(event)
        finally:
            if logdb_ctx is not None:
                await logdb_ctx.__aexit__(None, None, None)
    except Exception as exc:  # pragma: no cover - never break ingest
        logger.warning(
            "Camera alert event publish failed for NVR %s: %s", getattr(nvr, "id", "?"), exc
        )

    # 2) In-app notification (one summary) to the org's active users → the bell.
    try:
        from app.models.core import User, UserSiteAccess
        from app.services.notification_helpers import dispatch_notifications

        if org_id is not None:
            base_q = select(User.id).where(
                User.organization_id == org_id,
                User.is_active.is_(True),
                User.deleted_at.is_(None),
            )
            # Scope recipients to users who may access the NVR's site, mirroring
            # CurrentUser.can_access_site: admins, grant-less users, or users
            # granted this site. A site-limited operator without a grant for the
            # camera's site must NOT get the in-app bell for a sibling-site alert.
            # site_id=None (NVR has no site) preserves the legacy org-wide fan.
            if nvr_site_id is not None:
                _ADMIN_ROLES = ("super_admin", "admin", "org_admin")
                # user_ids that have at least one site grant in this org
                granted = (
                    select(UserSiteAccess.user_id)
                    .join(User, User.id == UserSiteAccess.user_id)
                    .where(User.organization_id == org_id)
                    .scalar_subquery()
                )
                # user_ids explicitly granted THIS site
                this_site = (
                    select(UserSiteAccess.user_id)
                    .where(UserSiteAccess.site_id == nvr_site_id)
                    .scalar_subquery()
                )
                base_q = base_q.where(
                    User.role.in_(_ADMIN_ROLES) | User.id.not_in(granted) | User.id.in_(this_site)
                )
            rows = await session.execute(base_q.limit(200))
            user_ids = [str(r[0]) for r in rows.all()]
            if user_ids:
                n = len(alerts)
                sample = alerts[0]
                pretty = str(sample["event_type"]).replace("_", " ").title()
                plural = "s" if n != 1 else ""
                body = f"{pretty} on {sample['camera_name']}" + (
                    f" (+{n - 1} more)" if n > 1 else ""
                )
                await dispatch_notifications(
                    session,
                    {"in_app": {"user_ids": user_ids}},
                    f"{n} camera alert{plural}",
                    body,
                    organization_id=org_id,
                )
    except Exception as exc:  # pragma: no cover - never break ingest
        logger.warning(
            "Camera alert in-app notify failed for NVR %s: %s", getattr(nvr, "id", "?"), exc
        )

    # 3) Browser WebPush (existing).
    await _maybe_push_alerts(session, nvr, len(alerts), alerts[0]["event_type"])


async def _ingest_nvr_alerts(nvr_id: UUID) -> dict[str, Any]:
    """
    Poll a single NVR's alert stream and store new CameraEvent records.
    Uses short-timeout ``get_event_state()`` to fetch any buffered events.
    """
    from app.adapters.hikvision.adapter import HikvisionAdapter
    from app.core.crypto import decrypt_credential
    from app.modules.cameras.models import NVR as NVRModel
    from app.modules.cameras.models import Camera, CameraEvent

    ingested = 0

    async with AsyncSessionLocal() as session:
        nvr = await session.get(NVRModel, nvr_id)
        if not nvr or not nvr.username or not nvr.password_encrypted:
            return {"nvr_id": str(nvr_id), "ingested": 0, "error": "NVR not found or no creds"}

        password = decrypt_credential(nvr.password_encrypted)
        adapter = HikvisionAdapter(
            host=nvr.ip_address,
            username=nvr.username,
            password=password,
            port=nvr.port,
        )

        try:
            await adapter.connect()
            event_state = await adapter.get_event_state()

            if "error" in event_state:
                return {"nvr_id": str(nvr_id), "ingested": 0, "error": event_state["error"]}

            raw_events = event_state.get("events", [])
            if not raw_events:
                return {"nvr_id": str(nvr_id), "ingested": 0}

            # Build channel → camera mapping (id + name for alert payloads)
            result = await session.execute(
                select(Camera.id, Camera.channel_id, Camera.name).where(
                    Camera.nvr_id == nvr_id,
                    Camera.deleted_at.is_(None),
                )
            )
            ch_to_camera: dict[int, UUID] = {}
            camera_names: dict[UUID, str] = {}
            for cam_id, ch_id, cam_name in result.all():
                if ch_id:
                    ch_to_camera[ch_id] = cam_id
                camera_names[cam_id] = cam_name or "Camera"

            # ── parse raw events into candidates ────────────────────────────
            # The alertStream long-poll returns whatever is CURRENTLY buffered on
            # the NVR, so consecutive 30s polls re-return the same physical event.
            # We dedup on (camera_id, canonical event_type, second-truncated ts)
            # against already-stored rows so one real event is stored — and
            # dispatched to the automation Fabric — exactly ONCE (otherwise a
            # single line-crossing would re-fire every connection every poll).
            candidates: list[dict[str, Any]] = []
            for raw in raw_events:
                ch = raw.get("channel_id")
                camera_id = ch_to_camera.get(ch) if ch else None
                if not camera_id:
                    continue  # Unknown channel — skip

                # Normalize the raw vendor eventType into the canonical taxonomy
                # so storage, the dispatch gate, the Fabric catalog and the UI all
                # agree (e.g. Hikvision's ``linedetection`` -> ``line_cross``). The
                # original device string is preserved in metadata for fidelity.
                raw_event_type = raw.get("event_type", "unknown")
                event_type = normalize_event_type(raw_event_type)
                dt_str = raw.get("date_time", "")
                try:
                    ts = datetime.fromisoformat(dt_str) if dt_str else datetime.now(UTC)
                except (ValueError, TypeError):
                    ts = datetime.now(UTC)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                candidates.append(
                    {
                        "ch": ch,
                        "camera_id": camera_id,
                        "event_type": event_type,
                        "raw_event_type": raw_event_type,
                        "ts": ts,
                        "raw": raw,
                    }
                )

            # ── dedup against already-stored rows (bounded time-window query) ──
            seen: set[tuple[UUID, str, datetime]] = set()
            if candidates:
                cam_ids = {c["camera_id"] for c in candidates}
                tss = [c["ts"] for c in candidates]
                existing = await session.execute(
                    select(
                        CameraEvent.camera_id, CameraEvent.event_type, CameraEvent.timestamp
                    ).where(
                        CameraEvent.camera_id.in_(cam_ids),
                        CameraEvent.timestamp >= min(tss) - timedelta(seconds=1),
                        CameraEvent.timestamp <= max(tss) + timedelta(seconds=1),
                    )
                )
                for cam_e, et_e, ts_e in existing.all():
                    seen.add(_alert_dedup_key(cam_e, et_e, ts_e))

            alert_details: list[dict[str, Any]] = []
            skipped_dup = 0
            for c in candidates:
                key = _alert_dedup_key(c["camera_id"], c["event_type"], c["ts"])
                if key in seen:
                    skipped_dup += 1
                    continue  # already stored (re-returned by a prior poll)
                seen.add(key)  # also dedups repeats WITHIN this poll batch

                if c["event_type"] in _PUSH_ALERT_TYPES:
                    alert_details.append(
                        {
                            "event_type": c["event_type"],
                            "camera_id": c["camera_id"],
                            "camera_name": camera_names.get(c["camera_id"], "Camera"),
                            "timestamp": c["ts"].isoformat(),
                        }
                    )

                session.add(
                    CameraEvent(
                        organization_id=nvr.organization_id,
                        camera_id=c["camera_id"],
                        event_type=c["event_type"],
                        timestamp=c["ts"],
                        description=c["raw"].get("event_description", ""),
                        metadata_json={
                            "event_state": c["raw"].get("event_state", ""),
                            "channel_id": c["ch"],
                            "active_post_count": c["raw"].get("active_post_count"),
                            "source": "alertStream",
                            # Preserve the device-native eventType so we never lose
                            # vendor fidelity after canonical normalization.
                            "raw_event_type": c["raw_event_type"],
                            # Object class when the NVR classifies it (AcuSense); "" otherwise.
                            "target_type": c["raw"].get("target_type", ""),
                        },
                    )
                )
                ingested += 1

            if skipped_dup:
                logger.debug(
                    "NVR %s alert ingest: %d new, %d duplicate(s) skipped",
                    nvr_id,
                    ingested,
                    skipped_dup,
                )
            if ingested:
                await session.commit()
                await _dispatch_alerts(session, nvr, alert_details)

        except Exception as exc:
            logger.error("Alert ingestion failed for NVR %s: %s", nvr_id, exc)
            return {"nvr_id": str(nvr_id), "ingested": 0, "error": "Alert ingestion failed"}
        finally:
            await adapter.disconnect()

    return {"nvr_id": str(nvr_id), "ingested": ingested}


async def _ingest_all_nvr_alerts() -> dict[str, Any]:
    """Poll alert streams for all NVRs."""
    from app.modules.cameras.models import NVR as NVRModel

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(NVRModel.id).where(NVRModel.deleted_at.is_(None)))
        nvr_ids = [row[0] for row in result.all()]

    # Ingest alerts from NVRs concurrently (bounded)
    sem = asyncio.Semaphore(4)

    async def _bounded_ingest(nid: UUID) -> dict[str, Any]:
        async with sem:
            try:
                return await _ingest_nvr_alerts(nid)
            except Exception as exc:
                logger.error("Alert ingestion error for NVR %s: %s", nid, exc)
                return {"nvr_id": str(nid), "error": "Alert ingestion failed", "ingested": 0}

    results = await asyncio.gather(
        *[_bounded_ingest(nid) for nid in nvr_ids],
        return_exceptions=True,
    )

    # Log any unexpected exceptions from gather
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            logger.error("Unexpected error ingesting alerts for NVR %s: %s", nvr_ids[i], r)
            results[i] = {
                "nvr_id": str(nvr_ids[i]),
                "error": "Unexpected ingestion failure",
                "ingested": 0,
            }

    total_ingested = sum(r.get("ingested", 0) for r in results if isinstance(r, dict))

    logger.info(
        "Alert ingestion complete: %d NVRs, %d events ingested",
        len(nvr_ids),
        total_ingested,
    )
    return {
        "nvrs_polled": len(nvr_ids),
        "events_ingested": total_ingested,
        "details": results,
    }


@celery_app.task(  # type: ignore[untyped-decorator]
    name="cameras.ingest_nvr_alerts",
    bind=True,
    max_retries=1,
    soft_time_limit=60,
    time_limit=120,
)
@async_task
async def ingest_nvr_alerts(self: Any) -> dict[str, Any]:
    """
    Periodic task: poll alert streams from all NVRs and store CameraEvent records.
    Runs every 30 seconds via beat_schedule.
    """
    return await _ingest_all_nvr_alerts()


# =========================================================================
# HLS Session Cleanup
# =========================================================================


@celery_app.task(  # type: ignore[untyped-decorator]
    name="cameras.cleanup_hls_sessions",
    bind=True,
    max_retries=1,
    soft_time_limit=30,
    time_limit=60,
)
@async_task
async def cleanup_hls_sessions(self: Any) -> dict[str, Any]:
    """No-op: HLS sessions live in HLSStreamService._sessions, a per-process
    in-memory ClassVar in the API (uvicorn) process. This task runs in the
    Celery WORKER process, where that dict is always empty — so it could never
    reap a real session. The real reaper now runs in-process in the
    API lifespan (app/main.py). Kept as a harmless no-op so the existing beat
    schedule entry doesn't error; remove both once HLS state moves to a shared
    store (e.g. Redis) that both processes can see."""
    return {"cleaned": 0, "note": "no-op: HLS reaping moved in-process to the API"}


# =========================================================================
# Daily Camera Report
# =========================================================================


async def _generate_daily_report() -> dict[str, Any]:
    """
    Generate a daily summary report for each organisation that has cameras.

    For every org the report contains:
      - total cameras
      - online cameras (last_seen within 5 min)
      - total events in the last 24 h
      - uptime % derived from health snapshots in the period
    """
    from app.modules.cameras.models import (
        Camera,
        CameraEvent,
        CameraHealthSnapshot,
        CameraReport,
    )

    now = datetime.now(UTC)
    period_start = now - timedelta(hours=24)
    online_cutoff = now - timedelta(minutes=5)

    reports_created = 0
    errors = 0

    async with AsyncSessionLocal() as session:
        # Find all organisations that own at least one camera
        org_q = (
            select(Camera.organization_id)
            .where(Camera.deleted_at.is_(None))
            .group_by(Camera.organization_id)
        )
        org_result = await session.execute(org_q)
        org_ids = [row[0] for row in org_result.all()]

        for org_id in org_ids:
            try:
                # Check if a report already exists for this org and period
                existing = await session.execute(
                    select(func.count())
                    .select_from(CameraReport)
                    .where(
                        CameraReport.organization_id == org_id,
                        CameraReport.report_type == "daily_summary",
                        CameraReport.period_start >= period_start,
                    )
                )
                if (existing.scalar() or 0) > 0:
                    continue

                # Total cameras
                total_q = (
                    select(func.count())
                    .select_from(Camera)
                    .where(
                        Camera.organization_id == org_id,
                        Camera.deleted_at.is_(None),
                    )
                )
                total_cameras: int = (await session.execute(total_q)).scalar_one()

                # Online cameras (last_seen within 5 min)
                online_q = (
                    select(func.count())
                    .select_from(Camera)
                    .where(
                        Camera.organization_id == org_id,
                        Camera.deleted_at.is_(None),
                        Camera.last_seen >= online_cutoff,
                    )
                )
                online_cameras: int = (await session.execute(online_q)).scalar_one()

                # Events in last 24 h
                events_q = (
                    select(func.count())
                    .select_from(CameraEvent)
                    .where(
                        CameraEvent.organization_id == org_id,
                        CameraEvent.timestamp >= period_start,
                    )
                )
                total_events: int = (await session.execute(events_q)).scalar_one()

                # Uptime % from health snapshots in period
                total_snapshots_q = (
                    select(func.count())
                    .select_from(CameraHealthSnapshot)
                    .where(
                        CameraHealthSnapshot.organization_id == org_id,
                        CameraHealthSnapshot.captured_at >= period_start,
                    )
                )
                total_snapshots: int = (await session.execute(total_snapshots_q)).scalar_one()

                online_snapshots_q = (
                    select(func.count())
                    .select_from(CameraHealthSnapshot)
                    .where(
                        CameraHealthSnapshot.organization_id == org_id,
                        CameraHealthSnapshot.captured_at >= period_start,
                        CameraHealthSnapshot.is_online.is_(True),
                    )
                )
                online_snapshots: int = (await session.execute(online_snapshots_q)).scalar_one()

                uptime_pct = round(
                    (online_snapshots / total_snapshots * 100) if total_snapshots > 0 else 0.0,
                    2,
                )

                report = CameraReport(
                    organization_id=org_id,
                    report_type="daily_summary",
                    period_start=period_start,
                    period_end=now,
                    data={
                        "total_cameras": total_cameras,
                        "online_cameras": online_cameras,
                        "total_events": total_events,
                        "uptime_pct": uptime_pct,
                        "total_snapshots": total_snapshots,
                        "online_snapshots": online_snapshots,
                    },
                )
                session.add(report)
                await session.commit()
                reports_created += 1
            except Exception as exc:
                await session.rollback()
                logger.warning("Daily report failed for org %s: %s", org_id, type(exc).__name__)
                errors += 1

    logger.info(
        "Daily camera reports generated for %d organisations (%d errors)", reports_created, errors
    )
    return {"reports_created": reports_created, "errors": errors}


@celery_app.task(  # type: ignore[untyped-decorator]
    name="cameras.generate_daily_report",
    bind=True,
    max_retries=1,
    soft_time_limit=120,
    time_limit=180,
)
@async_task
async def generate_daily_report(self: Any) -> dict[str, Any]:
    """Generate daily camera summary reports for all organisations."""
    return await _generate_daily_report()


# =========================================================================
# AI Scene Labeling
# =========================================================================


async def _label_camera_scenes() -> dict[str, Any]:
    """
    Run AI scene analysis on cameras that haven't been labeled in the
    last 7 days (or have never been labeled).
    """
    from app.modules.cameras.models import Camera
    from app.modules.cameras.service import SceneLabelingService

    cutoff = datetime.now(UTC) - timedelta(days=7)
    labeled = 0
    errors = 0

    async with AsyncSessionLocal() as session:
        # Fetch active cameras (limit to 200 per run to prevent OOM)
        result = await session.execute(select(Camera).where(Camera.deleted_at.is_(None)).limit(200))
        cameras = result.scalars().all()

        svc = SceneLabelingService(session)

        for cam in cameras:
            # Check if scene labels are recent enough
            settings = cam.settings or {}
            scene_labels = settings.get("scene_labels", {})
            analyzed_at_str = scene_labels.get("analyzed_at")
            if analyzed_at_str:
                try:
                    analyzed_at = datetime.fromisoformat(analyzed_at_str)
                    if analyzed_at.tzinfo is None:
                        analyzed_at = analyzed_at.replace(tzinfo=UTC)
                    if analyzed_at >= cutoff:
                        continue  # Still fresh — skip
                except (ValueError, TypeError):
                    pass  # Invalid date — re-analyze

            try:
                await svc.analyze_scene(
                    camera_id=cam.id,
                    organization_id=cam.organization_id,
                )
                labeled += 1
            except Exception as exc:
                logger.warning(
                    "Scene labeling failed for camera %s: %s", cam.id, type(exc).__name__
                )
                errors += 1

    logger.info("Scene labeling complete: %d labeled, %d errors", labeled, errors)
    return {"labeled": labeled, "errors": errors}


@celery_app.task(  # type: ignore[untyped-decorator]
    name="cameras.label_camera_scenes",
    bind=True,
    max_retries=1,
    soft_time_limit=300,
    time_limit=600,
)
@async_task
async def label_camera_scenes(self: Any) -> dict[str, Any]:
    """Label camera scenes using AI vision for cameras not labeled in 7 days."""
    return await _label_camera_scenes()
