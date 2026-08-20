# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Cameras Module Service
====================================

Business logic for camera management and streaming.
"""

import asyncio
import contextlib
import json
import logging
import os
import re
import shutil
from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
)
from app.core.crypto import decrypt_credential
from app.core.events import Event, EventCategory, EventPriority, get_event_bus

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================


class CameraError(Exception):
    """Base camera error."""

    pass


class StreamError(CameraError):
    """Streaming error."""

    pass


class RecordingError(CameraError):
    """Recording error."""

    pass


class CameraNotFoundError(CameraError):
    """Camera not found."""

    def __init__(self, camera_id: UUID):
        super().__init__(f"Camera not found: {camera_id}")


def _sanitize_url(url: str) -> str:
    """Strip credentials from URLs for safe logging."""
    return re.sub(r"://[^@]+@", "://***:***@", url)


def _validate_url_not_internal(url: str, label: str = "URL") -> None:
    """Block requests to private/internal networks (SSRF prevention)."""
    import ipaddress
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise CameraError(f"{label} must not target localhost")
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise CameraError(f"{label} must not target private networks")
    except ValueError:
        pass  # Domain name — allow


# =============================================================================
# Camera Service
# =============================================================================


class CameraService:
    """Service for camera management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    def _base_camera_filter(
        self,
        site_id: UUID | None = None,
        nvr_id: UUID | None = None,
        status: str | None = None,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | None = None,
        search: str | None = None,
        vendor: str | None = None,
    ) -> Any:
        """Build reusable WHERE clause for camera listing."""
        from sqlalchemy import or_

        from app.modules.cameras.models import Camera

        query = select(Camera).where(Camera.deleted_at.is_(None))
        if organization_id:
            query = query.where(Camera.organization_id == organization_id)
        if site_id:
            query = query.where(Camera.site_id == site_id)
        if nvr_id:
            query = query.where(Camera.nvr_id == nvr_id)
        if status:
            query = query.where(Camera.status == status)
        if vendor:
            query = query.where(Camera.vendor == vendor)
        if search:
            # Case-insensitive substring match across the user-facing identity
            # fields. INJ-02: escape LIKE metacharacters (%/_/\) in the
            # user-supplied term so a caller can't inject a wildcard that scans
            # the whole table (DoS) or alters the match.
            from app.core.security_utils import escape_like

            term = f"%{escape_like(search.strip())}%"
            query = query.where(
                or_(
                    Camera.name.ilike(term, escape="\\"),
                    Camera.ip_address.ilike(term, escape="\\"),
                    Camera.location.ilike(term, escape="\\"),
                    Camera.vendor.ilike(term, escape="\\"),
                    Camera.model.ilike(term, escape="\\"),
                )
            )
        # site-limited callers only list cameras in granted sites.
        if accessible_site_ids is not None:
            query = query.where(Camera.site_id.in_(accessible_site_ids))
        return query

    _MAX_LIST_LIMIT = 500

    async def list_cameras(
        self,
        site_id: UUID | None = None,
        nvr_id: UUID | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | None = None,
        search: str | None = None,
        vendor: str | None = None,
    ) -> list[Any]:
        """List cameras with optional filters."""
        limit = max(1, min(limit, self._MAX_LIST_LIMIT))
        offset = max(0, offset)
        query = self._base_camera_filter(
            site_id,
            nvr_id,
            status,
            organization_id,
            accessible_site_ids,
            search=search,
            vendor=vendor,
        )
        query = query.order_by("name").limit(limit).offset(offset)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def attach_nvr_refs(self, cameras: list[Any]) -> list[Any]:
        """Resolve each camera's parent NVR in a single batched query (no N+1).

        ``Camera.nvr`` is ``lazy="raise"`` so it can't be dereferenced during
        serialization. This collects the distinct ``nvr_id`` values across the
        page, fetches the matching NVR rows in one query, and populates the
        ``nvr`` relationship via ``set_committed_value`` — which marks it as
        already-loaded WITHOUT issuing a lazy load or flagging the instance
        dirty — so ``CameraResponse.nvr`` (from_attributes) can read id+name.
        Cameras with no NVR (or whose NVR was soft-deleted) get ``nvr = None``.
        """
        from sqlalchemy.orm.attributes import set_committed_value

        from app.modules.cameras.models import NVR

        nvr_ids = {c.nvr_id for c in cameras if getattr(c, "nvr_id", None) is not None}
        nvr_by_id: dict[UUID, Any] = {}
        if nvr_ids:
            rows = await self.db.execute(
                select(NVR).where(NVR.id.in_(nvr_ids), NVR.deleted_at.is_(None))
            )
            nvr_by_id = {nvr.id: nvr for nvr in rows.scalars().all()}
        for c in cameras:
            nid = getattr(c, "nvr_id", None)
            set_committed_value(c, "nvr", nvr_by_id.get(nid) if nid is not None else None)
        return cameras

    async def count_cameras(
        self,
        site_id: UUID | None = None,
        nvr_id: UUID | None = None,
        status: str | None = None,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | None = None,
        search: str | None = None,
        vendor: str | None = None,
    ) -> int:
        """Return total count for pagination (separate lightweight query).

        Reuses ``_base_camera_filter`` so the count always matches the list under
        the same filters (search/vendor/status/site/nvr).
        """
        base = self._base_camera_filter(
            site_id,
            nvr_id,
            status,
            organization_id,
            accessible_site_ids,
            search=search,
            vendor=vendor,
        )
        q = select(func.count()).select_from(base.subquery())
        result = await self.db.execute(q)
        return result.scalar() or 0

    async def get_fleet_bandwidth(
        self,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> tuple[float, float]:
        """Aggregate the latest health snapshot per ONLINE camera.

        Returns ``(avg_bitrate_kbps, total_bandwidth_kbps)`` over the most-recent
        ``CameraHealthSnapshot.bitrate_kbps`` per online camera. Cameras with no
        snapshot (or a NULL bitrate) are excluded from both the average and the
        sum — an empty fleet yields ``(0.0, 0.0)`` rather than dividing by zero.

        ``accessible_site_ids``: when non-None (site-limited caller), the
        aggregate only spans cameras in granted sites; an empty set is
        fail-closed (``(0.0, 0.0)``) so the fleet bandwidth never sums sibling
        sites (R5 cameras site-grant).
        """
        from app.modules.cameras.models import Camera, CameraHealthSnapshot

        # Latest captured_at per camera (subquery), then join back to pull that
        # row's bitrate. Scope to the org's ONLINE cameras only.
        latest = (
            select(
                CameraHealthSnapshot.camera_id.label("camera_id"),
                func.max(CameraHealthSnapshot.captured_at).label("max_ts"),
            )
            .join(Camera, Camera.id == CameraHealthSnapshot.camera_id)
            .where(
                Camera.deleted_at.is_(None),
                Camera.status == "online",
            )
        )
        if organization_id:
            latest = latest.where(CameraHealthSnapshot.organization_id == organization_id)
        if accessible_site_ids is not None:
            latest = latest.where(Camera.site_id.in_(list(accessible_site_ids)))
        latest = latest.group_by(CameraHealthSnapshot.camera_id).subquery()

        q = (
            select(CameraHealthSnapshot.bitrate_kbps)
            .join(
                latest,
                (CameraHealthSnapshot.camera_id == latest.c.camera_id)
                & (CameraHealthSnapshot.captured_at == latest.c.max_ts),
            )
            .where(CameraHealthSnapshot.bitrate_kbps.isnot(None))
        )
        result = await self.db.execute(q)
        bitrates = [int(b) for b in result.scalars().all() if b is not None]
        if not bitrates:
            return 0.0, 0.0
        total = float(sum(bitrates))
        return total / len(bitrates), total

    async def get_camera(
        self,
        camera_id: UUID,
        organization_id: UUID | None = None,
    ) -> Any:
        """Get a camera by ID, scoped to organization."""
        from app.modules.cameras.models import Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
        )
        if organization_id:
            q = q.where(Camera.organization_id == organization_id)
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()

        if not camera:
            raise CameraNotFoundError(camera_id)

        return camera

    async def create_camera(self, data: dict[str, Any]) -> Any:
        """Create a new camera."""
        from app.modules.cameras.models import Camera

        camera = Camera(**data)
        self.db.add(camera)
        await self.db.commit()
        await self.db.refresh(camera)

        return camera

    async def update_camera(
        self, camera_id: UUID, data: dict[str, Any], *, organization_id: UUID | None = None
    ) -> Any:
        """Update a camera."""
        camera = await self.get_camera(camera_id, organization_id=organization_id)

        # Allowlist of fields that may be updated
        _ALLOWED = {
            "name",
            "description",
            "ip_address",
            "port",
            "camera_type",
            "rtsp_main_stream",
            "rtsp_sub_stream",
            "has_ptz",
            "has_audio",
            "location",
            "floor",
            "status",
            "password_encrypted",
            "username",
            "vendor",
            "model",
            "firmware_version",
            "device_type",
            "motion_detection_enabled",
            "settings",
            "snapshot_url",
        }
        for key, value in data.items():
            if key in _ALLOWED and hasattr(camera, key):
                if key == "port" and value is not None:
                    value = int(value)
                    if not (1 <= value <= 65535):
                        raise CameraError("Port must be between 1 and 65535")
                setattr(camera, key, value)

        await self.db.commit()
        await self.db.refresh(camera)

        return camera

    async def delete_camera(self, camera_id: UUID, *, organization_id: UUID | None = None) -> bool:
        """Soft delete a camera."""
        camera = await self.get_camera(camera_id, organization_id=organization_id)
        camera.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    _VALID_STATUSES = frozenset(
        {"online", "offline", "recording", "error", "unknown", "maintenance"}
    )

    async def update_camera_status(
        self,
        camera_id: UUID,
        status: str,
        last_seen: datetime | None = None,
        organization_id: UUID | None = None,
    ) -> None:
        """Update camera status and publish events on status transitions."""
        if status not in self._VALID_STATUSES:
            raise CameraError(f"Invalid camera status: {status}")
        camera = await self.get_camera(camera_id, organization_id=organization_id)
        previous_status = camera.status
        camera.status = status
        camera.last_seen = last_seen or datetime.now(UTC)
        await self.db.commit()

        # Publish event on status transitions
        if previous_status != status:
            try:
                event_bus = get_event_bus()
                payload = {
                    "camera_id": str(camera.id),
                    "camera_name": camera.name,
                    "site_id": str(camera.site_id) if camera.site_id else None,
                    "organization_id": str(camera.organization_id)
                    if camera.organization_id
                    else None,
                    "previous_status": previous_status,
                    "new_status": status,
                    "location": getattr(camera, "location", None),
                }

                if status in ("offline", "error"):
                    await event_bus.publish(
                        Event(
                            event_type="camera.status.offline",
                            category=EventCategory.DEVICE,
                            priority=EventPriority.HIGH,
                            payload=payload,
                            organization_id=str(camera.organization_id)
                            if camera.organization_id
                            else None,
                        )
                    )
                    logger.info("Camera %s (%s) went %s", camera.name, camera_id, status)
                elif previous_status in ("offline", "error") and status in ("online", "recording"):
                    await event_bus.publish(
                        Event(
                            event_type="camera.status.online",
                            category=EventCategory.DEVICE,
                            priority=EventPriority.NORMAL,
                            payload=payload,
                            organization_id=str(camera.organization_id)
                            if camera.organization_id
                            else None,
                        )
                    )
                    logger.info("Camera %s (%s) came back online", camera.name, camera_id)
            except Exception:
                logger.exception("Failed to publish camera status event for %s", camera_id)

    async def get_camera_stats(
        self,
        site_id: UUID | None = None,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> dict[str, int]:
        """Get camera statistics scoped to organization.

        ``accessible_site_ids``: when non-None (site-limited caller), the
        aggregate counts only span cameras in granted sites; an empty set is
        fail-closed (zero counts) so a site-limited user never sees org-wide
        totals spanning sibling sites (R5 cameras site-grant).
        """
        from app.modules.cameras.models import Camera, CameraStatus

        query = select(Camera.status, func.count(Camera.id)).where(Camera.deleted_at.is_(None))
        if organization_id:
            query = query.where(Camera.organization_id == organization_id)

        if site_id:
            query = query.where(Camera.site_id == site_id)

        if accessible_site_ids is not None:
            query = query.where(Camera.site_id.in_(list(accessible_site_ids)))

        query = query.group_by(Camera.status)

        result = await self.db.execute(query)
        stats: dict[str, int] = dict(result.all())  # type: ignore[arg-type]

        return {
            "total": sum(stats.values()),
            "online": stats.get(CameraStatus.ONLINE.value, 0),
            "offline": stats.get(CameraStatus.OFFLINE.value, 0),
            "recording": stats.get(CameraStatus.RECORDING.value, 0),
            "error": stats.get(CameraStatus.ERROR.value, 0),
        }


# =============================================================================
# Stream Service
# =============================================================================


class StreamService:
    """Service for camera streaming."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_stream_url(
        self,
        camera_id: UUID,
        stream_type: str = "main",
        protocol: str = "rtsp",
        *,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | None = None,
    ) -> str:
        """
        Get streaming URL for a camera.

        Args:
            camera_id: Camera ID
            stream_type: "main" or "sub" stream
            protocol: "rtsp", "hls", or "webrtc"
            organization_id: Scope to organization (tenant isolation)

        Returns:
            Stream URL
        """
        from app.modules.cameras.models import Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
        )
        if organization_id:
            q = q.where(Camera.organization_id == organization_id)
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()

        if not camera:
            raise CameraNotFoundError(camera_id)

        # a site-limited user must not obtain a stream URL
        # (with decrypted RTSP credentials) for a camera in a non-granted site.
        if accessible_site_ids is not None and camera.site_id not in accessible_site_ids:
            raise CameraNotFoundError(camera_id)

        # Return direct RTSP URL with credentials injected at runtime
        if protocol == "rtsp":
            url = camera.rtsp_main_stream
            if stream_type == "sub" and camera.rtsp_sub_stream:
                url = camera.rtsp_sub_stream
            if not url:
                url = f"rtsp://{camera.ip_address}:{camera.port}/stream"
            # Inject credentials into URL at runtime (never stored in DB)
            if camera.username and camera.password_encrypted and "://" in url and "@" not in url:
                from urllib.parse import quote

                pwd = decrypt_credential(camera.password_encrypted)
                url = url.replace(
                    "rtsp://", f"rtsp://{quote(camera.username, safe='')}:{quote(pwd, safe='')}@", 1
                )
            return url

        # For HLS/WebRTC, return proxy URL
        # In production, this would point to a streaming server
        return f"/api/v1/cameras/{camera_id}/stream/{protocol}"

    async def get_snapshot(
        self, camera_id: UUID, organization_id: UUID | None = None
    ) -> bytes | None:
        """
        Get a snapshot from a camera via the appropriate adapter.

        Selects adapter based on camera/NVR vendor:
        - Hikvision: uses ISAPI adapter directly
        - Other vendors (Dahua, Axis, Reolink, etc.): uses ONVIF adapter
        - Unknown vendor: tries ONVIF first, falls back to Hikvision ISAPI

        Returns:
            JPEG image bytes or None
        """
        from app.core.crypto import decrypt_credential
        from app.modules.cameras.models import NVR, Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
        )
        if organization_id:
            q = q.where(Camera.organization_id == organization_id)
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()

        if not camera:
            raise CameraNotFoundError(camera_id)

        # Resolve connection params — use NVR if attached (org-scoped for defense-in-depth)
        nvr = None
        if camera.nvr_id:
            nvr_q = select(NVR).where(NVR.id == camera.nvr_id, NVR.deleted_at.is_(None))
            if camera.organization_id:
                nvr_q = nvr_q.where(NVR.organization_id == camera.organization_id)
            nvr_result = await self.db.execute(nvr_q)
            nvr = nvr_result.scalar_one_or_none()

        host = nvr.ip_address if nvr else camera.ip_address
        port = nvr.port if nvr else (camera.port or 80)
        username = nvr.username if nvr else camera.username
        password_enc = nvr.password_encrypted if nvr else camera.password_encrypted

        if not username or not password_enc:
            raise StreamError("Camera has no stored credentials for snapshot")

        password = decrypt_credential(password_enc)
        channel = camera.channel_id or 1

        vendor = getattr(nvr, "vendor", None) or getattr(camera, "vendor", None) or "onvif"
        adapter = self._create_camera_adapter(
            host=host,
            port=port,
            username=username,
            password=password,
            vendor=vendor,
        )
        snapshot: bytes | None = None
        outcome = "failed"
        try:
            await adapter.connect()
            snapshot = await adapter.get_snapshot(channel=channel)
            outcome = "captured"
            return snapshot
        except Exception as e:
            logger.error("Failed to get snapshot for camera %s: %s", camera_id, e)
            raise StreamError("Failed to get snapshot from camera")
        finally:
            await adapter.disconnect()
            # Platform-citizen event: publish
            # ``camera.snapshot.captured`` (or .failed) on the event bus
            # so the automation engine, WebSocket forwarder, and plugins
            # see snapshot activity the same way they see staged
            # controller changes. Camera + voice adapters bypass
            # AdapterStagingService, so they don't inherit the
            # ``controller.change.*`` event stream — this helper closes
            # the gap.
            try:
                from app.core.events import (
                    EventCategory,
                    EventPriority,
                    publish_adapter_event,
                )

                await publish_adapter_event(
                    f"camera.snapshot.{outcome}",
                    adapter_id=str(vendor or "onvif").lower() or "onvif",
                    organization_id=(
                        str(camera.organization_id) if camera.organization_id else None
                    ),
                    category=EventCategory.DEVICE,
                    priority=EventPriority.NORMAL,
                    camera_id=str(camera_id),
                    channel=channel,
                    bytes_returned=len(snapshot) if snapshot else 0,
                )
            except Exception:
                logger.debug(
                    "snapshot event publish skipped for camera %s",
                    camera_id,
                    exc_info=True,
                )

    @staticmethod
    def _create_camera_adapter(
        host: str,
        port: int,
        username: str,
        password: str,
        vendor: str | None = None,
    ) -> Any:
        """
        Select and instantiate the right camera adapter based on vendor.

        - ``hikvision``: uses HikvisionAdapter (ISAPI protocol)
        - ``unifi`` / ``unifi_protect`` / ``ubiquiti``: uses
          UniFiProtectAdapter (UniFi Protect API on the same UOS host
          that hosts the UniFi Network controller — operator installs
          the Protect app separately).
        - ``onvif`` or any other vendor: uses ONVIFAdapter (ONVIF protocol)
        - ``None``: defaults to ONVIFAdapter (widest compatibility)

        SSRF defense-in-depth: re-validate ``host`` against the canonical
        SSRF block-list on this read path before instantiating any adapter.
        The create/update schemas validate ``ip_address`` on the write path,
        but ONVIFAdapter and UniFiProtectAdapter do not re-check ``host`` in
        their ``__init__`` (only HikvisionAdapter does). A pre-validation row,
        or any future bypass of the write-path validator, would otherwise turn
        the snapshot/playback proxy into an SSRF vector (e.g. reaching
        169.254.169.254). Re-running the same validator here closes that gap
        at a single chokepoint for every vendor. (Private RFC1918 subnets stay
        allowed — cameras/NVRs live on private networks.)
        """
        from app.modules.cameras.schemas import _validate_host_not_ssrf

        try:
            _validate_host_not_ssrf(str(host))
        except ValueError as exc:
            raise CameraError(str(exc)) from exc

        # this read path decrypts the stored camera credential and (for the
        # ONVIF Basic-auth 401 fallback) sends it as plaintext Basic auth to ``host``.
        # Cameras/NVRs live on private networks, so refuse to send the credential to
        # a PUBLIC host — a cameras.manage holder (site_admin) who points ip_address
        # at a public address must not be able to exfiltrate the stored camera secret
        # (sibling of the firewall/credentials/controller stored-secret-egress fix).
        from app.core.security_utils import is_private_ip, resolve_and_pin_host

        try:
            _pinned = resolve_and_pin_host(str(host), allow_private=True)
        except ValueError as exc:
            raise CameraError(str(exc)) from exc
        if not is_private_ip(_pinned):
            raise CameraError(
                f"Camera host {host!r} resolves to a PUBLIC address. Cameras and NVRs "
                "must live on a private/on-prem network — FreeSDN refuses to send the "
                "stored camera credentials to a public-internet host. Set the camera's "
                "IP/host to its on-prem (RFC1918) address."
            )

        vendor_lower = (vendor or "").lower().strip()

        if vendor_lower == "hikvision":
            from app.adapters.hikvision.adapter import HikvisionAdapter

            return HikvisionAdapter(
                host=host,
                username=username,
                password=password,
                port=port,
            )

        # UniFi Protect — runs alongside UniFi Network on the same UOS
        # host. The same credentials work for both apps. Accept any of
        # the common vendor strings.
        if vendor_lower in ("unifi", "unifi_protect", "ubiquiti"):
            from app.adapters.unifi_protect.adapter import (
                UniFiProtectAdapter,
            )

            return UniFiProtectAdapter(
                host=host,
                username=username,
                password=password,
                port=port if port not in (None, 0, 80) else 443,
                verify_ssl=False,
            )

        # For all other vendors (Dahua, Axis, Reolink, Amcrest, etc.)
        # and unknown vendors, use the multi-vendor ONVIF adapter.
        from app.adapters.onvif.adapter import ONVIFAdapter

        return ONVIFAdapter(
            host=host,
            username=username,
            password=password,
            port=port,
        )


# =============================================================================
# Recording Service
# =============================================================================


class RecordingService:
    """Service for managing recordings."""

    _MAX_LIST_LIMIT = 1000

    def __init__(self, db: AsyncSession):
        self.db = db

    async def search_recordings(
        self,
        camera_id: UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        recording_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
        site_id: UUID | None = None,
    ) -> list[Any]:
        """Search for recordings scoped to organization.

        ``accessible_site_ids``: when non-None (site-limited caller), restrict
        results to recordings whose parent Camera's site_id is in the granted
        set.  An empty set is fail-closed — ``Camera.site_id IN ()`` matches no
        rows — so a site-limited user with zero grants never sees sibling-site
        recordings (R5 cameras site-grant).

        ``site_id``: the caller's explicit single-site narrowing (the global
        site selector). Distinct from ``accessible_site_ids``, which is a
        permission ceiling -- this one only narrows further, and is applied
        through the same parent-Camera join, so it can never widen what a
        site-limited caller may reach.
        """
        from app.modules.cameras.models import Camera, Recording

        limit = max(1, min(limit, self._MAX_LIST_LIMIT))
        offset = max(0, offset)

        query = select(Recording)

        # A site-grant restriction is enforced through the parent Camera, so the
        # Camera join must be present even when no org filter is supplied.
        if organization_id or accessible_site_ids is not None or site_id is not None:
            query = query.join(Camera, Recording.camera_id == Camera.id).where(
                Camera.deleted_at.is_(None),
            )
            if organization_id:
                query = query.where(Camera.organization_id == organization_id)
            if accessible_site_ids is not None:
                query = query.where(Camera.site_id.in_(list(accessible_site_ids)))
            if site_id is not None:
                query = query.where(Camera.site_id == site_id)

        if camera_id:
            query = query.where(Recording.camera_id == camera_id)
        if start_time:
            query = query.where(Recording.start_time >= start_time)
        if end_time:
            query = query.where(Recording.end_time <= end_time)
        if recording_type:
            query = query.where(Recording.recording_type == recording_type)

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(Recording.start_time.desc()).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_playback_url(
        self,
        recording_id: UUID,
        protocol: str = "hls",
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> str:
        """Get playback URL for a recording scoped to organization.

        ``accessible_site_ids``: a site-limited caller may only resolve a
        recording whose parent Camera lives in a granted site; an empty set is
        fail-closed (404-equivalent ``RecordingError``) so a sibling-site
        recording is never reachable (R5 cameras site-grant).
        """
        from app.modules.cameras.models import Camera, Recording

        q = select(Recording).where(Recording.id == recording_id)
        if organization_id or accessible_site_ids is not None:
            q = q.join(Camera, Recording.camera_id == Camera.id).where(
                Camera.deleted_at.is_(None),
            )
            if organization_id:
                q = q.where(Camera.organization_id == organization_id)
            if accessible_site_ids is not None:
                q = q.where(Camera.site_id.in_(list(accessible_site_ids)))
        result = await self.db.execute(q)
        recording = result.scalar_one_or_none()

        if not recording:
            raise RecordingError(f"Recording not found: {recording_id}")

        # Return proxy URL for playback
        return f"/api/v1/cameras/recordings/{recording_id}/play/{protocol}"

    async def lock_recording(
        self,
        recording_id: UUID,
        locked: bool = True,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> None:
        """Lock or unlock a recording to prevent deletion.

        ``accessible_site_ids``: a site-limited caller may only (un)lock a
        recording whose parent Camera lives in a granted site; an empty set is
        fail-closed so a sibling-site recording cannot be mutated (R5 cameras
        site-grant).
        """
        from app.modules.cameras.models import Camera, Recording

        q = select(Recording).where(Recording.id == recording_id)
        if organization_id or accessible_site_ids is not None:
            q = q.join(Camera, Recording.camera_id == Camera.id).where(
                Camera.deleted_at.is_(None),
            )
            if organization_id:
                q = q.where(Camera.organization_id == organization_id)
            if accessible_site_ids is not None:
                q = q.where(Camera.site_id.in_(list(accessible_site_ids)))
        result = await self.db.execute(q)
        recording = result.scalar_one_or_none()

        if not recording:
            raise RecordingError(f"Recording not found: {recording_id}")

        recording.is_locked = locked
        await self.db.commit()

    async def get_playback_frame(
        self,
        camera_id: UUID,
        playback_time: datetime,
        organization_id: UUID | None = None,
    ) -> bytes:
        """Grab a single recorded JPEG frame at an absolute playback time.

        Unlike the live snapshot path, this seeks the NVR's stored
        recording to ``playback_time`` and extracts one frame, so the
        multi-camera playback UI shows the *recording* rather than the
        live image.

        Resolves credentials from the parent NVR when attached (the same
        org-scoped resolution the snapshot path uses), then delegates to
        the adapter's ``get_playback_frame``.

        Raises:
            CameraNotFoundError: camera missing or not in the caller's org.
            RecordingError: no credentials, no recorded frame, or the
                adapter has no playback-frame capability.
        """
        from app.modules.cameras.models import NVR, Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
        )
        if organization_id:
            q = q.where(Camera.organization_id == organization_id)
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()
        if not camera:
            raise CameraNotFoundError(camera_id)

        nvr = None
        if camera.nvr_id:
            nvr_q = select(NVR).where(NVR.id == camera.nvr_id, NVR.deleted_at.is_(None))
            if camera.organization_id:
                nvr_q = nvr_q.where(NVR.organization_id == camera.organization_id)
            nvr_result = await self.db.execute(nvr_q)
            nvr = nvr_result.scalar_one_or_none()

        host = nvr.ip_address if nvr else camera.ip_address
        port = nvr.port if nvr else (camera.port or 80)
        username = nvr.username if nvr else camera.username
        password_enc = nvr.password_encrypted if nvr else camera.password_encrypted

        if not username or not password_enc:
            raise RecordingError("Camera has no stored credentials for playback")

        password = decrypt_credential(password_enc)
        channel = camera.channel_id or 1
        vendor = getattr(nvr, "vendor", None) or getattr(camera, "vendor", None) or "onvif"

        adapter = StreamService._create_camera_adapter(
            host=host,
            port=port,
            username=username,
            password=password,
            vendor=vendor,
        )

        grab = getattr(adapter, "get_playback_frame", None)
        if not callable(grab):
            # Honest signal: only the Hikvision adapter implements a
            # time-positioned recording-frame grab today. ONVIF / UniFi
            # Protect have no equivalent ISAPI playback track.
            raise RecordingError(f"Playback frame not supported by the {vendor} adapter")

        # Normalise to UTC ISO so the adapter's parser is unambiguous.
        if playback_time.tzinfo is None:
            playback_time = playback_time.replace(tzinfo=UTC)
        iso = playback_time.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            await adapter.connect()
            return await grab(channel=channel, playback_time=iso)
        except RecordingError:
            raise
        except Exception as e:
            logger.warning(
                "Failed to get playback frame for camera %s at %s: %s",
                camera_id,
                iso,
                e,
            )
            raise RecordingError("No recorded frame at the requested time")
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()


# =============================================================================
# NVR Service
# =============================================================================


class NVRNotFoundError(CameraError):
    """NVR not found."""

    def __init__(self, nvr_id: UUID):
        super().__init__(f"NVR not found: {nvr_id}")


class NVRService:
    """Service for NVR management."""

    _MAX_LIST_LIMIT = 500

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_nvrs(
        self,
        site_id: UUID | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        organization_id: UUID | None = None,
        accessible_site_ids: list[UUID] | None = None,
    ) -> list[Any]:
        """List NVRs with optional filters.

        ``accessible_site_ids``: when non-None (site-limited caller), restrict
        results to NVRs whose site_id is in the provided list.  An empty list
        is fail-closed — returns nothing — so a site-limited user with zero
        grants sees an empty response rather than all NVRs.
        """
        from app.modules.cameras.models import NVR

        limit = max(1, min(limit, self._MAX_LIST_LIMIT))
        offset = max(0, offset)
        query = select(NVR).where(NVR.deleted_at.is_(None))
        if organization_id:
            query = query.where(NVR.organization_id == organization_id)
        if site_id:
            query = query.where(NVR.site_id == site_id)
        if status:
            query = query.where(NVR.status == status)
        if accessible_site_ids is not None:
            # Fail-closed: empty list → NVR.site_id IN () → no rows.
            query = query.where(NVR.site_id.in_(list(accessible_site_ids)))

        query = query.order_by(NVR.name).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def count_nvrs(
        self,
        site_id: UUID | None = None,
        status: str | None = None,
        organization_id: UUID | None = None,
        accessible_site_ids: list[UUID] | None = None,
    ) -> int:
        """Return total NVR count for pagination.

        ``accessible_site_ids``: same fail-closed site-limiting semantics as
        :meth:`list_nvrs`.
        """
        from app.modules.cameras.models import NVR

        q = select(func.count(NVR.id)).where(NVR.deleted_at.is_(None))
        if organization_id:
            q = q.where(NVR.organization_id == organization_id)
        if site_id:
            q = q.where(NVR.site_id == site_id)
        if status:
            q = q.where(NVR.status == status)
        if accessible_site_ids is not None:
            q = q.where(NVR.site_id.in_(list(accessible_site_ids)))
        result = await self.db.execute(q)
        return result.scalar_one()

    async def get_nvr(
        self,
        nvr_id: UUID,
        organization_id: UUID | None = None,
    ) -> Any:
        """Get an NVR by ID, scoped to organization."""
        from app.modules.cameras.models import NVR

        q = select(NVR).where(
            NVR.id == nvr_id,
            NVR.deleted_at.is_(None),
        )
        if organization_id:
            q = q.where(NVR.organization_id == organization_id)
        result = await self.db.execute(q)
        nvr = result.scalar_one_or_none()

        if not nvr:
            raise NVRNotFoundError(nvr_id)

        return nvr

    async def create_nvr(self, data: dict[str, Any]) -> Any:
        """Create a new NVR."""
        from app.modules.cameras.models import NVR

        nvr = NVR(**data)
        self.db.add(nvr)
        await self.db.commit()
        await self.db.refresh(nvr)

        return nvr

    async def update_nvr(
        self, nvr_id: UUID, data: dict[str, Any], *, organization_id: UUID | None = None
    ) -> Any:
        """Update an NVR.

        the create path
        validates ``ip_address`` against the loopback/metadata
        block-list (via the Pydantic validator on
        ``NVRConnectionTestRequest``), but the update path was
        previously letting any value through with only a port-range
        check. A hostile (or compromised) caller could PATCH an NVR
        row to ``169.254.169.254`` and then trick the snapshot proxy
        into reaching cloud metadata. Re-run the same validator here.
        """
        nvr = await self.get_nvr(nvr_id, organization_id=organization_id)

        # Allowlist of fields that may be updated
        _ALLOWED = {
            "name",
            "description",
            "ip_address",
            "port",
            "status",
            "channel_count",
            "username",
            "password_encrypted",
            "vendor",
            "model",
            "firmware_version",
            "serial_number",
            "device_type",
            "mac_address",
            "storage_total_gb",
            "storage_used_gb",
            "last_seen",
            "last_synced_at",
            "settings",
        }
        for key, value in data.items():
            if key in _ALLOWED and hasattr(nvr, key):
                if key == "port" and value is not None:
                    value = int(value)
                    if not (1 <= value <= 65535):
                        raise CameraError("Port must be between 1 and 65535")
                if key == "ip_address" and value:
                    # Re-validate against the SSRF block-list before
                    # the change is persisted.
                    from app.modules.cameras.schemas import (
                        _validate_host_not_ssrf,
                    )

                    try:
                        _validate_host_not_ssrf(str(value))
                    except ValueError as exc:
                        raise CameraError(str(exc)) from exc
                setattr(nvr, key, value)

        await self.db.commit()
        await self.db.refresh(nvr)

        return nvr

    async def delete_nvr(self, nvr_id: UUID, *, organization_id: UUID | None = None) -> bool:
        """Soft-delete an NVR **and** all cameras attached to it.

        Also clears ``external_device_id`` so the same physical NVR can be
        re-imported later without hitting the unique constraint.
        """
        from sqlalchemy import update

        from app.modules.cameras.models import Camera

        nvr = await self.get_nvr(nvr_id, organization_id=organization_id)
        now = datetime.now(UTC)

        # Cascade soft-delete every camera that still belongs to this NVR
        # Defense-in-depth: also scope by org to prevent cross-tenant cascade
        await self.db.execute(
            update(Camera)
            .where(
                Camera.nvr_id == nvr_id,
                Camera.organization_id == nvr.organization_id,
                Camera.deleted_at.is_(None),
            )
            .values(deleted_at=now)
        )

        # Soft-delete the NVR itself and clear external_device_id so
        # a future re-import of the same physical device is not blocked
        # by the uq_nvrs_external_device_id constraint.
        nvr.deleted_at = now
        nvr.external_device_id = None
        await self.db.commit()

        logger.info(
            "Deleted NVR %s (%s) and cascade-deleted its cameras",
            nvr.name,
            nvr_id,
        )
        return True

    async def get_nvr_channels(
        self, nvr_id: UUID, *, organization_id: UUID | None = None
    ) -> list[Any]:
        """Get cameras associated with an NVR."""
        from app.modules.cameras.models import Camera

        nvr = await self.get_nvr(nvr_id, organization_id=organization_id)  # Verify NVR exists

        q = (
            select(Camera)
            .where(
                Camera.nvr_id == nvr_id,
                Camera.deleted_at.is_(None),
                Camera.organization_id == nvr.organization_id,
            )
            .order_by(Camera.channel_id)
        )
        result = await self.db.execute(q)
        return list(result.scalars().all())

    async def get_nvr_stats(
        self,
        site_id: UUID | None = None,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> dict[str, int]:
        """Get NVR statistics scoped to organization.

        ``accessible_site_ids``: when non-None (site-limited caller), the
        aggregate counts only span NVRs in granted sites; an empty set is
        fail-closed (zero counts) so a site-limited user never sees org-wide NVR
        totals spanning sibling sites (R5 cameras site-grant).
        """
        from app.modules.cameras.models import NVR, CameraStatus

        query = select(NVR.status, func.count(NVR.id)).where(NVR.deleted_at.is_(None))
        if organization_id:
            query = query.where(NVR.organization_id == organization_id)

        if site_id:
            query = query.where(NVR.site_id == site_id)

        if accessible_site_ids is not None:
            query = query.where(NVR.site_id.in_(list(accessible_site_ids)))

        query = query.group_by(NVR.status)

        result = await self.db.execute(query)
        stats: dict[str, int] = dict(result.all())  # type: ignore[arg-type]

        return {
            "total": sum(stats.values()),
            "online": stats.get(CameraStatus.ONLINE.value, 0),
            "offline": stats.get(CameraStatus.OFFLINE.value, 0),
            "recording": stats.get(CameraStatus.RECORDING.value, 0),
            "error": stats.get(CameraStatus.ERROR.value, 0),
        }


# =============================================================================
# PTZ Service
# =============================================================================


class PTZService:
    """Service for PTZ camera control."""

    def __init__(self, db: AsyncSession):
        self.db = db

    _VALID_PTZ_ACTIONS = frozenset(
        {
            "up",
            "down",
            "left",
            "right",
            "up_left",
            "up_right",
            "down_left",
            "down_right",
            "zoom_in",
            "zoom_out",
            "stop",
            "preset",
            "home",
        }
    )

    async def control_ptz(
        self,
        camera_id: UUID,
        action: str,
        speed: int = 50,
        preset: int | None = None,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """
        Control PTZ camera.

        Args:
            camera_id: Camera ID
            action: PTZ action (up, down, left, right, zoom_in, zoom_out, stop, preset)
            speed: Movement speed (1-100)
            preset: Preset number (for preset action)
            organization_id: Scope to organization
        """
        if action not in self._VALID_PTZ_ACTIONS:
            raise CameraError(f"Invalid PTZ action: {action}")
        speed = max(1, min(100, speed))
        if preset is not None and not (1 <= preset <= 255):
            raise CameraError("Preset must be between 1 and 255")
        from app.modules.cameras.models import Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
        )
        if organization_id:
            q = q.where(Camera.organization_id == organization_id)
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()

        if not camera:
            raise CameraNotFoundError(camera_id)

        if not camera.has_ptz:
            raise CameraError(f"Camera does not support PTZ: {camera_id}")

        # Get adapter for camera type and execute PTZ command
        # In real implementation, this would use the adapter factory
        from app.adapters import get_adapter

        adapter = await get_adapter(
            adapter_type=camera.device_type or "onvif",
            host=camera.ip_address,
            username=camera.username,
            password=decrypt_credential(camera.password_encrypted)
            if camera.password_encrypted
            else "",
        )

        # WP-18: PTZ move / preset-goto are OPERATIONAL direct-actions — they
        # intentionally do NOT ride the staging pipeline and are not config
        # writes. Some adapters (Hikvision) gate them behind ADAPTER_READ_ONLY,
        # which defaults True, so without force=True live PTZ is silently blocked
        # on a default deploy. Pass force=True ONLY to adapters whose signature
        # accepts it (ONVIF/base don't gate operational PTZ and take no force kwarg).
        import inspect as _inspect

        def _with_force(method: Any, base_kwargs: dict[str, Any]) -> dict[str, Any]:
            try:
                if "force" in _inspect.signature(method).parameters:
                    return {**base_kwargs, "force": True}
            except (TypeError, ValueError):
                pass
            return base_kwargs

        try:
            if action == "preset" and preset is not None:
                ptz_result = await adapter.goto_preset(
                    **_with_force(
                        adapter.goto_preset,
                        {"device_id": str(camera.id), "preset": preset},
                    )
                )
            else:
                ptz_result = await adapter.ptz_control(
                    **_with_force(
                        adapter.ptz_control,
                        {"device_id": str(camera.id), "action": action, "speed": speed},
                    )
                )
        except Exception as e:
            logger.error("PTZ control failed for camera %s: %s", camera_id, e)
            raise CameraError("PTZ command failed")
        finally:
            if hasattr(adapter, "disconnect"):
                await adapter.disconnect()

        return {
            "action": action,
            "speed": speed,
            "preset": preset,
            "success": ptz_result.success if hasattr(ptz_result, "success") else True,
        }

    async def get_presets(
        self,
        camera_id: UUID,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> list[dict[str, Any]]:
        """Get PTZ presets for a camera.

        ``accessible_site_ids``: a site-limited caller may only read presets for
        a camera in a granted site; an empty set is fail-closed (camera resolves
        to nothing → 404) so a sibling-site camera is never reachable (R5 cameras
        site-grant).
        """
        from app.modules.cameras.models import Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
        )
        if organization_id:
            q = q.where(Camera.organization_id == organization_id)
        if accessible_site_ids is not None:
            q = q.where(Camera.site_id.in_(list(accessible_site_ids)))
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()

        if not camera:
            raise CameraNotFoundError(camera_id)

        # Return presets from camera settings
        presets: list[dict[str, Any]] = camera.settings.get("ptz_presets", [])
        return presets

    async def set_preset(
        self,
        camera_id: UUID,
        preset: int,
        name: str,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> dict[str, Any]:
        """Set a PTZ preset.

        ``accessible_site_ids``: a site-limited caller may only set a preset on a
        camera in a granted site; an empty set is fail-closed (camera resolves to
        nothing → 404) so a sibling-site camera cannot be mutated (R5 cameras
        site-grant).
        """
        from app.modules.cameras.models import Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
        )
        if organization_id:
            q = q.where(Camera.organization_id == organization_id)
        if accessible_site_ids is not None:
            q = q.where(Camera.site_id.in_(list(accessible_site_ids)))
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()

        if not camera:
            raise CameraNotFoundError(camera_id)

        if not camera.has_ptz:
            raise CameraError(f"Camera does not support PTZ: {camera_id}")

        # SAVE THE POSITION ON THE CAMERA FIRST.
        #
        # This method used to write ``camera.settings["ptz_presets"]`` and stop
        # there, so the Presets panel was a notepad: the operator aimed the
        # camera, saved "Front Gate" as preset 1, and the camera never recorded
        # the position.
        #
        # That would merely be inert if recall were local too -- but it is not.
        # ``control_ptz(action="preset")`` calls ``adapter.goto_preset`` on the
        # real camera. So clicking "Front Gate" moved the camera to whatever
        # ITS OWN preset 1 happened to be: uninitialised, or something set from
        # the camera's native web UI, or a position saved by a previous
        # installer. A preset panel that aims the camera somewhere other than
        # where you saved it is worse than one that does nothing.
        #
        # Both shipped camera adapters implement this properly --
        # HikvisionAdapter.set_preset PUTs the ISAPI preset, ONVIFAdapter
        # .set_preset issues SetPreset -- and each stores the CURRENT position
        # under that number, which is exactly the semantic the UI promises.
        from app.adapters import get_adapter

        adapter = await get_adapter(
            adapter_type=camera.device_type or "onvif",
            host=camera.ip_address,
            username=camera.username,
            password=decrypt_credential(camera.password_encrypted)
            if camera.password_encrypted
            else "",
        )
        try:
            # Same force treatment as control_ptz: saving a preset is an
            # operational PTZ action, and Hikvision gates it behind
            # ADAPTER_READ_ONLY (which defaults True), so a default deploy
            # would otherwise refuse every save. ONVIF takes no force kwarg.
            import inspect as _inspect

            kwargs: dict[str, Any] = {
                "device_id": str(camera.id),
                "preset": preset,
                "name": name,
            }
            try:
                if "force" in _inspect.signature(adapter.set_preset).parameters:
                    kwargs["force"] = True
            except (TypeError, ValueError):
                pass
            ptz_result = await adapter.set_preset(**kwargs)
        except Exception as exc:
            logger.error("Set preset failed for camera %s: %s", camera_id, exc)
            raise CameraError("Preset save failed on the camera") from exc
        finally:
            if hasattr(adapter, "disconnect"):
                await adapter.disconnect()

        # A refused save does not raise -- it comes back as
        # AdapterResult(success=False), the same shape every other camera write
        # in this module has to check.
        if getattr(ptz_result, "success", True) is False:
            raise CameraError(
                getattr(ptz_result, "error", None) or "Camera refused the preset save"
            )

        # Only now record the friendly name locally. The camera owns the
        # POSITION; FreeSDN owns the label the operator typed, because neither
        # ISAPI nor ONVIF guarantees the name survives a round trip.
        presets = camera.settings.get("ptz_presets", [])
        preset_data = {"id": preset, "name": name}

        # Update or add preset
        existing = next((p for p in presets if p["id"] == preset), None)
        if existing:
            existing["name"] = name
        else:
            presets.append(preset_data)

        camera.settings["ptz_presets"] = presets
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(camera, "settings")
        await self.db.commit()

        return preset_data


# =============================================================================
# Camera Event Service
# =============================================================================


class CameraEventService:
    """Service for camera events."""

    def __init__(self, db: AsyncSession):
        self.db = db

    _MAX_LIST_LIMIT = 500

    async def list_events(
        self,
        camera_id: UUID | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        acknowledged: bool | None = None,
        limit: int = 100,
        offset: int = 0,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> list[Any]:
        """List camera events scoped to organization.

        ``accessible_site_ids``: when non-None (site-limited caller), restrict to
        events whose parent Camera's site_id is in the granted set; an empty set
        is fail-closed (no rows) so a site-limited user never sees sibling-site
        camera events (R5 cameras site-grant).
        """
        from app.modules.cameras.models import Camera, CameraEvent

        limit = max(1, min(limit, self._MAX_LIST_LIMIT))
        offset = max(0, offset)
        query = select(CameraEvent)

        if organization_id or accessible_site_ids is not None:
            query = query.join(Camera, CameraEvent.camera_id == Camera.id).where(
                Camera.deleted_at.is_(None),
            )
            if organization_id:
                query = query.where(Camera.organization_id == organization_id)
            if accessible_site_ids is not None:
                query = query.where(Camera.site_id.in_(list(accessible_site_ids)))

        if camera_id:
            query = query.where(CameraEvent.camera_id == camera_id)
        if event_type:
            query = query.where(CameraEvent.event_type == event_type)
        if start_time:
            query = query.where(CameraEvent.timestamp >= start_time)
        if end_time:
            query = query.where(CameraEvent.timestamp <= end_time)
        if acknowledged is not None:
            query = query.where(CameraEvent.is_acknowledged == acknowledged)

        query = query.order_by(CameraEvent.timestamp.desc()).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def count_events(
        self,
        camera_id: UUID | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        acknowledged: bool | None = None,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> int:
        """Return total event count for pagination, scoped to organization.

        ``accessible_site_ids``: same fail-closed site-grant semantics as
        :meth:`list_events` so the count stays in lockstep with the list (R5
        cameras site-grant).
        """
        from app.modules.cameras.models import Camera, CameraEvent

        q = select(func.count(CameraEvent.id))
        if organization_id or accessible_site_ids is not None:
            q = q.join(Camera, CameraEvent.camera_id == Camera.id).where(
                Camera.deleted_at.is_(None),
            )
            if organization_id:
                q = q.where(Camera.organization_id == organization_id)
            if accessible_site_ids is not None:
                q = q.where(Camera.site_id.in_(list(accessible_site_ids)))
        if camera_id:
            q = q.where(CameraEvent.camera_id == camera_id)
        if event_type:
            q = q.where(CameraEvent.event_type == event_type)
        if start_time:
            q = q.where(CameraEvent.timestamp >= start_time)
        if end_time:
            q = q.where(CameraEvent.timestamp <= end_time)
        if acknowledged is not None:
            q = q.where(CameraEvent.is_acknowledged == acknowledged)
        result = await self.db.execute(q)
        return result.scalar() or 0

    async def get_event(
        self,
        event_id: UUID,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> Any:
        """Get an event by ID, scoped to organization.

        ``accessible_site_ids``: a site-limited caller may only resolve an event
        whose parent Camera lives in a granted site; an empty set is fail-closed
        (event resolves to nothing → not found) so a sibling-site event is never
        reachable (R5 cameras site-grant).
        """
        from app.modules.cameras.models import Camera, CameraEvent

        q = select(CameraEvent).where(CameraEvent.id == event_id)
        if organization_id or accessible_site_ids is not None:
            q = q.join(Camera, CameraEvent.camera_id == Camera.id).where(
                Camera.deleted_at.is_(None),
            )
            if organization_id:
                q = q.where(Camera.organization_id == organization_id)
            if accessible_site_ids is not None:
                q = q.where(Camera.site_id.in_(list(accessible_site_ids)))
        result = await self.db.execute(q)
        event = result.scalar_one_or_none()

        if not event:
            raise CameraError(f"Event not found: {event_id}")

        return event

    async def acknowledge_event(
        self,
        event_id: UUID,
        user_id: UUID,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> Any:
        """Acknowledge an event, scoped to organization (and per-user site grant)."""
        event = await self.get_event(
            event_id,
            organization_id=organization_id,
            accessible_site_ids=accessible_site_ids,
        )

        event.is_acknowledged = True
        event.acknowledged_by = user_id
        event.acknowledged_at = datetime.now(UTC)

        await self.db.commit()
        await self.db.refresh(event)

        return event

    async def bulk_acknowledge(
        self,
        event_ids: list[UUID],
        user_id: UUID,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> int:
        """Bulk acknowledge events scoped to organization.

        ``accessible_site_ids``: when non-None (site-limited caller), only events
        whose parent Camera lives in a granted site are acknowledged; an empty
        set is fail-closed (acknowledges nothing) so a site-limited user cannot
        bulk-ack sibling-site events (R5 cameras site-grant).
        """
        from sqlalchemy import update

        from app.modules.cameras.models import Camera, CameraEvent

        if not event_ids:
            return 0

        # If org-scoped or site-limited, narrow event_ids to the ones the caller
        # may actually touch (own org AND, for a site-limited caller, granted
        # sites) before the bulk UPDATE.
        if organization_id or accessible_site_ids is not None:
            from sqlalchemy import select as sa_select

            valid_q = (
                sa_select(CameraEvent.id)
                .join(Camera, CameraEvent.camera_id == Camera.id)
                .where(CameraEvent.id.in_(event_ids))
            )
            if organization_id:
                valid_q = valid_q.where(Camera.organization_id == organization_id)
            if accessible_site_ids is not None:
                valid_q = valid_q.where(Camera.site_id.in_(list(accessible_site_ids)))
            valid_result = await self.db.execute(valid_q)
            event_ids = [row[0] for row in valid_result.all()]
            if not event_ids:
                return 0

        now = datetime.now(UTC)
        stmt = (
            update(CameraEvent)
            .where(
                CameraEvent.id.in_(event_ids),
                CameraEvent.is_acknowledged.is_(False),
            )
            .values(
                is_acknowledged=True,
                acknowledged_by=user_id,
                acknowledged_at=now,
            )
        )
        update_result = await self.db.execute(stmt)
        await self.db.commit()
        count: int = update_result.rowcount  # type: ignore[attr-defined]
        return count


# =============================================================================
# NVR Discovery & Import Service
# =============================================================================


class NVRDiscoveryService:
    """
    Service for discovering and importing NVRs and their cameras.

    Supports Hikvision (ISAPI) and multi-vendor ONVIF devices.

    Workflow:
        1. ``test_connection()``    — validate credentials, return device info
        2. ``discover_channels()``  — enumerate all camera channels + storage
        3. ``import_nvr()``         — persist NVR + per-channel Camera records
        4. ``sync_nvr()``           — re-scan, add new / mark missing offline
    """

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _create_adapter(
        host: str,
        port: int,
        username: str,
        password: str,
        vendor: str | None = None,
    ) -> Any:
        """
        Instantiate a camera adapter (without connecting).

        Selects HikvisionAdapter for Hikvision devices, ONVIFAdapter for
        all other vendors or when vendor is unknown.
        """
        vendor_lower = (vendor or "").lower().strip()

        if vendor_lower == "hikvision":
            from app.adapters.hikvision.adapter import HikvisionAdapter

            return HikvisionAdapter(
                host=host,
                username=username,
                password=password,
                port=port,
            )

        from app.adapters.onvif.adapter import ONVIFAdapter

        return ONVIFAdapter(
            host=host,
            username=username,
            password=password,
            port=port,
        )

    @staticmethod
    def _detect_vendor(adapter: Any, device_info: dict[str, Any] | None = None) -> tuple[str, str]:
        """Detect vendor name and device_type from adapter class and device info.

        Returns (vendor, device_type) — e.g. ("Hikvision", "hikvision") or ("ONVIF", "onvif").
        """
        from app.adapters.hikvision.adapter import HikvisionAdapter

        if isinstance(adapter, HikvisionAdapter):
            return "Hikvision", "hikvision"
        if device_info:
            vendor = device_info.get("vendor") or device_info.get("manufacturer") or ""
            if vendor:
                return vendor, "onvif"
        return "ONVIF", "onvif"

    async def _connect_autodetect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        vendor: str | None = None,
    ) -> Any:
        """Return a CONNECTED NVR/camera adapter.

        The pre-add discover/test flow has no saved vendor, and the old code
        hardcoded ONVIF — so a Hikvision NVR with ONVIF disabled or returning a
        SOAP fault (common on Hikvision) failed even though its ISAPI works. Now:
        if the vendor is known use it directly; otherwise try Hikvision ISAPI
        first (the primary NVR vendor), then fall back to ONVIF. Failed attempts
        are disconnected; the last connect error is raised if none succeed.

        SSRF guard: the pre-add discover/test/import flows take a
        caller-supplied host, so an authenticated operator could otherwise
        aim the server at loopback / cloud-metadata (169.254.169.254) /
        link-local. Validate the host through the same project SSRF policy the
        ``update_nvr`` PATCH path uses BEFORE any outbound connect. Private
        RFC1918 ranges stay allowed by design (cameras/NVRs live on the LAN);
        only loopback/metadata/link-local are blocked, so legitimate device
        connections are unaffected.
        """
        from app.modules.cameras.schemas import _validate_host_not_ssrf

        try:
            _validate_host_not_ssrf(str(host))
        except ValueError as exc:
            raise CameraError(str(exc)) from exc

        v = (vendor or "").lower().strip()
        if v == "hikvision":
            order: list[str | None] = ["hikvision"]
        elif v:
            order = [None]  # any other explicit vendor → ONVIF
        else:
            order = ["hikvision", None]  # autodetect: ISAPI first, then ONVIF

        last_exc: Exception | None = None
        for vend in order:
            adapter = self._create_adapter(host, port, username, password, vendor=vend)
            try:
                if await adapter.connect():
                    return adapter
                with contextlib.suppress(Exception):
                    await adapter.disconnect()
            except Exception as exc:  # noqa: BLE001 — fall through to the next adapter
                last_exc = exc
                with contextlib.suppress(Exception):
                    await adapter.disconnect()
        if last_exc is not None:
            raise last_exc
        raise CameraError("Cannot connect to device — check host, port, and credentials")

    # ── 1. Test Connection ───────────────────────────────────────────────

    async def test_connection(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        vendor: str | None = None,
    ) -> dict[str, Any]:
        """
        Test connection to an NVR and return device info.

        Returns::

            {
                "success": True,
                "device_id": "...",
                "device_name": "Office NVR",
                "device_type": "NVR",
                "model": "DS-7608NI-K2",
                "firmware_version": "V4.62.210",
                "serial_number": "...",
                "mac_address": "...",
            }
        """
        adapter: Any = None
        try:
            adapter = await self._connect_autodetect(host, port, username, password, vendor)
            info = adapter.device_info
            return {
                "success": True,
                "device_id": info.get("deviceID", info.get("serial", "")),
                "device_name": info.get("deviceName", ""),
                "device_type": info.get("deviceType", ""),
                "model": info.get("model", ""),
                "firmware_version": info.get("firmware", ""),
                "serial_number": info.get("serial", ""),
                "mac_address": info.get("macAddress", ""),
            }
        except AdapterAuthenticationError:
            return {"success": False, "error": "Authentication failed — check username/password"}
        except AdapterConnectionError:
            return {"success": False, "error": "Cannot reach device — check host and port"}
        except Exception as exc:
            logger.error("NVR test connection failed: %s", exc)
            return {"success": False, "error": "Connection failed"}
        finally:
            if adapter is not None:
                with contextlib.suppress(Exception):
                    await adapter.disconnect()

    # ── 2. Discover Channels ─────────────────────────────────────────────

    async def discover_channels(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        vendor: str | None = None,
    ) -> dict[str, Any]:
        """
        Discover all camera channels + storage on the NVR.

        Returns::

            {
                "nvr": { device info dict },
                "channels": [
                    {
                        "channel_id": 1,
                        "name": "Front Door",
                        "enabled": True,
                        "online": True,
                        "source_ip": "192.168.1.100",
                        "has_ptz": False,
                        "rtsp_main": "rtsp://...",
                        "rtsp_sub": "rtsp://...",
                    },
                    ...
                ],
                "storage": { total_gb, used_gb, free_gb, ... },
            }
        """
        adapter = await self._connect_autodetect(host, port, username, password, vendor)
        try:
            # Discover NVR + all camera channels (adapter already connected)
            devices = await adapter.discover_devices()
            nvr_dev = next((d for d in devices if d.device_type == "nvr"), None)
            cam_devs = [d for d in devices if d.device_type in ("camera", "camera_ptz")]

            # Build RTSP URLs for each channel
            channels: list[dict[str, Any]] = []
            for cam in cam_devs:
                ch_id = cam.raw_data.get("channel_id", 1)

                # Build RTSP URLs and strip credentials for the response
                rtsp_main = adapter.get_rtsp_url(
                    device_id="",
                    channel=ch_id,
                    stream="main",
                )
                rtsp_sub = adapter.get_rtsp_url(
                    device_id="",
                    channel=ch_id,
                    stream="sub",
                )
                # Sanitise: replace user:pass@ with placeholder
                import re as _re

                _cred_re = _re.compile(r"://[^@]+@")
                rtsp_main_safe = _cred_re.sub("://***:***@", rtsp_main)
                rtsp_sub_safe = _cred_re.sub("://***:***@", rtsp_sub)

                channels.append(
                    {
                        "channel_id": ch_id,
                        "name": cam.name,
                        "enabled": cam.raw_data.get("enabled", True),
                        "online": cam.raw_data.get("online", False),
                        "source_ip": cam.raw_data.get("source_ip", ""),
                        "has_ptz": cam.device_type == "camera_ptz",
                        "has_audio": any(
                            c.value.startswith("camera.audio") for c in (cam.capabilities or [])
                        ),
                        "rtsp_main": rtsp_main_safe,
                        "rtsp_sub": rtsp_sub_safe,
                    }
                )

            # Storage info
            storage = await adapter.get_storage_info()

            # Determine device type: if no NVR device found and we have
            # camera devices, the target is a standalone camera, not an NVR.
            if nvr_dev:
                detected_type = "nvr"
                device_info = {
                    "device_id": nvr_dev.serial_number or "",
                    "name": nvr_dev.name or "",
                    "model": nvr_dev.model or "",
                    "firmware": nvr_dev.firmware_version or "",
                    "serial_number": nvr_dev.serial_number or "",
                    "mac_address": nvr_dev.mac_address or "",
                }
            elif cam_devs:
                # Standalone camera — use the first (only) camera's info
                cam = cam_devs[0]
                detected_type = "camera"
                device_info = {
                    "device_id": cam.serial_number or "",
                    "name": cam.name or "",
                    "model": cam.model or "",
                    "firmware": cam.firmware_version or "",
                    "serial_number": cam.serial_number or "",
                    "mac_address": cam.mac_address or "",
                }
            else:
                detected_type = "unknown"
                device_info = {
                    "device_id": "",
                    "name": "",
                    "model": "",
                    "firmware": "",
                    "serial_number": "",
                    "mac_address": "",
                }

            # discovery
            # responses pass through ``redact_secrets`` so any vendor
            # field the device exposes (``snmp_community``, ``token``,
            # ``api_key`` …) gets masked before reaching the operator's
            # browser. Same contract as every other reference adapter.
            from app.core.redaction import redact_secrets

            return redact_secrets(
                {
                    "device_type": detected_type,
                    "nvr": device_info,
                    "channels": channels,
                    "storage": storage,
                }
            )
        finally:
            await adapter.disconnect()

    # ── 3. Import NVR + Cameras ──────────────────────────────────────────

    async def import_nvr(
        self,
        organization_id: UUID,
        site_id: UUID,
        host: str,
        port: int,
        username: str,
        password: str,
        nvr_name: str | None = None,
        selected_channels: list[int] | None = None,
    ) -> dict[str, Any]:
        """
        Import an NVR and its cameras into the database.

        Args:
            organization_id: Owning org.
            site_id: Site the NVR belongs to.
            host, port, username, password: Connection details.
            nvr_name: Override auto-detected name.
            selected_channels: Channel IDs to import (``None`` = all enabled).

        Returns::

            {"nvr": <NVR>, "cameras": [<Camera>, ...], "skipped": int}
        """
        from app.core.crypto import encrypt_credential
        from app.modules.cameras.models import NVR, Camera

        # 1. Discover
        discovery = await self.discover_channels(host, port, username, password)
        nvr_info = discovery["nvr"]
        channels = discovery["channels"]
        storage = discovery.get("storage", {})

        # Detect vendor/device_type from the adapter that actually connects
        # (autodetect: Hikvision ISAPI first, then ONVIF). A fresh
        # _create_adapter() defaults to ONVIF and would mis-tag a Hikvision NVR
        # as 'onvif', breaking streaming for the saved record.
        probe = await self._connect_autodetect(host, port, username, password)
        try:
            detected_vendor, detected_device_type = self._detect_vendor(probe, nvr_info)
        finally:
            with contextlib.suppress(Exception):
                await probe.disconnect()

        # 2. Check for duplicate (scoped to org for tenant isolation)
        ext_id = nvr_info.get("device_id") or nvr_info.get("serial_number", "")
        if ext_id:
            existing = await self.db.execute(
                select(NVR).where(
                    NVR.external_device_id == ext_id,
                    NVR.organization_id == organization_id,
                    NVR.deleted_at.is_(None),
                )
            )
            existing_nvr = existing.scalar_one_or_none()
            if existing_nvr is not None:
                # Idempotent re-import: the NVR already exists → re-sync its
                # channels instead of dead-ending the wizard with an error.
                # "Discover → Import" on a known NVR now smoothly refreshes it
                # (adds new channels, updates existing). sync_nvr commits.
                sync_counts = await self.sync_nvr(existing_nvr.id, organization_id=organization_id)
                cam_rows = await self.db.execute(
                    select(Camera).where(
                        Camera.nvr_id == existing_nvr.id,
                        Camera.deleted_at.is_(None),
                    )
                )
                cams = list(cam_rows.scalars().all())
                return {
                    "nvr_id": existing_nvr.id,
                    "nvr_name": existing_nvr.name,
                    "cameras_imported": int(sync_counts.get("added", 0)),
                    "cameras_skipped": 0,
                    "cameras": [
                        {"id": c.id, "name": c.name, "channel_id": c.channel_id} for c in cams
                    ],
                    "synced": True,
                }

            # Defence-in-depth: clear external_device_id on any
            # soft-deleted NVR in this org so the unique constraint
            # doesn't block the new INSERT.
            from sqlalchemy import update as sa_update

            await self.db.execute(
                sa_update(NVR)
                .where(
                    NVR.external_device_id == ext_id,
                    NVR.organization_id == organization_id,
                    NVR.deleted_at.isnot(None),
                )
                .values(external_device_id=None)
            )

        # 3. Create NVR record
        nvr = NVR(
            organization_id=organization_id,
            site_id=site_id,
            name=nvr_name or nvr_info.get("name", host),
            ip_address=host,
            port=port,
            mac_address=nvr_info.get("mac_address"),
            username=username,
            password_encrypted=encrypt_credential(password),
            device_type=detected_device_type,
            external_device_id=ext_id or None,
            vendor=detected_vendor,
            model=nvr_info.get("model", ""),
            firmware_version=nvr_info.get("firmware", ""),
            serial_number=nvr_info.get("serial_number", ""),
            channel_count=len(channels),
            storage_total_gb=storage.get("total_gb"),
            storage_used_gb=storage.get("used_gb"),
            status="online",
            last_synced_at=datetime.now(UTC),
        )
        self.db.add(nvr)
        await self.db.flush()  # get nvr.id

        # 4. Create Camera per selected channel
        imported: list[Any] = []
        skipped = 0

        for ch in channels:
            ch_id = ch["channel_id"]
            if selected_channels and ch_id not in selected_channels:
                skipped += 1
                continue
            if not ch.get("enabled", True):
                skipped += 1
                continue

            # If the NVR can enumerate this channel, it is reachable.
            # Hikvision <online> XML is unreliable for some firmware versions,
            # so we default to "online" for any enabled channel.
            camera = Camera(
                organization_id=organization_id,
                site_id=site_id,
                nvr_id=nvr.id,
                channel_id=ch_id,
                name=ch.get("name", f"Channel {ch_id}"),
                ip_address=ch.get("source_ip") or host,
                port=554,
                vendor=detected_vendor,
                model=nvr_info.get("model", ""),
                device_type=detected_device_type,
                username=username,
                password_encrypted=encrypt_credential(password),
                # Store RTSP URLs without embedded credentials (reconstructed at runtime)
                rtsp_main_stream=(f"rtsp://{host}:554/Streaming/Channels/{ch_id * 100 + 1}"),
                rtsp_sub_stream=(f"rtsp://{host}:554/Streaming/Channels/{ch_id * 100 + 2}"),
                snapshot_url=(
                    f"http://{host}:{port}/ISAPI/Streaming/channels/{ch_id * 100 + 1}/picture"
                ),
                has_ptz=ch.get("has_ptz", False),
                has_audio=ch.get("has_audio", False),
                camera_type="ptz_camera" if ch.get("has_ptz") else "ip_camera",
                status="online",
                last_seen=datetime.now(UTC),
            )
            self.db.add(camera)
            imported.append(camera)

        await self.db.commit()

        # Single refresh for the NVR (cameras are eagerly flushed above)
        await self.db.refresh(nvr)

        logger.info(
            "Imported NVR %s (%s) with %d cameras (%d skipped)",
            nvr.name,
            nvr.id,
            len(imported),
            skipped,
        )
        return {
            "nvr_id": nvr.id,
            "nvr_name": nvr.name,
            "cameras_imported": len(imported),
            "cameras_skipped": skipped,
            "cameras": [
                {
                    "id": cam.id,
                    "name": cam.name,
                    "channel_id": cam.channel_id,
                }
                for cam in imported
            ],
        }

    # ── 3b. Import standalone camera ────────────────────────────────────

    async def import_standalone_camera(
        self,
        organization_id: UUID,
        site_id: UUID,
        host: str,
        port: int,
        username: str,
        password: str,
        camera_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Import a standalone IP camera (not an NVR) into the database.

        Connects to the device, verifies it's a camera (not NVR), and
        creates a Camera record without an NVR parent.

        Returns::

            {"camera_id": <UUID>, "camera_name": str}
        """
        from app.core.crypto import encrypt_credential
        from app.modules.cameras.models import Camera

        # 1. Test connection + get device info
        result = await self.test_connection(host, port, username, password)
        if not result.get("success"):
            raise CameraError(result.get("error", "Cannot connect to camera"))

        device_type_raw = (result.get("device_type") or "").lower()
        device_id = result.get("device_id") or result.get("serial_number") or ""

        # 2. Check for duplicate (scoped to org for tenant isolation)
        if device_id:
            existing = await self.db.execute(
                select(Camera).where(
                    Camera.serial_number == device_id,
                    Camera.organization_id == organization_id,
                    Camera.deleted_at.is_(None),
                )
            )
            if existing.scalar_one_or_none():
                raise CameraError(
                    "This camera is already imported. "
                    "Edit the existing camera to update its settings."
                )

        # 3. Determine camera type
        is_ptz = "ptz" in device_type_raw
        cam_type = "ptz_camera" if is_ptz else "ip_camera"

        # 4. Build RTSP URLs (autodetect adapter: Hikvision ISAPI first, then ONVIF)
        adapter = None
        try:
            adapter = await self._connect_autodetect(host, port, username, password)
            rtsp_main = adapter.get_rtsp_url(device_id="", channel=1, stream="main")
            rtsp_sub = adapter.get_rtsp_url(device_id="", channel=1, stream="sub")
        except Exception:
            rtsp_main = f"rtsp://{host}:554/Streaming/Channels/101"
            rtsp_sub = f"rtsp://{host}:554/Streaming/Channels/102"
        finally:
            if adapter is not None:
                with contextlib.suppress(Exception):
                    await adapter.disconnect()

        # 5. Create Camera record (no nvr_id)
        camera = Camera(
            organization_id=organization_id,
            site_id=site_id,
            nvr_id=None,
            channel_id=None,
            name=camera_name or result.get("device_name") or host,
            ip_address=host,
            port=port,
            mac_address=result.get("mac_address"),
            # Default device_type for unknown ONVIF:
            # the prior implementation defaulted ``vendor`` to "Hikvision"
            # AND then evaluated ``"hikvision" in "hikvision".lower()``,
            # mis-classifying every unknown ONVIF camera as Hikvision.
            # Reads then hit ISAPI endpoints that don't exist on the
            # actual device. Fix:
            #   * keep vendor unchanged when the discovery payload
            #     surfaces no vendor (don't fabricate "Hikvision")
            #   * only set device_type="hikvision" when the
            #     discovery payload explicitly identifies the
            #     device as Hikvision.
            vendor=(result.get("vendor") or result.get("manufacturer") or "unknown"),
            model=result.get("model", ""),
            firmware_version=result.get("firmware_version", ""),
            serial_number=result.get("serial_number", ""),
            device_type=(
                "hikvision"
                if "hikvision" in (result.get("vendor") or result.get("manufacturer") or "").lower()
                else "onvif"
            ),
            username=username,
            password_encrypted=encrypt_credential(password),
            rtsp_main_stream=rtsp_main,
            rtsp_sub_stream=rtsp_sub,
            snapshot_url=f"http://{host}:{port}/ISAPI/Streaming/channels/101/picture",
            has_ptz=is_ptz,
            has_audio=False,
            camera_type=cam_type,
            status="online",
            last_seen=datetime.now(UTC),
        )
        self.db.add(camera)
        await self.db.commit()
        await self.db.refresh(camera)

        logger.info(
            "Imported standalone camera %s (%s) at %s:%d",
            camera.name,
            camera.id,
            host,
            port,
        )
        return {
            "camera_id": camera.id,
            "camera_name": camera.name,
        }

    # ── 4. Sync NVR ─────────────────────────────────────────────────────

    async def sync_nvr(
        self, nvr_id: UUID, *, organization_id: UUID | None = None
    ) -> dict[str, Any]:
        """
        Re-sync an imported NVR: discover current channels, add new ones,
        mark missing offline, update storage stats.

        Returns::

            {"added": [Camera, ...], "removed": [Camera, ...], "updated": [Camera, ...]}
        """
        from app.core.crypto import decrypt_credential
        from app.modules.cameras.models import NVR, Camera

        # 1. Load NVR (org-scoped for tenant isolation)
        q = select(NVR).where(NVR.id == nvr_id, NVR.deleted_at.is_(None))
        if organization_id:
            q = q.where(NVR.organization_id == organization_id)
        result = await self.db.execute(q)
        nvr = result.scalar_one_or_none()
        if not nvr:
            raise NVRNotFoundError(nvr_id)

        if not nvr.password_encrypted:
            raise CameraError("NVR has no stored credentials for sync")
        password = decrypt_credential(nvr.password_encrypted)

        # 2. Discover current state
        discovery = await self.discover_channels(
            nvr.ip_address,
            nvr.port or 80,
            nvr.username or "",
            password,
        )
        live_channels = {ch["channel_id"]: ch for ch in discovery["channels"]}

        # 3. Load DB cameras for this NVR (org-scoped for defense-in-depth)
        db_result = await self.db.execute(
            select(Camera).where(
                Camera.nvr_id == nvr_id,
                Camera.deleted_at.is_(None),
                Camera.organization_id == nvr.organization_id,
            )
        )
        existing = {cam.channel_id: cam for cam in db_result.scalars().all() if cam.channel_id}

        added: list[Any] = []
        removed: list[Any] = []
        updated: list[Any] = []

        # 4. New channels → create cameras
        for ch_id, ch in live_channels.items():
            if ch_id not in existing:
                camera = Camera(
                    organization_id=nvr.organization_id,
                    site_id=nvr.site_id,
                    nvr_id=nvr.id,
                    channel_id=ch_id,
                    name=ch.get("name", f"Channel {ch_id}"),
                    ip_address=ch.get("source_ip") or nvr.ip_address,
                    port=554,
                    vendor=nvr.vendor or "Hikvision",
                    device_type=nvr.device_type or "hikvision",
                    username=nvr.username,
                    password_encrypted=nvr.password_encrypted,
                    # Store RTSP URLs without embedded credentials (reconstructed at runtime)
                    rtsp_main_stream=(
                        f"rtsp://{nvr.ip_address}:554/Streaming/Channels/{ch_id * 100 + 1}"
                    ),
                    rtsp_sub_stream=(
                        f"rtsp://{nvr.ip_address}:554/Streaming/Channels/{ch_id * 100 + 2}"
                    ),
                    has_ptz=ch.get("has_ptz", False),
                    has_audio=ch.get("has_audio", False),
                    camera_type="ptz_camera" if ch.get("has_ptz") else "ip_camera",
                    status="online" if ch.get("online") else "offline",
                )
                self.db.add(camera)
                added.append(camera)
            else:
                # Update existing — keep RTSP URLs from DB (already have real creds)
                cam = existing[ch_id]
                cam.name = ch.get("name", cam.name)
                cam.status = "online" if ch.get("online") else "offline"
                updated.append(cam)

        # 5. Missing channels → mark offline
        for ch_id, cam in existing.items():
            if ch_id not in live_channels:
                cam.status = "offline"
                removed.append(cam)

        # 6. Update NVR metadata
        storage = discovery.get("storage", {})
        if storage and "total_gb" in storage:
            nvr.storage_total_gb = storage["total_gb"]
            nvr.storage_used_gb = storage.get("used_gb")
        nvr.channel_count = len(live_channels)
        nvr.last_synced_at = datetime.now(UTC)
        nvr.status = "online"

        await self.db.commit()

        logger.info(
            "NVR sync %s: +%d -%d ~%d",
            nvr.name,
            len(added),
            len(removed),
            len(updated),
        )
        return {
            "added": len(added),
            "removed": len(removed),
            "updated": len(updated),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Camera Access Control Service (Per-Camera RBAC)
# ═══════════════════════════════════════════════════════════════════════════════


class CameraAccessService:
    """
    Per-camera / per-group access grant management.

    Supplements the org-wide role system with fine-grained camera permissions:
      - Org admins+ bypass (implicit full access)
      - Explicit camera grants (viewer / operator / full)
      - Group grants (apply to all members)
      - Time-limited access (expires_at)
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_grants(
        self,
        organization_id: UUID,
        *,
        camera_id: UUID | None = None,
        user_id: UUID | None = None,
    ) -> list[Any]:
        """List access grants, optionally filtered by camera or user."""
        from app.models.core import User
        from app.modules.cameras.models import CameraAccessGrant

        q = (
            select(CameraAccessGrant, User.email, User.full_name)
            .outerjoin(User, CameraAccessGrant.user_id == User.id)
            .where(CameraAccessGrant.organization_id == organization_id)
        )
        if camera_id:
            q = q.where(CameraAccessGrant.camera_id == camera_id)
        if user_id:
            q = q.where(CameraAccessGrant.user_id == user_id)
        q = q.order_by(CameraAccessGrant.created_at.desc()).limit(500)

        result = await self.db.execute(q)
        rows = result.all()
        return [
            {
                "id": str(grant.id),
                "user_id": str(grant.user_id),
                "camera_id": str(grant.camera_id) if grant.camera_id else None,
                "group_id": str(grant.group_id) if grant.group_id else None,
                "access_level": grant.access_level,
                "can_live": grant.can_live,
                "can_playback": grant.can_playback,
                "can_ptz": grant.can_ptz,
                "can_export": grant.can_export,
                "can_configure": grant.can_configure,
                "expires_at": grant.expires_at.isoformat() if grant.expires_at else None,
                "created_at": grant.created_at.isoformat() if grant.created_at else None,
                "user_email": email,
                "user_name": name,
            }
            for grant, email, name in rows
        ]

    async def create_grant(
        self,
        organization_id: UUID,
        *,
        user_id: UUID,
        camera_id: UUID | None = None,
        group_id: UUID | None = None,
        access_level: str = "viewer",
        can_live: bool = True,
        can_playback: bool = False,
        can_ptz: bool = False,
        can_export: bool = False,
        can_configure: bool = False,
        expires_at: datetime | None = None,
        created_by: UUID | None = None,
    ) -> Any:
        """Create a new camera access grant."""
        from app.modules.cameras.models import CameraAccessGrant

        grant = CameraAccessGrant(
            user_id=user_id,
            camera_id=camera_id,
            group_id=group_id,
            access_level=access_level,
            can_live=can_live,
            can_playback=can_playback,
            can_ptz=can_ptz,
            can_export=can_export,
            can_configure=can_configure,
            organization_id=organization_id,
            expires_at=expires_at,
            created_by=created_by,
        )
        self.db.add(grant)
        await self.db.commit()
        await self.db.refresh(grant)
        return grant

    async def _grant_in_accessible_sites(
        self, grant: Any, accessible_site_ids: set[UUID] | list[UUID] | None
    ) -> bool:
        """Whether a site-limited caller may touch this grant.

        Mirrors ``create_access_grant``: the per-user site grant is enforced via
        the grant's *camera* (the only target with a site). Camera-targeted
        grants must live in a granted site; group-targeted grants have no site
        (a CameraGroup is org-scoped only), so they stay reachable exactly as
        the create path leaves them unfiltered. ``None`` means a non
        site-limited caller (super/org) — always allowed.
        """
        if accessible_site_ids is None:
            return True
        if grant.camera_id is None:
            # Group grant (no site) — matches create's unfiltered group path.
            return True
        from app.modules.cameras.models import Camera

        result = await self.db.execute(
            select(Camera.id).where(
                Camera.id == grant.camera_id,
                Camera.site_id.in_(list(accessible_site_ids)),
            )
        )
        return result.scalar_one_or_none() is not None

    async def update_grant(
        self,
        grant_id: UUID,
        organization_id: UUID,
        *,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Update an existing grant. Returns updated grant or None.

        ``accessible_site_ids``: when non-None (site-limited caller), the grant
        is only mutable if its target camera lives in a granted site — so a
        site-limited operator cannot edit a sibling-site grant (treated as
        not-found → None). An empty set is fail-closed.
        """
        from app.modules.cameras.models import CameraAccessGrant

        result = await self.db.execute(
            select(CameraAccessGrant).where(
                CameraAccessGrant.id == grant_id,
                CameraAccessGrant.organization_id == organization_id,
            )
        )
        grant = result.scalar_one_or_none()
        if not grant:
            return None

        if not await self._grant_in_accessible_sites(grant, accessible_site_ids):
            return None

        _ALLOWED_UPDATE_FIELDS = {
            "access_level",
            "can_live",
            "can_playback",
            "can_ptz",
            "can_export",
            "can_configure",
            "expires_at",
        }
        for key, value in kwargs.items():
            if key in _ALLOWED_UPDATE_FIELDS:
                setattr(grant, key, value)

        await self.db.commit()
        await self.db.refresh(grant)
        return grant

    async def delete_grant(
        self,
        grant_id: UUID,
        organization_id: UUID,
        *,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> bool:
        """Delete an access grant. Returns True if deleted.

        ``accessible_site_ids``: when non-None (site-limited caller), the grant
        is only deletable if its target camera lives in a granted site — so a
        site-limited operator cannot revoke a sibling-site grant (treated as
        not-found → False). An empty set is fail-closed.
        """
        from app.modules.cameras.models import CameraAccessGrant

        result = await self.db.execute(
            select(CameraAccessGrant).where(
                CameraAccessGrant.id == grant_id,
                CameraAccessGrant.organization_id == organization_id,
            )
        )
        grant = result.scalar_one_or_none()
        if not grant:
            return False

        if not await self._grant_in_accessible_sites(grant, accessible_site_ids):
            return False

        await self.db.delete(grant)
        await self.db.commit()
        return True

    async def check_access(
        self,
        user_id: UUID,
        camera_id: UUID,
        organization_id: UUID,
        *,
        user_role: str | None = None,
    ) -> dict[str, Any]:
        """
        Check effective permissions for a user on a specific camera.

        Resolution order:
        1. Org admin+ → full access (role-based bypass)
        2. Direct camera grant → use it
        3. Group grants → merge (highest wins)
        4. No grant → deny
        """
        from app.modules.cameras.models import (
            Camera,
            CameraAccessGrant,
            CameraGroup,
            CameraGroupMember,
        )

        # 0. Verify camera belongs to the organization
        cam_result = await self.db.execute(
            select(Camera.id).where(
                Camera.id == camera_id,
                Camera.organization_id == organization_id,
                Camera.deleted_at.is_(None),
            )
        )
        if not cam_result.scalar_one_or_none():
            return {
                "has_access": False,
                "access_level": None,
                "can_live": False,
                "can_playback": False,
                "can_ptz": False,
                "can_export": False,
                "can_configure": False,
                "grant_source": None,
            }

        # 1. Org admins+ get implicit full access
        admin_roles = {"super_admin", "admin", "org_admin"}
        if user_role and user_role in admin_roles:
            return {
                "has_access": True,
                "access_level": "full",
                "can_live": True,
                "can_playback": True,
                "can_ptz": True,
                "can_export": True,
                "can_configure": True,
                "grant_source": "role",
            }

        now = datetime.now(UTC)

        # 2. Direct camera grant
        result = await self.db.execute(
            select(CameraAccessGrant).where(
                CameraAccessGrant.user_id == user_id,
                CameraAccessGrant.camera_id == camera_id,
                CameraAccessGrant.organization_id == organization_id,
            )
        )
        direct = result.scalar_one_or_none()
        if direct and (not direct.expires_at or direct.expires_at > now):
            return {
                "has_access": True,
                "access_level": direct.access_level,
                "can_live": direct.can_live,
                "can_playback": direct.can_playback,
                "can_ptz": direct.can_ptz,
                "can_export": direct.can_export,
                "can_configure": direct.can_configure,
                "grant_source": "camera_grant",
            }

        # 3. Group grants — find all groups the camera belongs to,
        #    then find user grants for those groups, merge (highest wins)
        group_ids_result = await self.db.execute(
            select(CameraGroupMember.group_id)
            .join(CameraGroup, CameraGroupMember.group_id == CameraGroup.id)
            .where(
                CameraGroupMember.camera_id == camera_id,
                CameraGroup.organization_id == organization_id,
            )
        )
        group_ids = [r[0] for r in group_ids_result.all()]

        if group_ids:
            grants_result = await self.db.execute(
                select(CameraAccessGrant).where(
                    CameraAccessGrant.user_id == user_id,
                    CameraAccessGrant.group_id.in_(group_ids),
                    CameraAccessGrant.organization_id == organization_id,
                )
            )
            group_grants = [
                g for g in grants_result.scalars().all() if not g.expires_at or g.expires_at > now
            ]

            if group_grants:
                # Merge: OR across all boolean flags, highest access_level wins
                level_order = {"viewer": 0, "operator": 1, "full": 2}
                best_level = max(group_grants, key=lambda g: level_order.get(g.access_level, 0))
                return {
                    "has_access": True,
                    "access_level": best_level.access_level,
                    "can_live": any(g.can_live for g in group_grants),
                    "can_playback": any(g.can_playback for g in group_grants),
                    "can_ptz": any(g.can_ptz for g in group_grants),
                    "can_export": any(g.can_export for g in group_grants),
                    "can_configure": any(g.can_configure for g in group_grants),
                    "grant_source": "group_grant",
                }

        # 4. No grant — fall back to org-wide role permissions
        # (site_admin/operator/viewer still have cameras.view via role)
        if user_role and user_role in {"site_admin", "operator", "viewer"}:
            return {
                "has_access": True,
                "access_level": "viewer" if user_role == "viewer" else "operator",
                "can_live": True,
                "can_playback": user_role != "viewer",
                "can_ptz": user_role in {"site_admin", "operator"},
                "can_export": user_role == "site_admin",
                "can_configure": user_role == "site_admin",
                "grant_source": "role",
            }

        return {
            "has_access": False,
            "access_level": None,
            "can_live": False,
            "can_playback": False,
            "can_ptz": False,
            "can_export": False,
            "can_configure": False,
            "grant_source": None,
        }


# =============================================================================
# HLS Stream Service
# =============================================================================


class HLSStreamService:
    """HLS streaming via FFmpeg RTSP-to-HLS transcoding."""

    _sessions: ClassVar[dict[str, dict[str, Any]]] = {}
    _lock: ClassVar[asyncio.Lock] = asyncio.Lock()
    HLS_DIR = "/tmp/freesdn-hls"
    SESSION_TIMEOUT = 30  # seconds without heartbeat (only reaps when viewers<=0)
    MAX_SESSION_AGE = (
        6 * 3600
    )  # hard ceiling — reap regardless of viewers (crashed-client backstop)

    _QUALITY_PRESETS: ClassVar[dict[str, dict[str, str]]] = {
        "low": {"crf": "28", "maxrate": "500k", "bufsize": "1000k", "scale": "640:360"},
        "medium": {"crf": "23", "maxrate": "1500k", "bufsize": "3000k", "scale": "1280:720"},
        "high": {"crf": "20", "maxrate": "3000k", "bufsize": "6000k", "scale": ""},
        "source": {},  # copy mode for h264, or transcode with no scaling for h265
    }

    async def start_session(
        self,
        camera_id: UUID,
        quality: str,
        rtsp_url: str,
        source_codec: str = "h264",
        organization_id: UUID | None = None,
        session_key: str | None = None,
        is_recorded: bool = False,
    ) -> dict[str, Any]:
        """Start or join an HLS transcoding session.

        If a session already exists for this camera+quality, the viewer count
        is incremented and the existing session info is returned.  Otherwise a
        new FFmpeg subprocess is spawned.

        Args:
            camera_id: Camera identifier.
            quality: One of ``low``, ``medium``, ``high``, ``source``.
            rtsp_url: Fully-qualified RTSP URL with credentials.
            source_codec: Source video codec (``h264`` / ``h265``).
            organization_id: Optional org scope (unused internally but
                carried on the session metadata for auditing).

        Returns:
            Dict with ``session_id``, ``playlist_url``, ``codec``, ``quality``,
            ``viewers``.
        """
        if quality not in self._QUALITY_PRESETS:
            raise StreamError(f"Invalid quality preset: {quality}")

        if not re.match(r"^rtsps?://", rtsp_url):
            return {"error": "Invalid RTSP URL scheme"}

        # Live sessions key on camera+quality (so viewers of the same live feed
        # share one ffmpeg); recorded-playback passes an explicit key that also
        # includes the seek instant so different time-windows don't collide.
        session_key = session_key or f"{camera_id}:{quality}"

        async with self._lock:
            # Re-use existing session
            for sid, meta in self._sessions.items():
                if meta["session_key"] == session_key:
                    meta["viewers"] += 1
                    meta["last_heartbeat"] = datetime.now(UTC)
                    return {
                        "session_id": sid,
                        "playlist_url": f"/api/v1/cameras/streams/hls/{sid}/stream.m3u8",
                        "codec": meta["source_codec"],
                        "quality": quality,
                        "viewers": meta["viewers"],
                    }

            # Create new session
            session_id = uuid4().hex
            output_dir = os.path.join(self.HLS_DIR, session_id)
            os.makedirs(output_dir, exist_ok=True)

            ffmpeg_args = self._build_ffmpeg_args(
                rtsp_url, output_dir, source_codec, quality, is_recorded
            )

            # Capture ffmpeg stderr to a per-session log instead of discarding it —
            # when a session produces no segments (e.g. an NVR whose recorded HEVC
            # has no decodable parameter sets) the tail is logged on teardown so the
            # failure is diagnosable rather than a silent spinner.
            log_path = os.path.join(output_dir, "ffmpeg.log")
            log_file = open(log_path, "wb")  # noqa: SIM115 — closed in _kill_session
            process = await asyncio.create_subprocess_exec(
                *ffmpeg_args,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=log_file,
            )

            self._sessions[session_id] = {
                "session_key": session_key,
                "camera_id": str(camera_id),
                "organization_id": str(organization_id) if organization_id else None,
                "quality": quality,
                "source_codec": source_codec,
                "output_dir": output_dir,
                "process": process,
                "log_file": log_file,
                "log_path": log_path,
                "is_recorded": is_recorded,
                "viewers": 1,
                "started_at": datetime.now(UTC),
                "last_heartbeat": datetime.now(UTC),
            }

            logger.info(
                "Started HLS session %s for camera %s (quality=%s, codec=%s, pid=%s)",
                session_id,
                camera_id,
                quality,
                source_codec,
                process.pid,
            )

            return {
                "session_id": session_id,
                "playlist_url": f"/api/v1/cameras/streams/hls/{session_id}/stream.m3u8",
                "codec": source_codec,
                "quality": quality,
                "viewers": 1,
            }

    async def stop_session(self, session_id: str) -> None:
        """Decrement viewer count; kill FFmpeg when no viewers remain."""
        async with self._lock:
            meta = self._sessions.get(session_id)
            if meta is None:
                return

            meta["viewers"] = max(0, meta["viewers"] - 1)

            if meta["viewers"] <= 0:
                await self._kill_session(session_id, meta)

    async def heartbeat(self, session_id: str) -> bool:
        """Update heartbeat timestamp. Returns False if session does not exist."""
        meta = self._sessions.get(session_id)
        if meta is None:
            return False
        meta["last_heartbeat"] = datetime.now(UTC)
        return True

    def get_playlist_path(self, session_id: str) -> str | None:
        """Return filesystem path to the ``.m3u8`` playlist, or ``None``."""
        meta = self._sessions.get(session_id)
        if meta is None:
            return None
        # Active polling keeps the session alive even if the dedicated heartbeat
        # POST is throttled (e.g. backgrounded tab) — hls.js fetches the playlist
        # continuously while playing.
        meta["last_heartbeat"] = datetime.now(UTC)
        playlist = os.path.join(meta["output_dir"], "stream.m3u8")
        if os.path.isfile(playlist):
            return playlist
        return None

    def get_segment_path(self, session_id: str, segment: str) -> str | None:
        """Return filesystem path to a ``.ts`` segment after validation.

        The segment name is validated against a strict pattern to prevent
        path traversal attacks.
        """
        if not re.fullmatch(r"\d{5}\.ts", segment):
            return None
        meta = self._sessions.get(session_id)
        if meta is None:
            return None
        meta["last_heartbeat"] = datetime.now(UTC)
        seg_path = os.path.join(meta["output_dir"], segment)
        if os.path.isfile(seg_path):
            return seg_path
        return None

    async def cleanup_stale_sessions(self) -> int:
        """Kill FFmpeg and remove directories for sessions without a recent heartbeat.

        Intended to be called periodically (e.g. every 60 s by a Celery beat task).

        Returns:
            Number of sessions cleaned up.
        """
        now = datetime.now(UTC)
        stale_ids: list[str] = []

        async with self._lock:
            for sid, meta in self._sessions.items():
                elapsed = (now - meta["last_heartbeat"]).total_seconds()
                age = (now - meta.get("started_at", now)).total_seconds()
                # Reap when there are no active viewers AND no recent heartbeat
                # (honours the viewer count so a still-watched stream whose
                # heartbeat is briefly throttled isn't killed), OR when the
                # session exceeds the hard age ceiling regardless of viewers
                # (backstop for a crashed client that left viewers pinned > 0).
                idle = elapsed > self.SESSION_TIMEOUT and meta.get("viewers", 0) <= 0
                expired = age > self.MAX_SESSION_AGE
                if idle or expired:
                    stale_ids.append(sid)

            for sid in stale_ids:
                stale_meta = self._sessions.get(sid)
                if stale_meta is not None:
                    await self._kill_session(sid, stale_meta)

        if stale_ids:
            logger.info("Cleaned up %d stale HLS sessions", len(stale_ids))
        return len(stale_ids)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _kill_session(self, session_id: str, meta: dict[str, Any]) -> None:
        """Terminate FFmpeg process and remove output directory."""
        process: asyncio.subprocess.Process = meta["process"]
        try:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except TimeoutError:
                process.kill()
        except ProcessLookupError:
            pass  # already exited

        output_dir = meta["output_dir"]

        # Diagnose silent failures: a session that produced no .ts segments almost
        # always means ffmpeg couldn't open/decode the source (e.g. a classic NVR
        # whose recorded HEVC carries no decodable parameter sets). Log the stderr
        # tail so it isn't an unexplained spinner.
        log_file = meta.get("log_file")
        if log_file is not None:
            with contextlib.suppress(Exception):
                log_file.close()
        try:
            produced = (
                [f for f in os.listdir(output_dir) if f.endswith(".ts")]
                if os.path.isdir(output_dir)
                else []
            )
            if not produced and meta.get("log_path") and os.path.isfile(meta["log_path"]):
                with open(meta["log_path"], errors="replace") as fh:
                    tail = fh.read()[-800:]
                logger.warning(
                    "HLS session %s (camera=%s, recorded=%s) produced NO segments — ffmpeg tail: %s",
                    session_id,
                    meta.get("camera_id"),
                    meta.get("is_recorded"),
                    tail.replace("\n", " | ")[-600:],
                )
        except Exception:  # pragma: no cover - diagnostics must never raise
            pass

        if os.path.isdir(output_dir):
            shutil.rmtree(output_dir, ignore_errors=True)

        self._sessions.pop(session_id, None)
        logger.info("Stopped HLS session %s (camera=%s)", session_id, meta.get("camera_id"))

    @staticmethod
    def _build_ffmpeg_args(
        rtsp_url: str,
        output_dir: str,
        source_codec: str,
        quality: str,
        is_recorded: bool = False,
    ) -> list[str]:
        """Build FFmpeg command-line arguments.

        For h264 sources in ``source`` quality the video stream is copied
        without transcoding.  For h265 sources (or when a quality preset
        requests scaling / bitrate limiting) the stream is transcoded to h264.

        ``is_recorded`` switches the HLS muxer from a small rolling live window
        to a growing, bounded VOD-style playlist (see the HLS section below) so
        recorded playback buffers ahead and plays smoothly even when a heavy
        4K-HEVC source only transcodes at ~real-time.
        """
        preset = HLSStreamService._QUALITY_PRESETS.get(quality, {})

        args: list[str] = [
            "ffmpeg",
            "-hide_banner",
            "-y",
            "-rtsp_transport",
            "tcp",
            "-i",
            rtsp_url,
        ]

        # Copy (remux, no transcode) when the source is already browser-universal
        # H.264 — from ANY vendor/NVR — or when the caller explicitly asks for the
        # original codec. This is the smoothest, cheapest path and needs no decode.
        # H.265/HEVC (and anything else) is transcoded to H.264 below for universal
        # browser playback, unless quality=source (HEVC-capable clients only).
        if quality == "source" or source_codec == "h264":
            # For h265 'source' this produces HEVC segments playable only by
            # HEVC-capable clients (Safari / hls.js+MSE); for h264 it's universal.
            # 4K-HEVC software decode can't sustain real-time transcode, so 'source'
            # (copy) is the only real-time full-res option for HEVC.
            args.extend(["-c:v", "copy"])
        else:
            # Recorded playback decodes a heavy 4K-HEVC source — use ultrafast to
            # spend the least CPU on encode and leave headroom for the decoder
            # (the real bottleneck), keeping output at ~real-time.
            args.extend(["-c:v", "libx264", "-preset", "ultrafast" if is_recorded else "veryfast"])
            # Force a keyframe every 2s (= hls_time) so HLS segments are ~2s and
            # the FIRST segment is ready in ~3-4s instead of ~15s. x264's default
            # keyint is 250 frames (~8s), which made the first segment land long
            # after the player gave up ("Network error: unable to load stream").
            # fps-independent expr keyframes + disabled scene-cut keep segment
            # boundaries aligned and independently decodable.
            args.extend(
                [
                    "-force_key_frames",
                    "expr:gte(t,n_forced*2)",
                    "-sc_threshold",
                    "0",
                ]
            )
            if preset.get("crf"):
                args.extend(["-crf", preset["crf"]])
            if preset.get("maxrate"):
                args.extend(
                    ["-maxrate", preset["maxrate"], "-bufsize", preset.get("bufsize", "3000k")]
                )
            if preset.get("scale"):
                args.extend(["-vf", f"scale={preset['scale']}"])

        args.extend(["-c:a", "aac", "-ac", "1", "-ar", "8000", "-f", "hls", "-hls_time", "2"])
        if is_recorded:
            # Recorded playback is a BOUNDED forward window (duration_s). Keep every
            # segment in the playlist (list_size 0, no delete_segments) and mark it
            # EVENT so hls.js treats it as growing VOD: it builds a buffer and plays
            # straight through instead of chasing a live edge. This is what makes
            # 4K-HEVC recorded playback smooth despite a ~1x transcode rate — the
            # previous live-style 6-segment rolling window + lowLatencyMode made the
            # player ride the edge and stall on every jitter.
            args.extend(
                [
                    "-hls_list_size",
                    "0",
                    "-hls_flags",
                    "append_list+independent_segments",
                    "-hls_playlist_type",
                    "event",
                ]
            )
        else:
            # Live: small rolling window, delete old segments.
            args.extend(
                [
                    "-hls_list_size",
                    "6",
                    "-hls_flags",
                    "delete_segments+append_list+independent_segments",
                ]
            )
        args.extend(
            [
                "-hls_segment_filename",
                os.path.join(output_dir, "%05d.ts"),
                os.path.join(output_dir, "stream.m3u8"),
            ]
        )

        return args


# =============================================================================
# Transcode Service
# =============================================================================


class TranscodeService:
    """FFmpeg-based codec detection and transcoding configuration."""

    async def detect_codec(self, rtsp_url: str) -> dict[str, Any]:
        """Probe an RTSP stream to detect codec, resolution and bitrate.

        Runs ``ffprobe`` in a subprocess and parses its JSON output.

        Args:
            rtsp_url: Fully-qualified RTSP URL.

        Returns:
            Dict with ``codec``, ``resolution``, ``bitrate_kbps``,
            ``needs_transcode``.
        """
        if not re.match(r"^rtsps?://", rtsp_url):
            return {"error": "Invalid RTSP URL scheme"}

        args = [
            "ffprobe",
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_streams",
            "-rtsp_transport",
            "tcp",
            rtsp_url,
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15.0)
        except TimeoutError:
            process.kill()
            await process.wait()
            logger.warning("ffprobe timed out for %s", _sanitize_url(rtsp_url))
            return {
                "codec": "unknown",
                "resolution": "unknown",
                "bitrate_kbps": 0,
                "needs_transcode": False,
            }
        except FileNotFoundError:
            raise StreamError("ffprobe is not installed or not on PATH")

        if process.returncode != 0:
            logger.warning(
                "ffprobe failed (rc=%s) for %s: %s",
                process.returncode,
                _sanitize_url(rtsp_url),
                stderr.decode(errors="replace")[:500],
            )
            return {
                "codec": "unknown",
                "resolution": "unknown",
                "bitrate_kbps": 0,
                "needs_transcode": False,
            }

        try:
            probe_data = json.loads(stdout.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {
                "codec": "unknown",
                "resolution": "unknown",
                "bitrate_kbps": 0,
                "needs_transcode": False,
            }

        # Find the first video stream
        video_stream: dict[str, Any] | None = None
        for stream in probe_data.get("streams", []):
            if stream.get("codec_type") == "video":
                video_stream = stream
                break

        if video_stream is None:
            return {
                "codec": "unknown",
                "resolution": "unknown",
                "bitrate_kbps": 0,
                "needs_transcode": False,
            }

        codec_name = video_stream.get("codec_name", "unknown")
        width = video_stream.get("width", 0)
        height = video_stream.get("height", 0)
        bit_rate_str = video_stream.get("bit_rate", "0")
        try:
            bitrate_kbps = int(bit_rate_str) // 1000
        except (ValueError, TypeError):
            bitrate_kbps = 0

        return {
            "codec": codec_name,
            "resolution": f"{width}x{height}" if width and height else "unknown",
            "bitrate_kbps": bitrate_kbps,
            "needs_transcode": self.needs_transcode(codec_name),
        }

    @staticmethod
    def needs_transcode(codec: str) -> bool:
        """Return True if the codec requires transcoding for browser playback."""
        return codec.lower() in ("hevc", "h265", "h.265")


# =============================================================================
# Audio Service
# =============================================================================


class AudioService:
    """Two-way audio service for camera intercom via Hikvision ISAPI."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_camera_and_adapter(
        self,
        camera_id: UUID,
        organization_id: UUID,
    ) -> tuple[Any, Any, int]:
        """Retrieve camera, create adapter, and return (camera, adapter, channel).

        The adapter is connected and ready to use.  The caller is responsible
        for disconnecting it when done (use a ``try/finally`` block).
        """
        from app.modules.cameras.models import NVR, Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
            Camera.organization_id == organization_id,
        )
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()
        if camera is None:
            raise CameraNotFoundError(camera_id)

        # Resolve connection params — prefer NVR when attached
        nvr = None
        if camera.nvr_id:
            nvr_q = select(NVR).where(
                NVR.id == camera.nvr_id,
                NVR.deleted_at.is_(None),
                NVR.organization_id == organization_id,
            )
            nvr_result = await self.db.execute(nvr_q)
            nvr = nvr_result.scalar_one_or_none()

        host = nvr.ip_address if nvr else camera.ip_address
        port = nvr.port if nvr else (camera.port or 80)
        username = nvr.username if nvr else camera.username
        password_enc = nvr.password_encrypted if nvr else camera.password_encrypted

        if not username or not password_enc:
            raise CameraError("Camera has no stored credentials")

        password = decrypt_credential(password_enc)
        channel = camera.channel_id or 1

        adapter = StreamService._create_camera_adapter(
            host=host,
            port=port,
            username=username,
            password=password,
            vendor=getattr(nvr, "vendor", None) or getattr(camera, "vendor", None),
        )
        await adapter.connect()
        return camera, adapter, channel

    async def start_audio_session(
        self,
        camera_id: UUID,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Open a two-way audio channel on the camera.

        Returns:
            Dict with ``camera_id``, ``channel``, ``status``.
        """
        camera, adapter, channel = await self._get_camera_and_adapter(camera_id, organization_id)
        try:
            result = await adapter.open_two_way_audio(channel=channel)
            return {
                "camera_id": str(camera_id),
                "channel": channel,
                "status": "open",
                "detail": result,
            }
        except Exception as e:
            logger.error("Failed to start audio session for camera %s: %s", camera_id, e)
            raise CameraError("Failed to start audio session")
        finally:
            await adapter.disconnect()

    async def stop_audio_session(
        self,
        camera_id: UUID,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Close the two-way audio channel on the camera."""
        camera, adapter, channel = await self._get_camera_and_adapter(camera_id, organization_id)
        try:
            result = await adapter.close_two_way_audio(channel=channel)
            return {
                "camera_id": str(camera_id),
                "channel": channel,
                "status": "closed",
                "detail": result,
            }
        except Exception as e:
            logger.error("Failed to stop audio session for camera %s: %s", camera_id, e)
            raise CameraError("Failed to stop audio session")
        finally:
            await adapter.disconnect()

    async def send_audio_chunk(
        self,
        camera_id: UUID,
        audio_data: bytes,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Send an audio chunk to the camera's two-way audio channel.

        Args:
            camera_id: Camera identifier.
            audio_data: Raw audio bytes (typically G.711 or PCM).
            organization_id: Tenant scope.

        Returns:
            Dict with ``camera_id``, ``bytes_sent``, ``status``.
        """
        if len(audio_data) > 64 * 1024:
            raise CameraError("Audio chunk too large (max 64KB)")

        camera, adapter, channel = await self._get_camera_and_adapter(camera_id, organization_id)
        try:
            await adapter.send_audio_data(channel=channel, data=audio_data)
            return {
                "camera_id": str(camera_id),
                "bytes_sent": len(audio_data),
                "status": "sent",
            }
        except Exception as e:
            logger.error("Failed to send audio chunk for camera %s: %s", camera_id, e)
            raise CameraError("Failed to send audio data")
        finally:
            await adapter.disconnect()


# =============================================================================
# Thermal Service
# =============================================================================


class ThermalService:
    """Thermal camera data and alerting."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_thermal_data(
        self,
        camera_id: UUID,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Retrieve thermal configuration and current readings from a camera.

        Raises ``CameraError`` if the camera is not a thermal model.
        """
        from app.modules.cameras.models import NVR, Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
            Camera.organization_id == organization_id,
        )
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()
        if camera is None:
            raise CameraNotFoundError(camera_id)

        # Verify this is a thermal camera
        camera_settings: dict[str, Any] = camera.settings or {}
        is_thermal = getattr(camera, "camera_type", None) == "thermal" or camera_settings.get(
            "thermal_enabled", False
        )
        if not is_thermal:
            raise CameraError(f"Camera {camera_id} is not a thermal camera")

        # Resolve connection params
        nvr = None
        if camera.nvr_id:
            nvr_q = select(NVR).where(
                NVR.id == camera.nvr_id,
                NVR.deleted_at.is_(None),
                NVR.organization_id == organization_id,
            )
            nvr_result = await self.db.execute(nvr_q)
            nvr = nvr_result.scalar_one_or_none()

        host = nvr.ip_address if nvr else camera.ip_address
        port = nvr.port if nvr else (camera.port or 80)
        username = nvr.username if nvr else camera.username
        password_enc = nvr.password_encrypted if nvr else camera.password_encrypted

        if not username or not password_enc:
            raise CameraError("Camera has no stored credentials")

        password = decrypt_credential(password_enc)
        channel = camera.channel_id or 1

        adapter = StreamService._create_camera_adapter(
            host=host,
            port=port,
            username=username,
            password=password,
            vendor=getattr(nvr, "vendor", None) or getattr(camera, "vendor", None),
        )
        try:
            await adapter.connect()
            thermal_config = await adapter.get_thermal_config(channel=channel)
            return {
                "camera_id": str(camera_id),
                "is_thermal": True,
                "channel": channel,
                "thermal_config": thermal_config,
                "threshold": camera_settings.get("thermal_threshold"),
            }
        except Exception as e:
            logger.error("Failed to get thermal data for camera %s: %s", camera_id, e)
            raise CameraError("Failed to get thermal data")
        finally:
            await adapter.disconnect()

    async def set_threshold_alert(
        self,
        camera_id: UUID,
        min_temp: float,
        max_temp: float,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Configure temperature threshold alerting on a thermal camera.

        Args:
            camera_id: Camera identifier.
            min_temp: Minimum temperature in Celsius (-40 to 550).
            max_temp: Maximum temperature in Celsius (-40 to 550).
            organization_id: Tenant scope.

        Returns:
            Dict with the stored threshold configuration.
        """
        from sqlalchemy.orm.attributes import flag_modified

        from app.modules.cameras.models import NVR, Camera

        # Validate temperature range
        if not (-40 <= min_temp <= 550):
            raise CameraError(f"min_temp must be between -40 and 550, got {min_temp}")
        if not (-40 <= max_temp <= 550):
            raise CameraError(f"max_temp must be between -40 and 550, got {max_temp}")
        if min_temp >= max_temp:
            raise CameraError("min_temp must be less than max_temp")

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
            Camera.organization_id == organization_id,
        )
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()
        if camera is None:
            raise CameraNotFoundError(camera_id)

        # Resolve connection params to push threshold to device
        nvr = None
        if camera.nvr_id:
            nvr_q = select(NVR).where(
                NVR.id == camera.nvr_id,
                NVR.deleted_at.is_(None),
                NVR.organization_id == organization_id,
            )
            nvr_result = await self.db.execute(nvr_q)
            nvr = nvr_result.scalar_one_or_none()

        host = nvr.ip_address if nvr else camera.ip_address
        port = nvr.port if nvr else (camera.port or 80)
        username = nvr.username if nvr else camera.username
        password_enc = nvr.password_encrypted if nvr else camera.password_encrypted

        if not username or not password_enc:
            raise CameraError("Camera has no stored credentials")

        password = decrypt_credential(password_enc)
        channel = camera.channel_id or 1

        adapter = StreamService._create_camera_adapter(
            host=host,
            port=port,
            username=username,
            password=password,
            vendor=getattr(nvr, "vendor", None) or getattr(camera, "vendor", None),
        )
        try:
            await adapter.connect()
            await adapter.set_thermal_threshold(
                channel=channel,
                min_temp=min_temp,
                max_temp=max_temp,
            )
        except Exception as e:
            logger.error("Failed to set thermal threshold for camera %s: %s", camera_id, e)
            raise CameraError("Failed to set thermal threshold on device")
        finally:
            await adapter.disconnect()

        # Persist threshold in camera settings
        threshold_config = {
            "min_temp": min_temp,
            "max_temp": max_temp,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        if camera.settings is None:
            camera.settings = {}
        camera.settings["thermal_threshold"] = threshold_config
        flag_modified(camera, "settings")
        await self.db.commit()
        await self.db.refresh(camera)

        return {
            "camera_id": str(camera_id),
            "thermal_threshold": threshold_config,
        }


# =============================================================================
# LPR Service
# =============================================================================


class LPRService:
    """License plate recognition integration.

    Captures a snapshot from the camera and sends it to an external LPR API
    for plate detection.  Results are stored as ``CameraEvent`` records.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def recognize_plate(
        self,
        camera_id: UUID,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Take a snapshot and run LPR recognition.

        The LPR API endpoint and credentials are read from the camera's
        ``settings["lpr_config"]``.  Results are persisted as a
        ``CameraEvent`` of type ``license_plate``.

        Returns:
            Dict with ``plate``, ``confidence``, ``vehicle_type``, ``event_id``.
        """
        from app.modules.cameras.models import Camera, CameraEvent

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
            Camera.organization_id == organization_id,
        )
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()
        if camera is None:
            raise CameraNotFoundError(camera_id)

        # Validate LPR config
        camera_settings: dict[str, Any] = camera.settings or {}
        lpr_config: dict[str, Any] = camera_settings.get("lpr_config", {})
        if not lpr_config or not lpr_config.get("enabled"):
            raise CameraError("LPR is not configured or not enabled for this camera")

        api_url = lpr_config.get("api_url")
        if not api_url:
            raise CameraError("LPR API URL is not configured")

        # Get snapshot
        stream_svc = StreamService(self.db)
        snapshot = await stream_svc.get_snapshot(camera_id, organization_id=organization_id)
        if snapshot is None:
            raise CameraError("Failed to capture snapshot for LPR")

        # Decrypt API key if present
        api_key: str | None = None
        api_key_enc = lpr_config.get("api_key_encrypted")
        if api_key_enc:
            api_key = decrypt_credential(api_key_enc)

        # Call LPR API — safe_http_request resolves + IP-pins the hostname to
        # prevent DNS-rebinding (TOCTOU) attacks on the attacker-controllable URL.
        # LPR providers are public services; private ranges are blocked by default.
        headers: dict[str, str] = {"Content-Type": "application/octet-stream"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            from app.core.security_utils import safe_http_request

            response = await safe_http_request(
                "POST",
                api_url,
                content=snapshot,
                headers=headers,
                timeout=30.0,
            )
            response.raise_for_status()
            lpr_result = response.json()
        except ValueError as e:
            logger.error("LPR API URL blocked (SSRF) for camera %s: %s", camera_id, e)
            raise CameraError(f"LPR API URL is not allowed: {e}")
        except Exception as e:
            logger.error("LPR API request failed for camera %s: %s", camera_id, e)
            raise CameraError("LPR API request failed")

        plate = str(lpr_result.get("plate", ""))[:20]
        try:
            confidence = min(1.0, max(0.0, float(lpr_result.get("confidence", 0))))
        except (ValueError, TypeError):
            confidence = 0.0
        vehicle_type = str(lpr_result.get("vehicle_type", "unknown"))[:50]

        # Store as camera event
        event = CameraEvent(
            camera_id=camera_id,
            event_type="license_plate",
            timestamp=datetime.now(UTC),
            metadata_json={
                "plate": plate,
                "confidence": confidence,
                "vehicle_type": vehicle_type,
            },
        )
        self.db.add(event)
        await self.db.commit()
        await self.db.refresh(event)

        return {
            "plate": plate,
            "confidence": confidence,
            "vehicle_type": vehicle_type,
            "event_id": str(event.id),
            "camera_id": str(camera_id),
        }

    async def get_config(
        self,
        camera_id: UUID,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Return the LPR configuration for a camera."""
        from app.modules.cameras.models import Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
            Camera.organization_id == organization_id,
        )
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()
        if camera is None:
            raise CameraNotFoundError(camera_id)

        camera_settings: dict[str, Any] = camera.settings or {}
        config = dict(camera_settings.get("lpr_config", {}))
        # Strip encrypted key from response
        config.pop("api_key_encrypted", None)
        return config

    async def set_config(
        self,
        camera_id: UUID,
        config: dict[str, Any],
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Update the LPR configuration for a camera.

        Accepted config keys: ``provider``, ``api_url``, ``api_key``,
        ``confidence_threshold``, ``enabled``.  The ``api_key`` is encrypted
        before storage.

        Returns:
            The stored config (without the encrypted key).
        """
        from sqlalchemy.orm.attributes import flag_modified

        from app.core.crypto import encrypt_credential
        from app.modules.cameras.models import Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
            Camera.organization_id == organization_id,
        )
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()
        if camera is None:
            raise CameraNotFoundError(camera_id)

        # Validate required fields
        allowed_keys = {"provider", "api_url", "api_key", "confidence_threshold", "enabled"}
        sanitized: dict[str, Any] = {k: v for k, v in config.items() if k in allowed_keys}

        if "api_url" in sanitized and sanitized["api_url"]:
            url = str(sanitized["api_url"])
            if not url.startswith(("http://", "https://")):
                raise CameraError("LPR api_url must start with http:// or https://")

        if "confidence_threshold" in sanitized:
            threshold = float(sanitized["confidence_threshold"])
            if not (0.0 <= threshold <= 1.0):
                raise CameraError("confidence_threshold must be between 0.0 and 1.0")
            sanitized["confidence_threshold"] = threshold

        # Encrypt API key before storing
        if "api_key" in sanitized and sanitized["api_key"]:
            sanitized["api_key_encrypted"] = encrypt_credential(sanitized.pop("api_key"))
        else:
            sanitized.pop("api_key", None)

        # Merge with existing config
        if camera.settings is None:
            camera.settings = {}
        existing_lpr: dict[str, Any] = camera.settings.get("lpr_config", {})
        existing_lpr.update(sanitized)
        existing_lpr["updated_at"] = datetime.now(UTC).isoformat()
        camera.settings["lpr_config"] = existing_lpr
        flag_modified(camera, "settings")
        await self.db.commit()
        await self.db.refresh(camera)

        # Return config without encrypted key
        response = dict(existing_lpr)
        response.pop("api_key_encrypted", None)
        return response


# =============================================================================
# Scene Labeling Service
# =============================================================================


class SceneLabelingService:
    """AI scene analysis and auto-labeling.

    Uses a configured AI vision endpoint to analyze camera snapshots and
    generate descriptive tags (e.g. ``parking-lot``, ``indoor``,
    ``low-light``).
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def analyze_scene(
        self,
        camera_id: UUID,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Capture a snapshot and analyze the scene with an AI vision model.

        The AI endpoint URL is read from the camera's
        ``settings["ai_vision_url"]`` or from the application config
        (``AI_VISION_URL`` env var).

        Returns:
            Dict with ``labels`` (list of strings) and ``analyzed_at``.
        """
        import base64

        from sqlalchemy.orm.attributes import flag_modified

        from app.modules.cameras.models import Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
            Camera.organization_id == organization_id,
        )
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()
        if camera is None:
            raise CameraNotFoundError(camera_id)

        # Take snapshot
        stream_svc = StreamService(self.db)
        snapshot = await stream_svc.get_snapshot(camera_id, organization_id=organization_id)
        if snapshot is None:
            raise CameraError("Failed to capture snapshot for scene analysis")

        # Resolve AI vision endpoint
        camera_settings: dict[str, Any] = camera.settings or {}
        ai_url_from_settings = camera_settings.get("ai_vision_url")
        ai_url = ai_url_from_settings or os.environ.get("AI_VISION_URL")
        if not ai_url:
            raise CameraError("AI vision endpoint is not configured")

        # SSRF: safe_http_request (below) resolves + IP-pins the hostname for
        # both URL sources, closing the DNS-rebind hole. The admin-configured
        # env-var endpoint (AI_VISION_URL — used only when the per-camera
        # setting is empty) may legitimately live on the LAN (on-prem vision
        # model), so that host is trusted to permit private ranges; the IP-pin
        # and the metadata block still apply. Per-camera (user-supplied)
        # ai_vision_url gets no such trust — internal/private targets stay blocked.

        # Build request payload (OpenAI-compatible vision API)
        image_b64 = base64.b64encode(snapshot).decode("ascii")
        prompt = (
            "Describe this camera scene in 3-5 tags: location type, activity, "
            "lighting conditions. Return only comma-separated tags."
        )
        payload: dict[str, Any] = {
            "model": camera_settings.get("ai_vision_model", "gpt-4o-mini"),
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{image_b64}",
                            },
                        },
                    ],
                }
            ],
            "max_tokens": 100,
        }

        # Call AI vision API
        headers: dict[str, str] = {"Content-Type": "application/json"}
        encrypted_key = camera_settings.get("ai_api_key_encrypted")
        if encrypted_key:
            from app.core.crypto import decrypt_credential

            ai_api_key = decrypt_credential(encrypted_key)
            headers["Authorization"] = f"Bearer {ai_api_key}"

        try:
            from urllib.parse import urlparse

            from app.core.security_utils import safe_http_request

            # Trust the admin env-var endpoint's host (permit LAN/on-prem) only
            # when the URL did NOT come from per-camera settings; user-supplied
            # URLs are never host-trusted. The IP-pin/metadata block apply either way.
            _ai_host = urlparse(ai_url).hostname or ""
            _allow_hosts = (
                frozenset({_ai_host}) if (not ai_url_from_settings and _ai_host) else frozenset()
            )
            response = await safe_http_request(
                "POST",
                ai_url,
                json=payload,
                headers=headers,
                timeout=30.0,
                allow_hosts=_allow_hosts,
            )
            response.raise_for_status()
            ai_result = response.json()
        except ValueError as e:
            logger.error("AI vision URL blocked (SSRF) for camera %s: %s", camera_id, e)
            raise CameraError(f"AI vision URL is not allowed: {e}")
        except Exception as e:
            logger.error("AI vision API request failed for camera %s: %s", camera_id, e)
            raise CameraError("AI vision API request failed")

        # Parse tags from response
        raw_text = ""
        choices = ai_result.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            raw_text = message.get("content", "")

        labels = [
            tag.strip().lower()[:50]
            for tag in raw_text.split(",")
            if tag.strip() and re.fullmatch(r"[a-z0-9 _-]+", tag.strip().lower())
        ]

        # Store in camera settings
        analyzed_at = datetime.now(UTC)
        if camera.settings is None:
            camera.settings = {}
        camera.settings["scene_labels"] = {
            "labels": labels,
            "analyzed_at": analyzed_at.isoformat(),
        }
        flag_modified(camera, "settings")
        await self.db.commit()
        await self.db.refresh(camera)

        return {
            "labels": labels,
            "analyzed_at": analyzed_at.isoformat(),
            "camera_id": str(camera_id),
        }

    async def get_labels(
        self,
        camera_id: UUID,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Return previously computed scene labels for a camera."""
        from app.modules.cameras.models import Camera

        q = select(Camera).where(
            Camera.id == camera_id,
            Camera.deleted_at.is_(None),
            Camera.organization_id == organization_id,
        )
        result = await self.db.execute(q)
        camera = result.scalar_one_or_none()
        if camera is None:
            raise CameraNotFoundError(camera_id)

        camera_settings: dict[str, Any] = camera.settings or {}
        scene_data: dict[str, Any] = camera_settings.get("scene_labels", {})

        return {
            "labels": scene_data.get("labels", []),
            "analyzed_at": scene_data.get("analyzed_at"),
            "camera_id": str(camera_id),
        }
