# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Cameras Module API Endpoints
==========================================

REST API endpoints for camera management and streaming.
"""

import asyncio
import contextlib
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Any, Literal
from urllib.parse import quote
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, WebSocket, status
from fastapi.responses import FileResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_credential, encrypt_credential
from app.core.dependencies import (
    CurrentUser,
    is_unscoped_superuser,
    org_scope_or_platform,
    require_permissions,
)
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.db import get_session
from app.modules.cameras.config_write import staged_camera_write
from app.modules.cameras.models import NVR as NVRModel
from app.modules.cameras.schemas import (
    # Two-way Audio
    AudioSessionResponse,
    AudioSessionStopResponse,
    BulkAcknowledgeRequest,
    BulkAcknowledgeResponse,
    CameraAccessCheckResponse,
    # Camera RBAC schemas
    CameraAccessGrantCreate,
    CameraAccessGrantListResponse,
    CameraAccessGrantResponse,
    CameraAccessGrantUpdate,
    CameraCreateRequest,
    CameraEventListResponse,
    CameraEventResponse,
    CameraHealthHistoryResponse,
    CameraHealthResponse,
    CameraListResponse,
    CameraReportListResponse,
    # Scheduled Reports
    CameraReportResponse,
    CameraResponse,
    # Response model schemas (enterprise completeness)
    CameraStatsResponse,
    CameraTimelineResponse,
    CameraUpdateRequest,
    # Codec Detection
    CodecDetectionResponse,
    CrossSiteRecordingResult,
    CrossSiteRecordingSearchRequest,
    CrossSiteRecordingSearchResponse,
    DeletedResponse,
    # P1 feature schemas
    FaceDetectionResponse,
    FaceDetectionUpdateRequest,
    FleetHealthSummary,
    GroupCreateRequest,
    GroupCreateResponse,
    GroupDetailResponse,
    GroupListResponse,
    GroupUpdateRequest,
    HLSHeartbeatResponse,
    # HLS Streaming
    HLSSessionStartRequest,
    HLSSessionStartResponse,
    HolidayListResponse,
    HolidayScheduleResponse,
    HolidayScheduleUpdateRequest,
    HolidayUpdateRequest,
    ImageSettingsResponse,
    IntrusionDetectionResponse,
    IntrusionDetectionUpdateRequest,
    LineCrossingResponse,
    LineCrossingUpdateRequest,
    LockRecordingResponse,
    # LPR
    LPRConfigRequest,
    LPRConfigResponse,
    LPRReadResult,
    LPRSearchResponse,
    # P0 feature schemas
    MotionDetectionResponse,
    MotionDetectionUpdateRequest,
    NVRChannelsListResponse,
    NVRChannelStatusResponse,
    NVRConnectionTestRequest,
    NVRConnectionTestResponse,
    NVRCreateRequest,
    NVRDiscoveryResponse,
    NVRImportRequest,
    NVRImportResponse,
    NVRListResponse,
    NVRNetworkResponse,
    NVRPlaybackResponse,
    NVRRebootResponse,
    NVRRecordingSearchResponse,
    NVRResponse,
    NVRStatsResponse,
    NVRStorageSummary,
    NVRSyncResponse,
    NVRSystemInfoResponse,
    NVRUpdateRequest,
    PlaybackHLSStartRequest,
    PlaybackUrlResponse,
    PrivacyMaskResponse,
    PrivacyMaskUpdateRequest,
    PTZActionResponse,
    PTZAutoTrackingRequest,
    # PTZ Auto-tracking
    PTZAutoTrackingResponse,
    PTZPatrolCreateRequest,
    PTZPatrolResponse,
    PTZPatrolStartStop,
    PTZPresetsListResponse,
    RecordingScheduleResponse,
    RecordingScheduleTemplateCreateRequest,
    RecordingScheduleTemplateResponse,
    RecordingScheduleUpdateRequest,
    RecordingSearchResponse,
    # AI Scene Labeling
    SceneLabelResponse,
    SmartCapabilitiesResponse,
    StandaloneCameraImportRequest,
    StandaloneCameraImportResponse,
    StatusIdResponse,
    StatusResponse,
    StreamStatsResponse,
    StreamTokenResponse,
    StreamUrlResponse,
    # Thermal Camera
    ThermalCapabilitiesResponse,
    ThermalThresholdRequest,
    ThermalThresholdResponse,
    # Time Drift
    TimeDriftEntry,
    TimeDriftSummaryResponse,
    TimelineSegment,
    UnacknowledgedCountResponse,
    VideoExportRequest,
    ViewCreateRequest,
    ViewCreateResponse,
    ViewListResponse,
    ViewUpdateRequest,
)
from app.modules.cameras.schemas import (
    NVRRecordingStatusResponse as NVRRecStatusResponse,
)
from app.modules.cameras.service import (
    CameraError,
    CameraEventService,
    CameraNotFoundError,
    CameraService,
    NVRDiscoveryService,
    NVRNotFoundError,
    NVRService,
    PTZService,
    RecordingError,
    RecordingService,
    StreamError,
    StreamService,
)
from app.services.audit import AuditAction, AuditService, ResourceType

if TYPE_CHECKING:
    from app.modules.cameras.service import CameraAccessService

logger = logging.getLogger(__name__)


async def _authenticate_media_request(
    request: Request,
    session: AsyncSession,
    query_token: str | None,
    *,
    camera_id: UUID | None = None,
) -> Any:
    """Authenticate snapshot/MJPEG requests and enforce session revocation.

    For stream-scoped tokens (short-lived, issued via /stream-token), validates
    that the token was issued for the requested camera_id.
    """
    from app.core.dependencies import _get_user_by_id, _load_user_permissions
    from app.core.security import verify_token as _verify_token

    # Track the credential SOURCE. Precedence Bearer > query > cookie (unchanged),
    # but a token taken from the URL QUERY must be a short-lived stream-scoped
    # token — a full access JWT in a URL leaks via browser history,
    # proxy/access logs, and Referer headers. Full JWTs are accepted only via the
    # Authorization header or the httpOnly cookie.
    auth_header = request.headers.get("authorization", "")
    jwt_token: str | None = None
    token_source = None
    if auth_header.lower().startswith("bearer "):
        jwt_token, token_source = auth_header[7:], "bearer"
    elif query_token:
        jwt_token, token_source = query_token, "query"
    else:
        cookie_token = request.cookies.get("freesdn_access")
        if cookie_token:
            jwt_token, token_source = cookie_token, "cookie"

    if not jwt_token:
        raise HTTPException(status_code=401, detail="Authentication required")

    payload = await _verify_token(jwt_token, token_type="access")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    # a query-string credential MUST be a stream-scoped token.
    if token_source == "query" and payload.get("scope") != "stream":
        raise HTTPException(
            status_code=401,
            detail="A query-string media token must be a stream-scoped token (use ?token from /stream-token)",
        )

    # Enforce stream-scoped token: must match the requested camera.
    # Reject stream tokens missing the camera_id claim (defense-in-depth:
    # prevents a compromised token without camera_id from accessing any camera).
    if payload.get("scope") == "stream" and camera_id is not None:
        token_camera = payload.get("camera_id")
        if not token_camera or str(camera_id) != str(token_camera):
            raise HTTPException(status_code=403, detail="Token not valid for this camera")

    user_id = payload.get("sub")
    user = await _get_user_by_id(session, user_id) if user_id else None
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    # Verify org_id claim on stream tokens (defense-in-depth: prevents cross-org access)
    if payload.get("scope") == "stream":
        token_org = payload.get("org_id")
        if token_org and str(user.organization_id) != str(token_org):
            raise HTTPException(status_code=403, detail="Token organization mismatch")

    current_tv = getattr(user, "token_version", 0) or 0
    if payload.get("tv", 0) != current_tv:
        raise HTTPException(status_code=401, detail="Session has been revoked")

    # Wrap the ORM User in a CurrentUser so the media path carries the SAME
    # principal interface as every dependency-authenticated endpoint — in
    # particular .can_access_site(), which _enforce_camera_access ->
    # assert_can_access_site calls. Returning the raw ORM
    # User here raised "'User' object has no attribute 'can_access_site'" and
    # 500'd every snapshot/MJPEG request. Mirrors get_current_user_optional:
    # _get_user_by_id already selectinload's site_access, so no lazy load.
    site_accesses = user.site_access if getattr(user, "site_access", None) else []
    return CurrentUser(
        user=user,
        permissions=await _load_user_permissions(user),
        token_claims=payload,
        accessible_site_ids={sa.site_id for sa in site_accesses},
        site_access_levels={sa.site_id: sa.access_level for sa in site_accesses},
    )


# =============================================================================
# MJPEG Stream Pool — shared resources for scalable multi-channel streaming
# =============================================================================


class _StreamPool:
    """
    Manages a global pool of active MJPEG streams to support up to 64+
    concurrent channels without exhausting resources.

    Key features:
      - Tracks active stream count for adaptive frame-rate
      - Per-NVR httpx client reuse (connection pooling)
      - Configurable FPS tiers based on load
    """

    FPS_TIERS = [
        (8, 10.0),  # ≤8 streams  → 10 fps (~100ms)
        (16, 5.0),  # ≤16 streams → 5 fps  (~200ms)
        (32, 3.0),  # ≤32 streams → 3 fps  (~333ms)
        (64, 2.0),  # ≤64 streams → 2 fps  (~500ms)
    ]
    FALLBACK_FPS = 1.0  # >64 streams

    def __init__(self) -> None:
        self._active: int = 0
        self._lock = asyncio.Lock()

    @property
    def active_streams(self) -> int:
        return self._active

    @property
    def target_fps(self) -> float:
        for threshold, fps in self.FPS_TIERS:
            if self._active <= threshold:
                return fps
        return self.FALLBACK_FPS

    @property
    def frame_interval(self) -> float:
        return 1.0 / self.target_fps

    async def acquire(self) -> int:
        async with self._lock:
            self._active += 1
            count = self._active
            logger.debug("Stream acquired — active=%d  target_fps=%.1f", count, self.target_fps)
            return count

    async def release(self) -> int:
        async with self._lock:
            self._active = max(0, self._active - 1)
            count = self._active
            logger.debug("Stream released — active=%d", count)
            return count


_stream_pool = _StreamPool()


# =============================================================================
# Per-NVR Connection Limiter — prevents overwhelming individual NVRs
# =============================================================================


class _NvrConnectionLimiter:
    """
    Enforces a per-NVR concurrent connection cap.

    Hikvision NVRs typically support 4-6 simultaneous MJPEG/ISAPI streaming
    sessions before degrading (dropped frames, 503 errors).  This limiter
    tracks connections per unique ``host:port`` and rejects new ones once
    the cap is reached -- allowing the frontend to degrade gracefully to
    snapshot mode instead of overloading the hardware.

    The snapshot cache counts as 1 connection per unique channel (not per
    viewer), since it deduplicates fetches.
    """

    MAX_PER_NVR = 6  # Hikvision safe limit for concurrent streams

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._lock = asyncio.Lock()

    def _key(self, host: str, port: int) -> str:
        return f"{host}:{port}"

    async def acquire(self, host: str, port: int) -> bool:
        """Try to acquire a connection slot.  Returns False if NVR is at capacity."""
        key = self._key(host, port)
        async with self._lock:
            if key not in self._counts:
                self._counts[key] = 0

            # Non-blocking check using our own count (avoids private Semaphore._value)
            if self._counts[key] >= self.MAX_PER_NVR:
                logger.debug(
                    "NVR limiter: at capacity for %s (%d/%d)",
                    key,
                    self._counts[key],
                    self.MAX_PER_NVR,
                )
                return False

            self._counts[key] += 1
            logger.debug(
                "NVR limiter: acquired %s (%d/%d)", key, self._counts[key], self.MAX_PER_NVR
            )
        return True

    async def release(self, host: str, port: int) -> None:
        """Release a connection slot."""
        key = self._key(host, port)
        async with self._lock:
            self._counts[key] = max(0, self._counts.get(key, 1) - 1)
            logger.debug(
                "NVR limiter: released %s (%d/%d)", key, self._counts[key], self.MAX_PER_NVR
            )

    def get_stats(self) -> dict[str, dict[str, int]]:
        """Per-NVR connection stats for the /streams/stats endpoint."""
        return {
            key: {
                "active": count,
                "max": self.MAX_PER_NVR,
                "available": self.MAX_PER_NVR - count,
            }
            for key, count in self._counts.items()
            if count > 0  # only return NVRs with active connections
        }


_nvr_limiter = _NvrConnectionLimiter()


# =============================================================================
# SSRF pin — resolve+validate+pin a camera URL host (DNS-rebinding defense)
# =============================================================================


def _pin_url_to_resolved_ip(url: str) -> tuple[str, dict[str, str]]:
    """Resolve ``url``'s host ONCE, validate every resolved IP against the camera
    SSRF guard, and return ``(pinned_url, headers)`` with the host replaced by the
    validated IP literal and the original ``Host`` preserved in ``headers``.

    Pinning to the resolved IP stops httpx re-resolving the hostname on later
    requests from the same client — defeating a DNS-rebinding (TOCTOU) attack
    that would otherwise redirect a camera fetch to a cloud-metadata/internal
    endpoint after the camera passed creation-time validation. No-op for an
    IP-literal host (resolves to itself). Raises ValueError when the host is
    unresolvable or any resolved IP is blocked — callers MUST refuse the fetch.
    """
    import ipaddress
    import socket
    from urllib.parse import urlsplit, urlunsplit

    from app.modules.cameras.schemas import _is_address_allowed

    parts = urlsplit(url)
    hostname = parts.hostname
    if not hostname:
        raise ValueError("URL has no host")
    try:
        infos = socket.getaddrinfo(hostname, parts.port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"host {hostname!r} unresolvable") from exc
    ips = {ai[4][0] for ai in infos}
    if not ips or not all(_is_address_allowed(ipaddress.ip_address(ip)) for ip in ips):
        raise ValueError(f"host {hostname!r} resolves to a blocked IP")
    pinned = sorted(ips)[0]
    netloc = f"[{pinned}]" if ":" in pinned else pinned
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    pinned_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return pinned_url, {"Host": parts.netloc}


# =============================================================================
# Snapshot Cache — one fetch per camera channel shared across all viewers
# =============================================================================


class _SnapshotCache:
    """
    Caches the latest JPEG snapshot per (host:port, isapi_channel) key.

    When the first viewer subscribes, a background fetch task is started.
    Subsequent viewers for the same channel read from the shared cache,
    eliminating duplicate ISAPI /picture requests (e.g., 4 viewers = 1 fetch
    instead of 4 per interval).

    The fetch task stops automatically when the last viewer unsubscribes.
    """

    def __init__(self) -> None:
        self._frames: dict[str, bytes] = {}  # key -> latest JPEG
        self._viewers: dict[str, int] = {}  # key -> viewer count
        self._tasks: dict[str, asyncio.Task[None]] = {}  # key -> fetch task
        self._events: dict[str, asyncio.Event] = {}  # key -> new-frame signal
        self._nvr_held: set[str] = set()  # keys with active NVR slot
        self._lock = asyncio.Lock()

    @staticmethod
    def _key(host: str, port: int, isapi_ch: int) -> str:
        return f"{host}:{port}/{isapi_ch}"

    async def subscribe(
        self,
        host: str,
        port: int,
        isapi_ch: int,
        auth: Any,
        snapshot_url: str,
    ) -> str:
        """Register a viewer. Starts the fetch task if first subscriber."""
        key = self._key(host, port, isapi_ch)
        async with self._lock:
            self._viewers[key] = self._viewers.get(key, 0) + 1
            if key not in self._tasks or self._tasks[key].done():
                # Acquire NVR connection slot (1 per channel, not per viewer)
                if not await _nvr_limiter.acquire(host, port):
                    # NVR at capacity — don't start task, let caller degrade
                    self._viewers[key] = max(0, self._viewers[key] - 1)
                    if self._viewers[key] == 0:
                        self._viewers.pop(key, None)
                    logger.warning(
                        "Snapshot cache: NVR at capacity for %s, skipping",
                        key,
                    )
                    return key

                self._events[key] = asyncio.Event()
                self._nvr_held.add(key)
                self._tasks[key] = asyncio.create_task(
                    self._fetch_loop(key, host, port, auth, snapshot_url)
                )
                logger.info(
                    "Snapshot cache: started fetch for %s (viewers=%d)",
                    key,
                    self._viewers[key],
                )
            else:
                logger.debug(
                    "Snapshot cache: +1 viewer for %s (viewers=%d)",
                    key,
                    self._viewers[key],
                )
        return key

    async def unsubscribe(self, key: str) -> None:
        """Remove a viewer. Stops the fetch task when count hits zero."""
        async with self._lock:
            self._viewers[key] = max(0, self._viewers.get(key, 1) - 1)
            if self._viewers[key] == 0:
                task = self._tasks.pop(key, None)
                if task and not task.done():
                    task.cancel()
                self._frames.pop(key, None)
                self._events.pop(key, None)
                self._viewers.pop(key, None)
                # Release NVR slot only if still held (may have been released
                # by a crashed _fetch_loop already — prevents double-release)
                if key in self._nvr_held:
                    self._nvr_held.discard(key)
                    nvr_part = key.rsplit("/", 1)[0]  # "host:port"
                    if ":" in nvr_part:
                        h, p = nvr_part.rsplit(":", 1)
                        with contextlib.suppress(ValueError, TypeError):
                            await _nvr_limiter.release(h, int(p))
                logger.info("Snapshot cache: stopped fetch for %s", key)

    async def wait_frame(self, key: str) -> bytes | None:
        """Wait for the next frame, returns JPEG bytes or None if stopped."""
        evt = self._events.get(key)
        if not evt:
            return None
        # Wait for next set() — do NOT clear before wait (race condition).
        # Instead, clear AFTER wait returns so we don't miss a frame that
        # arrives between clear and wait.
        try:
            await asyncio.wait_for(evt.wait(), timeout=10.0)
        except TimeoutError:
            return None
        evt.clear()
        return self._frames.get(key)

    def get_frame(self, key: str) -> bytes | None:
        """Get the latest cached frame without waiting."""
        return self._frames.get(key)

    # the
    # caller previously did ``len(_snapshot_cache._viewers)`` which
    # is a private name and races against the snapshot fetch loop's
    # writes. Expose a tiny purpose-built accessor instead.
    def public_stats(self) -> dict[str, int]:
        """Return aggregate (non-identifying) snapshot-cache stats.

        Does NOT leak the per-channel viewer map — only the cardinality
        of active channels and total viewer count. Both are safe to
        surface in a /streams/stats endpoint.
        """
        return {
            "channels": len(self._viewers),
            "viewers": sum(self._viewers.values()) if self._viewers else 0,
        }

    async def _fetch_loop(
        self,
        key: str,
        host: str,
        port: int,
        auth: Any,
        snapshot_url: str,
    ) -> None:
        """Background task: fetch snapshots at pool-managed intervals."""
        import httpx

        # SSRF / DNS-rebinding hardening: pin the reused (Digest-authed) client to
        # the validated IP so httpx can't re-resolve the hostname mid-loop and be
        # rebound to a metadata/internal endpoint (TOCTOU). See _pin_url_to_resolved_ip.
        try:
            snapshot_url, _pin_headers = _pin_url_to_resolved_ip(snapshot_url)
        except ValueError as exc:
            logger.warning("snapshot fetch refused (SSRF) key=%s: %s", key, exc)
            return

        consecutive_errors = 0
        try:
            async with httpx.AsyncClient(
                auth=auth,
                timeout=httpx.Timeout(10.0, connect=5.0),
                limits=httpx.Limits(max_connections=2, max_keepalive_connections=1),
                headers=_pin_headers,
            ) as client:
                while self._viewers.get(key, 0) > 0:
                    interval = _stream_pool.frame_interval
                    try:
                        resp = await client.get(snapshot_url)
                        if resp.status_code == 200 and resp.content:
                            # Update frame and signal under lock to avoid
                            # race with unsubscribe() removing the event
                            async with self._lock:
                                if key in self._events:
                                    self._frames[key] = resp.content
                                    self._events[key].set()
                            consecutive_errors = 0
                        else:
                            consecutive_errors += 1
                    except (httpx.RemoteProtocolError, httpx.ReadError):
                        break
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        consecutive_errors += 1

                    if consecutive_errors >= 10:
                        logger.warning("Snapshot cache: 10 errors on %s, stopping", key)
                        break
                    elif consecutive_errors > 0:
                        await asyncio.sleep(min(interval * (1 + consecutive_errors), 5.0))
                    else:
                        await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Snapshot cache: fetch loop crashed for %s", key)
        finally:
            # Release NVR slot when task exits (crash, errors, cancellation)
            # to prevent phantom slot leaks. Uses _nvr_held set to coordinate
            # with unsubscribe() and prevent double-release.
            async with self._lock:
                if key in self._nvr_held:
                    self._nvr_held.discard(key)
                    with contextlib.suppress(Exception):
                        await _nvr_limiter.release(host, port)


_snapshot_cache = _SnapshotCache()


# =============================================================================
# Adapter Connection Cache — reuses authenticated HikvisionAdapter instances
# =============================================================================
#
# the legacy NVR endpoints
# (system-info, network, recording-status, storage, etc.) each created
# a fresh ``HikvisionAdapter`` per request, paying the full TCP +
# Digest auth handshake (~200ms) on every dashboard tab. The dashboard
# hits 6+ endpoints concurrently per NVR. Replace with a small
# process-local LRU keyed by ``(host, port, username)`` with a 30-second
# TTL (mirrors the Proxmox ``_ConnectionCache`` pattern).
#
# Adapters cached here are reused — callers must NOT call
# ``adapter.disconnect()`` on a cached instance; use the
# ``get_or_create_hikvision_adapter`` context-manager wrapper which
# handles ref-counting + lifecycle.


class _HikvisionAdapterCache:
    """LRU cache of authenticated HikvisionAdapter instances.

    Keyed by ``(host, port, username)``; password is implicitly
    pinned (an adapter is only retrieved by callers passing the
    same credentials). Entries expire after :attr:`_TTL_SECONDS`.
    """

    _TTL_SECONDS = 30
    _MAX_ENTRIES = 32

    def __init__(self) -> None:
        # value = (cached_at_monotonic, adapter)
        self._cache: dict[tuple[str, int, str], tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _make_key(host: str, port: int, username: str) -> tuple[str, int, str]:
        return (host, int(port), username)

    async def get(self, host: str, port: int, username: str) -> Any | None:
        import time

        async with self._lock:
            entry = self._cache.get(self._make_key(host, port, username))
            if not entry:
                return None
            cached_at, adapter = entry
            if time.monotonic() - cached_at >= self._TTL_SECONDS:
                # Expired — drop the entry and the caller will create
                # a fresh adapter. We do NOT close the expired adapter
                # here because another request may still be using it.
                self._cache.pop(self._make_key(host, port, username), None)
                return None
            # Mark it freshly-used (simple LRU).
            self._cache[self._make_key(host, port, username)] = (
                time.monotonic(),
                adapter,
            )
            return adapter

    async def put(
        self,
        host: str,
        port: int,
        username: str,
        adapter: Any,
    ) -> None:
        import time

        async with self._lock:
            self._cache[self._make_key(host, port, username)] = (
                time.monotonic(),
                adapter,
            )
            # Best-effort cap — drop the oldest entry over the limit.
            # Closing the evicted adapter is fire-and-forget so we
            # don't block the lock on a network round-trip.
            if len(self._cache) > self._MAX_ENTRIES:
                oldest_key = min(
                    self._cache.items(),
                    key=lambda kv: kv[1][0],
                )[0]
                _, evicted = self._cache.pop(oldest_key)
                with contextlib.suppress(Exception):
                    # Attach a done-callback so a failed disconnect()
                    # surfaces in logs instead of being a silent
                    # orphan task. Eviction is best-effort; the task
                    # is short-lived (httpx.aclose) and its result is
                    # only useful as a diagnostic.
                    _t = asyncio.create_task(evicted.disconnect())
                    # Retain a STRONG ref: the event loop only weakly references
                    # tasks, so a bare create_task held in a local can be
                    # GC-killed before disconnect() runs, leaking the adapter's
                    # httpx client on every eviction.
                    _HIKVISION_EVICT_TASKS.add(_t)

                    def _on_disconnect_done(t: "asyncio.Task[Any]") -> None:
                        _HIKVISION_EVICT_TASKS.discard(t)
                        if t.cancelled():
                            return
                        e = t.exception()
                        if e is not None:
                            import logging as _lg

                            _lg.getLogger(__name__).debug(
                                "Hikvision adapter evicted disconnect failed: %s",
                                e,
                            )

                    _t.add_done_callback(_on_disconnect_done)


# Strong refs for fire-and-forget eviction disconnect() tasks so they aren't
# GC-killed before completing.
_HIKVISION_EVICT_TASKS: set["asyncio.Task[Any]"] = set()

_hikvision_adapter_cache = _HikvisionAdapterCache()


@contextlib.asynccontextmanager
async def get_or_create_hikvision_adapter(
    host: str,
    port: int,
    username: str,
    password: str,
):
    """Yield a connected ``HikvisionAdapter``, reusing from the LRU.

    Callers should use this in a ``with`` block instead of manually
    constructing + ``disconnect()``-ing — the cache owns the
    lifecycle. Cache misses transparently create a fresh adapter and
    put it into the cache so the next request gets a warm connection.
    """
    from app.adapters.hikvision.adapter import HikvisionAdapter

    cached = await _hikvision_adapter_cache.get(host, port, username)
    if cached is not None:
        # Hot path — adapter is already connected.
        yield cached
        return

    adapter = HikvisionAdapter(
        host=host,
        username=username,
        password=password,
        port=port,
    )
    await adapter.connect()
    await _hikvision_adapter_cache.put(host, port, username, adapter)
    yield adapter


router = APIRouter(tags=["Cameras"])


def get_camera_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CameraService:
    return CameraService(db=session)


def get_stream_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> StreamService:
    return StreamService(db=session)


def get_recording_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RecordingService:
    return RecordingService(db=session)


def get_nvr_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> NVRService:
    return NVRService(db=session)


def get_ptz_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PTZService:
    return PTZService(db=session)


def get_event_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CameraEventService:
    return CameraEventService(db=session)


def get_discovery_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> NVRDiscoveryService:
    return NVRDiscoveryService(db=session)


# =============================================================================
# Helpers
# =============================================================================


async def _resolve_credentials(
    camera: Any,
    session: AsyncSession,
) -> tuple[str, int, str, str]:
    """
    Resolve host / port / username / password for a camera.
    Uses the parent NVR's credentials when the camera is NVR-attached.
    Returns (host, port, username, password) or raises HTTPException.
    """
    nvr = None
    if camera.nvr_id:
        # SECURITY: filter by camera's org to prevent cross-tenant NVR credential access
        result = await session.execute(
            select(NVRModel).where(
                NVRModel.id == camera.nvr_id,
                NVRModel.organization_id == camera.organization_id,
            )
        )
        nvr = result.scalar_one_or_none()

    host = nvr.ip_address if nvr else camera.ip_address
    port = nvr.port if nvr else (camera.port or 80)
    username = nvr.username if nvr else camera.username
    password_enc = nvr.password_encrypted if nvr else camera.password_encrypted

    if not username or not password_enc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No credentials available for this camera",
        )

    password = decrypt_credential(password_enc)
    return host, port, username, password


# =============================================================================
# Camera CRUD Endpoints
# =============================================================================


@router.get("/", response_model=CameraListResponse)
async def list_cameras(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    site_id: UUID | None = None,
    nvr_id: UUID | None = None,
    status: str | None = None,
    search: str | None = Query(None, max_length=255),
    vendor: str | None = Query(None, max_length=100),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Any:
    """List all cameras with optional filters (server-side search + pagination)."""
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    cameras = await service.list_cameras(
        site_id=site_id,
        nvr_id=nvr_id,
        status=status,
        search=search,
        vendor=vendor,
        limit=limit,
        offset=offset,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    # Batched parent-NVR resolution (id+name) so the UI can filter/group by NVR
    # without dereferencing the lazy="raise" Camera.nvr relationship (no N+1).
    await service.attach_nvr_refs(cameras)
    total = await service.count_cameras(
        site_id=site_id,
        nvr_id=nvr_id,
        status=status,
        search=search,
        vendor=vendor,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    return {"items": cameras, "total": total, "limit": limit, "offset": offset}


@router.get("/stats", response_model=CameraStatsResponse)
async def get_camera_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    site_id: UUID | None = None,
) -> Any:
    """Get camera statistics."""
    # R5 site-grant: a site-limited caller's aggregate must not span sibling
    # sites. Fold the per-user grant (no-op for super/org-admin).
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    return await service.get_camera_stats(
        site_id=site_id,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )


@router.get("/{camera_id}", response_model=CameraResponse)
async def get_camera(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
) -> Any:
    """Get a camera by ID."""
    try:
        cam = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
        assert_can_access_site(current_user, cam.site_id, detail="Camera not found")
        return cam
    except CameraNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Camera not found",
        )


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=CameraResponse)
async def create_camera(
    body: CameraCreateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
) -> Any:
    """Create a new camera."""
    data = body.model_dump(exclude_unset=True)
    # a site-limited user may only create cameras in granted sites.
    assert_can_access_site(current_user, data.get("site_id"), detail="Site not found")
    # Encrypt password if provided
    if "password" in data:
        data["password_encrypted"] = encrypt_credential(data.pop("password"))
    # resolve the owning org through org_scope_or_platform so a
    # scoped super_admin key (org=None) fails closed (403) BEFORE the row is
    # created — never an org=None orphan. Identical to current_user.organization_id
    # for an org user (own org) and an unscoped super_admin (None / platform).
    data["organization_id"] = org_scope_or_platform(current_user)
    # TI-04: the per-user grant check above is a NO-OP for org_admin / grant-less
    # users, and the camera.site_id DB FK targets the GLOBAL core.sites table with
    # no org constraint — so without this an org-A admin could attach an org-B
    # site_id (cross-org dangling FK / integrity break). Verify membership
    # explicitly (mirrors voip's _assert_site_in_org).
    if data.get("site_id") is not None:
        from sqlalchemy import select as _select

        from app.models.core import Site as _Site

        site_ok = await service.db.scalar(
            _select(_Site.id).where(
                _Site.id == data["site_id"],
                _Site.organization_id == current_user.organization_id,
                _Site.deleted_at.is_(None),
            )
        )
        if not site_ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    camera = await service.create_camera(data)
    # Audit log
    audit = AuditService(db=service.db)
    await audit.log(
        action=AuditAction.CREATE,
        resource_type=ResourceType.CAMERA,
        resource_id=camera.id,
        resource_name=getattr(camera, "name", None),
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        changes={"name": {"old": None, "new": data.get("name")}},
    )
    return camera


@router.patch("/{camera_id}", response_model=CameraResponse)
async def update_camera(
    camera_id: UUID,
    body: CameraUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
) -> Any:
    """Update a camera."""
    try:
        # Verify camera belongs to user's org before updating
        cam = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
        assert_can_access_site(current_user, cam.site_id, detail="Camera not found")
        data = body.model_dump(exclude_unset=True)

        # Persist stream_encryption_key into the settings JSONB
        enc_key = data.pop("stream_encryption_key", None)
        if enc_key is not None:
            settings = dict(getattr(cam, "settings", None) or {})
            if enc_key == "":
                settings.pop("stream_encryption_key", None)
            else:
                settings["stream_encryption_key"] = enc_key
            data["settings"] = settings

        updated = await service.update_camera(
            camera_id, data, organization_id=org_scope_or_platform(current_user)
        )
        # Audit log
        audit = AuditService(db=service.db)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            resource_name=getattr(updated, "name", None),
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            # CONV2-005: rtsp_*_stream URLs embed credentials (rtsp://user:pass@host).
            # The audit sanitizer is key-name based and would store these verbatim in
            # /security/audit-logs — mask the credential-bearing URL fields here.
            changes={
                k: {"new": ("[redacted]" if k in ("rtsp_main_stream", "rtsp_sub_stream") else v)}
                for k, v in data.items()
                if k != "settings"
            },
        )
        return updated
    except CameraNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Camera not found",
        )


@router.delete("/{camera_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_camera(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
) -> None:
    """Delete a camera."""
    try:
        # Verify camera belongs to user's org before deleting
        cam = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
        assert_can_access_site(current_user, cam.site_id, detail="Camera not found")
        await service.delete_camera(camera_id, organization_id=org_scope_or_platform(current_user))
        # Audit log
        audit = AuditService(db=service.db)
        await audit.log(
            action=AuditAction.DELETE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            resource_name=getattr(cam, "name", None),
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
        )
    except CameraNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Camera not found",
        )


# =============================================================================
# Streaming Endpoints
# =============================================================================


@router.get("/{camera_id}/stream", response_model=StreamUrlResponse)
async def get_stream_url(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[StreamService, Depends(get_stream_service)],
    stream_type: str = Query("main", pattern="^(main|sub)$"),
    protocol: str = Query("hls", pattern="^(rtsp|hls|webrtc)$"),
) -> Any:
    """Get streaming URL for a camera."""
    # the rtsp protocol returns a URL with the camera's OWN decrypted
    # credentials injected — that is a direct-device-access action, not a plain
    # view. Require the stronger ``cameras.access`` permission so a
    # ``cameras.view``-only viewer (who still gets the proxied HLS/WebRTC stream,
    # no creds) cannot extract the device credentials. has_permission is
    # scope-aware, so a narrowed API key needs cameras.access in its scopes too.
    if protocol == "rtsp" and not current_user.has_permission("cameras.access"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cameras.access permission is required for credential-bearing RTSP stream URLs",
        )
    try:
        url = await service.get_stream_url(
            camera_id,
            stream_type,
            protocol,
            organization_id=org_scope_or_platform(current_user),
            accessible_site_ids=(
                current_user.accessible_site_ids if current_user.is_site_limited else None
            ),
        )
        return {"url": url, "protocol": protocol}
    except CameraNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Camera not found",
        )


@router.get("/{camera_id}/snapshot")
async def get_snapshot(
    camera_id: UUID,
    request: Request,
    service: Annotated[StreamService, Depends(get_stream_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
    token: str | None = Query(None),
) -> Any:
    """Get a snapshot from a camera.

    Accepts auth via standard Bearer header or ``?token=`` query param
    (needed for ``<img src>`` tags which cannot send headers).
    """
    user = await _authenticate_media_request(request, session, token, camera_id=camera_id)
    await _enforce_camera_access(session, user, camera_id, "live")

    try:
        image_data = await service.get_snapshot(camera_id, organization_id=user.organization_id)
        if image_data:
            return Response(
                content=image_data,
                media_type="image/jpeg",
                headers={
                    "Cache-Control": "no-store",
                    "Referrer-Policy": "no-referrer",
                    "X-Content-Type-Options": "nosniff",
                },
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Snapshot not available",
        )
    except CameraNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Camera not found",
        )
    except StreamError as e:
        # The camera/NVR interaction failed (unreachable, timeout, auth, or no
        # usable frame) — that's an upstream gateway failure, not an internal
        # server error. 502 matches how the NVR discovery/import/storage
        # endpoints in this file already surface device-communication failures.
        logger.warning("Snapshot upstream error for %s: %s", camera_id, e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream camera/NVR did not return a snapshot",
        )


@router.get("/{camera_id}/playback-frame")
async def get_playback_frame(
    camera_id: UUID,
    request: Request,
    service: Annotated[RecordingService, Depends(get_recording_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
    time: datetime = Query(..., description="ISO 8601 instant to seek the recording to"),
    token: str | None = Query(None),
) -> Any:
    """Return a single recorded JPEG frame at an absolute playback time.

    This is the *recording* equivalent of ``/snapshot``: it seeks the NVR's
    stored recording to ``time`` and extracts one frame (via the adapter's
    ffmpeg-backed grab), rather than returning the live image. Used by the
    multi-camera playback wall so each tile shows the recording at the
    shared playhead position.

    Auth mirrors ``/snapshot``: a stream-scoped ``?token=`` (for ``<img src>``)
    or the standard cookie/Bearer session. Org-scoping is enforced in the
    service when resolving the camera + NVR credentials.
    """
    user = await _authenticate_media_request(request, session, token, camera_id=camera_id)
    await _enforce_camera_access(session, user, camera_id, "playback")

    try:
        frame = await service.get_playback_frame(
            camera_id,
            time,
            organization_id=user.organization_id,
        )
        return Response(
            content=frame,
            media_type="image/jpeg",
            headers={
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )
    except CameraNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Camera not found",
        )
    except RecordingError as e:
        # No recorded frame at this time, missing creds, or an adapter
        # without playback support — surface honestly so the UI can fall
        # back instead of mislabeling a live snapshot as a recording.
        logger.info("Playback frame unavailable for %s: %s", camera_id, e)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No recorded frame available at the requested time",
        )


@router.get("/{camera_id}/stream/mjpeg")
async def stream_mjpeg(
    camera_id: UUID,
    request: Request,
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
    quality: str = Query("sub", pattern="^(main|sub)$"),
    max_fps: float = Query(0, ge=0, le=30, description="Max FPS cap (0 = auto)"),
    token: str | None = Query(None),
) -> Any:
    """
    Proxy an MJPEG stream from a Hikvision camera/NVR channel.

    Scales to 64+ concurrent channels via adaptive frame-rate:
      - ≤8 streams  → 10 fps
      - ≤16 streams → 5 fps
      - ≤32 streams → 3 fps
      - ≤64 streams → 2 fps
      - >64 streams → 1 fps

    Pass ``max_fps`` to override the auto-scaling cap.

    the previous version
    accepted long-lived access tokens via ``?token=`` which then
    leaked into nginx access logs, browser history, and Referer
    headers. The fix:
      * If cookie auth is present (browser session), it is the
        PRIMARY credential — prefer it and ignore any redundant
        ``?token=``. A same-origin ``<img src>`` always attaches the
        cookie, and the FE also appends a short-lived stream token
        (the legacy auth path for tags that can't set headers), so
        cookie+token arriving together is the *normal* browser case,
        not an attack. The cookie still outranks the token, so a
        leaked URL can't bypass or downgrade cookie auth.
      * Otherwise accept ``?token=`` ONLY when it's a stream-scoped
        token (60s TTL) issued via ``/stream-token``. Bearer header
        remains a first-class auth path for clients that can set it.
    """
    import httpx

    from app.adapters.hikvision.adapter import DigestAuthHandler

    # If the browser sent a cookie session, prefer it and drop the
    # redundant ?token=. A same-origin <img>/<video> request ALWAYS
    # attaches the cookie (path=/api/v1/), and the FE also appends a
    # short-lived stream token — so cookie+token together is the normal
    # browser case, NOT an attack. Rejecting it (the old behavior) broke
    # live view: every same-origin <img> got 400 → "Stream unavailable".
    # Authenticating via the cookie keeps it the stronger credential, so a
    # leaked URL still can't bypass or downgrade cookie auth.
    if token is not None and request.cookies.get("freesdn_access"):
        token = None

    user = await _authenticate_media_request(request, session, token, camera_id=camera_id)
    await _enforce_camera_access(session, user, camera_id, "live")

    # ── Load camera + credentials ──────────────────────────────
    try:
        camera = await service.get_camera(camera_id, organization_id=user.organization_id)
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")

    if camera.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Camera not found")

    host, port, username, password = await _resolve_credentials(camera, session)

    channel = camera.channel_id or 1
    stream_idx = 1 if quality == "main" else 2
    isapi_ch = channel * 100 + stream_idx

    base_url = f"http://{host}:{port}"
    mjpeg_url = f"{base_url}/ISAPI/Streaming/channels/{isapi_ch}/httpPreview"
    snapshot_url = f"{base_url}/ISAPI/Streaming/channels/{isapi_ch}/picture"

    auth = DigestAuthHandler(username, password)

    BOUNDARY = "freesdn-mjpeg-boundary"

    # ── Per-NVR connection limit (checked before generator to return proper 429) ──
    if not await _nvr_limiter.acquire(host, port):
        raise HTTPException(
            status_code=429,
            detail="NVR connection limit reached — degrade to snapshot mode",
            headers={"X-Degrade-To": "snapshot", "Retry-After": "5"},
        )

    async def _managed_mjpeg_generator() -> Any:
        """
        MJPEG generator with pool-managed lifecycle.
        Automatically adjusts frame interval when many streams are active.

        Uses a shared snapshot cache so multiple viewers of the same channel
        share a single ISAPI fetch loop instead of each fetching independently.
        """
        cache_key: str | None = None
        nvr_slot_held = True  # Acquired before generator; tracks ownership

        await _stream_pool.acquire()
        try:
            # SSRF / DNS-rebinding pin for the native-MJPEG host (same TOCTOU as
            # the snapshot cache). On a blocked/unresolvable host, skip native
            # MJPEG — the snapshot fallback below re-validates and refuses too.
            _mjpeg_target: str | None = None
            _mjpeg_pin: dict[str, str] = {}
            try:
                _mjpeg_target, _mjpeg_pin = _pin_url_to_resolved_ip(mjpeg_url)
            except ValueError as exc:
                logger.warning("native MJPEG skipped (SSRF) ch=%s: %s", isapi_ch, exc)
            async with httpx.AsyncClient(
                auth=auth,
                timeout=httpx.Timeout(10.0, connect=5.0),
                limits=httpx.Limits(
                    max_connections=4,
                    max_keepalive_connections=2,
                ),
                headers=_mjpeg_pin,
            ) as client:
                # ── Try native MJPEG first ──
                try:
                    if _mjpeg_target is None:
                        raise httpx.ConnectError("native MJPEG disabled (SSRF block)")
                    async with client.stream("GET", _mjpeg_target) as resp:
                        if resp.status_code == 200:
                            logger.info(
                                "Native MJPEG ch=%s  active_streams=%d",
                                isapi_ch,
                                _stream_pool.active_streams,
                            )
                            async for chunk in resp.aiter_bytes(chunk_size=65_536):
                                if await request.is_disconnected():
                                    return
                                yield chunk
                            return
                        # Non-200: response is closed by async-with context
                        logger.debug(
                            "httpPreview returned %d, using snapshot polling",
                            resp.status_code,
                        )
                except (httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError) as e:
                    logger.debug("httpPreview error: %s, using snapshot polling", e)
                except Exception as e:
                    logger.debug("httpPreview unexpected error: %s, using snapshot polling", e)

            # ── Snapshot-based MJPEG via shared cache ──
            # Release the NVR slot we acquired pre-generator — the snapshot cache
            # manages its own slot (1 per unique channel, not per viewer).
            # This prevents double-slot consumption that would halve effective limits.
            await _nvr_limiter.release(host, port)
            nvr_slot_held = False

            cache_key = await _snapshot_cache.subscribe(
                host,
                port,
                isapi_ch,
                auth,
                snapshot_url,
            )
            logger.info(
                "Cached MJPEG ch=%s  active_streams=%d  target_fps=%.1f",
                isapi_ch,
                _stream_pool.active_streams,
                _stream_pool.target_fps,
            )

            # Yield the first cached frame immediately if available
            first = _snapshot_cache.get_frame(cache_key)
            if first:
                yield (
                    f"--{BOUNDARY}\r\n"
                    f"Content-Type: image/jpeg\r\n"
                    f"Content-Length: {len(first)}\r\n"
                    f"\r\n"
                ).encode()
                yield first
                yield b"\r\n"

            empty_count = 0
            while True:
                if await request.is_disconnected():
                    return

                frame = await _snapshot_cache.wait_frame(cache_key)
                if frame is None:
                    empty_count += 1
                    if empty_count >= 10:
                        return
                    continue

                empty_count = 0
                yield (
                    f"--{BOUNDARY}\r\n"
                    f"Content-Type: image/jpeg\r\n"
                    f"Content-Length: {len(frame)}\r\n"
                    f"\r\n"
                ).encode()
                yield frame
                yield b"\r\n"

                # Respect max_fps cap by sleeping if needed
                if max_fps > 0:
                    min_interval = 1.0 / max_fps
                    pool_interval = _stream_pool.frame_interval
                    if min_interval > pool_interval:
                        await asyncio.sleep(min_interval - pool_interval)
        finally:
            if cache_key:
                await _snapshot_cache.unsubscribe(cache_key)
            await _stream_pool.release()
            # Release NVR slot only if still held (snapshot path releases early)
            if nvr_slot_held:
                await _nvr_limiter.release(host, port)

    return StreamingResponse(
        _managed_mjpeg_generator(),
        media_type=f"multipart/x-mixed-replace; boundary={BOUNDARY}",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Connection": "keep-alive",
            "X-Stream-Pool-Active": str(_stream_pool.active_streams),
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )


# =============================================================================
# Live video via the go2rtc restreamer (connect-once → fan-out fMP4)
# =============================================================================


def _go2rtc_stream_name(camera_id: UUID) -> str:
    """Stable per-camera go2rtc stream name (so N viewers share one NVR pull)."""
    return f"freesdn_cam_{str(camera_id).replace('-', '')}"


async def _ensure_go2rtc_stream(name: str, rtsp_url: str) -> None:
    """Idempotently register/update a camera's RTSP source in go2rtc.

    ``rtsp_url`` carries single-encoded credentials (a valid URL). httpx
    percent-encodes the ``src`` query value; go2rtc decodes it once back to the
    valid URL — so a password like ``P@ssw0rd%^`` round-trips correctly.
    """
    import httpx

    from app.core.config import settings

    base = settings.GO2RTC_URL.rstrip("/")
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        await client.put(f"{base}/api/streams", params={"name": name, "src": rtsp_url})


@router.get("/{camera_id}/live/stream.mp4")
async def live_stream_mp4(
    camera_id: UUID,
    request: Request,
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
    quality: str = Query("main", pattern="^(main|sub)$"),
    token: str | None = Query(None),
) -> Any:
    """Live video as a fragmented-MP4 stream via the go2rtc restreamer.

    go2rtc connects to the NVR's RTSP ONCE and fans the stream out to every
    viewer (no per-viewer NVR load), and its native RTSP client handles the HEVC
    these NVRs emit that ffmpeg's demuxer cannot. The fMP4 plays in a <video>
    element on HEVC-capable browsers (Safari / modern Chrome/Edge); the UI falls
    back to the snapshot/MJPEG path when the browser can't decode it.
    """
    # Same cookie-vs-token rule as the MJPEG/snapshot endpoints: a same-origin
    # <video> attaches the cookie, so prefer it and drop the redundant token.
    if token is not None and request.cookies.get("freesdn_access"):
        token = None
    user = await _authenticate_media_request(request, session, token, camera_id=camera_id)
    await _enforce_camera_access(session, user, camera_id, "live")
    try:
        camera = await service.get_camera(camera_id, organization_id=user.organization_id)
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    if camera.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Camera not found")

    import httpx

    from app.core.config import settings

    host, _port, username, password = await _resolve_credentials(camera, session)
    ch = camera.channel_id or 1
    isapi_ch = ch * 100 + (1 if quality == "main" else 2)
    rtsp_url = (
        f"rtsp://{quote(username or '', safe='')}:{quote(password or '', safe='')}"
        f"@{host}:554/Streaming/Channels/{isapi_ch}"
    )
    name = _go2rtc_stream_name(camera_id)
    base = settings.GO2RTC_URL.rstrip("/")

    try:
        await _ensure_go2rtc_stream(name, rtsp_url)
    except Exception as exc:
        logger.warning("go2rtc stream register failed for camera %s: %s", camera_id, exc)
        raise HTTPException(status_code=502, detail="Live restream unavailable")

    async def _proxy() -> Any:
        # read=30.0 bounds a MID-STREAM stall: if the NVR's RTSP feed freezes
        # while go2rtc keeps the HTTP/TCP connection open (no further fMP4
        # chunks), aiter_bytes would otherwise block forever holding one
        # upstream pull + the client socket. A read timeout surfaces the stall
        # as httpx.ReadTimeout, which we catch below for clean teardown so the
        # browser sees EOF and the UI falls back to MJPEG/snapshot.
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, read=30.0)) as client:
            try:
                async with client.stream(
                    "GET", f"{base}/api/stream.mp4", params={"src": name}
                ) as resp:
                    if resp.status_code != 200:
                        return
                    async for chunk in resp.aiter_bytes(65536):
                        if await request.is_disconnected():
                            return
                        yield chunk
            except (
                httpx.StreamClosed,
                httpx.ReadError,
                httpx.ReadTimeout,
                httpx.RemoteProtocolError,
            ):
                return
            except Exception:  # pragma: no cover - defensive
                logger.debug("go2rtc proxy ended for camera %s", camera_id)

    return StreamingResponse(
        _proxy(),
        media_type="video/mp4",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/{camera_id}/timeline", response_model=CameraTimelineResponse)
async def get_camera_timeline(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
    start: datetime = Query(..., description="Window start (ISO 8601, UTC)"),
    end: datetime = Query(..., description="Window end (ISO 8601, UTC)"),
) -> Any:
    """Recorded-footage availability for the scrubber — segments (+ implied gaps)
    over [start, end], queried live from the NVR. Times are REAL UTC. Devices
    without a recording search (non-Hikvision) return supported=false + no
    segments so the UI can show an honest "no timeline" state.
    """
    await _enforce_camera_access(session, current_user, camera_id, "playback")
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")

    from app.modules.cameras.service import StreamService

    s_iso, e_iso = start.isoformat(), end.isoformat()
    host, port, username, password = await _resolve_credentials(camera, session)
    vendor = (getattr(camera, "vendor", "") or "").lower() or "hikvision"
    adapter = StreamService._create_camera_adapter(
        host=host, port=port, username=username, password=password, vendor=vendor
    )
    search = getattr(adapter, "search_recordings", None)
    if not callable(search):
        return CameraTimelineResponse(segments=[], start=s_iso, end=e_iso, supported=False)

    try:
        await adapter.connect()
        recs = await adapter.search_recordings(
            channel=camera.channel_id or 1, start_time=s_iso, end_time=e_iso, max_results=500
        )
    except Exception as exc:
        logger.warning("Timeline search failed for camera %s: %s", camera_id, exc)
        raise HTTPException(status_code=502, detail="Failed to load recording timeline")
    finally:
        with contextlib.suppress(Exception):
            await adapter.disconnect()

    def _seg_type(rec: dict[str, Any]) -> str:
        d = f"{rec.get('recording_type', '')} {rec.get('content_type', '')}".lower()
        if "vmd" in d or "motion" in d:
            return "motion"
        if "alarm" in d:
            return "alarm"
        return "continuous"

    segments = [
        TimelineSegment(start=r["start_time"], end=r["end_time"], type=_seg_type(r))
        for r in recs
        if r.get("start_time") and r.get("end_time")
    ]
    return CameraTimelineResponse(segments=segments, start=s_iso, end=e_iso, supported=True)


@router.websocket("/{camera_id}/live/mse")
async def live_mse_ws(
    websocket: WebSocket,
    camera_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    token: str | None = Query(None),
    quality: str = Query("main"),
) -> None:
    """Sub-second live video: proxy the go2rtc MSE WebSocket to the browser.

    The browser speaks go2rtc's MSE protocol (sends an ``mse`` request, receives
    the mime + binary fMP4 segments); FreeSDN authenticates the connection
    (httpOnly cookie or ``?token=``), org-scopes the camera, ensures the go2rtc
    stream, and relays both directions. go2rtc stays internal; viewers share one
    NVR pull. Lower latency than the progressive-fMP4 <video> path.
    """
    import websockets

    from app.api.v1.endpoints.websocket import _validate_ws_origin, authenticate_websocket
    from app.core.config import settings
    from app.core.cookies import ACCESS_COOKIE
    from app.modules.cameras.models import Camera

    # ── CSWSH (AUTH-WS-MSE-CSWSH): validate Origin BEFORE reading the cookie /
    # accepting. A cookie-authenticated browser WS is hijackable from a hostile
    # page without this — the main /ws endpoint already does the same check. ──
    if not await _validate_ws_origin(websocket):
        return

    # ── Auth: cookie (browser WS handshake sends it) or ?token= ──
    auth = None
    from_query = False
    cookie_token = websocket.cookies.get(ACCESS_COOKIE)
    if cookie_token:
        auth = await authenticate_websocket(cookie_token)
    if not auth and token:
        auth = await authenticate_websocket(token)
        from_query = True
    if not auth:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    # a token taken from the URL query MUST be a short-lived
    # stream-scoped token (a full access JWT in a URL leaks via history / proxy
    # logs / Referer). Cookie auth (the browser handshake) may carry a full
    # session. Mirrors _authenticate_media_request for the HTTP media paths.
    if from_query and auth.get("scope") != "stream":
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    org_id = auth.get("organization_id")

    # ── Resolve + org-scope the camera ──
    q = select(Camera).where(Camera.id == camera_id, Camera.deleted_at.is_(None))
    if org_id:
        q = q.where(Camera.organization_id == org_id)
    camera = (await session.execute(q)).scalar_one_or_none()
    if not camera:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # R5 site-grant: a site-limited operator must not open a live subscription
    # for a sibling-site camera. The JWT carries no site grants, so resolve the
    # per-user scope from UserSiteAccess (same helper the main WS uses; fails
    # CLOSED). Mirrors the HTTP path's _enforce_camera_access, which runs
    # assert_can_access_site BEFORE the role-fallback grant. No-op for
    # super_admin / org_admin (never site-limited).
    try:
        from app.api.v1.endpoints.websocket import _load_ws_site_scope

        _ws_limited, _ws_sites = await _load_ws_site_scope(
            str(auth.get("user_id")), auth.get("role")
        )
        if _ws_limited and camera.site_id is not None and str(camera.site_id) not in set(_ws_sites):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except Exception as exc:  # pragma: no cover - never stream when scope is indeterminate
        logger.warning("MSE site-scope check failed for camera %s: %s", camera_id, exc)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Per-camera live-access grant (org_admin+ bypass; restricted users held to
    # their grant). The WS auth dict carries the user_id/role claims.
    try:
        if org_id and auth.get("user_id"):
            from app.modules.cameras.service import CameraAccessService

            _acc = await CameraAccessService(db=session).check_access(
                user_id=UUID(str(auth["user_id"])),
                camera_id=camera_id,
                organization_id=UUID(str(org_id)),
                user_role=auth.get("role"),
            )
            if not _acc.get("has_access") or not _acc.get("can_live"):
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    except Exception as exc:  # pragma: no cover - never stream when authz is indeterminate
        # Fail CLOSED: if the access decision couldn't be computed (DB blip,
        # unexpected role), do not serve the stream — matches the HTTP path's
        # _enforce_camera_access which propagates rather than swallowing.
        logger.warning("MSE access check failed for camera %s: %s", camera_id, exc)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    host, port, username, password = await _resolve_credentials(camera, session)
    ch = camera.channel_id or 1
    isapi_ch = ch * 100 + (1 if quality == "main" else 2)
    rtsp_url = (
        f"rtsp://{quote(username or '', safe='')}:{quote(password or '', safe='')}"
        f"@{host}:554/Streaming/Channels/{isapi_ch}"
    )
    name = _go2rtc_stream_name(camera_id)
    try:
        await _ensure_go2rtc_stream(name, rtsp_url)
    except Exception as exc:
        logger.warning("go2rtc register failed (MSE) for camera %s: %s", camera_id, exc)
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    # Per-NVR connection backstop (mirrors the MJPEG path). go2rtc fans one pull
    # out to many viewers, but each relay still holds a browser WS + an upstream
    # go2rtc WS; cap them per NVR so a multi-camera wall on a struggling NVR
    # cannot pile up unbounded relays. Reject BEFORE accept so the browser can
    # degrade to the snapshot/MJPEG path.
    if not await _nvr_limiter.acquire(host, port):
        await websocket.close(code=status.WS_1013_TRY_AGAIN_LATER)
        return

    await websocket.accept()
    ws_base = (
        settings.GO2RTC_URL.replace("https://", "wss://").replace("http://", "ws://").rstrip("/")
    )
    upstream_url = f"{ws_base}/api/ws?src={name}"

    try:
        async with websockets.connect(upstream_url, max_size=None, open_timeout=10) as upstream:

            async def client_to_go2rtc() -> None:
                # Browser → go2rtc (the initial mse handshake + keepalives).
                while True:
                    msg = await websocket.receive()
                    if msg.get("type") == "websocket.disconnect":
                        return
                    if msg.get("text") is not None:
                        await upstream.send(msg["text"])
                    elif msg.get("bytes") is not None:
                        await upstream.send(msg["bytes"])

            async def go2rtc_to_client() -> None:
                # go2rtc → browser (json mime msg + binary fMP4 segments).
                # A bare `async for frame in upstream` has no idle timeout: if the
                # NVR's RTSP source stalls MID-STREAM while go2rtc stays alive
                # (answers WS pings but forwards no frames), this would block
                # forever, pinning the relay + go2rtc pull until the browser tab
                # closes. wait_for bounds the frame gap so a stall tears the relay
                # down cleanly and the client falls back to MJPEG/snapshot.
                while True:
                    try:
                        frame = await asyncio.wait_for(upstream.recv(), timeout=20.0)
                    except TimeoutError:
                        logger.debug("MSE frame-idle timeout for camera %s", camera_id)
                        return
                    if isinstance(frame, (bytes, bytearray)):
                        await websocket.send_bytes(bytes(frame))
                    else:
                        await websocket.send_text(frame)

            tasks = [
                asyncio.create_task(client_to_go2rtc()),
                asyncio.create_task(go2rtc_to_client()),
            ]
            _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
    except Exception as exc:  # pragma: no cover - network/relay teardown
        logger.debug("MSE proxy ended for camera %s: %s", camera_id, exc)
    finally:
        await _nvr_limiter.release(host, port)
        with contextlib.suppress(Exception):
            await websocket.close()


@router.get("/streams/stats", response_model=StreamStatsResponse)
async def get_stream_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    site_id: UUID | None = Query(None),
) -> Any:
    """
    Return current MJPEG stream pool statistics.

    Useful for dashboards monitoring streaming load.
    Per-NVR breakdown is only returned for super_admins to prevent
    cross-tenant information disclosure (NVR counts/load are global).
    Regular users see aggregate totals only.
    """
    raw_stats = _nvr_limiter.get_stats()

    # Per-NVR breakdown is global (shared process) — only expose to super_admin
    # to prevent cross-tenant metadata leakage (NVR count, load patterns).
    is_super = is_unscoped_superuser(current_user)  # scope-aware
    nvr_stats = {}
    overloaded = []
    if is_super:
        for i, (_key, s) in enumerate(sorted(raw_stats.items())):
            label = f"NVR-{i + 1}"
            nvr_stats[label] = s
            if s["available"] <= 0:
                overloaded.append(label)
    else:
        total_active = sum(s["active"] for s in raw_stats.values())
        total_max = sum(s["max"] for s in raw_stats.values())
        if raw_stats:
            nvr_stats["aggregate"] = {
                "active": total_active,
                "max": total_max,
                "available": total_max - total_active,
            }
        overloaded_count = sum(1 for s in raw_stats.values() if s["available"] <= 0)
        if overloaded_count > 0:
            overloaded.append(f"{overloaded_count} NVR(s) at capacity")
    return {
        "active_streams": _stream_pool.active_streams,
        "target_fps": _stream_pool.target_fps,
        "frame_interval_ms": round(_stream_pool.frame_interval * 1000),
        "per_nvr": nvr_stats,
        "overloaded_nvrs": overloaded,
        # use the new public accessor instead of
        # touching the private ``_viewers`` map.
        "snapshot_cache_channels": _snapshot_cache.public_stats()["channels"],
    }


# =============================================================================
# Stream Token Endpoint (C5 security fix)
# =============================================================================


@router.post("/{camera_id}/stream-token", response_model=StreamTokenResponse)
async def create_stream_token(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Issue a short-lived JWT for streaming/snapshot ``<img src>`` URLs.

    Returns a token valid for 60 seconds. Clients should use this instead of
    embedding the long-lived access token in query parameters, mitigating
    **C5 (JWT tokens exposed in URL query parameters)**.

    This is the chokepoint for all token-authenticated media (snapshot, MJPEG,
    fMP4, HLS, playback-frame): enforcing the per-camera ``live`` grant here
    means a user without access to this camera can never mint a media token
    for it, so the downstream media endpoints inherit the restriction.
    """
    await _enforce_camera_access(session, current_user, camera_id, "live")

    from app.core.security import create_access_token as _create_access_token

    current_tv = getattr(current_user.user, "token_version", 0) or 0
    stream_jwt = _create_access_token(
        subject=str(current_user.id),
        expires_delta=timedelta(seconds=60),
        token_version=current_tv,
        extra_claims={
            "org_id": str(current_user.organization_id) if current_user.organization_id else None,
            "scope": "stream",
            "camera_id": str(camera_id),
        },
    )
    return {"token": stream_jwt, "expires_in": 60}


# =============================================================================
# PTZ Endpoints
# =============================================================================


@router.post("/{camera_id}/ptz", response_model=PTZActionResponse)
async def control_ptz(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    ptz_service: Annotated[PTZService, Depends(get_ptz_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
    action: str = Query(..., pattern="^(up|down|left|right|zoom_in|zoom_out|stop|preset)$"),
    speed: int = Query(50, ge=1, le=100),
    preset: int | None = None,
) -> Any:
    """Control PTZ camera."""
    await _enforce_camera_access(session, current_user, camera_id, "ptz")
    outcome = "failed"
    adapter_id = "unknown"
    try:
        result = await ptz_service.control_ptz(
            camera_id=camera_id,
            action=action,
            speed=speed,
            preset=preset,
            organization_id=org_scope_or_platform(current_user),
        )
        adapter_id = (result.get("adapter") or result.get("vendor") or "").lower() or "onvif"
        # Audit log — PTZ control
        audit = AuditService(db=ptz_service.db)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"ptz_action": action, "speed": speed, "preset": preset},
            tags=["ptz"],
        )
        outcome = "ok"
        return {"status": "ok", **result}

    except CameraNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Camera not found",
        )
    except CameraError as e:
        logger.error("PTZ control error for %s: %s", camera_id, e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PTZ command failed",
        )
    finally:
        # Platform-citizen event — PTZ writes were the most-requested
        # camera trigger surface in the audit (security
        # operators want a Slack ping when anyone moves a camera off
        # its default position). HIGH priority so automation rules
        # match the catastrophic-action tier; payload includes
        # action+preset for "if action=goto_preset and preset=99"
        # condition matching.
        from app.core.events import EventPriority
        from app.modules.cameras.events import record_camera_action

        await record_camera_action(
            f"ptz_{action}",
            camera_id=camera_id,
            adapter_id=adapter_id,
            organization_id=org_scope_or_platform(current_user),
            outcome=outcome,
            priority=EventPriority.HIGH,
            ptz_action=action,
            speed=speed,
            preset=preset,
        )


# =============================================================================
# Recording Endpoints
# =============================================================================


@router.get("/recordings/search", response_model=RecordingSearchResponse)
async def search_recordings(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.playback"))],
    service: Annotated[RecordingService, Depends(get_recording_service)],
    camera_id: UUID | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    recording_type: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    site_id: UUID | None = Query(None),
) -> Any:
    """Search for recordings."""
    # R5 site-grant: restrict a site-limited caller to recordings whose parent
    # camera lives in a granted site (covers both the explicit camera_id param
    # and the org-wide search). No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    recordings, total = await service.search_recordings(
        camera_id=camera_id,
        start_time=start_time,
        end_time=end_time,
        recording_type=recording_type,
        limit=limit,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    return {"items": recordings, "total": total}


@router.get("/recordings/{recording_id}/playback", response_model=PlaybackUrlResponse)
async def get_playback_url(
    recording_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.playback"))],
    service: Annotated[RecordingService, Depends(get_recording_service)],
    protocol: str = Query("hls", pattern="^(hls|mp4)$"),
) -> Any:
    """Get playback URL for a recording."""
    # R5 site-grant: a site-limited caller may only resolve a recording whose
    # parent camera lives in a granted site. No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    url = await service.get_playback_url(
        recording_id,
        protocol,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    return {"url": url, "protocol": protocol}


@router.post("/recordings/{recording_id}/lock", response_model=LockRecordingResponse)
async def lock_recording(
    recording_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.playback"))],
    service: Annotated[RecordingService, Depends(get_recording_service)],
    locked: bool = True,
) -> Any:
    """Lock or unlock a recording."""
    # R5 site-grant: a site-limited caller may only (un)lock a recording whose
    # parent camera lives in a granted site. No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    await service.lock_recording(
        recording_id,
        locked,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    # Audit log
    audit = AuditService(db=service.db)
    await audit.log(
        action=AuditAction.UPDATE,
        resource_type=ResourceType.RECORDING,
        resource_id=recording_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        changes={"locked": {"new": locked}},
    )
    return {"status": "ok", "locked": locked}


# =============================================================================
# PTZ Preset Endpoints
# =============================================================================


@router.get("/{camera_id}/ptz/presets", response_model=PTZPresetsListResponse)
async def get_ptz_presets(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    ptz_service: Annotated[PTZService, Depends(get_ptz_service)],
) -> Any:
    """Get PTZ presets for a camera."""
    # R5 site-grant: a site-limited caller may only read presets for a camera in
    # a granted site (the service fail-closes to 404). No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    try:
        presets = await ptz_service.get_presets(
            camera_id,
            organization_id=org_scope_or_platform(current_user),
            accessible_site_ids=_sites,
        )
        return {"items": presets}
    except CameraNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Camera not found",
        )


@router.post("/{camera_id}/ptz/presets", response_model=PTZActionResponse)
async def set_ptz_preset(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    ptz_service: Annotated[PTZService, Depends(get_ptz_service)],
    preset: int = Query(..., ge=1, le=255),
    name: str = Query(..., min_length=1, max_length=50),
) -> Any:
    """Set a PTZ preset."""
    # R5 site-grant: a site-limited caller may only set a preset on a camera in a
    # granted site (the service fail-closes to 404). No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    try:
        result = await ptz_service.set_preset(
            camera_id,
            preset,
            name,
            organization_id=org_scope_or_platform(current_user),
            accessible_site_ids=_sites,
        )
        audit = AuditService(db=ptz_service.db)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"action": "ptz_preset_set", "preset": preset, "name": name},
        )
        return {"status": "ok", **result}
    except CameraNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Camera not found",
        )
    except CameraError as e:
        logger.error("PTZ preset error for %s: %s", camera_id, e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PTZ preset operation failed",
        )


# =============================================================================
# PTZ Tours / Patrols
# =============================================================================


@router.get("/{camera_id}/ptz/tours", response_model=list[PTZPatrolResponse])
async def get_ptz_tours(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """List PTZ tours / patrols for a PTZ camera."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        patrols = await adapter.get_patrols(channel=channel)
        return [PTZPatrolResponse(**p) for p in patrols]
    except Exception:
        logger.exception("Failed to get PTZ tours for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve PTZ tours")
    finally:
        await adapter.disconnect()


@router.get("/{camera_id}/ptz/tours/{tour_id}", response_model=PTZPatrolResponse)
async def get_ptz_tour(
    camera_id: UUID,
    tour_id: Annotated[int, Path(ge=1, le=255)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a single PTZ tour detail."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_patrol(tour_id, channel=channel)
        if "error" in data:
            raise HTTPException(status_code=404, detail="Tour not found")
        return PTZPatrolResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get PTZ tour %d for camera %s", tour_id, camera_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve PTZ tour")
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/ptz/tours/{tour_id}", response_model=PTZPatrolStartStop)
async def set_ptz_tour(
    camera_id: UUID,
    tour_id: Annotated[int, Path(ge=1, le=255)],
    body: PTZPatrolCreateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create or update a PTZ tour."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        result = await adapter.set_patrol(
            tour_id, body.model_dump(), channel=channel, force=_API_WRITE_FORCE
        )
        if not result.get("success"):
            raise HTTPException(status_code=500, detail="Failed to update PTZ tour")
        audit = AuditService(db=session)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"config": "ptz_tour", "tour_id": tour_id},
        )
        return PTZPatrolStartStop(**result)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to set PTZ tour %d for camera %s", tour_id, camera_id)
        raise HTTPException(status_code=502, detail="Failed to update PTZ tour")
    finally:
        await adapter.disconnect()


@router.delete("/{camera_id}/ptz/tours/{tour_id}", response_model=DeletedResponse)
async def delete_ptz_tour(
    camera_id: UUID,
    tour_id: Annotated[int, Path(ge=1, le=255)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Delete a PTZ tour."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        result = await adapter.delete_patrol(tour_id, channel=channel, force=_API_WRITE_FORCE)
        if not result.get("success"):
            raise HTTPException(status_code=500, detail="Failed to delete PTZ tour")
        audit = AuditService(db=session)
        await audit.log(
            action=AuditAction.DELETE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"config": "ptz_tour", "tour_id": tour_id},
        )
        return {"status": "ok", "deleted": tour_id}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to delete PTZ tour %d for camera %s", tour_id, camera_id)
        raise HTTPException(status_code=502, detail="Failed to delete PTZ tour")
    finally:
        await adapter.disconnect()


@router.post("/{camera_id}/ptz/tours/{tour_id}/start", response_model=PTZPatrolStartStop)
async def start_ptz_tour(
    camera_id: UUID,
    tour_id: Annotated[int, Path(ge=1, le=255)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Start a PTZ tour."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        result = await adapter.start_patrol(tour_id, channel=channel, force=_API_WRITE_FORCE)
        audit = AuditService(db=session)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"action": "ptz_tour_start", "tour_id": tour_id},
        )
        return PTZPatrolStartStop(**result)
    except Exception:
        logger.exception("Failed to start PTZ tour %d for camera %s", tour_id, camera_id)
        raise HTTPException(status_code=502, detail="Failed to start PTZ tour")
    finally:
        await adapter.disconnect()


@router.post("/{camera_id}/ptz/tours/{tour_id}/stop", response_model=PTZPatrolStartStop)
async def stop_ptz_tour(
    camera_id: UUID,
    tour_id: Annotated[int, Path(ge=1, le=255)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Stop a PTZ tour."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        result = await adapter.stop_patrol(tour_id, channel=channel, force=_API_WRITE_FORCE)
        audit = AuditService(db=session)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"action": "ptz_tour_stop", "tour_id": tour_id},
        )
        return PTZPatrolStartStop(**result)
    except Exception:
        logger.exception("Failed to stop PTZ tour %d for camera %s", tour_id, camera_id)
        raise HTTPException(status_code=502, detail="Failed to stop PTZ tour")
    finally:
        await adapter.disconnect()


# =============================================================================
# Image Settings Endpoints
# =============================================================================


@router.get("/{camera_id}/image", response_model=ImageSettingsResponse)
async def get_image_settings(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get image settings (brightness, contrast, saturation, etc.) from camera."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    if camera.device_type != "hikvision":
        raise HTTPException(
            status_code=400, detail="Image settings only supported for Hikvision devices"
        )

    from app.adapters.hikvision.adapter import HikvisionAdapter

    host, port, username, password = await _resolve_credentials(camera, session)

    adapter = HikvisionAdapter(host=host, username=username, password=password, port=port)
    try:
        await adapter.connect()
        channel = camera.channel_id or 1
        settings = await adapter.get_image_settings(channel=channel)
        return settings
    finally:
        await adapter.disconnect()


class ImageSettingsRequest(BaseModel):
    """Validated image settings — only known keys allowed."""

    brightness: int | None = Field(None, ge=0, le=100)
    contrast: int | None = Field(None, ge=0, le=100)
    saturation: int | None = Field(None, ge=0, le=100)
    sharpness: int | None = Field(None, ge=0, le=100)
    hue: int | None = Field(None, ge=0, le=100)


@router.put("/{camera_id}/image", response_model=StatusResponse)
async def set_image_settings(
    camera_id: UUID,
    settings: ImageSettingsRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update image settings (brightness, contrast, saturation, etc.)."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    if camera.device_type != "hikvision":
        raise HTTPException(
            status_code=400, detail="Image settings only supported for Hikvision devices"
        )

    from app.adapters.hikvision.adapter import HikvisionAdapter

    host, port, username, password = await _resolve_credentials(camera, session)

    adapter = HikvisionAdapter(host=host, username=username, password=password, port=port)
    try:
        await adapter.connect()
        channel = camera.channel_id or 1

        async def _apply() -> dict[str, Any]:
            r = await adapter.set_image_settings(
                settings.model_dump(exclude_none=True), channel=channel, force=_API_WRITE_FORCE
            )
            if not r.get("success"):
                raise CameraError(f"device rejected image-settings update: {r.get('error')}")
            return r

        await staged_camera_write(
            db=session,
            actor_id=current_user.id,
            organization_id=org_scope_or_platform(current_user),
            camera=camera,
            feature="image_settings",
            capture=lambda: adapter.get_image_settings(channel=channel),
            apply=_apply,
            rollback=lambda old: adapter.set_image_settings(
                old, channel=channel, force=_API_WRITE_FORCE
            ),
        )
        return {"status": "ok"}
    except HTTPException:
        raise
    except CameraError:
        raise HTTPException(status_code=500, detail="Failed to update image settings")
    finally:
        await adapter.disconnect()


# =============================================================================
# Smart Detection & Analytics Endpoints (P0 Features)
# =============================================================================


# the previous implementation
# unconditionally returned ``HikvisionAdapter`` even when the camera
# row was a Dahua / Axis / Reolink ONVIF device. Reads against ISAPI
# endpoints would fail in confusing ways. Restrict the Hikvision-only
# adapter to genuinely Hikvision rows; everything else gets a clean
# 400 indicating these endpoints are Hikvision-specific.
def _is_hikvision_camera(camera: Any) -> bool:
    """Return True if the camera row is a real Hikvision device."""
    dt = (getattr(camera, "device_type", None) or "").lower()
    if dt == "hikvision":
        return True
    vendor = (getattr(camera, "vendor", None) or "").lower()
    return "hikvision" in vendor


def _require_hikvision_camera(camera: Any) -> None:
    """Raise 400 if the camera is not a Hikvision device.

    Use this at the top of every Hikvision-specific endpoint so we
    fail fast with a clear error message instead of silently calling
    ISAPI URLs against an ONVIF-only device.
    """
    if not _is_hikvision_camera(camera):
        raise HTTPException(
            status_code=400,
            detail=(
                "this endpoint is Hikvision-specific; the camera "
                f"vendor is {getattr(camera, 'vendor', 'unknown')!r}"
            ),
        )


async def _get_adapter_for_camera(camera: Any, session: AsyncSession) -> tuple[Any, int]:
    """Shared helper: resolve credentials -> create & connect adapter -> return (adapter, channel).

    Raises HTTPException(400) when the camera is not Hikvision (the
    config endpoints downstream all hit ISAPI URLs that only exist on
    Hikvision firmware) and HTTPException(502) if the device is
    unreachable.
    """
    _require_hikvision_camera(camera)

    from app.adapters.hikvision.adapter import HikvisionAdapter

    host, port, username, password = await _resolve_credentials(camera, session)
    adapter = HikvisionAdapter(host=host, username=username, password=password, port=port)
    try:
        await adapter.connect()
    except Exception as e:
        logger.error("Failed to connect to camera %s at %s: %s", camera.id, host, e)
        with contextlib.suppress(Exception):
            await adapter.disconnect()
        raise HTTPException(status_code=502, detail="Camera device unreachable")
    return adapter, camera.channel_id or 1


async def _enforce_camera_access(
    session: AsyncSession,
    current_user: Any,
    camera_id: UUID,
    action: str,
) -> None:
    """Enforce per-camera CameraAccessGrant on top of the module-level
    ``cameras.*`` permission already checked by the endpoint dependency.

    ``action`` is one of: live / playback / ptz / export / configure.

    Semantics (see CameraAccessService.check_access): org_admin+ bypass with
    full access; a user with an explicit camera/group grant is held to that
    grant's flags; everyone else falls back to their org role's defaults — so
    this NEVER locks out a user who has access today, it only honours
    narrower per-camera grants. Raises 403 when the specific action flag is
    not allowed for this camera.

    before the role/grant check, assert that a site-limited
    caller's site grant covers the camera's own site_id.  Uses 404 (not 403)
    to avoid an existence oracle — consistent with the rest of the module.
    """
    from app.modules.cameras.models import Camera as _Camera

    org_id = getattr(current_user, "organization_id", None)
    if org_id is None:
        # No org context → nothing to scope against; the module permission
        # gate already ran, so allow (matches prior behaviour).
        return

    # Resolve camera site_id and assert site-grant BEFORE any role logic so
    # that a site-limited user cannot reach sibling-site cameras via the
    # role-fallback grant path.
    cam_site_row = await session.execute(
        select(_Camera.site_id).where(
            _Camera.id == camera_id,
            _Camera.organization_id == org_id,
            _Camera.deleted_at.is_(None),
        )
    )
    cam_site_id = cam_site_row.scalar_one_or_none()
    # cam_site_id may be None (no site assigned) — assert_can_access_site
    # treats None as "org-level resource" and is a no-op.
    assert_can_access_site(current_user, cam_site_id, detail="Camera not found")

    from app.modules.cameras.service import CameraAccessService

    role = current_user.role
    role_str = role.value if hasattr(role, "value") else str(role)
    access = await CameraAccessService(db=session).check_access(
        user_id=current_user.id,
        camera_id=camera_id,
        organization_id=org_id,
        user_role=role_str,
    )
    flag = {
        "live": "can_live",
        "playback": "can_playback",
        "ptz": "can_ptz",
        "export": "can_export",
        "configure": "can_configure",
    }.get(action, "can_live")
    if not access.get("has_access") or not access.get(flag):
        raise HTTPException(
            status_code=403,
            detail=f"You do not have '{action}' access to this camera",
        )


# every ``set_*`` / mutation
# call on the adapter is gated by ``force=False`` by default. The API
# endpoints in this module are reached only after ``cameras.manage``
# permission has already been checked, so passing ``force=True`` here
# is the contractually correct way to opt in to the write. Centralise
# the flag in one constant so it is easy to grep for.
_API_WRITE_FORCE = True


# ── Motion Detection ─────────────────────────────────────────────────────────


@router.get("/{camera_id}/motion-detection", response_model=MotionDetectionResponse)
async def get_motion_detection(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get motion detection configuration for a camera channel."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_motion_detection(channel=channel)
        if "error" in data:
            raise HTTPException(
                status_code=502, detail="Failed to retrieve motion detection config"
            )
        return MotionDetectionResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get motion detection for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve motion detection config")
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/motion-detection", response_model=MotionDetectionResponse)
async def set_motion_detection(
    camera_id: UUID,
    body: MotionDetectionUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update motion detection configuration."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    outcome = "failed"

    async def _apply() -> dict[str, Any]:
        r = await adapter.set_motion_detection(
            body.model_dump(), channel=channel, force=_API_WRITE_FORCE
        )
        if not r.get("success"):
            raise CameraError("device rejected motion-detection update")
        return r

    try:
        # Audit + best-effort rollback envelope (camera-native staged write).
        await staged_camera_write(
            db=session,
            actor_id=current_user.id,
            organization_id=org_scope_or_platform(current_user),
            camera=camera,
            feature="motion_detection",
            capture=lambda: adapter.get_motion_detection(channel=channel),
            apply=_apply,
            rollback=lambda old: adapter.set_motion_detection(
                old, channel=channel, force=_API_WRITE_FORCE
            ),
        )
        data = await adapter.get_motion_detection(channel=channel)
        outcome = "ok"
        return MotionDetectionResponse(**data)
    except HTTPException:
        raise
    except CameraError:
        raise HTTPException(status_code=500, detail="Failed to update motion detection")
    except Exception:
        logger.exception("Failed to set motion detection for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to update motion detection config")
    finally:
        await adapter.disconnect()
        # Platform-citizen event — automation rules can match
        # ``camera.set_motion_detection.ok`` to fire vendor-specific
        # workflows (e.g. log every change to a SIEM, alert on guest-
        # zone toggles, etc.).
        from app.modules.cameras.events import record_camera_action

        await record_camera_action(
            "set_motion_detection",
            camera_id=camera_id,
            adapter_id=(getattr(camera, "vendor", None) or "onvif").lower(),
            organization_id=org_scope_or_platform(current_user),
            outcome=outcome,
            channel=channel,
        )


# ── Privacy Masks ─────────────────────────────────────────────────────────────


@router.get("/{camera_id}/privacy-masks", response_model=PrivacyMaskResponse)
async def get_privacy_masks(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get privacy mask regions for a camera channel."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_privacy_masks(channel=channel)
        if "error" in data:
            raise HTTPException(status_code=502, detail="Failed to retrieve privacy mask config")
        return PrivacyMaskResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get privacy masks for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve privacy mask config")
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/privacy-masks", response_model=PrivacyMaskResponse)
async def set_privacy_masks(
    camera_id: UUID,
    body: PrivacyMaskUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update privacy mask regions."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)

    async def _apply() -> dict[str, Any]:
        r = await adapter.set_privacy_masks(
            body.model_dump(), channel=channel, force=_API_WRITE_FORCE
        )
        if not r.get("success"):
            raise CameraError("device rejected privacy-mask update")
        return r

    try:
        await staged_camera_write(
            db=session,
            actor_id=current_user.id,
            organization_id=org_scope_or_platform(current_user),
            camera=camera,
            feature="privacy_masks",
            capture=lambda: adapter.get_privacy_masks(channel=channel),
            apply=_apply,
            rollback=lambda old: adapter.set_privacy_masks(
                old, channel=channel, force=_API_WRITE_FORCE
            ),
        )
        data = await adapter.get_privacy_masks(channel=channel)
        return PrivacyMaskResponse(**data)
    except HTTPException:
        raise
    except CameraError:
        raise HTTPException(status_code=500, detail="Failed to update privacy masks")
    except Exception:
        logger.exception("Failed to set privacy masks for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to update privacy mask config")
    finally:
        await adapter.disconnect()


# ── Line Crossing Detection ──────────────────────────────────────────────────


@router.get("/{camera_id}/line-crossing", response_model=LineCrossingResponse)
async def get_line_crossing(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get line crossing detection configuration."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_line_crossing(channel=channel)
        if "error" in data:
            raise HTTPException(status_code=502, detail="Failed to retrieve line crossing config")
        return LineCrossingResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get line crossing for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve line crossing config")
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/line-crossing", response_model=LineCrossingResponse)
async def set_line_crossing(
    camera_id: UUID,
    body: LineCrossingUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update line crossing detection rules."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)

    async def _apply() -> dict[str, Any]:
        r = await adapter.set_line_crossing(
            body.model_dump(), channel=channel, force=_API_WRITE_FORCE
        )
        if not r.get("success"):
            raise CameraError("device rejected line-crossing update")
        return r

    try:
        await staged_camera_write(
            db=session,
            actor_id=current_user.id,
            organization_id=org_scope_or_platform(current_user),
            camera=camera,
            feature="line_crossing",
            capture=lambda: adapter.get_line_crossing(channel=channel),
            apply=_apply,
            rollback=lambda old: adapter.set_line_crossing(
                old, channel=channel, force=_API_WRITE_FORCE
            ),
        )
        data = await adapter.get_line_crossing(channel=channel)
        return LineCrossingResponse(**data)
    except HTTPException:
        raise
    except CameraError:
        raise HTTPException(status_code=500, detail="Failed to update line crossing")
    except Exception:
        logger.exception("Failed to set line crossing for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to update line crossing config")
    finally:
        await adapter.disconnect()


# ── Intrusion Detection (Field Detection) ────────────────────────────────────


@router.get("/{camera_id}/intrusion-detection", response_model=IntrusionDetectionResponse)
async def get_intrusion_detection(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get intrusion (field) detection configuration."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_intrusion_detection(channel=channel)
        if "error" in data:
            raise HTTPException(
                status_code=502, detail="Failed to retrieve intrusion detection config"
            )
        return IntrusionDetectionResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get intrusion detection for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve intrusion detection config")
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/intrusion-detection", response_model=IntrusionDetectionResponse)
async def set_intrusion_detection(
    camera_id: UUID,
    body: IntrusionDetectionUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update intrusion detection rules."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)

    async def _apply() -> dict[str, Any]:
        r = await adapter.set_intrusion_detection(
            body.model_dump(), channel=channel, force=_API_WRITE_FORCE
        )
        if not r.get("success"):
            raise CameraError("device rejected intrusion-detection update")
        return r

    try:
        await staged_camera_write(
            db=session,
            actor_id=current_user.id,
            organization_id=org_scope_or_platform(current_user),
            camera=camera,
            feature="intrusion_detection",
            capture=lambda: adapter.get_intrusion_detection(channel=channel),
            apply=_apply,
            rollback=lambda old: adapter.set_intrusion_detection(
                old, channel=channel, force=_API_WRITE_FORCE
            ),
        )
        data = await adapter.get_intrusion_detection(channel=channel)
        return IntrusionDetectionResponse(**data)
    except HTTPException:
        raise
    except CameraError:
        raise HTTPException(status_code=500, detail="Failed to update intrusion detection")
    except Exception:
        logger.exception("Failed to set intrusion detection for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to update intrusion detection config")
    finally:
        await adapter.disconnect()


# ── Smart Capabilities ───────────────────────────────────────────────────────


@router.get("/{camera_id}/smart-capabilities", response_model=SmartCapabilitiesResponse)
async def get_smart_capabilities(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Probe which smart features the camera channel supports."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_smart_capabilities(channel=channel)
        return SmartCapabilitiesResponse(**data)
    except Exception:
        logger.exception("Failed to get smart capabilities for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to probe smart capabilities")
    finally:
        await adapter.disconnect()


# ── Face Detection ───────────────────────────────────────────────────────────


@router.get("/{camera_id}/face-detection", response_model=FaceDetectionResponse)
async def get_face_detection(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get face detection configuration."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_face_detection(channel=channel)
        if "error" in data:
            raise HTTPException(status_code=502, detail="Failed to retrieve face detection config")
        return FaceDetectionResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get face detection for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve face detection config")
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/face-detection", response_model=FaceDetectionResponse)
async def set_face_detection(
    camera_id: UUID,
    body: FaceDetectionUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update face detection configuration."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)

    async def _apply() -> dict[str, Any]:
        r = await adapter.set_face_detection(
            body.model_dump(), channel=channel, force=_API_WRITE_FORCE
        )
        if not r.get("success"):
            raise CameraError("device rejected face-detection update")
        return r

    try:
        await staged_camera_write(
            db=session,
            actor_id=current_user.id,
            organization_id=org_scope_or_platform(current_user),
            camera=camera,
            feature="face_detection",
            capture=lambda: adapter.get_face_detection(channel=channel),
            apply=_apply,
            rollback=lambda old: adapter.set_face_detection(
                old, channel=channel, force=_API_WRITE_FORCE
            ),
        )
        data = await adapter.get_face_detection(channel=channel)
        return FaceDetectionResponse(**data)
    except HTTPException:
        raise
    except CameraError:
        raise HTTPException(status_code=500, detail="Failed to update face detection")
    except Exception:
        logger.exception("Failed to set face detection for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to update face detection config")
    finally:
        await adapter.disconnect()


# ── Recording Schedule ───────────────────────────────────────────────────────


@router.get("/{camera_id}/recording-schedule", response_model=RecordingScheduleResponse)
async def get_recording_schedule(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get current recording schedule for a camera channel."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_recording_schedule(channel=channel)
        if "error" in data:
            err = str(data.get("error", ""))
            # 401/403/404 → this NVR model doesn't expose a per-channel recording
            # schedule over ISAPI (recording is managed at the NVR). Report it as
            # "not available" (200, supported=False) so the UI shows an honest
            # message instead of a red 502 banner on every camera.
            if any(code in err for code in ("401", "403", "404")):
                return RecordingScheduleResponse(supported=False, enabled=False, days=[])
            raise HTTPException(status_code=502, detail="Failed to retrieve recording schedule")
        return RecordingScheduleResponse(supported=True, **data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get recording schedule for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve recording schedule")
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/recording-schedule", response_model=RecordingScheduleResponse)
async def set_recording_schedule(
    camera_id: UUID,
    body: RecordingScheduleUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update recording schedule for a camera channel."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    outcome = "failed"

    async def _apply() -> dict[str, Any]:
        r = await adapter.set_recording_schedule(
            body.model_dump(), channel=channel, force=_API_WRITE_FORCE
        )
        if not r.get("success"):
            raise CameraError("device rejected recording-schedule update")
        return r

    try:
        await staged_camera_write(
            db=session,
            actor_id=current_user.id,
            organization_id=org_scope_or_platform(current_user),
            camera=camera,
            feature="recording_schedule",
            capture=lambda: adapter.get_recording_schedule(channel=channel),
            apply=_apply,
            rollback=lambda old: adapter.set_recording_schedule(
                old, channel=channel, force=_API_WRITE_FORCE
            ),
        )
        data = await adapter.get_recording_schedule(channel=channel)
        outcome = "ok"
        return RecordingScheduleResponse(**data)
    except HTTPException:
        raise
    except CameraError:
        raise HTTPException(status_code=500, detail="Failed to update recording schedule")
    except Exception:
        logger.exception("Failed to set recording schedule for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to update recording schedule")
    finally:
        await adapter.disconnect()
        from app.modules.cameras.events import record_camera_action

        await record_camera_action(
            "set_recording_schedule",
            camera_id=camera_id,
            adapter_id=(getattr(camera, "vendor", None) or "onvif").lower(),
            organization_id=org_scope_or_platform(current_user),
            outcome=outcome,
            channel=channel,
        )


# ── Holiday Schedule (per-channel) ───────────────────────────────────────────


@router.get("/{camera_id}/holiday-schedule", response_model=HolidayScheduleResponse)
async def get_holiday_schedule(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get holiday recording schedule for a camera channel."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_holiday_schedule(channel=channel)
        if "error" in data:
            raise HTTPException(status_code=502, detail="Failed to retrieve holiday schedule")
        return HolidayScheduleResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get holiday schedule for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve holiday schedule")
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/holiday-schedule", response_model=HolidayScheduleResponse)
async def set_holiday_schedule(
    camera_id: UUID,
    body: HolidayScheduleUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update holiday recording schedule for a camera channel."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)

    async def _apply() -> dict[str, Any]:
        r = await adapter.set_holiday_schedule(
            body.model_dump(), channel=channel, force=_API_WRITE_FORCE
        )
        if not r.get("success"):
            raise CameraError("device rejected holiday-schedule update")
        return r

    try:
        await staged_camera_write(
            db=session,
            actor_id=current_user.id,
            organization_id=org_scope_or_platform(current_user),
            camera=camera,
            feature="holiday_schedule",
            capture=lambda: adapter.get_holiday_schedule(channel=channel),
            apply=_apply,
            rollback=lambda old: adapter.set_holiday_schedule(
                old, channel=channel, force=_API_WRITE_FORCE
            ),
        )
        data = await adapter.get_holiday_schedule(channel=channel)
        return HolidayScheduleResponse(**data)
    except HTTPException:
        raise
    except CameraError:
        raise HTTPException(status_code=500, detail="Failed to update holiday schedule")
    except Exception:
        logger.exception("Failed to set holiday schedule for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to update holiday schedule")
    finally:
        await adapter.disconnect()


# ── Video Clip Export ─────────────────────────────────────────────────────────


@router.post("/{camera_id}/recordings/export")
async def export_video_clip(
    camera_id: UUID,
    body: VideoExportRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Download a video clip from the NVR for a time range.
    Streams the MP4 data directly to the client.

    This data-exfil destructive op needs site_admin:
    bulk video export is the data exfiltration vector for cameras
    (the recordings are the high-value asset). Require ``site_admin``
    minimum role on top of ``cameras.manage``.
    """
    if not current_user.has_min_role("site_admin"):
        raise HTTPException(
            status_code=403,
            detail="Exporting video clips requires the site_admin role",
        )
    await _enforce_camera_access(session, current_user, camera_id, "export")
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")

    # Validate time range
    if body.end_time <= body.start_time:
        raise HTTPException(status_code=400, detail="end_time must be after start_time")
    max_export_hours = 4
    if (body.end_time - body.start_time).total_seconds() > max_export_hours * 3600:
        raise HTTPException(
            status_code=400, detail=f"Export range cannot exceed {max_export_hours} hours"
        )

    adapter, channel = await _get_adapter_for_camera(camera, session)

    # Resolve playback URI — only allow safe NVR-local patterns (prevent SSRF)
    playback_uri = body.playback_uri
    if playback_uri:
        import re

        # Only allow rtsp://0.0.0.0/Streaming/tracks/{digits} pattern
        if not re.match(r"^rtsp://0\.0\.0\.0/Streaming/tracks/\d+$", playback_uri):
            await adapter.disconnect()
            raise HTTPException(
                status_code=400,
                detail="Invalid playback URI format. Must be rtsp://0.0.0.0/Streaming/tracks/{channel}",
            )
    else:
        playback_uri = f"rtsp://0.0.0.0/Streaming/tracks/{channel}01"

    start_iso = body.start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = body.end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    suffix = "_wm" if body.watermark else ""
    filename = f"clip_{camera_id}_{body.start_time.strftime('%Y%m%d_%H%M%S')}{suffix}.mp4"

    # Chain-of-custody: who exported, when, what range — burned into the clip
    # (operator + export time) AND recorded in the audit log + response headers.
    export_id = uuid4().hex[:12]
    operator = (
        getattr(current_user, "email", None)
        or getattr(current_user, "username", None)
        or str(current_user.id)
    )
    export_ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    # Audit: video export is a data-exfiltration-sensitive operation
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.READ,
        resource_type=ResourceType.CAMERA,
        resource_id=camera_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={
            "action": "video_export",
            "start": start_iso,
            "end": end_iso,
            "export_id": export_id,
            "watermarked": body.watermark,
        },
    )

    cam_name = getattr(camera, "name", None) or str(camera_id)
    custody_headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Export-Id": export_id,
        "X-Export-Operator": operator,
        "X-Export-Camera": cam_name,
        "X-Export-Range": f"{start_iso}/{end_iso}",
        "X-Export-Watermarked": "true" if body.watermark else "false",
    }

    try:
        if body.watermark:
            overlay = f"{cam_name}  EXPORTED {export_ts}  by {operator}  id {export_id}"

            async def _stream() -> Any:
                try:
                    async for chunk in adapter.stream_clip_watermarked(
                        channel=channel,
                        start_iso=start_iso,
                        end_iso=end_iso,
                        overlay_text=overlay,
                    ):
                        yield chunk
                finally:
                    await adapter.disconnect()
        else:

            async def _stream() -> Any:
                try:
                    async for chunk in adapter.stream_video_clip(
                        playback_uri=playback_uri,
                        start_time=start_iso,
                        end_time=end_iso,
                    ):
                        yield chunk
                finally:
                    await adapter.disconnect()

        return StreamingResponse(_stream(), media_type="video/mp4", headers=custody_headers)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to export video clip for camera %s", camera_id)
        await adapter.disconnect()
        raise HTTPException(status_code=502, detail="Failed to export video clip")


# ── Camera Health ─────────────────────────────────────────────────────────────


@router.get("/{camera_id}/health", response_model=CameraHealthResponse)
async def get_camera_health(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get live health / bandwidth metrics for a camera."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        track_info = await adapter.get_channel_track_info(channel=channel)
        tracks = track_info.get("tracks", [])
        main = tracks[0] if tracks else {}
        return CameraHealthResponse(
            camera_id=camera_id,
            is_online=True,
            bitrate_kbps=main.get("bitrate_kbps"),
            frame_rate=main.get("frame_rate"),
            codec=main.get("codec"),
            resolution_width=main.get("resolution_width"),
            resolution_height=main.get("resolution_height"),
            captured_at=datetime.now(UTC),
        )
    except Exception:
        logger.exception("Failed to get health for camera %s", camera_id)
        return CameraHealthResponse(
            camera_id=camera_id,
            is_online=False,
            captured_at=datetime.now(UTC),
        )
    finally:
        await adapter.disconnect()


@router.get("/{camera_id}/health/history", response_model=CameraHealthHistoryResponse)
async def get_camera_health_history(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(24, ge=1, le=168),
) -> Any:
    """Get historical health snapshots for a camera (last N hours)."""
    # Verify camera belongs to user's organization (prevents IDOR)
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    from app.modules.cameras.models import CameraHealthSnapshot

    since = datetime.now(UTC) - timedelta(hours=hours)

    result = await session.execute(
        select(CameraHealthSnapshot)
        .where(
            CameraHealthSnapshot.camera_id == camera_id,
            CameraHealthSnapshot.organization_id == current_user.organization_id,
            CameraHealthSnapshot.captured_at >= since,
        )
        .order_by(CameraHealthSnapshot.captured_at.asc())
        .limit(500)
    )
    snapshots = result.scalars().all()
    return CameraHealthHistoryResponse(
        camera_id=camera_id,
        snapshots=[
            CameraHealthResponse(
                camera_id=s.camera_id,
                is_online=s.is_online,
                bitrate_kbps=s.bitrate_kbps,
                frame_rate=s.frame_rate,
                codec=s.codec,
                resolution_width=s.resolution_width,
                resolution_height=s.resolution_height,
                captured_at=s.captured_at,
            )
            for s in snapshots
        ],
    )


@router.get("/health/fleet-summary", response_model=FleetHealthSummary)
async def get_fleet_health_summary(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
) -> Any:
    """Fleet-wide camera health summary."""
    # R5 site-grant: a site-limited caller's fleet summary must only span granted
    # sites (count + bandwidth aggregates). No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    total = await service.count_cameras(
        organization_id=org_scope_or_platform(current_user), accessible_site_ids=_sites
    )
    online = await service.count_cameras(
        status="online",
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    offline = total - online
    # Aggregate the latest health snapshot per ONLINE camera so the
    # "Avg Bitrate" / "Total Bandwidth" tiles are populated.
    # Cameras without a snapshot are excluded; an empty fleet returns 0.0.
    avg_bitrate_kbps, total_bandwidth_kbps = await service.get_fleet_bandwidth(
        organization_id=org_scope_or_platform(current_user), accessible_site_ids=_sites
    )
    return FleetHealthSummary(
        total_cameras=total,
        online_cameras=online,
        offline_cameras=offline,
        avg_bitrate_kbps=avg_bitrate_kbps,
        # FE tile renders this field as Mbps — convert the summed kbps.
        total_bandwidth_mbps=total_bandwidth_kbps / 1000.0,
    )


# =============================================================================
# NVR Endpoints
# =============================================================================

nvr_router = APIRouter(prefix="/nvrs", tags=["NVRs"])


@nvr_router.get("", response_model=NVRListResponse)
@nvr_router.get("/", response_model=NVRListResponse)
async def list_nvrs(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRService, Depends(get_nvr_service)],
    site_id: UUID | None = None,
    status: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Any:
    """List all NVRs with pagination."""
    # restrict site-limited callers to their granted sites.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    nvrs = await service.list_nvrs(
        site_id=site_id,
        status=status,
        limit=limit,
        offset=offset,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    total = await service.count_nvrs(
        site_id=site_id,
        status=status,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    return {"items": nvrs, "total": total, "limit": limit, "offset": offset}


@nvr_router.get("/stats", response_model=NVRStatsResponse)
async def get_nvr_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRService, Depends(get_nvr_service)],
    site_id: UUID | None = None,
) -> Any:
    """Get NVR statistics."""
    # R5 site-grant: a site-limited caller's NVR aggregate must not span sibling
    # sites. No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    stats = await service.get_nvr_stats(
        site_id=site_id,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    return stats


@nvr_router.get("/{nvr_id}", response_model=NVRResponse)
async def get_nvr(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Get an NVR by ID."""
    try:
        nvr = await service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
        # enforce site-grant for site-limited callers.
        assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")
        return nvr
    except NVRNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NVR not found",
        )


@nvr_router.post("/", response_model=NVRResponse, status_code=status.HTTP_201_CREATED)
async def create_nvr(
    body: NVRCreateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Create a new NVR."""
    data = body.model_dump(exclude_unset=True)
    # a site-limited user may only create NVRs in granted sites (no-op for
    # org_admin / grant-less users).
    assert_can_access_site(current_user, data.get("site_id"), detail="Site not found")
    # Encrypt password before storing
    if "password" in data:
        raw_pw = data.pop("password")
        if raw_pw:
            data["password_encrypted"] = encrypt_credential(raw_pw)
    # fail closed (403) for a scoped super_admin key BEFORE the
    # NVR row is created — never an org=None orphan (mirrors create_camera).
    data["organization_id"] = org_scope_or_platform(current_user)
    # NVR.site_id is a FK to the GLOBAL core.sites table with no org
    # constraint, so without this an org-A user could attach an org-B site_id
    # (cross-object FK injection / tenant-graph corruption). Verify the submitted
    # site belongs to the caller's org explicitly — mirrors create_camera above.
    if data.get("site_id") is not None:
        from sqlalchemy import select as _select

        from app.models.core import Site as _Site

        site_ok = await service.db.scalar(
            _select(_Site.id).where(
                _Site.id == data["site_id"],
                _Site.organization_id == current_user.organization_id,
                _Site.deleted_at.is_(None),
            )
        )
        if not site_ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    nvr = await service.create_nvr(data)
    # Audit log
    audit = AuditService(db=service.db)
    await audit.log(
        action=AuditAction.CREATE,
        resource_type=ResourceType.NVR,
        resource_id=nvr.id,
        resource_name=getattr(nvr, "name", None),
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
    )
    # Sync to device registry
    from app.services.device_sync import trigger_device_registry_sync

    trigger_device_registry_sync("cameras")
    return nvr


@nvr_router.patch("/{nvr_id}", response_model=NVRResponse)
async def update_nvr(
    nvr_id: UUID,
    body: NVRUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Update an NVR."""
    try:
        # fetch NVR upfront so we can enforce the site grant
        # before any mutation regardless of which fields are in the request body.
        nvr_existing = await service.get_nvr(
            nvr_id, organization_id=org_scope_or_platform(current_user)
        )
        assert_can_access_site(current_user, nvr_existing.site_id, detail="NVR not found")

        data = body.model_dump(exclude_unset=True)
        # Encrypt password before storing
        if "password" in data:
            raw_pw = data.pop("password")
            if raw_pw:
                data["password_encrypted"] = encrypt_credential(raw_pw)
        # Handle stream_encryption_key → settings JSONB merge
        if "stream_encryption_key" in data:
            enc_key = data.pop("stream_encryption_key")
            current_settings = dict(nvr_existing.settings or {})
            if enc_key:
                current_settings["stream_encryption_key"] = enc_key
            else:
                current_settings.pop("stream_encryption_key", None)
            data["settings"] = current_settings
        nvr = await service.update_nvr(
            nvr_id, data, organization_id=org_scope_or_platform(current_user)
        )
        # Audit log
        audit = AuditService(db=service.db)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.NVR,
            resource_id=nvr_id,
            resource_name=getattr(nvr, "name", None),
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            changes={
                k: {"new": v}
                for k, v in data.items()
                if k not in ("password_encrypted", "settings")
            },
        )
        # Sync to device registry
        from app.services.device_sync import trigger_device_registry_sync

        trigger_device_registry_sync("cameras")
        return nvr
    except NVRNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NVR not found",
        )


@nvr_router.delete("/{nvr_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_nvr(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRService, Depends(get_nvr_service)],
) -> None:
    """Delete an NVR."""
    try:
        nvr_obj = await service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
        # enforce site-grant for site-limited callers.
        assert_can_access_site(current_user, nvr_obj.site_id, detail="NVR not found")
        await service.delete_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
        # Remove shadow device from registry
        from app.services.device_sync import DeviceSyncService

        await DeviceSyncService.remove_device(
            service.db,
            external_id_prefix="nvr",
            source_id=nvr_id,
        )
        # Audit log
        audit = AuditService(db=service.db)
        await audit.log(
            action=AuditAction.DELETE,
            resource_type=ResourceType.NVR,
            resource_id=nvr_id,
            resource_name=getattr(nvr_obj, "name", None),
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
        )
    except NVRNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NVR not found",
        )


@nvr_router.get("/{nvr_id}/channels", response_model=NVRChannelsListResponse)
async def get_nvr_channels(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Get cameras/channels for an NVR."""
    try:
        # verify site-grant before listing channels.
        nvr_for_grant = await service.get_nvr(
            nvr_id, organization_id=org_scope_or_platform(current_user)
        )
        assert_can_access_site(current_user, nvr_for_grant.site_id, detail="NVR not found")
        channels = await service.get_nvr_channels(
            nvr_id, organization_id=org_scope_or_platform(current_user)
        )
        items = [
            {
                "id": str(c.id),
                "name": c.name,
                "channel_id": c.channel_id,
                "status": c.status,
                "ip_address": c.ip_address,
                "camera_type": c.camera_type,
                "has_ptz": bool(c.has_ptz),
                "has_audio": bool(c.has_audio),
                "is_recording": bool(c.is_recording),
                "model": c.model,
                "vendor": c.vendor,
            }
            for c in channels
        ]
        return {"items": items, "total": len(items)}
    except NVRNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NVR not found",
        )


# =============================================================================
# NVR Discovery / Import Endpoints
# =============================================================================


@nvr_router.post("/test-connection", response_model=NVRConnectionTestResponse)
async def test_nvr_connection(
    body: NVRConnectionTestRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
) -> Any:
    """Test connectivity to a Hikvision NVR/camera and return device info."""
    result = await service.test_connection(
        host=body.host,
        port=body.port,
        username=body.username,
        password=body.password,
        vendor=body.vendor,
    )
    return result


@nvr_router.post("/discover", response_model=NVRDiscoveryResponse)
async def discover_nvr_channels(
    body: NVRConnectionTestRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
) -> Any:
    """Discover all camera channels on an NVR/camera and return their details."""
    try:
        result = await service.discover_channels(
            host=body.host,
            port=body.port,
            username=body.username,
            password=body.password,
            vendor=body.vendor,
        )
        return result
    except CameraError as exc:
        logger.warning("NVR discovery failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Discovery failed — check device connectivity and credentials",
        )
    except Exception:
        logger.exception("Unexpected error during NVR discovery for %s:%d", body.host, body.port)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not communicate with device — check IP address and port",
        )


@nvr_router.post("/import", response_model=NVRImportResponse, status_code=status.HTTP_201_CREATED)
async def import_nvr(
    body: NVRImportRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
) -> Any:
    """Import an NVR and selected camera channels into the database."""
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User must belong to an organization to import NVRs",
        )
    # Verify site belongs to user's organization
    from app.models.core import Site

    site = await session.get(Site, body.site_id)
    if not site or site.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Site does not belong to your organization",
        )
    # a site-limited user may only import NVRs into granted sites
    # (no-op for org_admin / grant-less users). Mirrors create_nvr — the org-FK
    # check above does NOT cover a site-scoped caller writing into a sibling site
    # of their own org.
    assert_can_access_site(current_user, body.site_id, detail="Site not found")
    from app.adapters.exceptions import (
        AdapterAuthenticationError,
        AdapterConnectionError,
    )

    # The NVR is a tenant-owned resource, so it MUST carry a concrete owning
    # org — the user's own org (already verified non-None above, and the site
    # was just checked to belong to it). org_scope_or_platform() is a READ
    # filter that returns None for an unscoped super_admin, which would
    # null-violate nvrs.organization_id on insert (the import was failing here).
    owner_org_id = current_user.organization_id
    try:
        result = await service.import_nvr(
            organization_id=owner_org_id,
            site_id=body.site_id,
            host=body.host,
            port=body.port,
            username=body.username,
            password=body.password,
            nvr_name=body.name,
            selected_channels=body.selected_channels,
        )
        # Audit log
        audit = AuditService(db=service.db)
        await audit.log(
            action=AuditAction.IMPORT,
            resource_type=ResourceType.NVR,
            resource_name=body.name or body.host,
            organization_id=owner_org_id,
            actor_id=current_user.id,
            extra_metadata={"host": body.host, "channels": len(body.selected_channels or [])},
        )
        return result
    except AdapterAuthenticationError as exc:
        # Wrong NVR username/password — actionable, distinct from a conflict.
        logger.warning("NVR import auth failed for %s: %s", body.host, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication failed — check the NVR username and password.",
        )
    except AdapterConnectionError as exc:
        # Can't reach the device (wrong host/port, or not routable from the
        # FreeSDN server — firewall / VLAN / different subnet). This was
        # previously mislabeled as "may already be registered".
        logger.warning("NVR import unreachable %s:%s: %s", body.host, body.port, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Cannot reach the NVR at {body.host}:{body.port}. Verify the IP/port and that "
                "the NVR is reachable from the FreeSDN server (a Dockerized server may not route "
                "to a device on your LAN/VLAN)."
            ),
        )
    except CameraError as exc:
        # CameraError covers a genuine conflict, validation, AND the
        # "Cannot connect to device" fallback from _connect_autodetect — so
        # surface the real message instead of always blaming a duplicate.
        logger.warning("NVR import failed for %s: %s", body.host, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"NVR import failed: {exc}",
        )


@nvr_router.post(
    "/import-camera",
    response_model=StandaloneCameraImportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def import_standalone_camera(
    body: StandaloneCameraImportRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
) -> Any:
    """Import a standalone IP camera (not an NVR) directly into the database."""
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User must belong to an organization to import cameras",
        )
    # Verify site belongs to user's organization
    from app.models.core import Site

    site = await session.get(Site, body.site_id)
    if not site or site.organization_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Site does not belong to your organization",
        )
    # a site-limited user may only import cameras into granted sites
    # (no-op for org_admin / grant-less users). Mirrors create_camera — the org-FK
    # check above does NOT cover a site-scoped caller writing into a sibling site
    # of their own org.
    assert_can_access_site(current_user, body.site_id, detail="Site not found")
    try:
        result = await service.import_standalone_camera(
            organization_id=org_scope_or_platform(current_user),
            site_id=body.site_id,
            host=body.host,
            port=body.port,
            username=body.username,
            password=body.password,
            camera_name=body.name,
        )
        audit = AuditService(db=service.db)
        await audit.log(
            action=AuditAction.IMPORT,
            resource_type=ResourceType.CAMERA,
            resource_name=body.name or body.host,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"host": body.host, "type": "standalone"},
        )
        return result
    except CameraError as exc:
        logger.warning("Standalone camera import failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Camera import failed — the device may already be registered",
        )


@nvr_router.post("/{nvr_id}/sync", response_model=NVRSyncResponse)
async def sync_nvr(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Re-scan an NVR and sync its channels with the database."""
    try:
        # Verify NVR belongs to user's org before syncing.
        # also assert site-grant for site-limited callers.
        _nvr_sync = await nvr_service.get_nvr(
            nvr_id, organization_id=org_scope_or_platform(current_user)
        )
        assert_can_access_site(current_user, _nvr_sync.site_id, detail="NVR not found")
        result = await service.sync_nvr(
            nvr_id=nvr_id, organization_id=org_scope_or_platform(current_user)
        )
        # Audit log
        audit = AuditService(db=service.db)
        await audit.log(
            action=AuditAction.SYNC,
            resource_type=ResourceType.NVR,
            resource_id=nvr_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
        )
        return result
    except NVRNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NVR not found",
        )
    except CameraError as exc:
        logger.error("NVR discovery failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="NVR discovery operation failed",
        )


@nvr_router.get("/{nvr_id}/storage", response_model=NVRStorageSummary)
async def get_nvr_storage(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Get real-time storage info from an NVR."""
    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NVR not found",
        )
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="NVR has no stored credentials",
        )

    adapter = service._create_adapter(
        host=nvr.ip_address,
        port=nvr.port or 80,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        # Forward the NVR's saved vendor so _create_adapter selects the
        # Hikvision ISAPI adapter instead of defaulting to ONVIF (which
        # fails on every Hikvision-specific call → 502/500). This was the
        # root cause of storage/system-info/network/recording-status/
        # holidays/reboot/playback all returning 502 on Hikvision NVRs.
        vendor=nvr.vendor,
    )
    try:
        await adapter.connect()
        storage = await adapter.get_storage_info()
        # storage HDD info may include vendor-specific
        # serial / firmware fields — pass through redact_secrets which
        # is a no-op for non-sensitive keys.
        from app.core.redaction import redact_secrets

        return redact_secrets(storage)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to retrieve storage info from NVR",
        )
    finally:
        await adapter.disconnect()


# =============================================================================
# Deep NVR System Endpoints
# =============================================================================


@nvr_router.get("/{nvr_id}/system-info", response_model=NVRSystemInfoResponse)
async def get_nvr_system_info(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """
    Get comprehensive NVR system information — device details, CPU/memory,
    time/NTP, network interfaces, storage, and recording tracks in one call.
    """
    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(status_code=404, detail="NVR not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(status_code=400, detail="NVR has no stored credentials")

    adapter = service._create_adapter(
        host=nvr.ip_address,
        port=nvr.port or 80,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        # Forward the NVR's saved vendor so _create_adapter selects the
        # Hikvision ISAPI adapter instead of defaulting to ONVIF (which
        # fails on every Hikvision-specific call → 502/500). This was the
        # root cause of storage/system-info/network/recording-status/
        # holidays/reboot/playback all returning 502 on Hikvision NVRs.
        vendor=nvr.vendor,
    )
    try:
        await adapter.connect()
        info = await adapter.get_full_system_info()
        # mask any sensitive field the NVR surfaced
        # (community strings, tokens, etc.) before the response leaves
        # the process.
        from app.core.redaction import redact_secrets

        return {"data": redact_secrets(info)}
    except Exception as exc:
        logger.warning("system-info failed for NVR %s: %s", nvr_id, exc)
        raise HTTPException(status_code=502, detail="Failed to query NVR system info")
    finally:
        await adapter.disconnect()


@nvr_router.get("/{nvr_id}/network", response_model=NVRNetworkResponse)
async def get_nvr_network(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Get NVR network interface configuration."""
    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(status_code=404, detail="NVR not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(status_code=400, detail="NVR has no stored credentials")

    adapter = service._create_adapter(
        host=nvr.ip_address,
        port=nvr.port or 80,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        # Forward the NVR's saved vendor so _create_adapter selects the
        # Hikvision ISAPI adapter instead of defaulting to ONVIF (which
        # fails on every Hikvision-specific call → 502/500). This was the
        # root cause of storage/system-info/network/recording-status/
        # holidays/reboot/playback all returning 502 on Hikvision NVRs.
        vendor=nvr.vendor,
    )
    try:
        await adapter.connect()
        interfaces = await adapter.get_network_interfaces()
        time_info = await adapter.get_time_info()
        # redact NTP/SNMP secret fields if present.
        from app.core.redaction import redact_secrets

        return {
            "data": redact_secrets(
                {
                    "interfaces": interfaces,
                    "time": time_info,
                }
            )
        }
    except Exception:
        raise HTTPException(status_code=502, detail="Failed to query NVR network info")
    finally:
        await adapter.disconnect()


@nvr_router.get("/{nvr_id}/recording-status", response_model=NVRRecStatusResponse)
async def get_nvr_recording_status(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Get per-channel recording track status from the NVR."""
    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(status_code=404, detail="NVR not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(status_code=400, detail="NVR has no stored credentials")

    adapter = service._create_adapter(
        host=nvr.ip_address,
        port=nvr.port or 80,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        # Forward the NVR's saved vendor so _create_adapter selects the
        # Hikvision ISAPI adapter instead of defaulting to ONVIF (which
        # fails on every Hikvision-specific call → 502/500). This was the
        # root cause of storage/system-info/network/recording-status/
        # holidays/reboot/playback all returning 502 on Hikvision NVRs.
        vendor=nvr.vendor,
    )
    try:
        await adapter.connect()
        tracks = await adapter.get_recording_tracks()
        # track XML may surface upstream credentials
        # in ``src_url`` — mask before returning.
        from app.core.redaction import redact_secrets

        return {"data": redact_secrets(tracks)}
    except Exception:
        raise HTTPException(status_code=502, detail="Failed to query recording status")
    finally:
        await adapter.disconnect()


@nvr_router.post("/{nvr_id}/recordings/search", response_model=NVRRecordingSearchResponse)
async def search_nvr_recordings(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
    channel: int = Query(1, ge=1, le=256),
    start_time: str = Query(..., description="ISO 8601 start time"),
    end_time: str = Query(..., description="ISO 8601 end time"),
    max_results: int = Query(100, ge=1, le=500),
) -> Any:
    """
    Search NVR recordings for a specific channel and time range.
    Returns recording segments with playback URIs.
    """
    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(status_code=404, detail="NVR not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(status_code=400, detail="NVR has no stored credentials")

    adapter = service._create_adapter(
        host=nvr.ip_address,
        port=nvr.port or 80,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        # Forward the NVR's saved vendor so _create_adapter selects the
        # Hikvision ISAPI adapter instead of defaulting to ONVIF (which
        # fails on every Hikvision-specific call → 502/500). This was the
        # root cause of storage/system-info/network/recording-status/
        # holidays/reboot/playback all returning 502 on Hikvision NVRs.
        vendor=nvr.vendor,
    )
    try:
        await adapter.connect()
        recordings = await adapter.search_recordings(
            channel=channel,
            start_time=start_time,
            end_time=end_time,
            max_results=max_results,
        )
        # Also build playback URL for convenience
        playback_url = adapter.get_playback_url(
            channel=channel,
            start_time=start_time.replace("-", "").replace(":", ""),
            end_time=end_time.replace("-", "").replace(":", ""),
        )
        # recordings list may include vendor metadata
        # — mask sensitive fields before returning.
        from app.core.redaction import redact_secrets

        return {
            "data": redact_secrets(
                {
                    "recordings": recordings,
                    "total": len(recordings),
                    "playback_url": playback_url,
                    "channel": channel,
                    "start_time": start_time,
                    "end_time": end_time,
                }
            )
        }
    except Exception as exc:
        logger.warning("Recording search failed for NVR %s: %s", nvr_id, exc)
        raise HTTPException(status_code=502, detail="Failed to search NVR recordings")
    finally:
        await adapter.disconnect()


@nvr_router.post("/{nvr_id}/reboot", response_model=NVRRebootResponse)
async def reboot_nvr(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
    confirmed: bool = Query(
        False,
        description="Must be true to reboot the NVR (catastrophic — drops every "
        "stream + recording session for ~1-2 min). The UI's type-to-confirm dialog "
        "sets this; without it the API returns 409.",
    ),
) -> Any:
    """Reboot the NVR device.

    rebooting an
    NVR drops every active stream + recording session for ~2 minutes.
    Aligning with the hypervisor pattern, require ``site_admin``
    minimum role in addition to the ``cameras.manage`` permission.
    """
    if not current_user.has_min_role("site_admin"):
        raise HTTPException(
            status_code=403,
            detail="Rebooting an NVR requires the site_admin role",
        )
    # Second factor: a catastrophic op (drops all streams/recordings) must not be
    # a single un-confirmed POST. The UI's type-to-confirm dialog supplies it.
    if not confirmed:
        raise HTTPException(
            status_code=409,
            detail=(
                "Rebooting an NVR is catastrophic (drops all streams + recordings "
                "for ~1-2 min) — resubmit with confirmed=true to proceed."
            ),
        )
    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(status_code=404, detail="NVR not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(status_code=400, detail="NVR has no stored credentials")

    adapter = service._create_adapter(
        host=nvr.ip_address,
        port=nvr.port or 80,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        # Forward the NVR's saved vendor so _create_adapter selects the
        # Hikvision ISAPI adapter instead of defaulting to ONVIF (which
        # fails on every Hikvision-specific call → 502/500). This was the
        # root cause of storage/system-info/network/recording-status/
        # holidays/reboot/playback all returning 502 on Hikvision NVRs.
        vendor=nvr.vendor,
    )
    outcome = "failed"
    try:
        await adapter.connect()
        result = await adapter.reboot_device(device_id="", force=_API_WRITE_FORCE)
        if result.success:
            # Mark NVR as rebooting
            await nvr_service.update_nvr(
                nvr_id, {"status": "rebooting"}, organization_id=org_scope_or_platform(current_user)
            )
            # Audit log — reboot is a critical operation
            audit = AuditService(db=nvr_service.db)
            await audit.log(
                action=AuditAction.REBOOT,
                resource_type=ResourceType.NVR,
                resource_id=nvr_id,
                resource_name=getattr(nvr, "name", None),
                organization_id=org_scope_or_platform(current_user),
                actor_id=current_user.id,
                tags=["critical"],
            )
            outcome = "ok"
            return {
                "status": "ok",
                "message": "NVR is rebooting — it may take 1-2 minutes to come back online.",
            }
        raise HTTPException(status_code=502, detail="Reboot command failed")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=502, detail="Failed to reboot NVR")
    finally:
        await adapter.disconnect()
        # Platform-citizen CRITICAL event — NVR reboot drops every
        # camera stream + active recording for 1-2 min. Automation
        # rules typically want to page oncall on this; the event
        # priority is CRITICAL so noisy rules can filter on it.
        from app.core.events import EventPriority
        from app.modules.cameras.events import record_nvr_action

        await record_nvr_action(
            "reboot",
            nvr_id=nvr_id,
            adapter_id=(getattr(nvr, "vendor", None) or "hikvision").lower(),
            organization_id=org_scope_or_platform(current_user),
            outcome=outcome,
            priority=EventPriority.CRITICAL,
        )


@nvr_router.get("/{nvr_id}/playback/{camera_id}", response_model=NVRPlaybackResponse)
async def get_playback_stream(
    nvr_id: UUID,
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
    start_time: str = Query(..., description="ISO 8601 start time"),
    end_time: str = Query(..., description="ISO 8601 end time"),
) -> Any:
    """
    Proxy a playback MJPEG stream from the NVR for a specific recording segment.
    Uses snapshot-based reconstruction from the NVR's playback API.
    Returns the RTSP playback URL and stream metadata.
    """
    from app.modules.cameras.models import Camera

    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(status_code=404, detail="NVR not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(status_code=400, detail="NVR has no stored credentials")

    # Find the camera to get its channel_id (org-scoped to prevent IDOR)
    db = nvr_service.db
    result = await db.execute(
        select(Camera).where(
            Camera.id == camera_id,
            Camera.nvr_id == nvr_id,
            Camera.organization_id == current_user.organization_id,
            Camera.deleted_at.is_(None),
        )
    )
    camera = result.scalar_one_or_none()
    if not camera:
        raise HTTPException(status_code=404, detail="Camera not found on this NVR")

    channel = camera.channel_id or 1

    adapter = service._create_adapter(
        host=nvr.ip_address,
        port=nvr.port or 80,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        # Forward the NVR's saved vendor so _create_adapter selects the
        # Hikvision ISAPI adapter instead of defaulting to ONVIF (which
        # fails on every Hikvision-specific call → 502/500). This was the
        # root cause of storage/system-info/network/recording-status/
        # holidays/reboot/playback all returning 502 on Hikvision NVRs.
        vendor=nvr.vendor,
    )

    # Build the playback URL — the frontend can use this with an RTSP player
    # or we can proxy frames (for now return the URL + metadata)
    playback_url = adapter.get_playback_url(
        channel=channel,
        start_time=start_time.replace("-", "").replace(":", "").replace("Z", ""),
        end_time=end_time.replace("-", "").replace(":", "").replace("Z", ""),
    )

    return {
        "data": {
            "playback_url": playback_url,
            "channel": channel,
            "camera_id": str(camera_id),
            "camera_name": camera.name,
            "start_time": start_time,
            "end_time": end_time,
        }
    }


# ── NVR Channel Status ──────────────────────────────────────────────────────


@nvr_router.get("/{nvr_id}/channel-status", response_model=NVRChannelStatusResponse)
async def get_nvr_channel_status(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Get online/offline status of all channels on an NVR."""
    from app.adapters.hikvision.adapter import HikvisionAdapter

    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(status_code=404, detail="NVR not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(status_code=400, detail="NVR has no stored credentials")

    adapter = HikvisionAdapter(
        host=nvr.ip_address,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        port=nvr.port or 80,
    )
    try:
        await adapter.connect()
        channels = await adapter.get_channel_status_list()
        return NVRChannelStatusResponse(
            nvr_id=nvr_id,
            channels=channels,  # type: ignore[arg-type]
        )
    except Exception:
        logger.exception("Failed to get channel status for NVR %s", nvr_id)
        raise HTTPException(status_code=502, detail="Failed to get channel status")
    finally:
        await adapter.disconnect()


# ── NVR Holidays (NVR-level, not per-camera) ─────────────────────────────────


@nvr_router.get("/{nvr_id}/holidays", response_model=HolidayListResponse)
async def get_nvr_holidays(
    nvr_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Get NVR-level holiday definitions."""
    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(status_code=404, detail="NVR not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(status_code=400, detail="NVR has no stored credentials")

    adapter = service._create_adapter(
        host=nvr.ip_address,
        port=nvr.port or 80,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        # Forward the NVR's saved vendor so _create_adapter selects the
        # Hikvision ISAPI adapter instead of defaulting to ONVIF (which
        # fails on every Hikvision-specific call → 502/500). This was the
        # root cause of storage/system-info/network/recording-status/
        # holidays/reboot/playback all returning 502 on Hikvision NVRs.
        vendor=nvr.vendor,
    )
    try:
        await adapter.connect()
        data = await adapter.get_holidays()
        if "error" in data:
            raise HTTPException(status_code=502, detail="Failed to retrieve holidays")
        return HolidayListResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get holidays for NVR %s", nvr_id)
        raise HTTPException(status_code=502, detail="Failed to retrieve holidays")
    finally:
        await adapter.disconnect()


@nvr_router.put("/{nvr_id}/holidays", response_model=HolidayListResponse)
async def set_nvr_holidays(
    nvr_id: UUID,
    body: HolidayUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[NVRDiscoveryService, Depends(get_discovery_service)],
    nvr_service: Annotated[NVRService, Depends(get_nvr_service)],
) -> Any:
    """Update NVR-level holiday definitions."""
    try:
        nvr = await nvr_service.get_nvr(nvr_id, organization_id=org_scope_or_platform(current_user))
    except NVRNotFoundError:
        raise HTTPException(status_code=404, detail="NVR not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, nvr.site_id, detail="NVR not found")

    if not nvr.username or not nvr.password_encrypted:
        raise HTTPException(status_code=400, detail="NVR has no stored credentials")

    adapter = service._create_adapter(
        host=nvr.ip_address,
        port=nvr.port or 80,
        username=nvr.username,
        password=decrypt_credential(nvr.password_encrypted),
        # Forward the NVR's saved vendor so _create_adapter selects the
        # Hikvision ISAPI adapter instead of defaulting to ONVIF (which
        # fails on every Hikvision-specific call → 502/500). This was the
        # root cause of storage/system-info/network/recording-status/
        # holidays/reboot/playback all returning 502 on Hikvision NVRs.
        vendor=nvr.vendor,
    )
    try:
        await adapter.connect()
        res = await adapter.set_holidays(
            [h.model_dump() for h in body.holidays], force=_API_WRITE_FORCE
        )
        if not res.get("success"):
            raise HTTPException(status_code=500, detail="Failed to update holidays")
        data = await adapter.get_holidays()

        audit = AuditService(db=nvr_service.db)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=nvr_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"config": "nvr_holidays"},
        )

        return HolidayListResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to set holidays for NVR %s", nvr_id)
        raise HTTPException(status_code=502, detail="Failed to update holidays")
    finally:
        await adapter.disconnect()


# =============================================================================
# Camera Event Endpoints
# =============================================================================

event_router = APIRouter(prefix="/events", tags=["Camera Events"])


@event_router.get("/", response_model=CameraEventListResponse)
async def list_camera_events(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraEventService, Depends(get_event_service)],
    camera_id: UUID | None = None,
    event_type: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    acknowledged: bool | None = None,
    # ``le`` matches CameraEventService._MAX_LIST_LIMIT (500): the service hard-
    # clamps the list to 500 rows, so advertising 1000 here let the "Load More"
    # UI keep growing ``limit`` past 500 and silently load nothing. Keep the
    # endpoint bound and the service clamp in lockstep.
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Any:
    """List camera events."""
    # R5 site-grant: restrict a site-limited caller to events whose parent camera
    # lives in a granted site (also covers the explicit camera_id param). No-op
    # for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    events = await service.list_events(
        camera_id=camera_id,
        event_type=event_type,
        start_time=start_time,
        end_time=end_time,
        acknowledged=acknowledged,
        limit=limit,
        offset=offset,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    total = await service.count_events(
        camera_id=camera_id,
        event_type=event_type,
        start_time=start_time,
        end_time=end_time,
        acknowledged=acknowledged,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    return {"items": events, "total": total, "limit": limit, "offset": offset}


@event_router.get("/unacknowledged/count", response_model=UnacknowledgedCountResponse)
async def unacknowledged_event_count(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraEventService, Depends(get_event_service)],
) -> Any:
    """Get count of unacknowledged camera events."""
    # R5 site-grant: a site-limited caller's unack count must not span sibling
    # sites. No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    count = await service.count_events(
        acknowledged=False,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    return {"count": count}


@event_router.get("/{event_id}", response_model=CameraEventResponse)
async def get_camera_event(
    event_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraEventService, Depends(get_event_service)],
) -> Any:
    """Get a camera event by ID."""
    # R5 site-grant: a site-limited caller may only read an event whose parent
    # camera lives in a granted site (service fail-closes to not-found). No-op
    # for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    try:
        event = await service.get_event(
            event_id,
            organization_id=org_scope_or_platform(current_user),
            accessible_site_ids=_sites,
        )
        return event
    except CameraError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )


@event_router.post("/{event_id}/acknowledge", response_model=CameraEventResponse)
async def acknowledge_event(
    event_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraEventService, Depends(get_event_service)],
) -> Any:
    """Acknowledge a camera event."""
    # R5 site-grant: a site-limited caller may only acknowledge an event whose
    # parent camera lives in a granted site. No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    try:
        event = await service.acknowledge_event(
            event_id,
            current_user.id,
            organization_id=org_scope_or_platform(current_user),
            accessible_site_ids=_sites,
        )
        # Audit log
        audit = AuditService(db=service.db)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA_EVENT,
            resource_id=event_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            changes={"acknowledged": {"old": False, "new": True}},
        )
        return event
    except CameraError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )


@event_router.post("/acknowledge/bulk", response_model=BulkAcknowledgeResponse)
async def bulk_acknowledge_events(
    body: BulkAcknowledgeRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraEventService, Depends(get_event_service)],
) -> Any:
    """Bulk acknowledge camera events."""
    # R5 site-grant: a site-limited caller may only acknowledge events whose
    # parent camera lives in a granted site (others are silently filtered out).
    # No-op for super/org-admin.
    _sites = current_user.accessible_site_ids if current_user.is_site_limited else None
    count = await service.bulk_acknowledge(
        body.event_ids,
        current_user.id,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_sites,
    )
    # Audit log
    audit = AuditService(db=service.db)
    await audit.log(
        action=AuditAction.UPDATE,
        resource_type=ResourceType.CAMERA_EVENT,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"bulk_count": count, "event_ids": [str(e) for e in body.event_ids[:20]]},
        changes={"acknowledged": {"old": False, "new": True}},
    )
    return {"status": "ok", "acknowledged_count": count}


# =============================================================================
# WebPush — browser push notifications for camera alerts
# =============================================================================

push_router = APIRouter(prefix="/push", tags=["Camera Push"])


class _PushKeys(BaseModel):
    p256dh: str
    auth: str


class PushSubscribeRequest(BaseModel):
    """The PushSubscription.toJSON() shape the browser produces."""

    endpoint: str = Field(..., max_length=2048)
    keys: _PushKeys


class PushUnsubscribeRequest(BaseModel):
    endpoint: str = Field(..., max_length=2048)


class VapidKeyResponse(BaseModel):
    enabled: bool
    public_key: str


class PushActionResponse(BaseModel):
    success: bool
    removed: int | None = None


@push_router.get("/vapid-key", response_model=VapidKeyResponse)
async def get_vapid_key(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
) -> Any:
    """Public VAPID key the browser needs to subscribe, plus whether push is
    configured at all (so the UI can hide the toggle when it isn't)."""
    from app.modules.cameras.push_service import push_enabled, vapid_public_key

    return VapidKeyResponse(enabled=push_enabled(), public_key=vapid_public_key())


@push_router.post("/subscribe", response_model=PushActionResponse)
async def push_subscribe(
    payload: PushSubscribeRequest,
    request: Request,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Register this browser to receive camera-alert push notifications."""
    from app.modules.cameras.push_service import PushService, push_enabled

    if not push_enabled():
        raise HTTPException(status_code=503, detail="Push notifications are not configured")
    svc = PushService(session)
    await svc.subscribe(
        user_id=current_user.id,
        organization_id=org_scope_or_platform(current_user),
        endpoint=payload.endpoint,
        p256dh=payload.keys.p256dh,
        auth=payload.keys.auth,
        user_agent=request.headers.get("user-agent"),
    )
    return PushActionResponse(success=True)


@push_router.post("/unsubscribe", response_model=PushActionResponse)
async def push_unsubscribe(
    payload: PushUnsubscribeRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Stop sending push to this browser (org-scoped delete by endpoint)."""
    from app.modules.cameras.push_service import PushService

    svc = PushService(session)
    removed = await svc.unsubscribe(
        endpoint=payload.endpoint, organization_id=org_scope_or_platform(current_user)
    )
    return PushActionResponse(success=True, removed=removed)


# =============================================================================
# Network discovery (ONVIF WS-Discovery)
# =============================================================================

discovery_router = APIRouter(prefix="/discovery", tags=["Camera Discovery"])


class DiscoveredDevice(BaseModel):
    ip: str
    vendor: str | None = None
    model: str | None = None
    hardware: str | None = None
    xaddrs: list[str] = Field(default_factory=list)


class DiscoverScanResponse(BaseModel):
    devices: list[DiscoveredDevice]
    count: int


@discovery_router.post("/scan", response_model=DiscoverScanResponse)
async def scan_for_cameras(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.nvr"))],
    timeout: float = Query(4.0, ge=0.5, le=15.0, description="Seconds to listen for responses"),
) -> Any:
    """Probe the server's local network (ONVIF WS-Discovery multicast) and return
    the cameras/NVRs that answer — IP + best-effort vendor/model.

    Read-only: nothing is imported. The operator picks a result to pre-fill the
    Add-device form. Requires cameras.nvr (it scans the local network).
    """
    from app.adapters.onvif.discovery import discover_onvif_devices

    try:
        found = await discover_onvif_devices(timeout=timeout, retries=2)
    except Exception as exc:
        logger.warning("ONVIF discovery scan failed: %s", exc)
        raise HTTPException(status_code=502, detail="Network discovery failed")

    devices = [
        DiscoveredDevice(
            ip=d.get("ip") or "",
            vendor=d.get("vendor"),
            model=d.get("model"),
            hardware=d.get("hardware"),
            xaddrs=d.get("xaddrs") or [],
        )
        for d in found
        if d.get("ip")
    ]
    return DiscoverScanResponse(devices=devices, count=len(devices))


# =============================================================================
# Evidence archive (legal hold)
# =============================================================================

evidence_router = APIRouter(prefix="/evidence", tags=["Camera Evidence"])


class EvidenceCreateRequest(BaseModel):
    camera_id: UUID
    start_time: datetime
    end_time: datetime
    watermark: bool = True
    note: str | None = Field(None, max_length=500)


class EvidenceArchiveItem(BaseModel):
    id: UUID
    camera_id: UUID
    camera_name: str | None
    start_time: datetime
    end_time: datetime
    watermarked: bool
    status: str
    file_size: int | None
    sha256: str | None
    note: str | None
    error: str | None
    created_at: datetime
    completed_at: datetime | None


class EvidenceListResponse(BaseModel):
    items: list[EvidenceArchiveItem]


def _evidence_item(a: Any) -> EvidenceArchiveItem:
    return EvidenceArchiveItem(
        id=a.id,
        camera_id=a.camera_id,
        camera_name=a.camera_name,
        start_time=a.start_time,
        end_time=a.end_time,
        watermarked=a.watermarked,
        status=a.status,
        file_size=a.file_size,
        sha256=a.sha256,
        note=a.note,
        error=a.error,
        created_at=a.created_at,
        completed_at=a.completed_at,
    )


@evidence_router.post("", response_model=EvidenceArchiveItem, status_code=status.HTTP_201_CREATED)
async def create_evidence_hold(
    body: EvidenceCreateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Place a time window on LEGAL HOLD: copy it off the NVR to durable storage
    with a SHA-256 integrity hash. Runs async (export is ~real-time); poll the
    archive's status. Requires site_admin (it exfiltrates + retains footage)."""
    if not current_user.has_min_role("site_admin"):
        raise HTTPException(status_code=403, detail="Evidence hold requires the site_admin role")
    if body.end_time <= body.start_time:
        raise HTTPException(status_code=400, detail="end_time must be after start_time")
    if (body.end_time - body.start_time).total_seconds() > 4 * 3600:
        raise HTTPException(status_code=400, detail="Evidence hold range cannot exceed 4 hours")
    await _enforce_camera_access(session, current_user, body.camera_id, "export")
    try:
        camera = await service.get_camera(
            body.camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")

    from app.modules.cameras.models import EvidenceArchive

    arch = EvidenceArchive(
        organization_id=org_scope_or_platform(current_user),
        camera_id=body.camera_id,
        camera_name=getattr(camera, "name", None),
        start_time=body.start_time,
        end_time=body.end_time,
        watermarked=body.watermark,
        status="pending",
        note=body.note,
        created_by=current_user.id,
    )
    session.add(arch)
    await session.commit()
    await session.refresh(arch)

    await AuditService(db=session).log(
        action=AuditAction.CREATE,
        resource_type=ResourceType.CAMERA,
        resource_id=body.camera_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"action": "evidence_hold", "archive_id": str(arch.id)},
    )

    # Dispatch the export → durable file → hash task.
    try:
        from app.tasks.cameras import archive_evidence

        archive_evidence.delay(str(arch.id))
    except Exception as exc:  # pragma: no cover - dispatch failure shouldn't 500
        logger.warning("Failed to dispatch evidence archive %s: %s", arch.id, exc)

    return _evidence_item(arch)


class EvidenceBatchCreateRequest(BaseModel):
    camera_ids: list[UUID]
    start_time: datetime
    end_time: datetime
    watermark: bool = True
    note: str | None = None


@evidence_router.post(
    "/batch", response_model=EvidenceListResponse, status_code=status.HTTP_201_CREATED
)
async def create_evidence_batch(
    body: EvidenceBatchCreateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.export"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Place the SAME recorded window on hold for many cameras at once — one sealed,
    hash-verified archive per camera. Bulk export is the data-exfiltration vector for
    cameras, so this requires site_admin (same gate as the single hold + the
    synchronous export endpoint)."""
    if not current_user.has_min_role("site_admin"):
        raise HTTPException(status_code=403, detail="Evidence hold requires the site_admin role")
    if not body.camera_ids:
        raise HTTPException(status_code=400, detail="No cameras selected")
    if len(body.camera_ids) > 32:
        raise HTTPException(status_code=400, detail="Cannot batch more than 32 cameras at once")
    if body.end_time <= body.start_time:
        raise HTTPException(status_code=400, detail="end_time must be after start_time")
    if (body.end_time - body.start_time).total_seconds() > 4 * 3600:
        raise HTTPException(status_code=400, detail="Evidence hold range cannot exceed 4 hours")

    from app.modules.cameras.models import Camera, EvidenceArchive

    # Dedupe while preserving the caller's order, then org-scope every camera.
    seen: set[UUID] = set()
    ids = [c for c in body.camera_ids if not (c in seen or seen.add(c))]
    cams = (
        (
            await session.execute(
                select(Camera).where(
                    Camera.id.in_(ids),
                    Camera.organization_id == current_user.organization_id,
                    Camera.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    found = {c.id: c for c in cams}
    missing = [str(c) for c in ids if c not in found]
    if missing:
        raise HTTPException(status_code=404, detail=f"Cameras not found: {', '.join(missing)}")

    # Enforce the per-camera export grant on EVERY camera in the batch (an
    # org-admin bypasses; a restricted user can only batch cameras they may
    # export). Fail the whole batch on the first denial — partial exfiltration
    # of an un-granted camera would defeat the point.
    for cid in ids:
        await _enforce_camera_access(session, current_user, cid, "export")

    archives = []
    for cid in ids:
        cam = found[cid]
        arch = EvidenceArchive(
            organization_id=org_scope_or_platform(current_user),
            camera_id=cam.id,
            camera_name=cam.name,
            start_time=body.start_time,
            end_time=body.end_time,
            watermarked=body.watermark,
            status="pending",
            note=body.note,
            created_by=current_user.id,
        )
        session.add(arch)
        archives.append(arch)
    await session.commit()
    for arch in archives:
        await session.refresh(arch)

    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.CREATE,
        resource_type=ResourceType.CAMERA,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={
            "action": "evidence_batch",
            "count": len(archives),
            "archive_ids": [str(a.id) for a in archives],
        },
    )

    for arch in archives:
        try:
            from app.tasks.cameras import archive_evidence

            archive_evidence.delay(str(arch.id))
        except Exception as exc:
            logger.warning("Failed to dispatch evidence archive %s: %s", arch.id, exc)

    return EvidenceListResponse(items=[_evidence_item(a) for a in archives])


@evidence_router.get("/bundle")
async def download_evidence_bundle(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.export"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    ids: str = Query(..., description="Comma-separated evidence archive IDs"),
) -> Any:
    """Stream a ZIP of several sealed clips + a SHA-256 MANIFEST for chain-of-custody
    of the whole set (site_admin). Only ``ready`` archives in the caller's org are
    included; the ZIP is assembled on disk (not buffered in RAM) and cleaned up after
    the response is sent."""
    if not current_user.has_min_role("site_admin"):
        raise HTTPException(
            status_code=403, detail="Downloading evidence requires the site_admin role"
        )
    try:
        id_list = [UUID(x.strip()) for x in ids.split(",") if x.strip()]
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid id list")
    if not id_list:
        raise HTTPException(status_code=400, detail="No ids provided")
    if len(id_list) > 64:
        raise HTTPException(status_code=400, detail="Too many ids (max 64)")

    from app.modules.cameras.models import EvidenceArchive

    rows = (
        (
            await session.execute(
                select(EvidenceArchive).where(
                    EvidenceArchive.id.in_(id_list),
                    EvidenceArchive.organization_id == current_user.organization_id,
                    EvidenceArchive.status == "ready",
                )
            )
        )
        .scalars()
        .all()
    )
    import os

    ready = [r for r in rows if r.file_path and os.path.exists(r.file_path)]
    if not ready:
        raise HTTPException(status_code=409, detail="No ready evidence files to bundle")

    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.READ,
        resource_type=ResourceType.CAMERA,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"action": "evidence_bundle", "archive_ids": [str(r.id) for r in ready]},
    )

    import re
    import tempfile
    import zipfile

    from app.core.config import settings

    fd, zip_path = tempfile.mkstemp(suffix=".zip", dir=settings.EVIDENCE_DIR)
    os.close(fd)
    manifest = ["FreeSDN evidence bundle", f"archives: {len(ready)}", ""]
    try:
        # ZIP_STORED — the MP4s are already compressed, so streaming-copy (no CPU).
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zf:
            for r in ready:
                raw = (
                    f"evidence_{str(r.id)[:8]}_{r.camera_name or r.camera_id}_"
                    f"{r.start_time.strftime('%Y%m%d_%H%M%S')}.mp4"
                )
                arcname = re.sub(r"[^A-Za-z0-9._-]", "_", raw)
                zf.write(r.file_path, arcname=arcname)
                manifest.append(
                    f"{arcname}\n"
                    f"  camera : {r.camera_name}\n"
                    f"  window : {r.start_time.isoformat()} -> {r.end_time.isoformat()}\n"
                    f"  sha256 : {r.sha256}\n"
                    f"  bytes  : {r.file_size}\n"
                    f"  sealed : {r.completed_at.isoformat() if r.completed_at else ''}\n"
                )
            zf.writestr("MANIFEST.txt", "\n".join(manifest))
    except Exception:
        with contextlib.suppress(OSError):
            os.remove(zip_path)
        raise

    from starlette.background import BackgroundTask

    def _cleanup(path: str) -> None:
        with contextlib.suppress(OSError):
            os.remove(path)

    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename="evidence_bundle.zip",
        background=BackgroundTask(_cleanup, zip_path),
    )


@evidence_router.get("", response_model=EvidenceListResponse)
async def list_evidence(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    camera_id: UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
) -> Any:
    from app.modules.cameras.models import Camera, EvidenceArchive

    q = select(EvidenceArchive).where(
        EvidenceArchive.organization_id == current_user.organization_id
    )
    # Site-grant: EvidenceArchive has no site_id of its own — it is scoped via its
    # parent camera. A site-limited caller may only list evidence whose camera is in
    # a granted site. No-op for super/org-admin (who also keep evidence whose camera
    # was since deleted; the subquery would otherwise hide those).
    if current_user.is_site_limited:
        q = q.where(
            EvidenceArchive.camera_id.in_(
                select(Camera.id).where(site_scope_filter(current_user, Camera.site_id))
            )
        )
    if camera_id:
        q = q.where(EvidenceArchive.camera_id == camera_id)
    q = q.order_by(EvidenceArchive.created_at.desc()).limit(limit)
    rows = (await session.execute(q)).scalars().all()
    return EvidenceListResponse(items=[_evidence_item(a) for a in rows])


async def _get_evidence_or_404(
    archive_id: UUID, current_user: CurrentUser, session: AsyncSession
) -> Any:
    from app.modules.cameras.models import Camera, EvidenceArchive

    arch = await session.get(EvidenceArchive, archive_id)
    if arch is None or arch.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Evidence archive not found")
    # Site-grant: a site-limited caller may only reach evidence whose parent camera
    # lives in a granted site (no-op for super/org-admin).
    if current_user.is_site_limited:
        cam = await session.get(Camera, arch.camera_id)
        if cam is None or not current_user.can_access_site(cam.site_id):
            raise HTTPException(status_code=404, detail="Evidence archive not found")
    return arch


@evidence_router.get("/{archive_id}", response_model=EvidenceArchiveItem)
async def get_evidence(
    archive_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    arch = await _get_evidence_or_404(archive_id, current_user, session)
    return _evidence_item(arch)


@evidence_router.get("/{archive_id}/download")
async def download_evidence(
    archive_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not current_user.has_min_role("site_admin"):
        raise HTTPException(
            status_code=403, detail="Downloading evidence requires the site_admin role"
        )
    arch = await _get_evidence_or_404(archive_id, current_user, session)
    import os

    if arch.status != "ready" or not arch.file_path or not os.path.isfile(arch.file_path):
        raise HTTPException(status_code=409, detail="Evidence is not ready for download")
    await AuditService(db=session).log(
        action=AuditAction.READ,
        resource_type=ResourceType.CAMERA,
        resource_id=arch.camera_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"action": "evidence_download", "archive_id": str(arch.id)},
    )
    fname = f"evidence_{str(arch.id)[:8]}_{arch.start_time.strftime('%Y%m%d_%H%M%S')}.mp4"
    return FileResponse(
        arch.file_path,
        media_type="video/mp4",
        filename=fname,
        headers={"X-Evidence-Sha256": arch.sha256 or "", "X-Evidence-Id": str(arch.id)},
    )


@evidence_router.delete("/{archive_id}")
async def delete_evidence(
    archive_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not current_user.has_min_role("site_admin"):
        raise HTTPException(
            status_code=403, detail="Deleting evidence requires the site_admin role"
        )
    arch = await _get_evidence_or_404(archive_id, current_user, session)
    import os

    # Don't delete a row the archive worker is actively writing — deleting it
    # mid-export orphans the partial file (file_path is still NULL) and makes the
    # worker's finally-commit raise StaleDataError (UPDATE matched 0 rows). The
    # caller can delete once it reaches ready/failed.
    if arch.status == "archiving":
        raise HTTPException(
            status_code=409,
            detail="Evidence is still archiving; cannot delete until it completes or fails",
        )

    await AuditService(db=session).log(
        action=AuditAction.DELETE,
        resource_type=ResourceType.CAMERA,
        resource_id=arch.camera_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"action": "evidence_delete", "archive_id": str(arch.id)},
    )
    if arch.file_path:
        with contextlib.suppress(OSError):
            if os.path.isfile(arch.file_path):
                os.remove(arch.file_path)
    await session.delete(arch)
    await session.commit()
    return {"status": "ok", "deleted": str(archive_id)}


# =============================================================================
# Camera Groups
# =============================================================================

group_router = APIRouter(prefix="/groups", tags=["Camera Groups"])


@group_router.get("/", response_model=GroupListResponse)
async def list_groups(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """List all camera groups with member counts."""
    from app.modules.cameras.models import CameraGroup, CameraGroupMember

    result = await session.execute(
        select(
            CameraGroup,
            func.count(CameraGroupMember.camera_id).label("camera_count"),
        )
        .outerjoin(CameraGroupMember, CameraGroup.id == CameraGroupMember.group_id)
        .where(
            CameraGroup.deleted_at.is_(None),
            CameraGroup.organization_id == current_user.organization_id,
        )
        .group_by(CameraGroup.id)
        .order_by(CameraGroup.sort_order, CameraGroup.name)
    )
    rows = result.all()
    items = []
    for group, count in rows:
        items.append(
            {
                "id": str(group.id),
                "name": group.name,
                "description": group.description,
                "color": group.color,
                "icon": group.icon,
                "sort_order": group.sort_order,
                "is_default": group.is_default,
                "camera_count": count,
                "created_at": group.created_at.isoformat() if group.created_at else None,
            }
        )
    return {"items": items, "total": len(items)}


@group_router.post("/", status_code=201, response_model=GroupCreateResponse)
async def create_group(
    body: GroupCreateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create a camera group, optionally with initial member cameras."""
    from app.modules.cameras.models import Camera, CameraGroup, CameraGroupMember

    group = CameraGroup(
        name=body.name,
        description=body.description,
        color=body.color,
        icon=body.icon,
        organization_id=org_scope_or_platform(current_user),
        created_by=current_user.id,
    )
    session.add(group)
    await session.flush()

    if body.camera_ids:
        # Validate all camera_ids belong to the user's organization AND a granted
        # site — a site-limited caller must not be able to seed a group with a
        # camera from a sibling site (site_scope_filter is a no-op for super/org).
        cam_result = await session.execute(
            select(Camera.id).where(
                Camera.id.in_(body.camera_ids),
                Camera.organization_id == current_user.organization_id,
                Camera.deleted_at.is_(None),
                site_scope_filter(current_user, Camera.site_id),
            )
        )
        valid_ids = {row[0] for row in cam_result.all()}
        invalid = [str(c) for c in body.camera_ids if c not in valid_ids]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Cameras not found: {', '.join(invalid)}")
        for i, cam_id in enumerate(body.camera_ids):
            session.add(
                CameraGroupMember(
                    group_id=group.id,
                    camera_id=cam_id,
                    sort_order=i,
                )
            )

    await session.commit()
    # Audit log
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.CREATE,
        resource_type=ResourceType.CAMERA_GROUP,
        resource_id=group.id,
        resource_name=group.name,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
    )
    return {
        "id": str(group.id),
        "name": group.name,
        "color": group.color,
        "icon": group.icon,
    }


@group_router.get("/{group_id}", response_model=GroupDetailResponse)
async def get_group(
    group_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a camera group with its member cameras."""
    from app.modules.cameras.models import Camera, CameraGroup, CameraGroupMember

    result = await session.execute(
        select(CameraGroup).where(
            CameraGroup.id == group_id,
            CameraGroup.deleted_at.is_(None),
            CameraGroup.organization_id == current_user.organization_id,
        )
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    members_result = await session.execute(
        select(
            CameraGroupMember.camera_id, CameraGroupMember.sort_order, Camera.name, Camera.status
        )
        .join(Camera, CameraGroupMember.camera_id == Camera.id)
        .where(
            CameraGroupMember.group_id == group_id,
            Camera.organization_id == current_user.organization_id,
            Camera.deleted_at.is_(None),
            # Site-grant: a site-limited caller viewing a (possibly cross-site)
            # group must only see member cameras in their granted sites.
            site_scope_filter(current_user, Camera.site_id),
        )
        .order_by(CameraGroupMember.sort_order)
        .limit(500)
    )
    members = [
        {
            "camera_id": str(r.camera_id),
            "sort_order": r.sort_order,
            "name": r.name,
            "status": r.status,
        }
        for r in members_result.all()
    ]

    return {
        "id": str(group.id),
        "name": group.name,
        "description": group.description,
        "color": group.color,
        "icon": group.icon,
        "sort_order": group.sort_order,
        "is_default": group.is_default,
        "camera_count": len(members),
        "cameras": members,
        "created_at": group.created_at.isoformat() if group.created_at else None,
    }


@group_router.patch("/{group_id}", response_model=StatusIdResponse)
async def update_group(
    group_id: UUID,
    body: GroupUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update a camera group. If camera_ids provided, replaces all members."""
    from app.modules.cameras.models import Camera, CameraGroup, CameraGroupMember

    result = await session.execute(
        select(CameraGroup).where(
            CameraGroup.id == group_id,
            CameraGroup.deleted_at.is_(None),
            CameraGroup.organization_id == current_user.organization_id,
        )
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if body.name is not None:
        group.name = body.name
    if body.description is not None:
        group.description = body.description
    if body.color is not None:
        group.color = body.color
    if body.icon is not None:
        group.icon = body.icon
    group.updated_by = current_user.id

    if body.camera_ids is not None:
        # Validate all camera_ids belong to the user's organization AND a granted
        # site (site-limited caller cannot add a sibling-site camera to the group).
        if body.camera_ids:
            cam_result = await session.execute(
                select(Camera.id).where(
                    Camera.id.in_(body.camera_ids),
                    Camera.organization_id == current_user.organization_id,
                    Camera.deleted_at.is_(None),
                    site_scope_filter(current_user, Camera.site_id),
                )
            )
            valid_ids = {row[0] for row in cam_result.all()}
            invalid = [str(c) for c in body.camera_ids if c not in valid_ids]
            if invalid:
                raise HTTPException(
                    status_code=400, detail=f"Cameras not found: {', '.join(invalid)}"
                )
        from sqlalchemy import delete as sa_delete

        await session.execute(
            sa_delete(CameraGroupMember).where(CameraGroupMember.group_id == group_id)
        )
        for i, cam_id in enumerate(body.camera_ids):
            session.add(
                CameraGroupMember(
                    group_id=group.id,
                    camera_id=cam_id,
                    sort_order=i,
                )
            )

    await session.commit()

    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.UPDATE,
        resource_type=ResourceType.CAMERA,
        resource_id=group_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"resource": "camera_group", "name": group.name},
    )

    return {"status": "ok", "id": str(group.id)}


@group_router.delete("/{group_id}", status_code=204)
async def delete_group(
    group_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Soft-delete a camera group."""
    from app.modules.cameras.models import CameraGroup

    result = await session.execute(
        select(CameraGroup).where(
            CameraGroup.id == group_id,
            CameraGroup.deleted_at.is_(None),
            CameraGroup.organization_id == current_user.organization_id,
        )
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    group.deleted_at = datetime.now(UTC)
    await session.commit()
    # Audit log
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.DELETE,
        resource_type=ResourceType.CAMERA_GROUP,
        resource_id=group_id,
        resource_name=group.name,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
    )


# =============================================================================
# Camera Views (Custom Layouts)
# =============================================================================

view_router = APIRouter(prefix="/views", tags=["Camera Views"])


@view_router.get("/", response_model=ViewListResponse)
async def list_views(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """List camera views accessible to the current user (owned + shared)."""
    from app.modules.cameras.models import CameraView

    result = await session.execute(
        select(CameraView)
        .where(
            CameraView.deleted_at.is_(None),
            CameraView.organization_id == current_user.organization_id,
            or_(
                CameraView.user_id == current_user.id,
                CameraView.is_shared.is_(True),
            ),
        )
        .order_by(CameraView.sort_order, CameraView.name)
        .limit(200)
    )
    views = result.scalars().all()
    return {
        "items": [
            {
                "id": str(v.id),
                "name": v.name,
                "description": v.description,
                "layout": v.layout,
                "camera_ids": [str(c) for c in (v.camera_ids or [])],
                "filters": v.filters or {},
                "is_default": v.is_default,
                "is_shared": v.is_shared,
                "is_owner": v.user_id == current_user.id,
                "sort_order": v.sort_order,
                "created_at": v.created_at.isoformat() if v.created_at else None,
            }
            for v in views
        ],
        "total": len(views),
    }


@view_router.post("/", status_code=201, response_model=ViewCreateResponse)
async def create_view(
    body: ViewCreateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create a custom camera view/layout."""
    from app.modules.cameras.models import Camera, CameraView

    # Validate all camera_ids belong to the user's organization AND a granted site
    # (a site-limited caller must not pin a sibling-site camera into a view).
    validated_camera_ids = body.camera_ids
    if validated_camera_ids:
        cam_result = await session.execute(
            select(Camera.id).where(
                Camera.id.in_(validated_camera_ids),
                Camera.organization_id == current_user.organization_id,
                Camera.deleted_at.is_(None),
                site_scope_filter(current_user, Camera.site_id),
            )
        )
        valid_ids = {row[0] for row in cam_result.all()}
        invalid = [str(c) for c in validated_camera_ids if c not in valid_ids]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Cameras not found: {', '.join(invalid)}")

    view = CameraView(
        name=body.name,
        description=body.description,
        layout=body.layout,
        camera_ids=validated_camera_ids,
        is_shared=body.is_shared,
        user_id=current_user.id,
        organization_id=org_scope_or_platform(current_user),
        created_by=current_user.id,
    )
    session.add(view)
    await session.commit()
    # Audit log
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.CREATE,
        resource_type=ResourceType.CAMERA_VIEW,
        resource_id=view.id,
        resource_name=view.name,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
    )
    return {
        "id": str(view.id),
        "name": view.name,
        "layout": view.layout,
        "camera_ids": [str(c) for c in (view.camera_ids or [])],
    }


@view_router.patch("/{view_id}", response_model=StatusIdResponse)
async def update_view(
    view_id: UUID,
    body: ViewUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update a camera view."""
    from app.modules.cameras.models import Camera, CameraView

    result = await session.execute(
        select(CameraView).where(
            CameraView.id == view_id,
            CameraView.deleted_at.is_(None),
            CameraView.organization_id == current_user.organization_id,
        )
    )
    view = result.scalar_one_or_none()
    if not view:
        raise HTTPException(status_code=404, detail="View not found")
    # Only the view owner can edit (shared views are read-only to non-owners)
    if view.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the view owner can edit")

    if body.name is not None:
        view.name = body.name
    if body.layout is not None:
        view.layout = body.layout
    if body.camera_ids is not None:
        # Validate all camera_ids belong to the user's organization AND a granted
        # site (a site-limited caller must not pin a sibling-site camera into a view).
        if body.camera_ids:
            cam_result = await session.execute(
                select(Camera.id).where(
                    Camera.id.in_(body.camera_ids),
                    Camera.organization_id == current_user.organization_id,
                    Camera.deleted_at.is_(None),
                    site_scope_filter(current_user, Camera.site_id),
                )
            )
            valid_ids = {row[0] for row in cam_result.all()}
            invalid = [str(c) for c in body.camera_ids if c not in valid_ids]
            if invalid:
                raise HTTPException(
                    status_code=400, detail=f"Cameras not found: {', '.join(invalid)}"
                )
        view.camera_ids = body.camera_ids
    if body.description is not None:
        view.description = body.description
    if body.is_shared is not None:
        view.is_shared = body.is_shared
    if body.is_default is not None:
        view.is_default = body.is_default
    view.updated_by = current_user.id

    await session.commit()

    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.UPDATE,
        resource_type=ResourceType.CAMERA,
        resource_id=view_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"resource": "camera_view", "name": view.name},
    )

    return {"status": "ok", "id": str(view.id)}


@view_router.delete("/{view_id}", status_code=204)
async def delete_view(
    view_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a camera view."""
    from app.modules.cameras.models import CameraView

    result = await session.execute(
        select(CameraView).where(
            CameraView.id == view_id,
            CameraView.deleted_at.is_(None),
            CameraView.organization_id == current_user.organization_id,
        )
    )
    view = result.scalar_one_or_none()
    if not view:
        raise HTTPException(status_code=404, detail="View not found")
    if view.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")

    view.deleted_at = datetime.now(UTC)
    await session.commit()
    # Audit log
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.DELETE,
        resource_type=ResourceType.CAMERA_VIEW,
        resource_id=view_id,
        resource_name=view.name,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
    )


# =============================================================================
# Recording Schedule Template CRUD
# =============================================================================

template_router = APIRouter(prefix="/recording-templates", tags=["Recording Templates"])


@template_router.get("", response_model=list[RecordingScheduleTemplateResponse])
@template_router.get("/", response_model=list[RecordingScheduleTemplateResponse])
async def list_templates(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """List recording schedule templates for the current org."""
    from app.modules.cameras.models import RecordingScheduleTemplate

    result = await session.execute(
        select(RecordingScheduleTemplate)
        .where(
            RecordingScheduleTemplate.deleted_at.is_(None),
            (
                (RecordingScheduleTemplate.organization_id == current_user.organization_id)
                | (RecordingScheduleTemplate.is_builtin.is_(True))
            ),
        )
        .order_by(RecordingScheduleTemplate.name)
        .limit(200)
    )
    return list(result.scalars().all())


@template_router.post(
    "/", status_code=status.HTTP_201_CREATED, response_model=RecordingScheduleTemplateResponse
)
async def create_template(
    body: RecordingScheduleTemplateCreateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create a new recording schedule template."""
    from app.modules.cameras.models import RecordingScheduleTemplate

    tmpl = RecordingScheduleTemplate(
        organization_id=org_scope_or_platform(current_user),
        name=body.name,
        description=body.description,
        schedule=body.schedule,
        is_builtin=False,
        created_by=current_user.id,
    )
    session.add(tmpl)
    await session.commit()
    await session.refresh(tmpl)
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.CREATE,
        resource_type=ResourceType.CAMERA,
        resource_id=tmpl.id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"config": "recording_template", "name": body.name},
    )
    return tmpl


@template_router.patch("/{template_id}", response_model=RecordingScheduleTemplateResponse)
async def update_template(
    template_id: UUID,
    body: RecordingScheduleTemplateCreateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update a recording schedule template."""
    from app.modules.cameras.models import RecordingScheduleTemplate

    result = await session.execute(
        select(RecordingScheduleTemplate).where(
            RecordingScheduleTemplate.id == template_id,
            RecordingScheduleTemplate.deleted_at.is_(None),
            RecordingScheduleTemplate.organization_id == current_user.organization_id,
            RecordingScheduleTemplate.is_builtin.is_(False),
        )
    )
    tmpl = result.scalar_one_or_none()
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")

    tmpl.name = body.name
    tmpl.description = body.description
    tmpl.schedule = body.schedule
    tmpl.updated_by = current_user.id
    await session.commit()
    await session.refresh(tmpl)
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.UPDATE,
        resource_type=ResourceType.CAMERA,
        resource_id=template_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"config": "recording_template", "name": body.name},
    )
    return tmpl


@template_router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_template(
    template_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a recording schedule template."""
    from app.modules.cameras.models import RecordingScheduleTemplate

    result = await session.execute(
        select(RecordingScheduleTemplate).where(
            RecordingScheduleTemplate.id == template_id,
            RecordingScheduleTemplate.deleted_at.is_(None),
            RecordingScheduleTemplate.organization_id == current_user.organization_id,
            RecordingScheduleTemplate.is_builtin.is_(False),
        )
    )
    tmpl = result.scalar_one_or_none()
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")

    tmpl.deleted_at = datetime.now(UTC)
    await session.commit()
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.DELETE,
        resource_type=ResourceType.CAMERA,
        resource_id=template_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"config": "recording_template"},
    )


# =============================================================================
# Camera Access Control (Per-Camera RBAC)
# =============================================================================

access_router = APIRouter(prefix="/access", tags=["Camera Access Control"])


def get_access_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> "CameraAccessService":
    from app.modules.cameras.service import CameraAccessService

    return CameraAccessService(db=session)


@access_router.get("/grants", response_model=CameraAccessGrantListResponse)
async def list_access_grants(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.access"))],
    service: Annotated["CameraAccessService", Depends(get_access_service)],
    camera_id: UUID | None = None,
    user_id: UUID | None = None,
) -> Any:
    """List camera access grants, optionally filtered by camera or user."""
    grants = await service.list_grants(
        organization_id=org_scope_or_platform(current_user),  # type: ignore[arg-type]
        camera_id=camera_id,
        user_id=user_id,
    )
    return {"items": grants, "total": len(grants)}


@access_router.post(
    "/grants", status_code=status.HTTP_201_CREATED, response_model=CameraAccessGrantResponse
)
async def create_access_grant(
    body: CameraAccessGrantCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.access"))],
    service: Annotated["CameraAccessService", Depends(get_access_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Grant a user per-camera or per-group access."""
    # Validate camera/group belongs to the org AND a site the grantor may access —
    # a site-limited caller must not grant another user access to a sibling-site
    # camera they themselves cannot reach (site_scope_filter no-ops for super/org).
    if body.camera_id:
        from app.modules.cameras.models import Camera

        result = await session.execute(
            select(Camera).where(
                Camera.id == body.camera_id,
                Camera.organization_id == current_user.organization_id,
                Camera.deleted_at.is_(None),
                site_scope_filter(current_user, Camera.site_id),
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Camera not found")

    if body.group_id:
        from app.modules.cameras.models import CameraGroup

        result = await session.execute(
            select(CameraGroup).where(
                CameraGroup.id == body.group_id,
                CameraGroup.organization_id == current_user.organization_id,
                CameraGroup.deleted_at.is_(None),
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Group not found")

    # Validate user belongs to the same org
    from app.models.core import User

    result = await session.execute(
        select(User).where(
            User.id == body.user_id,
            User.organization_id == current_user.organization_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="User not found in organization")

    from sqlalchemy.exc import IntegrityError

    try:
        grant = await service.create_grant(
            organization_id=org_scope_or_platform(current_user),  # type: ignore[arg-type]
            user_id=body.user_id,
            camera_id=body.camera_id,
            group_id=body.group_id,
            access_level=body.access_level,
            can_live=body.can_live,
            can_playback=body.can_playback,
            can_ptz=body.can_ptz,
            can_export=body.can_export,
            can_configure=body.can_configure,
            expires_at=body.expires_at,
            created_by=current_user.id,
        )
    except IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Access grant already exists for this user and camera/group",
        )

    # Audit log
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.CREATE,
        resource_type=ResourceType.CAMERA,
        resource_id=body.camera_id or body.group_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={
            "grant_type": "camera_access",
            "target_user": str(body.user_id),
            "access_level": body.access_level,
        },
    )

    return {
        "id": grant.id,
        "user_id": grant.user_id,
        "camera_id": grant.camera_id,
        "group_id": grant.group_id,
        "access_level": grant.access_level,
        "can_live": grant.can_live,
        "can_playback": grant.can_playback,
        "can_ptz": grant.can_ptz,
        "can_export": grant.can_export,
        "can_configure": grant.can_configure,
        "expires_at": grant.expires_at.isoformat() if grant.expires_at else None,
        "created_at": grant.created_at.isoformat() if grant.created_at else None,
    }


@access_router.patch("/grants/{grant_id}", response_model=CameraAccessGrantResponse)
async def update_access_grant(
    grant_id: UUID,
    body: CameraAccessGrantUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.access"))],
    service: Annotated["CameraAccessService", Depends(get_access_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update an existing camera access grant."""
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    grant = await service.update_grant(
        grant_id=grant_id,
        organization_id=org_scope_or_platform(current_user),  # type: ignore[arg-type]
        **updates,
    )
    if not grant:
        raise HTTPException(status_code=404, detail="Grant not found")

    # Audit log
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.UPDATE,
        resource_type=ResourceType.CAMERA,
        resource_id=grant_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"grant_type": "camera_access", "updated_fields": list(updates.keys())},
    )

    return {
        "id": grant.id,
        "user_id": grant.user_id,
        "camera_id": grant.camera_id,
        "group_id": grant.group_id,
        "access_level": grant.access_level,
        "can_live": grant.can_live,
        "can_playback": grant.can_playback,
        "can_ptz": grant.can_ptz,
        "can_export": grant.can_export,
        "can_configure": grant.can_configure,
        "expires_at": grant.expires_at.isoformat() if grant.expires_at else None,
        "created_at": grant.created_at.isoformat() if grant.created_at else None,
    }


@access_router.delete("/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_access_grant(
    grant_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.access"))],
    service: Annotated["CameraAccessService", Depends(get_access_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Revoke a camera access grant."""
    deleted = await service.delete_grant(
        grant_id=grant_id,
        organization_id=org_scope_or_platform(current_user),  # type: ignore[arg-type]
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Grant not found")

    # Audit log
    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.DELETE,
        resource_type=ResourceType.CAMERA,
        resource_id=grant_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"grant_type": "camera_access"},
    )


@access_router.get("/check/{camera_id}", response_model=CameraAccessCheckResponse)
async def check_camera_access(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated["CameraAccessService", Depends(get_access_service)],
) -> Any:
    """Check the current user's effective permissions on a specific camera."""
    result = await service.check_access(
        user_id=current_user.id,
        camera_id=camera_id,
        organization_id=org_scope_or_platform(current_user),  # type: ignore[arg-type]
        user_role=current_user.role.value
        if hasattr(current_user.role, "value")
        else str(current_user.role),
    )
    return result


@access_router.get("/check/{camera_id}/user/{user_id}", response_model=CameraAccessCheckResponse)
async def check_user_camera_access(
    camera_id: UUID,
    user_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.access"))],
    service: Annotated["CameraAccessService", Depends(get_access_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Check another user's effective permissions on a specific camera (admin only)."""
    from app.models.core import User

    result = await session.execute(
        select(User).where(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    access = await service.check_access(
        user_id=user_id,
        camera_id=camera_id,
        organization_id=org_scope_or_platform(current_user),  # type: ignore[arg-type]
        user_role=user.role.value if hasattr(user.role, "value") else str(user.role),
    )
    return access


# =============================================================================
# HLS Streaming Endpoints
# =============================================================================

hls_router = APIRouter(prefix="/streams/hls", tags=["HLS Streaming"])


@router.post("/{camera_id}/stream/hls/start", response_model=HLSSessionStartResponse)
async def start_hls_stream(
    camera_id: UUID,
    body: HLSSessionStartRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Start an HLS streaming session (FFmpeg RTSP->HLS transcoding)."""
    await _enforce_camera_access(session, current_user, camera_id, "live")
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")

    from app.modules.cameras.service import HLSStreamService

    hls_service = HLSStreamService()

    # Build an AUTHENTICATED RTSP URL. The stored rtsp_main_stream carries the
    # correct NVR host + channel but NO credentials, so feeding it straight to
    # ffmpeg yields "401 Unauthorized" and an empty playlist (404). Resolve the
    # NVR/camera credentials and inject them; fall back to the channel formula
    # only when no stream URL was stored.
    from urllib.parse import quote, urlsplit, urlunsplit

    host, _port, username, password = await _resolve_credentials(camera, session)
    base = camera.rtsp_main_stream or (
        f"rtsp://{host}:554/Streaming/Channels/{(camera.channel_id or 1) * 100 + 1}"
    )
    parts = urlsplit(base)
    if "@" not in parts.netloc and username:
        creds = f"{quote(username, safe='')}:{quote(password or '', safe='')}"
        base = urlunsplit(
            (parts.scheme, f"{creds}@{parts.netloc}", parts.path, parts.query, parts.fragment)
        )
    rtsp_url = base

    result = await hls_service.start_session(
        camera_id=camera_id,
        quality=body.quality,
        rtsp_url=rtsp_url,
        organization_id=org_scope_or_platform(current_user),
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    session_id = result["session_id"]
    return HLSSessionStartResponse(
        session_id=session_id,
        playlist_url=result["playlist_url"],
        heartbeat_url=f"/api/v1/cameras/streams/hls/{session_id}/heartbeat",
        codec=result.get("codec", "unknown"),
        quality=result.get("quality", "medium"),
    )


# Per-camera cache of the recorded stream's PROBE (codec + dimensions +
# decodability), keyed by camera_id with a TTL. These are stable properties of
# the camera/NVR's recording config, so we probe once and reuse — avoiding the
# ~1s ffprobe on every play while letting playback ADAPT to whatever codec each
# stream actually carries (H.264 / H.265 / etc., mixed across channels, NVRs and
# vendors) instead of assuming one. A "playable=False" verdict (no decodable
# video / 0×0 — the device emits no parameter sets) drives an honest fast-fail.
_RECORDED_PROBE_CACHE: dict[UUID, tuple[dict[str, Any] | None, float]] = {}
_RECORDED_PROBE_TTL = 1800.0  # seconds


def _normalize_codec(raw: str | None) -> str | None:
    """Map an ffprobe codec_name to our canonical {h264, h265} (or pass through)."""
    c = (raw or "").lower()
    if c in ("h264", "avc", "avc1"):
        return "h264"
    if c in ("hevc", "h265"):
        return "h265"
    return c or None


async def _probe_recorded_stream(rtsp_url: str) -> dict[str, Any] | None:
    """Quick bounded ffprobe of a recorded RTSP track.

    Returns ``{"playable", "codec", "width", "height"}`` — codec auto-detected so
    the caller can choose copy-vs-transcode per stream regardless of vendor/NVR —
    or ``None`` when inconclusive (ffprobe timed out / errored), in which case the
    caller should NOT cache and should let the normal path proceed.
    ``playable`` is False when there's no decodable video (no stream, or 0×0).
    """
    args = [
        "ffprobe",
        "-v",
        "quiet",
        "-print_format",
        "json",
        "-show_streams",
        "-rtsp_transport",
        "tcp",
        "-probesize",
        "2000000",
        "-analyzeduration",
        "3000000",
        rtsp_url,
    ]
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):
            await proc.communicate()
        return None
    try:
        streams = json.loads(out or b"{}").get("streams", [])
        video = next((s for s in streams if s.get("codec_type") == "video"), None)
        if video is None:
            return {"playable": False, "codec": None, "width": 0, "height": 0}
        width = int(video.get("width") or 0)
        height = int(video.get("height") or 0)
        return {
            "playable": bool(width and height),
            "codec": _normalize_codec(video.get("codec_name")),
            "width": width,
            "height": height,
        }
    except Exception:  # pragma: no cover - defensive
        return None


@router.post("/{camera_id}/playback/hls/start", response_model=HLSSessionStartResponse)
async def start_playback_hls_stream(
    camera_id: UUID,
    body: PlaybackHLSStartRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Start an HLS session that plays RECORDED footage forward from an instant.

    Unlike the live HLS path (which can't decode HEVC on these NVRs), recorded
    Hikvision tracks carry in-band parameter sets and DO decode. Default
    ``quality=low`` transcodes to H.264 ~360p (sustains real-time on a 4K-HEVC
    source AND plays in every browser); ``quality=source`` copies the original
    HEVC (real-time, HEVC-capable clients only). Devices without a recorded-track
    builder (non-Hikvision, or the classic NVR whose recorded HEVC is undecodable)
    fall back to the per-frame snapshot playback path.
    """
    await _enforce_camera_access(session, current_user, camera_id, "playback")
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")

    host, port, username, password = await _resolve_credentials(camera, session)
    vendor = (getattr(camera, "vendor", "") or "").lower() or "hikvision"

    from app.modules.cameras.service import HLSStreamService, StreamService

    adapter = StreamService._create_camera_adapter(
        host=host, port=port, username=username, password=password, vendor=vendor
    )
    build = getattr(adapter, "get_playback_rtsp_url", None)
    if not callable(build):
        raise HTTPException(
            status_code=501,
            detail="Recorded HLS playback is not supported for this device",
        )
    try:
        await adapter.connect()
        rtsp_url = await build(
            channel=camera.channel_id or 1,
            start_time=body.start_time.isoformat(),
            duration_s=body.duration_s,
        )
    except Exception as exc:
        logger.warning("Playback HLS URL build failed for camera %s: %s", camera_id, exc)
        raise HTTPException(status_code=502, detail="Failed to open recorded stream")
    finally:
        with contextlib.suppress(Exception):
            await adapter.disconnect()

    # Probe the recorded stream (cached per-camera) to (a) fail fast + honestly when
    # it isn't decodable — instead of spawning an ffmpeg that produces nothing and
    # leaving the player to spin 30s then silently fall back — and (b) AUTO-DETECT
    # the codec so playback adapts per stream (copy H.264, transcode HEVC) rather
    # than assuming one codec across all cameras/NVRs/vendors.
    cached = _RECORDED_PROBE_CACHE.get(camera_id)
    probe: dict[str, Any] | None
    if cached is not None and (time.monotonic() - cached[1]) < _RECORDED_PROBE_TTL:
        probe = cached[0]
    else:
        probe = await _probe_recorded_stream(rtsp_url)
        if probe is not None:  # only cache definitive probes
            _RECORDED_PROBE_CACHE[camera_id] = (probe, time.monotonic())
    if probe is not None and probe.get("playable") is False:
        raise HTTPException(
            status_code=422,
            detail=(
                "This NVR can't serve back a playable recording for this camera — "
                "its recorded video stream isn't decodable (often a camera recording "
                "in a codec the NVR can't re-stream). Live view is unaffected."
            ),
        )

    # Detected source codec drives copy-vs-transcode in _build_ffmpeg_args. Fall
    # back to h265 (transcode) when the probe was inconclusive — the safe default
    # for browser compatibility.
    detected_codec = (probe or {}).get("codec") or "h265"

    hls_service = HLSStreamService()
    start_key = body.start_time.strftime("%Y%m%dT%H%M%S")
    result = await hls_service.start_session(
        camera_id=camera_id,
        quality=body.quality,
        rtsp_url=rtsp_url,
        source_codec=detected_codec,
        organization_id=org_scope_or_platform(current_user),
        session_key=f"{camera_id}:{body.quality}:rec:{start_key}",
        is_recorded=True,
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    session_id = result["session_id"]
    return HLSSessionStartResponse(
        session_id=session_id,
        playlist_url=result["playlist_url"],
        heartbeat_url=f"/api/v1/cameras/streams/hls/{session_id}/heartbeat",
        codec=result.get("codec", "h265"),
        quality=result.get("quality", body.quality),
    )


@hls_router.post("/{session_id}/heartbeat", response_model=HLSHeartbeatResponse)
async def hls_heartbeat(
    session_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
) -> Any:
    """Keep HLS session alive. Call every 15s."""
    from app.modules.cameras.service import HLSStreamService

    hls_service = HLSStreamService()
    info = hls_service._sessions.get(session_id)
    if not info:
        raise HTTPException(status_code=404, detail="Session not found")
    # Verify org ownership before heartbeating
    if str(info.get("organization_id", "")) != str(current_user.organization_id):
        raise HTTPException(status_code=404, detail="Session not found")
    alive = await hls_service.heartbeat(session_id)
    if not alive:
        raise HTTPException(status_code=404, detail="Session not found")
    return HLSHeartbeatResponse(alive=True, viewers=info.get("viewers", 1))


@hls_router.get("/{session_id}/stream.m3u8")
async def get_hls_playlist(
    session_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Serve HLS playlist (.m3u8)."""
    from app.modules.cameras.service import HLSStreamService

    hls_service = HLSStreamService()
    # Verify org ownership
    info = hls_service._sessions.get(session_id, {})
    if str(info.get("organization_id", "")) != str(current_user.organization_id):
        raise HTTPException(status_code=404, detail="Playlist not found")
    # Re-evaluate the per-camera grant on every playlist fetch so a revoked grant
    # stops serving an already-started session within one fetch interval.
    cam_id = info.get("camera_id")
    if cam_id:
        await _enforce_camera_access(
            session,
            current_user,
            UUID(cam_id) if isinstance(cam_id, str) else cam_id,
            "playback" if info.get("is_recorded") else "live",
        )
    path = hls_service.get_playlist_path(session_id)
    if not path:
        # get_playlist_path already returns None unless the .m3u8 exists on disk;
        # ffmpeg may not have written the first segment yet, or the session ended.
        raise HTTPException(status_code=404, detail="Playlist not ready")
    # Serve via FileResponse (no aiofiles dependency — it isn't installed, which
    # previously made this endpoint 500 on every HLS playlist fetch). The .m3u8
    # is tiny and ffmpeg rewrites it in place; no-cache so the player re-reads it.
    from fastapi.responses import FileResponse

    return FileResponse(
        path,
        media_type="application/vnd.apple.mpegurl",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@hls_router.get("/{session_id}/{segment}")
async def get_hls_segment(
    session_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    segment: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Serve HLS segment (.ts)."""
    import re as _re

    if not _re.fullmatch(r"\d{5}\.ts", segment):
        raise HTTPException(status_code=400, detail="Invalid segment name")
    from app.modules.cameras.service import HLSStreamService

    hls_service = HLSStreamService()
    # Verify org ownership
    info = hls_service._sessions.get(session_id, {})
    if str(info.get("organization_id", "")) != str(current_user.organization_id):
        raise HTTPException(status_code=404, detail="Segment not found")
    cam_id = info.get("camera_id")
    if cam_id:
        await _enforce_camera_access(
            session,
            current_user,
            UUID(cam_id) if isinstance(cam_id, str) else cam_id,
            "playback" if info.get("is_recorded") else "live",
        )
    path = hls_service.get_segment_path(session_id, segment)
    if not path:
        raise HTTPException(status_code=404, detail="Segment not found")
    from fastapi.responses import FileResponse

    return FileResponse(
        path,
        media_type="video/mp2t",
        headers={"Cache-Control": "max-age=3600"},
    )


@hls_router.delete("/{session_id}")
async def stop_hls_stream(
    session_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
) -> Any:
    """Stop an HLS streaming session."""
    from app.modules.cameras.service import HLSStreamService

    hls_service = HLSStreamService()
    # Verify org ownership
    info = hls_service._sessions.get(session_id, {})
    if str(info.get("organization_id", "")) != str(current_user.organization_id):
        raise HTTPException(status_code=404, detail="Session not found")
    await hls_service.stop_session(session_id)
    return {"status": "stopped"}


# =============================================================================
# Codec Detection
# =============================================================================


@router.get("/{camera_id}/codec-info", response_model=CodecDetectionResponse)
async def get_codec_info(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Detect the video codec of a camera's RTSP stream."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    from app.modules.cameras.service import TranscodeService

    ts = TranscodeService()
    # Inject credentials — ffprobe against a credential-less rtsp_main_stream
    # gets 401 and reports codec "unknown".
    from urllib.parse import quote, urlsplit, urlunsplit

    host, _port, username, password = await _resolve_credentials(camera, session)
    rtsp_url = camera.rtsp_main_stream or (
        f"rtsp://{host}:554/Streaming/Channels/{(camera.channel_id or 1) * 100 + 1}"
    )
    _parts = urlsplit(rtsp_url)
    if "@" not in _parts.netloc and username:
        _creds = f"{quote(username, safe='')}:{quote(password or '', safe='')}"
        rtsp_url = urlunsplit(
            (_parts.scheme, f"{_creds}@{_parts.netloc}", _parts.path, _parts.query, _parts.fragment)
        )
    try:
        info = await ts.detect_codec(rtsp_url)
        return CodecDetectionResponse(**info)
    except Exception:
        logger.exception("Codec detection failed for camera %s", camera_id)
        return CodecDetectionResponse(codec="unknown", needs_transcode=False)


# =============================================================================
# Cross-site Recording Search
# =============================================================================


@router.post("/recordings/search-cross-site", response_model=CrossSiteRecordingSearchResponse)
async def search_recordings_cross_site(
    body: CrossSiteRecordingSearchRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
) -> Any:
    """Search recordings across all sites and NVRs within the organization."""
    from app.modules.cameras.models import Camera, Recording

    q = (
        select(Recording)
        .join(Camera, Recording.camera_id == Camera.id)
        .where(
            Camera.organization_id == current_user.organization_id,
            Recording.organization_id == current_user.organization_id,
            Camera.deleted_at.is_(None),
            # R5 site-grant: "across all sites" must still respect the caller's
            # per-user grant. Fail-closed empty IN for a site-limited user with
            # zero grants; no-op (true()) for super/org-admin.
            site_scope_filter(current_user, Camera.site_id),
        )
    )
    if body.site_ids:
        q = q.where(Camera.site_id.in_(body.site_ids))
    if body.camera_ids:
        q = q.where(Recording.camera_id.in_(body.camera_ids))
    if body.start_time:
        q = q.where(Recording.end_time >= body.start_time)
    if body.end_time:
        q = q.where(Recording.start_time <= body.end_time)
    if body.recording_type:
        q = q.where(Recording.recording_type == body.recording_type)

    # Count total
    count_q = select(func.count()).select_from(q.subquery())
    total = (await session.execute(count_q)).scalar() or 0

    # Paginate
    q = q.order_by(Recording.start_time.desc()).offset((page - 1) * per_page).limit(per_page)
    result = await session.execute(q)
    recordings = result.scalars().all()

    # Build response with camera info
    camera_ids_found = {r.camera_id for r in recordings}
    cam_q = select(Camera).where(
        Camera.id.in_(camera_ids_found),
        Camera.organization_id == current_user.organization_id,
        Camera.deleted_at.is_(None),
    )
    cam_result = await session.execute(cam_q)
    cam_map = {c.id: c for c in cam_result.scalars().all()}

    items = []
    for r in recordings:
        cam = cam_map.get(r.camera_id)
        duration = None
        if r.start_time and r.end_time:
            duration = int((r.end_time - r.start_time).total_seconds())
        items.append(
            CrossSiteRecordingResult(
                camera_id=r.camera_id,
                camera_name=cam.name if cam else "Unknown",
                site_id=cam.site_id if cam else None,
                site_name=None,  # Could join Site table if needed
                nvr_id=cam.nvr_id if cam else None,
                start_time=r.start_time,
                end_time=r.end_time,
                duration_seconds=duration,
                recording_type=r.recording_type,
                file_size_bytes=r.file_size_bytes,
                source="db",
            )
        )
    return CrossSiteRecordingSearchResponse(
        results=items, total=total, page=page, per_page=per_page
    )


# =============================================================================
# Scheduled Reports
# =============================================================================

report_router = APIRouter(prefix="/reports", tags=["Camera Reports"])


@report_router.get("/", response_model=CameraReportListResponse)
async def list_reports(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    report_type: Literal["daily_summary"] | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
) -> Any:
    """List generated camera reports for the organization.

    Only ``daily_summary`` is produced today (by the cameras.generate_daily_report
    beat task); its ``data`` payload already carries camera counts, 24h event
    totals and uptime %, so separate uptime/event report types would be
    redundant. The filter Literal is kept narrow to match what actually exists.
    """
    from app.modules.cameras.models import CameraReport

    # CameraReport has no site_id and its ``data`` aggregates ALL org cameras /
    # events / health across every site (tasks/cameras.py:_generate_daily_report).
    # A site-limited operator would therefore see org-wide figures spanning
    # sibling sites they cannot otherwise reach, so org-wide reports are
    # admin-only. Site-limited users get an empty list (not a 403/404 oracle —
    # the endpoint exists, there are simply no reports scoped to them).
    if current_user.is_site_limited:
        return CameraReportListResponse(items=[], total=0)

    q = select(CameraReport).where(
        CameraReport.organization_id == current_user.organization_id,
    )
    if report_type:
        q = q.where(CameraReport.report_type == report_type)
    q = q.order_by(CameraReport.generated_at.desc()).limit(limit)
    result = await session.execute(q)
    reports = result.scalars().all()
    return CameraReportListResponse(items=reports, total=len(reports))  # type: ignore[arg-type]


@report_router.get("/{report_id}", response_model=CameraReportResponse)
async def get_report(
    report_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a specific camera report."""
    from app.modules.cameras.models import CameraReport

    # See list_reports: org-wide aggregate reports (no site_id, span all sites)
    # are admin-only. 404 for site-limited users — same shape as a missing row,
    # so there is no existence oracle.
    if current_user.is_site_limited:
        raise HTTPException(status_code=404, detail="Report not found")

    result = await session.execute(
        select(CameraReport).where(
            CameraReport.id == report_id,
            CameraReport.organization_id == current_user.organization_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


# =============================================================================
# Two-way Audio (Intercom)
# =============================================================================


@router.post("/{camera_id}/audio/start", response_model=AudioSessionResponse)
async def start_audio_session(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Start a two-way audio session with a camera."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    if not camera.has_two_way_audio:
        raise HTTPException(status_code=400, detail="Camera does not support two-way audio")

    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        result = await adapter.open_two_way_audio(channel=channel, force=_API_WRITE_FORCE)
        if not result.get("success"):
            raise HTTPException(status_code=502, detail="Failed to start audio session")
        audit = AuditService(db=session)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"action": "audio_start"},
        )
        return AudioSessionResponse(status="started", camera_id=camera_id)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to start audio for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to start audio session")
    finally:
        await adapter.disconnect()


@router.post("/{camera_id}/audio/stop", response_model=AudioSessionStopResponse)
async def stop_audio_session(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Stop a two-way audio session."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        await adapter.close_two_way_audio(channel=channel, force=_API_WRITE_FORCE)
        audit = AuditService(db=session)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"action": "audio_stop"},
        )
        return AudioSessionStopResponse(status="stopped")
    except Exception:
        logger.exception("Failed to stop audio for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to stop audio session")
    finally:
        await adapter.disconnect()


# =============================================================================
# Thermal Camera
# =============================================================================


@router.get("/{camera_id}/thermal", response_model=ThermalCapabilitiesResponse)
async def get_thermal_data(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get thermal camera data and capabilities."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_thermal_capabilities(channel=channel)
        return ThermalCapabilitiesResponse(**data)
    except Exception:
        logger.exception("Failed to get thermal data for camera %s", camera_id)
        return ThermalCapabilitiesResponse(is_thermal=False, supported=False)
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/thermal/threshold", response_model=ThermalThresholdResponse)
async def set_thermal_threshold(
    camera_id: UUID,
    body: ThermalThresholdRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Set temperature threshold alerts for a thermal camera."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    # Store config in camera settings
    if not camera.settings:
        camera.settings = {}
    camera.settings["thermal_threshold"] = {
        "min_temp": body.min_temp,
        "max_temp": body.max_temp,
        "alert_enabled": body.alert_enabled,
    }
    from sqlalchemy.orm.attributes import flag_modified

    flag_modified(camera, "settings")
    await session.commit()

    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.UPDATE,
        resource_type=ResourceType.CAMERA,
        resource_id=camera_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"action": "thermal_threshold", "min": body.min_temp, "max": body.max_temp},
    )
    return ThermalThresholdResponse(
        min_temp=body.min_temp, max_temp=body.max_temp, alert_enabled=body.alert_enabled
    )


# =============================================================================
# LPR (License Plate Recognition)
# =============================================================================

lpr_router = APIRouter(prefix="/lpr", tags=["License Plate Recognition"])


@router.get("/{camera_id}/lpr/config", response_model=LPRConfigResponse)
async def get_lpr_config(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
) -> Any:
    """Get LPR configuration for a camera."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    config = (camera.settings or {}).get("lpr_config", {})
    return LPRConfigResponse(
        enabled=config.get("enabled", False),
        provider=config.get("provider", ""),
        api_url=config.get("api_url", ""),
        has_api_key=bool(config.get("api_key_encrypted")),
        regions=config.get("regions", []),
        confidence_threshold=config.get("confidence_threshold", 0.7),
    )


@router.put("/{camera_id}/lpr/config", response_model=LPRConfigResponse)
async def set_lpr_config(
    camera_id: UUID,
    body: LPRConfigRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Configure LPR for a camera."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    # enforce site-grant for site-limited callers.
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    if not camera.settings:
        camera.settings = {}
    camera.settings["lpr_config"] = {
        "enabled": body.enabled,
        "provider": body.provider,
        "api_url": body.api_url,
        "api_key_encrypted": encrypt_credential(body.api_key)
        if body.api_key
        else camera.settings.get("lpr_config", {}).get("api_key_encrypted"),
        "regions": body.regions,
        "confidence_threshold": body.confidence_threshold,
    }
    from sqlalchemy.orm.attributes import flag_modified

    flag_modified(camera, "settings")
    await session.commit()

    audit = AuditService(db=session)
    await audit.log(
        action=AuditAction.UPDATE,
        resource_type=ResourceType.CAMERA,
        resource_id=camera_id,
        organization_id=org_scope_or_platform(current_user),
        actor_id=current_user.id,
        extra_metadata={"action": "lpr_config_update"},
    )
    return LPRConfigResponse(
        enabled=body.enabled,
        provider=body.provider,
        api_url=body.api_url,
        has_api_key=bool(
            body.api_key or camera.settings.get("lpr_config", {}).get("api_key_encrypted")
        ),
        regions=body.regions,
        confidence_threshold=body.confidence_threshold,
    )


@router.post("/{camera_id}/lpr/recognize", response_model=LPRReadResult)
async def recognize_plate(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Run a one-shot license plate recognition on a camera snapshot."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    from app.modules.cameras.service import LPRService

    lpr_svc = LPRService(session)
    try:
        result = await lpr_svc.recognize_plate(camera_id, current_user.organization_id)  # type: ignore[arg-type]
        audit = AuditService(db=session)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"action": "lpr_recognize"},
        )
        from datetime import datetime as dt

        return LPRReadResult(
            plate_text=result.get("plate", ""),
            confidence=result.get("confidence", 0.0),
            vehicle_type=result.get("vehicle_type"),
            camera_id=camera_id,
            camera_name=camera.name,
            timestamp=dt.now(UTC),
        )
    except CameraError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("LPR recognition failed for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="License plate recognition failed")


@lpr_router.get("/reads", response_model=LPRSearchResponse)
async def search_plate_reads(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    plate: str | None = Query(None, min_length=1, max_length=20),
    camera_id: UUID | None = Query(None),
    start_time: datetime | None = Query(None),
    end_time: datetime | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> Any:
    """Search license plate reads across all cameras."""
    from app.modules.cameras.models import Camera, CameraEvent

    q = (
        select(CameraEvent, Camera.name.label("camera_name"))
        .join(Camera, CameraEvent.camera_id == Camera.id)
        .where(
            Camera.organization_id == current_user.organization_id,
            Camera.deleted_at.is_(None),
            CameraEvent.event_type == "license_plate",
            # R5 site-grant: a site-limited caller may only see plate reads from
            # cameras in granted sites. Fail-closed empty IN for zero grants;
            # no-op for super/org-admin.
            site_scope_filter(current_user, Camera.site_id),
        )
    )
    if plate:
        escaped_plate = plate.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q = q.where(
            CameraEvent.metadata_json["plate"].astext.ilike(f"%{escaped_plate}%", escape="\\")
        )
    if camera_id:
        q = q.where(CameraEvent.camera_id == camera_id)
    if start_time:
        q = q.where(CameraEvent.timestamp >= start_time)
    if end_time:
        q = q.where(CameraEvent.timestamp <= end_time)
    q = q.order_by(CameraEvent.timestamp.desc()).limit(limit)
    result = await session.execute(q)
    rows = result.all()
    items = []
    for event, cam_name in rows:
        meta = event.metadata_json or {}
        items.append(
            LPRReadResult(
                plate_text=meta.get("plate", ""),
                confidence=meta.get("confidence", 0.0),
                vehicle_type=meta.get("vehicle_type"),
                region=meta.get("region"),
                camera_id=event.camera_id,
                camera_name=cam_name,
                timestamp=event.timestamp,
            )
        )
    return LPRSearchResponse(results=items, total=len(items))


# =============================================================================
# AI Scene Labeling
# =============================================================================


@router.post("/{camera_id}/scene/analyze", response_model=SceneLabelResponse)
async def analyze_scene(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.manage"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Run AI scene analysis on a camera snapshot to generate labels."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")

    from app.modules.cameras.service import SceneLabelingService

    svc = SceneLabelingService(session)
    try:
        result = await svc.analyze_scene(camera_id, current_user.organization_id)  # type: ignore[arg-type]
        audit = AuditService(db=session)
        await audit.log(
            action=AuditAction.UPDATE,
            resource_type=ResourceType.CAMERA,
            resource_id=camera_id,
            organization_id=org_scope_or_platform(current_user),
            actor_id=current_user.id,
            extra_metadata={"action": "scene_analyze"},
        )
        return SceneLabelResponse(
            camera_id=camera_id,
            labels=result.get("labels", []),
            analyzed_at=result.get("analyzed_at"),
        )
    except Exception:
        logger.exception("Scene analysis failed for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Scene analysis failed")


@router.get("/{camera_id}/scene/labels", response_model=SceneLabelResponse)
async def get_scene_labels(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
) -> Any:
    """Get stored scene labels for a camera."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    scene_data = (camera.settings or {}).get("scene_labels", {})
    labels = scene_data.get("labels", [])
    analyzed_at = scene_data.get("analyzed_at")
    return SceneLabelResponse(
        camera_id=camera_id,
        labels=labels,
        analyzed_at=datetime.fromisoformat(analyzed_at) if analyzed_at else None,
    )


# =============================================================================
# PTZ Auto-tracking
# =============================================================================


@router.get("/{camera_id}/ptz/auto-tracking", response_model=PTZAutoTrackingResponse)
async def get_auto_tracking(
    camera_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get PTZ auto-tracking configuration."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    if not camera.has_ptz:
        return PTZAutoTrackingResponse(supported=False)
    adapter, channel = await _get_adapter_for_camera(camera, session)
    try:
        data = await adapter.get_auto_tracking(channel=channel)
        return PTZAutoTrackingResponse(**data)
    except Exception:
        logger.exception("Failed to get auto-tracking for camera %s", camera_id)
        return PTZAutoTrackingResponse(supported=False)
    finally:
        await adapter.disconnect()


@router.put("/{camera_id}/ptz/auto-tracking", response_model=PTZAutoTrackingResponse)
async def set_auto_tracking(
    camera_id: UUID,
    body: PTZAutoTrackingRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.ptz"))],
    service: Annotated[CameraService, Depends(get_camera_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Configure PTZ auto-tracking."""
    try:
        camera = await service.get_camera(
            camera_id, organization_id=org_scope_or_platform(current_user)
        )
    except CameraNotFoundError:
        raise HTTPException(status_code=404, detail="Camera not found")
    assert_can_access_site(current_user, camera.site_id, detail="Camera not found")
    if not camera.has_ptz:
        raise HTTPException(status_code=400, detail="Camera does not support PTZ")
    adapter, channel = await _get_adapter_for_camera(camera, session)

    async def _apply() -> dict[str, Any]:
        return await adapter.set_auto_tracking(
            channel=channel,
            enabled=body.enabled,
            duration=body.track_duration_sec,
            sensitivity=body.sensitivity,
            force=_API_WRITE_FORCE,
        )

    try:
        # Audit-only envelope (the setter takes kwargs, not a config dict, so a
        # shape-faithful rollback isn't available — before/after is still logged).
        result = await staged_camera_write(
            db=session,
            actor_id=current_user.id,
            organization_id=org_scope_or_platform(current_user),
            camera=camera,
            feature="auto_tracking",
            capture=lambda: adapter.get_auto_tracking(channel=channel),
            apply=_apply,
        )
        return PTZAutoTrackingResponse(**result)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to set auto-tracking for camera %s", camera_id)
        raise HTTPException(status_code=502, detail="Failed to update auto-tracking")
    finally:
        await adapter.disconnect()


# =============================================================================
# Time Sync Drift Detection
# =============================================================================


@nvr_router.get("/health/time-drift", response_model=TimeDriftSummaryResponse)
async def get_time_drift_summary(
    current_user: Annotated[CurrentUser, Depends(require_permissions("cameras.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    threshold: int = Query(30, ge=1, le=3600),
) -> Any:
    """Check NVR time synchronization drift across all NVRs."""
    from dateutil.parser import parse as parse_dt  # type: ignore[import-untyped]

    from app.adapters.hikvision.adapter import HikvisionAdapter

    result = await session.execute(
        select(NVRModel)
        .where(
            NVRModel.organization_id == current_user.organization_id,
            NVRModel.deleted_at.is_(None),
            NVRModel.status == "online",
            # R5 site-grant: a site-limited caller must only probe NVRs in granted
            # sites (this endpoint actively connects to each NVR). Fail-closed
            # empty IN for zero grants; no-op for super/org-admin.
            site_scope_filter(current_user, NVRModel.site_id),
        )
        .limit(50)
    )
    nvrs = result.scalars().all()
    server_now = datetime.now(UTC)

    async def _check_nvr_drift(nvr: Any, threshold_seconds: int) -> TimeDriftEntry | None:
        """Check time drift for a single NVR with timeout."""
        # Skip NVRs that aren't Hikvision (only adapter that supports get_time_info)
        if nvr.device_type not in ("hikvision", None):  # None = legacy default
            return None
        if not nvr.username or not nvr.password_encrypted:
            return None
        password = decrypt_credential(nvr.password_encrypted)
        adapter = HikvisionAdapter(
            host=nvr.ip_address,
            username=nvr.username,
            password=password,
            port=nvr.port,
        )
        try:
            await asyncio.wait_for(adapter.connect(), timeout=10.0)
            time_info = await asyncio.wait_for(adapter.get_time_info(), timeout=10.0)
            device_time_str = time_info.get("device_time", "")
            if not device_time_str:
                return None
            device_time = parse_dt(device_time_str)
            if device_time.tzinfo is None:
                device_time = device_time.replace(tzinfo=UTC)
            drift = abs((device_time - server_now).total_seconds())
            severity: Literal["normal", "warning", "critical"] = "normal"
            if drift > threshold_seconds * 3:
                severity = "critical"
            elif drift > threshold_seconds:
                severity = "warning"
            if drift > threshold_seconds:
                return TimeDriftEntry(
                    nvr_id=nvr.id,
                    nvr_name=nvr.name,
                    drift_seconds=round(drift, 1),
                    device_time=device_time_str,
                    server_time=server_now.isoformat(),
                    severity=severity,
                )
        except Exception:
            logger.debug("Time drift check failed for NVR %s", nvr.id)
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()
        return None

    sem = asyncio.Semaphore(10)

    async def bounded_check(nvr: Any) -> Any:
        async with sem:
            return await _check_nvr_drift(nvr, threshold)

    results = await asyncio.gather(
        *[bounded_check(n) for n in nvrs],
        return_exceptions=True,
    )
    drifted = [r for r in results if isinstance(r, TimeDriftEntry)]

    return TimeDriftSummaryResponse(
        threshold_seconds=threshold,
        total_nvrs=len(nvrs),
        drifted_count=len(drifted),
        drifted=drifted,
    )
