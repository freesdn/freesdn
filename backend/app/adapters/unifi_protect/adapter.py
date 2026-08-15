# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — UniFi Protect camera adapter.

Implements the camera-adapter contract the cameras module's
``_create_camera_adapter(vendor=...)`` dispatcher relies on:

  * ``async def connect() -> bool``
  * ``async def disconnect() -> None``
  * ``async def discover_devices() -> list[DiscoveredDevice]``
  * ``async def get_snapshot(channel: int = 1) -> bytes | None``
  * ``def get_rtsp_url_internal(channel: int, ...) -> str``
  * ``def get_rtsp_url_safe(channel: int, ...) -> str``
  * ``async def get_storage_info() -> dict[str, Any]``

UniFi Protect runs as a separate application alongside UniFi Network
on UniFi OS devices (UDM Pro, Cloud Key, UOS Server LXC). On a host
where Protect is NOT installed, the ``/proxy/protect/api/bootstrap``
endpoint returns the UOS HTML shell instead of JSON — the adapter
detects this case and raises :class:`UniFiProtectNotInstalledError`
so operators get an actionable error message.

Authentication mirrors :class:`UniFiAdapter` (the network adapter
shipped in rounds 1-5):

  * UniFi OS auth flow: POST ``/api/auth/login`` to obtain a TOKEN
    cookie + ``x-csrf-token`` response header.
  * Subsequent calls reuse the cookie via ``httpx.AsyncClient``.

The deploy path for operators: install the Protect app on the same
UOS host that runs Network, point the adapter at the same host/port,
re-use the existing UniFi credentials. The Hikvision and ONVIF
adapters continue to handle their respective vendors unchanged —
this is a third branch, not a replacement.

NOTE: live verification of this adapter against real cameras requires
the Protect app to be installed on the UniFi OS host; a Network-only
host exposes no camera endpoints.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

import httpx

from app.adapters.base import (
    AdapterManifest,
    AdapterResult,
    BaseAdapter,
    Capability,
    DeviceTypeCapabilities,
    DiscoveredDevice,
)
from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
)

logger = logging.getLogger(__name__)


class UniFiProtectNotInstalledError(AdapterConnectionError):
    """Raised when ``/proxy/protect/api/bootstrap`` returns the UOS HTML
    shell instead of the Protect JSON bootstrap.

    Operators should install the Protect application on the target UOS
    host before pointing the adapter at it. The Network adapter on the
    same host continues to work — this error only blocks the cameras
    path.
    """


class UniFiProtectAdapter(BaseAdapter):
    """Camera adapter for UniFi Protect.

    The dispatcher in ``app.modules.cameras.service.StreamService
    ._create_camera_adapter`` selects this adapter when the camera's
    ``vendor`` field is ``"unifi"`` or ``"unifi_protect"``.
    """

    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="unifi_protect",
        name="UniFi Protect",
        vendor="Ubiquiti",
        version="1.0.0-beta",
        description=(
            "Ubiquiti UniFi Protect camera platform — coexists with "
            "the UniFi Network adapter on the same UOS host. Requires "
            "the Protect application to be installed on the target "
            "UniFi OS device (UDM Pro, Cloud Key, UOS Server LXC)."
        ),
        controller_type=None,
        supports_controller=True,
        supports_direct=False,
        supported_versions=["2.x", "3.x", "4.x"],
        device_types={
            "camera": DeviceTypeCapabilities(
                module="cameras",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.CAMERA_SNAPSHOT,
                    Capability.CAMERA_STREAM_RTSP,
                    Capability.CAMERA_MOTION_DETECTION,
                ],
                models=["UVC-*", "G3-*", "G4-*", "G5-*", "AI-*"],
            ),
            "camera_ptz": DeviceTypeCapabilities(
                module="cameras",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.CAMERA_SNAPSHOT,
                    Capability.CAMERA_STREAM_RTSP,
                    Capability.CAMERA_PTZ,
                    Capability.CAMERA_MOTION_DETECTION,
                ],
                models=["G3-PTZ*", "G4-PTZ*", "G5-PTZ*"],
            ),
            "nvr": DeviceTypeCapabilities(
                module="cameras",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.CONTROLLER_BACKUP,
                ],
                models=["UDM-*", "UCK-*", "UNVR-*"],
            ),
        },
    )

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: float = 15.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(host, username, password, **kwargs)
        self.port = port
        self.verify_ssl = verify_ssl
        self._timeout = timeout

        scheme = "https"
        self.base_url = f"{scheme}://{host}:{port}"
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            verify=verify_ssl,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=10,
                max_keepalive_connections=5,
            ),
        )
        self._csrf_token: str | None = None
        self._bootstrap: dict[str, Any] = {}

    # ── Lifecycle ────────────────────────────────────────────────────

    async def connect(self) -> bool:
        """Authenticate via UniFi OS and fetch the Protect bootstrap.

        Two-step probe:
          1. POST ``/api/auth/login`` — same flow as UniFi Network.
          2. GET ``/proxy/protect/api/bootstrap`` with
             ``Accept: application/json``. If the response is HTML, the
             Protect application isn't installed on this UOS host —
             raise :class:`UniFiProtectNotInstalledError` with a clear
             remediation message.
        """
        # Step 1: UOS auth (same path as UniFi Network adapter).
        try:
            resp = await self._client.post(
                "/api/auth/login",
                json={
                    "username": self.username,
                    "password": self.password,
                    "remember": True,
                },
            )
        except httpx.HTTPError as exc:
            raise AdapterConnectionError(
                f"UniFi Protect host unreachable: {exc}",
                adapter_id="unifi_protect",
            ) from exc

        if resp.status_code in (401, 403):
            raise AdapterAuthenticationError(
                f"UniFi credentials rejected by {self.base_url}",
                adapter_id="unifi_protect",
            )
        if resp.status_code != 200:
            raise AdapterConnectionError(
                f"UniFi OS login returned HTTP {resp.status_code}",
                adapter_id="unifi_protect",
            )
        self._csrf_token = resp.headers.get("x-csrf-token")

        # Step 2: Protect bootstrap. If Protect isn't installed, the
        # UOS gateway falls through to the React shell (Content-Type:
        # text/html). Detect + raise so the operator sees a clean
        # actionable error.
        boot = await self._client.get(
            "/proxy/protect/api/bootstrap",
            headers={"Accept": "application/json"},
        )
        ct = boot.headers.get("content-type", "")
        if "application/json" not in ct:
            # Protect app missing — UOS returned the SPA shell.
            raise UniFiProtectNotInstalledError(
                "UniFi Protect application is not installed on the "
                f"target UOS host ({self.base_url}). Install the "
                "Protect app from the UniFi OS console / community "
                "scripts and retry. The UniFi Network adapter on the "
                "same host is unaffected.",
                adapter_id="unifi_protect",
            )
        try:
            self._bootstrap = boot.json()
        except Exception as exc:
            raise AdapterConnectionError(
                f"UniFi Protect bootstrap returned non-JSON: {exc}",
                adapter_id="unifi_protect",
            ) from exc

        self._connected = True
        self.device_info = {
            "deviceID": self._bootstrap.get("nvr", {}).get("id", ""),
            "deviceName": self._bootstrap.get("nvr", {}).get("name", ""),
            "model": self._bootstrap.get("nvr", {}).get("type", ""),
            "firmware": self._bootstrap.get("nvr", {}).get("version", ""),
            "serial": self._bootstrap.get("nvr", {}).get("hardwareId", ""),
            "macAddress": self._bootstrap.get("nvr", {}).get("mac", ""),
        }
        return True

    async def disconnect(self) -> None:
        """Close the httpx client + log out cleanly.

        UniFi OS logout lives at ``/api/auth/logout`` — same path used
        by the UniFi Network adapter.
        """
        try:
            if self._connected:
                headers = {"X-CSRF-Token": self._csrf_token} if self._csrf_token else {}
                await self._client.post(
                    "/api/auth/logout",
                    headers=headers,
                )
        except Exception:
            logger.debug("Protect logout failed", exc_info=True)
        finally:
            try:
                await self._client.aclose()
            except Exception:
                logger.debug("Protect aclose failed", exc_info=True)
            self._connected = False

    # ── Discovery ────────────────────────────────────────────────────

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """Enumerate cameras + the NVR itself from the Protect bootstrap.

        UniFi Protect's bootstrap response includes ``cameras`` (list),
        ``nvr`` (the controller itself), and ``viewers`` / ``lights``
        (UniFi Protect's smart-doorbell / floodlight devices). We
        surface cameras + the NVR as ``DiscoveredDevice`` so the
        cameras module's discovery flow auto-imports both.
        """
        if not self._bootstrap:
            await self.connect()

        devices: list[DiscoveredDevice] = []
        nvr = self._bootstrap.get("nvr") or {}
        if nvr:
            devices.append(
                DiscoveredDevice(
                    mac_address=nvr.get("mac", "") or "",
                    ip_address=nvr.get("host", "") or self.host,
                    name=nvr.get("name", "UniFi NVR"),
                    vendor="Ubiquiti",
                    model=nvr.get("type", "UDM/Cloud Key NVR"),
                    firmware_version=nvr.get("version"),
                    device_type="nvr",
                    status="online" if nvr.get("isStation") else "online",
                    serial_number=nvr.get("hardwareId"),
                    capabilities=[Capability.STREAM_VIEW],
                    raw_data=nvr,
                )
            )

        for cam in self._bootstrap.get("cameras") or []:
            caps = [Capability.STREAM_VIEW]
            if cam.get("featureFlags", {}).get("hasMotionZones"):
                caps.append(Capability.MOTION_DETECTION)
            if cam.get("featureFlags", {}).get("hasPanTilt"):
                caps.append(Capability.PTZ)
            devices.append(
                DiscoveredDevice(
                    mac_address=cam.get("mac", "") or "",
                    ip_address=cam.get("host", None),
                    name=cam.get("name", "UniFi Camera"),
                    vendor="Ubiquiti",
                    model=cam.get("type", "UniFi Protect Camera"),
                    firmware_version=cam.get("firmwareVersion"),
                    device_type=(
                        "camera_ptz" if cam.get("featureFlags", {}).get("hasPanTilt") else "camera"
                    ),
                    status=("online" if cam.get("isConnected") else "offline"),
                    serial_number=cam.get("hardwareId") or cam.get("id"),
                    capabilities=caps,
                    raw_data=cam,
                )
            )
        return devices

    # ── Snapshot ─────────────────────────────────────────────────────

    async def get_snapshot(self, channel: int = 1) -> bytes | None:
        """Fetch a JPEG snapshot from a Protect camera.

        UniFi Protect identifies cameras by ID (Mongo ObjectID),
        not by channel index. The cameras module passes ``channel``
        as a positional argument for parity with Hikvision/ONVIF —
        we map it onto the camera id list returned by the bootstrap.
        Caller can also pass the camera id directly via ``device_id``
        if they have it (matches the Hikvision interface).
        """
        cams = self._bootstrap.get("cameras") or []
        if not cams:
            return None
        # ``channel`` is 1-based per the cameras module convention.
        idx = max(0, min(int(channel) - 1, len(cams) - 1))
        cam = cams[idx]
        cam_id = cam.get("id")
        if not cam_id:
            return None
        try:
            r = await self._client.get(
                f"/proxy/protect/api/cameras/{cam_id}/snapshot",
                headers={"Accept": "image/jpeg"},
            )
            if r.status_code != 200:
                return None
            return r.content
        except httpx.HTTPError:
            logger.warning(
                "Protect snapshot failed for camera %s",
                cam_id,
                exc_info=True,
            )
            return None

    # ── RTSP URL helpers ─────────────────────────────────────────────

    def _camera_for_channel(self, channel: int) -> dict[str, Any] | None:
        cams = self._bootstrap.get("cameras") or []
        if not cams:
            return None
        idx = max(0, min(int(channel) - 1, len(cams) - 1))
        return cams[idx]

    def get_rtsp_url_internal(
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
        encryption_key: str | None = None,  # noqa: ARG002
    ) -> str:
        """SERVER-SIDE ONLY — RTSP URL with embedded creds.

        UniFi Protect exposes RTSP via the camera's ``rtspAlias`` field
        in the bootstrap. The URL form is::

            rtsp://<host>:7447/<rtspAlias>

        ``stream`` ("main"|"sub") maps to channel quality levels via
        the ``channels`` field on the camera. We pick the first
        ``isRtspEnabled`` channel matching the requested quality.
        """
        cam = self._camera_for_channel(channel)
        if not cam:
            return ""
        rtsp_channels = [c for c in (cam.get("channels") or []) if c.get("isRtspEnabled")]
        if not rtsp_channels:
            return ""
        # Pick highest quality for ``main``, lowest for ``sub``.
        rtsp_channels.sort(key=lambda c: c.get("bitrate", 0))
        chosen = rtsp_channels[-1] if stream == "main" else rtsp_channels[0]
        alias = chosen.get("rtspAlias", "")
        if not alias:
            return ""
        # Protect RTSP doesn't embed credentials — the URL itself is
        # the secret. We return as-is.
        return f"rtsp://{self.host}:7447/{alias}"

    def get_rtsp_url_safe(
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
        encryption_key: str | None = None,
    ) -> str:
        """UI-safe RTSP URL.

        Protect's RTSP URL is intrinsically secret (the ``rtspAlias``
        is the auth token). For UI display we mask the alias the same
        way Hikvision masks ``rtsp://***:***@``.
        """
        cam = self._camera_for_channel(channel)
        if not cam:
            return ""
        # Show host + sentinel alias, NOT the real rtspAlias.
        return f"rtsp://{self.host}:7447/<rtspAlias>"

    # ── Storage info ─────────────────────────────────────────────────

    async def get_storage_info(self) -> dict[str, Any]:
        """Return NVR storage usage from the bootstrap's ``storageInfo``.

        Protect surfaces total / used / free bytes per attached disk.
        We aggregate to match the Hikvision contract that returns a
        single ``{total_gb, used_gb, free_gb}`` dict.
        """
        storage = self._bootstrap.get("nvr", {}).get("storageInfo", {}) or {}
        total_bytes = storage.get("totalSize") or 0
        used_bytes = storage.get("totalSpaceUsed") or 0
        free_bytes = max(0, total_bytes - used_bytes)
        gb = 1024**3
        return {
            "total_gb": round(total_bytes / gb, 2) if total_bytes else 0,
            "used_gb": round(used_bytes / gb, 2) if used_bytes else 0,
            "free_gb": round(free_bytes / gb, 2),
            "disks": storage.get("storageDevices", []),
        }

    # ── BaseAdapter abstract method conformance ──────────────────────

    async def test_connection(self) -> AdapterResult:
        """Used by `/api/v1/controllers/{id}/test`. Returns OK + the NVR
        summary if Protect is installed; surfaces the not-installed
        error cleanly otherwise.
        """
        try:
            ok = await self.connect()
            if not ok:
                return AdapterResult.fail("UniFi Protect connect failed")
            nvr = self._bootstrap.get("nvr") or {}
            return AdapterResult.ok(
                data={
                    "version": nvr.get("version"),
                    "name": nvr.get("name"),
                    "model": nvr.get("type"),
                    "camera_count": len(self._bootstrap.get("cameras") or []),
                },
            )
        except UniFiProtectNotInstalledError as exc:
            return AdapterResult.fail(str(exc), error_code="PROTECT_NOT_INSTALLED")
        except (AdapterAuthenticationError, AdapterConnectionError) as exc:
            return AdapterResult.fail(str(exc))
        finally:
            with httpx_suppress():
                await self.disconnect()

    async def get_device_status(self, device_id: str) -> dict[str, Any]:
        """Return a single camera's runtime status by id (Protect's
        Mongo ObjectID). Returns ``{}`` if the camera isn't in the
        bootstrap — Protect surfaces all known cameras in bootstrap.
        """
        if not self._bootstrap:
            await self.connect()
        for cam in self._bootstrap.get("cameras") or []:
            if cam.get("id") == device_id or cam.get("mac") == device_id:
                return {
                    "id": cam.get("id"),
                    "name": cam.get("name"),
                    "isConnected": bool(cam.get("isConnected")),
                    "state": cam.get("state"),
                    "uptime": cam.get("upSince"),
                    "lastSeen": cam.get("lastSeen"),
                }
        return {}

    async def get_device_info(
        self,
        device_id: str,
    ) -> DiscoveredDevice | None:
        """Find a single camera by id (Mongo ObjectID) or MAC."""
        devices = await self.discover_devices()
        for d in devices:
            if (
                d.raw_data.get("id") == device_id
                or d.mac_address.lower() == (device_id or "").lower()
            ):
                return d
        return None


def httpx_suppress():
    """Tiny context manager that swallows httpx errors during
    disconnect() so a connection cleanup failure can't mask a real
    test_connection error.
    """
    import contextlib

    return contextlib.suppress(Exception)
