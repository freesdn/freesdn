# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - ONVIF Camera Adapter
==================================

Multi-vendor ONVIF adapter supporting cameras from Hikvision, Dahua,
Axis, Reolink, Amcrest, Hanwha/Samsung, Bosch, Vivotek, Uniview,
and any other ONVIF-compliant device.

Capabilities
------------
- Live streaming     (RTSP main + sub via Profile S)
- Snapshots          (JPEG via GetSnapshotUri / Media2)
- PTZ control        (continuous + absolute + presets)
- Recording search   (Profile G / RecordingSearch)
- Event subscription (PullPoint / BasicNotification)
- Image settings     (brightness, contrast, saturation via Imaging service)
- Device info        (GetDeviceInformation)
- Network config     (GetNetworkInterfaces)
- Reboot             (SystemReboot)
- Profile detection  (S, G, T auto-discovery)
- WS-Discovery       (find cameras on the LAN)

Uses ``onvif-zeep`` (``python-onvif-zeep``) for ONVIF SOAP operations
and ``httpx`` for HTTP snapshot downloads.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar
from urllib.parse import quote, urlparse, urlunparse

import httpx

from app.adapters.base import (
    AdapterManifest,
    AdapterResult,
    BaseAdapter,
    DeviceTypeCapabilities,
    DiscoveredDevice,
)
from app.adapters.capabilities import Capability
from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
)
from app.adapters.exceptions import (
    AdapterReadOnlyError as _BaseAdapterReadOnlyError,
)
from app.adapters.onvif.profiles import (
    ONVIFCapabilities,
    parse_legacy_capabilities,
    parse_services_response,
)
from app.core.http_client import build_async_client

logger = logging.getLogger(__name__)


# ── Read-only write gate (parity with the Hikvision camera adapter) ───────────
#
# ONVIF previously executed operational/config writes (PTZ move, goto/set/delete
# preset, image settings, reboot) unconditionally — the only camera adapter that
# did not honor ADAPTER_READ_ONLY. Restore parity with Hikvision: writes are
# refused unless the caller passes ``force=True`` AND the operator has cleared
# ADAPTER_READ_ONLY. The cameras API/service opt in for sanctioned operator
# actions (``_API_WRITE_FORCE`` / ``_with_force``), so the legitimate paths are
# unaffected; a direct, un-forced write under read-only is refused.
class AdapterReadOnlyError(_BaseAdapterReadOnlyError):
    """Write refused because ``ADAPTER_READ_ONLY`` is set.

    Subclasses the canonical AdapterReadOnlyError so the central handler maps an
    ONVIF write-refusal to 403 (policy refusal), not the 502 catch-all.
    """

    pass


def _is_adapter_read_only() -> bool:
    """True (default-safe) unless ``ADAPTER_READ_ONLY=false`` in env.

    Per-vendor isolation: only the global flag is consulted; ONVIF does
    NOT fall back to any legacy vendor-specific switch.
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


def _enforce_read_only(*, force: bool, action: str) -> None:
    """Raise ``AdapterReadOnlyError`` when the write would mutate device state.

    Centralised so the message + behaviour stay in sync across the ONVIF
    write methods, mirroring the Hikvision adapter's gate exactly.
    """
    if _is_adapter_read_only() and not force:
        raise AdapterReadOnlyError(
            f"ADAPTER_READ_ONLY is set — ONVIF {action} refused. "
            "Set ADAPTER_READ_ONLY=false in the environment AND pass "
            "force=true to override.",
            adapter_id="onvif",
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

_ONVIF_SERVICES = frozenset(
    {
        "media",
        "media2",
        "ptz",
        "imaging",
        "events",
        "recording",
        "search",
        "replay",
        "analytics",
        "devicemgmt",
    }
)


def _safe_str(value: Any, default: str = "") -> str:
    """Convert zeep object / None to plain string."""
    if value is None:
        return default
    return str(value).strip() or default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value) if value is not None else default
    except (ValueError, TypeError):
        return default


def _extract_ip_from_uri(uri: str) -> str:
    """Pull the host portion out of an RTSP or HTTP URL."""
    parsed = urlparse(uri)
    return parsed.hostname or ""


def _rewrite_uri_credentials(uri: str, username: str, password: str) -> str:
    """Inject credentials into an RTSP/HTTP URI, stripping any existing ones."""
    parsed = urlparse(uri)
    safe_user = quote(username, safe="")
    safe_pass = quote(password, safe="")
    netloc = f"{safe_user}:{safe_pass}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


def _rewrite_uri_host(uri: str, host: str, port: int | None = None) -> str:
    """Replace the host (and optionally port) in a URI, stripping any credentials."""
    parsed = urlparse(uri)
    # Validate scheme — only allow http/https/rtsp
    if not parsed.scheme or parsed.scheme.lower() not in ("http", "https", "rtsp"):
        return ""
    new_port = port or parsed.port
    # Strip credentials from camera-returned URIs for safety
    netloc = host
    if new_port:
        netloc += f":{new_port}"
    return urlunparse(parsed._replace(netloc=netloc))


# ═══════════════════════════════════════════════════════════════════════════════
# ONVIFAdapter
# ═══════════════════════════════════════════════════════════════════════════════


class ONVIFAdapter(BaseAdapter):
    """
    Multi-vendor ONVIF adapter for IP cameras and NVRs.

    Supports any camera implementing ONVIF Profile S (streaming).
    Optionally uses Profile G (recording), Profile T (analytics),
    and Media2 service for newer devices.

    Tested vendors: Hikvision, Dahua, Axis, Reolink, Amcrest,
    Hanwha/Samsung, Bosch, Vivotek, Uniview, Lorex, TP-Link VIGI.
    """

    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="onvif",
        name="ONVIF Generic",
        vendor="ONVIF",
        version="1.0.0",
        description=(
            "Multi-vendor ONVIF adapter for IP cameras and NVRs. "
            "Supports Profile S (streaming), G (recording), T (analytics)."
        ),
        controller_type=None,
        supports_controller=False,
        supports_direct=True,
        supported_versions=["2.0", "2.2", "2.4", "2.6", "21.06", "21.12", "23.06"],
        device_types={
            "camera": DeviceTypeCapabilities(
                module="cameras",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.CAMERA_SNAPSHOT,
                    Capability.CAMERA_STREAM_RTSP,
                    Capability.CAMERA_MOTION_DETECTION,
                    Capability.CAMERA_AUDIO,
                    Capability.CAMERA_OSD,
                    Capability.CAMERA_PRIVACY_MASK,
                ],
                models=["*"],
            ),
            "camera_ptz": DeviceTypeCapabilities(
                module="cameras",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.CAMERA_SNAPSHOT,
                    Capability.CAMERA_STREAM_RTSP,
                    Capability.CAMERA_PTZ,
                    Capability.CAMERA_PTZ_PRESETS,
                    Capability.CAMERA_MOTION_DETECTION,
                    Capability.CAMERA_AUDIO,
                    Capability.CAMERA_TWO_WAY_AUDIO,
                    Capability.CAMERA_OSD,
                    Capability.CAMERA_PRIVACY_MASK,
                ],
                models=["*PTZ*", "*SD*", "*"],
            ),
            "nvr": DeviceTypeCapabilities(
                module="cameras",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.NVR_RECORDING,
                    Capability.NVR_PLAYBACK,
                    Capability.NVR_SEARCH,
                    Capability.NVR_CHANNEL_MANAGEMENT,
                ],
                models=["*"],
            ),
        },
        auth_methods=["wsse", "digest", "username_token"],
        rate_limit_calls_per_minute=30,
        rate_limit_concurrent=2,
        default_sync_interval=120,
        min_sync_interval=60,
        supports_webhooks=False,
        supports_real_time_events=True,
        supports_bulk_operations=False,
    )

    def __init__(self, host: str, username: str, password: str, **kwargs: Any):
        super().__init__(host, username, password, **kwargs)
        self.port: int = int(kwargs.get("port", 80))
        self.use_ssl: bool = kwargs.get("use_ssl", False)
        # On-prem cameras typically use self-signed certs — verify=False is default
        # but can be enabled when proper CA certs are deployed
        self._ssl_verify: bool = kwargs.get("ssl_verify", False)
        self._channel: int = kwargs.get("channel", 1)
        self._wsdl_dir: str | None = kwargs.get("wsdl_dir")

        # ONVIF client (from onvif-zeep)
        self._cam: Any = None  # ONVIFCamera instance
        self._device_info: dict[str, str] = {}
        self._onvif_caps: ONVIFCapabilities = ONVIFCapabilities()

        # Service proxy cache — lazily created
        self._media_service: Any = None
        self._media2_service: Any = None
        self._ptz_service: Any = None
        self._imaging_service: Any = None
        self._events_service: Any = None
        self._recording_service: Any = None
        self._search_service: Any = None
        self._replay_service: Any = None

        # Media profile cache
        self._profiles: list[Any] = []
        self._profile_token: str = ""
        self._sub_profile_token: str = ""

        # httpx client for snapshot downloads
        self._http: httpx.AsyncClient | None = None

        # Subscription state
        self._pullpoint: Any = None

    # =========================================================================
    # Connection Management
    # =========================================================================

    async def test_connection(self) -> AdapterResult:
        """Test if the ONVIF device is reachable and credentials are valid."""
        cam = None
        try:
            cam = await self._create_onvif_camera()
            info = await self._run_in_executor(cam.devicemgmt.GetDeviceInformation)
            return AdapterResult.ok(
                {
                    "manufacturer": _safe_str(info.Manufacturer),
                    "model": _safe_str(info.Model),
                    "firmware": _safe_str(info.FirmwareVersion),
                    "serial": _safe_str(info.SerialNumber),
                    "hardware_id": _safe_str(info.HardwareId),
                }
            )
        except Exception as exc:
            logger.warning("ONVIF test_connection failed for %s:%d: %s", self.host, self.port, exc)
            # Classify by exception type first, message string as fallback
            if isinstance(exc, (PermissionError,)):
                return AdapterResult.fail("Authentication failed", error_code="AUTH_FAILED")
            if isinstance(exc, (TimeoutError, OSError, ConnectionError)):
                return AdapterResult.fail("Connection timed out", error_code="TIMEOUT")
            err_str = str(exc).lower()
            if "auth" in err_str or "credential" in err_str or "401" in err_str:
                return AdapterResult.fail("Authentication failed", error_code="AUTH_FAILED")
            if "timeout" in err_str or "timed out" in err_str:
                return AdapterResult.fail("Connection timed out", error_code="TIMEOUT")
            return AdapterResult.fail("Connection test failed")
        finally:
            if cam:
                try:
                    cam.transport.session.close()
                except Exception:
                    logger.debug("Failed to close ONVIF test session")

    async def connect(self) -> bool:
        """
        Establish ONVIF session: create camera client, fetch device info,
        detect capabilities, and cache media profiles.
        """
        try:
            self._cam = await self._create_onvif_camera()

            # 1. Device information
            info = await self._run_in_executor(self._cam.devicemgmt.GetDeviceInformation)
            self._device_info = {
                "manufacturer": _safe_str(info.Manufacturer),
                "model": _safe_str(info.Model),
                "firmware": _safe_str(info.FirmwareVersion),
                "serial": _safe_str(info.SerialNumber),
                "hardware_id": _safe_str(info.HardwareId),
            }

            # 2. Detect capabilities / services
            await self._detect_capabilities()

            # 3. Cache media profiles
            await self._cache_media_profiles()

            # 4. Create httpx client for snapshots
            self._http = build_async_client(
                timeout=15.0,
                limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
                verify=self._ssl_verify,
            )

            self._connected = True
            logger.info(
                "Connected to ONVIF device %s (%s %s) at %s:%d — profiles: %s",
                self._device_info.get("serial", "?"),
                self._device_info.get("manufacturer", "?"),
                self._device_info.get("model", "?"),
                self.host,
                self.port,
                ", ".join(self._onvif_caps.profile_names()) or "none",
            )
            return True

        except AdapterAuthenticationError:
            self._connected = False
            await self._cleanup()
            raise
        except AdapterConnectionError:
            self._connected = False
            await self._cleanup()
            raise
        except Exception as exc:
            self._connected = False
            await self._cleanup()
            logger.error("ONVIF connect to %s:%d failed: %s", self.host, self.port, exc)
            # Detect auth failures by exception type first, then by message as fallback
            if isinstance(exc, (PermissionError,)):
                raise AdapterAuthenticationError(
                    "ONVIF authentication failed",
                    adapter_id="onvif",
                )
            err_str = str(exc).lower()
            if "auth" in err_str or "credential" in err_str or "401" in err_str:
                raise AdapterAuthenticationError(
                    "ONVIF authentication failed",
                    adapter_id="onvif",
                )
            if isinstance(exc, (TimeoutError, OSError, ConnectionError)):
                raise AdapterConnectionError(
                    "ONVIF connection timed out",
                    adapter_id="onvif",
                )
            raise AdapterConnectionError(
                "ONVIF connection failed",
                adapter_id="onvif",
            )

    async def disconnect(self) -> None:
        """Close all connections and clean up resources."""
        await self._cleanup()
        self._connected = False

    async def _cleanup(self) -> None:
        """Release resources."""
        if self._pullpoint is not None:
            with contextlib.suppress(Exception):
                await self._run_in_executor(self._pullpoint.Unsubscribe)
            self._pullpoint = None

        if self._http:
            # Detach first so a failing aclose() can never leave a half-closed
            # client reachable: get_snapshot()'s `if not self._http` guard would
            # otherwise pass and reuse a broken transport.
            http, self._http = self._http, None
            with contextlib.suppress(Exception):
                await http.aclose()

        if self._cam:
            with contextlib.suppress(Exception):
                self._cam.transport.session.close()
        self._cam = None
        self._media_service = None
        self._media2_service = None
        self._ptz_service = None
        self._imaging_service = None
        self._events_service = None
        self._recording_service = None
        self._search_service = None
        self._replay_service = None
        self._profiles = []

    # =========================================================================
    # ONVIF Client Helpers
    # =========================================================================

    async def _create_onvif_camera(self) -> Any:
        """Create and update an ONVIFCamera client."""
        try:
            from onvif import ONVIFCamera
        except ImportError:
            raise AdapterConnectionError(
                "onvif-zeep library is not installed. Install it with: pip install onvif-zeep",
                adapter_id="onvif",
            )

        kwargs: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "user": self.username,
            "passwd": self.password,
        }
        if self._wsdl_dir:
            kwargs["wsdl_dir"] = self._wsdl_dir

        # SECURITY: harden the live ONVIF/zeep SOAP
        # transport against a malicious/compromised camera.
        #   - XXE / external-entity expansion is already blocked: zeep 4.3.2's
        #     loader parses with resolve_entities=False (verified), so a hostile
        #     SOAP body can't pull external entities / billion-laughs via DTD.
        #   - The remaining risk is a slow-loris / hung-read DoS, so we inject a
        #     zeep Transport with explicit connect + operation timeouts (the
        #     default onvif-zeep client has none). Best-effort: fall back to the
        #     default transport if zeep's API shape differs, so connectivity to
        #     real cameras is never broken by this hardening.
        try:
            from zeep.transports import Transport

            kwargs["transport"] = Transport(timeout=10, operation_timeout=30)
        except Exception:  # pragma: no cover - defensive
            logger.debug("ONVIF: could not build a bounded zeep Transport; using default")

        cam = ONVIFCamera(**kwargs)

        # ONVIFCamera.update_xaddrs() is a coroutine in newer versions,
        # but synchronous in older ones.  Handle both.
        update = cam.update_xaddrs()
        if asyncio.iscoroutine(update) or asyncio.isfuture(update):
            await update

        return cam

    async def _run_in_executor(self, func: Any, *args: Any) -> Any:
        """
        Run a blocking zeep/ONVIF call in the default executor so it
        does not block the event loop.

        onvif-zeep service methods are synchronous (zeep uses requests
        under the hood).  Wrapping them here keeps the adapter fully async.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func, *args)

    async def _get_service(self, service_name: str) -> Any:
        """Get or create an ONVIF service proxy by name."""
        if not self._cam:
            raise AdapterConnectionError("Not connected — call connect() first", adapter_id="onvif")

        if service_name not in _ONVIF_SERVICES:
            logger.warning("Rejected unknown ONVIF service name: %s", service_name)
            return None

        attr = f"_{service_name}_service"
        cached = getattr(self, attr, None)
        if cached is not None:
            return cached

        try:
            svc = await self._run_in_executor(self._cam.create_onvif_service, service_name)
            setattr(self, attr, svc)
            return svc
        except Exception as exc:
            logger.debug("Failed to create ONVIF %s service: %s", service_name, exc)
            return None

    # =========================================================================
    # Capability Detection
    # =========================================================================

    async def _detect_capabilities(self) -> None:
        """Probe the device for supported ONVIF services and profiles."""
        caps = ONVIFCapabilities()

        # Try GetServices first (ONVIF 2.0+)
        try:
            params = self._cam.devicemgmt.create_type("GetServices")
            params.IncludeCapability = False
            services_raw = await self._run_in_executor(self._cam.devicemgmt.GetServices, params)
            svc_list = []
            for svc in services_raw:
                svc_list.append(
                    {
                        "Namespace": _safe_str(svc.Namespace),
                        "XAddr": _safe_str(svc.XAddr),
                    }
                )
            caps = parse_services_response(svc_list)
            logger.debug("Detected services via GetServices: %s", list(caps.services.keys()))
        except Exception:
            # Fallback to GetCapabilities (ONVIF 1.x)
            try:
                params = self._cam.devicemgmt.create_type("GetCapabilities")
                params.Category = "All"
                raw_caps = await self._run_in_executor(self._cam.devicemgmt.GetCapabilities, params)
                # Convert zeep object to dict-like access
                cap_dict: dict[str, Any] = {}
                for attr_name in (
                    "Media",
                    "PTZ",
                    "Imaging",
                    "Events",
                    "Recording",
                    "Replay",
                    "Search",
                    "Analytics",
                ):
                    val = getattr(raw_caps, attr_name, None)
                    if val is not None:
                        cap_dict[attr_name] = val
                caps = parse_legacy_capabilities(cap_dict)
                logger.debug("Detected capabilities via GetCapabilities (legacy)")
            except Exception as exc:
                logger.warning("Failed to detect capabilities: %s", exc)

        # Detect ONVIF profiles from scopes
        try:
            scopes = await self._run_in_executor(self._cam.devicemgmt.GetScopes)
            for scope in scopes:
                scope_str = (
                    _safe_str(scope.ScopeItem) if hasattr(scope, "ScopeItem") else _safe_str(scope)
                )
                scope_lower = scope_str.lower()
                if "/profile/" in scope_lower:
                    profile_name = scope_str.rsplit("/", 1)[-1].upper()
                    if profile_name in ("S", "G", "T", "C", "A", "Q"):
                        from app.adapters.onvif.profiles import ONVIFProfile

                        caps.profiles.append(ONVIFProfile(name=profile_name))
        except Exception:
            pass

        # Probe for PullPoint event support
        if caps.has_events:
            try:
                events_svc = await self._get_service("events")
                if events_svc:
                    await self._run_in_executor(events_svc.GetEventProperties)
                    caps.has_pull_point = True
            except Exception:
                pass

        self._onvif_caps = caps

    async def _cache_media_profiles(self) -> None:
        """Fetch and cache media profiles (main + sub stream)."""
        # Try Media2 first
        if self._onvif_caps.has_media2:
            try:
                media2 = await self._get_service("media2")
                if media2:
                    self._profiles = await self._run_in_executor(media2.GetProfiles)
                    if self._profiles:
                        self._profile_token = _safe_str(self._profiles[0].token)
                        if len(self._profiles) > 1:
                            self._sub_profile_token = _safe_str(self._profiles[1].token)
                        self._media2_service = media2
                        logger.debug(
                            "Cached %d Media2 profiles (main=%s)",
                            len(self._profiles),
                            self._profile_token,
                        )
                        return
            except Exception as exc:
                logger.debug("Media2 profile fetch failed, falling back: %s", exc)

        # Fallback to Media1
        try:
            media = await self._get_service("media")
            if media:
                self._profiles = await self._run_in_executor(media.GetProfiles)
                if self._profiles:
                    self._profile_token = _safe_str(self._profiles[0].token)
                    if len(self._profiles) > 1:
                        self._sub_profile_token = _safe_str(self._profiles[1].token)
                    self._media_service = media
                    logger.debug(
                        "Cached %d Media profiles (main=%s)",
                        len(self._profiles),
                        self._profile_token,
                    )
                    # Detect PTZ support from profiles
                    for profile in self._profiles:
                        if hasattr(profile, "PTZConfiguration") and profile.PTZConfiguration:
                            self._onvif_caps.has_ptz = True
                            break
                    # Detect audio
                    for profile in self._profiles:
                        if (
                            hasattr(profile, "AudioSourceConfiguration")
                            and profile.AudioSourceConfiguration
                        ):
                            self._onvif_caps.has_audio = True
                            break
                        if (
                            hasattr(profile, "AudioEncoderConfiguration")
                            and profile.AudioEncoderConfiguration
                        ):
                            self._onvif_caps.has_audio = True
                            break
        except Exception as exc:
            logger.warning("Failed to get media profiles: %s", exc)

    def _get_profile_token(self, stream: str = "main") -> str:
        """Get the profile token for a given stream type."""
        if stream == "sub" and self._sub_profile_token:
            return self._sub_profile_token
        return self._profile_token

    # =========================================================================
    # Discovery Methods (BaseAdapter interface)
    # =========================================================================

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """Discover the device itself.  For NVRs, also enumerate channels."""
        if not self._connected:
            await self.connect()

        device = await self._build_discovered_device()
        devices: list[DiscoveredDevice] = [device]

        # If this is an NVR, try to enumerate video sources as channels
        if device.device_type == "nvr":
            try:
                channels = await self.get_channels()
                for ch in channels:
                    ch_caps = [Capability.CAMERA_SNAPSHOT, Capability.CAMERA_STREAM_RTSP]
                    if self._onvif_caps.has_ptz:
                        ch_caps.extend([Capability.CAMERA_PTZ, Capability.CAMERA_PTZ_PRESETS])
                    if self._onvif_caps.has_audio:
                        ch_caps.append(Capability.CAMERA_AUDIO)

                    cam_dev = DiscoveredDevice(
                        mac_address=device.mac_address,
                        ip_address=self.host,
                        name=ch.get("name", f"Channel {ch.get('id', '?')}"),
                        vendor=self._device_info.get("manufacturer", "ONVIF"),
                        model=ch.get("model", self._device_info.get("model", "")),
                        firmware_version=self._device_info.get("firmware"),
                        device_type="camera",
                        status="online" if ch.get("online", True) else "offline",
                        serial_number=device.serial_number,
                        capabilities=ch_caps,
                        raw_data={
                            "channel_id": ch.get("id", 0),
                            "profile_token": ch.get("profile_token", ""),
                            "source_token": ch.get("source_token", ""),
                            "parent_nvr_serial": device.serial_number or "",
                        },
                    )
                    devices.append(cam_dev)
            except Exception as exc:
                logger.warning("Channel enumeration failed: %s", exc)

        return devices

    async def get_device_status(self, device_id: str) -> dict[str, Any]:
        """Get current device status."""
        if not self._connected:
            await self.connect()
        return {
            "status": "online",
            "ip_address": self.host,
            "port": self.port,
            "manufacturer": self._device_info.get("manufacturer"),
            "model": self._device_info.get("model"),
            "firmware": self._device_info.get("firmware"),
            "serial": self._device_info.get("serial"),
            "profiles": self._onvif_caps.profile_names(),
        }

    async def get_device_info(self, device_id: str) -> DiscoveredDevice | None:
        """Get detailed device information."""
        devices = await self.discover_devices()
        return devices[0] if devices else None

    async def _build_discovered_device(self) -> DiscoveredDevice:
        """Build a DiscoveredDevice from cached device info."""
        model = self._device_info.get("model", "").upper()

        device_type = "camera"
        if "nvr" in model.lower() or "dvr" in model.lower():
            device_type = "nvr"
        elif self._onvif_caps.has_ptz:
            device_type = "camera_ptz"

        caps = self._onvif_caps.to_freesdn_capabilities(device_type)

        # Try to get MAC address (async to avoid blocking event loop)
        mac = ""
        try:
            if self._cam:
                ifaces = await self._run_in_executor(self._cam.devicemgmt.GetNetworkInterfaces)
                if ifaces:
                    hw = getattr(ifaces[0], "Info", None)
                    if hw:
                        mac = _safe_str(getattr(hw, "HwAddress", ""))
        except Exception:
            pass

        return DiscoveredDevice(
            mac_address=mac,
            ip_address=self.host,
            name=self._device_info.get("model", self.host),
            vendor=self._device_info.get("manufacturer", "ONVIF"),
            model=self._device_info.get("model", "unknown"),
            firmware_version=self._device_info.get("firmware"),
            device_type=device_type,
            status="online",
            serial_number=self._device_info.get("serial"),
            capabilities=caps,
            raw_data=dict(self._device_info),
        )

    # =========================================================================
    # Device Info & System
    # =========================================================================

    async def get_full_system_info(self) -> dict[str, Any]:
        """
        Aggregate device information in a single call.
        Combines device info, capabilities, network interfaces, and time.
        """
        if not self._connected:
            await self.connect()

        async def _safe(coro: Any, fallback: Any) -> Any:
            try:
                return await coro
            except Exception:
                return fallback

        net_ifaces, time_info = await asyncio.gather(
            _safe(self.get_network_interfaces(), []),
            _safe(self.get_time_info(), {}),
        )

        return {
            "device": dict(self._device_info),
            "capabilities": {
                "profiles": self._onvif_caps.profile_names(),
                "has_ptz": self._onvif_caps.has_ptz,
                "has_audio": self._onvif_caps.has_audio,
                "has_recording": self._onvif_caps.has_recording,
                "has_analytics": self._onvif_caps.has_analytics,
                "has_events": self._onvif_caps.has_events,
                "has_media2": self._onvif_caps.has_media2,
                "media_profiles": len(self._profiles),
            },
            "network_interfaces": net_ifaces,
            "time": time_info,
        }

    async def get_time_info(self) -> dict[str, Any]:
        """Get device date/time and NTP configuration."""
        if not self._connected or not self._cam:
            await self.connect()

        try:
            dt_info = await self._run_in_executor(self._cam.devicemgmt.GetSystemDateAndTime)

            result: dict[str, Any] = {
                "time_mode": _safe_str(dt_info.DateTimeType, "Manual"),
                "daylight_savings": getattr(dt_info, "DaylightSavings", False),
            }

            # UTC date/time
            utc = getattr(dt_info, "UTCDateTime", None)
            if utc:
                d = getattr(utc, "Date", None)
                t = getattr(utc, "Time", None)
                if d and t:
                    with contextlib.suppress(ValueError, TypeError):
                        result["device_time_utc"] = datetime(
                            _safe_int(d.Year),
                            _safe_int(d.Month),
                            _safe_int(d.Day),
                            _safe_int(t.Hour),
                            _safe_int(t.Minute),
                            _safe_int(t.Second),
                            tzinfo=UTC,
                        ).isoformat()

            # Timezone
            tz = getattr(dt_info, "TimeZone", None)
            if tz:
                result["time_zone"] = _safe_str(getattr(tz, "TZ", ""))

            # NTP info
            try:
                ntp_info = await self._run_in_executor(self._cam.devicemgmt.GetNTP)
                if ntp_info and hasattr(ntp_info, "NTPManual"):
                    servers = ntp_info.NTPManual or []
                    result["ntp_servers"] = [
                        _safe_str(getattr(s, "IPv4Address", "") or getattr(s, "DNSname", ""))
                        for s in servers
                    ]
                result["ntp_from_dhcp"] = getattr(ntp_info, "FromDHCP", False)
            except Exception:
                pass

            return result
        except Exception as exc:
            logger.warning("Failed to get time info: %s", exc)
            return {}

    async def get_network_interfaces(self) -> list[dict[str, Any]]:
        """Get network interface configuration."""
        if not self._connected or not self._cam:
            await self.connect()

        try:
            ifaces_raw = await self._run_in_executor(self._cam.devicemgmt.GetNetworkInterfaces)

            interfaces: list[dict[str, Any]] = []
            for iface in ifaces_raw or []:
                entry: dict[str, Any] = {
                    "token": _safe_str(getattr(iface, "token", "")),
                    "enabled": getattr(iface, "Enabled", True),
                }

                info = getattr(iface, "Info", None)
                if info:
                    entry["name"] = _safe_str(getattr(info, "Name", ""))
                    entry["mac_address"] = _safe_str(getattr(info, "HwAddress", ""))
                    entry["mtu"] = _safe_int(getattr(info, "MTU", 1500))

                ipv4 = getattr(iface, "IPv4", None)
                if ipv4:
                    entry["ipv4_enabled"] = getattr(ipv4, "Enabled", True)
                    cfg = getattr(ipv4, "Config", None)
                    if cfg:
                        entry["dhcp"] = getattr(cfg, "DHCP", False)
                        manual = getattr(cfg, "Manual", None)
                        if manual and len(manual) > 0:
                            addr_obj = manual[0]
                            entry["ip_address"] = _safe_str(getattr(addr_obj, "Address", ""))
                            entry["prefix_length"] = _safe_int(
                                getattr(addr_obj, "PrefixLength", 24)
                            )

                        from_dhcp = getattr(cfg, "FromDHCP", None)
                        if from_dhcp:
                            entry["dhcp_address"] = _safe_str(getattr(from_dhcp, "Address", ""))

                interfaces.append(entry)

            return interfaces
        except Exception as exc:
            logger.warning("Failed to get network interfaces: %s", exc)
            return []

    # =========================================================================
    # Snapshots
    # =========================================================================

    async def get_snapshot(
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
    ) -> bytes:
        """
        Capture a JPEG snapshot from the camera.

        Uses GetSnapshotUri from Media or Media2 service, then downloads
        the JPEG via HTTP with digest auth.
        """
        if not self._connected:
            await self.connect()

        snapshot_uri = await self._get_snapshot_uri(channel, stream)
        if not snapshot_uri:
            raise AdapterConnectionError("Camera did not return a snapshot URI", adapter_id="onvif")

        # Rewrite host in case camera returned an internal IP
        snapshot_uri = _rewrite_uri_host(snapshot_uri, self.host, self.port)

        if not self._http:
            self._http = build_async_client(timeout=15.0, verify=self._ssl_verify)

        _MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024  # 10 MB

        try:
            response = await self._http.get(
                snapshot_uri,
                auth=httpx.DigestAuth(self.username, self.password),
                timeout=15.0,
            )
            if response.status_code == 200:
                if len(response.content) > _MAX_SNAPSHOT_BYTES:
                    raise AdapterConnectionError("Snapshot response too large", adapter_id="onvif")
                content_type = response.headers.get("content-type", "")
                # Accept image/* content-type, or detect JPEG magic bytes if no content-type
                if "image" in content_type or response.content[:3] == b"\xff\xd8\xff":
                    return response.content

            # Some cameras need basic auth instead of digest
            if response.status_code == 401:
                response = await self._http.get(
                    snapshot_uri,
                    auth=httpx.BasicAuth(self.username, self.password),
                    timeout=15.0,
                )
                if response.status_code == 200:
                    if len(response.content) > _MAX_SNAPSHOT_BYTES:
                        raise AdapterConnectionError(
                            "Snapshot response too large", adapter_id="onvif"
                        )
                    ct = response.headers.get("content-type", "")
                    if "image" in ct or response.content[:3] == b"\xff\xd8\xff":
                        return response.content

            raise AdapterConnectionError(
                f"Snapshot failed: HTTP {response.status_code}",
                adapter_id="onvif",
            )
        except httpx.TimeoutException:
            raise AdapterConnectionError("Snapshot download timed out", adapter_id="onvif")
        except AdapterConnectionError:
            raise
        except Exception as exc:
            logger.error("Snapshot failed for %s: %s", self.host, exc)
            raise AdapterConnectionError("Snapshot failed", adapter_id="onvif")

    async def _get_snapshot_uri(self, channel: int = 1, stream: str = "main") -> str:
        """Get the snapshot URI from Media2 or Media1 service."""
        profile_token = self._resolve_profile_token(channel, stream)
        if not profile_token:
            return ""

        # Try Media2 first
        if self._media2_service:
            try:
                params = self._media2_service.create_type("GetSnapshotUri")
                params.ProfileToken = profile_token
                result = await self._run_in_executor(self._media2_service.GetSnapshotUri, params)
                uri = _safe_str(result)
                if uri:
                    return uri
            except Exception as exc:
                logger.debug("Media2 GetSnapshotUri failed: %s", exc)

        # Fallback to Media1
        if self._media_service:
            try:
                params = self._media_service.create_type("GetSnapshotUri")
                params.ProfileToken = profile_token
                result = await self._run_in_executor(self._media_service.GetSnapshotUri, params)
                uri = _safe_str(getattr(result, "Uri", result))
                if uri:
                    return uri
            except Exception as exc:
                logger.debug("Media GetSnapshotUri failed: %s", exc)

        return ""

    # =========================================================================
    # RTSP Streaming
    # =========================================================================

    def get_rtsp_url(  # type: ignore[override]
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
    ) -> str:
        """
        Build RTSP URL for live streaming.

        If a stream URI was cached during profile detection, rewrite it
        with correct host.  Otherwise build a standard ONVIF RTSP path.
        """
        # Try to get URI from cached profiles
        profile_token = self._resolve_profile_token(channel, stream)
        if not profile_token:
            # Fallback: generic RTSP path
            return f"rtsp://***:***@{self.host}:554/stream{channel}"

        # For the synchronous call path, return the constructed URL
        return f"rtsp://***:***@{self.host}:554/onvif/profile/{profile_token}"

    async def get_stream_url(
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
    ) -> str:
        """
        Get the actual RTSP stream URI from the camera via ONVIF.

        This is the async version that queries the device.
        """
        if not self._connected:
            await self.connect()

        profile_token = self._resolve_profile_token(channel, stream)
        if not profile_token:
            return ""

        # Try Media2
        if self._media2_service:
            try:
                params = self._media2_service.create_type("GetStreamUri")
                params.Protocol = "RTSP"
                params.ProfileToken = profile_token
                result = await self._run_in_executor(self._media2_service.GetStreamUri, params)
                uri = _safe_str(result)
                if uri:
                    return _rewrite_uri_host(uri, self.host)
            except Exception as exc:
                logger.debug("Media2 GetStreamUri failed: %s", exc)

        # Fallback to Media1
        if self._media_service:
            try:
                params = self._media_service.create_type("GetStreamUri")
                params.ProfileToken = profile_token
                stream_setup = self._media_service.create_type("StreamSetup")
                stream_setup.Stream = "RTP-Unicast"
                transport = self._media_service.create_type("Transport")
                transport.Protocol = "RTSP"
                stream_setup.Transport = transport
                params.StreamSetup = stream_setup
                result = await self._run_in_executor(self._media_service.GetStreamUri, params)
                uri = _safe_str(getattr(result, "Uri", result))
                if uri:
                    return _rewrite_uri_host(uri, self.host)
            except Exception as exc:
                logger.debug("Media GetStreamUri failed: %s", exc)

        return self.get_rtsp_url(device_id, channel, stream)

    # =========================================================================
    # PTZ Control
    # =========================================================================

    async def ptz_control(
        self,
        device_id: str = "",
        action: str = "stop",
        speed: int = 50,
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """
        Continuous PTZ movement via ONVIF PTZ service.

        Args:
            device_id: Device identifier (unused for direct connection).
            action: One of up / down / left / right / zoom_in / zoom_out /
                    up_left / up_right / down_left / down_right / stop.
            speed: Speed 1-100 (mapped to ONVIF 0.0-1.0 range).
            channel: Optional channel override.
            force: Opt in to the live write under ADAPTER_READ_ONLY.
        """
        _enforce_read_only(force=force, action="PTZ control")
        if not self._connected:
            await self.connect()

        if not self._onvif_caps.has_ptz:
            return AdapterResult.fail("Device does not support PTZ", error_code="NOT_SUPPORTED")

        ptz = await self._get_service("ptz")
        if not ptz:
            return AdapterResult.fail("PTZ service not available", error_code="NOT_SUPPORTED")

        profile_token = self._resolve_profile_token(channel or self._channel)
        if not profile_token:
            return AdapterResult.fail("No media profile available")

        # Normalise speed to 0.0-1.0
        norm_speed = max(0.01, min(1.0, speed / 100.0))

        # Action mapping: (pan, tilt, zoom) as sign multipliers
        _ACTION_MAP: dict[str, tuple[float, float, float]] = {
            "right": (1, 0, 0),
            "left": (-1, 0, 0),
            "up": (0, 1, 0),
            "down": (0, -1, 0),
            "up_right": (1, 1, 0),
            "up_left": (-1, 1, 0),
            "down_right": (1, -1, 0),
            "down_left": (-1, -1, 0),
            "zoom_in": (0, 0, 1),
            "zoom_out": (0, 0, -1),
            "stop": (0, 0, 0),
        }

        vec = _ACTION_MAP.get(action.lower())
        if vec is None:
            return AdapterResult.fail(f"Unknown PTZ action: {action}")

        try:
            if action.lower() == "stop":
                params = ptz.create_type("Stop")
                params.ProfileToken = profile_token
                params.PanTilt = True
                params.Zoom = True
                await self._run_in_executor(ptz.Stop, params)
            else:
                params = ptz.create_type("ContinuousMove")
                params.ProfileToken = profile_token
                velocity = ptz.create_type("PTZSpeed")

                pan_tilt = ptz.create_type("Vector2D")
                pan_tilt.x = vec[0] * norm_speed
                pan_tilt.y = vec[1] * norm_speed
                velocity.PanTilt = pan_tilt

                zoom_vec = ptz.create_type("Vector1D")
                zoom_vec.x = vec[2] * norm_speed
                velocity.Zoom = zoom_vec

                params.Velocity = velocity
                # Auto-stop after 5 seconds if client doesn't send stop
                params.Timeout = "PT5S"
                await self._run_in_executor(ptz.ContinuousMove, params)

            return AdapterResult.ok({"action": action, "speed": speed})
        except AdapterError:
            # Connection/auth/read-only refusals carry their own HTTP mapping
            # (conn->502, auth->401, read-only->403). Re-raise so the middleware
            # classifies them instead of collapsing every failure into a 500.
            raise
        except Exception as exc:
            logger.error("PTZ control failed for %s: %s", self.host, exc)
            return AdapterResult.fail("PTZ control failed", error_code="PTZ_FAILED")

    async def get_presets(
        self,
        device_id: str = "",
        channel: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get all PTZ presets."""
        if not self._connected:
            await self.connect()

        if not self._onvif_caps.has_ptz:
            return []

        ptz = await self._get_service("ptz")
        if not ptz:
            return []

        profile_token = self._resolve_profile_token(channel or self._channel)
        if not profile_token:
            return []

        try:
            presets_raw = await self._run_in_executor(ptz.GetPresets, profile_token)

            presets: list[dict[str, Any]] = []
            for p in presets_raw or []:
                preset: dict[str, Any] = {
                    "id": _safe_int(getattr(p, "token", "0")),
                    "token": _safe_str(getattr(p, "token", "")),
                    "name": _safe_str(getattr(p, "Name", "")),
                }

                pos = getattr(p, "PTZPosition", None)
                if pos:
                    pt = getattr(pos, "PanTilt", None)
                    z = getattr(pos, "Zoom", None)
                    if pt:
                        preset["pan"] = float(getattr(pt, "x", 0))
                        preset["tilt"] = float(getattr(pt, "y", 0))
                    if z:
                        preset["zoom"] = float(getattr(z, "x", 0))

                presets.append(preset)

            return presets
        except Exception as exc:
            logger.error("Failed to get PTZ presets: %s", exc)
            return []

    async def goto_preset(
        self,
        device_id: str = "",
        preset: int | str = 1,
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Move camera to a saved PTZ preset."""
        _enforce_read_only(force=force, action="goto preset")
        if not self._connected:
            await self.connect()

        ptz = await self._get_service("ptz")
        if not ptz:
            return AdapterResult.fail("PTZ service not available")

        profile_token = self._resolve_profile_token(channel or self._channel)
        if not profile_token:
            return AdapterResult.fail("No media profile available")

        try:
            params = ptz.create_type("GotoPreset")
            params.ProfileToken = profile_token
            params.PresetToken = str(preset)
            await self._run_in_executor(ptz.GotoPreset, params)
            return AdapterResult.ok({"preset": preset})
        except Exception as exc:
            logger.error("Goto preset failed for %s: %s", self.host, exc)
            return AdapterResult.fail("Goto preset failed")

    async def set_preset(
        self,
        device_id: str = "",
        preset: int | str = 1,
        name: str = "",
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Save the current PTZ position as a preset."""
        _enforce_read_only(force=force, action="set preset")
        if not self._connected:
            await self.connect()

        ptz = await self._get_service("ptz")
        if not ptz:
            return AdapterResult.fail("PTZ service not available")

        profile_token = self._resolve_profile_token(channel or self._channel)
        if not profile_token:
            return AdapterResult.fail("No media profile available")

        try:
            params = ptz.create_type("SetPreset")
            params.ProfileToken = profile_token
            params.PresetToken = str(preset)
            if name:
                params.PresetName = name
            result = await self._run_in_executor(ptz.SetPreset, params)
            return AdapterResult.ok(
                {
                    "preset": str(preset),
                    "name": name,
                    "token": _safe_str(result),
                }
            )
        except Exception as exc:
            logger.error("Set preset failed for %s: %s", self.host, exc)
            return AdapterResult.fail("Set preset failed")

    async def delete_preset(
        self,
        device_id: str = "",
        preset: int | str = 1,
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Delete a PTZ preset."""
        _enforce_read_only(force=force, action="delete preset")
        if not self._connected:
            await self.connect()

        ptz = await self._get_service("ptz")
        if not ptz:
            return AdapterResult.fail("PTZ service not available")

        profile_token = self._resolve_profile_token(channel or self._channel)
        if not profile_token:
            return AdapterResult.fail("No media profile available")

        try:
            params = ptz.create_type("RemovePreset")
            params.ProfileToken = profile_token
            params.PresetToken = str(preset)
            await self._run_in_executor(ptz.RemovePreset, params)
            return AdapterResult.ok({"deleted": str(preset)})
        except Exception as exc:
            logger.error("Delete preset failed for %s: %s", self.host, exc)
            return AdapterResult.fail("Delete preset failed")

    # =========================================================================
    # Image Settings
    # =========================================================================

    async def get_image_settings(
        self,
        device_id: str = "",
        channel: int | None = None,
    ) -> dict[str, Any]:
        """Get image settings (brightness, contrast, saturation, sharpness)."""
        if not self._connected:
            await self.connect()

        if not self._onvif_caps.has_imaging:
            return {"error": "Imaging service not available"}

        imaging = await self._get_service("imaging")
        if not imaging:
            return {"error": "Imaging service not available"}

        # Get video source token from profile
        source_token = self._get_video_source_token(channel or self._channel)
        if not source_token:
            return {"error": "No video source found"}

        try:
            params = imaging.create_type("GetImagingSettings")
            params.VideoSourceToken = source_token
            settings = await self._run_in_executor(imaging.GetImagingSettings, params)

            result: dict[str, Any] = {}

            # Standard settings
            result["brightness"] = _safe_int(getattr(settings, "Brightness", 50))
            result["contrast"] = _safe_int(getattr(settings, "Contrast", 50))
            result["saturation"] = _safe_int(getattr(settings, "ColorSaturation", 50))
            result["sharpness"] = _safe_int(getattr(settings, "Sharpness", 50))

            # Backlight compensation
            blc = getattr(settings, "BacklightCompensation", None)
            if blc:
                result["backlight_mode"] = _safe_str(getattr(blc, "Mode", "OFF"))
                result["backlight_level"] = _safe_int(getattr(blc, "Level", 0))

            # Exposure
            exposure = getattr(settings, "Exposure", None)
            if exposure:
                result["exposure_mode"] = _safe_str(getattr(exposure, "Mode", "AUTO"))
                result["exposure_min_gain"] = float(getattr(exposure, "MinGain", 0))
                result["exposure_max_gain"] = float(getattr(exposure, "MaxGain", 0))

            # White balance
            wb = getattr(settings, "WhiteBalance", None)
            if wb:
                result["white_balance_mode"] = _safe_str(getattr(wb, "Mode", "AUTO"))

            # Wide dynamic range
            wdr = getattr(settings, "WideDynamicRange", None)
            if wdr:
                result["wdr_mode"] = _safe_str(getattr(wdr, "Mode", "OFF"))
                result["wdr_level"] = _safe_int(getattr(wdr, "Level", 0))

            # IR cut filter (day/night)
            result["ir_cut_filter"] = _safe_str(getattr(settings, "IrCutFilter", "AUTO"))

            return result
        except Exception as exc:
            logger.error("get_image_settings failed for %s: %s", self.host, exc)
            return {"error": "Failed to retrieve image settings"}

    async def set_image_settings(
        self,
        settings: dict[str, Any],
        device_id: str = "",
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Update image settings (brightness, contrast, saturation, sharpness)."""
        _enforce_read_only(force=force, action="set image settings")
        if not self._connected:
            await self.connect()

        imaging = await self._get_service("imaging")
        if not imaging:
            return {"success": False, "error": "Imaging service not available"}

        source_token = self._get_video_source_token(channel or self._channel)
        if not source_token:
            return {"success": False, "error": "No video source found"}

        try:
            params = imaging.create_type("SetImagingSettings")
            params.VideoSourceToken = source_token

            img_settings = imaging.create_type("ImagingSettings20")

            def _clamp_img(val: Any, lo: float = 0.0, hi: float = 100.0) -> float:
                v = float(val)
                if not math.isfinite(v):
                    raise ValueError("non-finite imaging value")
                return max(lo, min(hi, v))

            if "brightness" in settings:
                img_settings.Brightness = _clamp_img(settings["brightness"])
            if "contrast" in settings:
                img_settings.Contrast = _clamp_img(settings["contrast"])
            if "saturation" in settings:
                img_settings.ColorSaturation = _clamp_img(settings["saturation"])
            if "sharpness" in settings:
                img_settings.Sharpness = _clamp_img(settings["sharpness"])

            params.ImagingSettings = img_settings
            await self._run_in_executor(imaging.SetImagingSettings, params)

            return {"success": True}
        except Exception as exc:
            logger.error("set_image_settings failed for %s: %s", self.host, exc)
            return {"success": False, "error": "Failed to update image settings"}

    # =========================================================================
    # Recording & Playback (Profile G)
    # =========================================================================

    async def search_recordings(
        self,
        device_id: str = "",
        channel: int = 1,
        start_time: str = "",
        end_time: str = "",
        event_type: str = "",
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search for recordings on an NVR via ONVIF RecordingSearch service.

        Args:
            device_id: Ignored for direct connection.
            channel: Channel number (used to filter by source).
            start_time: ISO 8601 start time.
            end_time: ISO 8601 end time.
            event_type: Optional filter.
            max_results: Maximum number of results.
        """
        if not self._connected:
            await self.connect()

        if not self._onvif_caps.has_search:
            return []

        search = await self._get_service("search")
        if not search:
            return []

        try:
            # Parse times
            if start_time:
                datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            else:
                datetime.now(UTC) - timedelta(hours=24)

            if end_time:
                datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            else:
                datetime.now(UTC)

            # FindRecordings
            params = search.create_type("FindRecordings")
            scope = search.create_type("SearchScope")

            # Set time range
            included_sources = search.create_type("SourceReference")
            scope.IncludedSources = [included_sources]

            params.Scope = scope
            params.MaxMatches = max_results
            # KeepAliveTime must be a duration string
            params.KeepAliveTime = "PT60S"

            token = await self._run_in_executor(search.FindRecordings, params)

            # GetRecordingSearchResults
            results_params = search.create_type("GetRecordingSearchResults")
            results_params.SearchToken = _safe_str(token)
            results_params.MaxResults = max_results
            results_params.WaitTime = "PT5S"

            results = await self._run_in_executor(search.GetRecordingSearchResults, results_params)

            recordings: list[dict[str, Any]] = []
            result_list = getattr(results, "RecordingInformation", []) or []
            for rec in result_list:
                entry: dict[str, Any] = {
                    "recording_token": _safe_str(getattr(rec, "RecordingToken", "")),
                    "source": _safe_str(
                        getattr(rec, "Source", {}).get("SourceId", "")
                        if isinstance(getattr(rec, "Source", None), dict)
                        else ""
                    ),
                }

                # Earliest/latest recording time
                entry["earliest"] = _safe_str(getattr(rec, "EarliestRecording", ""))
                entry["latest"] = _safe_str(getattr(rec, "LatestRecording", ""))

                # Track information
                tracks = getattr(rec, "Track", []) or []
                entry["tracks"] = []
                for track in tracks:
                    entry["tracks"].append(
                        {
                            "token": _safe_str(getattr(track, "TrackToken", "")),
                            "track_type": _safe_str(getattr(track, "TrackType", "")),
                            "description": _safe_str(getattr(track, "Description", "")),
                        }
                    )

                recordings.append(entry)

            return recordings
        except Exception as exc:
            logger.error("search_recordings failed: %s", exc)
            return []

    async def get_recording_tracks(self) -> list[dict[str, Any]]:
        """Get recording track information from the device."""
        if not self._connected:
            await self.connect()

        if not self._onvif_caps.has_recording:
            return []

        recording = await self._get_service("recording")
        if not recording:
            return []

        try:
            recs = await self._run_in_executor(recording.GetRecordings)

            tracks: list[dict[str, Any]] = []
            for rec in recs or []:
                rec_token = _safe_str(getattr(rec, "RecordingToken", ""))
                config = getattr(rec, "Configuration", None)
                source = getattr(config, "Source", None) if config else None

                track_entry: dict[str, Any] = {
                    "recording_token": rec_token,
                    "source_id": _safe_str(getattr(source, "SourceId", "")) if source else "",
                    "name": _safe_str(getattr(source, "Name", "")) if source else "",
                }

                # Track list
                track_list = getattr(rec, "Tracks", None)
                if track_list:
                    track_items = getattr(track_list, "Track", []) or []
                    track_entry["tracks"] = [
                        {
                            "token": _safe_str(getattr(t, "TrackToken", "")),
                            "track_type": _safe_str(getattr(t, "TrackType", "")),
                            "description": _safe_str(getattr(t, "Description", "")),
                        }
                        for t in track_items
                    ]

                tracks.append(track_entry)

            return tracks
        except Exception as exc:
            logger.warning("get_recording_tracks failed: %s", exc)
            return []

    def get_playback_url(
        self,
        device_id: str = "",
        channel: int = 1,
        start_time: str = "",
        end_time: str = "",
    ) -> str:
        """Build a playback RTSP URL (generic ONVIF pattern)."""
        profile_token = self._resolve_profile_token(channel)
        return (
            f"rtsp://***:***@{self.host}:554/"
            f"onvif/replay?profile={profile_token}"
            f"&starttime={start_time}&endtime={end_time}"
        )

    # =========================================================================
    # Events (PullPoint Subscription)
    # =========================================================================

    async def subscribe_events(
        self,
        callback_url: str = "",
        event_types: list[str] | None = None,
    ) -> AdapterResult:
        """
        Subscribe to camera events via ONVIF PullPoint subscription.

        Unlike HTTP callback (Hikvision-style), ONVIF PullPoint works
        behind NAT since the client polls for events.
        """
        if not self._connected:
            await self.connect()

        if not self._onvif_caps.has_events:
            return AdapterResult.fail("Events not supported", error_code="NOT_SUPPORTED")

        events = await self._get_service("events")
        if not events:
            return AdapterResult.fail("Events service not available")

        try:
            # Create PullPoint subscription
            params = events.create_type("CreatePullPointSubscription")
            # InitialTerminationTime: how long the subscription lives
            params.InitialTerminationTime = "PT600S"  # 10 minutes

            result = await self._run_in_executor(events.CreatePullPointSubscription, params)

            self._pullpoint = result
            subscription_id = _safe_str(
                getattr(result, "SubscriptionReference", {}).get("Address", "")
                if isinstance(getattr(result, "SubscriptionReference", None), dict)
                else ""
            )

            return AdapterResult.ok(
                {
                    "subscribed": True,
                    "mode": "pullpoint",
                    "subscription_id": subscription_id,
                }
            )
        except Exception as exc:
            logger.error("Event subscription failed for %s: %s", self.host, exc)
            return AdapterResult.fail("Event subscription failed")

    async def pull_events(self, timeout: int = 10, max_events: int = 50) -> list[dict[str, Any]]:
        """
        Pull pending events from an active PullPoint subscription.

        Returns a list of event dicts with normalized keys.
        """
        if not self._pullpoint:
            return []

        try:
            # PullMessages is on the subscription manager, not the events service
            pull_svc = self._pullpoint
            if hasattr(pull_svc, "PullMessages"):
                result = await self._run_in_executor(
                    pull_svc.PullMessages,
                    {"Timeout": f"PT{timeout}S", "MessageLimit": max_events},
                )
            else:
                return []

            events: list[dict[str, Any]] = []
            messages = getattr(result, "NotificationMessage", []) or []
            for msg in messages:
                event: dict[str, Any] = {
                    "topic": _safe_str(getattr(msg, "Topic", "")),
                }

                message = getattr(msg, "Message", None)
                if message:
                    event["property_operation"] = _safe_str(
                        getattr(message, "_attr_1", {}).get("PropertyOperation", "")
                        if isinstance(getattr(message, "_attr_1", None), dict)
                        else ""
                    )
                    utc_time = getattr(message, "UtcTime", None)
                    if utc_time:
                        event["timestamp"] = str(utc_time)

                    # Source and data items
                    source = getattr(message, "Source", None)
                    if source:
                        items = getattr(source, "SimpleItem", []) or []
                        event["source"] = {
                            _safe_str(getattr(item, "Name", "")): _safe_str(
                                getattr(item, "Value", "")
                            )
                            for item in items
                        }

                    data = getattr(message, "Data", None)
                    if data:
                        items = getattr(data, "SimpleItem", []) or []
                        event["data"] = {
                            _safe_str(getattr(item, "Name", "")): _safe_str(
                                getattr(item, "Value", "")
                            )
                            for item in items
                        }

                events.append(event)

            return events
        except Exception as exc:
            logger.debug("pull_events failed: %s", exc)
            return []

    async def get_event_state(self) -> dict[str, Any]:
        """Get current event state by pulling recent events."""
        events = await self.pull_events(timeout=3, max_events=20)
        return {"events": events}

    # =========================================================================
    # NVR Channel Discovery
    # =========================================================================

    async def get_channels(self) -> list[dict[str, Any]]:
        """
        Enumerate video sources / media profiles as channels.

        Works for both standalone cameras (1 channel) and NVRs (N channels).
        """
        if not self._connected:
            await self.connect()

        channels: list[dict[str, Any]] = []

        # Use video sources to enumerate channels
        try:
            if self._media_service:
                sources = await self._run_in_executor(self._media_service.GetVideoSources)
                for idx, src in enumerate(sources or []):
                    ch: dict[str, Any] = {
                        "id": idx + 1,
                        "source_token": _safe_str(getattr(src, "token", "")),
                        "name": f"Channel {idx + 1}",
                        "online": True,
                    }

                    resolution = getattr(src, "Resolution", None)
                    if resolution:
                        ch["resolution_width"] = _safe_int(getattr(resolution, "Width", 0))
                        ch["resolution_height"] = _safe_int(getattr(resolution, "Height", 0))

                    ch["framerate"] = _safe_int(getattr(src, "Framerate", 0))

                    # Find matching profile token
                    for profile in self._profiles:
                        vsc = getattr(profile, "VideoSourceConfiguration", None)
                        if vsc and _safe_str(getattr(vsc, "SourceToken", "")) == ch["source_token"]:
                            ch["profile_token"] = _safe_str(profile.token)
                            ch["name"] = _safe_str(getattr(profile, "Name", ch["name"]))
                            break

                    channels.append(ch)

                if channels:
                    return channels
        except Exception as exc:
            logger.debug("Video source enumeration failed: %s", exc)

        # Fallback: use media profiles directly
        for idx, profile in enumerate(self._profiles):
            ch = {
                "id": idx + 1,
                "profile_token": _safe_str(profile.token),
                "name": _safe_str(getattr(profile, "Name", f"Profile {idx + 1}")),
                "online": True,
            }

            vsc = getattr(profile, "VideoSourceConfiguration", None)
            if vsc:
                ch["source_token"] = _safe_str(getattr(vsc, "SourceToken", ""))

            vec = getattr(profile, "VideoEncoderConfiguration", None)
            if vec:
                res = getattr(vec, "Resolution", None)
                if res:
                    ch["resolution_width"] = _safe_int(getattr(res, "Width", 0))
                    ch["resolution_height"] = _safe_int(getattr(res, "Height", 0))
                ch["encoding"] = _safe_str(getattr(vec, "Encoding", ""))
                ch["bitrate"] = _safe_int(
                    getattr(getattr(vec, "RateControl", None), "BitrateLimit", 0)
                )

            channels.append(ch)

        return channels

    async def get_channel_capabilities(
        self,
        channel: int = 1,
    ) -> dict[str, Any]:
        """Get encoding capabilities for a channel."""
        if not self._connected:
            await self.connect()

        profile_token = self._resolve_profile_token(channel)
        if not profile_token:
            return {}

        result: dict[str, Any] = {"channel": channel}

        # Find matching profile
        for profile in self._profiles:
            if _safe_str(profile.token) == profile_token:
                vec = getattr(profile, "VideoEncoderConfiguration", None)
                if vec:
                    result["encoding"] = _safe_str(getattr(vec, "Encoding", ""))
                    res = getattr(vec, "Resolution", None)
                    if res:
                        result["video_resolution_width"] = _safe_int(getattr(res, "Width", 0))
                        result["video_resolution_height"] = _safe_int(getattr(res, "Height", 0))
                    rate = getattr(vec, "RateControl", None)
                    if rate:
                        result["max_framerate"] = _safe_int(getattr(rate, "FrameRateLimit", 0))
                        result["max_bitrate"] = _safe_int(getattr(rate, "BitrateLimit", 0))
                    result["quality"] = float(getattr(vec, "Quality", 0))

                aec = getattr(profile, "AudioEncoderConfiguration", None)
                if aec:
                    result["audio_codec"] = _safe_str(getattr(aec, "Encoding", ""))
                    result["audio_enabled"] = True
                else:
                    result["audio_enabled"] = False

                break

        return result

    # =========================================================================
    # Device Control
    # =========================================================================

    async def reboot_device(self, device_id: str = "", *, force: bool = False) -> AdapterResult:
        """Reboot the device via ONVIF SystemReboot."""
        _enforce_read_only(force=force, action="reboot")
        if not self._connected or not self._cam:
            await self.connect()

        try:
            message = await self._run_in_executor(self._cam.devicemgmt.SystemReboot)
            return AdapterResult.ok(
                {
                    "action": "reboot",
                    "message": _safe_str(message, "Rebooting..."),
                }
            )
        except Exception as exc:
            logger.error("Reboot failed for %s: %s", self.host, exc)
            return AdapterResult.fail("Reboot failed")

    # =========================================================================
    # OSD Settings
    # =========================================================================

    async def get_osd_settings(
        self,
        device_id: str = "",
        channel: int | None = None,
    ) -> dict[str, Any]:
        """Get OSD (on-screen display) overlay settings."""
        if not self._connected:
            await self.connect()

        if not self._media_service and not self._media2_service:
            return {"error": "Media service not available"}

        try:
            if self._media2_service:
                osds = await self._run_in_executor(self._media2_service.GetOSDs, {})
            elif self._media_service:
                # Media1 uses GetOSDs with OSDToken
                try:
                    osds = await self._run_in_executor(
                        self._media_service.GetOSDs, {"ConfigurationToken": self._profile_token}
                    )
                except Exception:
                    return {"error": "OSD query not supported by this camera"}
            else:
                return {"error": "No media service"}

            osd_list: list[dict[str, Any]] = []
            for osd in osds or []:
                entry: dict[str, Any] = {
                    "token": _safe_str(getattr(osd, "token", "")),
                    "type": _safe_str(getattr(osd, "Type", "")),
                }

                pos = getattr(osd, "Position", None)
                if pos:
                    entry["position_type"] = _safe_str(getattr(pos, "Type", ""))
                    pt = getattr(pos, "Pos", None)
                    if pt:
                        entry["position_x"] = float(getattr(pt, "x", 0))
                        entry["position_y"] = float(getattr(pt, "y", 0))

                text = getattr(osd, "TextString", None)
                if text:
                    entry["text_type"] = _safe_str(getattr(text, "Type", ""))
                    entry["text_content"] = _safe_str(getattr(text, "PlainText", ""))
                    entry["date_format"] = _safe_str(getattr(text, "DateFormat", ""))
                    entry["time_format"] = _safe_str(getattr(text, "TimeFormat", ""))

                osd_list.append(entry)

            return {"osds": osd_list}
        except Exception as exc:
            logger.error("get_osd_settings failed for %s: %s", self.host, exc)
            return {"error": "Failed to retrieve OSD settings"}

    # =========================================================================
    # Motion Detection (via Analytics / Events)
    # =========================================================================

    async def get_motion_detection(self, channel: int = 1) -> dict[str, Any]:
        """
        Get motion detection configuration.

        ONVIF motion detection is typically configured through analytics
        rules or via vendor extensions.  This provides the best-effort
        status via event properties.
        """
        if not self._connected:
            await self.connect()

        result: dict[str, Any] = {"channel": channel, "supported": False}

        if self._onvif_caps.has_analytics:
            try:
                analytics = await self._get_service("analytics")
                if analytics:
                    rules = await self._run_in_executor(
                        analytics.GetRules,
                        self._resolve_profile_token(channel),
                    )
                    for rule in rules or []:
                        rule_type = _safe_str(getattr(rule, "Type", ""))
                        if "motion" in rule_type.lower() or "CellMotionDetector" in rule_type:
                            result["supported"] = True
                            result["rule_name"] = _safe_str(getattr(rule, "Name", ""))
                            result["rule_type"] = rule_type

                            # Extract parameters
                            params = getattr(rule, "Parameters", None)
                            if params:
                                items = getattr(params, "SimpleItem", []) or []
                                for item in items:
                                    name = _safe_str(getattr(item, "Name", ""))
                                    value = _safe_str(getattr(item, "Value", ""))
                                    result[f"param_{name}"] = value
                            break
            except Exception as exc:
                logger.debug("Analytics motion detection query failed: %s", exc)

        return result

    # =========================================================================
    # Profile Token Resolution
    # =========================================================================

    def _resolve_profile_token(self, channel: int | None = None, stream: str = "main") -> str:
        """
        Resolve a channel number + stream type to an ONVIF profile token.

        For simple cameras with 2 profiles, channel 1 + main = first profile,
        channel 1 + sub = second profile.  For NVRs with many sources,
        channel N maps to the Nth video source's profile.
        """
        if not self._profiles:
            return self._profile_token or ""

        # For sub-stream, try to find a matching lower-resolution profile
        if stream == "sub" and self._sub_profile_token:
            return self._sub_profile_token

        ch_idx = max(0, (channel or 1) - 1)

        if ch_idx < len(self._profiles):
            return _safe_str(self._profiles[ch_idx].token)

        # Fallback
        return self._profile_token or ""

    def _get_video_source_token(self, channel: int = 1) -> str:
        """Get the VideoSourceToken for a channel from cached profiles."""
        ch_idx = max(0, channel - 1)

        if ch_idx < len(self._profiles):
            profile = self._profiles[ch_idx]
            vsc = getattr(profile, "VideoSourceConfiguration", None)
            if vsc:
                return _safe_str(getattr(vsc, "SourceToken", ""))

        # Fallback: try first profile
        if self._profiles:
            vsc = getattr(self._profiles[0], "VideoSourceConfiguration", None)
            if vsc:
                return _safe_str(getattr(vsc, "SourceToken", ""))

        return ""

    # =========================================================================
    # WS-Discovery Integration
    # =========================================================================

    @staticmethod
    async def discover_cameras(timeout: float = 4.0) -> list[dict[str, Any]]:
        """
        Discover ONVIF cameras on the local network via WS-Discovery.

        Returns a list of dicts with ip, vendor, model, xaddrs, etc.
        """
        from app.adapters.onvif.discovery import discover_onvif_devices

        return await discover_onvif_devices(timeout=timeout)
