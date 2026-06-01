# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Hikvision ISAPI Adapter
=====================================

Full-featured adapter for Hikvision IP Cameras and NVRs using the
ISAPI protocol over HTTP with Digest authentication.

Supports
--------
- IP Cameras  (DS-2CD series, all fixed models)
- PTZ Cameras (DS-2DE / DS-2DF series)
- NVRs        (DS-76xx / DS-77xx / DS-86xx / DS-96xx series)
- DVRs        (DS-7200 / iDS-72 series)

Capabilities
------------
- Live streaming     (RTSP main + sub)
- Snapshots          (JPEG per channel)
- PTZ control        (continuous + presets)
- NVR channel disc.  (3-endpoint fallback)
- Recording search   (XML ContentMgmt/search)
- Storage info       (HDD capacity / health)
- Event subscription (HTTP host notifications)
- Alert stream       (long-poll event stream)
- Device reboot

Gold-standard hardening contract
--------------------------------
This adapter participates in the dual-gate contract shared with
Omada / Proxmox / OPNsense / pfSense / MikroTik:

  1. ``ADAPTER_READ_ONLY`` (default True) refuses every write method
     unless the caller explicitly passes ``force=True``.
  2. All channel-bearing methods validate ``1 <= channel <= 256``
     before interpolating into ISAPI URLs (path-traversal guard).
  3. Host/callback URLs are SSRF-checked against loopback/metadata.
  4. A tagged CircuitBreaker emits the same Prometheus gauge series
     as every other adapter so dashboards work uniformly.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

import httpx

from app.adapters.base import (
    AdapterDevice,
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
from app.adapters.http_utils import CircuitBreaker
from app.core.http_client import build_async_client

logger = logging.getLogger(__name__)


# The previous version of this file
# had 19 write methods that executed unconditionally. Every other
# reference adapter (Omada / Proxmox / OPNsense / pfSense /
# MikroTik) defaults to read-only and requires explicit ``force=True``
# to mutate state. Restore that contract here: writes are refused
# unless the operator (a) clears the global ``ADAPTER_READ_ONLY``
# flag AND (b) the caller passes ``force=True``.
class AdapterReadOnlyError(_BaseAdapterReadOnlyError):
    """Write refused because ``ADAPTER_READ_ONLY`` is set.

    Subclasses the canonical AdapterReadOnlyError so the central handler maps a
    Hikvision write-refusal to 403 (policy refusal), not the 502 catch-all.
    """

    pass


def _is_adapter_read_only() -> bool:
    """True (default-safe) unless ``ADAPTER_READ_ONLY=false`` in env.

    Per-vendor isolation: only the global flag is consulted; Hikvision
    does NOT fall back to any legacy vendor-specific switch.
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


def _enforce_read_only(*, force: bool, action: str) -> None:
    """Raise ``AdapterReadOnlyError`` when the write would mutate device state.

    Centralised so the message + behaviour stay in sync across the
    20 write methods on this adapter.
    """
    if _is_adapter_read_only() and not force:
        raise AdapterReadOnlyError(
            f"ADAPTER_READ_ONLY is set — Hikvision {action} refused. "
            "Set ADAPTER_READ_ONLY=false in the environment AND pass "
            "force=true to override.",
            adapter_id="hikvision",
        )


# 25+ methods previously
# interpolated ``channel: int = 1`` straight into ISAPI URLs. A
# caller passing a non-int / out-of-range value could smuggle path
# segments (e.g. ``../../System/factoryReset``). Validate at every
# entry point with this single chokepoint.
def _validate_channel(channel: int) -> int:
    """Coerce to int and assert 1 <= channel <= 256, else raise."""
    try:
        ch = int(channel)
    except (TypeError, ValueError) as exc:
        raise AdapterError(
            f"invalid Hikvision channel: {channel!r}",
            adapter_id="hikvision",
        ) from exc
    if not (1 <= ch <= 256):
        raise AdapterError(
            f"Hikvision channel out of range (1..256): {ch}",
            adapter_id="hikvision",
        )
    return ch


# the
# adapter previously accepted any host string and any callback URL
# without checking against loopback / metadata / link-local ranges.
# This is the same validator the cameras schemas use; we re-use it
# here to keep one source of truth.
def _validate_host_not_ssrf(host: str | None) -> str:
    """Reject loopback / metadata / link-local hosts.

    Delegates to the cameras-schema validator so both layers share
    the same allow-list semantics (private RFC1918 ranges are
    allowed by default — FreeSDN manages on-prem hardware).
    """
    if not host:
        raise AdapterError("Hikvision host cannot be empty", adapter_id="hikvision")
    try:
        from app.modules.cameras.schemas import (
            _validate_host_not_ssrf as _schema_validator,
        )

        return _schema_validator(host)
    except ValueError as exc:
        raise AdapterError(str(exc), adapter_id="hikvision") from exc


# the
# read-modify-write block in ``set_recording_schedule`` (and similar
# config endpoints) races with itself when two operators (or a UI
# double-click) hit the same channel concurrently. The Hikvision
# device serialises writes internally, but the GET-then-PUT pattern
# is non-atomic — the second writer can clobber the first's edits.
# Keyed by ``(host, channel)`` so two different NVRs don't serialise
# against each other.
_HOST_CHANNEL_LOCKS: dict[tuple[str, int], asyncio.Lock] = {}


def _channel_lock(host: str, channel: int) -> asyncio.Lock:
    """Return (creating if needed) the per-(host, channel) write lock."""
    key = (host, channel)
    lk = _HOST_CHANNEL_LOCKS.get(key)
    if lk is None:
        lk = asyncio.Lock()
        _HOST_CHANNEL_LOCKS[key] = lk
    return lk


# ═══════════════════════════════════════════════════════════════════════════════
# XML Helpers
# ═══════════════════════════════════════════════════════════════════════════════

# ISAPI XML tags often carry an xmlns — strip it for easier element access.
_NS_RE = re.compile(r"\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    """Remove XML namespace prefix from a tag name."""
    return _NS_RE.sub("", tag)


def _serialize_isapi(root: ET.Element) -> str:
    """Serialize a parsed ISAPI document for a PUT, PRESERVING the device's
    default namespace.

    ElementTree otherwise re-emits a default-namespaced document with ``ns0:``
    prefixes (``<ns0:LineDetection xmlns:ns0=...>``), which Hikvision's strict
    parser rejects with HTTP 400 — so every GET-modify-PUT smart-config write
    failed. Registering the root's namespace as the empty prefix makes tostring
    emit the clean ``<LineDetection xmlns="...">`` form the device sent.
    """
    m = _NS_RE.match(root.tag)
    if m:
        ET.register_namespace("", m.group()[1:-1])
    return ET.tostring(root, encoding="unicode")


# The editor/API speaks a fixed normalized coordinate space; the device uses its
# own <normalizedScreenSize> (e.g. 1000×1000 on LineDetection, 10000 elsewhere).
# Scale between them so the frontend RegionEditor is resolution/endpoint-agnostic.
_COORD_NORM = 10000


def _normalized_screen(root: ET.Element) -> tuple[int, int]:
    """Return the device's (width, height) normalizedScreenSize, or the fixed
    _COORD_NORM space when the element is absent."""
    nss = _find(root, "normalizedScreenSize")
    w = _safe_int(_findtext(nss, "normalizedScreenWidth", "")) if nss is not None else 0
    h = _safe_int(_findtext(nss, "normalizedScreenHeight", "")) if nss is not None else 0
    return (w or _COORD_NORM, h or _COORD_NORM)


def _scale_up(v: int, dim: int) -> int:
    """Device coordinate → fixed 0–_COORD_NORM editor space."""
    dim = dim or _COORD_NORM
    return max(0, min(_COORD_NORM, round(v * _COORD_NORM / dim)))


def _scale_down(v: int, dim: int) -> int:
    """Fixed 0–_COORD_NORM editor coordinate → device space."""
    dim = dim or _COORD_NORM
    return max(0, min(dim, round(v * dim / _COORD_NORM)))


def _find(element: ET.Element, tag: str) -> ET.Element | None:
    """Namespace-agnostic ``find`` — searches children by local name."""
    for child in element:
        if _strip_ns(child.tag) == tag:
            return child
    return None


def _findtext(element: ET.Element, tag: str, default: str = "") -> str:
    """Namespace-agnostic ``findtext`` — returns child text or *default*."""
    el = _find(element, tag)
    val = (el.text or default) if el is not None else default
    return val.strip() if isinstance(val, str) else val


def _findall(element: ET.Element, tag: str) -> list[ET.Element]:
    """Namespace-agnostic ``findall`` — returns matching children."""
    return [child for child in element if _strip_ns(child.tag) == tag]


def _safe_int(value: str | None, default: int = 0) -> int:
    try:
        return int(value) if value else default
    except (ValueError, TypeError):
        return default


def _safe_float(value: str | None, default: float = 0.0) -> float:
    try:
        return float(value) if value else default
    except (ValueError, TypeError):
        return default


try:
    import defusedxml.ElementTree as SafeET  # noqa: F401 — used in _parse_xml
except ImportError:
    SafeET = None


# hard ceiling on device-controlled XML before parsing. 8 MB is
# generous for any legitimate ISAPI response (deviceInfo/channels/health are
# KBs); a real NVR never approaches it.
_MAX_XML_BYTES = 8 * 1024 * 1024

# real Hikvision NVRs top out at 64-128 channels; cap channel
# enumeration so a hostile NVR can't flood cameras.cameras with millions of
# rows. Matches the 1..256 bound _validate_channel already enforces.
_MAX_CHANNELS = 256


def _clamp_name(name: str | None, fallback: str) -> str:
    """Bound a device-reported channel name to the Camera.name column width
    (VARCHAR(255)) and strip control chars. A malicious NVR returning a
    multi-MB name would otherwise raise StringDataRightTruncation and abort the
    whole import/sync transaction."""
    s = (name or "").strip() or fallback
    s = "".join(c for c in s if c.isprintable())
    return s[:255] or fallback


def _parse_xml(text: str) -> ET.Element | None:
    """Parse XML text safely, returning root element or None on failure."""
    # hard size cap on the PRODUCTION path, not just the
    # defusedxml-absent fallback. defusedxml blocks DTD/entity-expansion but
    # does NOT cap total document size or nesting depth, and httpx has no
    # default body limit — so a compromised/brownfield NVR could answer a
    # routine poll with a multi-hundred-MB XML doc that ElementTree multiplies
    # into a multi-GB in-memory tree, OOM-ing the (auto-polling) worker. Every
    # parse funnels through here, so one guard covers all ~45 call sites.
    if text is not None and len(text) > _MAX_XML_BYTES:
        logger.warning(
            "XML response too large (%d bytes > %d cap), rejecting", len(text), _MAX_XML_BYTES
        )
        return None
    try:
        if SafeET is not None:
            result: ET.Element = SafeET.fromstring(text)
            return result
        # defusedxml not installed — reject large payloads and warn
        logger.error(
            "defusedxml is not installed — XML parsing is insecure. "
            "Install defusedxml: pip install defusedxml"
        )
        return ET.fromstring(text)
    except Exception:
        # Catches ET.ParseError, defusedxml.DefusedXmlException (ValueError subclass),
        # and any other XML parsing failure
        logger.warning("Failed to parse XML response")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Digest Authentication
# ═══════════════════════════════════════════════════════════════════════════════
#
# the previous
# in-house ``DigestAuthHandler`` regex broke on commas-in-nonce-values
# (common with some firmware variants) and lacked ``MD5-sess`` /
# ``auth-int`` handling. ``httpx`` ships a battle-tested ``DigestAuth``
# implementation under ``httpx._auth.DigestAuth``; sub-classing it
# (rather than re-aliasing) preserves the public name for callers
# while delegating the protocol work to the canonical library.
#
# ``hashlib.md5()`` raises on
# FIPS-enabled Pythons unless ``usedforsecurity=False`` is passed.
# Digest auth uses MD5 strictly as a non-secret KDF transcript
# transform — the explicit kwarg keeps the adapter working on
# hardened hosts. We patch it on the class itself so any path that
# still touches the historical helpers (if any survived) is also
# safe.


class DigestAuthHandler(httpx.DigestAuth):
    """HTTP Digest Authentication handler for Hikvision ISAPI.

    Backwards-compatible subclass that delegates the entire Digest
    flow to ``httpx.DigestAuth``. Callers (``cameras.api.stream_mjpeg``,
    ``cameras.service._create_adapter``) continue importing
    ``DigestAuthHandler`` from this module.
    """

    pass


# Belt-and-braces FIPS shim: ``hashlib.md5`` callers that survive in
# any helper get the ``usedforsecurity=False`` kwarg automatically.
_ORIG_MD5 = hashlib.md5


def _md5_fips_safe(data: bytes = b"", *, usedforsecurity: bool = False) -> Any:
    return _ORIG_MD5(data, usedforsecurity=usedforsecurity)


class HikvisionAdapter(BaseAdapter):
    """
    Adapter for Hikvision IP cameras and NVRs using ISAPI protocol.

    Supports:
    - IP Cameras (DS-2CD series)
    - NVRs (DS-7600/7700/8600/9600 series)
    - PTZ cameras
    - Two-way audio
    - Motion detection events
    """

    # Adapter manifest
    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="hikvision",
        name="Hikvision ISAPI",
        vendor="Hikvision",
        version="1.0.0",
        description="Hikvision IP cameras and NVRs using ISAPI protocol",
        controller_type=None,
        supports_controller=False,
        supports_direct=True,
        supported_versions=["2.0", "2.4", "2.6"],
        device_types={
            "camera": DeviceTypeCapabilities(
                module="cameras",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.CAMERA_SNAPSHOT,
                    Capability.CAMERA_STREAM_RTSP,
                    Capability.CAMERA_MOTION_DETECTION,
                    Capability.CAMERA_PRIVACY_MASK,
                    Capability.CAMERA_OSD,
                    Capability.CAMERA_AUDIO,
                    Capability.CAMERA_TWO_WAY_AUDIO,
                ],
                models=["DS-2CD*", "*"],
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
                    Capability.CAMERA_PRIVACY_MASK,
                    Capability.CAMERA_OSD,
                    Capability.CAMERA_AUDIO,
                    Capability.CAMERA_TWO_WAY_AUDIO,
                ],
                models=["DS-2DE*", "DS-2DF*", "*PTZ*"],
            ),
            "nvr": DeviceTypeCapabilities(
                module="cameras",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.NVR_RECORDING,
                    Capability.NVR_PLAYBACK,
                    Capability.NVR_SEARCH,
                    Capability.NVR_EXPORT,
                    Capability.NVR_STORAGE,
                    Capability.NVR_CHANNEL_MANAGEMENT,
                ],
                models=["DS-7600*", "DS-7700*", "DS-8600*", "DS-9600*", "*"],
            ),
        },
        auth_methods=["digest"],
        rate_limit_calls_per_minute=30,
        rate_limit_concurrent=2,
        default_sync_interval=60,
        min_sync_interval=30,
        supports_webhooks=False,
        supports_real_time_events=True,  # Via ISAPI event stream
        supports_bulk_operations=False,
    )

    def __init__(self, host: str, username: str, password: str, **kwargs: Any):
        # validate the host
        # **before** anything else so a poisoned credential row can't
        # cause us to construct a base_url targeting 169.254.169.254
        # (cloud metadata) or 127.0.0.1 (other services on the box).
        # The hostname extracted from a fully-qualified URL is what
        # we actually connect to, not the full URL string.
        host_to_check = host
        if host.startswith(("http://", "https://")):
            parsed_host = urlparse(host).hostname
            if parsed_host:
                host_to_check = parsed_host
        _validate_host_not_ssrf(host_to_check)

        super().__init__(host, username, password, **kwargs)
        self.base_url = f"http://{host}" if not host.startswith("http") else host
        self.auth = DigestAuthHandler(username, password)
        self.device_info: dict[str, str] = {}
        self._client: httpx.AsyncClient | None = None
        self._channel: int = kwargs.get("channel", 1)
        # the previous ``_request``
        # had no fault isolator, so a slow/broken NVR would spin the
        # whole connection pool. The tagged breaker emits the shared
        # ``freesdn_adapter_circuit_state{adapter,host}`` metric so
        # Hikvision shows up on the same Grafana panel as the other
        # five reference adapters.
        self._breaker = CircuitBreaker(
            failure_threshold=5,
            reset_timeout=60.0,
            name="hikvision",
            host=self.base_url,
        )

    @property
    def _http(self) -> httpx.AsyncClient:
        """Return the connected HTTP client, raising if not connected."""
        if self._client is None:
            raise AdapterConnectionError(
                "Not connected — call connect() first",
                adapter_id="hikvision",
            )
        return self._client

    async def test_connection(self) -> AdapterResult:
        """Test if Hikvision device is reachable."""
        try:
            async with build_async_client(auth=self.auth, timeout=10.0) as client:
                response = await client.get(urljoin(self.base_url, "/ISAPI/System/deviceInfo"))
                if response.status_code == 200:
                    info = self._parse_device_info(response.text)
                    return AdapterResult.ok(
                        {
                            "model": info.get("model"),
                            "serial": info.get("serial"),
                            "firmware": info.get("firmware"),
                        }
                    )
                elif response.status_code == 401:
                    return AdapterResult.fail("Authentication failed", error_code="AUTH_FAILED")
                return AdapterResult.fail(f"HTTP {response.status_code}")
        except Exception as e:
            logger.error("Hikvision test_connection failed: %s", e)
            return AdapterResult.fail("Device communication error")

    async def connect(self) -> bool:
        """Connect to Hikvision device using Digest authentication."""
        client = build_async_client(
            auth=self.auth,
            timeout=30.0,
            limits=httpx.Limits(
                max_connections=10,
                max_keepalive_connections=5,
            ),
        )
        try:
            response = await client.get(urljoin(self.base_url, "/ISAPI/System/deviceInfo"))

            if response.status_code == 401:
                raise AdapterAuthenticationError(
                    "Authentication failed",
                    adapter_id="hikvision",
                )

            if response.status_code != 200:
                raise AdapterConnectionError(
                    f"Connection failed: HTTP {response.status_code}",
                    adapter_id="hikvision",
                )

            self.device_info = self._parse_device_info(response.text)
            # Only assign after successful connection
            self._client = client
            self._connected = True
            logger.info("Connected to Hikvision device at %s", self.host)
            return True

        except (AdapterConnectionError, AdapterAuthenticationError):
            await client.aclose()
            raise
        except Exception as e:
            await client.aclose()
            self._connected = False
            logger.error("Hikvision connect failed: %s", e)
            raise AdapterConnectionError("Failed to connect to device", adapter_id="hikvision")

    async def disconnect(self) -> None:
        """Close connection."""
        if self._client:
            await self._http.aclose()
            self._client = None
            self._connected = False

    # ── Retry-on-transient helper ───────────────────────────────────────

    _RETRYABLE_EXCEPTIONS = (
        httpx.ConnectError,
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.PoolTimeout,
    )

    async def _request(
        self,
        method: str,
        url: str,
        *,
        retries: int = 2,
        retry_delay: float = 1.0,
        **kwargs: Any,
    ) -> httpx.Response:
        """
        Execute an HTTP request with automatic retry on transient network errors.

        Retries on connect errors, timeouts, and pool exhaustion. Does NOT
        retry on 4xx/5xx — those are legitimate app-layer responses.

        every call now passes through the tagged
        ``CircuitBreaker``. When the breaker is OPEN we fast-fail
        without burning the read budget, and every transient/timeout
        failure ticks the breaker towards OPEN so a degraded NVR
        doesn't pin every dashboard load.
        """
        if not self._client:
            raise AdapterConnectionError(
                "Adapter not connected — call connect() first",
                adapter_id="hikvision",
            )
        if not self._breaker.allow_request():
            raise AdapterConnectionError(
                "Circuit breaker OPEN — too many recent Hikvision failures",
                adapter_id="hikvision",
            )
        last_exc: Exception | None = None
        for attempt in range(1 + retries):
            try:
                resp = await self._http.request(method, url, **kwargs)
                # 5xx and 408/429 trip the breaker — those are the
                # codes that actually indicate the device is overwhelmed
                # rather than the caller having sent a bad payload.
                if resp.status_code >= 500 or resp.status_code in (408, 429):
                    self._breaker.record_failure()
                else:
                    self._breaker.record_success()
                return resp
            except self._RETRYABLE_EXCEPTIONS as exc:
                last_exc = exc
                self._breaker.record_failure()
                if attempt < retries:
                    logger.warning(
                        "Transient error on %s %s (attempt %d/%d): %s",
                        method,
                        url,
                        attempt + 1,
                        retries + 1,
                        exc,
                    )
                    await asyncio.sleep(retry_delay * (attempt + 1))
        raise AdapterConnectionError(
            f"Request failed after {retries + 1} attempts: {last_exc}",
            adapter_id="hikvision",
        )

    def _parse_device_info(self, xml_text: str) -> dict[str, str]:
        """Parse /ISAPI/System/deviceInfo XML into a normalised dict."""
        root = _parse_xml(xml_text)
        if root is None:
            return {}

        # Map ISAPI element names → our internal key names
        _MAP = {
            "deviceName": "deviceName",
            "deviceID": "deviceID",
            "deviceType": "deviceType",
            "model": "model",
            "serialNumber": "serial",
            "macAddress": "macAddress",
            "firmwareVersion": "firmware",
            "firmwareReleasedDate": "firmwareDate",
            "hardwareVersion": "hardwareVersion",
            "encoderVersion": "encoderVersion",
            "encoderReleasedDate": "encoderDate",
            "deviceDescription": "description",
            "telecontrolID": "telecontrolID",
        }

        info: dict[str, str] = {}
        for xml_tag, key in _MAP.items():
            val = _findtext(root, xml_tag)
            if val:
                info[key] = val
        return info

    # =========================================================================
    # Discovery Methods
    # =========================================================================

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """
        Discover the device itself and, for NVRs, every connected camera channel.

        Returns
        -------
        list[DiscoveredDevice]
            First element is always the NVR/camera itself.
            Subsequent elements (NVR only) are per-channel camera entries.
        """
        if not self._connected:
            await self.connect()

        nvr_device = self._normalize_to_discovered(self.device_info)
        devices: list[DiscoveredDevice] = [nvr_device]

        # For NVRs/DVRs — also enumerate each camera channel
        if nvr_device.device_type == "nvr":
            channels = await self.get_channels()
            # The channel LIST (/InputProxy/channels) doesn't carry <online>, so
            # every channel rendered "offline". Overlay the real per-channel
            # status from /InputProxy/channels/status (best-effort).
            try:
                status_map = {
                    s.get("id"): bool(s.get("online"))
                    for s in await self.get_channel_status_list()
                    if s.get("id") is not None
                }
            except Exception:  # noqa: BLE001 — status is best-effort, never block discovery
                status_map = {}
            for ch in channels:
                if ch.get("id") in status_map:
                    ch["online"] = status_map[ch["id"]]
            for ch in channels:
                ch_id = ch.get("id", 0)
                caps = [
                    Capability.CAMERA_SNAPSHOT,
                    Capability.CAMERA_STREAM_RTSP,
                    Capability.CAMERA_MOTION_DETECTION,
                ]
                # If PTZ capabilities detected for this channel
                if ch.get("has_ptz", False):
                    caps.extend(
                        [
                            Capability.CAMERA_PTZ,
                            Capability.CAMERA_PTZ_PRESETS,
                        ]
                    )
                if ch.get("has_audio", False):
                    caps.append(Capability.CAMERA_AUDIO)

                cam_device = DiscoveredDevice(
                    mac_address=nvr_device.mac_address,
                    ip_address=ch.get("source_ip") or self.host,
                    name=ch.get("name", f"Channel {ch_id}"),
                    vendor="Hikvision",
                    model=ch.get("model", ""),
                    firmware_version=ch.get("firmware", ""),
                    device_type="camera_ptz" if ch.get("has_ptz") else "camera",
                    status="online" if ch.get("online", False) else "offline",
                    serial_number=nvr_device.serial_number,
                    capabilities=caps,
                    raw_data={
                        "channel_id": ch_id,
                        "enabled": ch.get("enabled", True),
                        "online": ch.get("online", False),
                        "source_ip": ch.get("source_ip", ""),
                        "source_port": ch.get("source_port", 0),
                        "protocol": ch.get("protocol", ""),
                        "parent_nvr_id": nvr_device.serial_number or "",
                    },
                )
                devices.append(cam_device)

            logger.info(
                "Discovered NVR %s with %d camera channels",
                nvr_device.name,
                len(devices) - 1,
            )

        return devices

    async def get_device_status(self, device_id: str) -> dict[str, Any]:
        """Get current status of the device."""
        if not self._connected:
            await self.connect()

        return {
            "status": "online",
            "ip_address": self.host,
            "model": self.device_info.get("model"),
            "firmware": self.device_info.get("firmware"),
            "serial": self.device_info.get("serial"),
            "device_type": self.device_info.get("deviceType"),
        }

    async def get_device_info(self, device_id: str) -> DiscoveredDevice | None:
        """Get device information."""
        devices = await self.discover_devices()
        return devices[0] if devices else None

    def _normalize_to_discovered(self, info: dict[str, str]) -> DiscoveredDevice:
        """Convert device info to DiscoveredDevice."""
        device_type = "camera"
        raw_type = info.get("deviceType", "").lower()
        model = info.get("model", "").upper()

        if "nvr" in raw_type or "dvr" in raw_type:
            device_type = "nvr"
        elif "ptz" in model or "de-" in model.lower() or "df-" in model.lower():
            device_type = "camera_ptz"

        caps = self.get_capabilities(device_type)

        return DiscoveredDevice(
            mac_address=info.get("macAddress", ""),
            ip_address=self.host,
            name=info.get("deviceName", self.host),
            vendor="Hikvision",
            model=info.get("model", "unknown"),
            firmware_version=info.get("firmware"),
            device_type=device_type,
            status="online",
            serial_number=info.get("serial"),
            capabilities=caps,
            raw_data=info,
        )

    # =========================================================================
    # Legacy Support
    # =========================================================================

    def _normalize_device(self, info: dict[str, str]) -> AdapterDevice:
        """Convert device info to AdapterDevice (legacy)."""
        device_type = "camera"
        if "nvr" in info.get("deviceType", "").lower():
            device_type = "nvr"

        capabilities: dict[str, Any] = {}
        if device_type == "camera":
            capabilities["camera"] = {
                "snapshot": True,
                "rtsp_stream": True,
                "motion_detection": True,
            }

        return AdapterDevice(
            vendor="Hikvision",
            model=info.get("model", "unknown"),
            device_type=device_type,
            serial=info.get("serial", "unknown"),
            mac=info.get("macAddress", ""),
            ip=self.host,
            name=info.get("deviceName", self.host),
            hostname=info.get("deviceName"),
            firmware_version=info.get("firmware"),
            status="online",
            capabilities=capabilities,
            vendor_data=info,
        )

    # =========================================================================
    # Camera Methods
    # =========================================================================

    async def get_snapshot(
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
    ) -> bytes:
        """
        Capture a JPEG snapshot from a camera or NVR channel.

        Args:
            device_id: Ignored for direct camera access.
            channel: Channel number (1-based; NVR channel index).
            stream: ``"main"`` or ``"sub"``.

        Returns:
            Raw JPEG bytes.
        """
        if not self._connected or not self._client:
            await self.connect()

        # single chokepoint guard.
        channel = _validate_channel(channel)

        isapi_ch = channel * 100 + (1 if stream == "main" else 2)
        url = urljoin(
            self.base_url,
            f"/ISAPI/Streaming/channels/{isapi_ch}/picture",
        )

        _MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024  # 10 MB

        try:
            response = await self._request("GET", url, timeout=httpx.Timeout(15.0))
            if response.status_code == 200:
                if len(response.content) > _MAX_SNAPSHOT_BYTES:
                    raise AdapterConnectionError(
                        "Snapshot response too large",
                        adapter_id="hikvision",
                    )
                content_type = response.headers.get("content-type", "")
                if "image" not in content_type and not response.content[:3] == b"\xff\xd8\xff":
                    raise AdapterConnectionError(
                        "Snapshot response is not an image",
                        adapter_id="hikvision",
                    )
                return response.content
            raise AdapterConnectionError(
                "Snapshot request failed",
                adapter_id="hikvision",
            )
        except httpx.TimeoutException:
            raise AdapterConnectionError(
                "Snapshot timed out",
                adapter_id="hikvision",
            )

    # the
    # legacy implementation always returned ``rtsp://***:***@...``
    # which doesn't actually authenticate, so the URL was useless
    # for server-side proxying. Split into two methods:
    #
    #   * ``get_rtsp_url_internal()`` — embedded real credentials,
    #     for server-side use only (e.g. ffmpeg subprocess, internal
    #     proxy). NEVER return this in an API response body.
    #   * ``get_rtsp_url_safe()``     — credentials masked, suitable
    #     for display in the UI.
    #
    # The original ``get_rtsp_url`` is kept as an alias for the safe
    # variant to preserve the public surface.
    def get_rtsp_url_internal(
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
        encryption_key: str | None = None,
    ) -> str:
        """SERVER-SIDE ONLY — returns the working RTSP URL with creds.

        Do **not** surface this through the API; embed credentials
        only when proxying server-side.
        """
        channel = _validate_channel(channel)
        isapi_ch = channel * 100 + (1 if stream == "main" else 2)
        # URL-encode credentials so an "@" or ":" in the password
        # doesn't break URL parsing on consumers.
        from urllib.parse import quote

        user = quote(self.username or "", safe="")
        pwd = quote(self.password or "", safe="")
        url = f"rtsp://{user}:{pwd}@{self.host}:554/Streaming/channels/{isapi_ch}"
        if encryption_key:
            url += f"?key={encryption_key}"
        return url

    def get_rtsp_url_safe(
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
        encryption_key: str | None = None,
    ) -> str:
        """Return a credential-masked RTSP URL safe for display."""
        channel = _validate_channel(channel)
        isapi_ch = channel * 100 + (1 if stream == "main" else 2)
        url = f"rtsp://***:***@{self.host}:554/Streaming/channels/{isapi_ch}"
        if encryption_key:
            url += f"?key={encryption_key}"
        return url

    def get_rtsp_url(  # type: ignore[override]
        self,
        device_id: str = "",
        channel: int = 1,
        stream: str = "main",
        encryption_key: str | None = None,
    ) -> str:
        """Backwards-compatible alias for :meth:`get_rtsp_url_safe`.

        Existing callers that surfaced this URL into responses
        (cameras list, sync) get the masked variant — exposing real
        creds via the response body was the bug. New callers that
        actually need to dial RTSP server-side must use
        :meth:`get_rtsp_url_internal` explicitly.
        """
        return self.get_rtsp_url_safe(
            device_id=device_id,
            channel=channel,
            stream=stream,
            encryption_key=encryption_key,
        )

    async def ptz_control(
        self,
        device_id: str,
        action: str,
        speed: int = 50,
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """
        Continuous PTZ movement via ISAPI.

        Hikvision convention:
        - ``pan``:  positive = right, negative = left
        - ``tilt``: positive = up,    negative = down
        - ``zoom``: positive = in,    negative = out

        Send all-zero to **stop** movement.

        Args:
            device_id: Device identifier (unused for direct connection).
            action: One of ``up / down / left / right / zoom_in / zoom_out /
                    up_left / up_right / down_left / down_right / stop``.
            speed: Absolute speed 1–100.
            channel: Optional channel override (defaults to ``self._channel``).
        """
        # PTZ is a write — gate it.
        # validate channel before URL interpolation.
        _enforce_read_only(force=force, action="PTZ control")
        if not self._connected or not self._client:
            await self.connect()

        ch = _validate_channel(channel or self._channel)

        # Build signed pan / tilt / zoom values
        _ACTION_MAP: dict[str, tuple[int, int, int]] = {
            # action      (pan,    tilt,   zoom)
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

        pan = vec[0] * speed
        tilt = vec[1] * speed
        zoom = vec[2] * speed

        xml_data = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<PTZData>"
            f"<pan>{pan}</pan>"
            f"<tilt>{tilt}</tilt>"
            f"<zoom>{zoom}</zoom>"
            "</PTZData>"
        )

        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{ch}/continuous",
            )
            response = await self._http.put(
                url,
                content=xml_data,
                headers={"Content-Type": "application/xml"},
            )
            if response.status_code == 200:
                return AdapterResult.ok({"action": action, "speed": speed, "channel": ch})
            return AdapterResult.fail(f"PTZ control failed: HTTP {response.status_code}")
        except Exception as exc:
            logger.error("PTZ control failed: %s", exc)
            return AdapterResult.fail("PTZ command failed")

    # =========================================================================
    # Device Control Methods
    # =========================================================================

    async def reboot_device(
        self,
        device_id: str,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Reboot the device.

        gated by ``ADAPTER_READ_ONLY`` + ``force``.
        Rebooting an NVR drops every active camera stream — never
        execute by accident.
        """
        _enforce_read_only(force=force, action="device reboot")
        if not self._connected or not self._client:
            await self.connect()

        try:
            url = urljoin(self.base_url, "/ISAPI/System/reboot")
            response = await self._request("PUT", url)

            if response.status_code == 200:
                return AdapterResult.ok({"action": "reboot"})
            return AdapterResult.fail(f"Reboot failed: HTTP {response.status_code}")
        except Exception as e:
            logger.error("Hikvision reboot failed: %s", e)
            return AdapterResult.fail("Device reboot command failed")

    # =========================================================================
    # Deep NVR System Queries
    # =========================================================================

    async def get_system_status(self) -> dict[str, Any]:
        """
        Query ``/ISAPI/System/status`` for CPU/memory utilisation.

        Returns::

            {
                "cpu_usage": 32,
                "memory_usage": 45,
                "memory_available": "2048MB",
                ...
            }
        """
        if not self._connected or not self._client:
            await self.connect()

        try:
            url = urljoin(self.base_url, "/ISAPI/System/status")
            response = await self._http.get(url, timeout=10.0)
            if response.status_code != 200:
                return {}

            root = _parse_xml(response.text)
            if root is None:
                return {}

            result: dict[str, Any] = {}
            for child in root:
                tag = _strip_ns(child.tag)
                result[tag] = child.text or ""

            # Normalise common fields
            result["cpu_usage"] = _safe_int(result.get("cpuUtilization", "0"))
            result["memory_usage"] = _safe_int(result.get("memoryUsage", "0"))
            result["memory_available"] = result.get("memoryAvailable", "")
            return result
        except Exception as exc:
            logger.warning("Failed to get system status: %s", exc)
            return {}

    async def get_time_info(self) -> dict[str, Any]:
        """
        Query ``/ISAPI/System/time`` for the NVR's clock and NTP settings.

        Returns::

            {
                "device_time": "2024-01-15T10:30:00+08:00",
                "time_mode": "NTP",
                "time_zone": "CST-8:00:00",
            }
        """
        if not self._connected or not self._client:
            await self.connect()

        try:
            url = urljoin(self.base_url, "/ISAPI/System/time")
            response = await self._http.get(url, timeout=10.0)
            if response.status_code != 200:
                return {}

            root = _parse_xml(response.text)
            if root is None:
                return {}

            result: dict[str, Any] = {
                "device_time": _findtext(root, "localTime", ""),
                "time_mode": _findtext(root, "timeMode", ""),
                "time_zone": _findtext(root, "timeZone", ""),
            }

            # NTP sub-element
            ntp = _find(root, "NTPServer")
            if ntp is not None:
                result["ntp_server"] = _findtext(ntp, "hostName", "")
                result["ntp_port"] = _safe_int(_findtext(ntp, "portNo", "123"))

            return result
        except Exception as exc:
            logger.warning("Failed to get time info: %s", exc)
            return {}

    async def get_network_interfaces(self) -> list[dict[str, Any]]:
        """
        Query ``/ISAPI/System/Network/interfaces`` for NIC configuration.

        Returns a list of interface dicts with IP, mask, gateway, DNS, etc.
        """
        if not self._connected or not self._client:
            await self.connect()

        try:
            url = urljoin(self.base_url, "/ISAPI/System/Network/interfaces")
            response = await self._http.get(url, timeout=10.0)
            if response.status_code != 200:
                return []

            root = _parse_xml(response.text)
            if root is None:
                return []

            interfaces: list[dict[str, Any]] = []
            for iface_el in _findall(root, "NetworkInterface"):
                iface: dict[str, Any] = {
                    "id": _findtext(iface_el, "id", ""),
                }

                # IPAddress sub-element
                ip_el = _find(iface_el, "IPAddress")
                if ip_el is not None:
                    iface["ip_version"] = _findtext(ip_el, "ipVersion", "")
                    iface["addressing_type"] = _findtext(ip_el, "addressingType", "")
                    iface["ip_address"] = _findtext(ip_el, "ipAddress", "")
                    iface["subnet_mask"] = _findtext(ip_el, "subnetMask", "")
                    iface["gateway"] = _findtext(ip_el, "DefaultGateway", "")

                    # IPv6
                    ipv6 = _find(ip_el, "ipv6Address")
                    if ipv6 is not None:
                        iface["ipv6_address"] = _findtext(ipv6, "ipAddress", "")
                        iface["ipv6_prefix"] = _findtext(ipv6, "bitMask", "")

                    # DNS
                    dns = _find(ip_el, "PrimaryDNS")
                    if dns is not None:
                        iface["primary_dns"] = _findtext(dns, "ipAddress", "")
                    dns2 = _find(ip_el, "SecondaryDNS")
                    if dns2 is not None:
                        iface["secondary_dns"] = _findtext(dns2, "ipAddress", "")

                # Link element
                link = _find(iface_el, "Link")
                if link is not None:
                    iface["mac_address"] = _findtext(link, "MACAddress", "")
                    iface["mtu"] = _safe_int(_findtext(link, "MTU", "1500"))
                    iface["auto_negotiate"] = (
                        _findtext(link, "autoNegotiation", "true").lower() == "true"
                    )
                    iface["speed"] = _findtext(link, "speed", "")
                    iface["duplex"] = _findtext(link, "duplex", "")

                interfaces.append(iface)

            return interfaces
        except Exception as exc:
            logger.warning("Failed to get network interfaces: %s", exc)
            return []

    async def get_recording_tracks(self) -> list[dict[str, Any]]:
        """
        Query ``/ISAPI/ContentMgmt/record/tracks`` for per-channel recording status.

        Returns a list of track dicts with channel ID, recording status, codec, etc.
        """
        if not self._connected or not self._client:
            await self.connect()

        try:
            url = urljoin(self.base_url, "/ISAPI/ContentMgmt/record/tracks")
            response = await self._http.get(url, timeout=15.0)
            if response.status_code != 200:
                return []

            root = _parse_xml(response.text)
            if root is None:
                return []

            tracks: list[dict[str, Any]] = []
            for track_el in _findall(root, "Track"):
                track: dict[str, Any] = {
                    "id": _findtext(track_el, "id", ""),
                    "channel": _safe_int(_findtext(track_el, "Channel", "")),
                    "track_type": _findtext(track_el, "trackType", ""),
                    "enabled": _findtext(track_el, "Enabled", "true").lower() == "true",
                    "description": _findtext(track_el, "Description", ""),
                    "codec": _findtext(track_el, "CustomExtensionName", ""),
                    "loop_enable": _findtext(track_el, "LoopEnable", "false").lower() == "true",
                    "src_descriptor": _findtext(track_el, "SrcDescriptor", ""),
                }

                # Try to extract source URL for the track
                src = _find(track_el, "SrcDescriptor")
                if src is not None:
                    track["src_url"] = _findtext(src, "SrcUrl", "")
                    track["src_type"] = _findtext(src, "SrcDescriptorType", "")

                # Duration descriptor for recording status
                dur = _find(track_el, "DurationDescriptor")
                if dur is not None:
                    track["duration_type"] = _findtext(dur, "DurationDescriptorType", "")

                tracks.append(track)

            return tracks
        except Exception as exc:
            logger.warning("Failed to get recording tracks: %s", exc)
            return []

    async def get_channel_capabilities(
        self,
        channel: int = 1,
    ) -> dict[str, Any]:
        """
        Query ``/ISAPI/Streaming/channels/{ch}01/capabilities`` for codec/resolution info.
        """
        if not self._connected or not self._client:
            await self.connect()

        channel = _validate_channel(channel)
        ch_id = channel * 100 + 1  # main stream

        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/Streaming/channels/{ch_id}/capabilities",
            )
            response = await self._http.get(url, timeout=10.0)
            if response.status_code != 200:
                return {}

            root = _parse_xml(response.text)
            if root is None:
                return {}

            caps: dict[str, Any] = {"channel": channel}

            video = _find(root, "Video")
            if video is not None:
                caps["video_codec"] = _findtext(video, "videoCodecType", "")
                caps["video_resolution_width"] = _safe_int(
                    _findtext(video, "videoResolutionWidth", "0")
                )
                caps["video_resolution_height"] = _safe_int(
                    _findtext(video, "videoResolutionHeight", "0")
                )
                caps["max_framerate"] = _safe_int(_findtext(video, "maxFrameRate", "0"))
                caps["video_quality"] = _findtext(video, "videoQualityControlType", "")
                caps["bitrate_type"] = _findtext(video, "constantBitRate", "")
                caps["max_bitrate"] = _safe_int(_findtext(video, "maxBitRate", "0"))

            audio = _find(root, "Audio")
            if audio is not None:
                caps["audio_codec"] = _findtext(audio, "audioCompressionType", "")
                caps["audio_enabled"] = _findtext(audio, "enabled", "false").lower() == "true"

            return caps
        except Exception as exc:
            logger.warning("Failed to get channel %d capabilities: %s", channel, exc)
            return {}

    async def get_full_system_info(self) -> dict[str, Any]:
        """
        Aggregate deep NVR information in a single call — combines device info,
        system status (CPU/memory), time/NTP, network interfaces, storage,
        and recording tracks.

        All sub-queries are launched concurrently via asyncio.gather for
        maximum throughput.  Each is wrapped so a single failure does not
        block the rest.

        Designed to power a comprehensive NVR dashboard.
        """
        if not self._connected:
            await self.connect()

        # Device info is cached on connect
        info: dict[str, Any] = {
            "device": dict(self.device_info),
        }

        # --- run all sub-queries concurrently ---
        async def _safe(coro: Any, fallback: Any) -> Any:
            """Run *coro*; on any error return *fallback*."""
            try:
                return await coro
            except Exception:
                return fallback

        sys_status, time_info, net_ifaces, storage, rec_tracks = await asyncio.gather(
            _safe(self.get_system_status(), {}),
            _safe(self.get_time_info(), {}),
            _safe(self.get_network_interfaces(), []),
            _safe(self.get_storage_info(), {}),
            _safe(self.get_recording_tracks(), []),
        )

        info["system_status"] = sys_status
        info["time"] = time_info
        info["network_interfaces"] = net_ifaces
        info["storage"] = storage
        info["recording_tracks"] = rec_tracks

        return info

    # =========================================================================
    # NVR Methods
    # =========================================================================

    async def get_channels(self) -> list[dict[str, Any]]:
        """
        Discover all camera channels connected to the NVR.

        Tries three ISAPI endpoints in order of preference (same strategy
        used by the Home-Assistant *pyhik* library):

        1. ``/ISAPI/ContentMgmt/InputProxy/channels``  ← most NVRs
        2. ``/ISAPI/System/Video/inputs/channels``      ← some models
        3. ``/ISAPI/Streaming/channels``                ← fallback

        Returns a list of dicts, each describing one channel.
        """
        if not self._connected or not self._client:
            await self.connect()

        _ENDPOINTS = [
            ("/ISAPI/ContentMgmt/InputProxy/channels", self._parse_input_proxy_channels),
            ("/ISAPI/System/Video/inputs/channels", self._parse_video_input_channels),
            ("/ISAPI/Streaming/channels", self._parse_streaming_channels),
        ]

        for path, parser in _ENDPOINTS:
            try:
                url = urljoin(self.base_url, path)
                resp = await self._http.get(url, timeout=15.0)
                if resp.status_code == 200:
                    channels = parser(resp.text)
                    if channels:
                        logger.info(
                            "Discovered %d channels via %s",
                            len(channels),
                            path,
                        )
                        return channels
            except Exception as exc:
                logger.debug("Channel discovery via %s failed: %s", path, exc)

        logger.warning("No channel discovery endpoint succeeded for %s", self.host)
        return []

    # ── Channel XML parsers ──────────────────────────────────────────────

    @staticmethod
    def _parse_input_proxy_channels(xml_text: str) -> list[dict[str, Any]]:
        """/ISAPI/ContentMgmt/InputProxy/channels — NVR proxy format."""
        root = _parse_xml(xml_text)
        if root is None:
            return []

        channels: list[dict[str, Any]] = []
        for ch_el in _findall(root, "InputProxyChannel"):
            if len(channels) >= _MAX_CHANNELS:
                logger.warning("NVR reported > %d channels — truncating", _MAX_CHANNELS)
                break
            _cid = _findtext(ch_el, "id")
            ch: dict[str, Any] = {
                "id": _safe_int(_cid),
                "name": _clamp_name(_findtext(ch_el, "name"), f"Channel {_cid}"),
                "online": _findtext(ch_el, "online", "").lower() == "true",
                "enabled": True,
            }

            # Source descriptor (the IP camera behind this channel)
            src = _find(ch_el, "sourceInputPortDescriptor")
            if src is not None:
                ch["source_ip"] = _findtext(src, "ipAddress")
                ch["source_port"] = _safe_int(_findtext(src, "managePortNo"), 8000)
                ch["protocol"] = _findtext(src, "proxyProtocol")
                ch["username"] = _findtext(src, "userName")

            channels.append(ch)
        return channels

    @staticmethod
    def _parse_video_input_channels(xml_text: str) -> list[dict[str, Any]]:
        """/ISAPI/System/Video/inputs/channels — video input format."""
        root = _parse_xml(xml_text)
        if root is None:
            return []

        channels: list[dict[str, Any]] = []
        for ch_el in _findall(root, "VideoInputChannel"):
            if len(channels) >= _MAX_CHANNELS:
                logger.warning("NVR reported > %d channels — truncating", _MAX_CHANNELS)
                break
            _cid = _findtext(ch_el, "id")
            ch: dict[str, Any] = {
                "id": _safe_int(_cid),
                "name": _clamp_name(_findtext(ch_el, "name"), f"Channel {_cid}"),
                "enabled": _findtext(ch_el, "videoInputEnabled", "true").lower() == "true",
                "online": True,  # if returned, presumed online
            }

            res_el = _find(ch_el, "resDesc")
            if res_el is not None:
                ch["resolution_width"] = _safe_int(_findtext(res_el, "videoInputWidth"))
                ch["resolution_height"] = _safe_int(_findtext(res_el, "videoInputHeight"))

            channels.append(ch)
        return channels

    @staticmethod
    def _parse_streaming_channels(xml_text: str) -> list[dict[str, Any]]:
        """/ISAPI/Streaming/channels — streaming format (fallback).

        Each <StreamingChannel> has an <id> like 101 (ch1 main), 102 (ch1 sub).
        We only keep the main stream (suffix 01) and derive the channel number.
        """
        root = _parse_xml(xml_text)
        if root is None:
            return []

        seen: dict[int, dict[str, Any]] = {}
        for sc in _findall(root, "StreamingChannel"):
            raw_id = _safe_int(_findtext(sc, "id"))
            if raw_id == 0:
                continue

            # Channel math: 101 → ch 1, 201 → ch 2, etc.
            ch_num = raw_id // 100
            stream_type = raw_id % 100  # 01=main, 02=sub

            if ch_num not in seen:
                seen[ch_num] = {
                    "id": ch_num,
                    "name": _findtext(sc, "channelName", f"Channel {ch_num}"),
                    "enabled": _findtext(sc, "enabled", "true").lower() == "true",
                    "online": True,
                }
            # Mark sub stream availability
            if stream_type == 2:
                seen[ch_num]["has_sub_stream"] = True

        return list(seen.values())

    # =========================================================================
    # PTZ Preset Methods
    # =========================================================================

    async def goto_preset(
        self,
        device_id: str,
        preset: int,
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Move to a saved PTZ preset position.

        writes physical motion — gated.
        """
        _enforce_read_only(force=force, action="goto preset")
        if not self._connected or not self._client:
            await self.connect()

        ch = _validate_channel(channel or self._channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{ch}/presets/{preset}/goto",
            )
            response = await self._http.put(url)
            if response.status_code == 200:
                return AdapterResult.ok({"preset": preset, "channel": ch})
            return AdapterResult.fail(f"Goto preset failed: HTTP {response.status_code}")
        except Exception as exc:
            logger.error("Goto preset failed: %s", exc)
            return AdapterResult.fail("PTZ preset command failed")

    async def set_preset(
        self,
        device_id: str,
        preset: int,
        name: str = "",
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Save the current PTZ position as a preset.

        write to PTZ memory — gated.
        """
        _enforce_read_only(force=force, action="set preset")
        if not self._connected or not self._client:
            await self.connect()

        ch = _validate_channel(channel or self._channel)
        from xml.sax.saxutils import escape as _xml_escape

        safe_name = _xml_escape(name or f"Preset {preset}")
        xml_data = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<PTZPreset>"
            f"<id>{preset}</id>"
            f"<presetName>{safe_name}</presetName>"
            "</PTZPreset>"
        )

        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{ch}/presets/{preset}",
            )
            response = await self._http.put(
                url,
                content=xml_data,
                headers={"Content-Type": "application/xml"},
            )
            if response.status_code == 200:
                return AdapterResult.ok({"preset": preset, "name": name, "channel": ch})
            return AdapterResult.fail(f"Set preset failed: HTTP {response.status_code}")
        except Exception as exc:
            logger.error("Set preset failed: %s", exc)
            return AdapterResult.fail("PTZ preset save failed")

    async def delete_preset(
        self,
        device_id: str,
        preset: int,
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Delete a PTZ preset.

        destructive write — gated.
        """
        _enforce_read_only(force=force, action="delete preset")
        if not self._connected or not self._client:
            await self.connect()

        ch = _validate_channel(channel or self._channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{ch}/presets/{preset}",
            )
            response = await self._http.delete(url)
            if response.status_code == 200:
                return AdapterResult.ok({"deleted": preset, "channel": ch})
            return AdapterResult.fail(f"Delete preset failed: HTTP {response.status_code}")
        except Exception as exc:
            logger.error("Delete preset failed: %s", exc)
            return AdapterResult.fail("PTZ preset delete failed")

    async def get_presets(
        self,
        device_id: str = "",
        channel: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get all PTZ presets with positions."""
        if not self._connected or not self._client:
            await self.connect()

        # channel validation on read path too.
        ch = _validate_channel(channel or self._channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{ch}/presets",
            )
            response = await self._http.get(url)
            if response.status_code != 200:
                return []

            root = _parse_xml(response.text)
            if root is None:
                return []

            presets: list[dict[str, Any]] = []
            for p_el in _findall(root, "PTZPreset"):
                p: dict[str, Any] = {
                    "id": _safe_int(_findtext(p_el, "id")),
                    "name": _findtext(p_el, "presetName", ""),
                    "enabled": _findtext(p_el, "enabled", "true").lower() == "true",
                }
                # Absolute position data (if available)
                abs_pos = _find(p_el, "AbsoluteHigh")
                if abs_pos is not None:
                    p["pan"] = _safe_int(_findtext(abs_pos, "azimuth"))
                    p["tilt"] = _safe_int(_findtext(abs_pos, "elevation"))
                    p["zoom"] = _safe_int(_findtext(abs_pos, "absoluteZoom"))
                presets.append(p)

            return presets
        except Exception as exc:
            logger.error("Failed to get presets: %s", exc)
            return []

    # =========================================================================
    # Recording & Playback Methods
    # =========================================================================

    async def _get_device_utc_offset(self) -> str:
        """Return the NVR's UTC offset (e.g. ``-05:00``), cached per adapter.

        Read from ``/ISAPI/System/time`` ``<localTime>``. Hikvision's
        ContentMgmt/search matches recording windows against the device's
        LOCAL clock+offset, not UTC — sending ``Z`` times silently returns
        NO MATCHES (verified live on both lab NVRs). Defaults to ``+00:00``
        if the device time can't be read.
        """
        cached = getattr(self, "_device_utc_offset_cache", None)
        if cached is not None:
            return cached
        offset = "+00:00"
        try:
            import re as _re

            url = urljoin(self.base_url, "/ISAPI/System/time")
            resp = await self._request("GET", url, timeout=httpx.Timeout(10.0))
            if resp.status_code == 200:
                m = _re.search(r"<localTime>([^<]+)</localTime>", resp.text)
                if m:
                    lt = m.group(1).strip()
                    if lt.endswith("Z"):
                        offset = "+00:00"
                    elif len(lt) >= 6 and lt[-6] in "+-" and lt[-3] == ":":
                        offset = lt[-6:]
        except Exception:
            pass
        self._device_utc_offset_cache = offset
        return offset

    @staticmethod
    def _to_device_local_iso(iso_str: str, offset: str) -> str:
        """Convert an ISO-8601 instant to the device local clock + ``offset``.

        Hikvision ContentMgmt/search wants device-LOCAL times WITH the offset
        suffix (e.g. ``2026-05-31T04:00:00-05:00``); a naive or ``Z`` input is
        treated as UTC and shifted into the device's zone. Returns the input
        unchanged if it can't be parsed (graceful degrade).
        """
        from datetime import UTC, datetime, timedelta, timezone

        s = (iso_str or "").strip()
        if not s:
            return s
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return s
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        try:
            sign = 1 if offset[0] == "+" else -1
            oh, om = int(offset[1:3]), int(offset[4:6])
            tz = timezone(sign * timedelta(hours=oh, minutes=om))
        except (ValueError, IndexError):
            return s
        return dt.astimezone(tz).strftime("%Y-%m-%dT%H:%M:%S") + offset

    @staticmethod
    def _local_z_to_utc(iso_z: str, offset: str) -> str:
        """Convert an NVR ``...Z`` timestamp (really device-LOCAL wall-clock) to a
        REAL UTC ISO string.

        Hikvision search/playback report device-local wall-clock with a literal
        ``Z`` suffix (the inverse quirk of :meth:`_to_device_local_iso`). The API
        speaks real UTC, so reinterpret the wall-clock in the device's zone and
        shift to UTC. Returns the input unchanged if it can't be parsed.
        """
        from datetime import UTC, datetime, timedelta, timezone

        s = (iso_z or "").strip()
        if not s:
            return s
        try:
            naive = datetime.fromisoformat(s.replace("Z", ""))
        except ValueError:
            return s
        try:
            sign = 1 if offset[0] == "+" else -1
            oh, om = int(offset[1:3]), int(offset[4:6])
            tz = timezone(sign * timedelta(hours=oh, minutes=om))
        except (ValueError, IndexError):
            tz = UTC
        return naive.replace(tzinfo=tz).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

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
        Search NVR recordings via ``/ISAPI/ContentMgmt/search``.

        Args:
            device_id: Ignored for direct connection.
            channel: 1-based channel number.
            start_time: ISO 8601 (``2024-01-15T00:00:00Z``).
            end_time: ISO 8601.
            event_type: Optional filter (``CMR`` = continuous, ``VMD`` = motion).
            max_results: Max items per response page.

        Returns:
            List of recording segments with start/end times and playback URIs.
        """
        if not self._connected or not self._client:
            await self.connect()

        channel = _validate_channel(channel)
        track_id = channel * 100 + 1  # main stream track
        max_results = max(1, min(500, int(max_results)))

        from uuid import uuid4
        from xml.sax.saxutils import escape as _xml_esc

        # searchID MUST be a GUID — a literal "1" is rejected with statusCode 6
        # badXmlContent on these NVRs (verified live). And the search window must
        # be in the device's LOCAL clock+offset, not UTC ("Z" → silent NO MATCHES).
        search_id = "{" + str(uuid4()) + "}"
        offset = await self._get_device_utc_offset()
        start_local = self._to_device_local_iso(str(start_time), offset)
        end_local = self._to_device_local_iso(str(end_time), offset)

        xml_data = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<CMSearchDescription>"
            f"<searchID>{_xml_esc(search_id)}</searchID>"
            f"<trackIDList><trackID>{int(track_id)}</trackID></trackIDList>"
            "<timeSpanList><timeSpan>"
            f"<startTime>{_xml_esc(start_local)}</startTime>"
            f"<endTime>{_xml_esc(end_local)}</endTime>"
            "</timeSpan></timeSpanList>"
            f"<maxResults>{max_results}</maxResults>"
            "<searchResultPostion>0</searchResultPostion>"
            "<metadataList><metadataDescriptor>//recordType.meta.std-cgi.com"
            "</metadataDescriptor></metadataList>"
            "</CMSearchDescription>"
        )

        try:
            url = urljoin(self.base_url, "/ISAPI/ContentMgmt/search")
            response = await self._http.post(
                url,
                content=xml_data,
                headers={"Content-Type": "application/xml"},
                timeout=30.0,
            )
            if response.status_code != 200:
                return []

            root = _parse_xml(response.text)
            if root is None:
                return []

            # The CMSearchResult nests <searchMatchItem> under <matchList>;
            # _findall only matches DIRECT children, so search under matchList
            # (looking at root returned 0 — the third compounding search bug).
            match_list = _find(root, "matchList")
            if match_list is None:
                # A 200 with no <matchList> is normally "no footage in window",
                # but a buried error status looks identical — surface the status
                # string so a silent-empty timeline is diagnosable (not a warn:
                # genuinely-empty windows are common and shouldn't spam logs).
                status_str = _findtext(root, "responseStatusStrg", "") or _findtext(
                    root, "responseStatus", ""
                )
                logger.debug(
                    "Recording search ch=%d: no <matchList> (status=%r) — no recordings",
                    channel,
                    status_str,
                )
            # The NVR reports segment times as device-local wall-clock with a
            # literal Z; normalize to REAL UTC so the API/timeline/playback all
            # agree (offset was already fetched for the search window).
            recordings: list[dict[str, Any]] = []
            for item in _findall(match_list, "searchMatchItem") if match_list is not None else []:
                time_span = _find(item, "timeSpan")
                media_uri = _find(item, "mediaSegmentDescriptor")

                rec: dict[str, Any] = {
                    "source_id": _findtext(item, "sourceID", ""),
                    "track_id": _findtext(item, "trackID", ""),
                }

                if time_span is not None:
                    rec["start_time"] = self._local_z_to_utc(
                        _findtext(time_span, "startTime", ""), offset
                    )
                    rec["end_time"] = self._local_z_to_utc(
                        _findtext(time_span, "endTime", ""), offset
                    )

                rec["playback_uri"] = _findtext(item, "playbackURI", "")

                if media_uri is not None:
                    rec["content_type"] = _findtext(media_uri, "contentType", "")
                    rec["codec"] = _findtext(media_uri, "codecType", "")

                # Metadata (recording type — continuous / motion / alarm)
                meta = _find(item, "metadataMatches")
                if meta is not None:
                    rec["recording_type"] = _findtext(meta, "metadataDescriptor", "")

                recordings.append(rec)

            logger.debug(
                "Recording search ch=%d returned %d segments",
                channel,
                len(recordings),
            )
            return recordings
        except Exception as exc:
            logger.error("Failed to search recordings: %s", exc)
            return []

    def get_playback_url(
        self,
        device_id: str = "",
        channel: int = 1,
        start_time: str = "",
        end_time: str = "",
    ) -> str:
        """
        Build playback RTSP URL for a time range.

        Uses the Hikvision track convention: ``{channel}01`` for main stream.

        Returns the credential-masked variant (safe for API response
        bodies). For an internal-only working URL use
        :meth:`get_playback_url_internal`.

        Args:
            device_id: Ignored.
            channel: 1-based channel.
            start_time: ``YYYYMMDDTHHmmssZ``.
            end_time: ``YYYYMMDDTHHmmssZ``.
        """
        channel = _validate_channel(channel)
        track_id = channel * 100 + 1
        # Defense in depth: scrub characters that might smuggle URL
        # query components from caller-controlled time strings.
        _safe_time = re.compile(r"[^0-9TZ:.+\-]")
        st = _safe_time.sub("", str(start_time))
        et = _safe_time.sub("", str(end_time))
        return (
            f"rtsp://***:***@{self.host}:554/"
            f"Streaming/tracks/{track_id}?starttime={st}&endtime={et}"
        )

    def get_playback_url_internal(
        self,
        device_id: str = "",
        channel: int = 1,
        start_time: str = "",
        end_time: str = "",
    ) -> str:
        """SERVER-SIDE ONLY — playback RTSP URL with real credentials.

        Mirrors :meth:`get_rtsp_url_internal` but targets the recording
        track (``Streaming/tracks/{channel}01``) with a ``starttime``/
        ``endtime`` window, which Hikvision NVRs honour to seek the
        stored recording to an absolute position.

        Do **NOT** surface this through the API; it embeds credentials
        and is intended only for ffmpeg / internal proxying.

        Args:
            device_id: Ignored.
            channel: 1-based channel.
            start_time: ``YYYYMMDDTHHmmssZ`` (UTC).
            end_time: ``YYYYMMDDTHHmmssZ`` (UTC).
        """
        from urllib.parse import quote

        channel = _validate_channel(channel)
        track_id = channel * 100 + 1
        _safe_time = re.compile(r"[^0-9TZ:.+\-]")
        st = _safe_time.sub("", str(start_time))
        et = _safe_time.sub("", str(end_time))
        user = quote(self.username or "", safe="")
        pwd = quote(self.password or "", safe="")
        return (
            f"rtsp://{user}:{pwd}@{self.host}:554/"
            f"Streaming/tracks/{track_id}?starttime={st}&endtime={et}"
        )

    async def get_playback_rtsp_url(
        self,
        channel: int = 1,
        start_time: str = "",
        duration_s: int = 600,
    ) -> str:
        """Authenticated recorded-track RTSP URL for an HLS playback session.

        SERVER-SIDE ONLY (embeds credentials). Converts the absolute UTC
        ``start_time`` to the NVR's LOCAL clock (Hikvision labels recorded
        windows local-with-a-Z-suffix — see :meth:`get_playback_frame`) and
        opens a forward window of ``duration_s`` seconds (clamped 10s..1h).
        The HLS layer transcodes/remuxes from this URL.
        """
        from datetime import UTC, datetime, timedelta, timezone

        channel = _validate_channel(channel)
        raw = str(start_time).strip().replace("Z", "+00:00")
        start_dt = datetime.fromisoformat(raw)
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=UTC)

        offset = await self._get_device_utc_offset()
        try:
            sign = 1 if offset[0] == "+" else -1
            oh, om = int(offset[1:3]), int(offset[4:6])
            local_tz = timezone(sign * timedelta(hours=oh, minutes=om))
        except (ValueError, IndexError):
            local_tz = UTC
        ls = start_dt.astimezone(local_tz)
        le = ls + timedelta(seconds=max(10, min(int(duration_s), 3600)))

        def _ts(dt: datetime) -> str:
            return dt.strftime("%Y%m%dT%H%M%SZ")

        return self.get_playback_url_internal(channel=channel, start_time=_ts(ls), end_time=_ts(le))

    async def get_playback_frame(
        self,
        device_id: str = "",
        channel: int = 1,
        playback_time: str = "",
    ) -> bytes:
        """Grab a single JPEG frame from the recording at an absolute time.

        Seeks the stored recording on the NVR track to ``playback_time``
        and extracts one decoded frame via an ffmpeg subprocess. This is
        a genuine *recording* frame — distinct from :meth:`get_snapshot`,
        which always returns the *live* image.

        Args:
            device_id: Ignored.
            channel: 1-based channel.
            playback_time: ISO 8601 instant (``2024-03-15T10:30:00Z``).

        Returns:
            Raw JPEG bytes for the recorded frame at ``playback_time``.

        Raises:
            AdapterError: if the time is malformed, ffmpeg is missing,
                or no frame could be decoded (e.g. a recording gap).
        """
        from datetime import UTC, datetime, timedelta, timezone

        channel = _validate_channel(channel)

        # Parse the absolute instant; tolerate trailing Z and treat naive as UTC.
        try:
            raw = str(playback_time).strip().replace("Z", "+00:00")
            start_dt = datetime.fromisoformat(raw)
        except (ValueError, TypeError) as exc:
            raise AdapterError(
                f"get_playback_frame: invalid playback_time {playback_time!r}",
                adapter_id="hikvision",
            ) from exc
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=UTC)

        # Hikvision's RTSP playback track labels its window in the NVR's LOCAL
        # clock but with a literal 'Z' suffix (the search-result playback URIs
        # prove this — a "...Z" time that is really device-local). Convert the
        # absolute instant into the device's local clock first, otherwise we
        # seek ~offset hours away and find no footage → spurious 404.
        offset = await self._get_device_utc_offset()
        try:
            sign = 1 if offset[0] == "+" else -1
            oh, om = int(offset[1:3]), int(offset[4:6])
            local_tz = timezone(sign * timedelta(hours=oh, minutes=om))
        except (ValueError, IndexError):
            local_tz = UTC
        local_start = start_dt.astimezone(local_tz)
        # 10s window (was 5s) so the seek reliably lands on a GOP head — HEVC
        # keyframes are sparse, and a too-narrow window can miss the IDR.
        local_end = local_start + timedelta(seconds=10)

        def _hik_ts(dt: datetime) -> str:
            return dt.strftime("%Y%m%dT%H%M%SZ")

        rtsp_url = self.get_playback_url_internal(
            channel=channel,
            start_time=_hik_ts(local_start),
            end_time=_hik_ts(local_end),
        )

        # ffmpeg: pull one frame, output a single JPEG to stdout.
        # ``-frames:v 1`` + ``image2pipe`` keeps it a still-frame grab.
        args = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-rtsp_transport",
            "tcp",
            "-i",
            rtsp_url,
            "-frames:v",
            "1",
            "-q:v",
            "3",
            "-f",
            "image2pipe",
            "-vcodec",
            "mjpeg",
            "pipe:1",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise AdapterError(
                "get_playback_frame: ffmpeg not available on host",
                adapter_id="hikvision",
            ) from exc

        try:
            # 12s safety net (was 30s). A real recorded-frame grab — RTSP open +
            # seek + decode the first keyframe — completes in a few seconds; a
            # timestamp with no footage otherwise blocks the full timeout. The
            # frontend now pre-checks the timeline so gap requests rarely reach
            # here, but this bounds the worst case (e.g. a stale-timeline race).
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=12.0)
        except TimeoutError as exc:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            raise AdapterError(
                "get_playback_frame: ffmpeg timed out reaching the NVR",
                adapter_id="hikvision",
            ) from exc

        if proc.returncode != 0 or not stdout or stdout[:3] != b"\xff\xd8\xff":
            err = (stderr or b"").decode("utf-8", "ignore")[:200]
            logger.warning(
                "Playback frame grab failed ch=%d rc=%s: %s",
                channel,
                proc.returncode,
                err,
            )
            raise AdapterError(
                "get_playback_frame: no recorded frame at the requested time",
                adapter_id="hikvision",
            )
        return stdout

    # =========================================================================
    # Event Subscription Methods
    # =========================================================================

    async def subscribe_events(
        self,
        callback_url: str,
        event_types: list[str] | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """
        Subscribe to camera events via HTTP callback.

        writes device config (gated by
        ``force``) AND the ``callback_url`` is operator-controlled —
        without SSRF validation the device would happily POST to
        ``169.254.169.254`` or other internal addresses. We validate
        the hostname against the FreeSDN ingress allow-list before
        the XML is even constructed.

        Args:
            callback_url: URL to receive event notifications
            event_types: List of event types to subscribe to
        """
        _enforce_read_only(force=force, action="subscribe events")
        # SSRF check on the destination — the NVR will fire HTTP
        # callbacks to whatever we hand it; reject anything that
        # would let the device probe our internal network.
        parsed = urlparse(callback_url)
        if parsed.scheme not in ("http", "https"):
            raise AdapterError(
                "subscribe_events: callback_url must be http(s)://",
                adapter_id="hikvision",
            )
        _validate_host_not_ssrf(parsed.hostname)

        if not self._connected or not self._client:
            await self.connect()

        event_types = event_types or ["VMD", "linedetection", "fielddetection"]

        try:
            # Subscribe to notification host
            from xml.sax.saxutils import escape as _xml_esc

            xml_data = f"""<?xml version="1.0" encoding="UTF-8"?>
            <HttpHostNotification>
                <id>1</id>
                <url>{_xml_esc(callback_url)}</url>
                <protocolType>HTTP</protocolType>
                <parameterFormatType>XML</parameterFormatType>
                <addressingFormatType>ipaddress</addressingFormatType>
                <httpAuthenticationMethod>none</httpAuthenticationMethod>
            </HttpHostNotification>"""

            url = urljoin(self.base_url, "/ISAPI/Event/notification/httpHosts")
            response = await self._http.post(
                url,
                content=xml_data,
                headers={"Content-Type": "application/xml"},
            )

            if response.status_code not in [200, 201]:
                return AdapterResult.fail(f"Failed to subscribe: {response.status_code}")

            return AdapterResult.ok(
                {
                    "subscribed": True,
                    "callback_url": callback_url,
                    "event_types": event_types,
                }
            )
        except Exception as e:
            logger.error("Hikvision subscribe_events failed: %s", e)
            return AdapterResult.fail("Event subscription failed")

    async def unsubscribe_events(
        self,
        subscription_id: str = "1",
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Unsubscribe from camera events.

        removes device config — gated.
        """
        _enforce_read_only(force=force, action="unsubscribe events")
        # Defense-in-depth: subscription_id is interpolated into the
        # URL path; restrict to digits so a hostile caller can't pivot
        # to other endpoints via path traversal.
        if not re.fullmatch(r"\d+", str(subscription_id)):
            raise AdapterError(
                f"invalid subscription_id: {subscription_id!r}",
                adapter_id="hikvision",
            )
        if not self._connected or not self._client:
            await self.connect()

        try:
            url = urljoin(self.base_url, f"/ISAPI/Event/notification/httpHosts/{subscription_id}")
            response = await self._http.delete(url)

            if response.status_code == 200:
                return AdapterResult.ok({"unsubscribed": True})
            return AdapterResult.fail(f"Failed to unsubscribe: HTTP {response.status_code}")
        except Exception as e:
            logger.error("Hikvision unsubscribe_events failed: %s", e)
            return AdapterResult.fail("Event unsubscription failed")

    async def get_event_triggers(self) -> list[dict[str, Any]]:
        """
        Discover which event types each channel supports.

        Queries ``/ISAPI/Event/triggers`` and returns a list of trigger
        definitions with channel IDs, event types, and notification methods.
        """
        if not self._connected or not self._client:
            await self.connect()

        try:
            url = urljoin(self.base_url, "/ISAPI/Event/triggers")
            response = await self._http.get(url, timeout=10.0)
            if response.status_code != 200:
                return []

            root = _parse_xml(response.text)
            if root is None:
                return []

            triggers: list[dict[str, Any]] = []
            for trig_el in _findall(root, "EventTrigger"):
                channel_id = _findtext(trig_el, "videoInputChannelID", "")
                event_type = _findtext(trig_el, "eventType", "")

                # Notification methods (center, HTTP, record, email, beep)
                notif = _find(trig_el, "EventTriggerNotificationList")
                methods: list[str] = []
                if notif is not None:
                    for n_el in _findall(notif, "EventTriggerNotification"):
                        ntype = _findtext(n_el, "notificationMethod", "")
                        if ntype:
                            methods.append(ntype)

                triggers.append(
                    {
                        "channel_id": _safe_int(channel_id),
                        "event_type": event_type,
                        "notification_methods": methods,
                    }
                )

            return triggers
        except Exception as exc:
            logger.debug("Failed to get event triggers: %s", exc)
            return []

    # the
    # ``alertStream`` endpoint is long-poll, so a misbehaving device
    # (or a hostile man-in-the-middle) could stream unbounded text
    # back into our process. Cap (a) the total response size to
    # 256 KB × 20 = 5 MB and (b) the number of XML blocks parsed to
    # 20. Anything over that is silently truncated — a sane camera
    # never emits that many alerts in one window.
    _MAX_EVENT_STATE_CHUNKS = 20
    _MAX_EVENT_STATE_CHUNK_BYTES = 256 * 1024  # 256 KB

    async def get_event_state(self) -> dict[str, Any]:
        """
        Get current event/alarm state from the alert stream.

        Uses a short timeout because ``/alertStream`` is a long-poll endpoint.

        capped response size and chunk count so the
        endpoint can't be turned into a memory-pressure vector.
        """
        if not self._connected or not self._client:
            await self.connect()

        try:
            url = urljoin(self.base_url, "/ISAPI/Event/notification/alertStream")
            response = await self._http.get(url, timeout=5.0)

            if response.status_code != 200:
                return {"error": f"HTTP {response.status_code}"}

            # The response may contain multiple XML chunks separated by
            # multipart boundaries.  We parse any EventNotificationAlert
            # elements we can find.
            events: list[dict[str, Any]] = []

            # Cap total processed bytes. NOTE: httpx has NO
            # default response-size limit — `response.text` materializes the
            # ENTIRE device-controlled body — so this slice is the real bound,
            # not a backstop. (The earlier comment claiming a "16 MB httpx
            # default" was factually wrong.)
            _max_total = self._MAX_EVENT_STATE_CHUNKS * self._MAX_EVENT_STATE_CHUNK_BYTES
            text = response.text[:_max_total]

            chunks_seen = 0
            # Try to extract individual XML blocks
            for block in re.split(r"--\w+", text):
                if chunks_seen >= self._MAX_EVENT_STATE_CHUNKS:
                    logger.warning(
                        "get_event_state: reached %d-chunk cap, truncating",
                        self._MAX_EVENT_STATE_CHUNKS,
                    )
                    break
                stripped = block.strip()
                if not stripped:
                    continue
                # Per-chunk size cap — drop any oversize block before
                # passing it to the XML parser.
                if len(stripped) > self._MAX_EVENT_STATE_CHUNK_BYTES:
                    logger.warning(
                        "get_event_state: chunk exceeds %d bytes, skipping",
                        self._MAX_EVENT_STATE_CHUNK_BYTES,
                    )
                    chunks_seen += 1
                    continue
                root = _parse_xml(stripped)
                chunks_seen += 1
                if root is None:
                    continue
                if _strip_ns(root.tag) == "EventNotificationAlert":
                    events.append(self._parse_alert(root))
                else:
                    for alert_el in _findall(root, "EventNotificationAlert"):
                        events.append(self._parse_alert(alert_el))

            return {"events": events}
        except httpx.TimeoutException:
            # Expected — alertStream is long-poll
            return {"events": []}
        except Exception as exc:
            logger.error("Failed to get event state: %s", exc)
            return {"error": "Device communication error"}

    @staticmethod
    def _parse_alert(alert_el: ET.Element) -> dict[str, Any]:
        """Parse a single ``<EventNotificationAlert>`` into a dict."""
        # Best-effort object/target classification (AcuSense / DeepinMind smart
        # events nest it as <detectionTarget>/<targetType>/<objectType>, often
        # under DetectionRegionList). Absent on basic motion/tamper events — left
        # empty then. Captured so Person/Vehicle filtering works WHEN the NVR
        # actually classifies, without fabricating it when it doesn't.
        target_type = ""
        for el in alert_el.iter():
            if _strip_ns(el.tag).lower() in ("detectiontarget", "targettype", "objecttype"):
                val = (el.text or "").strip().lower()
                if val:
                    target_type = val
                    break
        return {
            "event_type": _findtext(alert_el, "eventType", ""),
            "event_state": _findtext(alert_el, "eventState", ""),
            "event_description": _findtext(alert_el, "eventDescription", ""),
            "channel_id": _safe_int(_findtext(alert_el, "channelID")),
            "date_time": _findtext(alert_el, "dateTime", ""),
            "active_post_count": _safe_int(_findtext(alert_el, "activePostCount")),
            "target_type": target_type,
        }

    # =========================================================================
    # Image Settings
    # =========================================================================

    async def get_image_settings(
        self,
        device_id: str = "",
        channel: int | None = None,
    ) -> dict[str, Any]:
        """
        Get image settings (brightness, contrast, saturation, sharpness, etc.)
        via ``/ISAPI/Image/channels/{ch}``.
        """
        if not self._connected or not self._client:
            await self.connect()

        # channel validation guards URL interpolation.
        ch = _validate_channel(channel or self._channel)
        url = urljoin(self.base_url, f"/ISAPI/Image/channels/{ch}")

        try:
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}

            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}

            # Standard image params live under <ImageChannel>
            color_el = _find(root, "Color") or root

            return {
                "brightness": _safe_int(_findtext(color_el, "brightnessLevel", "50")),
                "contrast": _safe_int(_findtext(color_el, "contrastLevel", "50")),
                "saturation": _safe_int(_findtext(color_el, "saturationLevel", "50")),
                "sharpness": _safe_int(_findtext(color_el, "sharpnessLevel", "50")),
                "hue": _safe_int(_findtext(color_el, "hueLevel", "50")),
                # WDR / BLC / HLC
                "wdr_enabled": _findtext(root, "WDR/enabled", "false").lower() == "true",
                "wdr_level": _safe_int(_findtext(root, "WDR/WDRLevel", "50")),
                # Noise reduction
                "noise_reduce_mode": _findtext(root, "noiseReduce/noiseReduceMode", "close"),
                "noise_reduce_level": _safe_int(
                    _findtext(root, "noiseReduce/NormalNoiseReduceLevel", "50")
                ),
                # Day/Night
                "ir_cut_filter_type": _findtext(root, "IrcutFilter/IrcutFilterType", "auto"),
                # Exposure
                "exposure_mode": _findtext(root, "Exposure/ExposureType", "auto"),
                # Backlight
                "backlight_mode": _findtext(
                    root, "BacklightCompensation/BacklightCompensationMode", "close"
                ),
            }
        except Exception as exc:
            logger.error("get_image_settings failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_image_settings(
        self,
        settings: dict[str, Any],
        device_id: str = "",
        channel: int | None = None,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Update image settings via PUT ``/ISAPI/Image/channels/{ch}``.

        write — gated; channel validated.

        Accepts a dict with keys like ``brightness``, ``contrast``,
        ``saturation``, ``sharpness``, ``hue`` (values 0-100).
        """
        _enforce_read_only(force=force, action="set image settings")
        if not self._connected or not self._client:
            await self.connect()

        ch = _validate_channel(channel or self._channel)
        url = urljoin(self.base_url, f"/ISAPI/Image/channels/{ch}")

        # First get current XML to preserve structure
        try:
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}"}

            # Build XML for PUT — just update Color subelement
            # Clamp all imaging values to safe integer range
            def _c(k: str, d: int = 50) -> int:
                return max(0, min(100, int(settings.get(k, d))))

            xml_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<ImageChannel xmlns="http://www.hikvision.com/ver20/XMLSchema">
<id>{int(ch)}</id>
<Color>
<brightnessLevel>{_c("brightness")}</brightnessLevel>
<contrastLevel>{_c("contrast")}</contrastLevel>
<saturationLevel>{_c("saturation")}</saturationLevel>
<sharpnessLevel>{_c("sharpness")}</sharpnessLevel>
<hueLevel>{_c("hue")}</hueLevel>
</Color>
</ImageChannel>"""

            put_resp = await self._http.put(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=10.0,
            )

            if put_resp.status_code == 200:
                return {"success": True}
            else:
                return {"success": False, "error": f"HTTP {put_resp.status_code}"}
        except Exception as exc:
            logger.error("set_image_settings failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}

    # =========================================================================
    # OSD (On-Screen Display) Settings
    # =========================================================================

    async def get_osd_settings(
        self,
        device_id: str = "",
        channel: int | None = None,
    ) -> dict[str, Any]:
        """
        Get OSD overlay settings via ``/ISAPI/System/Video/inputs/channels/{ch}/overlays``.
        """
        if not self._connected or not self._client:
            await self.connect()

        ch = _validate_channel(channel or self._channel)
        url = urljoin(
            self.base_url,
            f"/ISAPI/System/Video/inputs/channels/{ch}/overlays",
        )

        try:
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}

            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}

            # Channel name OSD
            chan_name = _find(root, "channelNameOverlay")
            # Date/time OSD
            datetime_overlay = _find(root, "DateTimeOverlay")

            return {
                "channel_name_enabled": (
                    _findtext(chan_name, "enabled", "true").lower() == "true"
                    if chan_name is not None
                    else True
                ),
                "channel_name": _findtext(chan_name, "channelName", "") if chan_name else "",
                "datetime_enabled": (
                    _findtext(datetime_overlay, "enabled", "true").lower() == "true"
                    if datetime_overlay is not None
                    else True
                ),
                "datetime_format": (
                    _findtext(datetime_overlay, "dateStyle", "") if datetime_overlay else ""
                ),
            }
        except Exception as exc:
            logger.error("get_osd_settings failed: %s", exc)
            return {"error": "Device communication error"}

    # =========================================================================
    # Storage Management
    # =========================================================================

    async def get_storage_info(self) -> dict[str, Any]:
        """
        Query NVR HDD storage via multiple ISAPI endpoints for maximum detail.

        Fetches from:
        - ``/ISAPI/ContentMgmt/Storage`` — capacity, free space, status, type
        - ``/ISAPI/ContentMgmt/Storage/hdd/{id}/SMARTTest/status`` — S.M.A.R.T. health per disk
        - ``/ISAPI/System/Storage/hdd`` — extended info (model, serial, firmware, temperature)

        Returns a normalised dict with per-disk details including SMART health,
        temperature, model number, serial number, and power-on hours.
        """
        if not self._connected or not self._client:
            await self.connect()

        try:
            # ── 1. Primary storage info ──────────────────────────────────
            url = urljoin(self.base_url, "/ISAPI/ContentMgmt/Storage")
            response = await self._http.get(url, timeout=10.0)

            if response.status_code != 200:
                return {"error": f"HTTP {response.status_code}"}

            root = _parse_xml(response.text)
            if root is None:
                return {"error": "Invalid XML"}

            disks: list[dict[str, Any]] = []

            # May be wrapped in <storage> → <hddList> → <hdd>, or just <hdd> children
            hdd_list_el = _find(root, "hddList") or root
            for hdd_el in _findall(hdd_list_el, "hdd"):
                d: dict[str, Any] = {
                    "id": _safe_int(_findtext(hdd_el, "id")),
                    "name": _findtext(hdd_el, "hddName", ""),
                    "capacity_mb": _safe_int(_findtext(hdd_el, "capacity")),
                    "free_mb": _safe_int(_findtext(hdd_el, "freeSpace")),
                    "status": _findtext(hdd_el, "status", "unknown"),
                    "hdd_type": _findtext(hdd_el, "hddType", ""),
                    "property": _findtext(hdd_el, "property", ""),
                    # Extended fields — populated below
                    "smart_status": None,
                    "temperature_c": None,
                    "power_on_hours": None,
                    "model": None,
                    "serial_number": None,
                    "firmware": None,
                    "smart_attributes": [],
                }
                disks.append(d)

            # ── 2. Extended HDD info (model, serial, firmware, temp) ─────
            await self._enrich_hdd_system_info(disks)

            # ── 3. S.M.A.R.T. health per disk ───────────────────────────
            await self._enrich_smart_status(disks)

            # ── Aggregate totals ─────────────────────────────────────────
            total_mb = sum(d["capacity_mb"] for d in disks)
            free_mb = sum(d["free_mb"] for d in disks)
            used_mb = total_mb - free_mb

            total_gb = round(total_mb / 1024, 1) if total_mb else 0.0
            free_gb = round(free_mb / 1024, 1) if free_mb else 0.0
            used_gb = round(used_mb / 1024, 1) if used_mb else 0.0
            pct = round((used_mb / total_mb) * 100, 1) if total_mb else 0.0

            # Count healthy vs unhealthy disks
            healthy = sum(
                1 for d in disks if d.get("smart_status") in ("ok", "good", "normal", None)
            )
            unhealthy = len(disks) - healthy

            return {
                "total_gb": total_gb,
                "used_gb": used_gb,
                "free_gb": free_gb,
                "percent_used": pct,
                "disk_count": len(disks),
                "healthy_count": healthy,
                "unhealthy_count": unhealthy,
                "disks": disks,
            }
        except Exception as exc:
            logger.error("Failed to get storage info: %s", exc)
            return {"error": "Device communication error"}

    async def _enrich_hdd_system_info(self, disks: list[dict[str, Any]]) -> None:
        """
        Fetch extended HDD details from ``/ISAPI/System/Storage/hdd``.

        Hikvision NVRs expose per-HDD metadata here including model name,
        serial number, firmware version, and optionally temperature.
        Falls back silently if the endpoint is unavailable.
        """
        try:
            url = urljoin(self.base_url, "/ISAPI/System/Storage/hdd")
            response = await self._http.get(url, timeout=8.0)
            if response.status_code != 200:
                return

            root = _parse_xml(response.text)
            if root is None:
                return

            # Build lookup by HDD id
            disk_map = {d["id"]: d for d in disks}

            hdd_list_el = _find(root, "hddList") or root
            for hdd_el in _findall(hdd_list_el, "hdd"):
                hdd_id = _safe_int(_findtext(hdd_el, "id"))
                disk = disk_map.get(hdd_id)
                if not disk:
                    continue

                # Model / serial / firmware — various possible tag names
                for tag, key in [
                    ("hddName", "_sys_name"),
                    ("model", "model"),
                    ("modelName", "model"),
                    ("serialNumber", "serial_number"),
                    ("serial", "serial_number"),
                    ("firmwareVersion", "firmware"),
                    ("firmware", "firmware"),
                ]:
                    val = _findtext(hdd_el, tag, "")
                    if val and not disk.get(key):
                        disk[key] = val

                # Temperature — may be nested in <smartInfo> or direct
                temp_val = _findtext(hdd_el, "temperature", "")
                if not temp_val:
                    smart_el = _find(hdd_el, "smartInfo") or _find(hdd_el, "SMARTInfo")
                    if smart_el:
                        temp_val = _findtext(smart_el, "temperature", "")
                if temp_val:
                    disk["temperature_c"] = _safe_int(temp_val)

                # Power-on hours — sometimes available directly
                poh = _findtext(hdd_el, "powerOnHours", "") or _findtext(hdd_el, "runningTime", "")
                if poh:
                    disk["power_on_hours"] = _safe_int(poh)

                # Capacity in bytes (more accurate than MB from ContentMgmt)
                cap_bytes = _findtext(hdd_el, "capacityBytes", "")
                if cap_bytes:
                    disk["capacity_bytes"] = _safe_int(cap_bytes)

        except Exception as exc:
            logger.debug("Extended HDD info unavailable: %s", exc)

    async def _enrich_smart_status(self, disks: list[dict[str, Any]]) -> None:
        """
        Fetch S.M.A.R.T. health for each disk from
        ``/ISAPI/ContentMgmt/Storage/hdd/{id}/SMARTTest/status``.

        Populates ``smart_status`` and ``smart_attributes`` on each disk dict.
        Uses concurrent requests for speed. Falls back silently per-disk.
        """

        async def _fetch_smart(disk: dict[str, Any]) -> None:
            hdd_id = disk["id"]
            try:
                url = urljoin(
                    self.base_url,
                    f"/ISAPI/ContentMgmt/Storage/hdd/{hdd_id}/SMARTTest/status",
                )
                resp = await self._http.get(url, timeout=8.0)
                if resp.status_code != 200:
                    return

                root = _parse_xml(resp.text)
                if root is None:
                    return

                # Overall SMART status
                overall = _findtext(root, "status", "") or _findtext(root, "testResult", "")
                if overall:
                    disk["smart_status"] = overall.lower()

                # Temperature from SMART (fallback if not already set)
                temp = _findtext(root, "temperature", "")
                if temp and not disk.get("temperature_c"):
                    disk["temperature_c"] = _safe_int(temp)

                # Power-on hours from SMART (fallback)
                poh = _findtext(root, "powerOnHours", "") or _findtext(root, "runTime", "")
                if poh and not disk.get("power_on_hours"):
                    disk["power_on_hours"] = _safe_int(poh)

                # Self-test progress
                progress = _findtext(root, "selfTestPercent", "") or _findtext(root, "percent", "")
                if progress:
                    disk["smart_self_test_percent"] = _safe_int(progress)

                # Parse S.M.A.R.T. attribute list if present
                attrs: list[dict[str, Any]] = []
                attr_list_el = (
                    _find(root, "SMARTAttributeList")
                    or _find(root, "smartAttributeList")
                    or _find(root, "attributeList")
                )
                if attr_list_el:
                    for attr_el in list(attr_list_el):
                        attr: dict[str, Any] = {
                            "id": _safe_int(
                                _findtext(attr_el, "id") or _findtext(attr_el, "attributeID")
                            ),
                            "name": _findtext(attr_el, "name")
                            or _findtext(attr_el, "attributeName", ""),
                            "current": _safe_int(
                                _findtext(attr_el, "current") or _findtext(attr_el, "currentValue")
                            ),
                            "worst": _safe_int(
                                _findtext(attr_el, "worst") or _findtext(attr_el, "worstValue")
                            ),
                            "threshold": _safe_int(
                                _findtext(attr_el, "threshold")
                                or _findtext(attr_el, "thresholdValue")
                            ),
                            "raw_value": _findtext(attr_el, "rawValue", "")
                            or _findtext(attr_el, "raw", ""),
                            "status": _findtext(attr_el, "statusString", "")
                            or _findtext(attr_el, "status", ""),
                        }
                        if attr["id"] or attr["name"]:
                            attrs.append(attr)
                if attrs:
                    disk["smart_attributes"] = attrs
            except Exception as exc:
                logger.debug("SMART status for HDD %s unavailable: %s", hdd_id, exc)

        # Fetch SMART for all disks concurrently
        await asyncio.gather(*[_fetch_smart(d) for d in disks], return_exceptions=True)

    # =========================================================================
    # Motion Detection
    # =========================================================================

    async def get_motion_detection(self, channel: int = 1) -> dict[str, Any]:
        """
        Read motion detection config from
        ``/ISAPI/System/Video/inputs/channels/{ch}/motionDetection``.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/System/Video/inputs/channels/{channel}/motionDetection",
            )
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            enabled = _findtext(root, "enabled", "false").lower() == "true"
            sensitivity = _safe_int(_findtext(root, "sensitivityLevel", "50"))
            # Grid layout (22×18 or 32×24 cells → bitstring)
            layout_el = _find(root, "MotionDetectionLayout") or _find(root, "layout")
            grid_map = ""
            if layout_el is not None:
                grid_map = _findtext(layout_el, "gridMap", "")
            return {
                "enabled": enabled,
                "sensitivity_level": sensitivity,
                "grid_map": grid_map,
            }
        except Exception as exc:
            logger.error("get_motion_detection failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_motion_detection(
        self,
        config: dict[str, Any],
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Write motion detection config to
        ``/ISAPI/System/Video/inputs/channels/{ch}/motionDetection``.

        write — gated; channel validated.

        *config* keys: ``enabled`` (bool), ``sensitivity_level`` (0-100),
        ``grid_map`` (hex bitstring).
        """
        _enforce_read_only(force=force, action="set motion detection")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            # Read existing XML first so we only overwrite the fields we want
            url = urljoin(
                self.base_url,
                f"/ISAPI/System/Video/inputs/channels/{channel}/motionDetection",
            )
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"success": False, "error": "Invalid XML"}

            # Patch fields
            if "enabled" in config:
                el = _find(root, "enabled")
                if el is not None:
                    el.text = "true" if config["enabled"] else "false"
            if "sensitivity_level" in config:
                el = _find(root, "sensitivityLevel")
                if el is not None:
                    el.text = str(max(0, min(100, int(config["sensitivity_level"]))))
            if "grid_map" in config:
                layout_el = _find(root, "MotionDetectionLayout") or _find(root, "layout")
                if layout_el is not None:
                    gm = _find(layout_el, "gridMap")
                    grid_val = str(config["grid_map"])
                    if gm is not None and re.fullmatch(r"[0-9a-fA-F]+", grid_val):
                        gm.text = grid_val

            xml_body = _serialize_isapi(root)
            put_resp = await self._http.put(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=10.0,
            )
            ok = put_resp.status_code == 200
            return {"success": ok, "status_code": put_resp.status_code}
        except Exception as exc:
            logger.error("set_motion_detection failed: %s", exc)
            return {"success": False, "error": "Failed to update motion detection settings"}

    # =========================================================================
    # Privacy Mask
    # =========================================================================

    async def get_privacy_masks(self, channel: int = 1) -> dict[str, Any]:
        """
        Read privacy mask regions from
        ``/ISAPI/System/Video/inputs/channels/{ch}/privacyMask``.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/System/Video/inputs/channels/{channel}/privacyMask",
            )
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            enabled = _findtext(root, "enabled", "false").lower() == "true"
            sw, sh = _normalized_screen(root)
            regions: list[dict[str, Any]] = []
            region_list = _find(root, "PrivacyMaskRegionList") or root
            for region_el in _findall(region_list, "PrivacyMaskRegion"):
                rid = _safe_int(_findtext(region_el, "id", "0"))
                region_enabled = _findtext(region_el, "enabled", "true").lower() == "true"
                # Scale device coords → fixed 0–10000 editor space.
                rect_el = _find(region_el, "RegionCoordinatesList") or region_el
                coords = []
                for pt in _findall(rect_el, "RegionCoordinates"):
                    x = _safe_int(_findtext(pt, "positionX", "0"))
                    y = _safe_int(_findtext(pt, "positionY", "0"))
                    coords.append({"x": _scale_up(x, sw), "y": _scale_up(y, sh)})
                regions.append({"id": rid, "enabled": region_enabled, "coordinates": coords})
            return {"enabled": enabled, "regions": regions}
        except Exception as exc:
            logger.error("get_privacy_masks failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_privacy_masks(
        self,
        config: dict[str, Any],
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Write privacy mask config.  *config* keys: ``enabled``,
        ``regions`` (list of ``{id, enabled, coordinates: [{x,y}…]}``)

        write — gated; channel validated.
        """
        _enforce_read_only(force=force, action="set privacy masks")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        # Serialise GET-modify-PUT per (host, channel) so two concurrent edits to
        # the same channel can't clobber each other (cf. set_recording_schedule).
        lock = _channel_lock(self.host, channel)
        await lock.acquire()
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/System/Video/inputs/channels/{channel}/privacyMask",
            )
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"success": False, "error": "Invalid XML"}

            sw, sh = _normalized_screen(root)

            if "enabled" in config:
                el = _find(root, "enabled")
                if el is not None:
                    el.text = "true" if config["enabled"] else "false"

            # Patch privacy regions (nested under <PrivacyMaskRegionList>).
            if "regions" in config and config["regions"]:
                existing_regions = _findall(
                    _find(root, "PrivacyMaskRegionList") or root, "PrivacyMaskRegion"
                )
                region_map = {}
                for r_el in existing_regions:
                    rid = _safe_int(_findtext(r_el, "id", "0"))
                    region_map[rid] = r_el

                for region_data in config["regions"]:
                    rid = region_data.get("id")
                    if rid is None or rid not in region_map:
                        continue
                    r_el = region_map[rid]

                    # Patch enabled flag for region
                    if "enabled" in region_data:
                        en_el = _find(r_el, "enabled")
                        if en_el is not None:
                            en_el.text = "true" if region_data["enabled"] else "false"

                    # Patch region coordinates
                    coords = region_data.get("coordinates")
                    if coords and len(coords) >= 4:
                        coord_list_el = _find(r_el, "RegionCoordinatesList") or r_el
                        # Remove existing coordinate children
                        for old_pt in _findall(coord_list_el, "RegionCoordinates"):
                            coord_list_el.remove(old_pt)
                        # Add new coordinate elements
                        for pt in coords:
                            pt_el = ET.SubElement(coord_list_el, "RegionCoordinates")
                            px = ET.SubElement(pt_el, "positionX")
                            px.text = str(_scale_down(int(pt.get("x", 0)), sw))
                            py = ET.SubElement(pt_el, "positionY")
                            py.text = str(_scale_down(int(pt.get("y", 0)), sh))

            xml_body = _serialize_isapi(root)
            put_resp = await self._http.put(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=10.0,
            )
            ok = put_resp.status_code == 200
            return {"success": ok, "status_code": put_resp.status_code}
        except Exception as exc:
            logger.error("set_privacy_masks failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}
        finally:
            lock.release()

    # =========================================================================
    # Line Crossing Detection
    # =========================================================================

    async def get_line_crossing(self, channel: int = 1) -> dict[str, Any]:
        """
        Read line-crossing detection rules from
        ``/ISAPI/Smart/LineDetection/{ch}``.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(self.base_url, f"/ISAPI/Smart/LineDetection/{channel}")
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            enabled = _findtext(root, "enabled", "false").lower() == "true"
            sw, sh = _normalized_screen(root)
            rules: list[dict[str, Any]] = []
            # LineItems are nested under <LineItemList> — _findall only matches
            # direct children, so look there (root-level returned nothing → the
            # editor saw zero slots even though the device exposes a fixed set).
            item_list = _find(root, "LineItemList") or root
            for rule_el in _findall(item_list, "LineItem"):
                rid = _safe_int(_findtext(rule_el, "id", "0"))
                rule_enabled = _findtext(rule_el, "enabled", "false").lower() == "true"
                sensitivity = _safe_int(_findtext(rule_el, "sensitivityLevel", "50"))
                direction = _findtext(rule_el, "directionSensitivity", "both")
                coords = []
                coord_list = _find(rule_el, "CoordinatesList") or rule_el
                for pt in _findall(coord_list, "Coordinates"):
                    x = _safe_int(_findtext(pt, "positionX", "0"))
                    y = _safe_int(_findtext(pt, "positionY", "0"))
                    coords.append({"x": _scale_up(x, sw), "y": _scale_up(y, sh)})
                rules.append(
                    {
                        "id": rid,
                        "enabled": rule_enabled,
                        "sensitivity": sensitivity,
                        "direction": direction,
                        "coordinates": coords,
                    }
                )
            return {"enabled": enabled, "rules": rules}
        except Exception as exc:
            logger.error("get_line_crossing failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_line_crossing(
        self,
        config: dict[str, Any],
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Write line-crossing detection config.  *config* keys: ``enabled``,
        ``rules`` (list of ``{id, enabled, sensitivity, direction, coordinates}``)

        write — gated; channel validated.
        """
        _enforce_read_only(force=force, action="set line crossing")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        # Serialise GET-modify-PUT per (host, channel) so two concurrent edits to
        # the same channel can't clobber each other (cf. set_recording_schedule).
        lock = _channel_lock(self.host, channel)
        await lock.acquire()
        try:
            url = urljoin(self.base_url, f"/ISAPI/Smart/LineDetection/{channel}")
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"success": False, "error": "Invalid XML"}

            sw, sh = _normalized_screen(root)

            if "enabled" in config:
                el = _find(root, "enabled")
                if el is not None:
                    el.text = "true" if config["enabled"] else "false"

            # Patch individual rules (LineItems live under <LineItemList>).
            if "rules" in config and config["rules"]:
                existing_rules = _findall(_find(root, "LineItemList") or root, "LineItem")
                rule_map = {}
                for r_el in existing_rules:
                    rid = _safe_int(_findtext(r_el, "id", "0"))
                    rule_map[rid] = r_el

                for rule_data in config["rules"]:
                    rid = rule_data.get("id")
                    if rid is None or rid not in rule_map:
                        continue
                    r_el = rule_map[rid]

                    if "enabled" in rule_data:
                        en_el = _find(r_el, "enabled")
                        if en_el is not None:
                            en_el.text = "true" if rule_data["enabled"] else "false"

                    if "sensitivity" in rule_data:
                        sens_el = _find(r_el, "sensitivityLevel")
                        if sens_el is not None:
                            sens_el.text = str(max(0, min(100, int(rule_data["sensitivity"]))))

                    if "direction" in rule_data:
                        dir_el = _find(r_el, "directionSensitivity")
                        _valid_dirs = {"both", "A-B", "B-A", "left-right", "right-left"}
                        if dir_el is not None and str(rule_data["direction"]) in _valid_dirs:
                            dir_el.text = str(rule_data["direction"])

                    # Patch line coordinates
                    coords = rule_data.get("coordinates")
                    if coords and len(coords) >= 2:
                        coord_list_el = _find(r_el, "CoordinatesList") or r_el
                        for old_pt in _findall(coord_list_el, "Coordinates"):
                            coord_list_el.remove(old_pt)
                        for pt in coords[:2]:  # Lines have exactly 2 points
                            pt_el = ET.SubElement(coord_list_el, "Coordinates")
                            px = ET.SubElement(pt_el, "positionX")
                            px.text = str(_scale_down(int(pt.get("x", 0)), sw))
                            py = ET.SubElement(pt_el, "positionY")
                            py.text = str(_scale_down(int(pt.get("y", 0)), sh))

            xml_body = _serialize_isapi(root)
            put_resp = await self._http.put(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=10.0,
            )
            ok = put_resp.status_code == 200
            return {"success": ok, "status_code": put_resp.status_code}
        except Exception as exc:
            logger.error("set_line_crossing failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}
        finally:
            lock.release()

    # =========================================================================
    # Intrusion (Field) Detection
    # =========================================================================

    async def get_intrusion_detection(self, channel: int = 1) -> dict[str, Any]:
        """
        Read intrusion (field) detection rules from
        ``/ISAPI/Smart/FieldDetection/{ch}``.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(self.base_url, f"/ISAPI/Smart/FieldDetection/{channel}")
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            enabled = _findtext(root, "enabled", "false").lower() == "true"
            sw, sh = _normalized_screen(root)
            rules: list[dict[str, Any]] = []
            region_list = _find(root, "FieldDetectionRegionList") or root
            for rule_el in _findall(region_list, "FieldDetectionRegion"):
                rid = _safe_int(_findtext(rule_el, "id", "0"))
                rule_enabled = _findtext(rule_el, "enabled", "false").lower() == "true"
                sensitivity = _safe_int(_findtext(rule_el, "sensitivityLevel", "50"))
                time_threshold = _safe_int(_findtext(rule_el, "timeThreshold", "0"))
                coords = []
                coord_list = _find(rule_el, "RegionCoordinatesList") or rule_el
                for pt in _findall(coord_list, "RegionCoordinates"):
                    x = _safe_int(_findtext(pt, "positionX", "0"))
                    y = _safe_int(_findtext(pt, "positionY", "0"))
                    coords.append({"x": _scale_up(x, sw), "y": _scale_up(y, sh)})
                rules.append(
                    {
                        "id": rid,
                        "enabled": rule_enabled,
                        "sensitivity": sensitivity,
                        "time_threshold": time_threshold,
                        "coordinates": coords,
                    }
                )
            return {"enabled": enabled, "rules": rules}
        except Exception as exc:
            logger.error("get_intrusion_detection failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_intrusion_detection(
        self,
        config: dict[str, Any],
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Write intrusion (field) detection config.  *config* keys: ``enabled``,
        ``rules`` (list of ``{id, enabled, sensitivity, time_threshold, coordinates}``)

        write — gated; channel validated.
        """
        _enforce_read_only(force=force, action="set intrusion detection")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        # Serialise GET-modify-PUT per (host, channel) so two concurrent edits to
        # the same channel can't clobber each other (cf. set_recording_schedule).
        lock = _channel_lock(self.host, channel)
        await lock.acquire()
        try:
            url = urljoin(self.base_url, f"/ISAPI/Smart/FieldDetection/{channel}")
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"success": False, "error": "Invalid XML"}

            sw, sh = _normalized_screen(root)

            if "enabled" in config:
                el = _find(root, "enabled")
                if el is not None:
                    el.text = "true" if config["enabled"] else "false"

            # Patch field-detection regions (nested under <FieldDetectionRegionList>).
            if "rules" in config and config["rules"]:
                existing_rules = _findall(
                    _find(root, "FieldDetectionRegionList") or root, "FieldDetectionRegion"
                )
                rule_map = {}
                for r_el in existing_rules:
                    rid = _safe_int(_findtext(r_el, "id", "0"))
                    rule_map[rid] = r_el

                for rule_data in config["rules"]:
                    rid = rule_data.get("id")
                    if rid is None or rid not in rule_map:
                        continue
                    r_el = rule_map[rid]

                    if "enabled" in rule_data:
                        en_el = _find(r_el, "enabled")
                        if en_el is not None:
                            en_el.text = "true" if rule_data["enabled"] else "false"

                    if "sensitivity" in rule_data:
                        sens_el = _find(r_el, "sensitivityLevel")
                        if sens_el is not None:
                            sens_el.text = str(max(0, min(100, int(rule_data["sensitivity"]))))

                    if "time_threshold" in rule_data:
                        tt_el = _find(r_el, "timeThreshold")
                        if tt_el is not None:
                            tt_el.text = str(max(0, min(10, int(rule_data["time_threshold"]))))

                    # Patch polygon coordinates
                    coords = rule_data.get("coordinates")
                    if coords and len(coords) >= 3:
                        coord_list_el = _find(r_el, "RegionCoordinatesList") or r_el
                        for old_pt in _findall(coord_list_el, "RegionCoordinates"):
                            coord_list_el.remove(old_pt)
                        for pt in coords:
                            pt_el = ET.SubElement(coord_list_el, "RegionCoordinates")
                            px = ET.SubElement(pt_el, "positionX")
                            px.text = str(_scale_down(int(pt.get("x", 0)), sw))
                            py = ET.SubElement(pt_el, "positionY")
                            py.text = str(_scale_down(int(pt.get("y", 0)), sh))

            xml_body = _serialize_isapi(root)
            put_resp = await self._http.put(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=10.0,
            )
            ok = put_resp.status_code == 200
            return {"success": ok, "status_code": put_resp.status_code}
        except Exception as exc:
            logger.error("set_intrusion_detection failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}
        finally:
            lock.release()

    # =========================================================================
    # Recording Schedule
    # =========================================================================

    async def get_recording_schedule(self, channel: int = 1) -> dict[str, Any]:
        """
        Read the per-channel weekly recording schedule from
        ``/ISAPI/ContentMgmt/record/channels/{ch}/schedule``.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/ContentMgmt/record/channels/{channel}01/schedule",
            )
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            schedule_enabled = _findtext(root, "enabled", "false").lower() == "true"
            days: list[dict[str, Any]] = []
            for day_el in _findall(root, "ScheduleAction"):
                day_id = _safe_int(_findtext(day_el, "id", "0"))
                action_type = _findtext(day_el, "ScheduleActionType", "")
                time_blocks: list[dict[str, str]] = []
                for block_el in _findall(day_el, "TimeBlockList"):
                    for tb in _findall(block_el, "TimeBlock"):
                        begin = _findtext(tb, "beginTime", "")
                        end = _findtext(tb, "endTime", "")
                        rec_type = _findtext(tb, "recordType", "")
                        time_blocks.append(
                            {
                                "begin_time": begin,
                                "end_time": end,
                                "record_type": rec_type,
                            }
                        )
                days.append(
                    {
                        "id": day_id,
                        "action_type": action_type,
                        "time_blocks": time_blocks,
                    }
                )
            return {"enabled": schedule_enabled, "days": days}
        except Exception as exc:
            logger.error("get_recording_schedule failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_recording_schedule(
        self,
        config: dict[str, Any],
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Write recording schedule config.  *config* keys: ``enabled``,
        ``days`` (list of ``{id, action_type, time_blocks: [{begin_time, end_time, record_type}]}``)

        write — gated; channel validated.
        the GET-then-PUT block is wrapped
        in a per-``(host, channel)`` asyncio.Lock so concurrent writes
        from two requests can't clobber each other's edits. Two
        different NVRs (or two different channels on the same NVR) do
        NOT contend.
        """
        _enforce_read_only(force=force, action="set recording schedule")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/ContentMgmt/record/channels/{channel}01/schedule",
            )
            async with _channel_lock(self.host, channel):
                resp = await self._http.get(url, timeout=10.0)
                if resp.status_code != 200:
                    return {"success": False, "error": f"HTTP {resp.status_code}"}
                root = _parse_xml(resp.text)
                if root is None:
                    return {"success": False, "error": "Invalid XML"}

                if "enabled" in config:
                    el = _find(root, "enabled")
                    if el is not None:
                        el.text = "true" if config["enabled"] else "false"

                # Patch individual day schedule actions
                if "days" in config and config["days"]:
                    existing_days = _findall(root, "ScheduleAction")
                    day_map = {}
                    for d_el in existing_days:
                        did = _safe_int(_findtext(d_el, "id", "0"))
                        day_map[did] = d_el

                    for day_data in config["days"]:
                        did = day_data.get("id")
                        if did is None or did not in day_map:
                            continue
                        d_el = day_map[did]

                        # Patch time blocks
                        time_blocks = day_data.get("time_blocks")
                        if time_blocks is not None:
                            tbl_el = _find(d_el, "TimeBlockList")
                            if tbl_el is not None:
                                # Remove existing TimeBlock children
                                for old_tb in _findall(tbl_el, "TimeBlock"):
                                    tbl_el.remove(old_tb)
                                # Add new time blocks
                                for tb in time_blocks:
                                    tb_el = ET.SubElement(tbl_el, "TimeBlock")
                                    bt = ET.SubElement(tb_el, "beginTime")
                                    bt.text = tb.get("begin_time", "00:00")
                                    et = ET.SubElement(tb_el, "endTime")
                                    et.text = tb.get("end_time", "23:59")
                                    rt = ET.SubElement(tb_el, "recordType")
                                    rt.text = tb.get("record_type", "continuous")

                xml_body = _serialize_isapi(root)
                put_resp = await self._http.put(
                    url,
                    content=xml_body,
                    headers={"Content-Type": "application/xml"},
                    timeout=10.0,
                )
                ok = put_resp.status_code == 200
                return {"success": ok, "status_code": put_resp.status_code}
        except Exception as exc:
            logger.error("set_recording_schedule failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}

    # =========================================================================
    # Video Clip Export / Download
    # =========================================================================

    async def download_video_clip(
        self,
        playback_uri: str,
        start_time: str,
        end_time: str,
    ) -> bytes | None:
        """
        Download a video clip from the NVR via
        ``/ISAPI/ContentMgmt/download``.

        Returns raw bytes of the video file (MP4/AVI), or None on failure.
        For large clips, callers should stream this to disk in chunks.
        """
        if not self._connected or not self._client:
            await self.connect()
        try:
            from xml.sax.saxutils import escape as xml_escape

            # ContentMgmt/download matches the time window against the device's
            # LOCAL clock+offset (a literal Z/UTC silently returns NO MATCHES),
            # exactly like ContentMgmt/search. Convert UTC->device-local here so
            # this path is time-axis-consistent with search_recordings and the
            # watermarked export. _to_device_local_iso degrades
            # gracefully (returns input unchanged) if unparseable.
            offset = await self._get_device_utc_offset()
            start_time = self._to_device_local_iso(start_time, offset)
            end_time = self._to_device_local_iso(end_time, offset)

            url = urljoin(self.base_url, "/ISAPI/ContentMgmt/download")
            xml_body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                "<downloadRequest>"
                f"<playbackURI>{xml_escape(playback_uri)}</playbackURI>"
                f"<startTime>{xml_escape(start_time)}</startTime>"
                f"<endTime>{xml_escape(end_time)}</endTime>"
                "</downloadRequest>"
            )
            resp = await self._http.post(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=120.0,
            )
            if resp.status_code == 200:
                return resp.content
            logger.warning(
                "download_video_clip HTTP %d from %s",
                resp.status_code,
                self.host,
            )
            return None
        except Exception as exc:
            logger.error("download_video_clip failed: %s", exc)
            return None

    async def stream_video_clip(
        self,
        playback_uri: str,
        start_time: str,
        end_time: str,
    ) -> AsyncIterator[bytes]:
        """
        Async generator that yields video bytes in chunks.
        Use this for large clips to avoid loading entire file into RAM.

        the previous version
        held the shared ``self._http`` client open for the entire
        export, which (a) hogged the connection pool and (b) could
        block every other API call against the same NVR for the
        ~minutes a clip download takes. Spin up a one-off
        ``httpx.AsyncClient`` here and close it in ``finally`` so
        the shared client stays free for snapshot/PTZ traffic.
        """
        if not self._connected or not self._client:
            await self.connect()
        from xml.sax.saxutils import escape as xml_escape

        # Convert UTC->device-local (see download_video_clip): the
        # ISAPI download window is matched against the NVR's local clock, so a
        # literal Z silently yields no footage on a non-UTC NVR.
        offset = await self._get_device_utc_offset()
        start_time = self._to_device_local_iso(start_time, offset)
        end_time = self._to_device_local_iso(end_time, offset)

        url = urljoin(self.base_url, "/ISAPI/ContentMgmt/download")
        xml_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<downloadRequest>"
            f"<playbackURI>{xml_escape(playback_uri)}</playbackURI>"
            f"<startTime>{xml_escape(start_time)}</startTime>"
            f"<endTime>{xml_escape(end_time)}</endTime>"
            "</downloadRequest>"
        )

        # Dedicated client — keeps the main pool unblocked.
        export_client = build_async_client(
            auth=self.auth,
            timeout=httpx.Timeout(600.0, connect=10.0),
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=1),
        )
        try:
            async with export_client.stream(
                "POST",
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
            ) as resp:
                if resp.status_code != 200:
                    logger.warning("stream_video_clip HTTP %d", resp.status_code)
                    return
                _MAX_STREAM_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB safety cap
                _total = 0
                async for chunk in resp.aiter_bytes(chunk_size=65536):
                    _total += len(chunk)
                    if _total > _MAX_STREAM_BYTES:
                        logger.warning(
                            "stream_video_clip exceeded %d byte limit, aborting",
                            _MAX_STREAM_BYTES,
                        )
                        return
                    yield chunk
        finally:
            await export_client.aclose()

    async def _recorded_rtsp_for_range(self, channel: int, start_iso: str, end_iso: str) -> str:
        """Credentialed recorded-track RTSP for an absolute UTC [start, end] window
        (converted to the NVR's local clock, like get_playback_rtsp_url)."""
        from datetime import UTC, datetime, timedelta, timezone

        channel = _validate_channel(channel)
        offset = await self._get_device_utc_offset()
        try:
            sign = 1 if offset[0] == "+" else -1
            oh, om = int(offset[1:3]), int(offset[4:6])
            local_tz = timezone(sign * timedelta(hours=oh, minutes=om))
        except (ValueError, IndexError):
            local_tz = UTC

        def _conv(iso: str) -> str:
            dt = datetime.fromisoformat(str(iso).strip().replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.astimezone(local_tz).strftime("%Y%m%dT%H%M%SZ")

        return self.get_playback_url_internal(
            channel=channel, start_time=_conv(start_iso), end_time=_conv(end_iso)
        )

    async def stream_clip_watermarked(
        self, channel: int, start_iso: str, end_iso: str, overlay_text: str = ""
    ) -> AsyncIterator[bytes]:
        """Export a recorded clip as MP4 with a burned-in chain-of-custody overlay
        (operator + export time), re-encoded via ffmpeg drawtext. Yields
        fragmented-MP4 bytes. The camera already burns in time + camera name; this
        adds the export provenance the camera can't know.
        """
        rtsp = await self._recorded_rtsp_for_range(channel, start_iso, end_iso)
        # Sanitise for the drawtext filter — drop chars that break its parser.
        safe = re.sub(r"[:'\\%\n\r]", " ", overlay_text)[:120]
        font = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        # Downscale to 720p: re-encoding a 4K-HEVC source at full res can't keep
        # up (the encoder stalls before emitting a frame). 720p libx264 ultrafast
        # sustains real-time, so the watermarked evidence copy is shareable and
        # fast; the full-res original is available via the no-watermark path.
        vf = (
            f"scale=-2:720,drawtext=fontfile={font}:text='{safe}':x=12:y=12:fontsize=16:"
            "fontcolor=white:box=1:boxcolor=black@0.5:boxborderw=6"
        )
        args = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            # Bound a stalled RTSP source: rw_timeout (us) makes ffmpeg exit
            # instead of blocking the demuxer forever; stimeout covers older
            # ffmpeg builds that read the rtsp-specific socket timeout. Without
            # these a mid-stream camera stall leaves proc.stdout.read() (below)
            # blocked indefinitely with the ffmpeg child + sockets alive.
            "-rtsp_transport",
            "tcp",
            "-rw_timeout",
            "15000000",
            "-stimeout",
            "15000000",
            "-i",
            rtsp,
            "-vf",
            vf,
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-c:a",
            "aac",
            "-ac",
            "1",
            "-ar",
            "16000",
            "-movflags",
            "+frag_keyframe+empty_moov+default_base_moof",
            "-f",
            "mp4",
            "pipe:1",
        ]
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        try:
            assert proc.stdout is not None
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()

    # =========================================================================
    # Camera Health / Bandwidth (Track Info)
    # =========================================================================

    async def get_channel_track_info(self, channel: int = 1) -> dict[str, Any]:
        """
        Read current stream track info (bitrate, codec, resolution) from
        ``/ISAPI/Streaming/channels/{ch}01/trackinfo``.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            isapi_ch = channel * 100 + 1
            url = urljoin(
                self.base_url,
                f"/ISAPI/Streaming/channels/{isapi_ch}/trackinfo",
            )
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            tracks: list[dict[str, Any]] = []
            for track_el in _findall(root, "StreamTrackInfo"):
                tracks.append(
                    {
                        "id": _safe_int(_findtext(track_el, "id")),
                        "codec": _findtext(track_el, "videoCodecType", ""),
                        "resolution_width": _safe_int(_findtext(track_el, "videoResolutionWidth")),
                        "resolution_height": _safe_int(
                            _findtext(track_el, "videoResolutionHeight")
                        ),
                        "bitrate_kbps": _safe_int(_findtext(track_el, "videoBitrate")),
                        "frame_rate": _safe_int(_findtext(track_el, "videoFrameRate")),
                    }
                )
            if not tracks:
                # Some firmware returns a flat structure
                tracks.append(
                    {
                        "id": 1,
                        "codec": _findtext(root, "videoCodecType", ""),
                        "resolution_width": _safe_int(_findtext(root, "videoResolutionWidth")),
                        "resolution_height": _safe_int(_findtext(root, "videoResolutionHeight")),
                        "bitrate_kbps": _safe_int(_findtext(root, "videoBitrate")),
                        "frame_rate": _safe_int(_findtext(root, "videoFrameRate")),
                    }
                )
            return {"channel": channel, "tracks": tracks}
        except Exception as exc:
            logger.error("get_channel_track_info failed: %s", exc)
            return {"error": "Device communication error"}

    async def get_channel_status_list(self) -> list[dict[str, Any]]:
        """
        Get the online/offline status of all NVR input channels via
        ``/ISAPI/ContentMgmt/InputProxy/channels/status``.
        """
        if not self._connected or not self._client:
            await self.connect()
        try:
            url = urljoin(
                self.base_url,
                "/ISAPI/ContentMgmt/InputProxy/channels/status",
            )
            resp = await self._http.get(url, timeout=15.0)
            if resp.status_code != 200:
                return []
            root = _parse_xml(resp.text)
            if root is None:
                return []
            channels: list[dict[str, Any]] = []
            for ch_el in _findall(root, "InputProxyChannelStatus"):
                channels.append(
                    {
                        "id": _safe_int(_findtext(ch_el, "id")),
                        "name": _findtext(ch_el, "name", ""),
                        "online": _findtext(ch_el, "online", "false").lower() == "true",
                        "ip_address": _findtext(ch_el, "sourceInputPortDescriptor", ""),
                    }
                )
            return channels
        except Exception as exc:
            logger.error("get_channel_status_list failed: %s", exc)
            return []

    async def get_smart_capabilities(self, channel: int = 1) -> dict[str, Any]:
        """
        Probe which smart features are available on a channel.
        Returns a dict of capability booleans.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)

        caps: dict[str, bool] = {
            "motion_detection": False,
            "line_crossing": False,
            "intrusion_detection": False,
            "privacy_mask": False,
        }

        async def _probe(path: str, key: str) -> None:
            try:
                url = urljoin(self.base_url, path)
                resp = await self._http.get(url, timeout=5.0)
                caps[key] = resp.status_code == 200
            except Exception:
                pass

        await asyncio.gather(
            _probe(
                f"/ISAPI/System/Video/inputs/channels/{channel}/motionDetection",
                "motion_detection",
            ),
            _probe(f"/ISAPI/Smart/LineDetection/{channel}", "line_crossing"),
            _probe(
                f"/ISAPI/Smart/FieldDetection/{channel}",
                "intrusion_detection",
            ),
            _probe(
                f"/ISAPI/System/Video/inputs/channels/{channel}/privacyMask",
                "privacy_mask",
            ),
            _probe(f"/ISAPI/Smart/FaceDetect/{channel}", "face_detection"),
        )
        return caps

    # =========================================================================
    # Face Detection
    # =========================================================================

    async def get_face_detection(self, channel: int = 1) -> dict[str, Any]:
        """
        Read face detection config from ``/ISAPI/Smart/FaceDetect/{ch}``.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(self.base_url, f"/ISAPI/Smart/FaceDetect/{channel}")
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            enabled = _findtext(root, "enabled", "false").lower() == "true"
            sensitivity = _safe_int(_findtext(root, "sensitivityLevel", "50"))
            # Snap interval controls how often face snapshots are captured (0 = every frame)
            snap_interval = _safe_int(_findtext(root, "snapInterval", "0"))
            # Detection target filter
            generation_speed = _safe_int(_findtext(root, "generationSpeed", "3"))
            # Min/max face size (% of image or pixels, varies by firmware)
            min_w = _safe_int(_findtext(root, "minWidth", "0"))
            min_h = _safe_int(_findtext(root, "minHeight", "0"))
            max_w = _safe_int(_findtext(root, "maxWidth", "0"))
            max_h = _safe_int(_findtext(root, "maxHeight", "0"))
            return {
                "enabled": enabled,
                "sensitivity": sensitivity,
                "snap_interval": snap_interval,
                "generation_speed": generation_speed,
                "min_width": min_w,
                "min_height": min_h,
                "max_width": max_w,
                "max_height": max_h,
            }
        except Exception as exc:
            logger.error("get_face_detection failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_face_detection(
        self,
        config: dict[str, Any],
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Write face detection config.  *config* keys: ``enabled``,
        ``sensitivity``, ``snap_interval``, etc.

        write — gated; channel validated.
        """
        _enforce_read_only(force=force, action="set face detection")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(self.base_url, f"/ISAPI/Smart/FaceDetect/{channel}")
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"success": False, "error": "Invalid XML"}

            _field_map: dict[str, tuple[str, Any]] = {
                "enabled": ("enabled", lambda v: "true" if v else "false"),
                "sensitivity": ("sensitivityLevel", lambda v: str(max(0, min(100, int(v))))),
                "snap_interval": ("snapInterval", lambda v: str(max(0, int(v)))),
                "generation_speed": ("generationSpeed", lambda v: str(max(1, min(5, int(v))))),
            }
            for key, (xml_tag, fmt) in _field_map.items():
                if key in config:
                    el = _find(root, xml_tag)
                    if el is not None:
                        el.text = fmt(config[key])

            xml_body = _serialize_isapi(root)
            put_resp = await self._http.put(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=10.0,
            )
            ok = put_resp.status_code == 200
            return {"success": ok, "status_code": put_resp.status_code}
        except Exception as exc:
            logger.error("set_face_detection failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}

    # =========================================================================
    # Holiday Schedule
    # =========================================================================

    async def get_holidays(self) -> dict[str, Any]:
        """
        Read NVR-level holidays from ``/ISAPI/System/Holidays``.
        Returns list of holiday definitions.
        """
        if not self._connected or not self._client:
            await self.connect()
        try:
            url = urljoin(self.base_url, "/ISAPI/System/Holidays")
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            holidays: list[dict[str, Any]] = []
            for h_el in _findall(root, "holiday"):
                hid = _safe_int(_findtext(h_el, "id", "0"))
                enabled = _findtext(h_el, "enabled", "false").lower() == "true"
                name = _findtext(h_el, "holidayName", "")
                mode = _findtext(h_el, "holidayMode", "date")  # date | week | month
                start_el = _find(h_el, "holidayDate") or _find(h_el, "HolidayDate")
                start_month = _safe_int(_findtext(start_el, "startMonth", "1")) if start_el else 1
                start_day = _safe_int(_findtext(start_el, "startDay", "1")) if start_el else 1
                end_month = _safe_int(_findtext(start_el, "endMonth", "1")) if start_el else 1
                end_day = _safe_int(_findtext(start_el, "endDay", "1")) if start_el else 1
                holidays.append(
                    {
                        "id": hid,
                        "enabled": enabled,
                        "name": name,
                        "mode": mode,
                        "start_month": start_month,
                        "start_day": start_day,
                        "end_month": end_month,
                        "end_day": end_day,
                    }
                )
            return {"holidays": holidays}
        except Exception as exc:
            logger.error("get_holidays failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_holidays(
        self,
        holidays: list[dict[str, Any]],
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Write holidays to ``/ISAPI/System/Holidays``.
        Reads existing XML, patches, PUTs back.

        write — gated.
        """
        _enforce_read_only(force=force, action="set holidays")
        if not self._connected or not self._client:
            await self.connect()
        try:
            url = urljoin(self.base_url, "/ISAPI/System/Holidays")
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"success": False, "error": "Invalid XML"}

            # Build map of existing holiday elements by id
            existing = {}
            for h_el in _findall(root, "holiday"):
                hid = _safe_int(_findtext(h_el, "id", "0"))
                existing[hid] = h_el

            for h_data in holidays:
                hid = h_data.get("id")  # type: ignore[assignment]
                if hid is None or hid not in existing:
                    continue
                h_el = existing[hid]
                if "enabled" in h_data:
                    en_el = _find(h_el, "enabled")
                    if en_el is not None:
                        en_el.text = "true" if h_data["enabled"] else "false"
                if "name" in h_data:
                    nm_el = _find(h_el, "holidayName")
                    if nm_el is not None:
                        # Sanitize: strip non-alphanumeric/space/dash/underscore
                        safe_name = re.sub(r"[^\w\s\-]", "", str(h_data["name"]))[:64]
                        nm_el.text = safe_name
                date_el = _find(h_el, "holidayDate") or _find(h_el, "HolidayDate")
                if date_el is not None:
                    for field, tag in [
                        ("start_month", "startMonth"),
                        ("start_day", "startDay"),
                        ("end_month", "endMonth"),
                        ("end_day", "endDay"),
                    ]:
                        if field in h_data:
                            t_el = _find(date_el, tag)
                            if t_el is not None:
                                t_el.text = str(int(h_data[field]))

            xml_body = _serialize_isapi(root)
            put_resp = await self._http.put(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=10.0,
            )
            ok = put_resp.status_code == 200
            return {"success": ok, "status_code": put_resp.status_code}
        except Exception as exc:
            logger.error("set_holidays failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}

    async def get_holiday_schedule(self, channel: int = 1) -> dict[str, Any]:
        """
        Read holiday recording schedule from
        ``/ISAPI/ContentMgmt/record/channels/{ch}/holidaySchedule``.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/ContentMgmt/record/channels/{channel}01/holidaySchedule",
            )
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            schedule_enabled = _findtext(root, "enabled", "false").lower() == "true"
            days: list[dict[str, Any]] = []
            for day_el in _findall(root, "ScheduleAction"):
                day_id = _safe_int(_findtext(day_el, "id", "0"))
                action_type = _findtext(day_el, "ScheduleActionType", "")
                time_blocks: list[dict[str, str]] = []
                for block_el in _findall(day_el, "TimeBlockList"):
                    for tb in _findall(block_el, "TimeBlock"):
                        begin = _findtext(tb, "beginTime", "")
                        end = _findtext(tb, "endTime", "")
                        rec_type = _findtext(tb, "recordType", "")
                        time_blocks.append(
                            {
                                "begin_time": begin,
                                "end_time": end,
                                "record_type": rec_type,
                            }
                        )
                days.append(
                    {
                        "id": day_id,
                        "action_type": action_type,
                        "time_blocks": time_blocks,
                    }
                )
            return {"enabled": schedule_enabled, "days": days}
        except Exception as exc:
            logger.error("get_holiday_schedule failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_holiday_schedule(
        self,
        config: dict[str, Any],
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Write holiday recording schedule.
        Same XML shape as weekly schedule, just at the holidaySchedule path.

        write — gated; channel validated.
        """
        _enforce_read_only(force=force, action="set holiday schedule")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/ContentMgmt/record/channels/{channel}01/holidaySchedule",
            )
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"success": False, "error": "Invalid XML"}

            if "enabled" in config:
                en_el = _find(root, "enabled")
                if en_el is not None:
                    en_el.text = "true" if config["enabled"] else "false"

            if "days" in config:
                existing_days = _findall(root, "ScheduleAction")
                day_map = {}
                for d_el in existing_days:
                    did = _safe_int(_findtext(d_el, "id", "0"))
                    day_map[did] = d_el

                for day_data in config["days"]:
                    did = day_data.get("id")
                    if did is None or did not in day_map:
                        continue
                    d_el = day_map[did]
                    for block_list_el in _findall(d_el, "TimeBlockList"):
                        for old_tb in list(_findall(block_list_el, "TimeBlock")):
                            block_list_el.remove(old_tb)
                        for tb_data in day_data.get("time_blocks", []):
                            tb_el = ET.SubElement(block_list_el, "TimeBlock")
                            bt = ET.SubElement(tb_el, "beginTime")
                            bt.text = tb_data.get("begin_time", "00:00")
                            et = ET.SubElement(tb_el, "endTime")
                            et.text = tb_data.get("end_time", "23:59")
                            rt = ET.SubElement(tb_el, "recordType")
                            rt.text = tb_data.get("record_type", "continuous")

            xml_body = _serialize_isapi(root)
            put_resp = await self._http.put(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=10.0,
            )
            ok = put_resp.status_code == 200
            return {"success": ok, "status_code": put_resp.status_code}
        except Exception as exc:
            logger.error("set_holiday_schedule failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}

    # =========================================================================
    # PTZ Tours / Patrols
    # =========================================================================

    async def get_patrols(self, channel: int = 1) -> list[dict[str, Any]]:
        """
        List PTZ patrols from ``/ISAPI/PTZCtrl/channels/{ch}/patrols``.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(self.base_url, f"/ISAPI/PTZCtrl/channels/{channel}/patrols")
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return []
            root = _parse_xml(resp.text)
            if root is None:
                return []
            patrols: list[dict[str, Any]] = []
            for p_el in _findall(root, "PTZPatrol"):
                pid = _safe_int(_findtext(p_el, "id", "0"))
                name = _findtext(p_el, "patrolName", f"Patrol {pid}")
                enabled = _findtext(p_el, "enabled", "true").lower() == "true"
                actions: list[dict[str, Any]] = []
                for a_el in _findall(p_el, "PatrolAction"):
                    actions.append(
                        {
                            "id": _safe_int(_findtext(a_el, "id", "0")),
                            "preset_id": _safe_int(_findtext(a_el, "presetID", "0")),
                            "dwell": _safe_int(_findtext(a_el, "dwellTime", "10")),
                            "speed": _safe_int(_findtext(a_el, "speed", "50")),
                        }
                    )
                patrols.append(
                    {
                        "id": pid,
                        "name": name,
                        "enabled": enabled,
                        "actions": actions,
                    }
                )
            return patrols
        except Exception as exc:
            logger.error("get_patrols failed: %s", exc)
            return []

    async def get_patrol(self, patrol_id: int, channel: int = 1) -> dict[str, Any]:
        """
        Get a single patrol's detail.
        """
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{channel}/patrols/{patrol_id}",
            )
            resp = await self._http.get(url, timeout=10.0)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            root = _parse_xml(resp.text)
            if root is None:
                return {"error": "Invalid XML"}
            pid = _safe_int(_findtext(root, "id", str(patrol_id)))
            name = _findtext(root, "patrolName", f"Patrol {pid}")
            enabled = _findtext(root, "enabled", "true").lower() == "true"
            actions: list[dict[str, Any]] = []
            for a_el in _findall(root, "PatrolAction"):
                actions.append(
                    {
                        "id": _safe_int(_findtext(a_el, "id", "0")),
                        "preset_id": _safe_int(_findtext(a_el, "presetID", "0")),
                        "dwell": _safe_int(_findtext(a_el, "dwellTime", "10")),
                        "speed": _safe_int(_findtext(a_el, "speed", "50")),
                    }
                )
            return {
                "id": pid,
                "name": name,
                "enabled": enabled,
                "actions": actions,
            }
        except Exception as exc:
            logger.error("get_patrol failed: %s", exc)
            return {"error": "Device communication error"}

    async def set_patrol(
        self,
        patrol_id: int,
        config: dict[str, Any],
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Create / update a PTZ patrol.

        write — gated; channel validated.
        """
        _enforce_read_only(force=force, action="set patrol")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            from xml.sax.saxutils import escape as _xml_escape

            name = _xml_escape(config.get("name", f"Patrol {patrol_id}"))
            enabled = "true" if config.get("enabled", True) else "false"

            actions_xml = ""
            for i, act in enumerate(config.get("actions", []), start=1):
                preset_id = int(act.get("preset_id", 1))
                dwell = max(1, int(act.get("dwell", 10)))
                speed = max(1, min(100, int(act.get("speed", 50))))
                actions_xml += (
                    f"<PatrolAction>"
                    f"<id>{i}</id>"
                    f"<presetID>{preset_id}</presetID>"
                    f"<dwellTime>{dwell}</dwellTime>"
                    f"<speed>{speed}</speed>"
                    f"</PatrolAction>"
                )

            xml_body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                f"<PTZPatrol>"
                f"<id>{patrol_id}</id>"
                f"<patrolName>{name}</patrolName>"
                f"<enabled>{enabled}</enabled>"
                f"{actions_xml}"
                f"</PTZPatrol>"
            )

            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{channel}/patrols/{patrol_id}",
            )
            put_resp = await self._http.put(
                url,
                content=xml_body,
                headers={"Content-Type": "application/xml"},
                timeout=10.0,
            )
            ok = put_resp.status_code == 200
            return {"success": ok, "status_code": put_resp.status_code}
        except Exception as exc:
            logger.error("set_patrol failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}

    async def delete_patrol(
        self,
        patrol_id: int,
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Delete a PTZ patrol.

        destructive write — gated.
        """
        _enforce_read_only(force=force, action="delete patrol")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{channel}/patrols/{patrol_id}",
            )
            resp = await self._http.delete(url, timeout=10.0)
            ok = resp.status_code == 200
            return {"success": ok, "status_code": resp.status_code}
        except Exception as exc:
            logger.error("delete_patrol failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}

    async def start_patrol(
        self,
        patrol_id: int,
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Start a PTZ patrol.

        causes physical motion — gated.
        """
        _enforce_read_only(force=force, action="start patrol")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{channel}/patrols/{patrol_id}/start",
            )
            resp = await self._http.put(url, timeout=10.0)
            ok = resp.status_code == 200
            return {"success": ok, "status_code": resp.status_code}
        except Exception as exc:
            logger.error("start_patrol failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}

    async def stop_patrol(
        self,
        patrol_id: int,
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Stop a PTZ patrol.

        cancels physical motion — gated.
        """
        _enforce_read_only(force=force, action="stop patrol")
        if not self._connected or not self._client:
            await self.connect()
        channel = _validate_channel(channel)
        try:
            url = urljoin(
                self.base_url,
                f"/ISAPI/PTZCtrl/channels/{channel}/patrols/{patrol_id}/stop",
            )
            resp = await self._http.put(url, timeout=10.0)
            ok = resp.status_code == 200
            return {"success": ok, "status_code": resp.status_code}
        except Exception as exc:
            logger.error("stop_patrol failed: %s", exc)
            return {"success": False, "error": "Device configuration update failed"}

    # ── Thermal ──────────────────────────────────────────────────────────

    async def get_thermal_capabilities(self, channel: int = 1) -> dict[str, Any]:
        """Get thermal camera capabilities and current readings via ISAPI."""
        try:
            channel = _validate_channel(channel)
        except AdapterError:
            return {"is_thermal": False, "supported": False, "error": "Invalid channel number"}
        if not self._connected or not self._client:
            await self.connect()

        url = urljoin(self.base_url, f"/ISAPI/Thermal/channels/{channel}/thermometry/capabilities")
        try:
            response = await self._request("GET", url, timeout=httpx.Timeout(10.0))
            if response.status_code != 200:
                return {"is_thermal": False, "supported": False}

            root = _parse_xml(response.text)
            if root is None:
                return {"is_thermal": False, "supported": False}

            return {
                "is_thermal": True,
                "supported": True,
                "min_temp": _safe_float(_findtext(root, "minTemperature"), -40.0),
                "max_temp": _safe_float(_findtext(root, "maxTemperature"), 550.0),
                "emissivity": _safe_float(_findtext(root, "emissivity"), 0.95),
                "palette": _findtext(root, "colorPalette") or "whitehot",
            }
        except Exception:
            logger.debug("Thermal capabilities check failed (not a thermal camera)")
            return {"is_thermal": False, "supported": False}

    async def set_thermal_threshold(
        self,
        channel: int = 1,
        min_temp: float = 0.0,
        max_temp: float = 100.0,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Set temperature alert thresholds on a thermal camera.

        write — gated; channel validated.
        """
        _enforce_read_only(force=force, action="set thermal threshold")
        channel = _validate_channel(channel)
        if not self._connected or not self._client:
            await self.connect()

        xml_data = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<ThermometryAlarmRule>"
            f"<id>{channel}</id>"
            "<enabled>true</enabled>"
            "<ThermometryAlarmRuleType>temperatureOverHighThreshold</ThermometryAlarmRuleType>"
            f"<highThreshold>{min(max_temp, 550)}</highThreshold>"
            f"<lowThreshold>{max(min_temp, -40)}</lowThreshold>"
            "</ThermometryAlarmRule>"
        )
        url = urljoin(self.base_url, f"/ISAPI/Thermal/channels/{channel}/thermometry/rules/1")
        try:
            response = await self._request(
                "PUT", url, content=xml_data, timeout=httpx.Timeout(10.0)
            )
            if response.status_code == 200:
                return AdapterResult.ok({"status": "threshold_set"})
            return AdapterResult.fail("Failed to set thermal threshold")
        except Exception:
            logger.exception("Failed to set thermal threshold")
            return AdapterResult.fail("Device communication error")

    # ── Auto-tracking ────────────────────────────────────────────────────

    async def get_auto_tracking(self, channel: int = 1) -> dict[str, Any]:
        """Get PTZ auto-tracking configuration via ISAPI Smart tracking."""
        try:
            channel = _validate_channel(channel)
        except AdapterError:
            return {"supported": False, "enabled": False, "error": "Invalid channel number"}
        if not self._connected or not self._client:
            await self.connect()

        url = urljoin(self.base_url, f"/ISAPI/Smart/channels/{channel}/autoTracking")
        try:
            response = await self._request("GET", url, timeout=httpx.Timeout(10.0))
            if response.status_code != 200:
                return {"supported": False, "enabled": False}

            root = _parse_xml(response.text)
            if root is None:
                return {"supported": False, "enabled": False}

            enabled_text = _findtext(root, "enabled") or "false"
            return {
                "supported": True,
                "enabled": enabled_text.lower() == "true",
                "track_duration_sec": _safe_int(_findtext(root, "trackDuration"), 30),
                "sensitivity": _safe_int(_findtext(root, "sensitivity"), 50),
            }
        except Exception:
            logger.debug("Auto-tracking not supported on this device")
            return {"supported": False, "enabled": False}

    async def set_auto_tracking(
        self,
        channel: int = 1,
        enabled: bool = False,
        duration: int = 30,
        sensitivity: int = 50,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Configure PTZ auto-tracking.

        write — gated; channel validated.
        """
        _enforce_read_only(force=force, action="set auto tracking")
        channel = _validate_channel(channel)
        if not self._connected or not self._client:
            await self.connect()

        duration = max(5, min(300, duration))
        sensitivity = max(1, min(100, sensitivity))

        xml_data = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<AutoTracking>"
            f"<enabled>{'true' if enabled else 'false'}</enabled>"
            f"<trackDuration>{duration}</trackDuration>"
            f"<sensitivity>{sensitivity}</sensitivity>"
            "</AutoTracking>"
        )
        url = urljoin(self.base_url, f"/ISAPI/Smart/channels/{channel}/autoTracking")
        try:
            response = await self._request(
                "PUT", url, content=xml_data, timeout=httpx.Timeout(10.0)
            )
            if response.status_code == 200:
                return {
                    "supported": True,
                    "enabled": enabled,
                    "track_duration_sec": duration,
                    "sensitivity": sensitivity,
                }
            return {
                "supported": False,
                "enabled": False,
                "track_duration_sec": 30,
                "sensitivity": 50,
            }
        except Exception:
            logger.exception("Failed to set auto-tracking")
            return {
                "supported": False,
                "enabled": False,
                "track_duration_sec": 30,
                "sensitivity": 50,
            }

    # ── Two-way audio ────────────────────────────────────────────────────

    async def open_two_way_audio(
        self,
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Open a two-way audio session via ISAPI.

        opens a write-back channel — gated.
        """
        _enforce_read_only(force=force, action="open two-way audio")
        channel = _validate_channel(channel)
        if not self._connected or not self._client:
            await self.connect()

        url = urljoin(self.base_url, f"/ISAPI/System/TwoWayAudio/channels/{channel}/open")
        try:
            response = await self._request("PUT", url, timeout=httpx.Timeout(10.0))
            if response.status_code == 200:
                return {"success": True, "channel": channel}
            return {"success": False, "error": "Failed to open audio channel"}
        except Exception:
            logger.exception("Failed to open two-way audio")
            return {"success": False, "error": "Device communication error"}

    async def close_two_way_audio(
        self,
        channel: int = 1,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Close a two-way audio session.

        state change — gated, channel validated.
        """
        _enforce_read_only(force=force, action="close two-way audio")
        channel = _validate_channel(channel)
        if not self._connected or not self._client:
            await self.connect()

        url = urljoin(self.base_url, f"/ISAPI/System/TwoWayAudio/channels/{channel}/close")
        try:
            response = await self._request("PUT", url, timeout=httpx.Timeout(10.0))
            return {"success": response.status_code == 200}
        except Exception:
            logger.exception("Failed to close two-way audio")
            return {"success": False}

    async def send_audio_data(
        self,
        channel: int = 1,
        audio_data: bytes = b"",
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Send audio data chunk to a two-way audio session (G.711u PCM).

        writes audio to remote speaker —
        gated. Channel validated.
        """
        _enforce_read_only(force=force, action="send audio data")
        channel = _validate_channel(channel)
        if not self._connected or not self._client:
            await self.connect()

        if len(audio_data) > 64 * 1024:  # 64KB max per chunk
            return {"success": False, "error": "Audio chunk too large"}

        url = urljoin(self.base_url, f"/ISAPI/System/TwoWayAudio/channels/{channel}/audioData")
        try:
            response = await self._request(
                "PUT",
                url,
                content=audio_data,
                headers={"Content-Type": "application/octet-stream"},
                timeout=httpx.Timeout(5.0),
            )
            return {"success": response.status_code == 200, "bytes_sent": len(audio_data)}
        except Exception:
            return {"success": False, "error": "Audio send failed"}
