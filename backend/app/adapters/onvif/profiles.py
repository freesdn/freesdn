# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - ONVIF Profile Detection & Capabilities
====================================================

Detects which ONVIF profiles (S, G, T) and services a camera
supports, and normalises them into FreeSDN capabilities.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.adapters.capabilities import Capability

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Profile Definitions
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ONVIFProfile:
    """Represents a detected ONVIF profile with its version."""

    name: str  # "S", "G", "T", "C", "A", "Q"
    version: str = ""  # e.g. "1.0"

    def __str__(self) -> str:
        return f"Profile {self.name}" + (f" v{self.version}" if self.version else "")


@dataclass
class ONVIFCapabilities:
    """Aggregated capabilities detected from an ONVIF device."""

    profiles: list[ONVIFProfile] = field(default_factory=list)

    # Service endpoints discovered via GetServices / GetCapabilities
    has_media: bool = False
    has_media2: bool = False
    has_ptz: bool = False
    has_imaging: bool = False
    has_recording: bool = False
    has_replay: bool = False
    has_search: bool = False
    has_events: bool = False
    has_analytics: bool = False
    has_device_io: bool = False

    # Granular feature flags derived from probing
    has_pull_point: bool = False
    has_basic_notification: bool = False
    has_audio: bool = False
    has_two_way_audio: bool = False
    has_onvif_streaming: bool = False

    # Counts
    video_source_count: int = 0
    audio_source_count: int = 0
    ptz_node_count: int = 0

    # Raw service map  {namespace_suffix -> xaddr}
    services: dict[str, str] = field(default_factory=dict)

    def profile_names(self) -> list[str]:
        return [p.name for p in self.profiles]

    def to_freesdn_capabilities(self, device_type: str = "camera") -> list[Capability]:
        """Map ONVIF capabilities to FreeSDN Capability enums."""

        caps: list[Capability] = [Capability.DEVICE_INFO]

        if self.has_media or self.has_media2:
            caps.append(Capability.CAMERA_SNAPSHOT)
            caps.append(Capability.CAMERA_STREAM_RTSP)

        if self.has_ptz:
            caps.append(Capability.CAMERA_PTZ)
            caps.append(Capability.CAMERA_PTZ_PRESETS)

        if self.has_imaging:
            caps.append(Capability.CAMERA_PRIVACY_MASK)
            caps.append(Capability.CAMERA_OSD)

        if self.has_recording or self.has_replay:
            caps.append(Capability.CAMERA_RECORDING)
            caps.append(Capability.CAMERA_PLAYBACK)

        if self.has_search:
            caps.append(Capability.NVR_SEARCH)

        if self.has_events or self.has_pull_point:
            caps.append(Capability.CAMERA_MOTION_DETECTION)

        if self.has_audio:
            caps.append(Capability.CAMERA_AUDIO)

        if self.has_two_way_audio:
            caps.append(Capability.CAMERA_TWO_WAY_AUDIO)

        if self.has_analytics:
            caps.append(Capability.CAMERA_AI_LINE_CROSSING)

        caps.append(Capability.DEVICE_REBOOT)

        return caps


# ═══════════════════════════════════════════════════════════════════════════════
# Service Namespace Constants
# ═══════════════════════════════════════════════════════════════════════════════

# Trailing path segments used in ONVIF WSDL / GetServices responses
NS_DEVICE = "device/wsdl"
NS_MEDIA = "media/wsdl"
NS_MEDIA2 = "media/wsdl/ver20"
NS_PTZ = "ptz/wsdl"
NS_IMAGING = "imaging/wsdl"
NS_RECORDING = "recording/wsdl"
NS_REPLAY = "replay/wsdl"
NS_SEARCH = "search/wsdl"
NS_EVENTS = "events/wsdl"
NS_ANALYTICS = "analytics/wsdl"
NS_DEVICE_IO = "deviceIO/wsdl"

# Map namespace suffixes to attribute names on ONVIFCapabilities
_NS_TO_ATTR: dict[str, str] = {
    NS_MEDIA: "has_media",
    NS_MEDIA2: "has_media2",
    NS_PTZ: "has_ptz",
    NS_IMAGING: "has_imaging",
    NS_RECORDING: "has_recording",
    NS_REPLAY: "has_replay",
    NS_SEARCH: "has_search",
    NS_EVENTS: "has_events",
    NS_ANALYTICS: "has_analytics",
    NS_DEVICE_IO: "has_device_io",
}


def parse_services_response(services: list[dict[str, Any]]) -> ONVIFCapabilities:
    """
    Build ONVIFCapabilities from the result of GetServices.

    Each service dict is expected to have at least ``Namespace`` and ``XAddr``.
    """
    caps = ONVIFCapabilities()

    for svc in services:
        ns = svc.get("Namespace", svc.get("namespace", ""))
        xaddr = svc.get("XAddr", svc.get("xaddr", ""))

        # Store raw endpoint
        caps.services[ns] = xaddr

        # Flip boolean flags
        for suffix, attr in _NS_TO_ATTR.items():
            if ns.endswith(suffix) or suffix.replace("/wsdl", "") in ns.lower():
                setattr(caps, attr, True)
                break

    return caps


def parse_legacy_capabilities(cap_response: dict[str, Any]) -> ONVIFCapabilities:
    """
    Fallback parser for the older ``GetCapabilities`` response.

    Works with the dict structure returned by ``onvif-zeep``'s
    ``devicemgmt.GetCapabilities({"Category": "All"})``.
    """
    caps = ONVIFCapabilities()

    if cap_response.get("Media"):
        caps.has_media = True
        xaddr = _extract_xaddr(cap_response["Media"])
        if xaddr:
            caps.services[NS_MEDIA] = xaddr

    if cap_response.get("PTZ"):
        caps.has_ptz = True
        xaddr = _extract_xaddr(cap_response["PTZ"])
        if xaddr:
            caps.services[NS_PTZ] = xaddr

    if cap_response.get("Imaging"):
        caps.has_imaging = True
        xaddr = _extract_xaddr(cap_response["Imaging"])
        if xaddr:
            caps.services[NS_IMAGING] = xaddr

    if cap_response.get("Events"):
        caps.has_events = True
        xaddr = _extract_xaddr(cap_response["Events"])
        if xaddr:
            caps.services[NS_EVENTS] = xaddr

    if cap_response.get("Recording"):
        caps.has_recording = True
        xaddr = _extract_xaddr(cap_response["Recording"])
        if xaddr:
            caps.services[NS_RECORDING] = xaddr

    if cap_response.get("Replay"):
        caps.has_replay = True
        xaddr = _extract_xaddr(cap_response["Replay"])
        if xaddr:
            caps.services[NS_REPLAY] = xaddr

    if cap_response.get("Search"):
        caps.has_search = True
        xaddr = _extract_xaddr(cap_response["Search"])
        if xaddr:
            caps.services[NS_SEARCH] = xaddr

    if cap_response.get("Analytics"):
        caps.has_analytics = True
        xaddr = _extract_xaddr(cap_response["Analytics"])
        if xaddr:
            caps.services[NS_ANALYTICS] = xaddr

    return caps


def _extract_xaddr(section: Any) -> str:
    """Safely extract ``XAddr`` from a capability section."""
    if isinstance(section, dict):
        return section.get("XAddr", "")
    # zeep object
    if hasattr(section, "XAddr"):
        return str(section.XAddr) if section.XAddr else ""
    return ""
