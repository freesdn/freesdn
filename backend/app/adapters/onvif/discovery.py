# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - ONVIF WS-Discovery
=================================

Discovers ONVIF-compliant cameras on the local network using
WS-Discovery (SOAP over UDP multicast, per ONVIF Core Spec Annex A).

Usage::

    devices = await discover_onvif_devices(timeout=5)
    for dev in devices:
        print(dev["xaddrs"], dev["scopes"])
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import uuid
from typing import Any

from defusedxml.ElementTree import fromstring as _safe_xml_fromstring

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

WS_DISCOVERY_MULTICAST = "239.255.255.250"
WS_DISCOVERY_PORT = 3702
WS_DISCOVERY_MAX_PACKET = 65536
WS_DISCOVERY_MAX_RESPONSES = 500

# XML namespaces used in WS-Discovery / ONVIF probes
_NS = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "d": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "dn": "http://www.onvif.org/ver10/network/wsdl",
}

# WS-Discovery Probe template targeting ONVIF NetworkVideoTransmitter
_PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
    <a:MessageID>urn:uuid:{message_id}</a:MessageID>
    <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </s:Header>
  <s:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </s:Body>
</s:Envelope>"""

# Regex to extract IP addresses from XAddrs
_IP_RE = re.compile(r"https?://([^:/]+)")


# ═══════════════════════════════════════════════════════════════════════════════
# UDP Multicast Protocol
# ═══════════════════════════════════════════════════════════════════════════════


class _DiscoveryProtocol(asyncio.DatagramProtocol):
    """asyncio protocol that collects WS-Discovery ProbeMatch responses."""

    def __init__(self) -> None:
        self.responses: list[bytes] = []
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) > WS_DISCOVERY_MAX_PACKET:
            return  # drop oversized packets
        if len(self.responses) >= WS_DISCOVERY_MAX_RESPONSES:
            return  # cap response count to prevent memory exhaustion
        self.responses.append(data)

    def error_received(self, exc: Exception) -> None:
        logger.debug("WS-Discovery receive error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════


async def discover_onvif_devices(
    timeout: float = 4.0,
    retries: int = 2,
) -> list[dict[str, Any]]:
    """
    Send a WS-Discovery Probe for ONVIF devices and collect responses.

    Args:
        timeout: Seconds to wait for responses per attempt.
        retries: Number of probe attempts (cameras may not answer the first).

    Returns:
        List of dicts, each containing:
        - ``xaddrs``: list of device service URLs
        - ``scopes``: list of scope URIs (contain vendor/model hints)
        - ``ip``: extracted IP address
        - ``vendor``: vendor name parsed from scopes (best-effort)
        - ``model``: model name parsed from scopes (best-effort)
        - ``hardware``: hardware ID parsed from scopes (best-effort)
        - ``epr``: endpoint reference (unique device ID)
    """
    timeout = min(max(0.5, timeout), 30.0)
    retries = min(max(1, retries), 5)
    seen_eprs: set[str] = set()
    devices: list[dict[str, Any]] = []

    for attempt in range(retries):
        try:
            found = await _probe_once(timeout)
        except Exception as exc:
            logger.warning(
                "WS-Discovery probe attempt %d/%d failed: %s",
                attempt + 1,
                retries,
                exc,
            )
            continue

        for dev in found:
            epr = dev.get("epr", "")
            if epr and epr in seen_eprs:
                continue
            if epr:
                seen_eprs.add(epr)
            devices.append(dev)

    logger.info("WS-Discovery found %d unique ONVIF device(s)", len(devices))
    return devices


async def _probe_once(timeout: float) -> list[dict[str, Any]]:
    """Send a single probe and collect responses until timeout."""

    loop = asyncio.get_running_loop()
    message_id = str(uuid.uuid4())
    probe_xml = _PROBE_TEMPLATE.format(message_id=message_id).encode("utf-8")

    # Create a UDP socket for multicast
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_MULTICAST_TTL,
        struct.pack("b", 1),
    )
    sock.setblocking(False)

    try:
        transport, protocol = await loop.create_datagram_endpoint(
            _DiscoveryProtocol,
            sock=sock,
        )
    except Exception:
        sock.close()
        raise

    try:
        # Send probe to multicast group
        transport.sendto(probe_xml, (WS_DISCOVERY_MULTICAST, WS_DISCOVERY_PORT))

        # Wait for responses
        await asyncio.sleep(timeout)
    finally:
        transport.close()

    # Parse all collected responses
    devices: list[dict[str, Any]] = []
    for raw in protocol.responses:
        try:
            dev = _parse_probe_match(raw)
            if dev:
                devices.append(dev)
        except Exception as exc:
            logger.debug("Failed to parse WS-Discovery response: %s", exc)

    return devices


# ═══════════════════════════════════════════════════════════════════════════════
# XML Parsing Helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _parse_probe_match(data: bytes) -> dict[str, Any] | None:
    """Parse a WS-Discovery ProbeMatch response into a device dict."""
    try:
        root = _safe_xml_fromstring(data)
    except Exception:
        return None

    body = root.find("s:Body", _NS)
    if body is None:
        return None

    matches = body.find("d:ProbeMatches", _NS)
    if matches is None:
        return None

    match = matches.find("d:ProbeMatch", _NS)
    if match is None:
        return None

    # Endpoint reference
    epr_el = match.find("a:EndpointReference/a:Address", _NS)
    epr = (epr_el.text or "").strip() if epr_el is not None else ""

    # XAddrs (space-separated list of service URLs)
    xaddrs_el = match.find("d:XAddrs", _NS)
    xaddrs_text = (xaddrs_el.text or "").strip() if xaddrs_el is not None else ""
    xaddrs = xaddrs_text.split() if xaddrs_text else []

    # Scopes (space-separated list of scope URIs)
    scopes_el = match.find("d:Scopes", _NS)
    scopes_text = (scopes_el.text or "").strip() if scopes_el is not None else ""
    scopes = scopes_text.split() if scopes_text else []

    # Extract IP from first XAddr
    ip = ""
    for addr in xaddrs:
        m = _IP_RE.search(addr)
        if m:
            ip = m.group(1)
            break

    # Parse vendor/model from scopes
    vendor, model, hardware = _parse_scopes(scopes)

    if not xaddrs and not ip:
        return None

    return {
        "epr": epr,
        "xaddrs": xaddrs,
        "scopes": scopes,
        "ip": ip,
        "vendor": vendor,
        "model": model,
        "hardware": hardware,
    }


def _parse_scopes(scopes: list[str]) -> tuple[str, str, str]:
    """
    Extract vendor, model, and hardware from ONVIF scope URIs.

    Standard scope prefixes:
    - ``onvif://www.onvif.org/name/<name>``
    - ``onvif://www.onvif.org/hardware/<hardware>``
    - ``onvif://www.onvif.org/Profile/<profile>``
    - ``onvif://www.onvif.org/type/<type>``

    Vendor-specific scopes also appear (e.g. Dahua, Axis, Reolink).
    """
    vendor = ""
    model = ""
    hardware = ""

    for scope in scopes:
        scope_lower = scope.lower()

        if "/name/" in scope_lower:
            # e.g. onvif://www.onvif.org/name/HIKVISION%20DS-2CD2143G0-I
            parts = scope.split("/name/")
            if len(parts) > 1:
                name_val = parts[-1].replace("%20", " ").strip()
                if not vendor:
                    # First token is often vendor
                    tokens = name_val.split()
                    if tokens:
                        vendor = tokens[0]
                        if len(tokens) > 1:
                            model = " ".join(tokens[1:])

        elif "/hardware/" in scope_lower:
            parts = scope.split("/hardware/")
            if len(parts) > 1:
                hardware = parts[-1].replace("%20", " ").strip()
                if not model:
                    model = hardware

        # Vendor detection from scope host
        if not vendor:
            for known in _KNOWN_VENDORS:
                if known.lower() in scope_lower:
                    vendor = known
                    break

    return vendor, model, hardware


_KNOWN_VENDORS = [
    "Hikvision",
    "Dahua",
    "Axis",
    "Reolink",
    "Amcrest",
    "Hanwha",
    "Bosch",
    "Vivotek",
    "GeoVision",
    "Uniview",
    "Tiandy",
    "FLIR",
    "Pelco",
    "Sony",
    "Panasonic",
    "Samsung",
    "Honeywell",
    "TP-LINK",
    "TP-Link",
    "Lorex",
    "Annke",
    "Ubiquiti",
]
