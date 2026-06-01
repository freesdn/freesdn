# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Overlay mesh device discovery
=======================================

The connected overlay mesh (Tailscale / NetBird) is itself an inventory: every
peer is a reachable device. This module enumerates those peers and classifies
each into an adoptable device candidate using ONLY overlay metadata (OS, ACL
tags, hostname) — no active probing, so it works capless (userspace overlay, no
NET_ADMIN) and needs no egress. Active fingerprinting (probing ports through the
overlay) is a later phase (egress/SOCKS5).

This feeds the "Discovered" inbox: open FreeSDN and see "I found Proxmox / TrueNAS
on your tailnet — adopt?". See docs.freesdn.org.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.config import settings
from app.services.vpn_integration import NetbirdService, TailscaleService

logger = logging.getLogger(__name__)

# Substring/tag -> adapter device type. Tag matches are HIGH confidence (the
# operator deliberately tagged the node); hostname matches are MEDIUM.
_TYPE_HINTS: dict[str, str] = {
    "proxmox": "proxmox",
    "pve": "proxmox",
    "truenas": "truenas",
    "freenas": "truenas",
    "nas": "truenas",
    "opnsense": "opnsense",
    "pfsense": "pfsense",
    "mikrotik": "mikrotik",
    "routeros": "mikrotik",
    "openwrt": "openwrt",
    "hikvision": "camera",
    "nvr": "camera",
    "camera": "camera",
    "freepbx": "freepbx",
    "asterisk": "freepbx",
    "pbx": "freepbx",
    "unifi": "unifi",
    "omada": "omada",
}


def classify_overlay_peer(
    hostname: str, os: str = "", tags: list[str] | None = None
) -> tuple[str, str]:
    """Classify an overlay peer into (suggested_device_type, confidence).

    Pure function (no I/O). Tag match -> high; hostname substring -> medium;
    a known OS but no type signal -> low ("linux"); otherwise ("unknown", "low").
    """
    tags = tags or []

    # 1) ACL tags are the strongest signal — the operator labeled the node.
    for raw in tags:
        tag = raw.split(":", 1)[-1].strip().lower()  # "tag:proxmox" -> "proxmox"
        if tag in _TYPE_HINTS:
            return _TYPE_HINTS[tag], "high"

    # 2) Hostname substrings.
    host = (hostname or "").lower()
    for needle, dtype in _TYPE_HINTS.items():
        if needle in host:
            return dtype, "medium"

    # 3) Fall back to OS family (still adoptable, just unclassified).
    osl = (os or "").lower()
    if osl:
        if "linux" in osl:
            return "linux", "low"
        return osl, "low"

    return "unknown", "low"


async def discover_overlay_devices() -> list[dict[str, Any]]:
    """Enumerate + classify adoptable devices across the connected overlays.

    Capless-safe: if no overlay daemon is reachable (the default), each provider
    block fails gracefully and contributes nothing — the result is just []. The
    controller's own node (self) is excluded; you don't adopt yourself.
    """
    devices: list[dict[str, Any]] = []

    # The api can only enumerate the overlay when IT has overlay access (sidecar
    # mode shares the daemon sockets; userspace runs in-process). When VPN is off
    # there is no overlay reachable from the api — return [] immediately rather
    # than invoking the tailscale/netbird CLIs (which would block ~10s on retry
    # timeouts). The capless "Tailscale access" ingress addon runs in a SEPARATE
    # container whose daemon the api can't see, so it doesn't enable api discovery.
    if settings.resolved_vpn_mode == "off":
        return devices

    # ── Tailscale peers (rich metadata: os + tags) ──────────────────────────────
    try:
        ts = TailscaleService()
        status = await ts.get_status(refresh=True)
        for node in status.peers:  # peers excludes self
            ip = node.primary_ip
            if not ip:
                continue
            dtype, conf = classify_overlay_peer(node.hostname, node.os, node.tags)
            devices.append(
                {
                    "source": "tailscale",
                    "hostname": node.hostname,
                    "magic_dns": node.dns_name,
                    "address": ip,
                    "online": node.online,
                    "os": node.os,
                    "tags": node.tags,
                    "suggested_type": dtype,
                    "confidence": conf,
                }
            )
    except Exception as e:  # noqa: BLE001 - discovery is best-effort, never fatal
        logger.debug("tailscale overlay discovery skipped: %s", e)

    # ── NetBird peers (hostname/ip only; no os/tags in status) ──────────────────
    try:
        nb = NetbirdService()
        for peer in await nb.list_peers():
            ip = peer.get("ip")
            if not ip:
                continue
            host = peer.get("hostname", "") or peer.get("name", "")
            dtype, conf = classify_overlay_peer(host, "", [])
            devices.append(
                {
                    "source": "netbird",
                    "hostname": host,
                    "magic_dns": host,
                    "address": ip,
                    "online": peer.get("status") == "connected",
                    "os": "",
                    "tags": [],
                    "suggested_type": dtype,
                    "confidence": conf,
                }
            )
    except Exception as e:  # noqa: BLE001
        logger.debug("netbird overlay discovery skipped: %s", e)

    return devices


# Process-local set of overlay peers already announced as discovered, keyed by
# (organization_id, source, address). Keeps a request-driven (or future periodic)
# discovery poll from re-announcing the same peer on every run — so a Connection
# wired to ``overlay.peer.discovered → notify`` fires on first sighting, not every
# page load. Bounded by the live peer count (dozens); never persisted.
_announced_peers: set[str] = set()


async def emit_overlay_discovery(
    devices: list[dict[str, Any]],
    *,
    organization_id: str,
    bus: Any = None,
) -> int:
    """Publish an ``overlay.peer.discovered`` Fabric event for each newly-seen,
    not-already-adopted overlay peer; return the number published.

    This is the bridge from discovery to the Fabric: it turns "I found Proxmox on
    your tailnet" into a wireable trigger (``overlay.peer.discovered``, declared by
    the network module's ``get_emitted_events()``). Shared by the ``/vpn/discovery``
    endpoint and any future periodic poller so both emit identically.

    - ``organization_id`` is REQUIRED. The Fabric negotiator is fail-closed on org
      (``handle_event`` drops an event whose ``organization_id`` is None/mismatched),
      so this both routes the event and keeps a discovered peer inside one tenant.
    - The event ``event_type`` is the catalog id ``overlay.peer.discovered`` exactly
      (NOT the ``discovery.`` prefix the :func:`discovery_event` factory would add) —
      otherwise no Connection's ``source_event`` matches and the wiring is silent.
    - Deduplicated per ``(org, source, address)``; ``already_adopted`` peers skipped.
    - Best-effort: a bus failure logs and is swallowed — discovery never breaks.
    """
    if not organization_id or not devices:
        return 0

    from app.core.events import Event, EventCategory, get_event_bus

    bus = bus or get_event_bus()
    emitted = 0
    for d in devices:
        if d.get("already_adopted"):
            continue
        key = f"{organization_id}|{d.get('source')}|{d.get('address')}"
        if key in _announced_peers:
            continue
        try:
            await bus.publish(
                Event(
                    event_type="overlay.peer.discovered",
                    category=EventCategory.SYSTEM,
                    organization_id=organization_id,
                    payload={**d, "organization_id": organization_id},
                )
            )
        except Exception as exc:  # noqa: BLE001 - emission is best-effort
            logger.debug("overlay.peer.discovered emit failed for %s: %s", key, exc)
            continue
        _announced_peers.add(key)
        emitted += 1
    return emitted


def annotate_already_adopted(
    devices: list[dict[str, Any]],
    adopted: list[tuple[Any, str | None, str | None]],
) -> list[dict[str, Any]]:
    """Cross-transport identity (first cut): mark each discovered device that is
    already a managed device, so the inbox doesn't re-offer something you manage
    and can recognise the same box reached on a different transport.

    ``adopted`` is an iterable of ``(device_id, ip_address, name)`` for the org.
    A discovered peer matches an adopted device when its overlay ``address`` equals
    an adopted ``ip_address`` (adopted over the overlay) OR its ``hostname`` equals
    an adopted ``name`` (same box, different transport — e.g. adopted by LAN IP).
    Pure/testable: callers pass the rows; no DB access here. Richer signals
    (cert fingerprint / serial / MAC) are a later phase. See
    docs.freesdn.org.
    """
    by_ip: dict[str, Any] = {}
    by_name: dict[str, Any] = {}
    for did, ip, name in adopted:
        if ip:
            by_ip[ip] = did
        if name:
            by_name[name.strip().lower()] = did
    for d in devices:
        match = by_ip.get(d.get("address") or "") or by_name.get(
            (d.get("hostname") or "").strip().lower()
        )
        d["already_adopted"] = match is not None
        d["adopted_device_id"] = str(match) if match is not None else None
    return devices
