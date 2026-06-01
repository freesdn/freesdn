# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Canonical Omada controller-event taxonomy + raw-alert normalization.

The Omada controller surfaces operational conditions (a device going offline, a
rogue AP, a PoE budget overload, available firmware) as entries in its alert /
event log. ``omada_monitor`` polls that log and emits ``omada.event.*`` Fabric
events on transitions, so "something happens on the Omada network → trigger X"
becomes wirable (e.g. ``omada.event.device_offline → fabric.notify``).

The raw Omada alert strings vary by controller version and aren't fully sampled
yet, so normalization here is intentionally KEYWORD-based and best-effort: a
known class maps to a canonical type; anything else passes through as the generic
``alert`` (never dropped). This mirrors the camera taxonomy
(``app/modules/cameras/event_types.py``) and is refined as real controller
samples are captured (see the live-validation item). Normalizing into a small
vendor-neutral set lets the poller, the Fabric event catalog
(``NetworkModule.get_emitted_events``), and the UI all agree.
"""

from __future__ import annotations

# ── canonical Omada event classes (vendor-neutral) ──────────────────────────
DEVICE_OFFLINE = "device_offline"
DEVICE_ONLINE = "device_online"
ROGUE_AP = "rogue_ap"
POE_OVERLOAD = "poe_overload"
FIRMWARE_AVAILABLE = "firmware_available"
GENERIC = "alert"

#: Ordered keyword → canonical class (first match wins). Keys are matched
#: case-insensitively against the alert's ``category`` + ``message`` combined.
_KEYWORDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("reconnected", "back online", "recovered", "is online", "came online"), DEVICE_ONLINE),
    (("offline", "disconnected", "lost connection", "unreachable", "went down"), DEVICE_OFFLINE),
    (("rogue", "interfering ap", "evil twin"), ROGUE_AP),
    (("poe", "power budget", "power overload", "over budget"), POE_OVERLOAD),
    (("firmware", "upgrade available", "new version", "update available"), FIRMWARE_AVAILABLE),
)


def normalize_alert(category: str | None, message: str | None) -> str:
    """Map a raw Omada alert (category + message) to a canonical class.

    Best-effort + keyword-based; unknown alerts return :data:`GENERIC` (kept,
    not dropped) so they still reach the bus as ``omada.event.alert`` and can be
    classified later once their strings are sampled.
    """
    text = f"{category or ''} {message or ''}".strip().lower()
    if not text:
        return GENERIC
    for keywords, canonical in _KEYWORDS:
        if any(k in text for k in keywords):
            return canonical
    return GENERIC


def event_type_for(canonical: str) -> str:
    """Bus event type for a canonical class — ``omada.event.<canonical>``."""
    return f"omada.event.{canonical}"


def priority_for_level(level: str | None) -> str:
    """Map an Omada alert ``level`` to an EventPriority value string.

    error/critical → high; everything else → normal. Returns the StrEnum *value*
    so callers can pass it straight to ``Event(priority=...)`` without importing
    the enum here (keeps this module dependency-free).
    """
    return (
        "high" if str(level or "").strip().lower() in ("error", "critical", "urgent") else "normal"
    )


#: Canonical classes promoted to their own first-class Fabric trigger (the rest
#: ride the generic ``omada.event.alert``). These are the high-value, reliably
#: actionable conditions an operator is likely to wire an automation to.
PUSH_EVENT_TYPES: frozenset[str] = frozenset(
    {DEVICE_OFFLINE, ROGUE_AP, POE_OVERLOAD, FIRMWARE_AVAILABLE}
)

#: Catalog metadata (title, description) for the declared Fabric event sources —
#: the single source the ``EventSpec`` declarations are built from, so the
#: advertised triggers can't drift from what the poller actually emits.
EVENT_META: dict[str, tuple[str, str]] = {
    DEVICE_OFFLINE: (
        "Omada device offline",
        "An Omada-managed device (AP/switch/gateway) dropped offline per the controller alert log.",
    ),
    ROGUE_AP: (
        "Rogue AP detected",
        "The Omada controller flagged a rogue / interfering access point.",
    ),
    POE_OVERLOAD: (
        "PoE power overload",
        "A switch reported a PoE power-budget overload.",
    ),
    FIRMWARE_AVAILABLE: (
        "Firmware available",
        "New firmware is available for an Omada-managed device.",
    ),
    GENERIC: (
        "Omada controller alert",
        "A controller alert that isn't a more specific class (carries the raw category/message).",
    ),
}
