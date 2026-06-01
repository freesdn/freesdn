# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Canonical camera-event taxonomy + raw-vendor normalization.

This is the SINGLE SOURCE OF TRUTH for camera alert/event types. It exists
because the vendor-native strings vary (and were previously guessed): Hikvision
ISAPI ``/alertStream`` emits, for example, ``linedetection`` for a line-crossing
event — NOT ``linecrossing`` — so the old hard-coded push set never recognized
line crossing and those alerts were silently dropped before ever reaching the
event bus (and thus the automation Fabric). Normalizing every raw type into a
small vendor-neutral set fixes that and lets the ingest gate, the Fabric event
catalog (``CamerasModule.get_emitted_events``), and the UI all agree.

Canonical types are emitted on the bus as ``camera.alert.<canonical>`` and stored
as ``CameraEvent.event_type``; the original vendor string is preserved in
``CameraEvent.metadata_json['raw_event_type']`` for fidelity.
"""

from __future__ import annotations

# ── canonical alert types (vendor-neutral) ──────────────────────────────────
MOTION = "motion"
LINE_CROSS = "line_cross"
INTRUSION = "intrusion"
FACE = "face"
TAMPER = "tamper"
VIDEO_LOSS = "video_loss"

#: raw vendor ``eventType`` (lowercased) → canonical. Absorbs Hikvision firmware
#: variants so a real device's strings normalize correctly regardless of model.
_ALIASES: dict[str, str] = {
    # motion / VMD
    "vmd": MOTION,
    "motion": MOTION,
    "motiondetection": MOTION,
    # line crossing — Hikvision's native string is ``linedetection``
    "linedetection": LINE_CROSS,
    "linecrossing": LINE_CROSS,
    "line_cross": LINE_CROSS,
    "crosslinedetection": LINE_CROSS,
    "crossline": LINE_CROSS,
    # intrusion / field / region enter-exit
    "fielddetection": INTRUSION,
    "intrusion": INTRUSION,
    "regionentrance": INTRUSION,
    "regionexiting": INTRUSION,
    "regionexit": INTRUSION,
    "perimeter": INTRUSION,
    # face / person
    "facedetection": FACE,
    "face": FACE,
    # tamper / occlusion / scene-change
    "shelteralarm": TAMPER,
    "tamperdetection": TAMPER,
    "tamper": TAMPER,
    "videotampering": TAMPER,
    "scenechangedetection": TAMPER,
    # video loss
    "videoloss": VIDEO_LOSS,
    "video_loss": VIDEO_LOSS,
    "videomismatch": VIDEO_LOSS,
}


def normalize_event_type(raw: str | None) -> str:
    """Map a raw vendor ``eventType`` to a canonical type.

    Unknown types pass through lowercased (so they remain stored/queryable and
    can be added to the alias table later) rather than being lost.
    """
    if not raw:
        return "unknown"
    key = str(raw).strip().lower()
    return _ALIASES.get(key, key)


#: Canonical alert types that warrant a real-time push/dispatch onto the event
#: bus — i.e. the ones exposed as Fabric automation triggers. ``motion`` and
#: ``video_loss`` are intentionally excluded as too chatty for a default push;
#: they stay persisted + queryable in the Review feed.
PUSH_ALERT_TYPES: frozenset[str] = frozenset({LINE_CROSS, INTRUSION, TAMPER, FACE})

#: Catalog metadata (title, description) for each pushed alert type — the single
#: source the Fabric ``EventSpec`` declarations are built from, so the advertised
#: triggers can never drift from what actually fires.
ALERT_EVENT_META: dict[str, tuple[str, str]] = {
    LINE_CROSS: (
        "Line crossing detected",
        "A camera's line-crossing rule tripped — a tracked object crossed a virtual tripwire.",
    ),
    INTRUSION: (
        "Intrusion detected",
        "A camera's intrusion / field-detection rule fired — an object entered a guarded zone.",
    ),
    TAMPER: (
        "Camera tamper detected",
        "A camera reported tampering / occlusion — the lens was blocked, moved, or covered.",
    ),
    FACE: (
        "Face detected",
        "A camera's face-detection fired.",
    ),
}
