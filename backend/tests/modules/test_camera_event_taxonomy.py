# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Canonical camera-event taxonomy: normalization + catalog/dispatch drift guard.

Locks the fix for the line-crossing bug — Hikvision emits ``linedetection`` for
line crossing, which the old hard-coded set never recognized, so those alerts
were dropped before reaching the bus / automation Fabric.
"""
from __future__ import annotations

import pytest

from app.modules.cameras.event_types import (
    ALERT_EVENT_META,
    FACE,
    INTRUSION,
    LINE_CROSS,
    MOTION,
    PUSH_ALERT_TYPES,
    TAMPER,
    VIDEO_LOSS,
    normalize_event_type,
)


@pytest.mark.parametrize(
    "raw,canonical",
    [
        # The headline bug: Hikvision's native line-crossing string.
        ("linedetection", LINE_CROSS),
        ("LineDetection", LINE_CROSS),  # case-insensitive
        ("linecrossing", LINE_CROSS),
        ("crossLineDetection", LINE_CROSS),
        ("fielddetection", INTRUSION),
        ("regionEntrance", INTRUSION),
        ("VMD", MOTION),
        ("motionDetection", MOTION),
        ("facedetection", FACE),
        ("shelteralarm", TAMPER),
        ("tamperdetection", TAMPER),
        ("videoloss", VIDEO_LOSS),
        ("  VMD  ", MOTION),  # whitespace-trimmed
    ],
)
def test_normalize_known_vendor_types(raw: str, canonical: str) -> None:
    assert normalize_event_type(raw) == canonical


def test_normalize_unknown_passes_through_lowercased() -> None:
    # Unknown types are preserved (lowercased) so they stay queryable and can be
    # mapped later — never silently lost.
    assert normalize_event_type("SomeNewSmartEvent") == "somenewsmartevent"


def test_normalize_empty_is_unknown() -> None:
    assert normalize_event_type("") == "unknown"
    assert normalize_event_type(None) == "unknown"


def test_alert_meta_matches_push_set() -> None:
    # The catalog metadata and the dispatch gate are driven from the same set.
    assert set(ALERT_EVENT_META) == set(PUSH_ALERT_TYPES)


def test_catalog_triggers_match_dispatch_set_no_drift() -> None:
    """The Fabric catalog's camera.alert.* triggers must EXACTLY match the
    canonical types the ingest actually dispatches — no advertised-but-dead
    triggers (the previous cameras.event.* bug) and no fired-but-hidden ones."""
    from app.modules.cameras.module import CamerasModule

    events = CamerasModule().get_emitted_events()
    advertised = {
        e.event_type[len("camera.alert.") :]
        for e in events
        if e.event_type.startswith("camera.alert.")
    }
    assert advertised == set(PUSH_ALERT_TYPES)


def test_push_set_includes_line_cross() -> None:
    # Regression: line crossing MUST be a dispatched, automatable trigger.
    assert LINE_CROSS in PUSH_ALERT_TYPES


# ── alert dedup key (so one real event isn't re-ingested every 30s poll) ──────
def test_alert_dedup_key_collapses_tz_and_subsecond() -> None:
    import uuid
    from datetime import UTC, datetime, timedelta, timezone

    from app.tasks.cameras import _alert_dedup_key

    cam = uuid.uuid4()
    # Same instant expressed tz-aware UTC, naive (assumed UTC), with sub-second
    # jitter, and via a different tz offset — must all collapse to ONE key so a
    # re-polled buffered event dedups against the stored row.
    a = _alert_dedup_key(cam, "line_cross", datetime(2026, 6, 17, 10, 0, 0, tzinfo=UTC))
    b = _alert_dedup_key(cam, "line_cross", datetime(2026, 6, 17, 10, 0, 0))  # naive
    c = _alert_dedup_key(cam, "line_cross", datetime(2026, 6, 17, 10, 0, 0, 999000, tzinfo=UTC))
    d = _alert_dedup_key(
        cam, "line_cross", datetime(2026, 6, 17, 12, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    )
    assert a == b == c == d
    # A different second, camera, or type is a DISTINCT event (not deduped).
    assert _alert_dedup_key(cam, "line_cross", datetime(2026, 6, 17, 10, 0, 1, tzinfo=UTC)) != a
    assert _alert_dedup_key(uuid.uuid4(), "line_cross", datetime(2026, 6, 17, 10, 0, 0, tzinfo=UTC)) != a
    assert _alert_dedup_key(cam, "intrusion", datetime(2026, 6, 17, 10, 0, 0, tzinfo=UTC)) != a
