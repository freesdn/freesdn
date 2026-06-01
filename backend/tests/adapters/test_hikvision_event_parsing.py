# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Hikvision alertStream parsing → canonical taxonomy (device-free).

Locks the automation-critical chain: the adapter parses the device-native
``<eventType>`` out of a real ``EventNotificationAlert`` (namespaced) XML chunk,
and the camera taxonomy normalizes it to the canonical type the Fabric fires on.
This is exactly where the line-crossing bug lived — Hikvision sends
``linedetection``, which must become ``line_cross`` and be push-worthy.
"""
from __future__ import annotations

import pytest

from app.adapters.hikvision.adapter import HikvisionAdapter, _parse_xml
from app.modules.cameras.event_types import (
    INTRUSION,
    LINE_CROSS,
    MOTION,
    PUSH_ALERT_TYPES,
    TAMPER,
    normalize_event_type,
)

_NS = "http://www.hikvision.com/ver20/XMLSchema"


def _alert_xml(event_type: str, *, channel: int = 1, target: str | None = None) -> str:
    target_block = (
        f"""
      <DetectionRegionList>
        <DetectionRegionEntry><detectionTarget>{target}</detectionTarget></DetectionRegionEntry>
      </DetectionRegionList>"""
        if target
        else ""
    )
    return f"""<EventNotificationAlert version="2.0" xmlns="{_NS}">
      <ipAddress>192.168.254.{channel}</ipAddress>
      <channelID>{channel}</channelID>
      <dateTime>2026-06-17T10:00:00+00:00</dateTime>
      <activePostCount>1</activePostCount>
      <eventType>{event_type}</eventType>
      <eventState>active</eventState>
      <eventDescription>{event_type} alarm</eventDescription>{target_block}
    </EventNotificationAlert>"""


def _parse(xml: str) -> dict:
    root = _parse_xml(xml)
    assert root is not None, "XML failed to parse"
    return HikvisionAdapter._parse_alert(root)


def test_parse_line_crossing_extracts_native_fields() -> None:
    a = _parse(_alert_xml("linedetection", channel=2))
    assert a["event_type"] == "linedetection"  # device-native string preserved
    assert a["channel_id"] == 2
    assert a["event_state"] == "active"
    assert a["date_time"].startswith("2026-06-17T10:00:00")


@pytest.mark.parametrize(
    "native,canonical,pushed",
    [
        ("linedetection", LINE_CROSS, True),   # the headline bug
        ("fielddetection", INTRUSION, True),
        ("shelteralarm", TAMPER, True),
        ("VMD", MOTION, False),                # motion is parsed but NOT pushed
    ],
)
def test_parsed_event_type_normalizes_and_gates(native: str, canonical: str, pushed: bool) -> None:
    a = _parse(_alert_xml(native))
    got = normalize_event_type(a["event_type"])
    assert got == canonical
    assert (got in PUSH_ALERT_TYPES) is pushed


def test_smart_target_type_extracted_from_nested_region() -> None:
    # AcuSense/DeepinMind classify the object; we capture it for Person/Vehicle filtering.
    a = _parse(_alert_xml("linedetection", target="human"))
    assert a["target_type"] == "human"


def test_basic_event_has_empty_target_type() -> None:
    a = _parse(_alert_xml("VMD"))
    assert a["target_type"] == ""


def test_malformed_xml_returns_none() -> None:
    assert _parse_xml("<EventNotificationAlert><unclosed>") is None
