# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Omada controller monitor → omada.event.* transition logic + alert taxonomy.

Pure (no DB, no Redis, no network): ``_omada_transitions`` decides which
``omada.event.*`` fire given a prev snapshot vs the current alert read — new
alerts (by id SET, normalized to a canonical class), reachability up/down, and
no re-alert on a re-seen alert id.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.adapters.omada.event_types import (
    DEVICE_OFFLINE,
    FIRMWARE_AVAILABLE,
    GENERIC,
    POE_OVERLOAD,
    ROGUE_AP,
    event_type_for,
    normalize_alert,
    priority_for_level,
)
from app.tasks.omada_monitor import _omada_snapshot, _omada_transitions


def _ctrl():
    return SimpleNamespace(id=uuid.uuid4(), name="OmadaV2", host="192.168.1.250")


def _types(evs) -> set[str]:
    return {e.event_type for e in evs}


class TestNormalizeAlert:
    def test_keyword_classes(self) -> None:
        assert normalize_alert("Device", "AP EAP670 went offline") == DEVICE_OFFLINE
        assert normalize_alert("WIDS", "Rogue AP detected on channel 6") == ROGUE_AP
        assert normalize_alert("Switch", "PoE power budget exceeded") == POE_OVERLOAD
        assert normalize_alert("System", "New firmware update available") == FIRMWARE_AVAILABLE
        assert normalize_alert("Device", "Gateway reconnected") == "device_online"

    def test_unknown_is_generic_not_dropped(self) -> None:
        assert normalize_alert("Misc", "something unclassified") == GENERIC
        assert normalize_alert(None, None) == GENERIC

    def test_priority_for_level(self) -> None:
        assert priority_for_level("error") == "high"
        assert priority_for_level("Critical") == "high"
        assert priority_for_level("info") == "normal"
        assert priority_for_level(None) == "normal"


class TestOmadaTransitions:
    def test_new_alert_emits_normalized_event(self) -> None:
        prev = {"reachable": True, "alert_ids": []}
        cur = {"alerts": [
            {"id": "a1", "category": "Device", "message": "EAP670 offline", "level": "error"},
        ]}
        evs = _omada_transitions(prev, cur, True, _ctrl(), "org-1")
        assert event_type_for(DEVICE_OFFLINE) in _types(evs)
        ev = next(e for e in evs if e.event_type == event_type_for(DEVICE_OFFLINE))
        assert ev.payload["alert_id"] == "a1"
        assert ev.payload["category"] == DEVICE_OFFLINE
        assert ev.payload["raw_category"] == "Device"
        assert str(ev.organization_id) == "org-1"

    def test_no_realert_on_same_alert_id(self) -> None:
        prev = {"reachable": True, "alert_ids": ["a1"]}
        cur = {"alerts": [{"id": "a1", "category": "Device", "message": "EAP670 offline"}]}
        assert _omada_transitions(prev, cur, True, _ctrl(), "o") == []

    def test_rogue_ap_is_security_category(self) -> None:
        from app.core.events import EventCategory

        prev = {"reachable": True, "alert_ids": []}
        cur = {"alerts": [{"id": "r1", "category": "WIDS", "message": "Rogue AP found"}]}
        ev = next(
            e for e in _omada_transitions(prev, cur, True, _ctrl(), "o")
            if e.event_type == event_type_for(ROGUE_AP)
        )
        assert ev.category == EventCategory.SECURITY

    def test_unreachable_then_online(self) -> None:
        evs = _omada_transitions({"reachable": True}, None, False, _ctrl(), "o")
        assert _types(evs) == {"omada.event.controller_unreachable"}
        # staying down → no re-alert
        assert _omada_transitions({"reachable": False}, None, False, _ctrl(), "o") == []
        # recovery
        evs2 = _omada_transitions({"reachable": False}, {"alerts": []}, True, _ctrl(), "o")
        assert "omada.event.controller_online" in _types(evs2)

    def test_alert_cap_bounds_flood(self) -> None:
        prev = {"reachable": True, "alert_ids": []}
        cur = {"alerts": [{"id": str(i), "category": "x", "message": "y"} for i in range(100)]}
        evs = _omada_transitions(prev, cur, True, _ctrl(), "o")
        assert len(evs) == 25  # _MAX_NEW_ALERTS

    def test_snapshot_shape(self) -> None:
        assert _omada_snapshot(False, None) == {"reachable": False}
        snap = _omada_snapshot(True, {"alerts": [{"id": "a1"}, {"id": "a2"}]})
        assert snap["reachable"] is True and snap["alert_ids"] == ["a1", "a2"]
