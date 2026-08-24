# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the TrueNAS health monitor: the rollup + the transition logic.

These are pure (no DB, no network): summarize_health classifies pool/alert/temp
state, and _transitions decides which storage.* events fire given a prev
snapshot vs the current reading — the enterprise "emit only on the edge" rule.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.modules.storage.health import summarize_health
from app.tasks.storage import _transitions


class _Usage:
    def __init__(self, size: int, alloc: int) -> None:
        self.size = size
        self.allocated = alloc


class _Pool:
    def __init__(self, name: str, status: str, size: int = 100, alloc: int = 10) -> None:
        self.name = name
        self.status = status
        self.usage = _Usage(size, alloc)


class TestSummarizeHealth:
    def test_ok(self) -> None:
        s = summarize_health([_Pool("tank", "ONLINE")], [], {})
        assert s["status"] == "ok" and s["degraded_pools"] == [] and s["over_capacity_pools"] == []

    def test_degraded_is_warning(self) -> None:
        s = summarize_health([_Pool("tank", "DEGRADED")], [], {})
        assert s["status"] == "warning" and "tank" in s["degraded_pools"]

    def test_faulted_is_error(self) -> None:
        s = summarize_health([_Pool("tank", "FAULTED")], [], {})
        assert s["status"] == "error" and "tank" in s["degraded_pools"]

    def test_capacity_threshold(self) -> None:
        s = summarize_health([_Pool("tank", "ONLINE", 100, 90)], [], {}, capacity_warn_pct=85)
        assert "tank" in s["over_capacity_pools"] and s["status"] == "warning"
        assert s["pools"][0]["capacity_pct"] == 90.0

    def test_critical_alert_and_temp(self) -> None:
        s = summarize_health([_Pool("tank", "ONLINE")], [{"level": "CRITICAL"}], {"da0": 45.0, "da1": 39})
        assert s["critical_alerts"] == 1 and s["status"] == "warning" and s["max_temp_c"] == 45.0


def _ctrl(controller_type: str = "truenas"):
    """A Controller stand-in.

    ``controller_type`` is not optional on the real model, and leaving it off
    here meant the double could not represent the thing the events now carry --
    the sweep covers more than one vendor, so "storage.appliance.unreachable"
    without a vendor makes an operator open the UI to find out which box.
    """
    return SimpleNamespace(id=uuid.uuid4(), name="S4", controller_type=controller_type)


def _types(evs) -> set[str]:
    return {e.event_type for e in evs}


def _summary(degraded=None, overcap=None, crit=0):
    return {
        "status": "ok",
        "degraded_pools": degraded or [],
        "over_capacity_pools": overcap or [],
        "critical_alerts": crit,
        "pools": [{"name": "tank", "capacity_pct": 91.0}],
    }


class TestTransitions:
    def test_pool_degraded_edge(self) -> None:
        prev = {"reachable": True, "degraded_pools": [], "over_capacity_pools": [], "critical_alerts": 0}
        evs = _transitions(prev, _summary(degraded=["tank"]), True, _ctrl(), uuid.uuid4())
        assert "storage.pool.degraded" in _types(evs)

    def test_pool_recovery_edge(self) -> None:
        prev = {"reachable": True, "degraded_pools": ["tank"], "over_capacity_pools": [], "critical_alerts": 0}
        evs = _transitions(prev, _summary(degraded=[]), True, _ctrl(), uuid.uuid4())
        assert "storage.pool.healthy" in _types(evs)

    def test_no_event_on_steady_degraded(self) -> None:
        # already-degraded pool must NOT re-emit every poll (the edge rule)
        prev = {"reachable": True, "degraded_pools": ["tank"], "over_capacity_pools": [], "critical_alerts": 0}
        evs = _transitions(prev, _summary(degraded=["tank"]), True, _ctrl(), uuid.uuid4())
        assert evs == []

    def test_capacity_warning_edge(self) -> None:
        prev = {"reachable": True, "degraded_pools": [], "over_capacity_pools": [], "critical_alerts": 0}
        evs = _transitions(prev, _summary(overcap=["tank"]), True, _ctrl(), uuid.uuid4())
        assert "storage.capacity.warning" in _types(evs)

    def test_critical_alert_increase(self) -> None:
        prev = {"reachable": True, "degraded_pools": [], "over_capacity_pools": [], "critical_alerts": 1}
        evs = _transitions(prev, _summary(crit=3), True, _ctrl(), uuid.uuid4())
        assert "storage.alert.critical" in _types(evs)

    def test_unreachable_then_online(self) -> None:
        prev = {"reachable": True}
        evs = _transitions(prev, None, False, _ctrl(), uuid.uuid4())
        assert _types(evs) == {"storage.appliance.unreachable"}
        # recovery
        evs2 = _transitions({"reachable": False}, _summary(), True, _ctrl(), uuid.uuid4())
        assert "storage.appliance.online" in _types(evs2)

    def test_events_carry_org_and_source(self) -> None:
        org = uuid.uuid4()
        evs = _transitions({"reachable": True, "degraded_pools": []}, _summary(degraded=["tank"]), True, _ctrl(), org)
        e = evs[0]
        assert str(e.organization_id) == str(org) and e.source == "storage"


def test_every_event_names_its_vendor():
    """
    The sweep is multi-vendor now. An event that says an appliance is
    unreachable, without saying what kind, sends the operator to the UI to
    work out which box and which credentials.
    """
    events = _transitions({}, None, False, _ctrl("proxmox"), uuid.uuid4())

    assert events
    for ev in events:
        assert ev.payload["vendor"] == "proxmox"


def test_the_unreachable_detail_is_not_hardcoded_to_one_vendor():
    events = _transitions({}, None, False, _ctrl("proxmox"), uuid.uuid4())

    assert "TrueNAS" not in events[0].payload["detail"]
    assert "proxmox" in events[0].payload["detail"]
