# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the firewall/gateway health monitor transition logic.

Pure (no DB, no network): _fw_transitions decides which firewall.event.* fire
given a prev snapshot vs the current reading — IDS-critical by signature SET (no
re-alert on re-trigger), WAN up/down by per-gateway status, and reachability.
"""
from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest

from app.tasks import firewall_monitor
from app.tasks.firewall_monitor import _fw_snapshot, _fw_transitions, _read_current


def _gw():
    return SimpleNamespace(id=uuid.uuid4(), name="edge-fw", vendor="opnsense", host="10.0.0.1", org_id=uuid.uuid4())


def _types(evs) -> set[str]:
    return {e.event_type for e in evs}


class TestFirewallTransitions:
    def test_ids_critical_new_signature(self) -> None:
        prev = {"reachable": True, "gateways": {}, "critical_sids": ["2001219"]}
        cur = {"gateways": {}, "critical_sids": ["2001219", "2100498"]}
        evs = _fw_transitions(prev, cur, True, _gw())
        assert "firewall.event.ids_critical" in _types(evs)
        ev = next(e for e in evs if e.event_type == "firewall.event.ids_critical")
        assert ev.payload["new_signatures"] == ["2100498"] and ev.payload["count"] == 1

    def test_ids_critical_carries_source_ips(self) -> None:
        # The event must carry the attacker source IPs so a Connection can
        # auto-respond (ids_critical → firewall.block_ip).
        prev = {"reachable": True, "gateways": {}, "critical_sids": []}
        cur = {
            "gateways": {}, "critical_sids": ["2100498"],
            "critical_src_ips": ["203.0.113.7", "198.51.100.9"],
        }
        ev = next(
            e for e in _fw_transitions(prev, cur, True, _gw())
            if e.event_type == "firewall.event.ids_critical"
        )
        assert ev.payload["source_ips"] == ["198.51.100.9", "203.0.113.7"]  # sorted
        assert ev.payload["source_ip"] == "198.51.100.9"  # convenience: first

    def test_ids_no_realert_on_same_signature(self) -> None:
        prev = {"reachable": True, "gateways": {}, "critical_sids": ["2001219"]}
        cur = {"gateways": {}, "critical_sids": ["2001219"]}
        assert _fw_transitions(prev, cur, True, _gw()) == []

    def test_wan_down_edge(self) -> None:
        prev = {"reachable": True, "gateways": {"WAN": "up"}, "critical_sids": []}
        cur = {"gateways": {"WAN": "down"}, "critical_sids": []}
        assert "firewall.event.wan_down" in _types(_fw_transitions(prev, cur, True, _gw()))

    def test_wan_recovery_edge(self) -> None:
        prev = {"reachable": True, "gateways": {"WAN": "down"}, "critical_sids": []}
        cur = {"gateways": {"WAN": "up"}, "critical_sids": []}
        assert "firewall.event.wan_up" in _types(_fw_transitions(prev, cur, True, _gw()))

    def test_no_event_on_steady_down(self) -> None:
        prev = {"reachable": True, "gateways": {"WAN": "down"}, "critical_sids": []}
        cur = {"gateways": {"WAN": "down"}, "critical_sids": []}
        assert _fw_transitions(prev, cur, True, _gw()) == []

    def test_unreachable_then_online(self) -> None:
        evs = _fw_transitions({"reachable": True}, None, False, _gw())
        assert _types(evs) == {"firewall.event.gateway_unreachable"}
        evs2 = _fw_transitions({"reachable": False}, {"gateways": {}, "critical_sids": []}, True, _gw())
        assert "firewall.event.gateway_online" in _types(evs2)

    def test_events_carry_org_and_source(self) -> None:
        gw = _gw()
        evs = _fw_transitions({"reachable": True, "gateways": {"WAN": "up"}}, {"gateways": {"WAN": "down"}}, True, gw)
        e = evs[0]
        assert str(e.organization_id) == str(gw.org_id) and e.source == "firewall"

    def test_snapshot_shape(self) -> None:
        assert _fw_snapshot(False, None) == {"reachable": False}
        snap = _fw_snapshot(True, {"gateways": {"WAN": "up"}, "critical_sids": ["1"]})
        assert snap["reachable"] is True and snap["gateways"] == {"WAN": "up"} and snap["critical_sids"] == ["1"]


class TestReadCurrentTimeout:
    """A gateway that connects but then stalls a read must not hang the whole
    poll cycle — each read is bounded by ``_READ_TIMEOUT`` and a timeout is
    swallowed (that signal is skipped, reachability still applies)."""

    @pytest.mark.asyncio
    async def test_hung_read_times_out_and_degrades(self, monkeypatch) -> None:
        monkeypatch.setattr(firewall_monitor, "_READ_TIMEOUT", 0.05)

        class _Hang:
            async def get_gateway_status(self):
                await asyncio.sleep(1.0)  # exceeds patched timeout

            async def get_ids_alerts(self):
                await asyncio.sleep(1.0)

        cur = await _read_current(_Hang())
        # Both reads timed out → suppressed → defaults; no exception escapes.
        assert cur == {"gateways": {}, "critical_sids": []}

    @pytest.mark.asyncio
    async def test_normal_reads_populate(self, monkeypatch) -> None:
        monkeypatch.setattr(firewall_monitor, "_READ_TIMEOUT", 5.0)

        class _OK:
            async def get_gateway_status(self):
                return SimpleNamespace(
                    success=True, data={"gateways": [{"name": "WAN", "status": "up"}]}
                )

            async def get_ids_alerts(self):
                return SimpleNamespace(
                    success=True,
                    data={"alerts": [
                        {"alert_sid": "111", "severity": "critical"},
                        {"alert_sid": "222", "severity": "low"},
                    ]},
                )

        cur = await _read_current(_OK())
        assert cur["gateways"] == {"WAN": "up"}
        assert cur["critical_sids"] == ["111"]
