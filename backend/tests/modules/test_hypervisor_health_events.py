# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Hypervisor (Proxmox) Fabric health events: transition diff + catalog drift guard.

Locks the automation unlock: the module now declares hypervisor.* events AND a
poller publishes them on cluster state transitions — so the advertised triggers
can't drift from what fires (the camera bug we previously fixed). Device-free.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.tasks.hypervisor import _read_cluster_status, _snapshot, _transitions

_CTRL = SimpleNamespace(id=uuid.uuid4(), name="pve-cluster")
_ORG = uuid.uuid4()


def _types(prev, status, reachable=True):
    return [e.event_type for e in _transitions(prev, status, reachable, _CTRL, _ORG)]


def test_first_seen_offline_node_fires_offline_only() -> None:
    # prev empty (first poll): an already-offline node surfaces as offline;
    # an online node does NOT fire (online is recovery-only).
    types = _types({}, {"quorate": True, "nodes": {"pve1": "online", "pve2": "offline"}})
    assert types == ["hypervisor.node.offline"]


def test_node_online_to_offline_transition() -> None:
    prev = {"reachable": True, "quorate": True, "nodes": {"pve1": "online"}}
    assert _types(prev, {"quorate": True, "nodes": {"pve1": "offline"}}) == [
        "hypervisor.node.offline"
    ]


def test_node_offline_to_online_recovery() -> None:
    prev = {"reachable": True, "quorate": True, "nodes": {"pve1": "offline"}}
    assert _types(prev, {"quorate": True, "nodes": {"pve1": "online"}}) == [
        "hypervisor.node.online"
    ]


def test_steady_offline_node_is_silent() -> None:
    prev = {"reachable": True, "quorate": True, "nodes": {"pve1": "offline"}}
    assert _types(prev, {"quorate": True, "nodes": {"pve1": "offline"}}) == []


def test_quorum_lost_and_regained() -> None:
    prev_q = {"reachable": True, "quorate": True, "nodes": {}}
    assert "hypervisor.cluster.inquorate" in _types(prev_q, {"quorate": False, "nodes": {}})
    prev_nq = {"reachable": True, "quorate": False, "nodes": {}}
    assert "hypervisor.cluster.quorate" in _types(prev_nq, {"quorate": True, "nodes": {}})


def test_unreachable_fires_once_then_silent() -> None:
    # reachable→unreachable fires; staying unreachable is silent.
    assert _types({"reachable": True}, None, reachable=False) == [
        "hypervisor.controller.unreachable"
    ]
    assert _types({"reachable": False}, None, reachable=False) == []


def test_reachable_again_fires_online() -> None:
    types = _types({"reachable": False}, {"quorate": True, "nodes": {}}, reachable=True)
    assert "hypervisor.controller.online" in types


# ── Reachability fallback: cluster-status perms gap must NOT read as down ──


class _R:
    def __init__(self, success, data):
        self.success = success
        self.data = data
        self.error = None


class _FallbackAdapter:
    """cluster_status fails (perms/standalone), but /nodes works → reachable."""

    def __init__(self, cluster_raises=False):
        self._cluster_raises = cluster_raises

    async def get_cluster_status(self):
        if self._cluster_raises:
            raise RuntimeError("Permission check failed (/, Sys.Audit)")
        return _R(False, None)

    async def get_nodes(self):
        return _R(True, [
            SimpleNamespace(node="s1", status="online"),
            SimpleNamespace(node="s2", status="offline"),
        ])


@pytest.mark.asyncio
@pytest.mark.parametrize("raises", [True, False])
async def test_cluster_status_perms_gap_falls_back_to_nodes(raises) -> None:
    # A token without Sys.Audit (cluster_status 403 / unsuccessful) is STILL
    # reachable — fall back to /nodes rather than report unreachable.
    status = await _read_cluster_status(_FallbackAdapter(cluster_raises=raises))
    assert status is not None  # ⇒ caller keeps reachable=True
    assert status["nodes"] == {"s1": "online", "s2": "offline"}
    assert status["quorum_unknown"] is True


@pytest.mark.asyncio
async def test_fallback_returns_none_when_nodes_also_unavailable() -> None:
    class _DeadAdapter:
        async def get_cluster_status(self):
            raise RuntimeError("down")

        async def get_nodes(self):
            return _R(False, None)

    assert await _read_cluster_status(_DeadAdapter()) is None  # ⇒ unreachable


def test_quorum_unknown_skips_quorum_events_but_still_diffs_nodes() -> None:
    # Fallback reading: quorum can't be observed, so no quorate/inquorate edge
    # fires even though prev was quorate — but a node going down still fires.
    prev = {"reachable": True, "quorate": True, "nodes": {"s1": "online"}}
    now = {"quorum_unknown": True, "nodes": {"s1": "offline"}}
    types = _types(prev, now)
    assert types == ["hypervisor.node.offline"]
    assert "hypervisor.cluster.inquorate" not in types
    assert "hypervisor.cluster.quorate" not in types


def test_snapshot_carries_prev_quorate_forward_when_unknown() -> None:
    # An inquorate cluster whose token then loses Sys.Audit must not have its
    # quorate flipped to True in the snapshot (which would later mis-fire a
    # spurious quorate-recovery once cluster_status returns).
    prev = {"reachable": True, "quorate": False, "nodes": {}}
    snap = _snapshot(True, {"quorum_unknown": True, "nodes": {"s1": "online"}}, prev)
    assert snap["quorate"] is False  # carried forward, not guessed True
    assert snap["nodes"] == {"s1": "online"}


def test_catalog_declares_exactly_what_the_poller_emits() -> None:
    """Drift guard: every advertised hypervisor.* trigger is one the poller can
    actually fire, and vice-versa — no declared-but-never-fired events."""
    from app.modules.hypervisor.module import HypervisorModule

    declared = {e.event_type for e in HypervisorModule().get_emitted_events()}
    emittable = {
        "hypervisor.node.offline",
        "hypervisor.node.online",
        "hypervisor.cluster.inquorate",
        "hypervisor.cluster.quorate",
        "hypervisor.controller.unreachable",
        "hypervisor.controller.online",
    }
    assert declared == emittable
