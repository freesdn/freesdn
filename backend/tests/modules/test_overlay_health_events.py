# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Overlay-mesh Fabric health events: transition diff + catalog drift guard.

Locks the poller↔catalog contract: the overlay poller emits exactly the
``overlay.*`` triggers the network module advertises — no declared-but-never-fired
event, no fired-but-undeclared one (the camera/hypervisor drift class). Pure:
no DB, no device, no Celery.
"""

from __future__ import annotations

import uuid

from app.tasks.overlay_monitor import _snapshot, _transitions

_ORG = str(uuid.uuid4())


def _types(prev, peers, reachable=True):
    return [e.event_type for e in _transitions(prev, peers, reachable, _ORG)]


def _peer(addr, online, **kw):
    return {"source": "tailscale", "address": addr, "online": online, **kw}


def test_first_seen_offline_peer_fires_offline_only():
    # first poll: an offline peer surfaces as offline; an online peer is silent
    # (online is recovery-only; a brand-new online peer is discovery's job).
    types = _types({}, [_peer("100.0.0.1", True), _peer("100.0.0.2", False)])
    assert types == ["overlay.peer.offline"]


def test_peer_online_to_offline_transition():
    prev = _snapshot(True, [_peer("100.0.0.1", True)])
    assert _types(prev, [_peer("100.0.0.1", False)]) == ["overlay.peer.offline"]


def test_peer_offline_to_online_recovery():
    prev = _snapshot(True, [_peer("100.0.0.1", False)])
    assert _types(prev, [_peer("100.0.0.1", True)]) == ["overlay.peer.online"]


def test_steady_state_is_silent():
    prev = _snapshot(True, [_peer("100.0.0.1", True)])
    assert _types(prev, [_peer("100.0.0.1", True)]) == []


def test_metadata_change_fires_connection_changed():
    prev = _snapshot(True, [_peer("100.0.0.1", True, hostname="pve", suggested_type="proxmox")])
    now = [_peer("100.0.0.1", True, hostname="pve-renamed", suggested_type="proxmox")]
    assert _types(prev, now) == ["overlay.connection.changed"]


def test_vanished_online_peer_fires_offline():
    prev = _snapshot(True, [_peer("100.0.0.1", True)])
    assert _types(prev, []) == ["overlay.peer.offline"]


def test_unreachable_fires_once_then_silent():
    assert _types({"reachable": True}, None, reachable=False) == ["overlay.status.unreachable"]
    assert _types({"reachable": False}, None, reachable=False) == []


def test_reachable_again_fires_online():
    assert "overlay.status.online" in _types({"reachable": False}, [], reachable=True)


def test_catalog_declares_exactly_what_the_poller_emits():
    """Drift guard: every advertised overlay.* trigger is one the poller can fire,
    and vice-versa. overlay.peer.discovered is included because the poller also
    calls emit_overlay_discovery() (so it stays emittable)."""
    from app.modules.network.module import NetworkModule

    declared = {
        e.event_type
        for e in NetworkModule().get_emitted_events()
        if e.event_type.startswith("overlay.")
    }
    emittable = {
        "overlay.peer.discovered",  # shipped via emit_overlay_discovery (also fired by the poller)
        "overlay.peer.online",
        "overlay.peer.offline",
        "overlay.connection.changed",
        "overlay.status.unreachable",
        "overlay.status.online",
    }
    assert declared == emittable
