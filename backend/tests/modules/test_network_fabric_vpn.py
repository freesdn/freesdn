# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""P5 — VPN/overlay capabilities on the Fabric.

The network module declares a VPN read-op (``vpn.overlay.status``) and an overlay
discovery trigger (``overlay.peer.discovered``); the ``/vpn/discovery`` path emits
that trigger through a shared, org-scoped, deduplicated emitter. These tests lock
the catalog shape and the emit contract WITHOUT the module registry / a DB (mirror
the hypervisor drift-guard pattern). Device-free.
"""

from __future__ import annotations

import pytest

from app.modules.network.module import NetworkModule
from app.services import overlay_discovery as od

# ── Catalog: the op + event are declared with the right shape ─────────────────


def test_vpn_overlay_status_operation_declared() -> None:
    ops = {o.id: o for o in NetworkModule().get_operations()}
    assert "vpn.overlay.status" in ops
    op = ops["vpn.overlay.status"]
    assert op.write is False  # a read — never stages
    assert op.permission == "vpn:read"  # the real permission used by /vpn endpoints
    assert op.handler is not None  # reads invoke directly (no staging feature)
    assert op.tier.value == "native"
    assert "application/json" in op.produces


def test_all_vpn_read_ops_declared_as_safe_reads() -> None:
    # the full VPN read surface — every one a safe read (no staging, vpn:read,
    # direct handler), so the Fabric/AI/automation can observe connectivity.
    ops = {o.id: o for o in NetworkModule().get_operations()}
    for op_id in ("vpn.overlay.status", "vpn.overlay.peers", "vpn.routes.list"):
        assert op_id in ops, f"{op_id} not declared"
        op = ops[op_id]
        assert op.write is False, f"{op_id} must be a read"
        assert op.permission == "vpn:read"
        assert op.handler is not None
        assert op.tier.value == "native"


def test_overlay_peer_discovered_event_declared() -> None:
    evs = {e.event_type: e for e in NetworkModule().get_emitted_events()}
    assert "overlay.peer.discovered" in evs
    ev = evs["overlay.peer.discovered"]
    assert ev.tier.value == "native"
    # the payload schema advertises the fields a Connection can template on
    props = ev.payload_schema.get("properties", {})
    for field in ("source", "address", "suggested_type", "organization_id"):
        assert field in props, f"declared overlay event missing {field!r}"


def test_existing_network_ops_and_events_not_regressed() -> None:
    # additive only — the original capabilities are still present
    ops = {o.id for o in NetworkModule().get_operations()}
    assert {"network.client.list", "network.client.block", "network.device.reboot"} <= ops
    evs = {e.event_type for e in NetworkModule().get_emitted_events()}
    assert {"network.vlan.created", "network.wifi.created"} <= evs


# ── Emit: org-scoped, exact event id, deduped, adopted-skipped, best-effort ───


class _CapturingBus:
    def __init__(self) -> None:
        self.events: list = []

    async def publish(self, event) -> None:  # noqa: ANN001
        self.events.append(event)


def _peer(address: str, *, adopted: bool = False, source: str = "tailscale") -> dict:
    return {
        "source": source,
        "hostname": f"host-{address}",
        "address": address,
        "online": True,
        "suggested_type": "proxmox",
        "confidence": "high",
        "already_adopted": adopted,
    }


@pytest.mark.asyncio
async def test_emit_publishes_exact_event_id_with_org() -> None:
    od._announced_peers.clear()
    bus = _CapturingBus()
    n = await od.emit_overlay_discovery([_peer("100.64.0.5")], organization_id="org-1", bus=bus)
    assert n == 1
    ev = bus.events[0]
    # the catalog id verbatim — NOT the discovery_event() "discovery." prefix,
    # else the negotiator's source_event would never match (silent wiring).
    assert ev.event_type == "overlay.peer.discovered"
    # fail-closed org gate: both the routing field and the payload carry the org
    assert ev.organization_id == "org-1"
    assert ev.payload["organization_id"] == "org-1"
    assert ev.payload["address"] == "100.64.0.5"


@pytest.mark.asyncio
async def test_emit_skips_already_adopted() -> None:
    od._announced_peers.clear()
    bus = _CapturingBus()
    n = await od.emit_overlay_discovery(
        [_peer("100.64.0.6", adopted=True)], organization_id="org-1", bus=bus
    )
    assert n == 0
    assert bus.events == []


@pytest.mark.asyncio
async def test_emit_dedupes_repeat_polls() -> None:
    od._announced_peers.clear()
    peers = [_peer("100.64.0.7")]
    bus = _CapturingBus()
    assert await od.emit_overlay_discovery(peers, organization_id="org-1", bus=bus) == 1
    # a second discovery poll re-announces nothing new for the same peer
    assert await od.emit_overlay_discovery(peers, organization_id="org-1", bus=bus) == 0
    assert len(bus.events) == 1


@pytest.mark.asyncio
async def test_emit_requires_org_and_devices() -> None:
    od._announced_peers.clear()
    bus = _CapturingBus()
    assert await od.emit_overlay_discovery([_peer("1.2.3.4")], organization_id="", bus=bus) == 0
    assert await od.emit_overlay_discovery([], organization_id="org-1", bus=bus) == 0
    assert bus.events == []


@pytest.mark.asyncio
async def test_emit_is_best_effort_on_bus_failure() -> None:
    od._announced_peers.clear()

    class _BrokenBus:
        async def publish(self, event) -> None:  # noqa: ANN001
            raise RuntimeError("redis down")

    # a publish failure is swallowed (returns 0), and the peer is NOT marked
    # announced — so a later healthy poll can still surface it.
    n = await od.emit_overlay_discovery(
        [_peer("100.64.0.8")], organization_id="org-1", bus=_BrokenBus()
    )
    assert n == 0
    assert "org-1|tailscale|100.64.0.8" not in od._announced_peers
