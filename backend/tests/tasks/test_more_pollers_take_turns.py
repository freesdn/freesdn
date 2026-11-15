# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Proxmox task observer, CDR sync, VPN pings, RADIUS checks and the
overlay monitor take their device's turn like every other poller.

Before this they contacted a device whatever discovery, a sync or a page was
doing to it. The slots and the breakers live in the real Valkey of the test
run; the devices are doubles that record every contact.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app.core.device_slot import OVERLAY_SLOT_KEY, device_slots


def _hold(key: str, holder: str = "another poller"):
    lease = device_slots.try_acquire(key, holder, ttl=60)
    assert lease is not None and lease.guarded, "the test needs real Valkey"
    return lease


# ── hypervisor.poll_tasks ───────────────────────────────────────────────

from tests.services.test_proxmox_task_tracking import (  # noqa: E402
    accept,
    observer,
)
from tests.services.test_proxmox_task_tracking import (  # noqa: E402
    records as records,  # noqa: F401 - fixture
)


async def _row(sessions, cid):
    from app.models.staging import AdapterPendingChange

    async with sessions() as session:
        return await session.get(AdapterPendingChange, cid)


async def test_the_task_observer_leaves_a_busy_cluster_for_a_minute(records, monkeypatch):
    from app.services import proxmox_task_tracking as tracking

    sessions, cid, _ = records
    await accept(sessions, cid)
    before = (await _row(sessions, cid)).provider_task
    _adapter, builder = observer(monkeypatch, "stopped", "OK")
    held = _hold("host:192.0.2.1", "discovery")
    try:
        await tracking.poll_due_tasks()
    finally:
        device_slots.release(held)
    builder.assert_not_awaited()
    row = await _row(sessions, cid)
    assert row.provider_task == before, "a skipped look is not an observation"
    wait = row.provider_task_next_poll_at - datetime.now(UTC)
    assert timedelta(seconds=30) < wait <= timedelta(seconds=60)
    # The next look, with the cluster free, observes as before.
    row_due = datetime.now(UTC) - timedelta(seconds=1)
    async with sessions() as session:
        from app.models.staging import AdapterPendingChange

        (await session.get(AdapterPendingChange, cid)).provider_task_next_poll_at = row_due
        await session.commit()
    await tracking.poll_due_tasks()
    builder.assert_awaited_once()
    assert (await _row(sessions, cid)).provider_task["status"] == "succeeded"


async def test_the_task_observer_leaves_an_unreachable_cluster_to_the_health_check(
    records, monkeypatch
):
    from app.core.device_breaker import controller_breaker, controller_key
    from app.services import proxmox_task_tracking as tracking

    sessions, cid, controller_id = records
    await accept(sessions, cid)
    _adapter, builder = observer(monkeypatch)
    for _ in range(controller_breaker.failure_threshold):
        controller_breaker.record_failure(controller_key(controller_id), "ConnectTimeout")
    await tracking.poll_due_tasks()
    builder.assert_not_awaited()
    wait = (await _row(sessions, cid)).provider_task_next_poll_at - datetime.now(UTC)
    assert timedelta(minutes=4) < wait <= timedelta(minutes=5)


# ── voip.sync_cdr ──────────────────────────────────────────────────────

from tests.modules.test_voip_cdr_sync import _FakeCdrAdapter, _read  # noqa: E402
from tests.modules.test_voip_cdr_sync import pbx as pbx  # noqa: E402, F401 - fixture


def test_the_cdr_sync_leaves_a_busy_pbx_for_the_next_run(pbx):
    from app.modules.voip import tasks

    held = _hold("host:192.0.2.30", "UI read (/api/v1/pbx/x/active-calls)")
    try:
        result = tasks.sync_cdr.run(str(pbx["id"]))
    finally:
        device_slots.release(held)
    assert result["status"] == "skipped" and "UI read" in result["reason"]
    assert _FakeCdrAdapter.connected == 0, "nothing may be sent to a busy PBX"
    _calls, settings = _read(pbx["id"])
    assert "cdr_sync" not in settings, "a skipped run is not a sync outcome"


# ── VPN tunnel pings ───────────────────────────────────────────────────


def test_a_vpn_ping_skips_a_target_another_poller_has_and_pings_each_target_once():
    from app.tasks import vpn

    pinged: list[str] = []

    async def ping(target: str) -> bool:
        pinged.append(target)
        return True

    held = _hold("host:192.0.2.40", "gateway full sync")
    try:
        results = asyncio.run(
            vpn._ping_targets(["192.0.2.40", "192.0.2.41", "192.0.2.41"], ping, "S2S ping")
        )
    finally:
        device_slots.release(held)
    assert pinged == ["192.0.2.41"]
    assert results["192.0.2.40"] is vpn._SKIPPED and results["192.0.2.41"] is True


def test_a_tunnel_whose_gateway_is_busy_keeps_its_status_and_records_nothing(monkeypatch):
    from app.tasks import vpn as vpn_task
    from tests.services.test_vpn_tunnel_status_honesty import _run_health_check, _tunnel

    tunnel = _tunnel(status="active", pushed=True)
    tunnel.config_a = {"health_check_ip": "192.0.2.42"}
    pinged: list[str] = []

    async def no_ping(target: str) -> bool:
        pinged.append(target)
        return False

    real = vpn_task._ping_targets

    async def spy(targets, _ping, holder):
        return await real(targets, no_ping, holder)

    monkeypatch.setattr(vpn_task, "_ping_targets", spy)
    held = _hold("host:192.0.2.42", "gateway full sync")
    try:
        out = _run_health_check(monkeypatch, tunnel)
    finally:
        device_slots.release(held)
    assert pinged == [] and out["checked"] == 0
    assert tunnel.status == "active", "a ping that was not sent cannot fail the tunnel"


# ── RADIUS checks ──────────────────────────────────────────────────────


class _Session:
    def __init__(self, answers: list[Any]) -> None:
        self.answers = list(answers)

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def execute(self, _stmt: Any) -> Any:
        return self.answers.pop(0)

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


class _Scalars(list):
    def all(self) -> list[Any]:
        return list(self)


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows

    def all(self) -> list[Any]:
        return [(r,) for r in self.rows]

    def scalars(self) -> _Scalars:
        return _Scalars(self.rows)


def test_the_radius_probe_skips_a_server_another_poller_has(monkeypatch):
    from app.services.radius import RadiusProfileService
    from app.tasks import radius

    busy = SimpleNamespace(id=uuid4(), host="192.0.2.43", port=1812, name="fw radius")
    free = SimpleNamespace(id=uuid4(), host="192.0.2.44", port=1812, name="nps")
    probed: list[str] = []

    async def probe(self, profile):
        probed.append(profile.host)
        return {"is_healthy": True}

    monkeypatch.setattr(RadiusProfileService, "health_check_profile", probe)
    monkeypatch.setattr(radius, "AsyncSessionLocal", lambda: _Session([_Result([busy, free])]))
    held = _hold("host:192.0.2.43", "firewall health")
    try:
        out = radius.check_radius_health.run()
    finally:
        device_slots.release(held)
    assert probed == ["192.0.2.44"]
    assert out["checked"] == 1 and out["skipped"] == 1


def test_the_8021x_event_sync_takes_the_controller_turn_and_respects_its_breaker(monkeypatch):
    from app.core.device_breaker import controller_breaker, controller_key
    from app.services.radius import RadiusProfileService
    from app.tasks import radius

    busy = SimpleNamespace(id=uuid4(), host="192.0.2.45", connection_mode="local")
    down = SimpleNamespace(id=uuid4(), host="192.0.2.46", connection_mode="local")
    free = SimpleNamespace(id=uuid4(), host="192.0.2.47", connection_mode="local")
    pulled: list[Any] = []

    async def pull(self, controller_id):
        pulled.append(controller_id)
        return {"success": True, "synced": 1}

    monkeypatch.setattr(RadiusProfileService, "sync_auth_events", pull)
    ids = [busy.id, down.id, free.id]
    monkeypatch.setattr(
        radius,
        "AsyncSessionLocal",
        lambda: _Session([_Result(ids), _Result([busy, down, free])]),
    )
    for _ in range(controller_breaker.failure_threshold):
        controller_breaker.record_failure(controller_key(down.id), "ConnectTimeout")
    held = _hold("host:192.0.2.45", "discovery")
    try:
        out = radius.sync_dot1x_events.run()
    finally:
        device_slots.release(held)
    assert pulled == [free.id]
    assert out["skipped"] == 2 and out["synced"] == 1


# ── overlay checks ─────────────────────────────────────────────────────


@pytest.fixture
def overlay(monkeypatch):
    from app.core.config import settings
    from app.services import overlay_discovery
    from app.tasks import overlay_monitor

    state = SimpleNamespace(read=0, session_open=False, open_during_read=None)

    class Session:
        async def __aenter__(self):
            state.session_open = True
            return self

        async def __aexit__(self, *_exc):
            state.session_open = False
            return False

    async def org(_session):
        return str(uuid4())

    async def discover():
        state.read += 1
        state.open_during_read = state.session_open
        return [{"source": "tailscale", "address": "100.64.0.9", "online": True}]

    monkeypatch.setattr(settings, "VPN_MODE", "sidecar")
    monkeypatch.setattr(overlay_monitor, "CelerySessionLocal", Session)
    monkeypatch.setattr(overlay_monitor, "_appliance_org_id", org)
    monkeypatch.setattr(overlay_discovery, "discover_overlay_devices", discover)
    monkeypatch.setattr(overlay_discovery, "emit_overlay_discovery", _no_discovery)
    return state


async def _no_discovery(*_a, **_k):
    return 0


def test_the_overlay_monitor_skips_while_the_daemon_is_busy(overlay):
    from app.tasks import overlay_monitor

    held = _hold(OVERLAY_SLOT_KEY, "VPN page")
    try:
        out = asyncio.run(overlay_monitor._poll_overlay_health())
    finally:
        device_slots.release(held)
    assert out["skipped"] is True and "VPN page" in out["reason"]
    assert overlay.read == 0


def test_the_overlay_monitor_holds_no_database_session_while_the_daemon_answers(overlay):
    from app.tasks import overlay_monitor

    out = asyncio.run(overlay_monitor._poll_overlay_health())
    assert out["success"] is True and overlay.read == 1
    assert overlay.open_during_read is False
