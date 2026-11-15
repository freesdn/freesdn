# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A config backup never lands on a busy or unresponsive gateway, and a
disabled Firewall module stops scheduled exports. Real PostgreSQL, real Valkey."""

from __future__ import annotations

from datetime import UTC, datetime

from app.core.config import settings
from app.core.device_slot import device_slots, gateway_slot_key
from app.services.device_config_backup import DeviceConfigBackupService
from tests.services.test_device_config_backup import _claim, _targets
from tests.services.test_device_config_backup import fleet as fleet  # noqa: F401


async def test_a_busy_gateway_is_backed_up_later_without_a_failure(fleet):
    """Fails on the old capture: it exported while another poller held the box."""
    f = fleet
    service, target, claim = await _claim(f, f.gws.opnsense)
    held = device_slots.try_acquire(gateway_slot_key(f.gws.opnsense), "gateway full sync", ttl=60)
    assert held is not None and held.guarded
    try:
        outcome = await service.capture(claim)
    finally:
        device_slots.release(held)
    assert outcome == "deferred"
    assert f.calls == [], "nothing may be sent to a device another poller holds"
    await f.db.refresh(target)
    assert target.consecutive_failures == 0 and target.lease_token is None
    ahead = (target.next_due_at - datetime.now(UTC)).total_seconds()
    assert 590 <= ahead <= 1210


async def test_a_scheduled_export_leaves_an_unresponsive_gateway_alone(fleet):
    from app.core.device_breaker import gateway_breaker, gateway_key

    f = fleet
    service, target, claim = await _claim(f, f.gws.opnsense)
    for _ in range(gateway_breaker.failure_threshold):
        gateway_breaker.record_failure(gateway_key(f.gws.opnsense.id), "ConnectTimeout")
    try:
        assert await service.capture(claim) == "deferred"
        assert f.calls == []
    finally:
        gateway_breaker.record_success(gateway_key(f.gws.opnsense.id))


async def test_disabling_the_firewall_module_stops_scheduled_exports(fleet):
    from app.modules.models import OrganizationModule

    f = fleet
    f.db.add(OrganizationModule(organization_id=f.org.id, module_id="firewall", is_enabled=False))
    await f.db.flush()
    service = DeviceConfigBackupService(f.db)
    await service.sync_targets()
    for target in (await _targets(f)).values():
        target.next_due_at = datetime(2000, 1, 1, tzinfo=UTC)
    await f.db.flush()
    claimed = {c.target_id for c in await service.claim_due()}
    targets = await _targets(f)
    mine = {t.id for sid, t in targets.items() if t.organization_id == f.org.id}
    assert mine and not (claimed & mine)
    assert targets[f.gws.foreign.id].id in claimed  # the other organization still runs


async def test_new_targets_take_the_configured_interval(fleet, monkeypatch):
    f = fleet
    monkeypatch.setattr(settings, "CONFIG_BACKUP_INTERVAL_HOURS", 48)
    await DeviceConfigBackupService(f.db).sync_targets()
    assert {t.interval_hours for t in (await _targets(f)).values()} == {48}
