# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The full gateway sync waits its turn at the device instead of piling on.

The device slot lives in the real Valkey of the test run; the breakers use the
same Redis double as the breaker tests.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.core.device_slot import device_slots, gateway_slot_key
from app.modules.gateway.services import sync_service
from tests.modules.test_gateway_sync_breaker import TIMED_OUT, _run
from tests.modules.test_gateway_sync_breaker import breakers as breakers  # noqa: F401


class _Row:
    def __init__(self, gw):
        self._gw = gw

    def scalar_one_or_none(self):
        return self._gw


class _Session:
    def __init__(self, gw):
        self.gw = gw

    async def execute(self, _stmt):
        return _Row(self.gw)

    async def commit(self):
        return None

    async def refresh(self, _obj):
        return None


def test_a_sync_finding_the_device_busy_sends_nothing(monkeypatch):
    """Fails on the old service: it read every section regardless."""
    gw = SimpleNamespace(
        id=uuid4(), host="192.0.2.80", deleted_at=None, sync_enabled=True, org_id=uuid4()
    )
    touched: list = []

    class _Adapter:
        async def __aenter__(self):
            touched.append("connect")
            return self

        async def __aexit__(self, *_exc):
            return False

    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: _Adapter())
    held = device_slots.try_acquire(gateway_slot_key(gw), "firewall health poll", ttl=60)
    assert held is not None and held.guarded
    try:
        result = asyncio.run(sync_service.SyncService(_Session(gw)).sync_gateway(gw.id))
    finally:
        device_slots.release(held)
    assert touched == []
    assert result["status"] == "skipped" and result["device_busy"] is True
    assert result["reason"].startswith("Device busy: firewall health poll")


BUSY = {"status": "skipped", "reason": "Device busy: firewall health poll", "device_busy": True}


def test_a_busy_device_neither_counts_against_it_nor_burns_the_probe(monkeypatch, breakers):
    """Fails on the old loop: the half-open probe lease stayed taken, so the
    gateway was skipped as "probe in flight" for the next 15 minutes."""
    gw = uuid4()
    _run(monkeypatch, gw, TIMED_OUT)  # one failed sync backs the full sync off
    breakers.now += 1000  # cooldown over: the next run is the probe
    result, calls, session = _run(monkeypatch, gw, BUSY)
    assert calls == [gw]
    assert session.updates == 1  # the busy reason is shown where the UI looks
    breakers.now += 1
    result, calls, _ = _run(monkeypatch, gw, {"status": "success", "synced": {}})
    assert calls == [gw] and result["synced"] == 1
