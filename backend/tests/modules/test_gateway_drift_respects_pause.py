# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The drift check does not contact a gateway whose polling is paused.

Evidence: after the 2026-11 soak's OPNsense incident the owner paused polling
(``sync_enabled=false``). The periodic drift check loaded a site's brain by id
alone and would still have opened up to four adapter sessions to it every 15
minutes (architecture review 2026-11, topic 1). Same for a soft-deleted gateway
and for one the health poll's shared breaker has just found unreachable.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core import device_breaker
from app.core.device_breaker import DeviceBreaker
from app.modules.gateway.models import NetworkRole
from app.modules.gateway.services import drift_service
from app.modules.gateway.services.drift_service import DriftService
from tests.core.test_device_breaker import Clock, RedisDouble


class _Result:
    def __init__(self, rows):
        self._rows = list(rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))


class _DB:
    def __init__(self, *results):
        self._results = list(results)

    async def execute(self, _stmt):
        return _Result(self._results.pop(0) if self._results else [])


@pytest.fixture
def breaker(monkeypatch):
    redis, clock = RedisDouble(), Clock()
    b = DeviceBreaker(failure_threshold=1, redis_factory=lambda: redis, clock=clock)
    monkeypatch.setattr(device_breaker, "gateway_breaker", b)
    return b


@pytest.fixture
def contacted(monkeypatch):
    calls: list = []

    def build(gw):
        calls.append(gw.id)
        raise RuntimeError("contacted the device")

    monkeypatch.setattr(drift_service, "build_adapter", build)
    return calls


def _gateway(**kw):
    base = {"id": uuid4(), "deleted_at": None, "sync_enabled": True}
    base.update(kw)
    return SimpleNamespace(**base)


def _role_map(gw):
    return SimpleNamespace(
        organization_id=uuid4(),
        site_id=uuid4(),
        assignments=[SimpleNamespace(role=NetworkRole.BRAIN, gateway_id=gw.id)],
    )


PAUSED = [
    pytest.param({"sync_enabled": False}, id="sync-disabled"),
    pytest.param({"deleted_at": "2026-11-13"}, id="soft-deleted"),
]


@pytest.mark.parametrize("state", PAUSED)
async def test_brain_checks_leave_a_paused_gateway_alone(state, contacted, breaker):
    """Fails on the old service: every check built an adapter for it."""
    gw = _gateway(**state)
    rm = _role_map(gw)
    item = SimpleNamespace(vlan_id=uuid4())
    assert await DriftService(_DB([gw], [item]))._check_brain_vlans(rm) == []
    assert await DriftService(_DB([gw], [item], [item]))._check_brain_dhcp(rm) == []
    assert await DriftService(_DB([gw], [item]))._check_brain_dns(rm) == []
    rule = SimpleNamespace(resource_type="dhcp", device_id=gw.id)
    assert await DriftService(_DB([rule], [gw]))._check_suppressions(rm) == []
    assert contacted == []


async def test_an_open_breaker_pauses_drift_too(contacted, breaker):
    gw = _gateway()
    breaker.record_failure(device_breaker.gateway_key(gw.id), "connect: TimeoutError")
    item = SimpleNamespace(vlan_id=uuid4())
    assert await DriftService(_DB([gw], [item]))._check_brain_vlans(_role_map(gw)) == []
    assert contacted == []


async def test_a_healthy_enabled_gateway_is_still_checked(contacted, breaker):
    gw = _gateway()
    item = SimpleNamespace(vlan_id=uuid4())
    with pytest.raises(RuntimeError, match="contacted"):
        await DriftService(_DB([gw], [item]))._check_brain_vlans(_role_map(gw))
    assert contacted == [gw.id]
