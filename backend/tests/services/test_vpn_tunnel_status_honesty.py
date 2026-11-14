# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A site-to-site tunnel is "active" only when its config reached the gateways.

Four paths reported a tunnel active, or a change made, with nothing on either
gateway:

1. ``tunnel_action("enable")`` wrote ``status = "active"`` and pushed nothing,
   so "Enable" on an errored tunnel turned it green.
2. ``_reprovision_tunnel`` discarded the adapter's answer (the create path was
   fixed for this earlier, reprovision kept its own copy), marked a tunnel with
   no gateway active, and skipped a side whose gateway was gone.
3. ``check_tunnel_health`` pings the far gateway's public endpoint when no
   health IP is set, so a reachable gateway promoted a never-pushed tunnel.
4. OPNsense's WireGuard push answered "configured" for a config with neither a
   server nor a peer section, which free-form templates usually are.

Disable never touched the gateways, while its confirm said traffic would stop;
its message now says what it does.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.adapters.base import AdapterResult
from app.api.v1.endpoints import vpn_orchestration as ep
from app.services import adapter_factory
from app.services.vpn_orchestration import VPNOrchestrationService


class _Result:
    def __init__(self, tunnel: Any, devices: list[Any]) -> None:
        self._tunnel, self._devices = tunnel, devices

    def scalar_one_or_none(self) -> Any:
        return self._tunnel

    def scalars(self) -> Any:
        return SimpleNamespace(all=lambda: list(self._devices))


def _db(tunnel: Any = None, devices: list[Any] | None = None) -> Any:
    db = SimpleNamespace()
    db.execute = AsyncMock(return_value=_Result(tunnel, devices or []))
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    return db


def _device(gw_id: Any) -> Any:
    ctrl = SimpleNamespace(
        controller_type="omada",
        host="192.0.2.1",
        username="viewer",
        password="not-encrypted",
        port=443,
        use_ssl=True,
        verify_ssl=False,
    )
    return SimpleNamespace(id=gw_id, mac_address="aa:bb:cc:dd:ee:ff", controller=ctrl)


def _tunnel(*, gateways: int = 2, status: str = "error", pushed: bool = False) -> Any:
    return SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        site_a_id=uuid4(),
        site_b_id=uuid4(),
        gateway_a_device_id=uuid4() if gateways >= 1 else None,
        gateway_b_device_id=uuid4() if gateways >= 2 else None,
        status=status,
        config_a={"endpoint": "192.0.2.10"},
        config_b={"endpoint": "192.0.2.20"},
        provisioned_at=datetime(2026, 11, 1, tzinfo=UTC) if pushed else None,
        error_message=None,
    )


class _Adapter:
    def __init__(self, result: AdapterResult | Exception) -> None:
        self.result = result
        self.pushes = 0

    async def __aenter__(self) -> _Adapter:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def push_vpn_config(self, device_id: str, config: dict[str, Any]) -> AdapterResult:
        self.pushes += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch) -> _Adapter:
    """Every gateway answers with ``adapter.result``; set it per test.

    The database here is a stub, so the push's change group runs in memory
    (tests/fixtures_harness/change_groups.py); the real group, ledger rows
    included, is covered by tests/services/test_change_groups.py.
    """
    import app.services.device_writes as device_writes
    from tests.fixtures_harness.change_groups import run_group

    fake = _Adapter(AdapterResult.ok({}))
    monkeypatch.setattr(adapter_factory, "get_adapter", lambda *_a, **_k: fake)
    monkeypatch.setattr(device_writes, "apply_group_through_staging", run_group)
    return fake


def _gateways(tunnel: Any) -> list[Any]:
    ids = (tunnel.gateway_a_device_id, tunnel.gateway_b_device_id)
    return [_device(gw) for gw in ids if gw]


# ── the shared push ──────────────────────────────────────────────


async def test_a_refused_push_is_not_reported_active(adapter: _Adapter) -> None:
    """Every adapter but OPNsense refuses with NOT_SUPPORTED; that is not active."""
    adapter.result = AdapterResult.fail("VPN push not supported", error_code="NOT_SUPPORTED")
    tunnel = _tunnel()
    ok = await VPNOrchestrationService(_db(devices=_gateways(tunnel)))._reprovision_tunnel(tunnel)
    assert ok is False
    assert tunnel.status == "error"
    assert tunnel.provisioned_at is None
    assert "Side a" in tunnel.error_message and "Side b" in tunnel.error_message


async def test_a_tunnel_with_no_gateway_stays_pending(adapter: _Adapter) -> None:
    tunnel = _tunnel(gateways=0)
    ok = await VPNOrchestrationService(_db())._reprovision_tunnel(tunnel)
    assert ok is False
    assert tunnel.status == "pending"
    assert "nothing was pushed" in tunnel.error_message
    assert adapter.pushes == 0


async def test_a_side_whose_gateway_is_gone_is_a_failure(adapter: _Adapter) -> None:
    """The query filters soft-deleted devices, so a removed gateway returns no row."""
    tunnel = _tunnel()
    only_a = [_device(tunnel.gateway_a_device_id)]
    ok = await VPNOrchestrationService(_db(devices=only_a))._reprovision_tunnel(tunnel)
    assert ok is False
    assert tunnel.status == "error"
    assert "Side b" in tunnel.error_message and "no longer registered" in tunnel.error_message


async def test_a_push_that_raises_is_a_failure(adapter: _Adapter) -> None:
    adapter.result = ConnectionError("gateway unreachable")
    tunnel = _tunnel()
    ok = await VPNOrchestrationService(_db(devices=_gateways(tunnel)))._reprovision_tunnel(tunnel)
    assert ok is False
    assert tunnel.status == "error"


async def test_both_sides_accepting_is_active(adapter: _Adapter) -> None:
    tunnel = _tunnel()
    tunnel.error_message = "stale reason from an earlier failure"
    ok = await VPNOrchestrationService(_db(devices=_gateways(tunnel)))._reprovision_tunnel(tunnel)
    assert ok is True
    assert tunnel.status == "active"
    assert tunnel.provisioned_at is not None
    assert tunnel.error_message is None
    assert adapter.pushes == 2


# ── the action endpoint ──────────────────────────────────────────


async def _act(monkeypatch: pytest.MonkeyPatch, tunnel: Any, action: str) -> Any:
    monkeypatch.setattr(ep, "_org_id", lambda _user: tunnel.organization_id)
    monkeypatch.setattr(ep, "_assert_tunnel_sites", lambda *_a, **_k: None)
    db = _db(tunnel, _gateways(tunnel))
    resp = await ep.tunnel_action(
        tunnel.id, ep.TunnelActionRequest(action=action), db=db, user=SimpleNamespace()
    )
    db.commit.assert_awaited()
    return resp


async def test_enable_on_a_failed_tunnel_pushes_and_reports_the_refusal(
    monkeypatch: pytest.MonkeyPatch, adapter: _Adapter
) -> None:
    """The bug: this turned the tunnel green without contacting a gateway.

    One push, not two: the sides are one change group, and the first refusal
    stops it (owner decision 2026-11-13), so side B is not configured after
    side A refused.
    """
    adapter.result = AdapterResult.fail("VPN push not supported", error_code="NOT_SUPPORTED")
    tunnel = _tunnel(status="error", pushed=False)
    resp = await _act(monkeypatch, tunnel, "enable")
    assert adapter.pushes == 1
    assert resp.success is False
    assert resp.new_status == "error"
    assert "not supported" in resp.error_message


async def test_enable_on_a_never_pushed_tunnel_is_active_only_after_the_push(
    monkeypatch: pytest.MonkeyPatch, adapter: _Adapter
) -> None:
    tunnel = _tunnel(status="disabled", pushed=False)
    resp = await _act(monkeypatch, tunnel, "enable")
    assert adapter.pushes == 2
    assert resp.success is True and resp.new_status == "active"


async def test_enable_after_disable_restores_without_pushing_twice(
    monkeypatch: pytest.MonkeyPatch, adapter: _Adapter
) -> None:
    """Disable leaves the config on the gateways; pushing again would duplicate it."""
    tunnel = _tunnel(status="disabled", pushed=True)
    resp = await _act(monkeypatch, tunnel, "enable")
    assert adapter.pushes == 0
    assert resp.success is True and resp.new_status == "active"


async def test_enable_cannot_clear_a_failed_health_check(
    monkeypatch: pytest.MonkeyPatch, adapter: _Adapter
) -> None:
    tunnel = _tunnel(status="error", pushed=True)
    resp = await _act(monkeypatch, tunnel, "enable")
    assert adapter.pushes == 0
    assert resp.success is False
    assert resp.new_status == "error"
    assert "health check" in resp.message


async def test_disable_does_not_claim_the_traffic_stopped(
    monkeypatch: pytest.MonkeyPatch, adapter: _Adapter
) -> None:
    tunnel = _tunnel(status="active", pushed=True)
    resp = await _act(monkeypatch, tunnel, "disable")
    assert adapter.pushes == 0
    assert resp.new_status == "disabled"
    assert "still on the gateways" in resp.message
    assert "traffic keeps flowing" in resp.message


# ── the health check ─────────────────────────────────────────────


def _run_health_check(monkeypatch: pytest.MonkeyPatch, tunnel: Any) -> dict[str, Any]:
    from app.core import redis_client
    from app.services import vpn_alerts
    from app.tasks import vpn as vpn_task

    class _Session:
        execute = AsyncMock(return_value=_Result(None, [tunnel]))
        commit = AsyncMock()
        rollback = AsyncMock()

        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

    class _LogDB(_Session):
        def add(self, row: Any) -> None:
            return None

    class _Proc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"", b""

    async def _ping(*args: Any, **kwargs: Any) -> _Proc:
        return _Proc()

    lock = SimpleNamespace(set=lambda *_a, **_k: True, delete=lambda *_a: None, close=lambda: None)
    alerts = SimpleNamespace(on_tunnel_status_change=AsyncMock())
    monkeypatch.setattr(vpn_task, "AsyncSessionLocal", _Session)
    monkeypatch.setattr(vpn_task, "_get_logdb", lambda: _LogDB)
    monkeypatch.setattr(redis_client, "get_sync_redis", lambda: lock)
    monkeypatch.setattr(vpn_alerts, "VPNAlertService", lambda _session: alerts)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _ping)
    return vpn_task.check_tunnel_health.run()


def test_a_reachable_gateway_does_not_activate_a_tunnel_never_pushed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tunnel = _tunnel(status="error", pushed=False)
    out = _run_health_check(monkeypatch, tunnel)
    assert out["checked"] == 1
    assert tunnel.status == "error"


def test_a_pushed_tunnel_still_recovers_on_a_passing_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: the guard must not freeze a real tunnel in error."""
    tunnel = _tunnel(status="error", pushed=True)
    out = _run_health_check(monkeypatch, tunnel)
    assert out["checked"] == 1
    assert tunnel.status == "active"


# ── OPNsense's empty WireGuard push ──────────────────────────────


async def test_opnsense_wireguard_push_with_nothing_to_send_fails() -> None:
    from app.adapters.opnsense.adapter import OPNsenseAdapter

    api = SimpleNamespace(
        add_wireguard_server=AsyncMock(),
        add_wireguard_peer=AsyncMock(),
        apply_wireguard_changes=AsyncMock(),
    )
    fake_self = SimpleNamespace(_api=api, _direct_write_force=False)
    result = await OPNsenseAdapter._push_wireguard(fake_self, {"endpoint": "192.0.2.10"})
    assert result.success is False
    assert result.error_code == "MISSING_CONFIG"
    api.add_wireguard_server.assert_not_awaited()
    api.apply_wireguard_changes.assert_not_awaited()
