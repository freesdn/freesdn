"""Gateway diagnostics backup / service restart: refused in read-only mode
before the gateway is contacted, and still audited when they run."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from fastapi import HTTPException

import app.core.runtime_flags as rf
from app.adapters.base import AdapterResult
from app.modules.gateway.api import passthrough_api as api


class _Gateway:
    def __init__(self, box: SimpleNamespace) -> None:
        self.box = box

    async def __aenter__(self) -> _Gateway:
        self.box.calls.append("connect")
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def create_backup(self) -> Any:
        self.box.calls.append("create_backup")
        return AdapterResult.ok({"backup": "ok"})

    async def restart_service(self, name: str) -> Any:
        self.box.calls.append(f"restart_service:{name}")
        return AdapterResult.ok({"restarted": name})


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    box = SimpleNamespace(calls=[], audited=[], read_only=False)
    gw = SimpleNamespace(
        id=uuid4(), name="fw", org_id=uuid4(), site_id=uuid4(), host="192.0.2.80"
    )

    async def _get_gateway(*_a: Any, **_k: Any) -> Any:
        return gw

    async def _audited(_db: Any, *, perform: Any, action: str, **_k: Any) -> Any:
        result = await perform()
        box.audited.append(action)
        return result

    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: box.read_only)
    monkeypatch.setattr(api, "get_gateway", _get_gateway)
    monkeypatch.setattr(api, "build_adapter", lambda _gw: _Gateway(box))
    monkeypatch.setattr(api, "audited_device_action", _audited)
    box.gw = gw
    box.user = SimpleNamespace(id=uuid4(), organization_id=gw.org_id)
    return box


async def _backup(w: SimpleNamespace) -> Any:
    return await api.trigger_backup(w.gw.id, w.user, None)


async def _restart(w: SimpleNamespace) -> Any:
    body = api.ServiceRestartRequest(gateway_id=w.gw.id, service_name="unbound")
    return await api.restart_service(body, w.user, None)


@pytest.mark.parametrize("call", [_backup, _restart])
async def test_read_only_mode_refuses_before_the_gateway_is_contacted(world, call) -> None:
    world.read_only = True

    with pytest.raises(HTTPException) as refused:
        await call(world)

    assert refused.value.status_code == 403
    assert "Read-only mode is on" in refused.value.detail
    assert world.calls == [], "the gateway must not even be connected to"
    assert world.audited == []


async def test_backup_and_restart_still_run_and_are_audited(world) -> None:
    assert await _backup(world) == {"backup": "ok"}
    assert await _restart(world) == {"restarted": "unbound"}

    assert world.calls == ["connect", "create_backup", "connect", "restart_service:unbound"]
    assert world.audited == ["create_backup", "restart_service"]
