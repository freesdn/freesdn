# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Device writes made directly by an endpoint now leave a record.

STAGING-MIGRATION.md option 2 (configuration writes): the endpoints that wrote
to a device straight from the request (UniFi WLAN/client/device writes, the
access-point, device, switch, PoE, network and controller configuration
routes) are refused while read-only mode is on, then staged as a
``direct.*`` row and applied in the same request, so the staging ledger
records who, what, when and the result. Their responses are unchanged.

Option 3 (operational actions: reboot, PoE cycle, controller backup): not
staged; an audit record is written once the device accepts the action.

These call the endpoint functions with the device lookups and the adapter
replaced by fakes; nothing is contacted.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select

import app.core.runtime_flags as rf
from app.adapters.base import AdapterResult
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.devices import Device
from app.models.security_audit import AuditLogRecord
from app.models.staging import AdapterPendingChange


class _Adapter:
    """Records every call; every method answers AdapterResult.ok.

    The UniFi adapter answers plain dicts, so its families swap the answer.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.answer: Any = AdapterResult.ok({"ok": True})

    async def __aenter__(self) -> _Adapter:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        return None

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)

        async def _call(*_a: Any, **_k: Any) -> Any:
            self.calls.append(name)
            return self.answer

        return _call


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def world(db_session):
    org = Organization(name="direct writes", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="c", site_id=site.id, controller_type="omada", host="127.0.0.1", port=443
    )
    db_session.add(ctrl)
    await db_session.flush()
    device = Device(
        name="dev",
        site_id=site.id,
        controller_id=ctrl.id,
        device_type="switch",
        mac_address="aa:bb:cc:00:00:01",
        status="online",
    )
    db_session.add(device)
    await db_session.commit()
    user = SimpleNamespace(
        id=uuid4(),
        organization_id=org.id,
        is_superuser=True,
        role="super_admin",
        user=SimpleNamespace(email="admin@example.test", id=uuid4()),
    )
    return SimpleNamespace(org=org, site=site, ctrl=ctrl, device=device, user=user)


async def _ledger(db_session) -> list[AdapterPendingChange]:
    return list(
        (
            await db_session.execute(
                select(AdapterPendingChange).where(AdapterPendingChange.feature.like("direct.%"))
            )
        ).scalars()
    )


async def _actions(db_session) -> list[AuditLogRecord]:
    return list(
        (
            await db_session.execute(
                select(AuditLogRecord).where(AuditLogRecord.action.like("device_action:%"))
            )
        ).scalars()
    )


# ── one call per converted family ────────────────────────────────────────────


def _ap_radio(monkeypatch, w, adapter):
    from app.api.v1.endpoints import access_points as m

    async def _get_ap(*_a: Any) -> Any:
        return w.device

    async def _adapter_for(*_a: Any) -> Any:
        return adapter

    monkeypatch.setattr(m, "_get_ap", _get_ap)
    monkeypatch.setattr(m, "_get_adapter_for_device", _adapter_for)
    return lambda s: m.update_ap_radio(
        "ap", "2g", m.RadioUpdateIn(channel=6), session=s, _user=w.user
    ), "direct.ap.radio"


def _switch_lag_delete(monkeypatch, w, adapter):
    from app.api.v1.endpoints import switches as m

    async def _get_switch(*_a: Any) -> Any:
        return w.device

    async def _adapter_for(*_a: Any) -> Any:
        return adapter

    monkeypatch.setattr(m, "_get_switch", _get_switch)
    monkeypatch.setattr(m, "_get_adapter_for_device", _adapter_for)
    return lambda s: m.delete_lag("sw", 1, session=s, _user=w.user), "direct.switch.lag"


def _device_led(monkeypatch, w, adapter):
    from app.api.v1.endpoints import devices as m

    async def _load(*_a: Any, **_k: Any) -> Any:
        return w.device

    async def _adapter_for(*_a: Any) -> Any:
        return adapter

    monkeypatch.setattr(m, "_load_device", _load)
    monkeypatch.setattr(m, "_get_adapter_for_device", _adapter_for)
    return lambda s: m.set_device_led(
        w.device.id, m.LEDSettingIn(setting=1), current_user=w.user, session=s
    ), "direct.device.led"


def _hotspot(monkeypatch, w, adapter):
    from app.api.v1.endpoints import controllers as m

    async def _ctrl_and_adapter(*_a: Any) -> Any:
        return w.ctrl, adapter

    monkeypatch.setattr(m, "_get_controller_and_adapter", _ctrl_and_adapter)
    return lambda s: m.update_hotspot_config(
        w.ctrl.id, {"enabled": True}, session=s, current_user=w.user
    ), "direct.controller.hotspot"


def _unifi_psk(monkeypatch, w, adapter):
    from app.api.v1.endpoints import unifi_wlans as m

    adapter.answer = {"meta": {"rc": "ok"}}
    return lambda s: m.update_wlan_password(
        w.ctrl.id,
        "default",
        "wlan1",
        m._WlanPasswordBody(new_psk="correct horse battery", force=True),
        user=w.user,
        adapter=adapter,
        session=s,
    ), "direct.unifi.wlans.password"


def _vlan_push(monkeypatch, w, adapter):
    from app.api.v1.endpoints import network as m

    async def _adapter_for(*_a: Any) -> Any:
        return adapter

    monkeypatch.setattr(m, "_get_adapter_for_controller", _adapter_for)
    net = SimpleNamespace(
        controller_id=w.ctrl.id,
        site_id=w.site.id,
        vlan_id=30,
        name="cams",
        description=None,
        external_id=None,
    )
    return lambda s: m._push_vlan_to_controller(
        s, net, action="create", actor_id=w.user.id
    ), "direct.network.vlan"


STAGED = [_ap_radio, _switch_lag_delete, _device_led, _hotspot, _unifi_psk, _vlan_push]


@pytest.mark.parametrize("family", STAGED, ids=lambda f: f.__name__)
async def test_a_configuration_write_is_recorded_in_the_ledger(
    family, monkeypatch, db_session, world, mode
) -> None:
    adapter = _Adapter()
    call, feature = family(monkeypatch, world, adapter)

    await call(db_session)

    assert adapter.calls, "the device write did not happen"
    (row,) = await _ledger(db_session)
    assert row.feature == feature
    assert row.status == "applied"
    assert row.created_by == world.user.id
    assert row.controller_id == world.ctrl.id
    assert row.organization_id == world.org.id
    assert row.applied_at is not None
    assert "correct horse" not in str(row.payload)


@pytest.mark.parametrize("family", STAGED, ids=lambda f: f.__name__)
async def test_read_only_mode_still_refuses_the_write(
    family, monkeypatch, db_session, world, mode
) -> None:
    mode["read_only"] = True
    adapter = _Adapter()
    call, _feature = family(monkeypatch, world, adapter)

    try:
        out = await call(db_session)
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        # The VLAN/WiFi push reports a refused controller write as a warning on
        # the saved record instead of failing the request, as it always has.
        assert out["controller_synced"] is False
        assert "Read-only mode is on" in out["controller_warning"]
    assert adapter.calls == []
    assert await _ledger(db_session) == []


# ── operational actions: audited, not staged ────────────────────────────────


def _ap_reboot(monkeypatch, w, adapter):
    from app.api.v1.endpoints import access_points as m

    async def _get_ap(*_a: Any) -> Any:
        return w.device

    async def _adapter_for(*_a: Any) -> Any:
        return adapter

    monkeypatch.setattr(m, "_get_ap", _get_ap)
    monkeypatch.setattr(m, "_get_adapter_for_device", _adapter_for)
    return lambda s: m.reboot_ap("ap", session=s, _user=w.user, confirm=True), "reboot_device"


def _controller_backup(monkeypatch, w, adapter):
    from app.api.v1.endpoints import controllers as m

    async def _ctrl_and_adapter(*_a: Any) -> Any:
        return w.ctrl, adapter

    monkeypatch.setattr(m, "_get_controller_and_adapter", _ctrl_and_adapter)
    return lambda s: m.create_controller_backup(
        w.ctrl.id, session=s, current_user=w.user
    ), "create_controller_backup"


def _unifi_restart(monkeypatch, w, adapter):
    from app.api.v1.endpoints import unifi_devices as m

    adapter.answer = {"meta": {"rc": "ok"}}
    return lambda s: m.restart_device(
        w.ctrl.id,
        "default",
        "aa:bb:cc:00:00:01",
        m._RestartBody(force=True),
        user=w.user,
        adapter=adapter,
        session=s,
    ), "restart_device"


@pytest.mark.parametrize(
    "family", [_ap_reboot, _controller_backup, _unifi_restart], ids=lambda f: f.__name__
)
async def test_an_operational_action_is_audited_not_staged(
    family, monkeypatch, db_session, world, mode
) -> None:
    adapter = _Adapter()
    call, action = family(monkeypatch, world, adapter)

    await call(db_session)

    assert adapter.calls
    assert await _ledger(db_session) == []
    (record,) = await _actions(db_session)
    assert record.action == f"device_action:{action}"
    assert record.actor_id == str(world.user.id)
    assert record.organization_id == world.org.id
    assert record.new_state["action"] == action


# ── DeviceControlService (automation and the network module's device actions) ──


async def test_device_control_stages_a_config_action_and_audits_a_reboot(
    db_session, world, mode
) -> None:
    from app.services.device_control import ActionRequest, ActionType, DeviceControlService

    adapter = _Adapter()
    svc = DeviceControlService(db_session)
    poe = ActionRequest(
        device_id=world.device.id, action_type=ActionType.POE_ENABLE, parameters={"port": 3}
    )
    reboot = ActionRequest(device_id=world.device.id, action_type=ActionType.REBOOT)

    assert (await svc._execute_action_with_adapter(adapter, world.device, poe)).success
    assert (await svc._execute_action_with_adapter(adapter, world.device, reboot)).success

    assert adapter.calls == ["set_port_poe", "reboot_device"]
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.device.port.poe" and row.status == "applied"
    (record,) = await _actions(db_session)
    assert record.action == "device_action:reboot_device"


async def test_device_control_config_action_is_refused_in_read_only_mode(
    db_session, world, mode
) -> None:
    from app.services.device_control import ActionRequest, ActionType, DeviceControlService

    mode["read_only"] = True
    adapter = _Adapter()
    poe = ActionRequest(
        device_id=world.device.id, action_type=ActionType.POE_ENABLE, parameters={"port": 3}
    )
    result = await DeviceControlService(db_session)._execute_action_with_adapter(
        adapter, world.device, poe
    )
    assert result.success is False and result.error_code == "READ_ONLY"
    assert adapter.calls == []
    assert await _ledger(db_session) == []
