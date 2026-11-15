# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The service-layer device writes go through the staging chokepoint.

Five services wrote to a device directly, outside staging, and the ratchet
pinned them as known bypasses: config-version rollback, drift auto-remediation,
the 802.1X profile push, the SSID roaming push and the Celery bulk operations
(config push, reboot, firmware). Each is now staged and applied where it runs
(a ``direct.*`` ledger row) or, for the bulk reboot, an audited action; read-only
mode refuses before the device is contacted.

Two of them also reported refusals as success, fixed with the conversion:
the 802.1X push ignored the controller's answer and recorded every push as
"pushed", and the config-version rollback called ``adapter.push_config``, a
method no adapter has ever had, so every rollback failed with AttributeError.

Adapters are fakes; nothing is contacted.
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
from app.adapters.base import AdapterResult, BaseAdapter
from app.core.crypto import encrypt_credential
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.devices import Device
from app.models.security_audit import AuditLogRecord
from app.models.staging import AdapterPendingChange


class _Fake:
    """A device that implements every write the services use; records calls."""

    def __init__(self, box: SimpleNamespace) -> None:
        self.box = box

    async def __aenter__(self) -> _Fake:
        self.box.entered += 1
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def _record(self, name: str, *args: Any) -> Any:
        self.box.calls.append((name, args))
        return self.box.answer

    async def push_full_config(self, device_id: str, config: dict[str, Any]) -> Any:
        return await self._record("push_full_config", device_id, config)

    async def update_dot1x_config(self, config: dict[str, Any]) -> Any:
        return await self._record("update_dot1x_config", config)

    async def update_ssid_config(self, ssid_id: str, config: dict[str, Any]) -> Any:
        return await self._record("update_ssid_config", ssid_id, config)

    async def reboot_device(self, device_id: str) -> Any:
        return await self._record("reboot_device", device_id)

    async def upgrade_firmware(self, device_id: str) -> Any:
        return await self._record("upgrade_firmware", device_id)

    async def get_running_config(self, _device_id: str) -> dict[str, Any]:
        return {"hostname": "old"}

    async def normalize_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return config

    async def diff_config(self, desired: dict[str, Any], running: dict[str, Any]) -> Any:
        return None if desired == running else {"hostname": [running, desired]}


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def world(db_session):
    org = Organization(name="service writes", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="c", site_id=site.id, controller_type="omada", host="192.0.2.60", port=443
    )
    db_session.add(ctrl)
    await db_session.flush()
    device = Device(
        name="sw1",
        site_id=site.id,
        controller_id=ctrl.id,
        device_type="switch",
        mac_address="aa:bb:cc:00:00:60",
        status="online",
    )
    db_session.add(device)
    await db_session.commit()
    box = SimpleNamespace(entered=0, calls=[], answer=AdapterResult.ok({"ok": True}))
    return SimpleNamespace(org=org, site=site, ctrl=ctrl, device=device, box=box)


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


# ── config-version rollback ──────────────────────────────────────────────────


async def _version(db_session, world, monkeypatch) -> Any:
    """A version to roll back to, and the service.

    ``record_version`` is replaced: on PostgreSQL it fails before this code is
    reached (``SELECT max(...) FOR UPDATE`` is rejected: "FOR UPDATE is not
    allowed with aggregate functions"), a separate defect reported with this
    change. These tests are about the device write.
    """
    from app.models.enterprise import ConfigVersion
    from app.services.config_versions import ConfigVersionService

    version = ConfigVersion(
        device_id=world.device.id,
        organization_id=world.org.id,
        version_number=1,
        config_snapshot={"hostname": "sw1"},
        source="manual",
    )
    db_session.add(version)
    await db_session.commit()
    svc = ConfigVersionService(db_session)

    async def _reserved(**_kwargs: Any) -> Any:
        return SimpleNamespace(id=uuid4(), version_number=2)

    monkeypatch.setattr(svc, "record_version", _reserved)
    return svc, version


async def test_a_rollback_is_staged_and_pushes_the_version(
    db_session, world, mode, monkeypatch
) -> None:
    svc, version = await _version(db_session, world, monkeypatch)
    user = uuid4()

    await svc.rollback(world.device.id, version.id, _Fake(world.box), user_id=user)

    ((name, args),) = world.box.calls
    assert name == "push_full_config"
    assert args == ("aa:bb:cc:00:00:60", {"hostname": "sw1"})
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.device.config.rollback"
    assert row.status == "applied"
    assert row.controller_id == world.ctrl.id
    assert row.created_by == user
    assert row.payload["version_id"] == str(version.id)


async def test_a_rollback_is_refused_in_read_only_mode(
    db_session, world, mode, monkeypatch
) -> None:
    svc, version = await _version(db_session, world, monkeypatch)
    mode["read_only"] = True

    with pytest.raises(HTTPException) as refused:
        await svc.rollback(world.device.id, version.id, _Fake(world.box))

    assert refused.value.status_code == 403
    assert world.box.entered == 0
    assert await _ledger(db_session) == []


async def test_a_rollback_the_device_refuses_is_an_error_and_recorded(
    db_session, world, mode, monkeypatch
) -> None:
    svc, version = await _version(db_session, world, monkeypatch)
    world.box.answer = AdapterResult.fail("config rejected")

    with pytest.raises(RuntimeError, match="config rejected"):
        await svc.rollback(world.device.id, version.id, _Fake(world.box))
    (row,) = await _ledger(db_session)
    assert row.status == "failed"


async def test_a_rollback_on_an_adapter_without_full_config_push_contacts_nothing(
    db_session, world, mode, monkeypatch
) -> None:
    class _Placeholder(BaseAdapter):
        """BaseAdapter's push_full_config is a NOT_SUPPORTED placeholder."""

        def __init__(self) -> None:
            pass

        async def __aenter__(self) -> Any:
            raise AssertionError("the device must not be contacted")

    # BaseAdapter is abstract; only the placeholder matters here.
    _Placeholder.__abstractmethods__ = frozenset()
    svc, version = await _version(db_session, world, monkeypatch)
    with pytest.raises(RuntimeError, match="cannot apply a full configuration"):
        await svc.rollback(world.device.id, version.id, _Placeholder())
    assert await _ledger(db_session) == []


# ── drift auto-remediation ───────────────────────────────────────────────────


async def test_drift_auto_remediation_is_staged(db_session, world, mode, monkeypatch) -> None:
    from app.models.enterprise import DeviceConfig
    from app.services.enterprise import ReconciliationService

    db_session.add(
        DeviceConfig(device_id=world.device.id, organization_id=world.org.id, auto_remediate=True)
    )
    await db_session.commit()
    svc = ReconciliationService(db_session)

    async def _desired(_device: Any) -> dict[str, Any]:
        return {"hostname": "new"}

    async def _health(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(svc.template_resolver, "resolve", _desired)
    monkeypatch.setattr(svc.health_service, "compute_device_health", _health)

    async def _no_version(*_a: Any, **_k: Any) -> None:
        # See _version: record_version fails on PostgreSQL (reported separately).
        return None

    monkeypatch.setattr(
        "app.services.config_versions.ConfigVersionService.record_version", _no_version
    )

    out = await svc.reconcile_device(world.device, _Fake(world.box))

    assert out["push_status"] == "success"
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.device.config.drift"
    assert row.status == "applied"
    assert row.created_by is None

    # Read-only mode: refused before the device is asked, and said so.
    mode["read_only"] = True
    world.box.calls.clear()
    out = await svc.reconcile_device(world.device, _Fake(world.box))
    assert out["push_status"] == "error"
    assert "Read-only mode is on" in out["push_error"]
    assert [c[0] for c in world.box.calls] == []


# ── no adapter implements push_full_config: refused before anything ───────


class _NoFullConfigPush:
    """Reads like a real adapter, but cannot apply a whole configuration."""

    def __init__(self, box: SimpleNamespace) -> None:
        self.box = box

    async def __aenter__(self) -> Any:
        self.box.entered += 1
        raise AssertionError("the device must not be contacted")

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def get_running_config(self, _device_id: str) -> dict[str, Any]:
        return {"hostname": "old"}

    async def normalize_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return config

    async def diff_config(self, desired: dict[str, Any], running: dict[str, Any]) -> Any:
        return None if desired == running else {"hostname": [running, desired]}


async def test_a_rollback_that_cannot_apply_reserves_no_version_and_says_why(
    db_session, world, mode, monkeypatch
) -> None:
    from app.services.device_writes import FullConfigPushUnsupported

    svc, version = await _version(db_session, world, monkeypatch)
    reserved: list[Any] = []

    async def _reserve(**kwargs: Any) -> Any:
        reserved.append(kwargs)
        return SimpleNamespace(id=uuid4(), version_number=2)

    monkeypatch.setattr(svc, "record_version", _reserve)

    with pytest.raises(FullConfigPushUnsupported, match="Configuration rollback is not available"):
        await svc.rollback(world.device.id, version.id, _NoFullConfigPush(world.box))

    assert reserved == [], "no rollback version for a rollback that cannot happen"
    assert world.box.entered == 0
    assert await _ledger(db_session) == []


async def test_the_rollback_route_answers_501_with_the_reason(
    db_session, world, mode, monkeypatch
) -> None:
    from app.api.v1.endpoints.config_versions import rollback_config_version
    from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS, CurrentUser
    from app.models.core import User

    _svc, version = await _version(db_session, world, monkeypatch)

    async def _adapter(_device: Any) -> Any:
        return _NoFullConfigPush(world.box)

    monkeypatch.setattr("app.api.v1.endpoints.poe._get_adapter_for_device", _adapter)
    user = User(
        id=uuid4(),
        email="admin@example.com",
        username="admin",
        organization_id=world.org.id,
        role="org_admin",
        hashed_password="x",
        is_active=True,
    )
    principal = CurrentUser(user=user, permissions=list(DEFAULT_ROLE_PERMISSIONS["org_admin"]))

    with pytest.raises(HTTPException) as refused:
        await rollback_config_version(
            world.device.id, version.id, session=db_session, _user=principal
        )

    assert refused.value.status_code == 501
    assert "cannot apply a full configuration" in refused.value.detail
    assert world.box.entered == 0
    assert await _ledger(db_session) == []


async def test_drift_remediation_that_cannot_apply_contacts_nothing_and_records_no_push(
    db_session, world, mode, monkeypatch
) -> None:
    from app.models.enterprise import DeviceConfig
    from app.services.enterprise import ReconciliationService

    dc = DeviceConfig(device_id=world.device.id, organization_id=world.org.id, auto_remediate=True)
    db_session.add(dc)
    await db_session.commit()
    svc = ReconciliationService(db_session)
    backups: list[str] = []

    async def _desired(_device: Any) -> dict[str, Any]:
        return {"hostname": "new"}

    async def _health(*_a: Any, **_k: Any) -> None:
        return None

    async def _backup(_self: Any, _device: Any, reason: str) -> None:
        backups.append(reason)

    monkeypatch.setattr(svc.template_resolver, "resolve", _desired)
    monkeypatch.setattr(svc.health_service, "compute_device_health", _health)
    monkeypatch.setattr(
        "app.services.auto_backup.AutoBackupService.backup_before_change", _backup
    )

    out = await svc.reconcile_device(world.device, _NoFullConfigPush(world.box))

    assert out["push_status"] == "failed"
    assert "Drift auto-remediation is not available" in out["push_error"]
    assert backups == [], "no pre-change backup for a push that cannot happen"
    assert dc.pushed_at is None and not dc.pushed_config
    assert await _ledger(db_session) == []


# ── 802.1X profile push ──────────────────────────────────────────────────────


async def _dot1x(db_session, world, monkeypatch) -> Any:
    from app.models.radius import Dot1xPortConfig, RadiusServerProfile

    profile = RadiusServerProfile(
        organization_id=world.org.id,
        name="radius",
        host="192.0.2.70",
        port=1812,
        shared_secret_encrypted=encrypt_credential("radius-shared-secret"),
    )
    db_session.add(profile)
    await db_session.flush()
    config = Dot1xPortConfig(controller_id=world.ctrl.id, radius_profile_id=profile.id)
    db_session.add(config)
    await db_session.commit()
    # The push builds its adapter from the controller row
    # (build_adapter_for_controller), which ends in adapter_factory.get_adapter.
    built: list[dict[str, Any]] = []

    def _built(*_a: Any, **kwargs: Any) -> _Fake:
        built.append(kwargs)
        return _Fake(world.box)

    monkeypatch.setattr("app.services.adapter_factory.get_adapter", _built)
    world.box.built = built
    return config


async def test_an_8021x_push_is_staged_with_the_shared_secret_masked(
    db_session, world, mode, monkeypatch
) -> None:
    from app.services.radius import RadiusProfileService

    config = await _dot1x(db_session, world, monkeypatch)

    out = await RadiusProfileService(db_session).push_dot1x_config(config.id)

    assert out["success"] is True
    ((name, args),) = world.box.calls
    assert name == "update_dot1x_config"
    assert args[0]["shared_secret"] == "radius-shared-secret", "the controller needs the secret"
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.radius.dot1x"
    assert row.status == "applied"
    assert "radius-shared-secret" not in str(row.payload)
    assert config.push_status == "pushed"


async def test_an_8021x_push_the_controller_refuses_is_not_recorded_as_pushed(
    db_session, world, mode, monkeypatch
) -> None:
    from app.services.radius import RadiusProfileService

    config = await _dot1x(db_session, world, monkeypatch)
    world.box.answer = AdapterResult.fail("802.1X is not licensed on this controller")

    out = await RadiusProfileService(db_session).push_dot1x_config(config.id)

    assert out["success"] is False
    assert "not licensed" in out["error"]
    assert config.push_status == "failed"


async def test_an_8021x_push_is_refused_in_read_only_mode(
    db_session, world, mode, monkeypatch
) -> None:
    from app.services.radius import RadiusProfileService

    config = await _dot1x(db_session, world, monkeypatch)
    mode["read_only"] = True

    out = await RadiusProfileService(db_session).push_dot1x_config(config.id)

    assert out["success"] is False
    assert "Read-only mode is on" in out["error"]
    assert world.box.entered == 0
    assert config.push_status == "failed"


async def test_an_8021x_push_to_a_cloud_controller_uses_its_cloud_settings(
    db_session, world, mode, monkeypatch
) -> None:
    from app.services.radius import RadiusProfileService

    world.ctrl.config = {
        "connection_mode": "cloud",
        "client_id": "cloud-client",
        "client_secret": encrypt_credential("cloud-client-secret"),
        "omada_id": "omadac-1",
        "cloud_region": "eu",
    }
    await db_session.commit()
    config = await _dot1x(db_session, world, monkeypatch)

    out = await RadiusProfileService(db_session).push_dot1x_config(config.id)

    assert out["success"] is True
    (kwargs,) = world.box.built
    assert kwargs["mode"] == "cloud"
    assert kwargs["client_id"] == "cloud-client"
    assert kwargs["client_secret"] == "cloud-client-secret"
    assert kwargs["omada_id"] == "omadac-1"
    assert kwargs["cloud_region"] == "eu"


# ── SSID roaming push ────────────────────────────────────────────────────────


async def test_a_roaming_push_is_staged(db_session, world, mode, monkeypatch) -> None:
    from app.modules.network.models import WifiNetwork
    from app.services.roaming import RoamingAnalyticsService

    # The controller's own id for the SSID; FreeSDN's UUID means nothing to it.
    wifi = WifiNetwork(site_id=world.site.id, ssid="corp", external_id="ssid-on-controller")
    db_session.add(wifi)
    await db_session.commit()
    monkeypatch.setattr(
        "app.services.adapter_factory.get_adapter", lambda *_a, **_k: _Fake(world.box)
    )

    out = await RoamingAnalyticsService(db_session).push_roaming_config(
        wifi.id, {"fast_roaming": True, "roaming_protocol": "802.11r"}
    )

    assert out["fast_roaming"] is True
    ((name, args),) = world.box.calls
    assert name == "update_ssid_config"
    assert args[0] == "ssid-on-controller", "the controller is addressed by its own SSID id"
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.roaming.ssid"
    assert row.status == "applied"
    assert row.target_id == "ssid-on-controller"

    mode["read_only"] = True
    world.box.calls.clear()
    await RoamingAnalyticsService(db_session).push_roaming_config(wifi.id, {"minimum_rssi": -70})
    assert world.box.calls == [], "read-only mode must refuse before the controller is asked"


async def test_a_roaming_push_without_the_controllers_ssid_id_sends_nothing(
    db_session, world, mode, monkeypatch
) -> None:
    from app.modules.network.models import WifiNetwork
    from app.services.roaming import RoamingAnalyticsService

    wifi = WifiNetwork(site_id=world.site.id, ssid="never-synced")
    db_session.add(wifi)
    await db_session.commit()
    monkeypatch.setattr(
        "app.services.adapter_factory.get_adapter", lambda *_a, **_k: _Fake(world.box)
    )

    out = await RoamingAnalyticsService(db_session).push_roaming_config(
        wifi.id, {"fast_roaming": True}
    )

    assert out["fast_roaming"] is True, "the setting is still saved in FreeSDN"
    assert world.box.calls == [], "FreeSDN's UUID must never be sent as the SSID id"
    assert await _ledger(db_session) == []


# ── Celery bulk operations ───────────────────────────────────────────────────


@pytest.fixture
def bulk(world, monkeypatch: pytest.MonkeyPatch) -> Any:
    import app.tasks.bulk_operations as bulk_ops

    monkeypatch.setattr(bulk_ops, "_adapter_for_device", lambda _device: _Fake(world.box))

    class _Resolver:
        def __init__(self, _db: Any) -> None:
            pass

        async def resolve(self, _device: Any) -> dict[str, Any]:
            return {"hostname": "new"}

    monkeypatch.setattr(bulk_ops, "TemplateResolver", _Resolver)
    return bulk_ops


async def test_a_bulk_config_push_is_staged(db_session, world, mode, bulk) -> None:
    actor = uuid4()
    await bulk._push_config_to_device(db_session, world.device, None, actor_id=actor)

    assert [c[0] for c in world.box.calls] == ["push_full_config"]
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.bulk.config_push"
    assert row.created_by == actor


async def test_a_bulk_config_push_that_cannot_apply_contacts_nothing(
    db_session, world, mode, bulk, monkeypatch
) -> None:
    from app.services.device_writes import FullConfigPushUnsupported

    monkeypatch.setattr(bulk, "_adapter_for_device", lambda _d: _NoFullConfigPush(world.box))

    with pytest.raises(FullConfigPushUnsupported, match="Bulk config push is not available"):
        await bulk._push_config_to_device(db_session, world.device, None)

    assert world.box.entered == 0
    assert await _ledger(db_session) == []


async def test_a_bulk_firmware_upgrade_is_staged(db_session, world, mode, bulk) -> None:
    await bulk._firmware_update_device(db_session, world.device, {"firmware_version": "5.1"})

    (row,) = await _ledger(db_session)
    assert row.feature == "direct.bulk.firmware"
    assert row.payload["firmware_version"] == "5.1"


async def test_a_bulk_reboot_is_audited(db_session, world, mode, bulk) -> None:
    await bulk._reboot_device(db_session, world.device)

    assert [c[0] for c in world.box.calls] == ["reboot_device"]
    assert await _ledger(db_session) == []
    (record,) = await _actions(db_session)
    assert record.action == "device_action:reboot_device"


async def test_bulk_operations_are_refused_in_read_only_mode(db_session, world, mode, bulk) -> None:
    mode["read_only"] = True

    with pytest.raises(HTTPException):
        await bulk._firmware_update_device(db_session, world.device, None)
    with pytest.raises(RuntimeError, match="read-only mode is on"):
        await bulk._reboot_device(db_session, world.device)
    with pytest.raises(HTTPException):
        await bulk._push_config_to_device(db_session, world.device, None)

    assert [c[0] for c in world.box.calls] == []
    assert await _ledger(db_session) == []
    assert await _actions(db_session) == []
