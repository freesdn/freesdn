# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Zero-touch provisioning writes go through the staging chokepoint, and a
provisioning profile's configuration template is actually used.

Two defects:

* The adoption pipeline (adopt, firmware upgrade, provisioning push) and
  "apply profile" called the adapter directly. Nothing reached the staging
  ledger, so a ZTP write left no record of what was sent, and "apply profile"
  needed no ``force`` at all. Only the adapter clients' own read-only gates
  stood between a ZTP write and the device.
* ``ProvisioningProfileService.apply_profile`` merged the linked template from
  ``tpl.config_data``. ``ConfigTemplate`` has no such attribute (its values are
  ``config``), so applying any profile with a template raised AttributeError
  before anything was sent, and the adoption pipeline ignored the template, so
  the two paths pushed different configurations for one profile.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
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
from app.models.enterprise import ConfigTemplate
from app.models.staging import AdapterPendingChange
from app.models.ztp import AdoptionJobStatus, ProvisioningProfile
from app.services.ztp import AdoptionOrchestrator, ProvisioningProfileService


class _Adapter:
    def __init__(self, **results: Any) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self._results = results

    async def __aenter__(self) -> _Adapter:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)

        async def _call(*args: Any) -> Any:
            self.calls.append((name, args))
            return self._results.get(name, AdapterResult.ok({}))

        return _call


@pytest.fixture
def writable(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def world(db_session):
    org = Organization(name="ZTP staging", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="ztp", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="ztp controller", site_id=site.id, controller_type="omada", host="127.0.0.1", port=443
    )
    db_session.add(ctrl)
    await db_session.flush()
    device = Device(
        name="sw-ztp",
        site_id=site.id,
        controller_id=ctrl.id,
        device_type="switch",
        mac_address="aa:bb:cc:00:11:22",
        status="online",
    )
    db_session.add(device)
    await db_session.commit()
    return SimpleNamespace(org=org, site=site, ctrl=ctrl, device=device)


def _orchestrator(db_session, adapter: _Adapter) -> AdoptionOrchestrator:
    orch = AdoptionOrchestrator(ledger_session_factory=lambda: contextlib.nullcontext(db_session))

    async def _get_adapter(*_a: Any) -> _Adapter:
        return adapter

    orch._get_adapter = _get_adapter  # type: ignore[method-assign]
    return orch


def _job(world) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        organization_id=world.org.id,
        triggered_by="manual",
        profile_id=None,
        status=AdoptionJobStatus.ADOPTING,
    )


async def _ledger(db_session) -> list[AdapterPendingChange]:
    rows = (
        await db_session.execute(
            select(AdapterPendingChange).where(AdapterPendingChange.feature.like("direct.ztp.%"))
        )
    ).scalars()
    return list(rows)


async def test_adoption_is_recorded_in_the_staging_ledger(db_session, world, writable) -> None:
    adapter = _Adapter()
    out = await _orchestrator(db_session, adapter)._step_adopt(
        world.device, _job(world), db_session
    )

    assert out == {"success": True}
    assert adapter.calls == [("adopt_device", ("aa:bb:cc:00:11:22",))]
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.ztp.adopt"
    assert row.status == "applied"
    assert row.controller_id == world.ctrl.id
    assert row.site_id == world.site.id
    assert row.target_id == "aa:bb:cc:00:11:22"
    assert row.applied_at is not None
    assert "zero-touch adoption job" in (row.notes or "")


async def test_read_only_mode_refuses_adoption_before_the_device(
    db_session, world, writable
) -> None:
    writable["read_only"] = True
    adapter = _Adapter()
    out = await _orchestrator(db_session, adapter)._step_adopt(
        world.device, _job(world), db_session
    )

    assert out["success"] is False
    assert "Read-only mode is on" in out["error"]
    assert adapter.calls == []
    assert await _ledger(db_session) == []


async def test_a_refused_adoption_is_recorded_as_failed(db_session, world, writable) -> None:
    adapter = _Adapter(adopt_device=AdapterResult.fail("device offline", error_code="OFFLINE"))
    out = await _orchestrator(db_session, adapter)._step_adopt(
        world.device, _job(world), db_session
    )

    assert out == {"success": False, "error": "device offline"}
    (row,) = await _ledger(db_session)
    assert row.status == "failed"
    assert "device offline" in (row.failure_reason or "")


async def _profile(db_session, world, *, template: dict[str, Any] | None, active: bool = True):
    tpl_id = None
    if template is not None:
        tpl = ConfigTemplate(
            organization_id=world.org.id,
            name="base",
            scope="organization",
            config=template,
            is_active=active,
        )
        db_session.add(tpl)
        await db_session.flush()
        tpl_id = tpl.id
    profile = ProvisioningProfile(
        organization_id=world.org.id,
        name="edge",
        device_type="switch",
        config_payload={"vlan": 20, "ntp": {"server": "10.0.0.1"}},
        config_template_id=tpl_id,
    )
    db_session.add(profile)
    await db_session.commit()
    return profile


async def test_apply_profile_merges_the_template_and_goes_through_staging(
    db_session, world, writable, monkeypatch
) -> None:
    profile = await _profile(
        db_session, world, template={"vlan": 10, "ntp": {"server": "x", "tz": "UTC"}, "dns": "1"}
    )
    adapter = _Adapter()

    async def _get_adapter(*_a: Any) -> _Adapter:
        return adapter

    monkeypatch.setattr(AdoptionOrchestrator, "_get_adapter", _get_adapter)
    out = await ProvisioningProfileService(db_session).apply_profile(
        world.device, profile, force=True, actor_id=None
    )

    assert out == {"success": True, "config_pushed": True}
    (name, args) = adapter.calls[0]
    assert name == "push_full_config"
    assert args[1] == {"vlan": 20, "ntp": {"server": "10.0.0.1", "tz": "UTC"}, "dns": "1"}
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.ztp.profile_apply"
    assert row.status == "applied"


async def test_apply_profile_needs_force_and_honours_read_only(
    db_session, world, writable, monkeypatch
) -> None:
    profile = await _profile(db_session, world, template=None)
    adapter = _Adapter()

    async def _get_adapter(*_a: Any) -> _Adapter:
        return adapter

    monkeypatch.setattr(AdoptionOrchestrator, "_get_adapter", _get_adapter)
    svc = ProvisioningProfileService(db_session)

    with pytest.raises(HTTPException) as no_force:
        await svc.apply_profile(world.device, profile, force=False)
    assert no_force.value.status_code == 403
    writable["read_only"] = True
    with pytest.raises(HTTPException) as read_only:
        await svc.apply_profile(world.device, profile, force=True)
    assert read_only.value.status_code == 403
    assert adapter.calls == []


async def test_apply_profile_no_longer_claims_an_unsupported_push(
    db_session, world, writable, monkeypatch
) -> None:
    profile = await _profile(db_session, world, template=None)
    adapter = _Adapter(push_full_config=AdapterResult.fail("nope", error_code="NOT_SUPPORTED"))

    async def _get_adapter(*_a: Any) -> _Adapter:
        return adapter

    monkeypatch.setattr(AdoptionOrchestrator, "_get_adapter", _get_adapter)
    out = await ProvisioningProfileService(db_session).apply_profile(
        world.device, profile, force=True
    )
    assert out["success"] is False
    assert "cannot push a full configuration" in out["error"]


async def test_adoption_provisioning_uses_the_template_too(db_session, world, writable) -> None:
    profile = await _profile(db_session, world, template={"dns": "1.1.1.1", "vlan": 10})
    adapter = _Adapter()
    job = _job(world)
    job.profile_id = profile.id
    out = await _orchestrator(db_session, adapter)._step_provision(world.device, job, db_session)

    assert out == {"success": True}
    (name, args) = adapter.calls[0]
    assert name == "push_full_config"
    assert args[1]["dns"] == "1.1.1.1" and args[1]["vlan"] == 20


async def test_an_inactive_or_deleted_template_is_not_merged(db_session, world, writable) -> None:
    profile = await _profile(db_session, world, template={"dns": "1.1.1.1"}, active=False)
    adapter = _Adapter()
    job = _job(world)
    job.profile_id = profile.id
    await _orchestrator(db_session, adapter)._step_provision(world.device, job, db_session)
    assert "dns" not in adapter.calls[0][1][1]

    tpl = await db_session.get(ConfigTemplate, profile.config_template_id)
    tpl.is_active = True
    tpl.deleted_at = datetime.now(UTC)
    await db_session.commit()
    adapter.calls.clear()
    await _orchestrator(db_session, adapter)._step_provision(world.device, job, db_session)
    assert "dns" not in adapter.calls[0][1][1]
