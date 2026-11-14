# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression: the ZTP adoption pipeline must treat adapter returns as AdapterResult.

A capability audit found ``_step_adopt`` called ``.get()`` on an ``AdapterResult``
dataclass -> ``AttributeError`` swallowed by the broad except -> adoption ALWAYS
failed (even for Omada, the only adapter that implements it). And ``_step_verify``
returned ``success`` on every branch, so a device that never came online was still
marked adopted/ONLINE. These tests lock the fixes.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.adapters.base import AdapterResult
from app.services.ztp import AdoptionOrchestrator


class _FakeAdapter:
    """Async-context-manager adapter exposing one mocked method."""

    def __init__(self, method: str, result):
        setattr(self, method, AsyncMock(return_value=result))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


async def _straight_through(**kwargs):
    """Stand-in for the staging chokepoint: these tests are about result handling.

    The chokepoint itself (read-only refusal, the ledger row) is covered by
    test_ztp_staging.py.
    """
    return await kwargs["perform"]()


def _orch(adapter):
    orch = AdoptionOrchestrator()
    orch._get_adapter = AsyncMock(return_value=adapter)  # type: ignore[method-assign]
    orch._device_write = _straight_through  # type: ignore[method-assign]
    return orch


def _job(**kwargs):
    return SimpleNamespace(
        id=uuid4(), organization_id=uuid4(), triggered_by="manual", profile_id=None, **kwargs
    )


@pytest.fixture
def device():
    return SimpleNamespace(mac_address="aa:bb:cc:dd:ee:ff", id=uuid4(), name="sw1")


@pytest.mark.asyncio
async def test_step_adopt_success_on_adapterresult_ok(device):
    orch = _orch(_FakeAdapter("adopt_device", AdapterResult.ok({"adopted": True})))
    out = await orch._step_adopt(device, _job(), MagicMock())
    assert out["success"] is True


@pytest.mark.asyncio
async def test_step_adopt_fails_on_adapterresult_fail(device):
    orch = _orch(
        _FakeAdapter("adopt_device", AdapterResult.fail("device offline", error_code="OFFLINE"))
    )
    out = await orch._step_adopt(device, _job(), MagicMock())
    assert out["success"] is False
    assert "device offline" in (out.get("error") or "")


@pytest.mark.asyncio
async def test_step_adopt_skips_when_not_supported(device):
    orch = _orch(
        _FakeAdapter("adopt_device", AdapterResult.fail("nope", error_code="NOT_SUPPORTED"))
    )
    out = await orch._step_adopt(device, _job(), MagicMock())
    assert out["success"] is True  # not-supported = skip, not failure


@pytest.mark.asyncio
async def test_step_verify_succeeds_only_when_online(device):
    online = _orch(_FakeAdapter("get_device_status", {"online": True}))
    assert (await online._step_verify(device, None, MagicMock()))["success"] is True

    no_status = _orch(_FakeAdapter("get_device_status", None))
    out = await no_status._step_verify(device, None, MagicMock())
    assert out["success"] is False  # was a false success before the fix


@pytest.mark.asyncio
async def test_step_verify_fails_when_no_adapter(device):
    orch = AdoptionOrchestrator()
    orch._get_adapter = AsyncMock(return_value=None)  # type: ignore[method-assign]
    out = await orch._step_verify(device, None, MagicMock())
    assert out["success"] is False


# ── skipped steps are not completed steps ────────────────────────


async def test_step_provision_not_supported_is_a_skip_not_a_completion(device):
    """No adapter implements push_full_config, so this is the common case."""
    orch = _orch(
        _FakeAdapter("push_full_config", AdapterResult.fail("nope", error_code="NOT_SUPPORTED"))
    )
    session = MagicMock()
    session.get = AsyncMock(
        return_value=SimpleNamespace(
            id=uuid4(),
            organization_id=uuid4(),
            config_payload={"vlan": 10},
            config_template_id=None,
            deleted_at=None,
        )
    )
    device.external_id = None
    job = SimpleNamespace(
        id=uuid4(), organization_id=uuid4(), triggered_by="manual", profile_id=uuid4()
    )
    out = await orch._step_provision(device, job, session)
    assert out["success"] is True
    assert "profile was not applied" in out["skipped"]


async def test_step_firmware_refused_is_a_skip(device):
    orch = _orch(_FakeAdapter("upgrade_firmware", AdapterResult.fail("busy", error_code="BUSY")))
    session = MagicMock()
    session.get = AsyncMock(
        return_value=SimpleNamespace(
            deleted_at=None, auto_firmware_update=True, target_firmware_version="2.0"
        )
    )
    device.firmware_version = "1.0"
    job = SimpleNamespace(
        id=uuid4(), organization_id=uuid4(), triggered_by="manual", profile_id=uuid4()
    )
    out = await orch._step_firmware_check(device, job, session)
    assert out["success"] is True
    assert "2.0 was not started: busy" in out["skipped"]


async def test_a_skipped_step_is_reported_and_not_listed_as_completed(monkeypatch):
    """The bug: provision was listed in steps_completed while nothing was applied."""
    from app.core import events
    from app.models.ztp import AdoptionJobStatus

    job = SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        status=AdoptionJobStatus.PENDING,
        current_step="validate",
        steps_completed=[],
        error_message=None,
        completed_at=None,
        triggered_by="manual",
        device=SimpleNamespace(id=uuid4(), name="sw1", controller_id=None),
    )
    session = MagicMock()
    session.execute = AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: job))
    session.flush = AsyncMock()
    published = []
    bus = SimpleNamespace(publish=AsyncMock(side_effect=published.append))
    monkeypatch.setattr(events, "get_event_bus", lambda: bus)

    orch = AdoptionOrchestrator()
    done = AsyncMock(return_value={"success": True})
    for step in ("validate", "adopt", "firmware_check", "verify"):
        setattr(orch, f"_step_{step}", done)
    orch._step_provision = AsyncMock(  # type: ignore[method-assign]
        return_value={"success": True, "skipped": "the profile was not applied"}
    )

    out = await orch.execute(job.id, session)

    assert out["success"] is True
    assert out["steps_completed"] == ["validate", "adopt", "firmware_check", "verify"]
    assert out["steps_skipped"] == ["provision: the profile was not applied"]
    assert job.status == AdoptionJobStatus.COMPLETED
    assert job.error_message.startswith("Adopted, but these steps did not run: provision")
    types = [e.event_type for e in published]
    assert "adoption.completed" in types, types  # was "adoption.adoption.completed"
    assert not any(t.startswith("adoption.adoption.") for t in types)
