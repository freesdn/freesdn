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


def _orch(adapter):
    orch = AdoptionOrchestrator()
    orch._get_adapter = AsyncMock(return_value=adapter)  # type: ignore[method-assign]
    return orch


@pytest.fixture
def device():
    return SimpleNamespace(mac_address="aa:bb:cc:dd:ee:ff", id=uuid4(), name="sw1")


@pytest.mark.asyncio
async def test_step_adopt_success_on_adapterresult_ok(device):
    orch = _orch(_FakeAdapter("adopt_device", AdapterResult.ok({"adopted": True})))
    out = await orch._step_adopt(device, None, MagicMock())
    assert out["success"] is True


@pytest.mark.asyncio
async def test_step_adopt_fails_on_adapterresult_fail(device):
    orch = _orch(
        _FakeAdapter("adopt_device", AdapterResult.fail("device offline", error_code="OFFLINE"))
    )
    out = await orch._step_adopt(device, None, MagicMock())
    assert out["success"] is False
    assert "device offline" in (out.get("error") or "")


@pytest.mark.asyncio
async def test_step_adopt_skips_when_not_supported(device):
    orch = _orch(
        _FakeAdapter("adopt_device", AdapterResult.fail("nope", error_code="NOT_SUPPORTED"))
    )
    out = await orch._step_adopt(device, None, MagicMock())
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
