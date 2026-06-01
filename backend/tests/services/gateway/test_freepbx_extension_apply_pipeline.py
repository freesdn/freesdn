# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreePBX extension UPDATE through the FULL apply_change pipeline.

The recommended first live write is an extension update. This locks the STAGED
orchestration for it — dual-gate, the SELECT-FOR-UPDATE atomic claim, the
pending→applying→applied transitions, and error fidelity — with the real
FreePBXExtensionsService applier and only the device transport faked. When the
live mutation transport is implemented (needs the operator's FreePBX OAuth2 API
Application), the staging path it rides is already proven here.

Mirrors test_freepbx_apply_pipeline (inbound routes); session mocked, row real.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.models.staging import AdapterPendingChange
from app.services import adapter_staging
from app.services.adapter_freepbx_extensions import FreePBXExtensionsService
from app.services.adapter_staging import AdapterStagingService


class _RecAdapter:
    """Stands in for a connected FreePBXAdapter; records update_extension + force."""

    def __init__(self, *, fail_error: str | None = None) -> None:
        self.calls: list[tuple] = []
        self._fail = fail_error

    async def update_extension(self, target_id, payload, *, force=False):
        self.calls.append(("update_extension", target_id, payload, force))
        if self._fail:
            return AdapterResult.fail(error=self._fail)
        return AdapterResult.ok(data={"ok": True}, message="updated")


def _make_session():
    s = AsyncMock()
    s.commit = AsyncMock()
    s.refresh = AsyncMock()
    cnt = MagicMock()
    cnt.scalar.return_value = 0
    s.execute = AsyncMock(return_value=cnt)
    s.get = AsyncMock(return_value=None)
    return s


def _change():
    return AdapterPendingChange(
        id=uuid4(),
        organization_id=uuid4(),
        controller_id=uuid4(),
        site_id=None,
        feature="pbx.extension.update",
        operation="update",
        target_id="1001",
        payload={"name": "Front Desk", "ring_timer": 25},
        status="pending",
        notes=None,
    )


def _ext_applier(session, change, adapter):
    svc = FreePBXExtensionsService(session)

    async def _gc(cid, org):
        return SimpleNamespace(id=cid, controller_type="freepbx")

    async def _gx(ctrl):
        return adapter

    svc._get_controller = _gc  # type: ignore[assignment]
    svc._get_client = _gx  # type: ignore[assignment]
    return svc.build_applier(change)


@pytest.fixture(autouse=True)
def _env_open(monkeypatch):
    # Open the env half of the dual-gate so apply reaches the applier.
    monkeypatch.setattr(
        adapter_staging.AdapterStagingService, "is_read_only", staticmethod(lambda: False)
    )


@pytest.mark.asyncio
async def test_extension_update_applies_through_full_pipeline():
    """stage(pbx.extension.update) -> apply_change -> FreePBX applier ->
    adapter.update_extension(target_id, payload, force=True), pending->applying->applied."""
    session = _make_session()
    change = _change()
    session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))

    observed: list[str] = []
    session.commit = AsyncMock(side_effect=lambda: observed.append(change.status))

    adapter = _RecAdapter()
    applier = _ext_applier(session, change, adapter)
    result = await AdapterStagingService(session).apply_change(
        change.id, force=True, applier=applier
    )

    assert observed == ["applying", "applied"]  # two commits: claim + final
    assert result.status == "applied"
    name, target_id, payload, force = adapter.calls[-1]
    assert name == "update_extension" and force is True
    assert target_id == "1001"
    assert payload["name"] == "Front Desk"


@pytest.mark.asyncio
async def test_extension_update_failure_persists_real_vendor_error():
    """A FreePBX rejection lands in failure_reason verbatim (error fidelity)."""
    session = _make_session()
    change = _change()
    session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))

    adapter = _RecAdapter(fail_error="Extension 1001 does not exist")
    applier = _ext_applier(session, change, adapter)

    with pytest.raises(HTTPException) as ei:
        await AdapterStagingService(session).apply_change(change.id, force=True, applier=applier)

    assert ei.value.status_code == 502
    assert change.status == "failed"
    assert change.failure_reason == "Extension 1001 does not exist"
