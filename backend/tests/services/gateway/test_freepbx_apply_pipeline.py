# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreePBX staged write through the FULL apply_change pipeline.

The other FreePBX tests invoke ``build_applier`` directly. This exercises a
``pbx.*`` change through the real ``AdapterStagingService.apply_change``
orchestration — dual-gate, the SELECT-FOR-UPDATE atomic claim, the
pending→applying→applied status transitions, and the failure path — with the
real FreePBX applier and only the device transport faked. It also locks the
error-fidelity fix: a failed apply must persist the real FreePBX message, not
the opaque "applier raised HTTPException".

Session is mocked (no DB); the row is a real model. Mirrors the
``test_staging_security`` apply-pipeline pattern.
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
from app.services.adapter_freepbx_inbound_routes import FreePBXInboundRoutesService
from app.services.adapter_staging import AdapterStagingService


class _RecAdapter:
    """Stands in for a connected FreePBXAdapter; records create_did + force."""

    def __init__(self, *, fail_error: str | None = None) -> None:
        self.calls: list[tuple] = []
        self._fail = fail_error

    async def create_did(self, data, *, force=False):
        self.calls.append(("create_did", data, force))
        if self._fail:
            return AdapterResult.fail(error=self._fail)
        return AdapterResult.ok(data={"ok": True}, message="created")


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
        feature="pbx.inbound_route.create",
        operation="create",
        target_id=None,
        payload={"extension": "15551234", "destination": "app-blackhole,hangup,1"},
        status="pending",
        notes=None,
    )


def _freepbx_applier(session, change, adapter):
    svc = FreePBXInboundRoutesService(session)

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
async def test_freepbx_change_applies_through_full_pipeline():
    """stage(pbx.inbound_route.create) -> apply_change -> FreePBX applier ->
    adapter.create_did(force=True), with pending->applying->applied."""
    session = _make_session()
    change = _change()
    session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))

    observed: list[str] = []
    session.commit = AsyncMock(side_effect=lambda: observed.append(change.status))

    adapter = _RecAdapter()
    applier = _freepbx_applier(session, change, adapter)
    result = await AdapterStagingService(session).apply_change(
        change.id, force=True, applier=applier
    )

    assert observed == ["applying", "applied"]  # two commits: claim + final
    assert result.status == "applied"
    # The FreePBX feature routed all the way to the adapter, forced.
    name, data, force = adapter.calls[-1]
    assert name == "create_did" and force is True
    assert data["extension"] == "15551234"


@pytest.mark.asyncio
async def test_freepbx_apply_failure_persists_real_vendor_error():
    """A FreePBX rejection must land in failure_reason verbatim (the
    error-fidelity fix), not the opaque 'applier raised HTTPException'."""
    session = _make_session()
    change = _change()
    session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))

    adapter = _RecAdapter(fail_error="Extension 15551234 already exists")
    applier = _freepbx_applier(session, change, adapter)

    with pytest.raises(HTTPException) as ei:
        await AdapterStagingService(session).apply_change(change.id, force=True, applier=applier)

    assert ei.value.status_code == 502
    assert change.status == "failed"
    assert change.failure_reason == "Extension 15551234 already exists"
    assert change.failure_reason != "applier raised HTTPException"
