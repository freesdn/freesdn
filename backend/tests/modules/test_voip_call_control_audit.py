# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
PBX call control leaves a durable audit record.

Originate, hang up and transfer are the PBX writes that deliberately stay live
while ``ADAPTER_READ_ONLY`` is on: the service passes ``force=True`` and the
FreePBX adapter lists them in ``_OPERATIONAL_OPS``. The camera exemptions (PTZ,
patrols, two-way audio) each write an audit row; these wrote none. Originate
published a transient event-bus message, hang up and transfer nothing at all,
so the one class of PBX action that bypasses monitor-only mode, and that
places real calls, left no record of who did it.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.modules.voip.service import VoIPService

ORG_ID = uuid4()
PBX_ID = uuid4()


class _Recorder:
    """Stands in for AuditService and keeps every log() call."""

    calls: list[dict[str, Any]] = []

    def __init__(self, db: Any) -> None:
        self.db = db

    async def log(self, **kwargs: Any) -> None:
        _Recorder.calls.append(kwargs)


class _Adapter:
    async def connect(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    async def originate_call(self, **_: Any) -> SimpleNamespace:
        return SimpleNamespace(success=True, data={"ActionID": "1"}, error=None)

    async def hangup_call(self, *_: Any, **__: Any) -> SimpleNamespace:
        return SimpleNamespace(success=True, data={}, error=None)

    async def transfer_call(self, *_: Any, **__: Any) -> SimpleNamespace:
        return SimpleNamespace(success=True, data={}, error=None)


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> VoIPService:
    import app.services.audit as audit_module

    _Recorder.calls = []
    monkeypatch.setattr(audit_module, "AuditService", _Recorder)
    db = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    svc = VoIPService(db=db, organization_id=ORG_ID)
    pbx = SimpleNamespace(id=PBX_ID, name="main-pbx", pbx_type="freepbx", last_seen=None)
    monkeypatch.setattr(svc, "get_pbx", AsyncMock(return_value=pbx))
    monkeypatch.setattr(svc, "_adapter_from_pbx", lambda _pbx: _Adapter())
    return svc


def _only_call() -> dict[str, Any]:
    assert len(_Recorder.calls) == 1, _Recorder.calls
    call = _Recorder.calls[0]
    assert call["organization_id"] == ORG_ID
    assert call["resource_id"] == PBX_ID
    return call


async def test_originate_is_audited(service: VoIPService) -> None:
    await service.originate_call(PBX_ID, "1001", "5551234")
    call = _only_call()
    assert call["action"] == "call_originate"
    assert call["extra_metadata"]["destination"] == "5551234"
    assert call["extra_metadata"]["channel"] == "SIP/1001"


async def test_hangup_is_audited(service: VoIPService) -> None:
    await service.hangup_call(PBX_ID, "SIP/1001-00000001")
    call = _only_call()
    assert call["action"] == "call_hangup"
    assert call["extra_metadata"]["channel"] == "SIP/1001-00000001"


async def test_transfer_is_audited(service: VoIPService) -> None:
    await service.transfer_call(PBX_ID, "SIP/1001-00000001", "2002")
    call = _only_call()
    assert call["action"] == "call_transfer"
    assert call["extra_metadata"]["destination"] == "2002"
