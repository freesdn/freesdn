# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Camera config-write envelope: audit before/after + best-effort rollback."""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.modules.cameras import config_write
from app.modules.cameras.config_write import staged_camera_write


@pytest.fixture
def audit_calls(monkeypatch):
    calls: list[dict] = []

    class _FakeAudit:
        def __init__(self, db=None):
            pass

        async def log(self, **kw):
            calls.append(kw)

    monkeypatch.setattr(config_write, "AuditService", _FakeAudit)
    return calls


def _camera():
    return SimpleNamespace(id=uuid.uuid4(), name="Front Door", site_id=uuid.uuid4())


@pytest.mark.asyncio
async def test_success_audits_before_and_after(audit_calls) -> None:
    cam = _camera()
    rolled = []

    async def capture():
        return {"enabled": False, "sensitivity_level": 20}

    async def apply():
        return {"success": True, "enabled": True}

    async def rollback(old):
        rolled.append(old)

    out = await staged_camera_write(
        db=object(), actor_id=cam.id, organization_id=uuid.uuid4(), camera=cam,
        feature="motion_detection", capture=capture, apply=apply, rollback=rollback,
    )
    assert out == {"success": True, "enabled": True}
    assert rolled == []  # no rollback on success
    assert len(audit_calls) == 1
    meta = audit_calls[0]["extra_metadata"]
    assert meta["config"] == "motion_detection"
    assert meta["outcome"] == "success"
    assert meta["before"] == {"enabled": False, "sensitivity_level": 20}
    assert meta["after"] == {"success": True, "enabled": True}


@pytest.mark.asyncio
async def test_failure_rolls_back_and_audits_failure(audit_calls) -> None:
    cam = _camera()
    rolled = []
    old_state = {"enabled": False, "sensitivity_level": 20}

    async def capture():
        return old_state

    async def apply():
        raise RuntimeError("device PUT failed")

    async def rollback(old):
        rolled.append(old)

    with pytest.raises(RuntimeError):
        await staged_camera_write(
            db=object(), actor_id=cam.id, organization_id=uuid.uuid4(), camera=cam,
            feature="line_crossing", capture=capture, apply=apply, rollback=rollback,
        )
    assert rolled == [old_state]  # restored to captured pre-state
    meta = audit_calls[0]["extra_metadata"]
    assert meta["outcome"] == "failure"
    assert meta["rolled_back"] is True
    assert "device PUT failed" in meta["error"]


@pytest.mark.asyncio
async def test_capture_failure_does_not_block_apply(audit_calls) -> None:
    cam = _camera()

    async def capture():
        raise RuntimeError("GET failed")

    async def apply():
        return {"success": True}

    out = await staged_camera_write(
        db=object(), actor_id=cam.id, organization_id=uuid.uuid4(), camera=cam,
        feature="privacy_masks", capture=capture, apply=apply,
    )
    assert out == {"success": True}
    assert audit_calls[0]["extra_metadata"]["before"] is None


@pytest.mark.asyncio
async def test_error_payload_prestate_is_not_rolled_back_to(audit_calls) -> None:
    cam = _camera()
    rolled = []

    async def capture():
        return {"error": "device unreachable"}  # not a clean state — unsafe to restore

    async def apply():
        raise RuntimeError("PUT failed")

    async def rollback(old):
        rolled.append(old)

    with pytest.raises(RuntimeError):
        await staged_camera_write(
            db=object(), actor_id=cam.id, organization_id=uuid.uuid4(), camera=cam,
            feature="field_detection", capture=capture, apply=apply, rollback=rollback,
        )
    assert rolled == []  # never roll back to an error payload
    assert audit_calls[0]["extra_metadata"]["rolled_back"] is False
