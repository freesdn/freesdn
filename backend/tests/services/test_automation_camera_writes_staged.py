# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
An automation rule's camera write is staged, and its camera reboot is audited.

moved the automation engine's camera actions onto the chokepoint:
``camera.motion_detection`` writes through ``write_through_staging`` (a
``direct.camera.motion_detection.automation`` ledger row, refused in read-only
mode) and ``camera.reboot`` through ``audited_device_action`` (an audit record
once the camera accepts it). Nothing tested either. These drive the real
action handlers with the camera lookup, the author's permission check and the
adapter replaced by fakes, and the ledger written to the test database.
"""

from __future__ import annotations

import contextlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

import app.core.runtime_flags as rf
import app.services.device_writes as device_writes
from app.models.core import Organization, Site
from app.models.security_audit import AuditLogRecord
from app.models.staging import AdapterPendingChange
from app.services.automation import Action, ActionType, AutomationEngine


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def rule(db_session, monkeypatch: pytest.MonkeyPatch):
    org = Organization(name="automation camera", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.commit()

    actor = SimpleNamespace(
        id=uuid4(),
        organization_id=org.id,
        role="org_admin",
        is_active=True,
        deleted_at=None,
        site_access=[],
    )
    camera = SimpleNamespace(
        id=uuid4(), organization_id=org.id, site_id=site.id, deleted_at=None, name="door"
    )
    # The handlers open their own session for the camera lookup; it is a fake.
    lookup_db = MagicMock()
    lookup_db.get = AsyncMock(return_value=camera)
    row = MagicMock()
    row.scalar_one_or_none.return_value = site.id
    row.one_or_none.return_value = (camera.id, site.id)
    lookup_db.execute = AsyncMock(return_value=row)
    lookup_db.__aenter__ = AsyncMock(return_value=lookup_db)
    lookup_db.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr("app.db.async_session_factory", MagicMock(return_value=lookup_db))
    monkeypatch.setattr("app.core.dependencies._get_user_by_id", AsyncMock(return_value=actor))
    monkeypatch.setattr(
        "app.modules.cameras.service.CameraAccessService.check_access",
        AsyncMock(
            return_value={
                "has_access": True,
                "can_live": True,
                "can_ptz": True,
                "can_configure": True,
            }
        ),
    )
    # ...and the ledger row and audit record go to the test database.
    monkeypatch.setattr(
        device_writes, "ledger_session_factory", lambda _db: contextlib.nullcontext(db_session)
    )
    adapter = SimpleNamespace(
        set_motion_detection=AsyncMock(return_value=SimpleNamespace(success=True, data={})),
        reboot_device=AsyncMock(return_value=SimpleNamespace(success=True, data={})),
        disconnect=AsyncMock(),
    )
    monkeypatch.setattr(
        "app.modules.cameras.api._get_adapter_for_camera", AsyncMock(return_value=(adapter, 1))
    )
    return SimpleNamespace(
        engine=AutomationEngine(),
        camera=camera,
        org=org,
        adapter=adapter,
        context={"organization_id": str(org.id), "actor_id": str(actor.id)},
    )


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


def _action(rule, action_type: ActionType, **params) -> Action:
    return Action(action_type=action_type, params={"camera_id": str(rule.camera.id), **params})


async def test_motion_detection_from_a_rule_is_recorded_in_the_ledger(
    db_session, rule, mode
) -> None:
    result = await rule.engine._execute_action(
        _action(rule, ActionType.CAMERA_MOTION_DETECTION, enabled=False, sensitivity_level=40),
        rule.context,
    )

    assert result.success is True
    rule.adapter.set_motion_detection.assert_awaited_once()
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.camera.motion_detection.automation"
    assert row.status == "applied"
    assert row.organization_id == rule.org.id
    assert row.target_id == str(rule.camera.id)
    assert row.payload == {"enabled": False, "sensitivity_level": 40}
    assert await _actions(db_session) == []


async def test_motion_detection_from_a_rule_is_refused_in_read_only_mode(
    db_session, rule, mode
) -> None:
    mode["read_only"] = True
    result = await rule.engine._execute_action(
        _action(rule, ActionType.CAMERA_MOTION_DETECTION, enabled=True), rule.context
    )

    assert result.success is False
    assert "Read-only mode is on" in (result.error or "")
    rule.adapter.set_motion_detection.assert_not_awaited()
    assert await _ledger(db_session) == []


async def test_a_camera_refusal_is_recorded_as_failed(db_session, rule, mode) -> None:
    rule.adapter.set_motion_detection.return_value = SimpleNamespace(
        success=False, error="camera refused", error_code=None, data=None
    )
    result = await rule.engine._execute_action(
        _action(rule, ActionType.CAMERA_MOTION_DETECTION, enabled=True), rule.context
    )

    assert result.success is False
    (row,) = await _ledger(db_session)
    assert row.status == "failed"
    assert "camera refused" in (row.failure_reason or "")


async def test_a_camera_reboot_from_a_rule_is_audited_not_staged(db_session, rule, mode) -> None:
    result = await rule.engine._execute_action(
        _action(rule, ActionType.CAMERA_REBOOT), rule.context
    )

    assert result.success is True
    rule.adapter.reboot_device.assert_awaited_once()
    assert await _ledger(db_session) == []
    (record,) = await _actions(db_session)
    assert record.action == "device_action:reboot_device"
    assert record.organization_id == rule.org.id
    assert record.new_state["parameters"] == {"source": "automation"}
    assert record.new_state["target_id"] == str(rule.camera.id)


async def test_a_camera_reboot_the_camera_refuses_leaves_no_record(db_session, rule, mode) -> None:
    rule.adapter.reboot_device.return_value = SimpleNamespace(success=False, error="busy")
    result = await rule.engine._execute_action(
        _action(rule, ActionType.CAMERA_REBOOT), rule.context
    )

    assert result.success is False
    assert await _actions(db_session) == []
