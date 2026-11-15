# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Camera configuration writes go through the staging chokepoint.

The camera envelope (cameras/config_write.py) captured the pre-state, applied
the write straight to the device and audited it; the staging ledger never saw
a camera write, because cameras are not controller rows. Now every camera
config write, and its rollback, is a ``direct.camera.*`` ledger row, refused
while read-only mode is on.
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
from app.models.core import Organization, Site
from app.models.staging import AdapterPendingChange
from app.modules.cameras.config_write import staged_camera_write


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def camera(db_session) -> Any:
    org = Organization(name="cams", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.commit()
    return SimpleNamespace(id=uuid4(), organization_id=org.id, site_id=site.id, name="gate")


async def _rows(db_session) -> list[AdapterPendingChange]:
    return list(
        (
            await db_session.execute(
                select(AdapterPendingChange)
                .where(AdapterPendingChange.feature.like("direct.camera.%"))
                .order_by(AdapterPendingChange.created_at)
            )
        ).scalars()
    )


def _calls() -> tuple[list[str], Any, Any, Any]:
    log: list[str] = []

    async def capture() -> dict[str, Any]:
        log.append("capture")
        return {"enabled": False}

    async def apply() -> dict[str, Any]:
        log.append("apply")
        return {"success": True}

    async def rollback(old: Any) -> dict[str, Any]:
        log.append(f"rollback {old}")
        return {"success": True}

    return log, capture, apply, rollback


async def test_a_camera_config_write_is_in_the_ledger(db_session, camera, mode) -> None:
    log, capture, apply, rollback = _calls()
    actor = uuid4()
    out = await staged_camera_write(
        db=db_session,
        actor_id=actor,
        organization_id=None,
        camera=camera,
        feature="motion_detection",
        capture=capture,
        apply=apply,
        rollback=rollback,
    )

    assert out == {"success": True}
    assert log == ["capture", "apply"]
    (row,) = await _rows(db_session)
    assert row.feature == "direct.camera.motion_detection"
    assert row.status == "applied"
    assert row.controller_id is None
    assert row.organization_id == camera.organization_id
    assert row.target_id == str(camera.id)
    assert row.created_by == actor


async def test_read_only_mode_refuses_a_camera_write(db_session, camera, mode) -> None:
    mode["read_only"] = True
    log, capture, apply, rollback = _calls()
    with pytest.raises(HTTPException) as refused:
        await staged_camera_write(
            db=db_session,
            actor_id=None,
            organization_id=None,
            camera=camera,
            feature="motion_detection",
            capture=capture,
            apply=apply,
            rollback=rollback,
        )
    assert refused.value.status_code == 403
    assert log == ["capture"]  # a read; no write, and nothing to roll back
    assert await _rows(db_session) == []


async def test_a_failed_write_is_rolled_back_through_the_chokepoint(
    db_session, camera, mode
) -> None:
    log, capture, _apply, rollback = _calls()

    class _Rejected(RuntimeError):
        pass

    async def apply() -> dict[str, Any]:
        log.append("apply")
        raise _Rejected("device rejected the update")

    with pytest.raises(_Rejected):
        await staged_camera_write(
            db=db_session,
            actor_id=None,
            organization_id=None,
            camera=camera,
            feature="motion_detection",
            capture=capture,
            apply=apply,
            rollback=rollback,
        )
    assert log == ["capture", "apply", "rollback {'enabled': False}"]
    rows = await _rows(db_session)
    assert [(r.feature, r.status) for r in rows] == [
        ("direct.camera.motion_detection", "failed"),
        ("direct.camera.motion_detection.rollback", "applied"),
    ]
