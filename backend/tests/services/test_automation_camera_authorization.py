# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Native camera automation must authorize the stored author before I/O."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services.automation import Action, ActionType, AutomationEngine

CAMERA_ACTIONS = [
    (ActionType.CAMERA_PTZ, "cameras.ptz", "can_ptz"),
    (ActionType.CAMERA_SNAPSHOT, "cameras.view", "can_live"),
    (ActionType.CAMERA_MOTION_DETECTION, "cameras.manage", "can_configure"),
    (ActionType.CAMERA_REBOOT, "cameras.manage", "can_configure"),
]


@pytest.fixture
def camera_authorization(monkeypatch):
    org, actor_id, camera_id, site_id = (uuid4() for _ in range(4))
    actor = SimpleNamespace(
        id=actor_id,
        organization_id=org,
        role="org_admin",
        is_active=True,
        deleted_at=None,
        site_access=[],
    )
    camera = SimpleNamespace(id=camera_id, organization_id=org, site_id=site_id, deleted_at=None)
    db = MagicMock()
    db.get = AsyncMock(return_value=camera)
    site_row = MagicMock()
    site_row.scalar_one_or_none.return_value = site_id
    site_row.one_or_none.return_value = (camera_id, site_id)
    db.execute = AsyncMock(return_value=site_row)
    db.__aenter__ = AsyncMock(return_value=db)
    db.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr("app.db.async_session_factory", MagicMock(return_value=db))
    lookup = AsyncMock(return_value=actor)
    monkeypatch.setattr("app.core.dependencies._get_user_by_id", lookup)
    access = AsyncMock(
        return_value={
            "has_access": True,
            "can_live": True,
            "can_ptz": True,
            "can_configure": True,
        }
    )
    monkeypatch.setattr("app.modules.cameras.service.CameraAccessService.check_access", access)
    adapter = SimpleNamespace(
        ptz_control=AsyncMock(return_value=SimpleNamespace(success=True)),
        goto_preset=AsyncMock(return_value=SimpleNamespace(success=True)),
        get_snapshot=AsyncMock(return_value=b"owned snapshot"),
        set_motion_detection=AsyncMock(return_value=SimpleNamespace(success=True)),
        reboot_device=AsyncMock(return_value=SimpleNamespace(success=True)),
        disconnect=AsyncMock(),
    )
    connect = AsyncMock(return_value=(adapter, 1))
    monkeypatch.setattr("app.modules.cameras.api._get_adapter_for_camera", connect)
    return SimpleNamespace(
        engine=AutomationEngine(),
        actor=actor,
        camera=camera,
        db=db,
        lookup=lookup,
        access=access,
        adapter=adapter,
        connect=connect,
        context={"organization_id": str(org), "actor_id": str(actor_id)},
    )


@pytest.mark.parametrize("action_type,permission,flag", CAMERA_ACTIONS)
@pytest.mark.parametrize(
    "refusal",
    [
        "missing_actor",
        "invalid_actor",
        "deleted_actor",
        "inactive_actor",
        "foreign_actor",
        "missing_actor_row",
        "lost_permission",
        "outside_site",
        "camera_grant",
        "lookup_failure",
    ],
)
async def test_camera_automation_refuses_before_adapter_io(
    camera_authorization, action_type, permission, flag, refusal, monkeypatch
):
    f = camera_authorization
    if refusal == "missing_actor":
        f.context.pop("actor_id")
    elif refusal == "invalid_actor":
        f.context["actor_id"] = "not-a-uuid"
    elif refusal == "deleted_actor":
        f.actor.deleted_at = object()
    elif refusal == "inactive_actor":
        f.actor.is_active = False
    elif refusal == "foreign_actor":
        f.actor.organization_id = uuid4()
    elif refusal == "missing_actor_row":
        f.lookup.return_value = None
    elif refusal == "lost_permission":
        f.actor.role = "operator"
        monkeypatch.setattr(
            "app.core.dependencies._load_user_permissions", AsyncMock(return_value=[])
        )
    elif refusal == "outside_site":
        f.actor.role = "site_admin"
        f.actor.site_access = [SimpleNamespace(site_id=uuid4(), access_level="admin")]
    elif refusal == "camera_grant":
        f.access.return_value[flag] = False
    else:
        f.lookup.side_effect = RuntimeError("synthetic-private-database-detail")
    result = await f.engine._execute_action(
        Action(
            action_type=action_type,
            params={
                "camera_id": str(f.camera.id),
                "actor_id": str(uuid4()),  # An action payload cannot provide trusted identity.
                "__context__": {
                    "actor_id": str(uuid4()),
                    "organization_id": str(f.camera.organization_id),
                },
            },
        ),
        f.context,
    )
    assert result.success is False
    assert result.error and "synthetic-private-database-detail" not in result.error
    f.connect.assert_not_awaited()
    f.adapter.disconnect.assert_not_awaited()


@pytest.mark.parametrize("action_type,permission,flag", CAMERA_ACTIONS)
async def test_authorized_camera_action_uses_current_context_and_disconnects(
    camera_authorization, action_type, permission, flag
):
    f = camera_authorization
    result = await f.engine._execute_action(
        Action(
            action_type=action_type,
            params={
                "camera_id": str(f.camera.id),
                "actor_id": str(uuid4()),
            },
        ),
        f.context,
    )
    assert result.success is True
    f.lookup.assert_awaited_once_with(f.db, f.context["actor_id"])
    f.access.assert_awaited_once_with(
        user_id=f.actor.id,
        camera_id=f.camera.id,
        organization_id=f.camera.organization_id,
        user_role="org_admin",
    )
    f.connect.assert_awaited_once_with(f.camera, f.db)
    f.adapter.disconnect.assert_awaited_once()


@pytest.mark.parametrize("action_type,permission,flag", CAMERA_ACTIONS)
async def test_camera_access_lookup_error_is_fail_closed(
    camera_authorization, action_type, permission, flag
):
    f = camera_authorization
    f.access.side_effect = RuntimeError("synthetic-private-grant-detail")
    result = await f.engine._execute_action(
        Action(action_type=action_type, params={"camera_id": str(f.camera.id)}), f.context
    )
    assert result.success is False and "synthetic-private-grant-detail" not in result.error
    f.connect.assert_not_awaited()


async def test_camera_permission_revocation_is_observed_on_next_action(camera_authorization):
    f = camera_authorization
    action = Action(action_type=ActionType.CAMERA_REBOOT, params={"camera_id": str(f.camera.id)})
    first = await f.engine._execute_action(action, f.context)
    f.actor.is_active = False
    second = await f.engine._execute_action(action, f.context)
    assert first.success and not second.success
    assert f.lookup.await_count == 2
    f.connect.assert_awaited_once()


@pytest.mark.parametrize("action_type,permission,flag", CAMERA_ACTIONS)
@pytest.mark.parametrize("level", ["read", "unknown-level"])
async def test_camera_automation_honors_site_permission_ceiling(
    camera_authorization, action_type, permission, flag, level
):
    f = camera_authorization
    f.actor.role = "site_admin"
    f.actor.site_access = [SimpleNamespace(site_id=f.camera.site_id, access_level=level)]
    result = await f.engine._execute_action(
        Action(action_type=action_type, params={"camera_id": str(f.camera.id)}), f.context
    )
    allowed = level == "read" and action_type == ActionType.CAMERA_SNAPSHOT
    assert result.success is allowed
    assert f.connect.await_count == int(allowed)
