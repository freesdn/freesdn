# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Moving a camera and configuring it are different permissions.

``cameras.ptz`` (held by the operator role) gated every PTZ endpoint, so an
operator could also save, overwrite and delete presets and patrol tours,
change auto-tracking and open two-way audio: changes every later viewer
inherits, and talk-back into the monitored space. Those now need
``cameras.manage_ptz``, which site_admin and above hold through ``cameras.*``.
Moving the camera, going to a preset and running or stopping a patrol stay on
``cameras.ptz``.

Each check evaluates the permission dependency FastAPI actually runs for the
route, with the default permission set of each role.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS, CurrentUser
from app.models.core import User
from app.modules.cameras.api import router

CONFIGURATION = [
    "set_ptz_preset",
    "set_ptz_tour",
    "delete_ptz_tour",
    "set_auto_tracking",
    "start_audio_session",
    "stop_audio_session",
]
MOVEMENT = ["control_ptz", "start_ptz_tour", "stop_ptz_tour"]


def _principal(role: str) -> CurrentUser:
    user = User(
        id=uuid4(),
        email=f"{role}@example.com",
        username=role,
        organization_id=uuid4(),
        role=role,
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(user=user, permissions=list(DEFAULT_ROLE_PERMISSIONS[role]))


def _permission_gate(endpoint: str) -> Any:
    """The require_permissions() closure on the route serving ``endpoint``."""
    routes = [
        r
        for r in router.routes
        if getattr(getattr(r, "endpoint", None), "__name__", None) == endpoint
    ]
    assert len(routes) == 1, f"{endpoint}: {len(routes)} routes"
    stack = list(routes[0].dependant.dependencies)
    while stack:
        dep = stack.pop()
        if "require_permissions" in getattr(dep.call, "__qualname__", ""):
            return dep.call
        stack.extend(dep.dependencies)
    raise AssertionError(f"{endpoint} has no require_permissions gate")


async def _allowed(endpoint: str, role: str) -> bool:
    try:
        await _permission_gate(endpoint)(current_user=_principal(role))
    except HTTPException as exc:
        assert exc.status_code == 403
        return False
    return True


@pytest.mark.parametrize("endpoint", CONFIGURATION)
async def test_an_operator_cannot_configure_ptz_or_talk_back(endpoint: str) -> None:
    assert await _allowed(endpoint, "operator") is False


@pytest.mark.parametrize("endpoint", CONFIGURATION)
async def test_a_site_admin_still_can(endpoint: str) -> None:
    assert await _allowed(endpoint, "site_admin") is True


@pytest.mark.parametrize("endpoint", MOVEMENT)
async def test_an_operator_can_still_move_cameras(endpoint: str) -> None:
    assert await _allowed(endpoint, "operator") is True


@pytest.mark.parametrize("endpoint", CONFIGURATION + MOVEMENT)
async def test_a_viewer_can_do_neither(endpoint: str) -> None:
    assert await _allowed(endpoint, "viewer") is False
