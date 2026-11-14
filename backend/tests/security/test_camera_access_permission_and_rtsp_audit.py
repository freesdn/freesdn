"""``cameras.access`` grants and revokes per-camera permissions and returns the
camera's own login inside the RTSP stream URL. Operators no longer hold it;
site admins and above keep it through ``cameras.*``. Every issuance of an RTSP
stream URL is audited: who, which camera, which stream, never the URL or the
password."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.dependencies import (
    CurrentUser,
    PermissionDeniedError,
    _load_user_permissions,
)
from app.models.core import User
from app.modules.cameras import api as cameras_api

SECRET = "s3cr3t-camera-pass"


async def _principal(role: str) -> CurrentUser:
    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        organization_id=uuid4(),
        role=role,
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(
        user=user,
        permissions=await _load_user_permissions(user),
        accessible_site_ids=set(),
        scoped=False,
    )


@pytest.mark.parametrize(
    ("role", "holds"),
    [("viewer", False), ("operator", False), ("site_admin", True), ("org_admin", True)],
)
async def test_who_holds_camera_access(role: str, holds: bool) -> None:
    assert (await _principal(role)).has_permission("cameras.access") is holds


async def test_operator_is_refused_every_access_grant_route() -> None:
    operator = await _principal("operator")
    site_admin = await _principal("site_admin")
    checks = {}
    for route in cameras_api.access_router.routes:
        (dep,) = [d for d in route.dependant.dependencies if d.name == "current_user"]
        checks[(route.path, frozenset(route.methods))] = dep.call
    # Asking about one's own access to a camera stays open to every viewer.
    own = checks.pop(("/access/check/{camera_id}", frozenset({"GET"})))
    assert await own(current_user=operator) is operator
    # List, create, update and delete grants, and checking another user's access.
    assert len(checks) == 5, sorted(checks)
    for key, check in checks.items():
        with pytest.raises(PermissionDeniedError):
            await check(current_user=operator)
        assert await check(current_user=site_admin) is site_admin, key


async def test_operator_cannot_read_the_rtsp_url() -> None:
    service = MagicMock()
    service.get_stream_url = AsyncMock(return_value=f"rtsp://admin:{SECRET}@10.0.0.5:554/s")
    with pytest.raises(HTTPException) as exc:
        await cameras_api.get_stream_url(
            uuid4(), await _principal("operator"), service, stream_type="main", protocol="rtsp"
        )
    assert exc.value.status_code == 403
    service.get_stream_url.assert_not_awaited()


async def test_rtsp_url_issuance_is_audited_without_the_secret(monkeypatch) -> None:
    logged: list[dict[str, Any]] = []
    order: list[str] = []

    async def _log(self: Any, **kwargs: Any) -> None:
        order.append("audit")
        logged.append(kwargs)

    monkeypatch.setattr(cameras_api.AuditService, "log", _log)
    service = MagicMock()
    service.db = MagicMock()
    service.db.commit = AsyncMock(side_effect=lambda: order.append("commit"))
    url = f"rtsp://admin:{SECRET}@10.0.0.5:554/Streaming/Channels/102"
    service.get_stream_url = AsyncMock(return_value=url)
    admin = await _principal("site_admin")
    camera_id = uuid4()

    out = await cameras_api.get_stream_url(
        camera_id, admin, service, stream_type="sub", protocol="rtsp"
    )

    assert out == {"url": url, "protocol": "rtsp"}
    assert order == ["audit", "commit"], "the record is committed before the URL is returned"
    (entry,) = logged
    assert entry["resource_id"] == camera_id
    assert entry["actor_id"] == admin.id
    assert entry["extra_metadata"]["stream_type"] == "sub"
    assert SECRET not in repr(entry) and "rtsp://" not in repr(entry)


async def test_proxied_hls_url_is_not_audited(monkeypatch) -> None:
    log = AsyncMock()
    monkeypatch.setattr(cameras_api.AuditService, "log", log)
    service = MagicMock()
    service.get_stream_url = AsyncMock(return_value="/api/v1/cameras/x/stream/hls")
    await cameras_api.get_stream_url(
        uuid4(), await _principal("viewer"), service, stream_type="main", protocol="hls"
    )
    log.assert_not_awaited()
