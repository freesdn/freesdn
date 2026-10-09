# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""HLS continuation must resolve current scoped camera authority before activity."""

import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.modules.cameras import api, service


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["heartbeat", "playlist", "segment", "stop"])
@pytest.mark.parametrize(
    "kind",
    [
        "missing_camera",
        "foreign_camera",
        "deleted_camera",
        "denied_site",
        "denied_live",
        "denied_playback",
        "missing_metadata_camera",
        "bad_metadata_camera",
        "missing_metadata_org",
        "missing_metadata_mode",
        "bad_metadata_mode",
        "wrong_org",
        "allowed_unassigned",
        "allowed_site",
        "orgless_viewer",
        "scoped_platform",
        "allowed_platform_with_org",
        "allowed_scoped_tenant",
    ],
)
async def test_hls_continuation_requires_current_camera_authority(monkeypatch, route, kind):
    camera, org, site = uuid4(), uuid4(), uuid4()
    sid = uuid4().hex
    user = SimpleNamespace(
        id=uuid4(),
        organization_id=org,
        role="viewer",
        can_access_site=lambda _value: kind != "denied_site",
    )
    info = {
        "camera_id": str(camera),
        "organization_id": str(org),
        "is_recorded": kind == "denied_playback",
        "viewers": 1,
    }
    if kind in ["orgless_viewer", "scoped_platform"]:
        user.organization_id = None
        info["organization_id"] = None
        if kind == "scoped_platform":
            user.role = "super_admin"
            user._scoped = True
    elif kind == "allowed_platform_with_org":
        user.role = "super_admin"
        info["organization_id"] = None
    elif kind == "allowed_scoped_tenant":
        user.role = "super_admin"
        user._scoped = True
    if kind == "missing_metadata_camera":
        info.pop("camera_id")
    if kind == "bad_metadata_camera":
        info["camera_id"] = "invalid"
    if kind == "missing_metadata_org":
        info.pop("organization_id")
    if kind == "missing_metadata_mode":
        info.pop("is_recorded")
    if kind == "bad_metadata_mode":
        info["is_recorded"] = "recorded"
    if kind == "wrong_org":
        info["organization_id"] = str(uuid4())
    exists = kind not in ["missing_camera", "foreign_camera", "deleted_camera"]
    site_value = None if kind == "allowed_unassigned" else site
    row = MagicMock()
    row.scalar_one_or_none.return_value = site_value if exists else None
    row.one_or_none.return_value = (camera, site_value) if exists else None
    db = SimpleNamespace(execute=AsyncMock(return_value=row))
    permission = AsyncMock(
        return_value={
            "has_access": exists,
            "can_live": kind != "denied_live",
            "can_playback": kind != "denied_playback",
        }
    )
    monkeypatch.setattr(service.CameraAccessService, "check_access", permission)
    cls = service.HLSStreamService
    monkeypatch.setattr(cls, "_sessions", {sid: info})
    heartbeat = AsyncMock(return_value=True)
    stop = AsyncMock()
    playlist = MagicMock(return_value="/private/owned/stream.m3u8")
    segment = MagicMock(return_value="/private/owned/00001.ts")
    for name, value in [
        ("heartbeat", heartbeat),
        ("stop_session", stop),
        ("get_playlist_path", playlist),
        ("get_segment_path", segment),
    ]:
        monkeypatch.setattr(cls, name, value)

    async def local_transport(operation, **params):
        instance = cls()
        session_id = params["session_id"]
        if operation == "info":
            return cls._sessions.get(session_id)
        if operation == "heartbeat":
            return await instance.heartbeat(session_id)
        if operation == "stop":
            return await instance.stop_session(session_id)
        if operation == "playlist":
            return instance.get_playlist_path(session_id)
        if operation == "segment":
            return instance.get_segment_path(session_id, params["segment"])
        raise AssertionError(operation)

    monkeypatch.setattr(api, "_shared_hls_request", local_transport)
    functions = {
        "heartbeat": api.hls_heartbeat,
        "playlist": api.get_hls_playlist,
        "segment": api.get_hls_segment,
        "stop": api.stop_hls_stream,
    }
    fn = functions[route]
    kwargs = {"session_id": sid, "current_user": user}
    if "session" in inspect.signature(fn).parameters:
        kwargs["session"] = db
    if route == "segment":
        kwargs["segment"] = "00001.ts"
    allowed = kind.startswith("allowed_")
    if allowed:
        response = await fn(**kwargs)
        if route in ["playlist", "segment"]:
            assert "private" in response.headers["cache-control"]
            assert "no-store" in response.headers["cache-control"]
        if kind == "allowed_platform_with_org":
            permission.assert_not_awaited()
        else:
            permission.assert_awaited_once()
        statement = db.execute.call_args.args[0].compile()
        assert camera in statement.params.values()
        if kind == "allowed_platform_with_org":
            assert org not in statement.params.values()
        else:
            assert org in statement.params.values()
    else:
        with pytest.raises(HTTPException) as exc:
            await fn(**kwargs)
        assert exc.value.status_code == (
            403
            if kind in ["denied_live", "denied_playback", "orgless_viewer", "scoped_platform"]
            else 404
        )
        heartbeat.assert_not_awaited()
        stop.assert_not_awaited()
        playlist.assert_not_called()
        segment.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("exists", [True, False])
async def test_platform_scope_still_requires_a_current_camera(monkeypatch, exists):
    camera = uuid4()
    row = MagicMock()
    row.one_or_none.return_value = (camera, None) if exists else None
    row.scalar_one_or_none.return_value = None
    db = SimpleNamespace(execute=AsyncMock(return_value=row))
    user = SimpleNamespace(
        id=uuid4(), organization_id=None, role="super_admin", can_access_site=lambda _: True
    )
    if exists:
        await api._enforce_camera_access(db, user, camera, "live")
    else:
        with pytest.raises(HTTPException) as exc:
            await api._enforce_camera_access(db, user, camera, "live")
        assert exc.value.status_code == 404
    db.execute.assert_awaited_once()
