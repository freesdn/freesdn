# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Exact HLS source/request reuse, with owned local children and stub adapters.

These tests do not claim database authorization, HTTP authentication or hardware
acceptance. Current authorization is stubbed before the source-identity path.
"""

import asyncio
import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException

from app.modules.cameras import api, service


@pytest_asyncio.fixture
async def streams(monkeypatch, tmp_path):
    cls = service.HLSStreamService
    monkeypatch.setattr(cls, "_sessions", {})
    monkeypatch.setattr(cls, "_lock", asyncio.Lock())
    monkeypatch.setattr(cls, "HLS_DIR", str(tmp_path / "hls"))
    monkeypatch.setattr(
        cls,
        "_build_ffmpeg_args",
        staticmethod(lambda *_args: [sys.executable, "-c", "import time;time.sleep(180)"]),
    )
    instance = cls()
    try:
        yield instance
    finally:
        for sid, meta in list(instance._sessions.items()):
            await instance._kill_session(sid, meta)
            assert meta["process"].returncode is not None
        assert not instance._sessions


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed",
    ["camera", "org", "quality", "codec", "mode", "host", "credentials", "path", "caller_key"],
)
async def test_different_media_sources_cannot_join_same_explicit_key(streams, changed):
    kwargs = {
        "camera_id": uuid4(),
        "organization_id": uuid4(),
        "quality": "source",
        "source_codec": "h264",
        "is_recorded": False,
        "rtsp_url": "rtsp://PRIVATE_USER:PRIVATE_PASSWORD@one.invalid/live",
        "session_key": "same-caller-key",
    }
    first = await streams.start_session(**kwargs)
    update = {
        "camera": ("camera_id", uuid4()),
        "org": ("organization_id", uuid4()),
        "quality": ("quality", "low"),
        "codec": ("source_codec", "h265"),
        "mode": ("is_recorded", True),
        "host": ("rtsp_url", kwargs["rtsp_url"].replace("one.invalid", "two.invalid")),
        "credentials": (
            "rtsp_url",
            kwargs["rtsp_url"].replace("PRIVATE_PASSWORD", "ROTATED_PASSWORD"),
        ),
        "path": ("rtsp_url", kwargs["rtsp_url"].replace("/live", "/recorded")),
        "caller_key": ("session_key", "different-window"),
    }
    key, value = update[changed]
    kwargs[key] = value
    second = await streams.start_session(**kwargs)
    assert second["session_id"] != first["session_id"]
    assert second["viewers"] == first["viewers"] == 1
    assert len(streams._sessions) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("recorded", [False, True])
async def test_identical_requests_share_one_owned_child(streams, recorded):
    kwargs = {
        "camera_id": uuid4(),
        "organization_id": uuid4(),
        "quality": "source",
        "rtsp_url": "rtsp://owned.example.invalid/live",
        "is_recorded": recorded,
        "session_key": "requested-window" if recorded else None,
    }
    first = await streams.start_session(**kwargs)
    second = await streams.start_session(**kwargs)
    assert first["session_id"] == second["session_id"]
    assert second["viewers"] == 2 and len(streams._sessions) == 1


@pytest.mark.asyncio
async def test_stored_session_key_does_not_retain_raw_caller_or_source_secrets(streams):
    row = await streams.start_session(
        uuid4(),
        "source",
        "rtsp://PRIVATE_USER:PRIVATE_PASSWORD@owned.invalid/video",
        organization_id=uuid4(),
        session_key="PRIVATE_CALLER_WINDOW",
    )
    key = streams._sessions[row["session_id"]]["session_key"]
    assert isinstance(key, str)
    assert "PRIVATE_" not in key and "rtsp://" not in key


@pytest_asyncio.fixture
async def playback(monkeypatch, streams):
    state = SimpleNamespace(
        url="rtsp://PRIVATE_USER:PRIVATE_PASSWORD@one.invalid/recorded",
        camera=SimpleNamespace(id=uuid4(), channel_id=1, vendor="hikvision"),
        user=SimpleNamespace(id=uuid4(), role="viewer", organization_id=uuid4()),
        now=100.0,
    )

    async def build(**kwargs):
        state.build_args = kwargs
        return state.url

    state.adapter = SimpleNamespace(
        connect=AsyncMock(),
        disconnect=AsyncMock(),
        get_playback_rtsp_url=AsyncMock(side_effect=build),
    )
    monkeypatch.setattr(
        service.StreamService, "_create_camera_adapter", lambda **_kwargs: state.adapter
    )
    state.probe = AsyncMock(
        return_value={"playable": True, "codec": "h264", "width": 64, "height": 48}
    )
    monkeypatch.setattr(api, "_probe_recorded_stream", state.probe)
    monkeypatch.setattr(api, "_RECORDED_PROBE_CACHE", {})
    monkeypatch.setattr(api, "time", SimpleNamespace(monotonic=lambda: state.now))
    monkeypatch.setattr(api, "_enforce_camera_access", AsyncMock())
    monkeypatch.setattr(
        api,
        "_resolve_credentials",
        AsyncMock(return_value=("one.invalid", 80, "owned", "synthetic")),
    )
    camera_service = SimpleNamespace(
        get_camera=AsyncMock(side_effect=lambda *_args, **_kwargs: state.camera)
    )

    async def local_transport(operation, **params):
        assert operation == "start"
        return await streams.start_session(**params)

    monkeypatch.setattr(api, "_shared_hls_request", local_transport)
    state.body = api.PlaybackHLSStartRequest(
        start_time=datetime(2026, 1, 1, tzinfo=UTC), duration_s=60, quality="low"
    )

    async def call(body=None):
        return await api.start_playback_hls_stream(
            state.camera.id, body or state.body, state.user, camera_service, object()
        )

    state.call = call
    state.streams = streams
    return state


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed", ["duration", "instant", "microsecond", "org", "source", "credentials"]
)
async def test_recording_window_or_source_change_gets_fresh_probe_and_session(playback, changed):
    state = playback
    first = await state.call()
    if changed == "duration":
        state.body = state.body.model_copy(update={"duration_s": 120})
    elif changed in ["instant", "microsecond"]:
        delta = timedelta(seconds=1) if changed == "instant" else timedelta(microseconds=1)
        state.body = state.body.model_copy(update={"start_time": state.body.start_time + delta})
    elif changed == "org":
        state.user.organization_id = uuid4()
    elif changed == "source":
        state.url = state.url.replace("one.invalid", "two.invalid")
    else:
        state.url = state.url.replace("PRIVATE_PASSWORD", "ROTATED_PASSWORD")
    second = await state.call()
    assert state.probe.await_count == 2
    assert second.session_id != first.session_id
    assert state.build_args["duration_s"] == state.body.duration_s
    assert "PRIVATE_" not in repr(list(api._RECORDED_PROBE_CACHE))


@pytest.mark.asyncio
async def test_unplayable_window_does_not_block_different_requested_window(playback):
    playback.probe.side_effect = [
        {"playable": False, "codec": None, "width": 0, "height": 0},
        {"playable": True, "codec": "h264", "width": 64, "height": 48},
    ]
    with pytest.raises(HTTPException) as error:
        await playback.call()
    assert error.value.status_code == 422
    body = playback.body.model_copy(
        update={"start_time": playback.body.start_time + timedelta(hours=1)}
    )
    result = await playback.call(body)
    assert result.session_id and playback.probe.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["same", "quality", "expired", "inconclusive", "unplayable"])
async def test_probe_cache_retains_only_appropriate_reuse(playback, kind):
    if kind == "inconclusive":
        playback.probe.return_value = None
    elif kind == "unplayable":
        playback.probe.return_value = {"playable": False, "codec": None, "width": 0, "height": 0}
    results = []
    for repeat in range(2):
        if repeat and kind == "quality":
            playback.body = playback.body.model_copy(update={"quality": "source"})
        if repeat and kind == "expired":
            playback.now += api._RECORDED_PROBE_TTL
        if kind == "unplayable":
            with pytest.raises(HTTPException) as error:
                await playback.call()
            assert error.value.status_code == 422
        else:
            results.append(await playback.call())
    assert playback.probe.await_count == (2 if kind in ["expired", "inconclusive"] else 1)
    if kind == "quality":
        assert results[0].session_id != results[1].session_id
    if kind == "same":
        assert results[0].session_id == results[1].session_id


@pytest.mark.asyncio
async def test_probe_cache_bound_evicts_oldest_result(playback, monkeypatch):
    monkeypatch.setattr(api, "_RECORDED_PROBE_MAX_ENTRIES", 2, raising=False)
    first = playback.camera.id
    for _ in range(4):
        await playback.call()
        playback.camera.id = uuid4()
    assert len(api._RECORDED_PROBE_CACHE) == 2
    playback.camera.id = first
    await playback.call()
    assert playback.probe.await_count == 5
    assert len(api._RECORDED_PROBE_CACHE) == 2


@pytest.mark.asyncio
async def test_adapter_error_does_not_log_native_secret_text(playback, caplog):
    playback.adapter.connect.side_effect = RuntimeError("PRIVATE_ADAPTER_CREDENTIAL")
    with pytest.raises(HTTPException) as error:
        await playback.call()
    assert error.value.status_code == 502
    assert "PRIVATE_ADAPTER_CREDENTIAL" not in caplog.text
    playback.adapter.disconnect.assert_awaited_once()
    assert playback.probe.await_count == 0 and not playback.streams._sessions
