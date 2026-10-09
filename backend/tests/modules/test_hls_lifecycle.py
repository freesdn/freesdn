# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A disconnected viewer must not retain a transcoder for the six-hour ceiling."""

import asyncio
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from app.modules.cameras import service as cameras


@pytest.fixture
async def owned_hls(monkeypatch, tmp_path):
    class Clock:
        current = datetime(2026, 1, 1, tzinfo=UTC)

        @classmethod
        def now(cls, timezone):
            assert timezone is UTC
            return cls.current

        @classmethod
        def advance(cls, seconds):
            cls.current += timedelta(seconds=seconds)

    cls = cameras.HLSStreamService
    monkeypatch.setattr(cameras, "datetime", Clock)
    monkeypatch.setattr(cls, "_sessions", {})
    monkeypatch.setattr(cls, "_lock", asyncio.Lock())
    monkeypatch.setattr(cls, "HLS_DIR", str(tmp_path / "hls"))
    # Exercise real child ownership/termination without a camera or FFmpeg.
    monkeypatch.setattr(
        cls,
        "_build_ffmpeg_args",
        staticmethod(lambda *_args: [sys.executable, "-c", "import time;time.sleep(180)"]),
    )
    service = cls()
    camera, organization = uuid4(), uuid4()
    row = await service.start_session(
        camera,
        "source",
        "rtsp://owned.example.invalid/video",
        organization_id=organization,
    )
    sid = row["session_id"]
    meta = service._sessions[sid]
    output = Path(meta["output_dir"])
    (output / "stream.m3u8").write_text("#EXTM3U\n")
    (output / "00001.ts").write_bytes(b"owned synthetic segment")
    try:
        yield service, sid, meta, Clock, camera, organization
    finally:
        for session_id, session_meta in list(service._sessions.items()):
            await service._kill_session(session_id, session_meta)


@pytest.mark.parametrize("viewers", [1, 2])
async def test_abandoned_viewers_release_child_and_private_files(owned_hls, viewers):
    service, sid, meta, clock, camera, organization = owned_hls
    if viewers == 2:
        joined = await service.start_session(
            camera,
            "source",
            "rtsp://owned.example.invalid/video",
            organization_id=organization,
        )
        assert joined["session_id"] == sid and joined["viewers"] == 2
    clock.advance(service.SESSION_TIMEOUT + 1)
    assert await service.cleanup_stale_sessions() == 1
    assert sid not in service._sessions
    assert meta["process"].returncode is not None
    assert meta["log_file"].closed
    assert not Path(meta["output_dir"]).exists()


async def test_idle_timeout_does_not_expire_a_session_early(owned_hls):
    service, sid, meta, clock, *_ = owned_hls
    clock.advance(service.SESSION_TIMEOUT)
    assert await service.cleanup_stale_sessions() == 0
    assert meta["process"].returncode is None
    clock.advance(0.001)
    assert await service.cleanup_stale_sessions() == 1
    assert sid not in service._sessions


@pytest.mark.parametrize("activity", ["heartbeat", "playlist", "segment"])
async def test_current_playback_keeps_session_alive_without_relying_on_viewer_count(
    owned_hls, activity
):
    service, sid, meta, clock, *_ = owned_hls
    clock.advance(service.SESSION_TIMEOUT - 1)
    if activity == "heartbeat":
        assert await service.heartbeat(sid)
    elif activity == "playlist":
        assert service.get_playlist_path(sid)
    else:
        assert service.get_segment_path(sid, "00001.ts")
    clock.advance(service.SESSION_TIMEOUT - 1)
    assert await service.cleanup_stale_sessions() == 0
    assert meta["process"].returncode is None
    clock.advance(2)
    assert await service.cleanup_stale_sessions() == 1


async def test_invalid_segment_does_not_extend_idle_session(owned_hls):
    service, sid, _, clock, *_ = owned_hls
    clock.advance(service.SESSION_TIMEOUT - 1)
    assert service.get_segment_path(sid, "../stream.m3u8") is None
    clock.advance(2)
    assert await service.cleanup_stale_sessions() == 1


async def test_explicit_last_viewer_stop_releases_child_immediately(owned_hls):
    service, sid, meta, *_ = owned_hls
    await service.stop_session(sid)
    assert meta["process"].returncode is not None
    assert sid not in service._sessions
    assert not Path(meta["output_dir"]).exists()


async def test_hard_age_ceiling_remains_even_with_recent_activity(owned_hls):
    service, sid, meta, clock, *_ = owned_hls
    clock.advance(service.MAX_SESSION_AGE + 1)
    assert await service.heartbeat(sid)
    assert await service.cleanup_stale_sessions() == 1
    assert meta["process"].returncode is not None
