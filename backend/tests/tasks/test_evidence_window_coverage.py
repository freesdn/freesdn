# SPDX-License-Identifier: AGPL-3.0-only
"""A watermarked legal hold is sealed only when its clip covers the window.

Found in review of 26.11.2: FFmpeg ends a watermarked export with status 0
when the recorder stops sending part-way (a dropped connection), so the hold
worker hashed and sealed a partial clip as the whole requested window. The
recorder here is a double that streams a real 6-second clip
(fixtures/media/clip-6s.mp4); the coverage check runs the installed ffprobe.
Real PostgreSQL.
"""

from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from app.core.config import settings
from app.core.crypto import encrypt_credential
from app.models.core import Organization, Site
from app.modules.cameras.models import NVR, Camera, EvidenceArchive
from app.tasks import cameras as cam_tasks

CLIP = Path(__file__).resolve().parents[1] / "fixtures" / "media" / "clip-6s.mp4"

pytestmark = pytest.mark.skipif(shutil.which("ffprobe") is None, reason="ffprobe not installed")


class _Recorder:
    def __init__(self, host: str, **_kw: object) -> None:
        pass

    async def connect(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    async def stream_clip_watermarked(self, **_kw: object):
        data = CLIP.read_bytes()
        for i in range(0, len(data), 16384):
            yield data[i : i + 16384]


@pytest.fixture
def evidence(monkeypatch, db_session, tmp_path):
    monkeypatch.setattr("app.adapters.hikvision.adapter.HikvisionAdapter", _Recorder)

    class _Ctx:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    async def _private(_nvr):
        return "10.0.0.5", None

    monkeypatch.setattr(cam_tasks, "AsyncSessionLocal", lambda: _Ctx())
    monkeypatch.setattr(cam_tasks, "_pinned_nvr_host", _private)
    monkeypatch.setattr(settings, "EVIDENCE_DIR", str(tmp_path))
    return tmp_path


async def _hold(db_session, seconds: int) -> EvidenceArchive:
    suffix = uuid4().hex[:8]
    org = Organization(name="Evidence Org", slug=f"evid-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=f"evid-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    nvr = NVR(
        organization_id=org.id,
        site_id=site.id,
        name="nvr",
        ip_address="10.0.0.5",
        username="admin",
        password_encrypted=encrypt_credential("stored-secret"),
    )
    db_session.add(nvr)
    await db_session.flush()
    cam = Camera(
        organization_id=org.id,
        site_id=site.id,
        nvr_id=nvr.id,
        name="lobby",
        ip_address="10.0.0.9",
        channel_id=1,
    )
    db_session.add(cam)
    await db_session.flush()
    end = datetime.now(UTC)
    arch = EvidenceArchive(
        organization_id=org.id,
        camera_id=cam.id,
        start_time=end - timedelta(seconds=seconds),
        end_time=end,
        watermarked=True,
        status="pending",
    )
    db_session.add(arch)
    await db_session.flush()
    return arch


async def test_a_clip_covering_the_window_is_sealed(db_session, evidence):
    arch = await _hold(db_session, seconds=6)
    result = await cam_tasks._archive_evidence(arch.id)
    await db_session.refresh(arch)
    assert result["status"] == "ready", arch.error
    assert arch.sha256 and arch.file_path and os.path.isfile(arch.file_path)


async def test_a_clip_that_stops_early_is_not_sealed(db_session, evidence):
    """Fails on 26.11.2's candidate fix: 6 s of a 60 s window was sealed."""
    arch = await _hold(db_session, seconds=60)
    result = await cam_tasks._archive_evidence(arch.id)
    await db_session.refresh(arch)
    assert result["status"] == "failed"
    assert "6 s of video for the requested 60 s window" in (arch.error or "")
    assert arch.sha256 is None
    assert list(evidence.iterdir()) == []


async def test_a_short_hold_is_not_sealed_from_a_shorter_clip(db_session, evidence):
    """Fails on the first 26.11.3 candidate: its 10 s minimum tolerance let a
    15 s hold seal this 6 s clip."""
    arch = await _hold(db_session, seconds=15)
    result = await cam_tasks._archive_evidence(arch.id)
    await db_session.refresh(arch)
    assert result["status"] == "failed"
    assert "6 s of video for the requested 15 s window" in (arch.error or "")
    assert arch.sha256 is None


def test_a_gap_between_frames_is_not_counted_as_video():
    """A clip whose timestamps jump across a hole in the recording spans the
    window but does not cover it."""
    frames = [i / 25 for i in range(25 * 5)]  # 5 s of video at 25 fps
    frames += [50 + i / 25 for i in range(25 * 5)]  # 45 s hole, then 5 s more
    assert frames[-1] - frames[0] > 54
    assert cam_tasks._covered_seconds(frames) < 10


def test_the_allowed_shortfall_scales_with_the_window():
    assert cam_tasks._allowed_shortfall(2) == 1  # never more than half the window
    assert cam_tasks._allowed_shortfall(10) == 2
    assert cam_tasks._allowed_shortfall(60) == 6
    assert cam_tasks._allowed_shortfall(3600) == 10
