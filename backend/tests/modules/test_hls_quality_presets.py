# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Decode real HLS output to check requested quality, using only synthetic files.

The fixture replaces RTSP input with local generated clips and limits native
threads. It is encoding behavior coverage, not vendor/network interoperability
or production concurrency/capacity qualification. Release images provide FFmpeg.
"""

import asyncio
import re
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio

from app.modules.cameras.service import HLSStreamService

_FFMPEG = shutil.which("ffmpeg")
pytestmark = pytest.mark.skipif(_FFMPEG is None, reason="native FFmpeg not installed")


def native(args):
    return subprocess.run(
        [_FFMPEG, "-hide_banner", "-loglevel", "error", "-nostdin", *args],
        capture_output=True,
        timeout=45,
        check=True,
    ).stdout


@pytest.fixture(scope="module")
def clips(tmp_path_factory):
    root = tmp_path_factory.mktemp("owned-quality-inputs")
    paths = {}
    for codec, encoder in [("h264", "libx264"), ("h265", "libx265")]:
        path = root / (codec + ".mp4")
        options = ["-crf", "0", "-preset", "ultrafast"]
        if codec == "h265":
            options += ["-x265-params", "pools=1:frame-threads=1:log-level=error"]
        native(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=1600x900:rate=4",
                "-frames:v",
                "9",
                "-an",
                "-c:v",
                encoder,
                "-threads",
                "1",
                "-g",
                "4",
                *options,
                str(path),
            ]
        )
        paths[codec] = path
    return paths


@pytest_asyncio.fixture
async def stream(monkeypatch, tmp_path, clips):
    cls = HLSStreamService
    monkeypatch.setattr(cls, "_sessions", {})
    monkeypatch.setattr(cls, "_lock", asyncio.Lock())
    monkeypatch.setattr(cls, "HLS_DIR", str(tmp_path / "hls"))
    build = cls._build_ffmpeg_args

    def local_input(url, output, codec, quality, recorded):
        args = build(url, output, codec, quality, recorded)
        assert args[args.index("-rtsp_transport") + 1] == "tcp"
        index = args.index("-rtsp_transport")
        del args[index : index + 2]
        args[args.index("-i") + 1] = str(clips[codec])
        args[1:1] = ["-filter_threads", "1"]
        args[-1:-1] = ["-threads", "1"]
        return args

    monkeypatch.setattr(cls, "_build_ffmpeg_args", staticmethod(local_input))
    service = cls()

    async def render(codec, quality, recorded):
        row = await service.start_session(
            camera_id=uuid4(),
            quality=quality,
            rtsp_url="rtsp://owned.invalid/synthetic",
            source_codec=codec,
            organization_id=uuid4(),
            is_recorded=recorded,
        )
        meta = service._sessions[row["session_id"]]
        await asyncio.wait_for(meta["process"].wait(), timeout=45)
        await asyncio.wait_for(asyncio.shield(meta["stderr_task"]), timeout=5)
        assert meta["process"].returncode == 0
        output = Path(meta["output_dir"])
        playlist = output / "stream.m3u8"
        assert playlist.is_file() and "#EXT-X-ENDLIST" in playlist.read_text()
        decoded = native(
            [
                "-i",
                str(playlist),
                "-map",
                "0:v:0",
                "-frames:v",
                "1",
                "-an",
                "-pix_fmt",
                "yuv420p",
                "-f",
                "yuv4mpegpipe",
                "pipe:1",
            ]
        )
        header = decoded.split(b"\n", 1)[0]
        width = int(re.search(rb"\bW(\d+)", header)[1])
        height = int(re.search(rb"\bH(\d+)", header)[1])
        assert len(decoded) >= width * height * 3 // 2
        segments = sorted(output.glob("*.ts"))
        assert segments and all(p.stat().st_size > 0 for p in segments)
        payload = b"".join(p.read_bytes() for p in segments)
        return (width, height), payload

    try:
        yield render
    finally:
        for sid, meta in list(service._sessions.items()):
            await service._kill_session(sid, meta)
            assert meta["process"].returncode is not None and meta["stderr_task"].done()
        assert not service._sessions and not list((tmp_path / "hls").glob("*/stream.m3u8"))


@pytest.mark.asyncio
@pytest.mark.parametrize("recorded", [False, True], ids=["live", "recorded"])
@pytest.mark.parametrize("codec", ["h264", "h265"])
@pytest.mark.parametrize("quality", ["low", "medium", "high", "source"])
async def test_requested_quality_changes_actual_encoded_media(stream, quality, codec, recorded):
    original_dimensions, original_video = await stream(codec, "source", recorded)
    dimensions, video = await stream(codec, quality, recorded)
    assert original_dimensions == (1600, 900)
    expected = {
        "low": (640, 360),
        "medium": (1280, 720),
        "high": (1600, 900),
        "source": (1600, 900),
    }
    assert dimensions == expected[quality]
    # Even high quality (which keeps resolution) must encode, rather than
    # silently copy the source. Source mode deliberately keeps original packets.
    assert (video == original_video) is (quality == "source")
