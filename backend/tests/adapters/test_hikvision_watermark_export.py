# SPDX-License-Identifier: AGPL-3.0-only
"""The watermarked clip export starts FFmpeg with options it accepts.

Found on the live fleet with 26.11.1: FFmpeg 9 refuses to start when given
``-stimeout`` (renamed ``-timeout`` in FFmpeg 5) or ``-rw_timeout`` (not an RTSP
demuxer option), and the watermark font pointed at a Debian path that does not
exist in the Alpine image. Every watermarked export produced nothing. This runs
the installed ffmpeg on the adapter's real argument list against a closed port,
so FFmpeg gets as far as connecting, and the failed connection must surface as
an error rather than an empty clip.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
from typing import Any

import pytest

from app.adapters.exceptions import AdapterError
from app.adapters.hikvision import adapter as hik

FFMPEG_MISSING = shutil.which("ffmpeg") is None


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.skipif(FFMPEG_MISSING, reason="ffmpeg is not installed here")
async def test_ffmpeg_accepts_every_watermark_export_option(monkeypatch):
    port = _closed_port()
    started: dict[str, Any] = {}
    real_exec = asyncio.create_subprocess_exec

    async def keep_stderr(*args: Any, **kwargs: Any) -> Any:
        kwargs["stderr"] = asyncio.subprocess.PIPE
        started["proc"] = await real_exec(*args, **kwargs)
        return started["proc"]

    async def recorded(*_args: Any) -> str:
        return f"rtsp://127.0.0.1:{port}/Streaming/tracks/101"

    monkeypatch.setattr(hik.asyncio, "create_subprocess_exec", keep_stderr)
    export = hik.HikvisionAdapter.__new__(hik.HikvisionAdapter)
    monkeypatch.setattr(export, "_recorded_rtsp_for_range", recorded, raising=False)

    chunks: list[bytes] = []
    with pytest.raises(AdapterError, match="exit status"):
        async for chunk in export.stream_clip_watermarked(
            1, "2026-11-18T10:00:00Z", "2026-11-18T10:01:00Z", "exported by operator"
        ):
            chunks.append(chunk)

    stderr = (await started["proc"].stderr.read()).decode("utf-8", "replace")
    assert chunks == []
    assert "Unrecognized option" not in stderr and "Option not found" not in stderr, stderr
    assert "Connection refused" in stderr, stderr


@pytest.mark.skipif(
    not os.path.isdir("/usr/share/freesdn-sources/ffmpeg"),
    reason="only inside a FreeSDN backend image",
)
def test_the_watermark_font_is_in_the_image():
    assert os.path.isfile(hik.WATERMARK_FONT)
