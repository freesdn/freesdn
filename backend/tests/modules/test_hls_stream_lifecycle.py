# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bound native diagnostics and replace dead HLS producers using real children."""

import asyncio
import errno
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio

from app.modules.cameras import service as cameras


@pytest_asyncio.fixture
async def stream(monkeypatch, tmp_path):
    cls = cameras.HLSStreamService
    monkeypatch.setattr(cls, "_sessions", {})
    monkeypatch.setattr(cls, "_lock", asyncio.Lock())
    monkeypatch.setattr(cls, "HLS_DIR", str(tmp_path / "hls"))
    state = SimpleNamespace(program="import time;time.sleep(180)", service=cls())
    monkeypatch.setattr(
        cls,
        "_build_ffmpeg_args",
        staticmethod(lambda _url, output, *_args: [sys.executable, "-c", state.program, output]),
    )
    state.kwargs = {
        "camera_id": uuid4(),
        "quality": "source",
        "rtsp_url": "rtsp://owned.invalid/live",
        "organization_id": uuid4(),
        "is_recorded": False,
    }

    async def start():
        row = await state.service.start_session(**state.kwargs)
        return row, state.service._sessions[row["session_id"]]

    state.start = start
    try:
        yield state
    finally:
        for sid, meta in list(state.service._sessions.items()):
            await state.service._kill_session(sid, meta)
            assert meta["process"].returncode is not None
            assert meta["log_file"].closed
            task = meta.get("stderr_task")
            if task is not None:
                assert task.done()
        assert not state.service._sessions


async def completed(meta):
    await asyncio.wait_for(meta["process"].wait(), timeout=15)
    task = meta.get("stderr_task")
    if task is not None:
        await asyncio.wait_for(asyncio.shield(task), timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [8192, 131072, 2 * 1024 * 1024])
async def test_stderr_prefix_is_bounded_without_blocking_child(stream, size, caplog):
    stream.program = (
        "import os;data=b'PRIVATE_NATIVE_MARKER'+b'x'*" + str(size) + ";os.write(2,data)"
    )
    _, meta = await stream.start()
    await completed(meta)
    assert meta["process"].returncode == 0
    content = Path(meta["log_path"]).read_bytes()
    assert content.startswith(b"PRIVATE_NATIVE_MARKER")
    assert len(content) == min(size + len(b"PRIVATE_NATIVE_MARKER"), 64 * 1024)
    assert os.stat(meta["log_path"]).st_mode & 0o777 == 0o600
    assert "PRIVATE_NATIVE_MARKER" not in caplog.text


@pytest.mark.asyncio
async def test_diagnostic_write_failure_still_drains_child(stream, monkeypatch, caplog):
    from app.core import private_files

    create = private_files.create_private

    class FailingWriter:
        def __init__(self, handle):
            self.handle = handle

        def fileno(self):
            return self.handle.fileno()

        @property
        def closed(self):
            return self.handle.closed

        def write(self, data):
            raise OSError(errno.ENOSPC, "PRIVATE_DISK_ERROR_MARKER")

        def flush(self):
            self.handle.flush()

        def close(self):
            self.handle.close()

    monkeypatch.setattr(private_files, "create_private", lambda path: FailingWriter(create(path)))
    stream.program = "import os;os.write(2,b'PRIVATE_NATIVE_MARKER'+b'x'*(2*1024*1024))"
    _, meta = await stream.start()
    await completed(meta)
    assert meta["process"].returncode == 0
    assert Path(meta["log_path"]).stat().st_size <= 64 * 1024
    assert (
        "PRIVATE_NATIVE_MARKER" not in caplog.text
        and "PRIVATE_DISK_ERROR_MARKER" not in caplog.text
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("flood", [False, True])
async def test_stop_reaps_child_and_diagnostic_task(stream, flood):
    if flood:
        stream.program = "import os,time;os.write(2,b'x'*(2*1024*1024));time.sleep(180)"
    row, meta = await stream.start()
    await asyncio.sleep(0.1)
    await asyncio.wait_for(stream.service.stop_session(row["session_id"]), timeout=10)
    assert meta["process"].returncode is not None
    assert meta["log_file"].closed
    task = meta.get("stderr_task")
    if task is not None:
        assert task.done()
    assert not Path(meta["output_dir"]).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("recorded", [False, True])
@pytest.mark.parametrize("code", [0, 1])
@pytest.mark.parametrize("has_media", [False, True])
async def test_dead_producers_are_replaced_except_completed_recordings(
    stream, recorded, code, has_media
):
    stream.kwargs["is_recorded"] = recorded
    stream.program = "import sys;from pathlib import Path;p=Path(sys.argv[1]);"
    if has_media:
        stream.program += "(p/'stream.m3u8').write_text('#EXTM3U\\n#EXT-X-ENDLIST\\n');(p/'00000.ts').write_bytes(b'synthetic media');"
    stream.program += "sys.exit(" + str(code) + ")"
    first, old = await stream.start()
    await completed(old)
    assert old["process"].returncode == code
    second, _ = await stream.start()
    reusable = recorded and code == 0 and has_media
    assert (first["session_id"] == second["session_id"]) is reusable
    assert second["viewers"] == (2 if reusable else 1)
    if not reusable:
        assert not Path(old["output_dir"]).exists()
        assert old["log_file"].closed
    assert len(stream.service._sessions) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("recorded", [False, True])
async def test_running_producer_is_still_shared(stream, recorded):
    stream.kwargs["is_recorded"] = recorded
    first, _ = await stream.start()
    second, _ = await stream.start()
    assert second["session_id"] == first["session_id"] and second["viewers"] == 2
    assert len(stream.service._sessions) == 1
