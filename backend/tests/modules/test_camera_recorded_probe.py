# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Recorded probes distinguish definitive video metadata from failed discovery."""

import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio

from app.modules.cameras import api, service

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def recorded(monkeypatch):
    original = asyncio.create_subprocess_exec
    children = []
    state = SimpleNamespace(program="", timeout=10.0, spawned=asyncio.Event(), children=children)

    async def spawn(*args, **kwargs):
        if len(args) >= 4 and args[1] == "-B" and Path(args[2]).name == "owned_child.py":
            assert args[3] == str(os.getpid())
            args = args[4:]
        assert args[0] == "ffprobe" and args[-1].startswith("rtsp://")
        child = await original(sys.executable, "-c", state.program, **kwargs)
        children.append(child)
        state.spawned.set()
        return child

    async def wait_for(awaitable, timeout):
        return await asyncio.wait_for(awaitable, timeout=min(timeout, state.timeout))

    proxy = SimpleNamespace(
        create_subprocess_exec=spawn,
        subprocess=asyncio.subprocess,
        wait_for=wait_for,
        CancelledError=asyncio.CancelledError,
    )
    monkeypatch.setattr(api, "asyncio", proxy)
    monkeypatch.setattr(service, "asyncio", proxy)
    state.run = lambda: api._probe_recorded_stream(
        "rtsp://owned:synthetic-only@example.invalid/recorded"
    )
    state.document = lambda value: setattr(
        state, "program", "print(" + repr(json.dumps(value)) + ")"
    )
    try:
        yield state
    finally:
        for child in children:
            if child.returncode is None:
                child.kill()
            await child.communicate()


@pytest.mark.parametrize("closed_stdout", [False, True])
async def test_cancelled_recorded_probe_reaps_child(recorded, closed_stdout):
    f = recorded
    f.program = ("import os;os.close(1);" if closed_stdout else "") + "import time;time.sleep(180)"
    task = asyncio.create_task(f.run())
    await f.spawned.wait()
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert all(child.returncode is not None for child in f.children)


async def test_timed_out_probe_is_inconclusive_and_reaped(recorded):
    f = recorded
    f.timeout = 0.3
    f.program = "import time;time.sleep(180)"
    assert await f.run() is None
    assert all(child.returncode is not None for child in f.children)


async def test_nonzero_exit_cannot_be_cached_as_definitive_video(recorded):
    recorded.document(
        {"streams": [{"codec_type": "video", "codec_name": "h264", "width": 1920, "height": 1080}]}
    )
    recorded.program += ";import sys;sys.exit(1)"
    assert await recorded.run() is None


async def test_oversized_document_is_inconclusive_and_child_reaped(recorded):
    recorded.program = "import json;print(json.dumps({'streams':[{'codec_type':'video','codec_name':'h264','width':1920,'height':1080}],'padding':'x'*(2*1024*1024)}))"
    assert await recorded.run() is None
    assert all(child.returncode is not None for child in recorded.children)


@pytest.mark.parametrize(
    "document", [None, [], {}, {"streams": None}, {"streams": [None]}, {"streams": "invalid"}]
)
async def test_malformed_document_is_inconclusive(recorded, document):
    recorded.document(document)
    assert await recorded.run() is None


@pytest.mark.parametrize(
    "codec,expected", [("h264", "h264"), ("hevc", "h265"), ("vp9", "vp9"), (None, None)]
)
async def test_valid_video_preserves_codec_and_decodability(recorded, codec, expected):
    recorded.document(
        {"streams": [{"codec_type": "video", "codec_name": codec, "width": 1920, "height": 1080}]}
    )
    assert await recorded.run() == {
        "playable": True,
        "codec": expected,
        "width": 1920,
        "height": 1080,
    }


@pytest.mark.parametrize("streams", [[], [{"codec_type": "audio"}]])
async def test_definitive_absent_video_remains_unplayable(recorded, streams):
    recorded.document({"streams": streams})
    assert await recorded.run() == {"playable": False, "codec": None, "width": 0, "height": 0}


async def test_zero_dimensions_remain_definitively_unplayable(recorded):
    recorded.document(
        {"streams": [{"codec_type": "video", "codec_name": "hevc", "width": 0, "height": 0}]}
    )
    assert await recorded.run() == {"playable": False, "codec": "h265", "width": 0, "height": 0}


@pytest.mark.parametrize("value", [-1, True, "PRIVATE_INVALID_DIMENSION", 999999])
async def test_malformed_dimension_is_not_a_definitive_probe(recorded, value):
    recorded.document(
        {"streams": [{"codec_type": "video", "codec_name": "h264", "width": value, "height": 1080}]}
    )
    assert await recorded.run() is None


async def test_deep_metadata_is_inconclusive(recorded):
    recorded.program = "print('['*10000+'0'+']'*10000)"
    assert await recorded.run() is None
