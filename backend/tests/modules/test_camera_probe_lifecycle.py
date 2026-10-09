# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Codec probes must not leak private child output or retain canceled children."""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio

from app.modules.cameras import service as cameras

pytestmark = pytest.mark.asyncio
PRIVATE = "OWNED_CAMERA_PASSWORD_DO_NOT_LOG"
UNKNOWN = {"codec": "unknown", "resolution": "unknown", "bitrate_kbps": 0, "needs_transcode": False}


@pytest_asyncio.fixture
async def probe(monkeypatch):
    original = asyncio.create_subprocess_exec
    children = []
    state = SimpleNamespace(program="", spawned=asyncio.Event(), messages=[], timeout=10.0)

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

    class Capture(logging.Handler):
        def emit(self, record):
            state.messages.append(record.getMessage())

    handler = Capture()
    cameras.logger.addHandler(handler)
    monkeypatch.setattr(
        cameras,
        "asyncio",
        SimpleNamespace(
            create_subprocess_exec=spawn,
            subprocess=asyncio.subprocess,
            wait_for=wait_for,
            CancelledError=asyncio.CancelledError,
        ),
    )
    state.children = children
    state.run = lambda: cameras.TranscodeService().detect_codec(
        "rtsp://owned:" + PRIVATE + "@example.invalid/video"
    )
    try:
        yield state
    finally:
        cameras.logger.removeHandler(handler)
        for child in children:
            if child.returncode is None:
                child.kill()
            await child.communicate()


async def test_failed_probe_never_logs_native_credentials(probe):
    probe.program = "import sys;sys.stderr.write(" + repr(PRIVATE) + ");sys.exit(1)"
    assert await probe.run() == UNKNOWN
    assert PRIVATE not in "\n".join(probe.messages)
    assert all(child.returncode is not None for child in probe.children)


async def test_cancelled_probe_reaps_its_owned_child(probe):
    probe.program = "import time;time.sleep(180)"
    task = asyncio.create_task(probe.run())
    await probe.spawned.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert all(child.returncode is not None for child in probe.children)


async def test_timeout_returns_unknown_and_reaps_child(probe):
    probe.timeout = 0.3
    probe.program = "import time;time.sleep(180)"
    assert await probe.run() == UNKNOWN
    assert all(child.returncode is not None for child in probe.children)
    assert PRIVATE not in "\n".join(probe.messages)


@pytest.mark.parametrize(
    "data",
    [
        [],
        None,
        {"streams": None},
        {"streams": [None]},
        {"streams": [{"codec_type": "video", "codec_name": None}]},
    ],
)
async def test_malformed_probe_shape_is_an_unknown_result(probe, data):
    probe.program = "print(" + repr(json.dumps(data)) + ")"
    assert await probe.run() == UNKNOWN


@pytest.mark.parametrize("codec,transcode", [("h264", False), ("hevc", True)])
async def test_valid_codec_dimensions_and_bitrate_remain_available(probe, codec, transcode):
    data = {
        "streams": [
            {"codec_type": "audio"},
            {
                "codec_type": "video",
                "codec_name": codec,
                "width": 1920,
                "height": 1080,
                "bit_rate": "2000000",
            },
        ]
    }
    probe.program = "print(" + repr(json.dumps(data)) + ")"
    assert await probe.run() == {
        "codec": codec,
        "resolution": "1920x1080",
        "bitrate_kbps": 2000,
        "needs_transcode": transcode,
    }


async def test_oversized_valid_document_is_refused_and_child_reaped(probe):
    probe.program = "import json;print(json.dumps({'streams':[{'codec_type':'video','codec_name':'h264','width':1920,'height':1080}],'padding':'x'*(2*1024*1024)}))"
    assert await probe.run() == UNKNOWN
    assert all(child.returncode is not None for child in probe.children)


async def test_cancellation_after_stdout_closes_still_reaps_child(probe):
    probe.program = "import os,time;os.close(1);time.sleep(180)"
    task = asyncio.create_task(probe.run())
    await probe.spawned.wait()
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert all(child.returncode is not None for child in probe.children)


@pytest.mark.parametrize("payload", ["", "not-json", "\\xff"])
async def test_invalid_document_is_unknown_without_logging_payload(probe, payload):
    probe.program = "import sys;sys.stdout.write(" + repr(payload) + ")"
    assert await probe.run() == UNKNOWN
    assert all(child.returncode is not None for child in probe.children)


@pytest.mark.parametrize(
    "field,value", [("width", PRIVATE), ("width", -2), ("width", True), ("height", 999999)]
)
async def test_untrusted_dimensions_never_become_response_text(probe, field, value):
    stream = {"codec_type": "video", "codec_name": "h264", "width": 1920, "height": 1080}
    stream[field] = value
    probe.program = "print(" + repr(json.dumps({"streams": [stream]})) + ")"
    result = await probe.run()
    assert result["codec"] == "h264" and result["resolution"] == "unknown"
    assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("value", [-2000, True, "-2000"])
async def test_invalid_bitrate_does_not_produce_negative_or_boolean_value(probe, value):
    stream = {"codec_type": "video", "codec_name": "h264", "bit_rate": value}
    probe.program = "print(" + repr(json.dumps({"streams": [stream]})) + ")"
    assert (await probe.run())["bitrate_kbps"] == 0


async def test_deeply_nested_metadata_is_unknown_without_parser_failure(probe):
    probe.program = "print('['*10000+'0'+']'*10000)"
    assert await probe.run() == UNKNOWN
    assert all(child.returncode is not None for child in probe.children)
