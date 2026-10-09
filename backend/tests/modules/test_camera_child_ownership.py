# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""An API worker crash must not retain an owned camera media subprocess.

The subreaper and signals run only inside an isolated helper process. All child
commands are harmless local Python programs; no FFmpeg, RTSP or devices are used.
"""

import asyncio
import ctypes
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

import pytest


async def owner(kind, ready):
    from app.modules.cameras import api, service

    original = asyncio.create_subprocess_exec
    program = (
        "from pathlib import Path;import time;Path("
        + repr(ready)
        + ").write_text('ready');time.sleep(180)"
    )

    async def spawn(*args, **kwargs):
        # Preserve the real launcher if present, replacing only its media binary
        # with the owned fixture child. The old source launches that child directly.
        if len(args) >= 4 and args[1] == "-B" and Path(args[2]).name == "owned_child.py":
            command = [*args[:4], sys.executable, "-c", program]
        else:
            command = [sys.executable, "-c", program]
        child = await original(*command, **kwargs)
        print("CHILD_PID=" + str(child.pid), flush=True)
        return child

    asyncio.create_subprocess_exec = spawn
    if kind == "hls":
        service.HLSStreamService.HLS_DIR = str(Path(ready).parent / "hls")
        await service.HLSStreamService().start_session(
            uuid4(), "source", "rtsp://owned.example.invalid/live", organization_id=uuid4()
        )
        await asyncio.sleep(180)
    elif kind == "codec":
        await service.TranscodeService().detect_codec("rtsp://owned.example.invalid/live")
    else:
        await api._probe_recorded_stream("rtsp://owned.example.invalid/recorded")


def check(kind, kill_owner):
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("Owned test subreaper unavailable")
    result = {"kind": kind, "owner_killed": kill_owner}
    with tempfile.TemporaryDirectory(prefix="owned-camera-parent-") as directory:
        ready = Path(directory) / "ready"
        parent = subprocess.Popen(
            [sys.executable, "-B", __file__, "--owner", kind, str(ready)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        child = None
        fd = None
        try:
            deadline = time.monotonic() + 15
            while child is None:
                if parent.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Owned media worker did not start")
                if not select.select([parent.stdout], [], [], 0.1)[0]:
                    continue
                line = parent.stdout.readline()
                if not line:
                    raise RuntimeError("Owned media worker closed its readiness stream")
                if line.startswith("CHILD_PID="):
                    child = int(line.split("=", 1)[1])
            fd = os.pidfd_open(child)
            while not ready.exists():
                if parent.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Owned media child did not become ready")
                time.sleep(0.01)
            assert not select.select([fd], [], [], 0)[0]
            if kill_owner:
                parent.kill()
                parent.wait(timeout=5)
            else:
                assert parent.poll() is None
            result["child_exited"] = bool(select.select([fd], [], [], 0.3)[0])
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=5)
            if fd is not None:
                if not select.select([fd], [], [], 0)[0]:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                assert select.select([fd], [], [], 5)[0]
                pid, _status = os.waitpid(child, 0)
                assert pid == child
                os.close(fd)
            parent.stdout.close()
            parent.stderr.close()
        result["owned_children_reaped"] = True
    return result


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "pidfd_open"),
    reason="Linux packaged media process ownership",
)
@pytest.mark.parametrize("kind", ["hls", "codec", "recorded"])
@pytest.mark.parametrize("kill_owner", [False, True])
@pytest.mark.parametrize("repeat", range(2))
def test_camera_child_follows_its_original_owner(kind, kill_owner, repeat):
    del repeat
    output = subprocess.run(
        [sys.executable, "-B", __file__, "--check", kind, str(int(kill_owner))],
        capture_output=True,
        text=True,
        timeout=25,
        check=True,
    )
    row = json.loads(output.stdout)
    assert row["owned_children_reaped"]
    assert row["child_exited"] is kill_owner


@pytest.mark.skipif(sys.platform != "linux", reason="Linux owned media launcher")
@pytest.mark.parametrize(
    "reason", ["invalid_parent", "wrong_parent", "missing_binary", "setuid", "setgid", "fifo"]
)
def test_owned_launcher_refuses_invalid_or_privileged_targets(tmp_path, reason):
    from app.core import owned_child

    parent = str(os.getpid())
    marker = tmp_path / "must-not-execute"
    program = "from pathlib import Path;Path(" + repr(str(marker)) + ").write_text('unexpected')"
    command = [sys.executable, "-c", program]
    if reason == "invalid_parent":
        parent = "-1"
    elif reason == "wrong_parent":
        parent = str(os.getpid() + 1)
    elif reason == "missing_binary":
        command = [str(tmp_path / "PRIVATE_MISSING_EXECUTABLE")]
    else:
        target = tmp_path / "PRIVATE_TEST_EXECUTABLE"
        if reason == "fifo":
            os.mkfifo(target, mode=0o700)
        else:
            shutil.copyfile(sys.executable, target)
            target.chmod(0o4700 if reason == "setuid" else 0o2700)
        command[0] = str(target)
    result = subprocess.run(
        [sys.executable, "-B", owned_child.__file__, parent, *command],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 78
    assert result.stdout == "" and result.stderr.strip() == "Unable to start owned media child"
    assert not marker.exists()


if __name__ == "__main__":
    # Direct execution puts tests/modules on sys.path, not the backend root.
    # Keep this subprocess probe independent of the outer pytest PYTHONPATH.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    if sys.argv[1] == "--owner":
        asyncio.run(owner(sys.argv[2], sys.argv[3]))
    elif sys.argv[1] == "--check":
        print(json.dumps(check(sys.argv[2], sys.argv[3] == "1")), flush=True)
