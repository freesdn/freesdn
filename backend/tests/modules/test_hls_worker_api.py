# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real workers and API handlers; explicit camera/authority and media fixtures.

This proves routing across processes, not HTTP authentication, database policy,
vendor RTSP or container namespaces. The same behavior test runs on the parent.
"""

import asyncio
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

_FRAME = b"OWNED_HLS_API_RESULT="
_CASES = [
    "shared_id",
    "single_child",
    "follower_heartbeat",
    "follower_playlist",
    "follower_segment",
    "follower_stop",
    "owner_heartbeat",
    "owner_playlist",
    "owner_segment",
    "private_media",
    "wrong_org_heartbeat",
    "wrong_org_playlist",
    "wrong_org_segment",
    "wrong_org_stop",
    "current_denial",
    "missing_camera",
    "viewer_count_after_stop",
    "owned_cleanup",
]


async def _worker(directory):
    from fastapi import HTTPException
    from starlette.responses import FileResponse

    import app.main  # Register models before importing the endpoint module.
    from app.modules.cameras import api
    from app.modules.cameras.service import HLSStreamService as cls

    assert app.main
    cls.HLS_DIR = directory
    program = (
        "from pathlib import Path;import sys,time;p=Path(sys.argv[1]);"
        "(p/'stream.m3u8').write_text('#EXTM3U\\n');"
        "(p/'00000.ts').write_bytes(b'owned local media');time.sleep(180)"
    )
    cls._build_ffmpeg_args = staticmethod(
        lambda _url, output, *_rest: [sys.executable, "-c", program, output]
    )
    state = SimpleNamespace(authority="allowed")

    async def access(_db, _user, _camera, _mode):
        if state.authority == "denied":
            raise HTTPException(status_code=403, detail="Current camera access denied")
        if state.authority == "missing":
            raise HTTPException(status_code=404, detail="Camera not found")

    async def camera(*_args, **_kwargs):
        return SimpleNamespace(rtsp_main_stream="rtsp://owned.invalid/live", channel_id=1)

    async def credentials(*_args):
        return "owned.invalid", 554, "synthetic", "synthetic-only"

    api._enforce_camera_access = access
    api._resolve_credentials = credentials

    def emit(value):
        print(_FRAME.decode() + json.dumps(value), flush=True)

    emit({"ready": os.getpid()})
    try:
        while line := await asyncio.to_thread(sys.stdin.readline):
            cmd = json.loads(line)
            op = cmd["op"]
            if op == "quit":
                break
            if op == "owned":
                emit({"result": {sid: meta["process"].pid for sid, meta in cls._sessions.items()}})
                continue
            state.authority = cmd.get("authority", "allowed")
            user = SimpleNamespace(organization_id=UUID(cmd["org"]), role="viewer")
            kwargs = {"current_user": user, "session": object()}
            try:
                if op == "start":
                    result = await api.start_hls_stream(
                        camera_id=UUID(cmd["camera"]),
                        body=api.HLSSessionStartRequest(quality="source"),
                        service=SimpleNamespace(get_camera=camera),
                        **kwargs,
                    )
                else:
                    kwargs["session_id"] = cmd["sid"]
                    methods = {
                        "heartbeat": api.hls_heartbeat,
                        "playlist": api.get_hls_playlist,
                        "segment": api.get_hls_segment,
                        "stop": api.stop_hls_stream,
                    }
                    if op == "segment":
                        kwargs["segment"] = "00000.ts"
                    result = await methods[op](**kwargs)
                if isinstance(result, FileResponse):
                    value = {
                        "content": Path(result.path).read_text(),
                        "headers": dict(result.headers),
                    }
                else:
                    value = (
                        result.model_dump(mode="json") if hasattr(result, "model_dump") else result
                    )
                emit({"result": {"status": 200, "body": value}})
            except HTTPException as exc:
                emit({"result": {"status": exc.status_code, "detail": str(exc.detail)}})
    finally:
        coordinator = sys.modules.get("app.modules.cameras.coordinator")
        if coordinator is not None:
            await coordinator.shutdown_coordinator(permanent=True)
        async with cls._lock:
            for sid, meta in list(cls._sessions.items()):
                await cls()._kill_session(sid, meta)
        assert not cls._sessions


@pytest.fixture(scope="module")
def worker_outcomes(tmp_path_factory):
    root = tmp_path_factory.mktemp("owned-hls-api")
    directory = root / "media"
    workers, logs, buffers, children = [], [], {}, {}
    rows = {}
    # pytest's source import path does not necessarily reach child processes.
    import app

    source = Path(app.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"}

    def send(worker, value):
        worker.stdin.write(json.dumps(value) + "\n")
        worker.stdin.flush()

    def receive(worker):
        deadline = time.monotonic() + 30
        while True:
            buf = buffers.get(worker.pid, b"")
            if b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buffers[worker.pid] = rest
                if line.startswith(_FRAME):
                    return json.loads(line[len(_FRAME) :])
                continue
            assert time.monotonic() < deadline, "Owned API worker response timed out"
            if select.select([worker.stdout], [], [], 0.1)[0]:
                data = os.read(worker.stdout.fileno(), 65536)
                assert data, "Owned API worker exited; inspect its private test log"
                buffers[worker.pid] = buf + data

    def call(worker, op, **values):
        send(worker, {"op": op, **values})
        return receive(worker)["result"]

    try:
        for index in range(2):
            log = (root / f"worker-{index}.log").open("w")
            logs.append(log)
            worker = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(Path(__file__).resolve()),
                    "--owned-worker",
                    str(directory),
                ],
                cwd=source,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=log,
                text=True,
            )
            workers.append(worker)
            assert receive(worker)["ready"] == worker.pid
        org, camera = str(uuid4()), str(uuid4())
        for worker in workers:
            send(worker, {"op": "start", "org": org, "camera": camera})
        starts = [receive(worker)["result"] for worker in workers]
        assert all(row["status"] == 200 for row in starts), starts
        sids = [row["body"]["session_id"] for row in starts]
        ownership = [call(worker, "owned") for worker in workers]
        for owned in ownership:
            for pid in owned.values():
                children.setdefault(pid, os.pidfd_open(pid))
        owner_index = next(i for i, owned in enumerate(ownership) if sids[0] in owned)
        owner, follower = workers[owner_index], workers[1 - owner_index]
        sid = sids[0]
        deadline = time.monotonic() + 10
        while not (directory / sid / "00000.ts").exists():
            assert time.monotonic() < deadline, "Owned synthetic media was not created"
            time.sleep(0.01)
        rows["shared_id"] = sids[0] == sids[1]
        rows["single_child"] = len(children) == 1
        owner_media = []
        for op in ["heartbeat", "playlist", "segment"]:
            result = call(owner, op, org=org, sid=sid)
            rows["owner_" + op] = result["status"] == 200
            if op != "heartbeat":
                owner_media.append(result["body"])
            result = call(follower, op, org=org, sid=sid)
            rows["follower_" + op] = result["status"] == 200
            if result["status"] == 200 and op != "heartbeat":
                assert result["body"] == owner_media[-1]
        rows["private_media"] = all(
            "private" in row["headers"]["cache-control"]
            and "no-store" in row["headers"]["cache-control"]
            for row in owner_media
        )
        for op in ["heartbeat", "playlist", "segment", "stop"]:
            rows["wrong_org_" + op] = call(owner, op, org=str(uuid4()), sid=sid)["status"] == 404
        rows["current_denial"] = (
            call(owner, "heartbeat", org=org, sid=sid, authority="denied")["status"] == 403
        )
        rows["missing_camera"] = (
            call(owner, "heartbeat", org=org, sid=sid, authority="missing")["status"] == 404
        )
        rows["follower_stop"] = call(follower, "stop", org=org, sid=sid)["status"] == 200
        final = call(owner, "heartbeat", org=org, sid=sid)
        rows["viewer_count_after_stop"] = final["status"] == 200 and final["body"]["viewers"] == 1
    finally:
        for worker in workers:
            if worker.poll() is None:
                try:
                    send(worker, {"op": "quit"})
                    worker.wait(timeout=15)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    worker.kill()
                    worker.wait(timeout=5)
            worker.stdin.close()
            worker.stdout.close()
        children_exited = all(select.select([fd], [], [], 5)[0] for fd in children.values())
        for fd in children.values():
            os.close(fd)
        for log in logs:
            log.close()
        rows["owned_cleanup"] = (
            all(worker.returncode == 0 for worker in workers)
            and children_exited
            and not list(directory.glob("*/stream.m3u8"))
        )
        (root / "outcomes.json").write_text(json.dumps(rows, indent=2))
    return rows


@pytest.mark.parametrize("case", _CASES)
def test_api_session_is_usable_across_workers(worker_outcomes, case):
    assert worker_outcomes[case], case


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--owned-worker":
    asyncio.run(_worker(sys.argv[2]))
