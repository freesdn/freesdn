"""Real API workers with delayed socket publication, synthetic camera and media sources."""

import asyncio
import fcntl
import json
import os
import select
import stat
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest

from app.core.private_files import private_directory
from app.modules.cameras import coordinator as coordinator
from tests.modules import test_hls_coordinator_safety as safety_helpers

root = safety_helpers.root

FRAME = b"OWNED_HLS_API_RESULT="


async def delayed_worker(directory: Path, stage: str):
    import app.main
    from app.modules.cameras import coordinator as c
    from tests.modules.test_hls_worker_api import _worker

    assert app.main
    marker = directory.parent / "election-delayed"

    def signal():
        marker.write_text(stage)

    if stage == "lock":
        original = c._take_lock

        def take_lock(fd):
            lock = original(fd)
            if lock is not None:
                signal()
                time.sleep(0.25)
            return lock

        c._take_lock = take_lock
    elif stage == "permissions":
        original_chmod = os.chmod

        def chmod(path, mode, **kwargs):
            if kwargs.get("dir_fd") is not None and stat.S_ISSOCK(
                os.stat(path, dir_fd=kwargs["dir_fd"], follow_symlinks=False).st_mode
            ):
                signal()
                time.sleep(0.25)
            return original_chmod(path, mode, **kwargs)

        c.os.chmod = chmod
    elif stage == "listen":
        original_server = asyncio.start_unix_server

        async def start_server(*args, **kwargs):
            signal()
            await asyncio.sleep(0.25)
            return await original_server(*args, **kwargs)

        c.asyncio.start_unix_server = start_server
    await _worker(directory)


@pytest.mark.parametrize("stage", ["lock", "permissions", "listen"])
def test_follower_waits_for_elected_worker_to_publish_a_ready_private_socket(tmp_path, stage):
    import app

    source = Path(app.__file__).resolve().parent.parent
    directory = tmp_path / "media"
    marker = tmp_path / "election-delayed"
    workers, logs, buffers, children = [], [], {}, {}

    def send(worker, value):
        worker.stdin.write(json.dumps(value) + "\n")
        worker.stdin.flush()

    def receive(worker):
        deadline = time.monotonic() + 30
        while True:
            buffer = buffers.get(worker.pid, b"")
            if b"\n" in buffer:
                line, _, buffers[worker.pid] = buffer.partition(b"\n")
                if line.startswith(FRAME):
                    return json.loads(line[len(FRAME) :])
                continue
            assert time.monotonic() < deadline, "Owned worker response timeout"
            if select.select([worker.stdout], [], [], 0.1)[0]:
                data = os.read(worker.stdout.fileno(), 65536)
                assert data, "Owned worker exited; inspect retained worker log"
                buffers[worker.pid] = buffer + data

    starts = []
    try:
        for index in range(2):
            log = (tmp_path / f"worker-{index}.log").open("w")
            logs.append(log)
            worker = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(Path(__file__).resolve()),
                    "--owned-worker",
                    str(directory),
                    stage if index == 0 else "follower",
                ],
                cwd=source,
                env={**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"},
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=log,
                text=True,
            )
            workers.append(worker)
            assert receive(worker)["ready"] == worker.pid
        command = {"op": "start", "org": str(uuid4()), "camera": str(uuid4())}
        send(workers[0], command)
        deadline = time.monotonic() + 5
        while not marker.exists():
            assert time.monotonic() < deadline, "Owned startup stage was not reached"
            time.sleep(0.001)
        send(workers[1], command)
        starts = [receive(worker)["result"] for worker in workers]
        for worker in workers:
            send(worker, {"op": "owned"})
            for pid in receive(worker)["result"].values():
                children.setdefault(pid, os.pidfd_open(pid))
        assert [row["status"] for row in starts] == [200, 200], starts
        assert starts[0]["body"]["session_id"] == starts[1]["body"]["session_id"]
        send(
            workers[1],
            {"op": "heartbeat", "org": command["org"], "sid": starts[1]["body"]["session_id"]},
        )
        heartbeat = receive(workers[1])["result"]
        assert heartbeat["status"] == 200 and heartbeat["body"]["viewers"] == 2
        assert len(children) == 1
        assert (directory / "control.sock").stat().st_mode & 0o777 == 0o600
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
        reaped = all(select.select([fd], [], [], 5)[0] for fd in children.values())
        for fd in children.values():
            os.close(fd)
        for log in logs:
            log.close()
        (tmp_path / "outcomes.json").write_text(
            json.dumps(
                {
                    "stage": stage,
                    "starts": starts,
                    "children_reaped": reaped,
                    "workers_exited": [w.returncode for w in workers],
                },
                indent=2,
            )
        )
        assert reaped and all(worker.returncode == 0 for worker in workers)
        assert not list(directory.glob("*/stream.m3u8"))


@pytest.mark.parametrize("failure", ["error", "cancel"])
async def test_interrupted_election_removes_only_its_socket_and_releases_lock(
    root, monkeypatch, failure
):
    entered = asyncio.Event()

    async def fail_or_wait(*args, **kwargs):
        entered.set()
        if failure == "error":
            raise OSError("Owned server startup failure")
        await asyncio.Future()

    monkeypatch.setattr(coordinator.asyncio, "start_unix_server", fail_or_wait)
    task = asyncio.create_task(coordinator.ensure_coordinator())
    await asyncio.wait_for(entered.wait(), 2)
    if failure == "cancel":
        task.cancel()
    with pytest.raises(asyncio.CancelledError if failure == "cancel" else OSError):
        await task
    assert coordinator._owner is None
    assert not list(root.glob("*.sock"))
    with private_directory(root) as directory:
        lock = coordinator._take_lock(directory)
        assert lock is not None
        os.close(lock)


async def test_wait_for_a_missing_elected_socket_uses_the_request_deadline(root, monkeypatch):
    monkeypatch.setattr(coordinator, "_TIMEOUT", 0.15)
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = time.monotonic()
        with pytest.raises(coordinator.HLSCoordinatorError, match="^HLS coordinator unavailable$"):
            await asyncio.wait_for(coordinator.request("info", session_id=uuid4().hex), 1)
        assert 0.1 <= time.monotonic() - started < 1
        assert coordinator._owner is None and not (root / "control.sock").exists()
    finally:
        os.close(fd)


async def test_cancelling_a_follower_does_not_steal_the_election_lock(root):
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        task = asyncio.create_task(coordinator.request("info", session_id=uuid4().hex))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert coordinator._owner is None and not (root / "control.sock").exists()
    finally:
        os.close(fd)


if __name__ == "__main__" and len(sys.argv) == 4 and sys.argv[1] == "--owned-worker":
    asyncio.run(delayed_worker(Path(sys.argv[2]), sys.argv[3]))
