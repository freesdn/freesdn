# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bound local control messages and preserve media-child ownership on failure."""

import asyncio
import fcntl
import json
import os
import socket
import sys
from uuid import uuid4

import pytest
import pytest_asyncio

from app.core.private_files import private_directory
from app.modules.cameras import coordinator as c
from app.modules.cameras.service import HLSStreamService
from tests.harness_wait import HARNESS_WAIT_SECONDS


@pytest_asyncio.fixture
async def root(monkeypatch, tmp_path):
    path = tmp_path / "control"
    path.mkdir(mode=0o700)
    monkeypatch.setattr(HLSStreamService, "HLS_DIR", str(path))
    monkeypatch.setattr(HLSStreamService, "_sessions", {})
    monkeypatch.setattr(HLSStreamService, "_lock", asyncio.Lock())
    c.begin_coordinator_lifecycle()
    yield path
    await c.shutdown_coordinator()
    assert not HLSStreamService._sessions


async def connect(root):
    with private_directory(root, create=False) as directory:
        return await asyncio.open_unix_connection(
            f"/proc/self/fd/{directory}/control.sock", limit=20000
        )


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=HARNESS_WAIT_SECONDS)
    except OSError:
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory", "writable"])
async def test_unsafe_lock_refused_without_modifying_target(root, kind):
    target = root / "unrelated"
    target.write_bytes(b"preserve")
    target.chmod(0o600)
    lock = root / "control.lock"
    if kind == "symlink":
        lock.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, lock)
    elif kind == "fifo":
        os.mkfifo(lock, 0o600)
    elif kind == "directory":
        lock.mkdir()
    else:
        lock.write_bytes(b"owned lock")
        lock.chmod(0o666)
    with pytest.raises(c.HLSCoordinatorError, match="^HLS coordinator unavailable$"):
        await c.request("info", session_id=uuid4().hex)
    assert c._owner is None and target.read_bytes() == b"preserve"
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["file", "symlink", "writable_socket"])
async def test_unsafe_socket_is_not_unlinked(root, kind):
    path = root / "control.sock"
    target = root / "unrelated"
    target.write_bytes(b"preserve")
    native = None
    if kind == "file":
        path.write_bytes(b"preserve socket path")
    elif kind == "symlink":
        path.symlink_to(target)
    else:
        native = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        with private_directory(root) as directory:
            native.bind(f"/proc/self/fd/{directory}/control.sock")
        path.chmod(0o666)
    try:
        with pytest.raises(c.HLSCoordinatorError):
            await c.request("info", session_id=uuid4().hex)
        assert c._owner is None and path.exists() and target.read_bytes() == b"preserve"
    finally:
        if native is not None:
            native.close()


@pytest.mark.asyncio
async def test_safe_stale_socket_is_replaced_under_owned_lock(root):
    native = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with private_directory(root) as directory:
        native.bind(f"/proc/self/fd/{directory}/control.sock")
    (root / "control.sock").chmod(0o600)
    native.close()
    assert await c.request("info", session_id=uuid4().hex) is None
    assert c._owner is not None
    assert (root / "control.sock").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_existing_election_lock_is_not_stolen(root):
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(c.HLSCoordinatorError):
            await c.request("info", session_id=uuid4().hex)
        assert c._owner is None and not (root / "control.sock").exists()
    finally:
        os.close(fd)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        b"not json\n",
        b"{}\n",
        b"[]\n",
        b"x" * 18000 + b"\n",
        b"[" * 2000 + b"0" + b"]" * 2000 + b"\n",
        b'{"operation":"info","params":{"session_id":"../../other"}}\n',
        b'{"operation":"unknown","params":{"session_id":"11111111111111111111111111111111"}}\n',
        b'{"operation":"start","params":{"camera_id":"PRIVATE_BAD_UUID"}}\n',
    ],
    ids=[
        "json",
        "empty-map",
        "array",
        "oversize",
        "deep",
        "bad-session",
        "unknown-op",
        "bad-camera",
    ],
)
async def test_bad_control_messages_are_bounded_fixed_refusals(root, payload):
    await c.ensure_coordinator()
    reader, writer = await connect(root)
    try:
        writer.write(payload)
        await writer.drain()
        response = json.loads(await asyncio.wait_for(reader.readline(), timeout=HARNESS_WAIT_SECONDS))
        assert response["ok"] is False and response["error"] in ["invalid_request", "unavailable"]
        assert set(response) == {"ok", "error"} and not HLSStreamService._sessions
    finally:
        await close(writer)


@pytest.mark.asyncio
async def test_silent_connection_is_closed_at_deadline(root, monkeypatch):
    monkeypatch.setattr(c, "_TIMEOUT", 0.15)
    await c.ensure_coordinator()
    reader, writer = await connect(root)
    try:
        assert await asyncio.wait_for(reader.read(), timeout=HARNESS_WAIT_SECONDS) == b""
    finally:
        await close(writer)
    await asyncio.sleep(0.01)
    assert not c._owner.clients


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        b"PRIVATE_INVALID_JSON\n",
        b'{"ok":true,"extra":"PRIVATE_DATA"}\n',
        b'{"ok":true,"result":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}\n",
        b"x" * 18000 + b"\n",
        b'{"ok":true,"result":null}',
    ],
    ids=["json", "fields", "deep", "oversize", "missing-newline"],
)
async def test_bad_peer_responses_never_leak_native_data(root, response):
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    native = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with private_directory(root) as directory:
        native.bind(f"/proc/self/fd/{directory}/control.sock")
    (root / "control.sock").chmod(0o600)
    native.setblocking(False)

    async def peer(reader, writer):
        await reader.readline()
        writer.write(response)
        try:
            await writer.drain()
        except OSError:
            pass
        await close(writer)

    server = await asyncio.start_unix_server(peer, sock=native, cleanup_socket=False)
    try:
        with pytest.raises(c.HLSCoordinatorError, match="^HLS coordinator unavailable$"):
            await c.request("info", session_id=uuid4().hex)
        assert c._owner is None
    finally:
        server.close()
        await server.wait_closed()
        os.close(fd)


@pytest.mark.asyncio
async def test_shutdown_gate_blocks_reelection_until_new_lifespan(root):
    assert await c.request("info", session_id=uuid4().hex) is None
    await c.shutdown_coordinator(permanent=True)
    with pytest.raises(c.HLSCoordinatorError):
        await c.request("info", session_id=uuid4().hex)
    assert c._owner is None and not (root / "control.sock").exists()
    c.begin_coordinator_lifecycle()
    assert await c.request("info", session_id=uuid4().hex) is None


@pytest.mark.asyncio
async def test_peer_uid_refusal_cannot_start_media(root, monkeypatch):
    monkeypatch.setattr(c, "_same_uid", lambda _writer: False)
    with pytest.raises(c.HLSCoordinatorError):
        await c.request(
            "start", camera_id=str(uuid4()), quality="source", rtsp_url="rtsp://owned.invalid/live"
        )
    assert not HLSStreamService._sessions


@pytest.mark.asyncio
async def test_connection_limit_refuses_additional_idle_peer(root, monkeypatch):
    monkeypatch.setattr(c, "_MAX_CONNECTIONS", 1)
    await c.ensure_coordinator()
    reader, writer = await connect(root)
    try:
        async with asyncio.timeout(HARNESS_WAIT_SECONDS):
            while len(c._owner.clients) != 1:
                await asyncio.sleep(0.01)
        second_reader, second_writer = await connect(root)
        try:
            assert await asyncio.wait_for(second_reader.read(), timeout=HARNESS_WAIT_SECONDS) == b""
        finally:
            await close(second_writer)
        assert len(c._owner.clients) == 1 and not HLSStreamService._sessions
    finally:
        await close(writer)
    async with asyncio.timeout(HARNESS_WAIT_SECONDS):
        while c._owner.clients:
            await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_shutdown_cancels_inflight_response_and_reaps_spawned_child(root, monkeypatch):
    monkeypatch.setattr(
        HLSStreamService,
        "_build_ffmpeg_args",
        staticmethod(lambda *_args: [sys.executable, "-c", "import time;time.sleep(180)"]),
    )
    original = HLSStreamService.start_session
    ready = asyncio.Event()
    children = []

    async def delayed(self, *args, **kwargs):
        row = await original(self, *args, **kwargs)
        children.append(self._sessions[row["session_id"]]["process"])
        ready.set()
        await asyncio.sleep(60)
        return row

    monkeypatch.setattr(HLSStreamService, "start_session", delayed)
    call = asyncio.create_task(
        c.request(
            "start",
            camera_id=str(uuid4()),
            organization_id=str(uuid4()),
            quality="source",
            rtsp_url="rtsp://owned.invalid/live",
        )
    )
    try:
        await asyncio.wait_for(ready.wait(), timeout=5)
        await asyncio.wait_for(c.shutdown_coordinator(permanent=True), timeout=15)
        with pytest.raises(c.HLSCoordinatorError):
            await call
        assert len(children) == 1 and children[0].returncode is not None
        assert not HLSStreamService._sessions
        assert not [p for p in root.iterdir() if p.is_dir()]
    finally:
        if not call.done():
            call.cancel()
        await asyncio.gather(call, return_exceptions=True)


@pytest.mark.asyncio
async def test_session_info_waits_for_stop_to_finish(root, monkeypatch):
    monkeypatch.setattr(
        HLSStreamService,
        "_build_ffmpeg_args",
        staticmethod(lambda *_args: [sys.executable, "-c", "import time;time.sleep(180)"]),
    )
    row = await c.request(
        "start", camera_id=str(uuid4()), quality="source", rtsp_url="rtsp://owned.invalid/live"
    )
    original = HLSStreamService._kill_session
    entered, release = asyncio.Event(), asyncio.Event()

    async def delayed(self, *args):
        entered.set()
        await release.wait()
        await original(self, *args)

    monkeypatch.setattr(HLSStreamService, "_kill_session", delayed)
    stop = asyncio.create_task(c.request("stop", session_id=row["session_id"]))
    info = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        info = asyncio.create_task(c.request("info", session_id=row["session_id"]))
        await asyncio.sleep(0.1)
        assert not info.done(), "Session metadata exposed a partially stopped session"
        release.set()
        await stop
        assert await info is None
    finally:
        release.set()
        await asyncio.gather(
            *[task for task in [stop, info] if task is not None], return_exceptions=True
        )


@pytest.mark.asyncio
async def test_uncertain_mutation_response_is_not_replayed(root):
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    native = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with private_directory(root) as directory:
        native.bind(f"/proc/self/fd/{directory}/control.sock")
    (root / "control.sock").chmod(0o600)
    native.setblocking(False)
    mutations = []

    async def peer(reader, writer):
        request = json.loads(await reader.readline())
        mutations.append(request["operation"])
        writer.write(b'{"ok":false,"error":"unavailable"}\n')
        await writer.drain()
        await close(writer)

    server = await asyncio.start_unix_server(peer, sock=native, cleanup_socket=False)
    try:
        with pytest.raises(c.HLSCoordinatorError):
            await c.request("stop", session_id=uuid4().hex)
        assert mutations == ["stop"] and c._owner is None
    finally:
        server.close()
        await server.wait_closed()
        os.close(fd)
