# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real local disk and ASGI lifetime probes, without an HTTP/database shortcut."""

import asyncio
import hashlib
import os
import threading
from pathlib import Path

import anyio
import pytest
from fastapi import HTTPException

from app.core.backup_download_response import LocalDownloadResponse, LocalDownloadSource
from app.core.backup_downloads import (
    CHUNK_BYTES,
    DownloadCapacityError,
    DownloadPool,
    DownloadSnapshot,
)
from app.core.backup_files import BackupFiles
from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES


def opened(root):
    result = []
    for entry in Path("/proc/self/fd").iterdir():
        try:
            if os.readlink(entry).startswith(str(root) + "/"):
                result.append(entry.name)
        except FileNotFoundError:
            pass
    return result


def fixture(root, *, size=CHUNK_BYTES * 3 + 13, verified=True, seconds=5):
    archives = root / "archives"
    archives.mkdir(mode=0o700)
    path = archives / "owned.fsdn"
    raw = os.urandom(size)
    path.write_bytes(raw)
    path.chmod(0o600)
    expected = {"version": 1, "bytes": size, "sha256": hashlib.sha256(raw).hexdigest()}
    source = LocalDownloadSource(archives, path.name, {"artifact_identity": expected} if verified else {}, MAX_BACKUP_IMPORT_BYTES)
    pool = DownloadPool(root / "spool", slots=1, limit=MAX_BACKUP_IMPORT_BYTES, free_floor=0)
    return LocalDownloadResponse(source, pool, path.name, seconds=seconds), path, expected


class Sink:
    def __init__(self, *, paused=False, broken=False):
        self.body_started = asyncio.Event()
        self.release = asyncio.Event()
        if not paused:
            self.release.set()
        self.disconnected = asyncio.Event()
        self.broken = broken
        self.headers = {}
        self.max_chunk = self.total = 0
        self.digest = hashlib.sha256()
        self.status = None
        self.completed = False

    async def receive(self):
        await self.disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(self, message):
        if message["type"] == "http.response.start":
            self.status = message["status"]
            self.headers = dict(message["headers"])
            return
        body = message.get("body", b"")
        if body:
            self.body_started.set()
            await self.release.wait()
            if self.broken:
                raise OSError("Owned send failure")
        self.max_chunk = max(self.max_chunk, len(body))
        self.total += len(body)
        self.digest.update(body)
        self.completed = not message.get("more_body", False)


async def call(response, sink):
    await response({"type": "http", "method": "GET", "asgi": {"spec_version": "2.4"}}, sink.receive, sink.send)


@pytest.mark.parametrize("verified", [False, True])
def test_actual_ASGI_transfer_is_bounded_verified_and_independent(tmp_path, monkeypatch, request, verified):
    response, path, identity = fixture(tmp_path, verified=verified)

    def refuse_load(*_args):
        raise AssertionError("A bounded response must not materialize via load")

    monkeypatch.setattr(BackupFiles, "load", refuse_load)

    async def scenario():
        sink = Sink(paused=True)
        task = asyncio.create_task(call(response, sink))
        try:
            await asyncio.wait_for(sink.body_started.wait(), 5)
            assert response.snapshot is not None and response.snapshot.integrity is not None
            assert response.snapshot.size == identity["bytes"]
            with pytest.raises(DownloadCapacityError):
                response.pool.acquire()
            replacement = path.with_name("replacement")
            replacement.write_bytes(b"changed after snapshot")
            replacement.chmod(0o600)
            replacement.replace(path)
            sink.release.set()
            await task
        finally:
            sink.release.set()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        assert sink.status == 200 and sink.completed
        assert sink.total == identity["bytes"] and sink.digest.hexdigest() == identity["sha256"]
        assert sink.max_chunk <= CHUNK_BYTES
        assert int(sink.headers[b"content-length"]) == sink.total
        assert sink.headers[b"x-freesdn-artifact-integrity"] == (b"verified" if verified else b"legacy_unverified")
        assert b"accept-ranges" not in sink.headers
        return sink.max_chunk

    maximum = asyncio.run(scenario())
    assert not opened(tmp_path)
    response.pool.acquire().close()
    request.node.user_properties.extend([("actual_max_chunk", maximum), ("exact_verified_snapshot", True), ("capacity_retained_until_finish", True), ("no_owned_descriptors", True)])


@pytest.mark.parametrize("phase", ["allocation-handoff", "copy", "read", "close"])
@pytest.mark.parametrize("kind", ["task", "anyio"])
def test_cancellation_drains_real_allocation_copy_read_and_close(tmp_path, monkeypatch, request, phase, kind):
    response, _path, _identity = fixture(tmp_path)
    entered, release = threading.Event(), threading.Event()
    hits = []

    def pause():
        hits.append(phase)
        entered.set()
        assert release.wait(10), "Owned syscall boundary was not released"

    if phase == "allocation-handoff":
        original = response.pool.acquire

        def acquire():
            lease = original()
            pause()
            return lease

        monkeypatch.setattr(response.pool, "acquire", acquire)
    elif phase == "copy":
        original = response.source.copy_into

        def copy(lease):
            original(lease)
            pause()

        monkeypatch.setattr(response.source, "copy_into", copy)
    elif phase == "read":
        original = DownloadSnapshot.read_chunk

        def read(lease):
            result = original(lease)
            if not hits:
                pause()
            return result

        monkeypatch.setattr(DownloadSnapshot, "read_chunk", read)
    else:
        original = DownloadSnapshot.close

        def close(lease):
            if not hits:
                pause()
            original(lease)

        monkeypatch.setattr(DownloadSnapshot, "close", close)

    async def scenario():
        scope_box = []

        async def owner():
            if kind == "task":
                await call(response, Sink())
            else:
                with anyio.CancelScope() as scope:
                    scope_box.append(scope)
                    await call(response, Sink())

        task = asyncio.create_task(owner())
        try:
            for _ in range(500):
                if entered.is_set() or task.done():
                    break
                await asyncio.sleep(.01)
            assert entered.is_set() and not task.done()
            for _ in range(3):
                if kind == "task":
                    assert task.cancel()
                else:
                    scope_box[0].cancel()
                await asyncio.sleep(.01)
                assert not task.done(), "Owner detached before real operation completion"
            assert opened(tmp_path), "Actual owned descriptor must remain live at this boundary"
        finally:
            release.set()
            outcome = await asyncio.gather(task, return_exceptions=True)
        if kind == "task":
            assert isinstance(outcome[0], asyncio.CancelledError)
        else:
            assert outcome == [None]
        assert not opened(tmp_path)

    asyncio.run(scenario())
    assert hits == [phase]
    # Restore the allocation wrapper before checking a fresh available slot.
    monkeypatch.undo()
    response.pool.acquire().close()
    request.node.user_properties.extend([("real_operation_boundary", phase), ("three_cancellations_drained", True), ("no_owned_descriptors", True), ("slot_available_after_cleanup", True)])


@pytest.mark.parametrize("kind", ["task", "disconnect", "send-error", "deadline"])
def test_slow_or_interrupted_send_cleans_slot_and_snapshot(tmp_path, request, kind):
    response, path, identity = fixture(tmp_path, seconds=.15 if kind == "deadline" else 5)

    async def scenario():
        sink = Sink(paused=True, broken=kind == "send-error")
        task = asyncio.create_task(call(response, sink))
        try:
            await asyncio.wait_for(sink.body_started.wait(), 5)
            if kind == "task":
                task.cancel()
            elif kind == "disconnect":
                sink.disconnected.set()
            elif kind == "send-error":
                sink.release.set()
            result = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
        finally:
            sink.release.set()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        expected = OSError if kind == "send-error" else TimeoutError if kind == "deadline" else asyncio.CancelledError
        assert isinstance(result[0], expected)
        assert not sink.completed

    asyncio.run(scenario())
    assert not opened(tmp_path)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == identity["sha256"]
    response.pool.acquire().close()
    request.node.user_properties.extend([("interrupted_before_successful_completion", True), ("no_owned_descriptors", True), ("original_archive_unchanged", True)])


@pytest.mark.parametrize("kind", ["empty", "oversize", "identity", "copy-error", "readback-error", "source-growth"])
def test_prepare_failures_send_no_headers_or_archive_bytes(tmp_path, monkeypatch, request, kind):
    response, path, _identity = fixture(tmp_path)
    if kind == "empty":
        path.write_bytes(b"")
    elif kind == "oversize":
        with path.open("r+b") as stream:
            stream.truncate(MAX_BACKUP_IMPORT_BYTES + 1)
    elif kind == "identity":
        path.write_bytes(b"z" * path.stat().st_size)
    elif kind == "copy-error":
        def fail(_lease, _chunk):
            raise OSError("synthetic private source error")

        monkeypatch.setattr(DownloadSnapshot, "append", fail)
    elif kind == "readback-error":
        original = DownloadSnapshot.seal

        def corrupt(lease, expected):
            os.pwrite(lease._fd, b"changed", 0)
            return original(lease, expected)

        monkeypatch.setattr(DownloadSnapshot, "seal", corrupt)
    else:
        original = DownloadSnapshot.append
        calls = []

        def grow(lease, chunk):
            original(lease, chunk)
            if not calls:
                calls.append(True)
                with path.open("ab") as stream:
                    stream.write(b"grown")

        monkeypatch.setattr(DownloadSnapshot, "append", grow)

    async def scenario():
        sink = Sink()
        with pytest.raises(HTTPException) as error:
            await call(response, sink)
        assert error.value.status_code in (409, 500)
        assert "synthetic private" not in str(error.value)
        assert sink.status is None and sink.total == 0 and not sink.completed

    asyncio.run(scenario())
    assert not opened(tmp_path)
    response.pool.acquire().close()
    request.node.user_properties.extend([("refused_before_headers", True), ("no_owned_descriptors", True)])


def test_already_cancelled_owner_does_not_allocate(tmp_path, monkeypatch):
    response, _path, _identity = fixture(tmp_path)
    allocations = []
    original = response.pool.acquire

    def acquire():
        allocations.append(True)
        return original()

    monkeypatch.setattr(response.pool, "acquire", acquire)

    async def scenario():
        with anyio.CancelScope() as scope:
            scope.cancel()
            await call(response, Sink())

    asyncio.run(scenario())
    assert not allocations and not opened(tmp_path)


def test_transfer_capacity_refusal_is_retryable_and_does_not_read_source(tmp_path, monkeypatch):
    response, _path, _identity = fixture(tmp_path)
    occupied = response.pool.acquire()
    reads = []

    def copy(_snapshot):
        reads.append(True)

    monkeypatch.setattr(response.source, "copy_into", copy)

    async def scenario():
        sink = Sink()
        with pytest.raises(HTTPException) as error:
            await call(response, sink)
        assert error.value.status_code == 503 and error.value.headers == {"Retry-After": "5"}
        assert sink.status is None and not reads

    try:
        asyncio.run(scenario())
    finally:
        occupied.close()
    assert not opened(tmp_path)


def test_supported_maximum_archive_uses_bounded_copy_and_send(tmp_path, request):
    response, path, _identity = fixture(tmp_path, size=1, verified=False, seconds=30)
    with path.open("r+b") as stream:
        stream.truncate(MAX_BACKUP_IMPORT_BYTES)

    async def scenario():
        sink = Sink()
        await call(response, sink)
        assert sink.completed and sink.total == MAX_BACKUP_IMPORT_BYTES
        assert sink.max_chunk <= CHUNK_BYTES
        return sink.max_chunk, sink.total

    maximum, size = asyncio.run(scenario())
    assert not opened(tmp_path)
    request.node.user_properties.extend([("actual_archive_bytes", size), ("actual_maximum_send_chunk", maximum), ("no_owned_descriptors", True)])
