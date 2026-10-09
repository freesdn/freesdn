"""Owned process streaming for blocking SSH/FTPS, before snapshot acceptance.

The network worker has a fixed operation deadline and bounded pipes/memory.
It receives only the copied destination and requested path. Cancellation kills
through a stable pidfd and reaps before releasing admission. Disk operations
retain their existing owner; this does not promise to terminate stuck kernel
I/O or establish process/host-loss recovery or deployment-wide quotas.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, cast

import anyio

from app.core.backup_downloads import CHUNK_BYTES, DownloadSnapshot
from app.core.owned_async import complete_before_cancellation
from app.services.vault_native_resolution import (
    _close_owned,
    _Input,
    _Lookup,
    _Output,
    _OwnedChild,
    _readable,
)

if TYPE_CHECKING:
    from app.services.backup import _RemoteFileStorageBackend


_ADMISSION = anyio.CapacityLimiter(2)
_SPAWN_THREADS = anyio.CapacityLimiter(2)
_DISK_THREADS = anyio.CapacityLimiter(2)
_SECONDS = 60.0
_CHILD = Path(__file__).with_name("vault_remote_stream_child.py")
_ERROR = "Remote backup transfer failed; verify the destination and retry"


class RemoteTransferError(ValueError):
    """Fixed diagnostic; never include child/provider/credential details."""


class _Request(_Input):
    def write(self, value: bytes) -> None:
        # Linux PIPE_BUF write to an empty nonblocking stdin pipe.
        if not 0 < len(value) <= 4096 or os.write(self.stream.fileno(), value) != len(value):
            raise RemoteTransferError(_ERROR)


class _Archive(_Output):
    async def read(self, size: int) -> bytes:
        if not 1 <= size <= CHUNK_BYTES:
            raise RemoteTransferError(_ERROR)
        fd = self.stream.fileno()
        while True:
            try:
                return os.read(fd, size)
            except BlockingIOError:
                await _readable(fd)


@complete_before_cancellation
async def _start_owned(state: _Lookup) -> None:
    if (
        sys.platform != "linux"
        or not os.path.isabs(sys.executable)
        or not hasattr(os, "pidfd_open")
        or not hasattr(signal, "pidfd_send_signal")
    ):
        raise RemoteTransferError(_ERROR)

    def spawn() -> None:
        environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        # Preserve operator CA trust, never the application secrets/environment.
        for key in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            if key in os.environ:
                environment[key] = os.environ[key]
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(_CHILD)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            close_fds=True,
            env=environment,
        )
        state.process = _OwnedChild(process)
        state.process.stdin = _Request(cast(IO[bytes], process.stdin))
        state.process.stdout = _Archive(cast(IO[bytes], process.stdout))
        os.set_blocking(cast(IO[bytes], process.stdin).fileno(), False)
        os.set_blocking(cast(IO[bytes], process.stdout).fileno(), False)

    await anyio.to_thread.run_sync(spawn, limiter=_SPAWN_THREADS)
    process = cast(_OwnedChild, state.process)
    state.pidfd = os.pidfd_open(process.pid)
    process.pidfd = state.pidfd


@complete_before_cancellation
async def _append_owned(snapshot: DownloadSnapshot, chunk: bytes) -> None:
    await anyio.to_thread.run_sync(snapshot.append, chunk, limiter=_DISK_THREADS)


@complete_before_cancellation
async def _seal_owned(snapshot: DownloadSnapshot, expected: dict[str, Any] | None) -> None:
    await anyio.to_thread.run_sync(snapshot.seal, expected, limiter=_DISK_THREADS)


async def copy_remote_into(
    backend: _RemoteFileStorageBackend,
    path: str,
    expected: dict[str, Any] | None,
    snapshot: DownloadSnapshot,
) -> None:
    await anyio.lowlevel.checkpoint()
    # Use the already pinned backend and the original locator validation. No
    # re-query, hostname resolution, new credential source or load() fallback.
    request = {
        "protocol": backend.scheme,
        "hostname": backend.hostname,
        "pin": backend.host,
        "port": backend.port,
        "username": backend.username,
        "password": backend.password or "",
        "private_key_path": getattr(backend, "private_key_path", None),
        "host_key_sha256": backend.config.get("host_key_sha256"),
        "use_tls": backend.config.get("use_tls"),
        "path": backend._path(path),
        "limit": snapshot.limit,
    }
    payload = json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode()
    if len(payload) > 4096:
        raise RemoteTransferError(_ERROR)
    try:
        _ADMISSION.acquire_nowait()
    except anyio.WouldBlock:
        raise RemoteTransferError("Remote backup transfer capacity is busy; retry later") from None
    state = _Lookup()
    started = time.monotonic()
    try:
        try:
            with anyio.fail_after(_SECONDS):
                await _start_owned(state)
                await anyio.lowlevel.checkpoint()
                process = state.process
                if process is None:
                    raise RemoteTransferError(_ERROR)
                process.stdin.write(payload)
                await process.stdin.drain()
                process.stdin.close()
                while chunk := await process.stdout.read(CHUNK_BYTES):
                    await _append_owned(snapshot, chunk)
                if await process.wait() != 0:
                    raise RemoteTransferError(_ERROR)
        except (OSError, TimeoutError, ValueError, RuntimeError, UnicodeError):
            raise RemoteTransferError(_ERROR) from None
        finally:
            payload = b""
            request.clear()
            await _close_owned(state)
        await anyio.lowlevel.checkpoint()
        if time.monotonic() - started >= _SECONDS:
            raise RemoteTransferError(_ERROR)
        # No worker can still write and no network client survives this point.
        await _seal_owned(snapshot, expected)
        await anyio.lowlevel.checkpoint()
    finally:
        _ADMISSION.release()
