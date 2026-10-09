"""Private bounded native resolution, preserving standard system hosts/DNS.

A Linux child uses the configured system resolver, without application secrets,
site startup hooks or further processes. Cleanup kills through a pidfd and reaps
before releasing admission. Unsupported kernels fail closed; deployed Alpine,
NSS/plugin compatibility and process/host-loss qualification remain required.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, cast

import anyio

from app.core.owned_async import complete_before_cancellation
from app.core.security_utils import validate_target_host

_ADMISSION = anyio.CapacityLimiter(2)
_SPAWN_THREADS = anyio.CapacityLimiter(2)
_REAP_THREADS = anyio.CapacityLimiter(2)
_SECONDS = 5.0
_CHILD = Path(__file__).with_name("vault_native_resolver_child.py")
_ERROR = "Storage destination resolution failed; retry after checking the destination"


class StorageResolutionError(ValueError):
    """Fixed diagnostic with no lookup or operating-system details."""


async def _readable(fd: int) -> None:
    loop = asyncio.get_running_loop()
    ready = loop.create_future()

    def wake() -> None:
        if not ready.done():
            ready.set_result(None)

    loop.add_reader(fd, wake)
    try:
        await ready
    finally:
        loop.remove_reader(fd)


class _Input:
    def __init__(self, stream: IO[bytes]) -> None:
        self.stream = stream

    def write(self, value: bytes) -> None:
        # One bounded Linux PIPE_BUF write to an otherwise empty input pipe.
        # Nonblocking mode also refuses an unexpected full pipe without waiting.
        if not 0 < len(value) <= 1024 or os.write(self.stream.fileno(), value) != len(value):
            raise StorageResolutionError(_ERROR)

    async def drain(self) -> None:
        await anyio.lowlevel.checkpoint()

    def close(self) -> None:
        self.stream.close()

    def is_closing(self) -> bool:
        return self.stream.closed

    async def wait_closed(self) -> None:
        await anyio.lowlevel.checkpoint()


class _Output:
    def __init__(self, stream: IO[bytes]) -> None:
        self.stream = stream

    async def read(self, size: int) -> bytes:
        if not 1 <= size <= 4097:
            raise StorageResolutionError(_ERROR)
        fd = self.stream.fileno()
        while True:
            try:
                return os.read(fd, size)
            except BlockingIOError:
                await _readable(fd)


class _OwnedChild:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.raw = process
        self.pid = process.pid
        self.pidfd: int | None = None
        self.stdin = _Input(cast(IO[bytes], process.stdin))
        self.stdout = _Output(cast(IO[bytes], process.stdout))

    @property
    def returncode(self) -> int | None:
        return self.raw.poll()

    async def wait(self) -> int:
        value = self.raw.poll()
        if value is not None:
            return value
        if self.pidfd is None:
            # Only startup refusal reaches this path, inside owned cleanup.
            # Closing stdin makes the fixed child exit without running DNS.
            return await anyio.to_thread.run_sync(self.raw.wait, limiter=_REAP_THREADS)
        await _readable(self.pidfd)
        return self.raw.wait(timeout=0)


@dataclass
class _Lookup:
    process: _OwnedChild | None = None
    pidfd: int | None = None


@complete_before_cancellation
async def _start_owned(state: _Lookup) -> None:
    if (
        sys.platform != "linux"
        or not os.path.isabs(sys.executable)
        or not hasattr(os, "pidfd_open")
        or not hasattr(signal, "pidfd_send_signal")
    ):
        raise StorageResolutionError(_ERROR)

    def spawn() -> None:
        # Capture the handle before any watcher/pidfd setup. The enclosing
        # ownership scope drains this worker even under repeated cancellation.
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", str(_CHILD)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            close_fds=True,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        state.process = _OwnedChild(process)
        os.set_blocking(cast(IO[bytes], process.stdin).fileno(), False)
        os.set_blocking(cast(IO[bytes], process.stdout).fileno(), False)

    await anyio.to_thread.run_sync(spawn, limiter=_SPAWN_THREADS)
    # The child waits for bounded stdin. Keep a stable kernel process reference
    # before sending input; killing must not target a subsequently reused PID.
    state.pidfd = os.pidfd_open(cast(_OwnedChild, state.process).pid)
    cast(_OwnedChild, state.process).pidfd = state.pidfd


async def _close(state: _Lookup) -> None:
    process = state.process
    if process is None:
        return
    try:
        if process.returncode is None:
            if state.pidfd is not None:
                try:
                    signal.pidfd_send_signal(state.pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                # Spawn/setup failed before input was sent. Closing stdin lets
                # the fixed child refuse empty input and exit; never kill by PID.
                if process.stdin is not None:
                    process.stdin.close()
        await process.wait()
        if process.stdin is not None:
            process.stdin.close()
            try:
                await process.stdin.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
    finally:
        try:
            cast(IO[bytes], process.raw.stdin).close()
            cast(IO[bytes], process.raw.stdout).close()
        finally:
            if state.pidfd is not None:
                os.close(state.pidfd)
                state.pidfd = None
                process.pidfd = None


async def _close_owned(state: _Lookup) -> None:
    # No admission checkpoint: an existing child must always acquire an owner
    # for cleanup, even when cancellation is already pending.
    cancelled = None
    with anyio.CancelScope(shield=True):
        task = asyncio.create_task(_close(state))
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError as error:
                if task.cancelled():
                    raise
                cancelled = error
        task.result()
    if cancelled is not None:
        raise cancelled


def _checked_addresses(value: object, *, allow_private: bool) -> str:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise StorageResolutionError(_ERROR)
    for address in value:
        if not isinstance(address, str) or not 1 <= len(address) <= 96:
            raise StorageResolutionError(_ERROR)
        # Validate shape before target policy, so malformed output cannot send
        # a hostname back into the synchronous resolver in validate_target_host.
        ipaddress.ip_address(address)
    # Preserve the existing storage resolver's first-allowed-address policy.
    # Its current docstring overstates mixed-answer rejection; do not silently
    # change that policy while replacing its lifetime implementation.
    for address in value:
        try:
            validate_target_host(address, allow_private=allow_private)
            return cast(str, address)
        except ValueError:
            continue
    raise StorageResolutionError(_ERROR)


async def resolve_storage_host(host: str, *, allow_private: bool = False) -> str:
    await anyio.lowlevel.checkpoint()
    if type(allow_private) is not bool:
        raise StorageResolutionError(_ERROR)
    if not isinstance(host, str) or not 1 <= len(host) <= 253 or any(ord(c) < 33 for c in host):
        raise StorageResolutionError(_ERROR)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        try:
            return _checked_addresses([host], allow_private=allow_private)
        except ValueError:
            raise StorageResolutionError(_ERROR) from None
    try:
        query_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise StorageResolutionError(_ERROR) from None
    if len(query_host) > 253:
        raise StorageResolutionError(_ERROR)
    payload = json.dumps({"host": query_host}, ensure_ascii=True).encode()
    if len(payload) > 1024:
        raise StorageResolutionError(_ERROR)
    try:
        _ADMISSION.acquire_nowait()
    except anyio.WouldBlock:
        raise StorageResolutionError(_ERROR) from None
    state = _Lookup()
    started = time.monotonic()
    try:
        try:
            with anyio.fail_after(_SECONDS):
                await _start_owned(state)
                await anyio.lowlevel.checkpoint()
                process = state.process
                if process is None or process.stdin is None or process.stdout is None:
                    raise StorageResolutionError(_ERROR)
                process.stdin.write(payload)
                await process.stdin.drain()
                process.stdin.close()
                output = bytearray()
                while chunk := await process.stdout.read(4097 - len(output)):
                    output.extend(chunk)
                    if len(output) > 4096:
                        raise StorageResolutionError(_ERROR)
                if await process.wait() != 0:
                    raise StorageResolutionError(_ERROR)
                result = _checked_addresses(json.loads(output), allow_private=allow_private)
        except (OSError, TimeoutError, ValueError, RuntimeError, UnicodeError):
            raise StorageResolutionError(_ERROR) from None
    finally:
        try:
            await _close_owned(state)
        finally:
            _ADMISSION.release()
    await anyio.lowlevel.checkpoint()
    if time.monotonic() - started >= _SECONDS:
        raise StorageResolutionError(_ERROR)
    return result
