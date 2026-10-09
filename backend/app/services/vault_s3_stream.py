"""Private bounded S3 data transfer; not the public constructor/export flow.

Credentials are frozen from the caller's real SDK client in an owned worker.
That step retains ownership, but cannot kill arbitrary credential-provider
helpers or stuck filesystem calls. Only the subsequent network/data child has
a hard process deadline. No SDK credential chain runs in that child.
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
from collections.abc import Awaitable, Callable
from copy import deepcopy
from pathlib import Path
from typing import IO, Any, Protocol, cast
from urllib.parse import urlsplit

import anyio

from app.core.backup_downloads import CHUNK_BYTES, DownloadSnapshot
from app.core.owned_async import complete_before_cancellation
from app.core.security_utils import validate_target_host
from app.services.vault_native_resolution import (
    _close_owned,
    _Input,
    _Lookup,
    _OwnedChild,
    resolve_storage_host,
)
from app.services.vault_remote_stream import (
    _ADMISSION,
    _SPAWN_THREADS,
    _append_owned,
    _Archive,
    _seal_owned,
)
from app.services.vault_remote_stream import (
    RemoteTransferError as RemoteTransferError,
)

_CHILD = Path(__file__).with_name("vault_s3_stream_child.py")
_PREP_THREADS = anyio.CapacityLimiter(2)
_SECONDS = 60.0
_PREP_SECONDS = 5.0
_REQUEST_BYTES = 65536
_ERROR = "S3 backup transfer failed; verify the destination and retry"


class _S3ClientView(Protocol):
    """The three fields copied from an already constructed boto3 client adapter."""

    @property
    def bucket(self) -> str: ...

    @property
    def client(self) -> Any: ...  # boto3 exposes this SDK surface dynamically.

    @property
    def _sni_hostname(self) -> str | None: ...


class _Request(_Input):
    async def send(self, payload: bytes) -> None:
        # Session credentials can exceed PIPE_BUF. Bounded nonblocking writes
        # wait for pipe readiness, never a detached executor write.
        if not 0 < len(payload) <= _REQUEST_BYTES:
            raise RemoteTransferError(_ERROR)
        view = memoryview(payload)
        fd = self.stream.fileno()
        while view:
            await anyio.lowlevel.checkpoint()
            try:
                sent = os.write(fd, view[:4096])
                if sent <= 0:
                    raise RemoteTransferError(_ERROR)
                view = view[sent:]
            except BlockingIOError:
                loop = asyncio.get_running_loop()
                ready = loop.create_future()

                def wake(future: asyncio.Future[None] = ready) -> None:
                    if not future.done():
                        future.set_result(None)

                loop.add_writer(fd, wake)
                try:
                    await ready
                finally:
                    loop.remove_writer(fd)


def _freeze_client(backend: _S3ClientView, path: str, limit: int) -> dict[str, Any]:
    bucket = backend.bucket
    if not isinstance(bucket, str) or not bucket or not isinstance(path, str):
        raise ValueError(_ERROR)
    prefix = "s3://" + bucket + "/"
    if path.startswith("s3://"):
        if not path.startswith(prefix):
            raise ValueError(_ERROR)
        key = path[len(prefix) :]
    else:
        key = path
    if not key:
        raise ValueError(_ERROR)
    client = backend.client
    endpoint = urlsplit(client.meta.endpoint_url)
    if (
        endpoint.scheme not in {"http", "https"}
        or not endpoint.hostname
        or endpoint.username
        or endpoint.password
        or endpoint.query
        or endpoint.fragment
    ):
        raise ValueError(_ERROR)
    credentials = client._request_signer._credentials
    frozen = credentials.get_frozen_credentials()
    expiry = getattr(credentials, "_expiry_time", None)
    expiry = expiry.timestamp() if expiry is not None else None
    config = client.meta.config
    transport = client._endpoint.http_session
    cert = transport._cert_file
    if transport._key_file:
        cert = [cert, transport._key_file]
    result: dict[str, Any] = {
        "bucket": bucket,
        "key": key,
        "limit": limit,
        "scheme": endpoint.scheme,
        "endpoint_host": endpoint.hostname,
        "hostname": backend._sni_hostname or endpoint.hostname,
        "port": endpoint.port or (443 if endpoint.scheme == "https" else 80),
        "basepath": endpoint.path,
        "region": config.region_name,
        "access": frozen.access_key,
        "secret": frozen.secret_key,
        "token": frozen.token,
        "expires": expiry,
        "verify": transport._verify,
        "client_cert": cert,
        "options": {
            "signature_version": config.signature_version,
            "connect_timeout": config.connect_timeout,
            "read_timeout": config.read_timeout,
            "retries": config.retries,
            "s3": config.s3,
            "request_checksum_calculation": config.request_checksum_calculation,
            "response_checksum_validation": config.response_checksum_validation,
        },
        "proxies": dict(transport._proxy_config._proxies),
        "proxies_config": dict(transport._proxy_config.settings),
    }
    result = deepcopy(result)
    if len(json.dumps(result, ensure_ascii=True).encode()) > _REQUEST_BYTES:
        raise ValueError(_ERROR)
    return result


@complete_before_cancellation
async def _prepare_owned(backend: _S3ClientView, path: str, limit: int) -> dict[str, Any]:
    return await anyio.to_thread.run_sync(
        _freeze_client, backend, path, limit, limiter=_PREP_THREADS
    )


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
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(_CHILD)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            close_fds=True,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
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


def _live(request: dict[str, Any]) -> None:
    expiry = request["expires"]
    if expiry is not None and time.time() >= expiry:
        raise RemoteTransferError(_ERROR)


async def _copy_prepared_into(
    prepare: Callable[[], Awaitable[dict[str, Any]]],
    expected: dict[str, Any] | None,
    snapshot: DownloadSnapshot,
) -> None:
    await anyio.lowlevel.checkpoint()
    try:
        _ADMISSION.acquire_nowait()
    except anyio.WouldBlock:
        raise RemoteTransferError("Remote backup transfer capacity is busy; retry later") from None
    request, payload = {}, b""
    state = _Lookup()
    try:
        try:
            started = time.monotonic()
            try:
                request = await prepare()
            except Exception:
                raise RemoteTransferError(_ERROR) from None
            await anyio.lowlevel.checkpoint()
            if time.monotonic() - started >= _PREP_SECONDS:
                raise RemoteTransferError(_ERROR)
            host = request.pop("endpoint_host")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pin = await resolve_storage_host(host, allow_private=False)
            else:
                pin = validate_target_host(host, allow_private=False)
            request["pin"] = pin
            _live(request)
            payload = json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode()
            started = time.monotonic()
            with anyio.fail_after(_SECONDS):
                await _start_owned(state)
                await anyio.lowlevel.checkpoint()
                process = cast(_OwnedChild, state.process)
                await cast(_Request, process.stdin).send(payload)
                process.stdin.close()
                while chunk := await process.stdout.read(CHUNK_BYTES):
                    await _append_owned(snapshot, chunk)
                if await process.wait() != 0:
                    raise RemoteTransferError(_ERROR)
            await _close_owned(state)
            await anyio.lowlevel.checkpoint()
            _live(request)
            if time.monotonic() - started >= _SECONDS:
                raise RemoteTransferError(_ERROR)
        except (OSError, TimeoutError, ValueError, RuntimeError, UnicodeError):
            raise RemoteTransferError(_ERROR) from None
        await _seal_owned(snapshot, expected)
        await anyio.lowlevel.checkpoint()
        _live(request)
    finally:
        request.clear()
        payload = b""
        try:
            await _close_owned(state)
        finally:
            _ADMISSION.release()


async def copy_s3_into(
    backend: _S3ClientView,
    path: str,
    expected: dict[str, Any] | None,
    snapshot: DownloadSnapshot,
) -> None:
    async def prepare() -> dict[str, Any]:
        return await _prepare_owned(backend, path, snapshot.limit)

    await _copy_prepared_into(prepare, expected, snapshot)
