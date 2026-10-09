"""Private client-free Dropbox preparation and owned bounded SDK download.

Native resolution retains system DNS policy. Only SDK environment inspection
uses an admitted thread; token refresh and all data networking execute in the
owned child. No public/export route imports this component yet.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, cast
from urllib.parse import urlsplit

import anyio

from app.core.backup_downloads import CHUNK_BYTES, DownloadSnapshot
from app.core.owned_async import complete_before_cancellation
from app.services.vault_native_resolution import (
    _close_owned,
    _Lookup,
    _OwnedChild,
    resolve_storage_host,
)
from app.services.vault_remote_stream import (
    _ADMISSION,
    _SPAWN_THREADS,
    RemoteTransferError,
    _append_owned,
    _Archive,
    _seal_owned,
)
from app.services.vault_s3_stream import _Request

_CHILD = Path(__file__).with_name("vault_dropbox_stream_child.py")
_PREP_ADMISSION = anyio.CapacityLimiter(2)
_PREP_THREADS = anyio.CapacityLimiter(2)
_SECONDS = 60.0
_PREP_SECONDS = 5.0
_MAX_CONTROL = 65536
_ERROR = "Dropbox backup transfer failed; verify the destination and retry"


def _origin(authority: str) -> dict[str, Any]:
    if not isinstance(authority, str) or not authority or len(authority) > 8192:
        raise ValueError(_ERROR)
    parsed = urlsplit("https://" + authority)
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or any(ord(c) < 33 for c in authority)
    ):
        raise ValueError(_ERROR)
    return {"host": parsed.hostname, "port": parsed.port or 443}


def _sdk_environment(config: dict[str, Any]) -> dict[str, Any]:
    credentials = (
        {
            "oauth2_refresh_token": config["refresh_token"],
            "app_key": config["app_key"],
            "app_secret": config.get("app_secret") or "",
        }
        if config.get("refresh_token") and config.get("app_key")
        else {"oauth2_access_token": config.get("access_token")}
    )
    if any(not isinstance(v, str) or len(v) > _MAX_CONTROL for v in credentials.values()):
        raise ValueError(_ERROR)
    if not any(credentials.values()):
        raise ValueError(_ERROR)
    from dropbox import dropbox_client
    from requests.utils import get_environ_proxies, select_proxy

    result: dict[str, Any] = {
        "credentials": credentials,
        "verify": os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("CURL_CA_BUNDLE") or True,
    }
    for name, host in (
        ("api", dropbox_client.API_HOST),
        ("content", dropbox_client.API_CONTENT_HOST),
    ):
        endpoint = _origin(host)
        url = "https://" + host
        proxy = select_proxy(url, get_environ_proxies(url))
        if proxy is not None:
            parsed = urlsplit(proxy)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
                or any(ord(c) < 33 for c in proxy)
            ):
                raise ValueError(_ERROR)
            # Installed Requests has no SOCKS provider. Do not silently fall
            # back to direct networking for an unsupported proxy configuration.
            endpoint["proxy"] = {
                "url": proxy,
                "host": parsed.hostname,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            }
        else:
            endpoint["proxy"] = None
        result[name] = endpoint
    return result


@complete_before_cancellation
async def _environment_owned(config: dict[str, Any]) -> dict[str, Any]:
    return await anyio.to_thread.run_sync(_sdk_environment, config, limiter=_PREP_THREADS)


@dataclass(frozen=True, slots=True)
class PreparedDropboxDownload:
    _plan_json: str = field(repr=False)

    async def copy_download_into(
        self,
        path: str,
        expected: dict[str, Any] | None,
        snapshot: DownloadSnapshot,
    ) -> None:
        if not isinstance(path, str) or not path:
            raise RemoteTransferError(_ERROR)
        key = path[len("dropbox://") :] if path.startswith("dropbox://") else path
        if not key or len(key) > 16384 or any(ord(c) < 32 for c in key):
            raise RemoteTransferError(_ERROR)
        value = json.loads(self._plan_json)
        value.update(path=key, limit=snapshot.limit)
        await _copy_into(value, expected, snapshot)


async def prepare_dropbox_download(
    config: dict[str, Any],
    *,
    revalidate: Callable[[], Awaitable[None]] | None = None,
) -> PreparedDropboxDownload:
    await anyio.lowlevel.checkpoint()
    try:
        _PREP_ADMISSION.acquire_nowait()
    except anyio.WouldBlock:
        raise RemoteTransferError("Dropbox preparation capacity is busy; retry later") from None
    try:
        started = time.monotonic()
        copied = deepcopy(config)
        if not isinstance(copied, dict) or len(json.dumps(copied).encode()) > _MAX_CONTROL:
            raise RemoteTransferError(_ERROR)
        try:
            value = await _environment_owned(copied)
        except Exception:
            raise RemoteTransferError(_ERROR) from None
        await anyio.lowlevel.checkpoint()
        if revalidate is not None:
            await revalidate()
        for name in ("api", "content"):
            endpoint = value[name]
            endpoint["pin"] = await resolve_storage_host(endpoint["host"], allow_private=False)
            if revalidate is not None:
                await revalidate()
            proxy = endpoint["proxy"]
            if proxy:
                # Proxy is trusted process configuration, not a storage-row
                # URL. Preserve private enterprise proxies, while the existing
                # resolver still refuses loopback/link-local/metadata targets.
                proxy["pin"] = await resolve_storage_host(proxy["host"], allow_private=True)
                if revalidate is not None:
                    await revalidate()
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode()) > _MAX_CONTROL or time.monotonic() - started >= _PREP_SECONDS:
            raise RemoteTransferError(_ERROR)
        await anyio.lowlevel.checkpoint()
        return PreparedDropboxDownload(encoded)
    finally:
        _PREP_ADMISSION.release()


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
        state.process.stdin, state.process.stdout = (
            _Request(cast(IO[bytes], process.stdin)),
            _Archive(cast(IO[bytes], process.stdout)),
        )
        os.set_blocking(cast(IO[bytes], process.stdin).fileno(), False)
        os.set_blocking(cast(IO[bytes], process.stdout).fileno(), False)

    await anyio.to_thread.run_sync(spawn, limiter=_SPAWN_THREADS)
    process = cast(_OwnedChild, state.process)
    state.pidfd = os.pidfd_open(process.pid)
    process.pidfd = state.pidfd


async def _copy_into(
    value: dict[str, Any],
    expected: dict[str, Any] | None,
    snapshot: DownloadSnapshot,
) -> None:
    await anyio.lowlevel.checkpoint()
    try:
        _ADMISSION.acquire_nowait()
    except anyio.WouldBlock:
        raise RemoteTransferError("Remote backup transfer capacity is busy; retry later") from None
    payload, state = b"", _Lookup()
    try:
        try:
            payload = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
            if len(payload) > _MAX_CONTROL:
                raise RemoteTransferError(_ERROR)
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
            if time.monotonic() - started >= _SECONDS:
                raise RemoteTransferError(_ERROR)
        except (OSError, TimeoutError, ValueError, RuntimeError, UnicodeError):
            raise RemoteTransferError(_ERROR) from None
        await _seal_owned(snapshot, expected)
        await anyio.lowlevel.checkpoint()
    finally:
        value.clear()
        payload = b""
        try:
            await _close_owned(state)
        finally:
            _ADMISSION.release()
