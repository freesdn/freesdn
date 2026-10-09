"""Private Google Drive single-response preparation and owned bounded download.

Native resolution retains system DNS policy. Only SDK environment inspection
uses an admitted thread; token refresh and all data networking execute in the
owned child. No public/export route imports this component yet.
"""

from __future__ import annotations

import json
import os
import re
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

_CHILD = Path(__file__).with_name("vault_gdrive_single_stream_child.py")
_PREP_ADMISSION = anyio.CapacityLimiter(2)
_PREP_THREADS = anyio.CapacityLimiter(2)
_SECONDS = 60.0
_PREP_SECONDS = 5.0
_MAX_CONTROL = 65536
_ERROR = "Google Drive backup transfer failed; verify the destination and retry"


def _sdk_environment(config: dict[str, Any]) -> dict[str, Any]:
    # Validate bounded plain metadata before importing SDK modules.
    credentials: dict[str, Any]
    if config.get("credentials_json"):
        info = config["credentials_json"]
        if isinstance(info, str):
            if len(info) > _MAX_CONTROL:
                raise ValueError(_ERROR)
            info = json.loads(info)
        if (
            not isinstance(info, dict)
            or info.get("type") != "service_account"
            or info.get("token_uri") != "https://oauth2.googleapis.com/token"
            or info.get("universe_domain", "googleapis.com") != "googleapis.com"
            or not isinstance(info.get("client_email"), str)
            or not re.fullmatch(
                r"[A-Za-z0-9_.+-]{1,256}@[A-Za-z0-9.-]{1,253}", info["client_email"]
            )
            or not isinstance(info.get("private_key"), str)
            or not 1 <= len(info["private_key"]) <= 16384
        ):
            raise ValueError(_ERROR)
        credentials = {
            "service_account": {
                key: info[key] for key in ("type", "client_email", "private_key", "token_uri")
            }
        }
    else:
        credentials = {
            key: config.get(key)
            for key in ("access_token", "refresh_token", "client_id", "client_secret")
        }
        if any(
            v is not None
            and (not isinstance(v, str) or len(v) > 16384 or any(ord(c) < 32 for c in v))
            for v in credentials.values()
        ) or not (
            credentials["access_token"]
            or (
                credentials["refresh_token"]
                and credentials["client_id"]
                and credentials["client_secret"]
            )
        ):
            raise ValueError(_ERROR)
    from requests.utils import get_environ_proxies, select_proxy

    result: dict[str, Any] = {
        "credentials": credentials,
        "verify": os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("CURL_CA_BUNDLE") or True,
    }
    endpoints = [("drive", "www.googleapis.com")]
    if credentials.get("refresh_token") or "service_account" in credentials:
        endpoints.append(("token", "oauth2.googleapis.com"))
    if "service_account" in credentials:
        endpoints.append(("regional", "iamcredentials.googleapis.com"))
    for name, hostname in endpoints:
        url = "https://" + hostname
        proxy = select_proxy(url, get_environ_proxies(url))
        endpoint: dict[str, Any] = {"host": hostname, "port": 443, "proxy": None}
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
            endpoint["proxy"] = {
                "url": proxy,
                "host": parsed.hostname,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            }
        result[name] = endpoint
    return result


@complete_before_cancellation
async def _environment_owned(config: dict[str, Any]) -> dict[str, Any]:
    return await anyio.to_thread.run_sync(_sdk_environment, config, limiter=_PREP_THREADS)


@dataclass(frozen=True, slots=True)
class PreparedGoogleDriveSingleDownload:
    _plan_json: str = field(repr=False)

    async def copy_download_into(
        self,
        path: str,
        expected: dict[str, Any] | None,
        snapshot: DownloadSnapshot,
    ) -> None:
        if not isinstance(path, str) or not path:
            raise RemoteTransferError(_ERROR)
        key = path[len("gdrive://") :] if path.startswith("gdrive://") else path
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}", key):
            raise RemoteTransferError(_ERROR)
        value = json.loads(self._plan_json)
        value.update(path=key, limit=snapshot.limit)
        await _copy_into(value, expected, snapshot)


async def prepare_gdrive_single_download(
    config: dict[str, Any],
    *,
    revalidate: Callable[[], Awaitable[None]] | None = None,
) -> PreparedGoogleDriveSingleDownload:
    await anyio.lowlevel.checkpoint()
    try:
        _PREP_ADMISSION.acquire_nowait()
    except anyio.WouldBlock:
        raise RemoteTransferError(
            "Google Drive preparation capacity is busy; retry later"
        ) from None
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
        for name in (n for n in ("drive", "token", "regional") if n in value):
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
        return PreparedGoogleDriveSingleDownload(encoded)
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
