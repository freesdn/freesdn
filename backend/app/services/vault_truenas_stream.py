"""Copied TrueNAS identity and owned, bounded WebSocket/HTTPS archive reads.

The native child owns both connections. A killed child is local cleanup, not
proof that an appliance has finished or aborted its remote download job.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, cast
from uuid import UUID

import anyio
from fastapi import HTTPException

from app.core.backup_downloads import CHUNK_BYTES, DownloadSnapshot
from app.core.owned_async import complete_before_cancellation
from app.models.core import Controller
from app.services.adapter_truenas_storage import _validate_dataset_path, _validate_filename
from app.services.backup import TrueNASStorageBackend
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

_CHILD = Path(__file__).with_name("vault_truenas_stream_child.py")
_PREP_ADMISSION = anyio.CapacityLimiter(2)
_PREP_THREADS = anyio.CapacityLimiter(2)
_SECONDS = 60.0
_PREP_SECONDS = 5.0
_MAX_CONTROL = 65536
_ERROR = "TrueNAS backup transfer failed; verify the destination and retry"
logger = logging.getLogger(__name__)


def _collect_plan(config: dict[str, Any], controller_json: str | None) -> dict[str, Any]:
    backend = TrueNASStorageBackend(config)
    if controller_json is None:
        raise ValueError(_ERROR)
    values = json.loads(controller_json)
    if (
        UUID(values.pop("organization_id")) != UUID(backend._organization_id)
        or values.pop("site_deleted_at") is not None
        or UUID(values["id"]) != backend.controller_id
    ):
        raise ValueError(_ERROR)
    for name in ("id", "site_id", "credential_id"):
        if values[name] is not None:
            values[name] = UUID(values[name])
    controller = Controller(**values)
    if (
        controller.controller_type != "truenas"
        or controller.is_active is not True
        or controller.deleted_at is not None
    ):
        raise ValueError(_ERROR)
    # Detached real properties preserve field-key decryption, with no database
    # lookup or last_used commit that could replace the checked authority.
    host = controller.host
    if not isinstance(host, str) or not 1 <= len(host) <= 253 or any(ord(c) < 33 for c in host):
        raise ValueError(_ERROR)
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode("idna").decode("ascii")
        if any(c in host for c in "/\\:@?#[]"):
            raise ValueError(_ERROR) from None
    port = controller.port or 443
    if type(port) is not int or not 1 <= port <= 65535 or type(controller.verify_ssl) is not bool:
        raise ValueError(_ERROR)
    if port == 80:
        port = 443  # Existing adapter always uses TLS for its data plane.
    username, api_key = controller.username or "", controller.password or ""
    if any(not isinstance(v, str) or len(v.encode()) > 16384 for v in (username, api_key)):
        raise ValueError(_ERROR)
    dataset = backend.dataset_path
    if not dataset.startswith("/mnt/"):
        dataset = "/mnt/" + dataset.strip("/")
    dataset = _validate_dataset_path(dataset)
    trust = {
        name: os.environ.get(name)
        for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "FREESDN_DEVICE_CA_BUNDLE")
    }
    if any(
        v is not None and (not isinstance(v, str) or len(v) > 4096 or "\0" in v)
        for v in trust.values()
    ):
        raise ValueError(_ERROR)
    if not controller.verify_ssl:
        logger.warning(
            "truenas: TLS peer verification explicitly disabled; connection is not authenticated"
        )
    return {
        "host": host,
        "port": port,
        "username": username,
        "api_key": api_key,
        "verify_ssl": controller.verify_ssl,
        "trust": trust,
        "dataset": dataset,
    }


@complete_before_cancellation
async def _plan_owned(config: dict[str, Any], controller_json: str | None) -> dict[str, Any]:
    return await anyio.to_thread.run_sync(
        _collect_plan, config, controller_json, limiter=_PREP_THREADS
    )


@dataclass(frozen=True, slots=True)
class PreparedTrueNASDownload:
    _plan_json: str = field(repr=False)

    async def copy_download_into(
        self,
        path: str,
        expected: dict[str, Any] | None,
        snapshot: DownloadSnapshot,
    ) -> None:
        try:
            if not isinstance(path, str) or not 1 <= len(path.encode()) <= 4096:
                raise ValueError(_ERROR)
            token, separator, filename = path.partition("/")
            if (
                not separator
                or not token
                or any(not (c.isascii() and (c.isalnum() or c in "-_")) for c in token)
            ):
                raise ValueError(_ERROR)
            *directories, leaf = filename.split("/")
            if any(
                not p or p in (".", "..") or "\\" in p or any(ord(c) < 32 for c in p)
                for p in directories
            ):
                raise ValueError(_ERROR)
            value = json.loads(self._plan_json)
            base = _validate_dataset_path(value.pop("dataset") + "/" + token)
            value.update(
                path=base.rstrip("/") + "/" + "/".join([*directories, _validate_filename(leaf)]),
                limit=snapshot.limit,
            )
        except (TypeError, ValueError, KeyError, UnicodeError, HTTPException):
            raise RemoteTransferError(_ERROR) from None
        await _copy_into(value, expected, snapshot)


async def prepare_truenas_download(
    config: dict[str, Any],
    controller_json: str | None,
    *,
    revalidate: Callable[[], Awaitable[None]] | None = None,
) -> PreparedTrueNASDownload:
    await anyio.lowlevel.checkpoint()
    try:
        _PREP_ADMISSION.acquire_nowait()
    except anyio.WouldBlock:
        raise RemoteTransferError("TrueNAS preparation capacity is busy; retry later") from None
    try:
        started = time.monotonic()
        try:
            value = await _plan_owned(config, controller_json)
        except Exception:
            raise RemoteTransferError(_ERROR) from None
        await anyio.lowlevel.checkpoint()
        if revalidate is not None:
            await revalidate()
        value["pin"] = await resolve_storage_host(value["host"], allow_private=True)
        if revalidate is not None:
            await revalidate()
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode()) > _MAX_CONTROL or time.monotonic() - started >= _PREP_SECONDS:
            raise RemoteTransferError(_ERROR)
        await anyio.lowlevel.checkpoint()
        return PreparedTrueNASDownload(encoded)
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
