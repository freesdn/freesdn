# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private Linux HLS control IPC for workers sharing one local media directory.

The elected worker alone owns Process objects. This is same-host coordination,
not cross-host routing or seamless active-stream failover. Peers share the trusted
application UID; current user/camera authorization belongs at each HTTP request.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import logging
import os
import re
import socket
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from app.core.private_files import PrivateFileError, private_directory
from app.modules.cameras.service import HLSStreamService

_MAX_MESSAGE = 16384
_TIMEOUT = 20.0
_MAX_CONNECTIONS = 64
_SOCKET = "control.sock"
_LOCK = "control.lock"


class HLSCoordinatorError(RuntimeError):
    """Fixed control-plane availability error; never contains source credentials."""


@dataclass
class _Owner:
    root: Path
    lock_fd: int
    directory_fd: int
    service: HLSStreamService
    server: asyncio.Server | None = None
    socket_identity: tuple[int, int] | None = None
    clients: set[asyncio.Task[Any]] = field(default_factory=set)
    closing: bool = False


_owner: _Owner | None = None
_gate = asyncio.Lock()
_stopping = False
logger = logging.getLogger(__name__)


def _same_uid(writer: asyncio.StreamWriter) -> bool:
    peer = writer.get_extra_info("socket")
    if peer is None:
        return False
    _pid, uid, _gid = struct.unpack(
        "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    )
    return bool(uid == os.geteuid())


def _socket_info(directory: int, name: str = _SOCKET) -> os.stat_result:
    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PrivateFileError("Unsafe HLS control socket")
    return info


def _take_lock(directory: int) -> int | None:
    fd = os.open(
        _LOCK,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        0o600,
        dir_fd=directory,
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
        ):
            raise PrivateFileError("Unsafe HLS election file")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        return fd
    except BaseException:
        os.close(fd)
        raise


def _session_id(params: dict[str, Any]) -> str:
    value = params.get("session_id")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise ValueError("Invalid session")
    return value


async def _dispatch(owner: _Owner, operation: str, params: dict[str, Any]) -> Any:
    if owner.closing:
        raise HLSCoordinatorError("HLS coordinator unavailable")
    service = owner.service
    if operation == "start":
        allowed = {
            "camera_id",
            "organization_id",
            "quality",
            "rtsp_url",
            "source_codec",
            "session_key",
            "is_recorded",
        }
        if set(params) - allowed:
            raise ValueError("Invalid fields")
        camera = UUID(params["camera_id"])
        org = params.get("organization_id")
        org = UUID(org) if org is not None else None
        url, quality = params["rtsp_url"], params["quality"]
        codec, key, recorded = (
            params.get("source_codec", "h264"),
            params.get("session_key"),
            params.get("is_recorded", False),
        )
        if (
            not isinstance(url, str)
            or len(url) > 8192
            or not re.match(r"^rtsps?://", url)
            or quality not in service._QUALITY_PRESETS
            or not isinstance(codec, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", codec)
            or (key is not None and (not isinstance(key, str) or len(key) > 512))
            or not isinstance(recorded, bool)
        ):
            raise ValueError("Invalid media request")
        return await service.start_session(camera, quality, url, codec, org, key, recorded)
    sid = _session_id(params)
    if set(params) != ({"session_id", "segment"} if operation == "segment" else {"session_id"}):
        raise ValueError("Invalid fields")
    if operation == "info":
        # Stop mutates viewer count before awaiting child reaping. Serialize
        # metadata reads so peers see a complete session or its absence.
        async with service._lock:
            meta = service._sessions.get(sid)
            if meta is None:
                return None
            return {
                key: meta[key]
                for key in [
                    "camera_id",
                    "organization_id",
                    "is_recorded",
                    "viewers",
                    "source_codec",
                    "quality",
                ]
            }
    if operation == "heartbeat":
        return await service.heartbeat(sid)
    if operation == "playlist":
        return service.get_playlist_path(sid)
    if operation == "segment":
        segment = params["segment"]
        if not isinstance(segment, str) or not re.fullmatch(r"\d{5}\.ts", segment):
            raise ValueError("Invalid segment")
        return service.get_segment_path(sid, segment)
    if operation == "stop":
        await service.stop_session(sid)
        return None
    raise ValueError("Invalid operation")


async def _handle(
    owner: _Owner, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    task = asyncio.current_task()
    if task is None:
        writer.close()
        return
    if owner.closing or len(owner.clients) >= _MAX_CONNECTIONS:
        writer.close()
        return
    owner.clients.add(task)
    try:
        async with asyncio.timeout(_TIMEOUT):
            if not _same_uid(writer):
                return
            try:
                data = await reader.readline()
                if not data.endswith(b"\n") or len(data) > _MAX_MESSAGE:
                    raise ValueError("Invalid framing")
                request = json.loads(data)
                if not isinstance(request, dict) or set(request) != {"operation", "params"}:
                    raise ValueError("Invalid request")
                if not isinstance(request["operation"], str) or not isinstance(
                    request["params"], dict
                ):
                    raise ValueError("Invalid request")
                result = await _dispatch(owner, request["operation"], request["params"])
                response = {"ok": True, "result": result}
            except (ValueError, TypeError, KeyError, UnicodeDecodeError):
                response = {"ok": False, "error": "invalid_request"}
            except Exception:
                response = {"ok": False, "error": "unavailable"}
            encoded = json.dumps(response, separators=(",", ":")).encode() + b"\n"
            if len(encoded) > _MAX_MESSAGE:
                encoded = b'{"ok":false,"error":"unavailable"}\n'
            writer.write(encoded)
            await writer.drain()
    except (OSError, TimeoutError):
        logger.debug("HLS control connection closed before completion")
    finally:
        owner.clients.discard(task)
        writer.close()
        with contextlib.suppress(OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)


def begin_coordinator_lifecycle() -> None:
    """Allow requests at API lifespan start, without electing an idle owner."""
    global _stopping
    if _owner is not None and _owner.closing:
        raise HLSCoordinatorError("HLS coordinator unavailable")
    _stopping = False


async def ensure_coordinator() -> None:
    global _owner
    root = Path(HLSStreamService.HLS_DIR).absolute()
    async with _gate:
        if _stopping:
            raise HLSCoordinatorError("HLS coordinator unavailable")
        if _owner is not None:
            if _owner.root != root or _owner.closing:
                raise HLSCoordinatorError("HLS coordinator unavailable")
            return
        with private_directory(root) as directory:
            fd = _take_lock(directory)
            if fd is None:
                return
            kept_directory = os.dup(directory)
            owner = _Owner(root, fd, kept_directory, HLSStreamService())
            sock: socket.socket | None = None
            staging_name = f".control-{uuid4().hex}.sock"
            staging_identity: tuple[int, int] | None = None
            try:
                try:
                    _socket_info(directory)
                except FileNotFoundError:
                    pass
                else:
                    os.unlink(_SOCKET, dir_fd=directory)
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                # The public name becomes visible only after permissions and
                # listening are ready. Do not change the process-wide umask.
                sock.bind(f"/proc/self/fd/{directory}/{staging_name}")
                info = os.stat(staging_name, dir_fd=directory, follow_symlinks=False)
                staging_identity = info.st_dev, info.st_ino
                os.chmod(staging_name, 0o600, dir_fd=directory, follow_symlinks=False)
                info = _socket_info(directory, staging_name)
                owner.socket_identity = info.st_dev, info.st_ino
                sock.setblocking(False)
                owner.server = await asyncio.start_unix_server(
                    lambda reader, writer: _handle(owner, reader, writer),
                    sock=sock,
                    limit=_MAX_MESSAGE + 1,
                    cleanup_socket=False,
                )
                os.rename(staging_name, _SOCKET, src_dir_fd=directory, dst_dir_fd=directory)
                _owner = owner
            except BaseException:
                try:
                    if owner.server is not None:
                        owner.server.close()
                        await owner.server.wait_closed()
                    elif sock is not None:
                        sock.close()
                finally:
                    try:
                        if staging_identity is not None:
                            with contextlib.suppress(FileNotFoundError):
                                info = os.stat(
                                    staging_name, dir_fd=directory, follow_symlinks=False
                                )
                                if (info.st_dev, info.st_ino) == staging_identity:
                                    os.unlink(staging_name, dir_fd=directory)
                    finally:
                        os.close(kept_directory)
                        os.close(fd)
                raise


def _validate_result(operation: str, params: dict[str, Any], result: Any) -> None:
    """Accept only the flat, operation-specific response contract."""
    if operation == "stop" and result is None:
        return
    if operation == "heartbeat" and isinstance(result, bool):
        return
    if operation in {"info", "playlist", "segment"} and result is None:
        return
    if operation in {"playlist", "segment"}:
        sid = _session_id(params)
        name = "stream.m3u8" if operation == "playlist" else params.get("segment")
        if not isinstance(name, str) or (
            operation == "segment" and not re.fullmatch(r"\d{5}\.ts", name)
        ):
            raise ValueError("Invalid media response")
        if result != str(Path(HLSStreamService.HLS_DIR).absolute() / sid / name):
            raise ValueError("Invalid media response")
        return
    if not isinstance(result, dict):
        raise ValueError("Invalid control result")
    if operation == "info":
        expected = {
            "camera_id",
            "organization_id",
            "is_recorded",
            "viewers",
            "source_codec",
            "quality",
        }
        if set(result) != expected or not isinstance(result["camera_id"], str):
            raise ValueError("Invalid session metadata")
        UUID(result["camera_id"])
        org = result["organization_id"]
        if org is not None:
            if not isinstance(org, str):
                raise ValueError("Invalid session scope")
            UUID(org)
        if not isinstance(result["is_recorded"], bool):
            raise ValueError("Invalid session mode")
        codec = result["source_codec"]
    elif operation == "start":
        expected = {"session_id", "playlist_url", "codec", "quality", "viewers"}
        if set(result) != expected:
            raise ValueError("Invalid session start result")
        sid = _session_id(result)
        if result["playlist_url"] != f"/api/v1/cameras/streams/hls/{sid}/stream.m3u8":
            raise ValueError("Invalid playlist location")
        codec = result["codec"]
    else:
        raise ValueError("Invalid operation result")
    if not isinstance(codec, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", codec):
        raise ValueError("Invalid source codec")
    if (
        not isinstance(result["quality"], str)
        or result["quality"] not in HLSStreamService._QUALITY_PRESETS
    ):
        raise ValueError("Invalid quality")
    if type(result["viewers"]) is not int or result["viewers"] < 1:
        raise ValueError("Invalid viewer count")


async def request(operation: str, **params: Any) -> Any:
    """One bounded request; never replay a mutation after bytes were submitted."""
    writer: asyncio.StreamWriter | None = None
    try:
        encoded = (
            json.dumps({"operation": operation, "params": params}, default=str).encode() + b"\n"
        )
        if len(encoded) > _MAX_MESSAGE:
            raise ValueError("Request too large")
        async with asyncio.timeout(_TIMEOUT):
            # Retry only connection establishment, before any operation was sent.
            # Another worker may hold the election lock while it is still
            # starting. The existing request deadline bounds this wait.
            while True:
                await ensure_coordinator()
                try:
                    with private_directory(
                        Path(HLSStreamService.HLS_DIR), create=False
                    ) as directory:
                        _socket_info(directory)
                        reader, writer = await asyncio.open_unix_connection(
                            f"/proc/self/fd/{directory}/{_SOCKET}",
                            limit=_MAX_MESSAGE + 1,
                        )
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    await asyncio.sleep(0.05)
            if writer is None or not _same_uid(writer):
                raise ValueError("Invalid peer")
            writer.write(encoded)
            await writer.drain()
            data = await reader.readline()
            if not data.endswith(b"\n") or len(data) > _MAX_MESSAGE:
                raise ValueError("Invalid response")
            response = json.loads(data)
            if (
                not isinstance(response, dict)
                or response.get("ok") is not True
                or set(response) != {"ok", "result"}
            ):
                raise ValueError("Control refusal")
            _validate_result(operation, params, response["result"])
            return response["result"]
    except (OSError, TimeoutError, ValueError, TypeError, RecursionError):
        raise HLSCoordinatorError("HLS coordinator unavailable") from None
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)


async def shutdown_coordinator(*, permanent: bool = False) -> None:
    global _owner, _stopping
    async with _gate:
        _stopping = _stopping or permanent
        owner = _owner
        if owner is None:
            return
        owner.closing = True
        if owner.server is not None:
            owner.server.close()
        tasks = list(owner.clients)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # wait_closed also waits for accepted connections; stop their handlers
        # first so shutdown does not wait for the normal request deadline.
        if owner.server is not None:
            await owner.server.wait_closed()
        async with owner.service._lock:
            for sid, meta in list(owner.service._sessions.items()):
                await owner.service._kill_session(sid, meta)
        info = _socket_info(owner.directory_fd)
        if (info.st_dev, info.st_ino) != owner.socket_identity:
            raise HLSCoordinatorError("HLS coordinator unavailable")
        os.unlink(_SOCKET, dir_fd=owner.directory_fd)
        os.close(owner.directory_fd)
        os.close(owner.lock_fd)
        _owner = None
