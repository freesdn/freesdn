# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Own a verified snapshot for exactly one ASGI response lifetime.

No ORM/session or open descriptor is carried from the endpoint into this plan.
This supports local and explicitly integrated remote transfer sources, not
exports, decryptors, uploads or arbitrary remote SDK buffers. Source writers with the same UID remain trusted. Process loss and
stuck kernel I/O require separate deployment/recovery qualification.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import anyio
from fastapi import HTTPException
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from app.core.backup_artifacts import BackupArtifactError, recorded_identity
from app.core.backup_download_lifetime import SCOPE_KEY, DownloadLifetime
from app.core.backup_downloads import (
    CHUNK_BYTES,
    DownloadCapacityError,
    DownloadPool,
    DownloadSnapshot,
)
from app.core.backup_files import BackupFileError, BackupFiles
from app.core.owned_async import complete_before_cancellation

logger = logging.getLogger(__name__)


class LocalDownloadSource:
    """Copied catalogue intent; construction performs no filesystem operation."""

    def __init__(self, root: Path, path: str, metadata: Any, limit: int):
        self.expected = recorded_identity(metadata)
        self.files = BackupFiles(root, limit)
        self.path = path

    def copy_into(self, snapshot: DownloadSnapshot) -> None:
        """Copy a pinned inode without ever materializing the complete archive."""
        with (
            self.files._parent(self.path) as (directory, name),
            self.files._read_fd(directory, name) as fd,
        ):
            before = os.fstat(fd)
            limit = min(self.files.limit, snapshot.limit)
            if not 0 < before.st_size <= limit:
                raise BackupArtifactError("Backup archive is empty or exceeds its size limit.")
            if self.expected is not None and before.st_size != self.expected["bytes"]:
                raise BackupArtifactError("Backup archive does not match its recorded identity.")
            copied = 0
            while chunk := os.read(fd, min(CHUNK_BYTES, limit - copied + 1)):
                copied += len(chunk)
                if copied > limit:
                    raise BackupFileError("Archive exceeds its size limit")
                snapshot.append(chunk)
            after = os.fstat(fd)
            self.files._file_policy(after)
            if (
                copied != before.st_size
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns
            ):
                raise BackupFileError("Archive changed while being read")
        snapshot.seal(self.expected)


class _SnapshotDownloadResponse(Response):
    """Allocate only inside ASGI, retaining ownership through mandatory cleanup."""

    def __init__(
        self,
        pool: DownloadPool,
        filename: str,
        *,
        seconds: float = 900,
        authorize: Callable[[], Awaitable[None]] | None = None,
    ):
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not 0 < seconds <= 86400
        ):
            raise ValueError("Invalid transfer deadline")
        super().__init__(
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
        self.pool, self.seconds = pool, seconds
        self.authorize = authorize
        self.snapshot: DownloadSnapshot | None = None
        self._called = False

    async def _prepare_owned(self) -> None:
        raise NotImplementedError

    @complete_before_cancellation
    async def _read_owned(self) -> bytes:
        if self.snapshot is None:
            raise BackupFileError("Backup download has no owned snapshot")
        return await anyio.to_thread.run_sync(self.snapshot.read_chunk)

    async def _cleanup(self, watcher: asyncio.Task[None], *, release_snapshot: bool = True) -> None:
        watcher.cancel()
        try:
            await watcher
        except asyncio.CancelledError:
            pass
        if self.snapshot is not None and release_snapshot:
            await anyio.to_thread.run_sync(self.snapshot.close)

    async def _cleanup_owned(
        self, watcher: asyncio.Task[None], *, release_snapshot: bool = True
    ) -> None:
        # Unlike ordinary operation admission, cleanup MUST start even when
        # cancellation is already pending. Drain repeated direct cancellation,
        # shield AnyIO scopes and capture errors before asyncio can log them.
        # Stop this receiver before yielding to the owned cleanup task.
        # A completed transport can report disconnect immediately after
        # terminal send; it must not cancel an already completed body.
        # Cancellation delivered during preparation/send still propagates.
        watcher.cancel()
        cancelled = None
        with anyio.CancelScope(shield=True):

            async def capture() -> Exception | None:
                try:
                    await self._cleanup(watcher, release_snapshot=release_snapshot)
                except Exception as error:
                    return error
                return None

            cleanup = asyncio.create_task(capture())
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError as error:
                    if cleanup.cancelled():
                        raise
                    cancelled = error
            cleanup_error = cleanup.result()
            if cleanup_error is not None:
                logger.error("Backup download cleanup ended with %s", type(cleanup_error).__name__)
            if cancelled is not None:
                raise cancelled from None
            if cleanup_error is not None:
                # Do not expose provider/path text through framework logging.
                raise BackupFileError("Backup download cleanup failed") from None

    async def _prepare_headers(self) -> None:
        if self.snapshot is None or self.snapshot.integrity is None:
            raise BackupFileError("Backup download snapshot was not verified")
        self.headers["Content-Length"] = str(self.snapshot.size)
        self.headers["X-FreeSDN-Artifact-Integrity"] = self.snapshot.integrity

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._called:
            raise RuntimeError("A backup download response cannot be reused")
        self._called = True
        owner = asyncio.current_task()
        if owner is None:
            raise RuntimeError("Backup download requires an owning task")

        async def disconnect() -> None:
            try:
                while True:
                    if (await receive())["type"] == "http.disconnect":
                        owner.cancel()
                        return
            except Exception as error:
                logger.warning("Backup download receive ended with %s", type(error).__name__)
                owner.cancel()

        watcher = asyncio.create_task(disconnect())
        started = False
        outer = scope.get(SCOPE_KEY)
        adopted = False
        try:
            if isinstance(outer, DownloadLifetime):

                async def release_outer_snapshot() -> None:
                    await self._cleanup_owned(watcher)

                # No await separates registration and ownership transfer.
                # The outer owner closes even a partially prepared snapshot.
                outer.adopt(self.seconds, release_outer_snapshot)
                adopted = True
            with anyio.fail_after(self.seconds):
                try:
                    await self._prepare_owned()
                except HTTPException:
                    # Private fresh-export preparers perform authorization before
                    # archive access. Preserve their safe refusal status.
                    raise
                except BackupArtifactError as error:
                    raise HTTPException(409, str(error)) from None
                except DownloadCapacityError:
                    raise HTTPException(
                        503,
                        "Backup download capacity is unavailable; retry later.",
                        headers={"Retry-After": "5"},
                    ) from None
                except Exception as error:
                    logger.warning(
                        "Backup download preparation ended with %s", type(error).__name__
                    )
                    raise HTTPException(500, "Backup file is unavailable") from None
                if self.snapshot is None or self.snapshot.integrity is None:
                    raise BackupFileError("Backup download snapshot was not verified")
                if self.authorize is not None:
                    await self.authorize()
                await self._prepare_headers()
                # Owned worker cleanup may return while an enclosing AnyIO
                # cancellation is pending. Honor it before even a synchronous
                # ASGI sender can accept response headers.
                await anyio.lowlevel.checkpoint()
                await send(
                    {
                        "type": "http.response.start",
                        "status": self.status_code,
                        "headers": self.raw_headers,
                    }
                )
                started = True
                while chunk := await self._read_owned():
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
                await send({"type": "http.response.body", "body": b"", "more_body": False})
        except TimeoutError:
            if not started:
                raise HTTPException(
                    504, "Backup download preparation exceeded its deadline."
                ) from None
            raise TimeoutError("Backup download exceeded its deadline") from None
        finally:
            # Always stop the inner receive watcher. Its stream may synthesize
            # disconnect at producer EOF, which is not an outer client event.
            # A registered outer owner retains the snapshot and shared slot.
            await self._cleanup_owned(watcher, release_snapshot=not adopted)


class LocalDownloadResponse(_SnapshotDownloadResponse):
    """Copy a local inode into the shared owned snapshot before sending."""

    def __init__(
        self,
        source: LocalDownloadSource,
        pool: DownloadPool,
        filename: str,
        *,
        seconds: float = 900,
        authorize: Callable[[], Awaitable[None]] | None = None,
    ):
        super().__init__(pool, filename, seconds=seconds, authorize=authorize)
        self.source = source

    def _prepare(self) -> None:
        # Store ownership synchronously before an async result can be discarded
        # by cancellation. The ASGI finally block owns even a partial snapshot.
        self.snapshot = self.pool.acquire()
        self.source.copy_into(self.snapshot)

    @complete_before_cancellation
    async def _prepare_owned(self) -> None:
        await anyio.to_thread.run_sync(self._prepare)


class RemoteDownloadResponse(_SnapshotDownloadResponse):
    """Reserve shared capacity before cancellable remote I/O into that snapshot."""

    def __init__(
        self,
        copy_into: Callable[[DownloadSnapshot], Awaitable[None]],
        pool: DownloadPool,
        filename: str,
        *,
        seconds: float = 900,
        authorize: Callable[[], Awaitable[None]] | None = None,
    ):
        super().__init__(pool, filename, seconds=seconds, authorize=authorize)
        self.copy_into = copy_into

    def _allocate(self) -> None:
        self.snapshot = self.pool.acquire()

    @complete_before_cancellation
    async def _allocate_owned(self) -> None:
        await anyio.to_thread.run_sync(self._allocate)

    async def _prepare_owned(self) -> None:
        await self._allocate_owned()
        if self.snapshot is None:
            raise BackupFileError("Backup download has no owned snapshot")
        # Do not shield the remote request. The provider must close its own
        # response/client before cancellation reaches the snapshot finally.
        await self.copy_into(self.snapshot)
