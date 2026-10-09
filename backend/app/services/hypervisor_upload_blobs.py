# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private, immutable upload sources bound to durable operation IDs.

The persistent upload volume is shared by API and workers. No user-controlled
server path is accepted. Crash orphans are retained for explicit maintenance;
never delete a pending operation's source just because it is old.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import BinaryIO
from uuid import UUID

from fastapi import HTTPException, UploadFile

from app.core.config import settings
from app.models.staging import AdapterPendingChange

MAX_BYTES = 4 * 1024**3
RESERVE_BYTES = 64 * 1024**2


def _root() -> Path:
    root = Path(settings.PROXMOX_UPLOAD_DIR) / "reviewed-v1"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise HTTPException(503, detail="Private upload directory ownership or permissions invalid")
    return root


def _path(change_id: UUID, checksum: str) -> Path:
    # Both inputs are validated before this helper; no path supplied by clients.
    import re

    if not isinstance(change_id, UUID) or not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise HTTPException(400, detail="Invalid upload source identity")
    return _root() / f"{change_id.hex}-{checksum}.blob"


def open_verified(change_id: UUID, checksum: str, size: int) -> BinaryIO:
    path = _path(change_id, checksum)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        handle = os.fdopen(fd, "rb")
        try:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
                or info.st_size != size
            ):
                raise ValueError("source metadata")
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
            if digest != checksum:
                raise ValueError("source checksum")
            handle.seek(0)
            return handle
        except BaseException:
            handle.close()
            raise
    except (OSError, ValueError):
        raise HTTPException(
            409, detail="Upload source missing or changed; do not retry an uncertain operation"
        ) from None


async def spool(file: UploadFile, change_id: UUID, size: int) -> str:
    if type(size) is not int or not 0 < size <= MAX_BYTES:
        raise HTTPException(413, detail="Upload must contain 1 byte to 4 GiB")
    root = _root()
    if shutil.disk_usage(root).free < size + RESERVE_BYTES:
        raise HTTPException(507, detail="Insufficient local upload capacity")
    fd, name = tempfile.mkstemp(prefix="incoming-", dir=root)
    checksum = hashlib.sha256()
    count = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            while chunk := await file.read(1024**2):
                count += len(chunk)
                if count > size or count > MAX_BYTES:
                    raise HTTPException(413, detail="Upload size differs from reviewed size")
                if shutil.disk_usage(root).free < len(chunk) + RESERVE_BYTES:
                    raise HTTPException(507, detail="Insufficient local upload capacity")
                checksum.update(chunk)
                # Disk I/O stays off the event loop. A cancelled request must
                # finish the outstanding write before closing its descriptor.
                task = asyncio.create_task(asyncio.to_thread(handle.write, chunk))
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    await task
                    raise
            if count != size:
                raise HTTPException(400, detail="Upload size differs from reviewed size")
            handle.flush()
            os.fsync(handle.fileno())
        digest = checksum.hexdigest()
        final = _path(change_id, digest)
        try:
            os.link(name, final, follow_symlinks=False)
        except FileExistsError:
            with open_verified(change_id, digest, size):
                pass
        os.unlink(name)
        # Persist the directory entry before committing a DB reference to it.
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return digest
    finally:
        Path(name).unlink(missing_ok=True)


def remove(change_id: UUID, checksum: str) -> None:
    # Only called for the exact operation's source after a durable terminal or
    # uncertain dispatch receipt. No recursive deletion or arbitrary paths.
    _path(change_id, checksum).unlink(missing_ok=True)


async def cleanup_committed(change: AdapterPendingChange) -> None:
    """Best-effort cleanup after the dispatch/discard receipt is committed.

    Failure to unlink must never rewrite an acknowledged provider outcome.
    Unknown/applying crash orphans still need operator maintenance.
    """
    from app.services.hypervisor_storage_operations import is_reviewed_storage, validated_plan

    if not is_reviewed_storage(change) or getattr(change, "status", None) not in {
        "applied",
        "failed",
        "discarded",
        "reconciliation_required",
    }:
        return
    try:
        plan = validated_plan(change)
        if plan["checksum"]:
            await asyncio.to_thread(remove, change.id, plan["checksum"])
    except Exception:
        import logging

        logging.getLogger(__name__).warning("Committed storage upload source requires cleanup")
