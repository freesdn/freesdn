# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private prototype: bounded disk snapshots and cross-process transfer slots.

A snapshot must remain owned through response completion. This module does not
integrate HTTP authorization/cancellation, remote providers, import/restore or
whole-container resource admission. Shared-UID processes are trusted writers.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import hmac
import json
import os
import stat
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.backup_artifacts import BackupArtifactError, recorded_identity
from app.core.backup_files import BackupFileError, BackupFiles
from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES

CHUNK_BYTES = 64 * 1024


class DownloadCapacityError(BackupFileError):
    """Fixed safe resource-admission failure; no provider details."""


class DownloadPoolError(BackupFileError):
    """Unsupported transfer-directory or shared-pool configuration."""


def _disk_filesystem(directory: int) -> str:
    """Use the opened directory's kernel mount ID, not a path-prefix guess."""
    with open(f"/proc/self/fdinfo/{directory}", encoding="ascii") as info:
        details = info.read(4097)
    if len(details) > 4096:
        raise DownloadPoolError("Transfer directory metadata is unsupported")
    mount_ids = [line.split()[1] for line in details.splitlines() if line.startswith("mnt_id:")]
    with open("/proc/self/mountinfo", encoding="utf-8") as mounts:
        rows = mounts.read(1024 * 1024 + 1)
    if len(mount_ids) != 1 or len(rows) > 1024 * 1024:
        raise DownloadPoolError("Transfer mount metadata is unsupported")
    for row in rows.splitlines():
        left, separator, right = row.partition(" - ")
        if separator and left.split()[0] == mount_ids[0]:
            filesystem = right.split()[0]
            if filesystem in {"ext4", "xfs", "btrfs", "zfs"}:
                return filesystem
            break
    raise DownloadPoolError("Transfers require a supported disk-backed local directory")


def _owned_regular(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise DownloadPoolError("Transfer pool file has unsupported ownership or permissions")


def _write_all(fd: int, value: bytes | memoryview) -> None:
    view = memoryview(value)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset : offset + CHUNK_BYTES])
        if written < 1:
            raise DownloadPoolError("Transfer snapshot write made no progress")
        offset += written


class DownloadSnapshot:
    """An unlinked bounded snapshot plus its still-held cross-process slot."""

    def __init__(self, fd: int, slot: int, limit: int):
        self._fd, self._slot = fd, slot
        self.limit = limit
        self.size = 0
        self._digest = hashlib.sha256()
        self.integrity: str | None = None

    def append(self, value: bytes) -> None:
        if self._fd < 0 or self.integrity is not None:
            raise DownloadPoolError("Transfer snapshot is not writable")
        if (
            not isinstance(value, bytes)
            or len(value) > CHUNK_BYTES
            or self.size + len(value) > self.limit
        ):
            raise DownloadPoolError("Transfer snapshot exceeds its bounded capacity")
        _write_all(self._fd, value)
        self._digest.update(value)
        self.size += len(value)

    def seal(self, expected: dict[str, Any] | None) -> str:
        if self._fd < 0 or self.integrity is not None or self.size < 1:
            raise DownloadPoolError("Transfer snapshot is empty or already sealed")
        if expected is not None:
            expected = recorded_identity({"artifact_identity": expected})
        os.fsync(self._fd)
        os.lseek(self._fd, 0, os.SEEK_SET)
        stored_digest = hashlib.sha256()
        stored_bytes = 0
        while chunk := os.read(self._fd, min(CHUNK_BYTES, self.limit - stored_bytes + 1)):
            stored_bytes += len(chunk)
            if stored_bytes > self.limit:
                raise DownloadPoolError("Transfer snapshot exceeds its bounded capacity")
            stored_digest.update(chunk)
        if stored_bytes != self.size or not hmac.compare_digest(
            stored_digest.hexdigest(), self._digest.hexdigest()
        ):
            raise DownloadPoolError("Transfer snapshot readback did not match the copied bytes")
        if expected is not None and (
            expected["bytes"] != stored_bytes
            or not hmac.compare_digest(expected["sha256"], stored_digest.hexdigest())
        ):
            raise BackupArtifactError("Backup archive does not match its recorded identity.")
        os.lseek(self._fd, 0, os.SEEK_SET)
        self.integrity = "verified" if expected is not None else "legacy_unverified"
        return self.integrity

    def read_chunk(self) -> bytes:
        if self._fd < 0 or self.integrity is None:
            raise DownloadPoolError("Transfer snapshot is not ready")
        return os.read(self._fd, CHUNK_BYTES)

    def close(self) -> None:
        fd, slot = self._fd, self._slot
        self._fd = self._slot = -1
        try:
            if fd >= 0:
                os.close(fd)
        finally:
            # Close releases flock. Never retry a close that may have released
            # its descriptor number even when reporting an error on Linux.
            if slot >= 0:
                os.close(slot)


class DownloadPool:
    """Fail-fast disk reservations shared by processes using one configured root.

    Transfer slots have no waiter queue. Only metadata initialization/validation
    may wait, for at most one second, so available slots are not lost to a brief
    cross-process policy lock. Slot count and file-size
    policy must agree across all processes. Free-space checking is conservative;
    unrelated disk consumers may still cause I/O failure, which callers must
    recover without releasing a resource before its owned operation completes.
    """

    def __init__(self, root: Path, *, slots: int, limit: int, free_floor: int):
        if (
            any(type(value) is not int for value in (slots, limit, free_floor))
            or not 1 <= slots <= 16
            or not 1 <= limit <= MAX_BACKUP_IMPORT_BYTES
            or free_floor < 0
        ):
            raise ValueError("Invalid transfer resource limits")
        self.files = BackupFiles(root, limit)
        self.slots, self.limit, self.free_floor = slots, limit, free_floor
        self._policy = json.dumps(
            {"version": 1, "slots": slots, "limit": limit, "free_floor": free_floor}, sort_keys=True
        ).encode()

    def _configuration(self, directory: int) -> None:
        fd = os.open(
            "pool-policy.json",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        try:
            _owned_regular(fd)
            deadline = time.monotonic() + 1.0
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise DownloadCapacityError("Transfer pool is busy; retry later") from None
                    # Runs only in the owned file worker. This waits for the
                    # short metadata critical section, never for a transfer
                    # slot or client; cancellation still drains owned work.
                    time.sleep(min(0.005, remaining))
            value = os.read(fd, 4097)
            if not value:
                _write_all(fd, self._policy)
                os.fsync(fd)
                os.fsync(directory)
            elif value != self._policy:
                raise DownloadPoolError("Transfer pool configuration differs across processes")
        finally:
            os.close(fd)

    @staticmethod
    def _unlinked_snapshot(directory: int) -> int:
        if hasattr(os, "O_TMPFILE"):
            try:
                return os.open(
                    ".", os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC, 0o600, dir_fd=directory
                )
            except OSError as error:
                if error.errno not in {errno.EOPNOTSUPP, errno.EINVAL, errno.EISDIR}:
                    raise
        # Unlink before accepting any archive bytes. A failed unlink can leave
        # an empty owned file, never a secret-bearing partial snapshot.
        name = ".empty-transfer-" + uuid4().hex
        fd = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        try:
            os.unlink(name, dir_fd=directory)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def acquire(self) -> DownloadSnapshot:
        result = None
        try:
            with self.files._parent("pool-policy.json", create=True) as (directory, _):
                _disk_filesystem(directory)
                self._configuration(directory)
                for number in range(self.slots):
                    slot = os.open(
                        f"slot-{number:02d}",
                        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        0o600,
                        dir_fd=directory,
                    )
                    admitted = False
                    snapshot = -1
                    try:
                        _owned_regular(slot)
                        try:
                            fcntl.flock(slot, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            continue
                        space = os.fstatvfs(directory)
                        if (
                            space.f_bavail * space.f_frsize
                            < self.free_floor + self.slots * self.limit
                        ):
                            raise DownloadCapacityError(
                                "Insufficient free disk space for bounded transfers"
                            )
                        snapshot = self._unlinked_snapshot(directory)
                        result = DownloadSnapshot(snapshot, slot, self.limit)
                        admitted = True
                        break
                    finally:
                        if not admitted:
                            try:
                                if snapshot >= 0:
                                    os.close(snapshot)
                            finally:
                                os.close(slot)
        except BaseException:
            if result is not None:
                result.close()
            raise
        if result is not None:
            return result
        raise DownloadCapacityError("Transfer capacity is occupied; retry later")
