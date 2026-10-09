# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Provision one new managed-artifact directory without adopting legacy data.

The parent must already exist. Existing roots must have our exact marker and
private ownership/modes; this function never repairs, chmods, empties, or adopts
them. A failed creation is retained for explicit operator investigation. The
parent directory inode is the startup lock: concurrent cooperating workers must
not unlink/replace it to clear contention.

This is local Linux filesystem policy, not NFS/SMB or host-administrator
qualification. The lock wait is bounded; a kernel filesystem syscall itself
cannot be interrupted by that bound. The returned observation is not a lease:
artifact operations must still validate and lock their current descriptors.
"""

from __future__ import annotations

import fcntl
import os
import stat
import time
from contextlib import ExitStack
from dataclasses import dataclass

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_MARKER_NAME = ".freesdn-managed-artifacts-v1"
_MARKER = b'{"format":1,"purpose":"freesdn-managed-agent-artifacts"}\n'
_LOCK_SECONDS = 5.0


class ReleaseStorageUnavailable(RuntimeError):
    """Safe public reason; raw OS errors and paths must not reach HTTP clients."""


@dataclass(frozen=True)
class ReleaseStorageObservation:
    root: str
    device: int
    inode: int
    created: bool


def canonical_release_storage_path(root: str) -> tuple[str, ...]:
    """Check without filesystem access, resolution, expansion, or normalization."""
    if type(root) is not str or not root.startswith("/") or "\0" in root:
        raise ReleaseStorageUnavailable("Managed storage needs a canonical absolute path")
    try:
        encoded = root.encode("utf-8", errors="strict")
        parts = tuple(root.split("/")[1:])
        valid = (
            len(encoded) <= 4096
            and 1 <= len(parts) <= 63
            and all(part not in ("", ".", "..") and len(part.encode()) <= 255 for part in parts)
        )
    except UnicodeError:
        valid = False
    if not valid:
        raise ReleaseStorageUnavailable("Managed storage needs a bounded canonical path")
    return parts


def _directory(value: os.stat_result, *, private: bool) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid not in (0, os.geteuid()):
        raise ReleaseStorageUnavailable("Managed storage has an untrusted directory")
    if private:
        if value.st_uid != os.geteuid() or mode != 0o700:
            raise ReleaseStorageUnavailable("Managed storage must be owned and private")
    elif mode & 0o022 and not (value.st_uid == 0 and mode & stat.S_ISVTX):
        raise ReleaseStorageUnavailable("Managed storage ancestor is writable by others")


def _marker_file(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_size != len(_MARKER)
    ):
        raise ReleaseStorageUnavailable("Managed storage marker is not trusted")


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _marker_state(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _check_links(links: list[tuple[int, str, int, bool]]) -> None:
    for parent, name, descriptor, private in links:
        current = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _directory(current, private=private)
        _directory(linked, private=private)
        if _identity(current) != _identity(linked):
            raise ReleaseStorageUnavailable("Managed storage path changed during startup")


def initialize_release_storage_root(
    root: str,
    *,
    lock_seconds: float = _LOCK_SECONDS,
) -> ReleaseStorageObservation:
    """Create only a missing final directory, or verify an already marked one.

    No database, signing identity, caller transaction, or old release file is
    changed. The parent lock is acquired before creation, so another worker
    cannot mistake our in-progress marker write for an unmarked existing root.
    """
    parts = canonical_release_storage_path(root)
    if type(lock_seconds) not in (int, float) or not 0 <= lock_seconds <= _LOCK_SECONDS:
        raise ReleaseStorageUnavailable("Invalid managed storage startup wait")
    try:
        with ExitStack() as resources:

            def opened(
                name: str, flags: int, *, parent: int | None = None, mode: int = 0o600
            ) -> int:
                descriptor = os.open(name, flags, mode, dir_fd=parent)
                resources.callback(os.close, descriptor)
                return descriptor

            parent = opened("/", _DIRECTORY_FLAGS)
            _directory(os.fstat(parent), private=False)
            links: list[tuple[int, str, int, bool]] = []
            for name in parts[:-1]:
                child = opened(name, _DIRECTORY_FLAGS, parent=parent)
                _directory(os.fstat(child), private=False)
                links.append((parent, name, child, False))
                parent = child

            deadline = time.monotonic() + lock_seconds
            while True:
                try:
                    fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ReleaseStorageUnavailable("Managed storage startup is busy") from None
                    time.sleep(min(0.025, remaining))
            _check_links(links)

            created = False
            try:
                os.mkdir(parts[-1], mode=0o700, dir_fd=parent)
                created = True
            except FileExistsError:
                pass
            directory = opened(parts[-1], _DIRECTORY_FLAGS, parent=parent)
            _directory(os.fstat(directory), private=True)
            links.append((parent, parts[-1], directory, True))
            _check_links(links)

            if created:
                marker = opened(_MARKER_NAME, _CREATE_FLAGS, parent=directory)
                pending = memoryview(_MARKER)
                while pending:
                    written = os.write(marker, pending)
                    if written <= 0:
                        raise ReleaseStorageUnavailable(
                            "Managed storage marker write did not finish"
                        )
                    pending = pending[written:]
                os.fsync(marker)
            # Reopen read-only, including on creation; never truncate or repair.
            marker = opened(_MARKER_NAME, _READ_FLAGS, parent=directory)
            before = os.fstat(marker)
            _marker_file(before)
            if os.read(marker, len(_MARKER) + 1) != _MARKER:
                raise ReleaseStorageUnavailable("Managed storage marker has another purpose")
            after = os.fstat(marker)
            linked = os.stat(_MARKER_NAME, dir_fd=directory, follow_symlinks=False)
            if _marker_state(before) != _marker_state(after) or _marker_state(
                after
            ) != _marker_state(linked):
                raise ReleaseStorageUnavailable("Managed storage marker changed during startup")
            _check_links(links)
            # Persist the verified directory entry, including after another
            # worker/crash left a complete marker before its directory fsync.
            os.fsync(marker)
            os.fsync(directory)
            os.fsync(parent)
            current = os.fstat(directory)
            return ReleaseStorageObservation(root, current.st_dev, current.st_ino, created)
    except OSError as exc:
        raise ReleaseStorageUnavailable(
            "Managed storage is unavailable; existing data was preserved"
        ) from exc
