# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Descriptor-based private files for the Linux appliance runtime.

No symlink traversal, no replacement on create, no special/hard-linked files.
Root-owned sticky temporary ancestors are permitted; application directories
must belong to the process user and must not be writable by other users.
Existing owner-only-writable files/directories have read permissions tightened.
This does not isolate mutually untrusted processes sharing the application UID.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO


class PrivateFileError(OSError):
    """Unsafe or unsupported filesystem state; never contains file contents."""


@contextmanager
def private_directory(path: Path, *, create: bool = True) -> Iterator[int]:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise PrivateFileError("Private storage requires POSIX descriptor support")
    path = path.absolute()
    if ".." in path.parts:
        raise PrivateFileError("Invalid storage path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for index, part in enumerate(path.parts[1:]):
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            leaf = index == len(path.parts) - 2
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (
                info.st_mode & 0o022 and not (sticky_root and not leaf)
            ):
                raise PrivateFileError("Storage ancestor has unsafe ownership or permissions")
            if leaf:
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise PrivateFileError("Private directory has unsafe ownership or permissions")
                os.fchmod(fd, 0o700)
        if path == Path(path.anchor):
            raise PrivateFileError("Filesystem root is not private storage")
        yield fd
    finally:
        os.close(fd)


def create_private(path: Path) -> BinaryIO:
    with private_directory(path.parent) as directory:
        fd = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
    return os.fdopen(fd, "wb")


def write_private(path: Path, data: bytes) -> None:
    with create_private(path) as handle:
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            unlink_private(path)
            raise


def open_private(path: Path, limit: int) -> BinaryIO:
    with private_directory(path.parent, create=False) as directory:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
            or info.st_size > limit
        ):
            raise PrivateFileError("Stored file metadata is unsafe or exceeds its size limit")
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_private(path: Path, limit: int) -> bytes:
    with open_private(path, limit) as handle:
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise PrivateFileError("Stored file exceeds its size limit")
        return data


def unlink_private(path: Path) -> None:
    try:
        with private_directory(path.parent, create=False) as directory:
            # unlink removes the entry itself; it never follows a final symlink.
            os.unlink(path.name, dir_fd=directory)
    except FileNotFoundError:
        pass


def touch_private(path: Path) -> None:
    """Update a liveness marker without following links or truncating any file."""
    # The legacy heartbeat is in /tmp directly, not a private directory. Open
    # its parent without changing parent permissions, then validate the inode.
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise PrivateFileError("Private storage requires POSIX descriptor support")
    parent = path.parent.absolute()
    # The default /tmp parent is root-owned/sticky; configured private parents
    # use the same checked traversal as every other application storage path.
    if parent == Path("/tmp"):
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(directory)
        if info.st_uid != 0 or not info.st_mode & stat.S_ISVTX:
            os.close(directory)
            raise PrivateFileError("Unsafe heartbeat directory")
        try:
            _touch_at(directory, path.name)
        finally:
            os.close(directory)
    else:
        with private_directory(parent) as directory:
            _touch_at(directory, path.name)


def _touch_at(directory: int, name: str) -> None:
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise PrivateFileError("Unsafe heartbeat file")
        os.fchmod(fd, 0o600)
        os.utime(fd)
    finally:
        os.close(fd)
