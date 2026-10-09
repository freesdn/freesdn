# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded, descriptor-relative archive files on the Linux appliance.

Application processes sharing the UID or primary group are trusted writers.
This is not isolation from those processes or from a privileged administrator.
Existing modes are inspected, never tightened implicitly. New files are 0600.
Local filesystem behavior does not establish NFS mount or durability guarantees.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from uuid import uuid4


class BackupFileError(OSError):
    """An unsafe archive path, inode or bounded I/O operation."""


class BackupPublicationError(BackupFileError):
    """A complete destination exists but the operation could not acknowledge it."""

    def __init__(self, storage_path: str):
        super().__init__("Archive publication could not be confirmed")
        self.storage_path = storage_path


class BackupFiles:
    """Use a pinned directory descriptor for each complete file operation."""

    def __init__(self, root: Path, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("Invalid archive size limit")
        self.root = root.absolute()
        if ".." in self.root.parts or self.root == Path(self.root.anchor):
            raise BackupFileError("Invalid archive root")
        self.limit = limit

    @staticmethod
    def _parts(path: str) -> tuple[str, ...]:
        if not isinstance(path, str) or not path or "\x00" in path:
            raise BackupFileError("Invalid archive path")
        parts = path.split("/")
        if PurePosixPath(path).is_absolute() or any(p in ("", ".", "..") for p in parts):
            raise BackupFileError("Archive path must be relative and canonical")
        return tuple(parts)

    @staticmethod
    def _directory_policy(fd: int, *, ancestor: bool = False) -> None:
        info = os.fstat(fd)
        sticky_root = ancestor and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        trusted_group = info.st_gid == os.getegid()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or (info.st_mode & 0o002 and not sticky_root)
            or (info.st_mode & 0o020 and not trusted_group and not sticky_root)
        ):
            raise BackupFileError("Archive directory has unsupported ownership or permissions")

    @contextmanager
    def _parent(self, path: str, *, create: bool = False) -> Iterator[tuple[int, str]]:
        parts = self._parts(path)
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise BackupFileError("Archive storage requires POSIX descriptor support")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(self.root.anchor, flags)
        try:
            self._directory_policy(fd, ancestor=True)
            root_parts = self.root.parts[1:]
            traversal = root_parts + parts[:-1]
            for index, part in enumerate(traversal):
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                    child = os.open(part, flags, dir_fd=fd)
                try:
                    self._directory_policy(child, ancestor=index < len(root_parts) - 1)
                except BaseException:
                    os.close(child)
                    raise
                # Transfer ownership before close: on Linux a close error can
                # still release the old number. Never retry it or leak the child.
                closing = fd
                fd = child
                os.close(closing)
            yield fd, parts[-1]
        finally:
            os.close(fd)

    @staticmethod
    def _file_policy(info: os.stat_result) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o002
            or (info.st_mode & 0o020 and info.st_gid != os.getegid())
        ):
            raise BackupFileError("Archive inode has unsupported type, aliases or permissions")

    @contextmanager
    def _read_fd(self, directory: int, name: str) -> Iterator[int]:
        # NONBLOCK prevents a FIFO from blocking before fstat can refuse it.
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
        )
        try:
            self._file_policy(os.fstat(fd))
            yield fd
        finally:
            os.close(fd)

    def load(self, path: str) -> bytes:
        with self._parent(path) as (directory, name), self._read_fd(directory, name) as fd:
            before = os.fstat(fd)
            if before.st_size > self.limit:
                raise BackupFileError("Archive exceeds its size limit")
            data = bytearray()
            while True:
                chunk = os.read(fd, min(64 * 1024, self.limit - len(data) + 1))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > self.limit:
                    raise BackupFileError("Archive exceeds its size limit")
            after = os.fstat(fd)
            self._file_policy(after)
            if (
                len(data) != before.st_size
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns
            ):
                raise BackupFileError("Archive changed while being read")
            return bytes(data)

    def save(self, path: str, data: bytes) -> str:
        if not isinstance(data, bytes) or len(data) > self.limit:
            raise BackupFileError("Archive payload is invalid or exceeds its size limit")
        published = False
        try:
            with self._parent(path, create=True) as (directory, name):
                try:
                    self._file_policy(os.stat(name, dir_fd=directory, follow_symlinks=False))
                except FileNotFoundError:
                    pass
                temporary = ".freesdn-archive-" + uuid4().hex + ".tmp"
                fd = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=directory,
                )
                owned = None
                try:
                    owned = os.fstat(fd)
                    view = memoryview(data)
                    offset = 0
                    while offset < len(view):
                        written = os.write(fd, view[offset : offset + 64 * 1024])
                        if written < 1:
                            raise BackupFileError("Archive write made no progress")
                        offset += written
                    self._file_policy(os.fstat(fd))
                    os.fsync(fd)
                    closing = fd
                    fd = -1
                    os.close(closing)
                    # Never follow or silently replace a pre-existing alias. Names
                    # remain controlled by trusted writers; this is not a same-UID
                    # adversary boundary or a compare-and-swap filesystem primitive.
                    try:
                        self._file_policy(os.stat(name, dir_fd=directory, follow_symlinks=False))
                    except FileNotFoundError:
                        pass
                    current = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino):
                        raise BackupFileError("Temporary archive identity changed")
                    self._file_policy(current)
                    os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                    published = True
                    # A failure here reports an uncertain durable publication. Do
                    # not delete the complete destination or claim rollback.
                    os.fsync(directory)
                finally:
                    try:
                        if fd != -1:
                            os.close(fd)
                    finally:
                        if not published:
                            try:
                                current = os.stat(
                                    temporary, dir_fd=directory, follow_symlinks=False
                                )
                                if owned is not None and (current.st_dev, current.st_ino) == (
                                    owned.st_dev,
                                    owned.st_ino,
                                ):
                                    os.unlink(temporary, dir_fd=directory)
                            except FileNotFoundError:
                                pass
        except OSError as error:
            if published:
                raise BackupPublicationError(path) from error
            raise
        return path

    def delete(self, path: str) -> bool:
        try:
            with self._parent(path) as (directory, name):
                self._file_policy(os.stat(name, dir_fd=directory, follow_symlinks=False))
                os.unlink(name, dir_fd=directory)
                os.fsync(directory)
        except FileNotFoundError:
            pass
        return True

    def exists(self, path: str) -> bool:
        try:
            with self._parent(path) as (directory, name):
                self._file_policy(os.stat(name, dir_fd=directory, follow_symlinks=False))
        except FileNotFoundError:
            return False
        return True

    def get_size(self, path: str) -> int:
        with self._parent(path) as (directory, name):
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            self._file_policy(info)
            return info.st_size
