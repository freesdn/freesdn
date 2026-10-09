# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Read-only compatibility lifetime for pre-journal local release files.

The caller must separately verify current authority, the exact database row,
absence of managed publication history and the release signature policy before
and after I/O. A matching checksum is not publication provenance or permission.
No file, directory, marker or database record is created, repaired or adopted.

Existing regular files may retain their old read/execute modes. They and their
directories must have a trusted owner and not be writable by other users. All
components are opened relative to retained descriptors without following links.
The size and SHA-256 are verified before any read is exposed to the caller.

This is local Linux behavior, not NFS/SMB or hostile service-UID/administrator
protection. The advisory shared file lock excludes only cooperating writers.
Observed pathname, metadata or byte changes invalidate the lifetime; changes
after a chunk was handed to a network cannot recall that chunk. A deadline does
not interrupt a stuck kernel call. Async callers must own and drain workers.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import re
import stat
import threading
import time
from dataclasses import dataclass
from uuid import UUID

from app.core.agent_release_storage_root import canonical_release_storage_path

_MAX_SIZE = 500 * 1024 * 1024
_CHUNK = 1024 * 1024
_DIRECTORY_ENTRY_LIMIT = 10000
_LIFETIME_SECONDS = 120
_SLOTS = threading.BoundedSemaphore(8)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class LegacyReleaseUnavailable(RuntimeError):
    """A safe error; keep original files and investigate metadata/storage."""


@dataclass(frozen=True)
class LegacyReleaseFile:
    release_id: UUID
    filename: str | None
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not isinstance(self.release_id, UUID) or not self.release_id.int:
            raise LegacyReleaseUnavailable("Invalid legacy release identity")
        object.__setattr__(self, "release_id", UUID(bytes=self.release_id.bytes))
        if self.filename is not None and not _filename(self.filename):
            raise LegacyReleaseUnavailable("Legacy filename needs explicit correction")
        if type(self.sha256) is not str or re.fullmatch(r"[a-fA-F0-9]{64}", self.sha256) is None:
            raise LegacyReleaseUnavailable("Legacy release needs a recorded checksum")
        if type(self.size) is not int or not 0 <= self.size <= _MAX_SIZE:
            raise LegacyReleaseUnavailable("Legacy release needs a bounded recorded size")


@dataclass(frozen=True)
class VerifiedLegacyFile:
    expected: LegacyReleaseFile
    filename: str
    file_state: tuple[int, ...]


def _filename(value: object) -> bool:
    # Old uploads used this exact sanitization alphabet and 128-character cap.
    return (
        type(value) is str
        and value not in (".", "..")
        and re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", value) is not None
    )


def _state(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory(value: os.stat_result, *, ancestor: bool) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid not in (0, os.geteuid())
        or mode & 0o022
        and not (ancestor and value.st_uid == 0 and mode & stat.S_ISVTX)
    ):
        raise LegacyReleaseUnavailable("Legacy release directory is not trusted")


def _regular(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid not in (0, os.geteuid())
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) & 0o022
    ):
        raise LegacyReleaseUnavailable("Legacy release is not a trusted regular file")


class LegacyReleaseLease:
    """Retain verified read-only descriptors; close after the actual response.

    No raw descriptor or pathname is returned. A filename-null legacy row must
    have exactly one matching, bounded candidate. The directory scan is limited
    to 10,000 entries. Any directory change invalidates that inferred selection;
    an unrelated concurrent upload may therefore require a new request. Rows
    with an explicit filename do not scan the directory.
    """

    _mutex: threading.RLock
    _fds: list[int]
    _links: list[tuple[int, str, int, bool]]
    _closed: bool
    _failed: bool
    _deadline: float
    _expected: LegacyReleaseFile
    _reader: int
    _verified: VerifiedLegacyFile | None
    _scan_state: tuple[int, ...] | None
    _root: int
    _name: str

    @classmethod
    def acquire(cls, root: str, expected: LegacyReleaseFile) -> LegacyReleaseLease:
        parts = canonical_release_storage_path(root)
        if type(expected) is not LegacyReleaseFile:
            raise LegacyReleaseUnavailable("Validated legacy file metadata required")
        if not _SLOTS.acquire(blocking=False):
            raise LegacyReleaseUnavailable("Legacy release readers are busy")
        self = cls()
        self._mutex = threading.RLock()
        self._fds = []
        self._links = []
        self._closed = False
        self._failed = False
        self._deadline = time.monotonic() + _LIFETIME_SECONDS
        self._expected = expected
        self._reader = -1
        self._verified = None
        self._scan_state = None
        try:
            parent = os.open("/", _DIRECTORY_FLAGS)
            self._fds.append(parent)
            _directory(os.fstat(parent), ancestor=True)
            for i, name in enumerate(parts):
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
                self._fds.append(child)
                ancestor = i < len(parts) - 1
                _directory(os.fstat(child), ancestor=ancestor)
                self._links.append((parent, name, child, ancestor))
                parent = child
            self._root = parent
            self._check()
            prefix = str(expected.release_id) + "-"
            filename = expected.filename
            if filename is None:
                before = _state(os.fstat(parent))
                found = []
                with os.scandir(parent) as entries:
                    for count, entry in enumerate(entries, 1):
                        self._check()
                        if count > _DIRECTORY_ENTRY_LIMIT:
                            raise LegacyReleaseUnavailable(
                                "Legacy directory scan needs explicit filename metadata"
                            )
                        if entry.name.startswith(prefix):
                            candidate = entry.name[len(prefix) :]
                            if not _filename(candidate):
                                raise LegacyReleaseUnavailable(
                                    "Legacy release has an invalid candidate filename"
                                )
                            found.append(candidate)
                            if len(found) > 1:
                                raise LegacyReleaseUnavailable("Legacy release has ambiguous files")
                if len(found) != 1 or _state(os.fstat(parent)) != before:
                    raise LegacyReleaseUnavailable("Legacy file selection is absent or changed")
                filename = found[0]
                self._scan_state = before
            self._name = prefix + filename
            self._reader = os.open(self._name, _READ_FLAGS, dir_fd=parent)
            self._fds.append(self._reader)
            _regular(os.fstat(self._reader))
            fcntl.flock(self._reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
            before = self._file_state()
            if before[6] != expected.size:
                raise LegacyReleaseUnavailable("Legacy release size differs from its record")
            digest = hashlib.sha256()
            offset = 0
            while offset < expected.size:
                self._check()
                chunk = os.pread(self._reader, min(_CHUNK, expected.size - offset), offset)
                if not chunk:
                    raise LegacyReleaseUnavailable("Legacy release ended during verification")
                digest.update(chunk)
                offset += len(chunk)
            if (
                os.pread(self._reader, 1, offset)
                or self._file_state() != before
                or not hmac.compare_digest(digest.hexdigest(), expected.sha256.lower())
            ):
                raise LegacyReleaseUnavailable("Legacy release bytes differ from its record")
            self._check()
            self._verified = VerifiedLegacyFile(expected, filename, before)
            return self
        except BaseException:
            self.close()
            raise

    def _check(self) -> None:
        if self._closed or self._failed or time.monotonic() >= self._deadline:
            raise LegacyReleaseUnavailable("Legacy release lifetime is unavailable")
        for parent, name, descriptor, ancestor in self._links:
            held = os.fstat(descriptor)
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _directory(held, ancestor=ancestor)
            _directory(linked, ancestor=ancestor)
            if (held.st_dev, held.st_ino) != (linked.st_dev, linked.st_ino):
                raise LegacyReleaseUnavailable("Legacy release directory changed")
        if self._scan_state is not None and _state(os.fstat(self._root)) != self._scan_state:
            raise LegacyReleaseUnavailable("Legacy filename selection changed")

    def _file_state(self) -> tuple[int, ...]:
        self._check()
        held = os.fstat(self._reader)
        linked = os.stat(self._name, dir_fd=self._root, follow_symlinks=False)
        _regular(held)
        _regular(linked)
        if _state(held) != _state(linked):
            raise LegacyReleaseUnavailable("Legacy release file changed")
        return _state(held)

    @property
    def verified(self) -> VerifiedLegacyFile:
        with self._mutex:
            try:
                if self._verified is None or self._file_state() != self._verified.file_state:
                    raise LegacyReleaseUnavailable("Legacy release has no current verified file")
                return self._verified
            except BaseException:
                self._failed = True
                raise

    def read(self, offset: int, size: int) -> bytes:
        with self._mutex:
            try:
                checked = self.verified
                if (
                    type(offset) is not int
                    or type(size) is not int
                    or not 0 <= offset <= checked.expected.size
                    or not 1 <= size <= _CHUNK
                ):
                    raise LegacyReleaseUnavailable("Invalid bounded legacy release read")
                count = min(size, checked.expected.size - offset)
                data = os.pread(self._reader, count, offset)
                if len(data) != count or self._file_state() != checked.file_state:
                    raise LegacyReleaseUnavailable("Legacy release changed during reading")
                return data
            except BaseException:
                self._failed = True
                raise

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            error = None
            for descriptor in reversed(self._fds):
                try:
                    os.close(descriptor)
                except OSError as exc:
                    error = error or exc
            self._fds.clear()
            _SLOTS.release()
            if error is not None:
                raise error

    def __enter__(self) -> LegacyReleaseLease:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
