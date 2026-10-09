# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private, unintegrated preparation and delivery lifetime for owned artifacts.

The caller must first establish the journal reservation and current authority.
Neither an intent nor a prepared receipt proves publication, permission or a
database decision. Retirement accepts only an internal confirmed-action/decision
binding; the coordinator must obtain it from committed, coordinated observations.
It must never construct that binding from an HTTP request or an exception.

Use only an explicitly provisioned private directory on a qualified local Linux
filesystem. This does not detect or qualify NFS, SMB, container volumes or host
administrators writing as the service UID. All participating writers must use the
same persistent directory lock. Never remove its inode to "clear" a stale lock.
No old upload/delete endpoint may be enabled against these objects.

Methods are synchronous. A future async adapter must own and drain its worker
before releasing this lease on cancellation/DB connection loss. Per-call clock
checks cannot interrupt a stuck kernel syscall. Process/global quotas, crash and
backup/restore reconciliation, adoption and operator recovery remain separate.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal
from uuid import UUID

if TYPE_CHECKING:
    from _hashlib import HASH

_LIMIT = 500 * 1024 * 1024
_CHUNK = 1024 * 1024
_MARKER_LIMIT = 4096
_LEASE_SECONDS = 120.0
_SLOTS = threading.BoundedSemaphore(8)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NEW_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class ArtifactUnavailable(RuntimeError):
    """Preserve existing bytes and obtain coordinated status/operator recovery."""


class ArtifactBusy(ArtifactUnavailable):
    """Admission or a conflicting lifetime lease is currently unavailable."""


@dataclass(frozen=True)
class ArtifactIntent:
    artifact_id: UUID
    publish_operation_id: UUID
    release_id: UUID
    request_sha256: str
    payload_sha256: str
    size: int

    def encoded(self) -> bytes:
        for value in (self.artifact_id, self.publish_operation_id, self.release_id):
            if type(value) is not UUID or value.int == 0:
                raise ArtifactUnavailable("Invalid artifact identity")
        for digest in (self.request_sha256, self.payload_sha256):
            if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ArtifactUnavailable("Invalid artifact digest")
        if type(self.size) is not int or not 0 <= self.size <= _LIMIT:
            raise ArtifactUnavailable("Invalid owned artifact size")
        return _encode(
            {
                "format": 1,
                "artifact_id": str(self.artifact_id),
                "publish_operation_id": str(self.publish_operation_id),
                "release_id": str(self.release_id),
                "request_sha256": self.request_sha256,
                "payload_sha256": self.payload_sha256,
                "size": self.size,
            }
        )


@dataclass(frozen=True)
class PreparedArtifact:
    intent: ArtifactIntent
    # Local device/inode and complete observed file state, not portable identity.
    file_state: tuple[int, ...]


@dataclass(frozen=True)
class ArtifactCleanupDecision:
    """Internal association, not a signed capability or independent SQL proof."""

    intent: ArtifactIntent
    operation_id: UUID
    kind: Literal["publish", "delete"]
    decision: Literal["cancelled", "deleted"]
    retained_decision_sha256: str

    def encoded(self) -> bytes:
        intent = self.intent.encoded()
        if type(self.operation_id) is not UUID or self.operation_id.int == 0:
            raise ArtifactUnavailable("Invalid cleanup operation identity")
        if (
            type(self.retained_decision_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.retained_decision_sha256) is None
        ):
            raise ArtifactUnavailable("Invalid cleanup decision binding")
        if (self.kind, self.decision) == ("publish", "cancelled"):
            if self.operation_id != self.intent.publish_operation_id:
                raise ArtifactUnavailable("Cancellation belongs to another publication")
        elif (self.kind, self.decision) == ("delete", "deleted"):
            if self.operation_id == self.intent.publish_operation_id:
                raise ArtifactUnavailable("Deletion needs its own retained operation")
        else:
            raise ArtifactUnavailable("This action and decision cannot remove an artifact")
        return _encode(
            {
                "format": 1,
                "operation_id": str(self.operation_id),
                "kind": self.kind,
                "decision": self.decision,
                "retained_decision_sha256": self.retained_decision_sha256,
                "intent_sha256": hashlib.sha256(intent).hexdigest(),
            }
        )


@dataclass(frozen=True)
class CleanedArtifact:
    artifact_id: UUID
    operation_id: UUID
    retirement_sha256: str


def _encode(value: dict[str, object]) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(data) > _MARKER_LIMIT:
        raise ArtifactUnavailable("Artifact marker exceeds its bound")
    return data


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


def _directory(value: os.stat_result, *, private: bool) -> None:
    if not stat.S_ISDIR(value.st_mode) or value.st_uid not in (0, os.geteuid()):
        raise ArtifactUnavailable("Untrusted artifact directory")
    mode = stat.S_IMODE(value.st_mode)
    if private:
        if value.st_uid != os.geteuid() or mode != 0o700:
            raise ArtifactUnavailable("Artifact storage must be owned and private")
    elif mode & 0o022 and not (value.st_uid == 0 and mode & stat.S_ISVTX):
        raise ArtifactUnavailable("Artifact ancestor is writable by others")


def _regular(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) != 0o600
    ):
        raise ArtifactUnavailable("Artifact file must be an owned private regular file")


class ArtifactLease:
    """Own all path, lock and payload descriptors until synchronous close drains.

    Open through acquire(). Do not fork with a live lease or export its private
    descriptors. Shared leases hold delivery lifetime; exclusive leases prepare
    bytes. There is no in-place shared/exclusive conversion or lock-file removal.
    """

    _mutex: threading.RLock
    _fds: list[int]
    _links: list[tuple[int, str, int, bool]]
    _writer: int
    _reader: int
    _closed: bool
    _poisoned: bool
    _intent: ArtifactIntent
    _encoded_intent: bytes
    _exclusive: bool
    _deadline: float
    _written: int
    _digest: HASH
    _write_state: tuple[int, ...] | None
    _prepared: PreparedArtifact | None
    _object: int

    @classmethod
    def acquire(
        cls,
        root: str,
        intent: ArtifactIntent,
        *,
        mode: Literal["shared", "exclusive"],
        create: bool = False,
    ) -> ArtifactLease:
        encoded = intent.encoded()
        if (
            type(root) is not str
            or not root.startswith("/")
            or len(root) > 4096
            or len(root.split("/")) > 64
            or any(part in ("", ".", "..") for part in root.split("/")[1:])
        ):
            raise ArtifactUnavailable("Artifact root must be a bounded canonical absolute path")
        if mode not in ("shared", "exclusive") or type(create) is not bool:
            raise ArtifactUnavailable("Invalid artifact lease mode")
        if create and mode != "exclusive":
            raise ArtifactUnavailable("Creation requires an exclusive lease")
        if not _SLOTS.acquire(blocking=False):
            raise ArtifactBusy("Artifact admission is full")
        self = cls()
        self._mutex = threading.RLock()
        self._fds = []
        self._links = []
        self._writer = -1
        self._reader = -1
        self._closed = False
        self._poisoned = False
        self._intent = intent
        self._encoded_intent = encoded
        self._exclusive = mode == "exclusive"
        self._deadline = time.monotonic() + _LEASE_SECONDS
        self._written = 0
        self._digest = hashlib.sha256()
        self._write_state = None
        self._prepared = None
        try:
            parent = os.open("/", _DIR_FLAGS)
            self._fds.append(parent)
            _directory(os.fstat(parent), private=False)
            parts = root.split("/")[1:]
            for index, component in enumerate(parts):
                child = os.open(component, _DIR_FLAGS, dir_fd=parent)
                self._fds.append(child)
                private = index == len(parts) - 1
                _directory(os.fstat(child), private=private)
                self._links.append((parent, component, child, private))
                parent = child
            name = str(intent.artifact_id)
            created = False
            if create:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=parent)
                    created = True
                except FileExistsError:
                    # Existing objects need exact intent and policy; never repair.
                    created = False
            child = os.open(name, _DIR_FLAGS, dir_fd=parent)
            self._fds.append(child)
            self._links.append((parent, name, child, True))
            self._object = child
            _directory(os.fstat(child), private=True)
            try:
                operation = fcntl.LOCK_EX if self._exclusive else fcntl.LOCK_SH
                fcntl.flock(child, operation | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ArtifactBusy("Artifact lifetime is already owned") from exc
            self._check()
            if created:
                os.fsync(parent)
                self._create_marker("intent.json", encoded)
            elif not hmac.compare_digest(self._read_marker("intent.json"), encoded):
                raise ArtifactUnavailable("Artifact intent differs from the reservation")
            self._check()
            return self
        except BaseException:
            self.close()
            raise

    def _check(self) -> None:
        if self._closed or self._poisoned:
            raise ArtifactUnavailable("Artifact lease is closed or requires recovery")
        if time.monotonic() >= self._deadline:
            raise ArtifactUnavailable("Artifact lease deadline expired")
        for parent, name, child, private in self._links:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(child)
            _directory(current, private=private)
            _directory(held, private=private)
            if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                raise ArtifactUnavailable("Artifact directory identity changed")

    def _file_check(self, fd: int, name: str) -> tuple[int, ...]:
        self._check()
        held = os.fstat(fd)
        current = os.stat(name, dir_fd=self._object, follow_symlinks=False)
        _regular(held)
        _regular(current)
        if _state(held) != _state(current):
            raise ArtifactUnavailable("Artifact file identity changed")
        return _state(held)

    def _require_not_retired(self) -> None:
        for name in ("retired.json", "cleaned.json"):
            try:
                os.stat(name, dir_fd=self._object, follow_symlinks=False)
            except FileNotFoundError:
                continue
            # Even a partial/unsafe marker stops delivery and reallocation. It
            # is unavailable evidence, never permission to overwrite the marker.
            raise ArtifactUnavailable("Artifact is retired or requires recovery")

    def _write_all(self, fd: int, data: bytes) -> None:
        pending = memoryview(data)
        while pending:
            self._check()
            count = os.write(fd, pending)
            if count <= 0:
                raise ArtifactUnavailable("Artifact write did not complete")
            pending = pending[count:]

    def _create_marker(self, name: str, data: bytes) -> None:
        if not self._exclusive or len(data) > _MARKER_LIMIT:
            raise ArtifactUnavailable("Artifact marker cannot be created")
        fd = os.open(name, _NEW_FLAGS, 0o600, dir_fd=self._object)
        try:
            self._file_check(fd, name)
            self._write_all(fd, data)
            os.fsync(fd)
            state = self._file_check(fd, name)
            if state[6] != len(data):
                raise ArtifactUnavailable("Artifact marker size changed")
        finally:
            os.close(fd)
        os.fsync(self._object)

    def _read_marker(self, name: str) -> bytes:
        fd = os.open(name, _READ_FLAGS, dir_fd=self._object)
        try:
            before = self._file_check(fd, name)
            if not 0 < before[6] <= _MARKER_LIMIT:
                raise ArtifactUnavailable("Invalid artifact marker size")
            data = bytearray()
            while len(data) <= _MARKER_LIMIT:
                self._check()
                chunk = os.read(fd, _MARKER_LIMIT + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) != before[6] or self._file_check(fd, name) != before:
                raise ArtifactUnavailable("Artifact marker changed while reading")
            return bytes(data)
        finally:
            os.close(fd)

    def begin(self) -> None:
        """Exclusively allocate once; a partial object is never silently retried."""
        with self._mutex:
            self._check()
            self._require_not_retired()
            if not self._exclusive or self._writer >= 0 or self._reader >= 0:
                raise ArtifactUnavailable("Artifact lease cannot start a writer")
            try:
                # A retained prepared/allocation marker also forbids reallocation
                # if an operator removed the original payload outside this protocol.
                for name in ("allocation.json", "prepared.json"):
                    try:
                        os.stat(name, dir_fd=self._object, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise ArtifactUnavailable("Artifact allocation already exists")
                self._writer = os.open("payload", _NEW_FLAGS, 0o600, dir_fd=self._object)
                self._write_state = self._file_check(self._writer, "payload")
                os.fsync(self._writer)
                self._create_marker(
                    "allocation.json",
                    _encode(
                        {
                            "format": 1,
                            "intent_sha256": hashlib.sha256(self._encoded_intent).hexdigest(),
                            "device": self._write_state[0],
                            "inode": self._write_state[1],
                        }
                    ),
                )
            except BaseException:
                self._poisoned = True
                raise

    def append(self, chunk: bytes) -> None:
        """Write one bounded owned chunk, never an unbounded caller iterator."""
        with self._mutex:
            self._check()
            if self._writer < 0:
                raise ArtifactUnavailable("Artifact writer is not active")
            try:
                if type(chunk) is not bytes or not 0 < len(chunk) <= _CHUNK:
                    raise ArtifactUnavailable("Artifact chunk has invalid type or size")
                if len(chunk) > self._intent.size - self._written:
                    raise ArtifactUnavailable("Artifact exceeds its declared size")
                if self._file_check(self._writer, "payload") != self._write_state:
                    raise ArtifactUnavailable("Artifact changed before writing")
                self._write_all(self._writer, chunk)
                self._written += len(chunk)
                self._digest.update(chunk)
                self._write_state = self._file_check(self._writer, "payload")
                if self._write_state[6] != self._written:
                    raise ArtifactUnavailable("Artifact size changed during writing")
            except BaseException:
                self._poisoned = True
                raise

    def finish(self) -> PreparedArtifact:
        """Synchronize exact bytes and a receipt; this is not SQL publication."""
        with self._mutex:
            self._check()
            if self._writer < 0:
                raise ArtifactUnavailable("Artifact writer is not active")
            try:
                if self._written != self._intent.size or not hmac.compare_digest(
                    self._digest.hexdigest(), self._intent.payload_sha256
                ):
                    raise ArtifactUnavailable("Artifact differs from its declared size or digest")
                if self._file_check(self._writer, "payload") != self._write_state:
                    raise ArtifactUnavailable("Artifact changed before synchronization")
                os.fsync(self._writer)
                file_state = self._file_check(self._writer, "payload")
                self._create_marker(
                    "prepared.json",
                    _encode(
                        {
                            "format": 1,
                            "intent_sha256": hashlib.sha256(self._encoded_intent).hexdigest(),
                            "file_state": file_state,
                        }
                    ),
                )
                fd, self._writer = self._writer, -1
                os.close(fd)
                # Read back actual stored bytes, not merely the submitted stream hash.
                return self.verify_prepared()
            except BaseException:
                self._poisoned = True
                raise

    def verify_prepared(self) -> PreparedArtifact:
        """Recheck the complete bounded file and hold its delivery descriptor."""
        with self._mutex:
            self._check()
            if self._writer >= 0:
                raise ArtifactUnavailable("Artifact writer has not finished")
            # Any later verification failure invalidates an earlier delivery grant.
            self._prepared = None
            self._require_not_retired()
            if not hmac.compare_digest(self._read_marker("intent.json"), self._encoded_intent):
                raise ArtifactUnavailable("Artifact intent changed")
            raw = self._read_marker("prepared.json")
            try:
                value = json.loads(raw)
                state = value["file_state"]
                if (
                    type(value) is not dict
                    or type(state) is not list
                    or len(state) != 9
                    or any(type(item) is not int or item < 0 for item in state)
                ):
                    raise ValueError
                expected = _encode(
                    {
                        "format": 1,
                        "intent_sha256": hashlib.sha256(self._encoded_intent).hexdigest(),
                        "file_state": state,
                    }
                )
                if not hmac.compare_digest(raw, expected):
                    raise ValueError
            except (ValueError, TypeError, KeyError) as exc:
                raise ArtifactUnavailable("Invalid prepared artifact receipt") from exc
            if self._reader < 0:
                self._reader = os.open("payload", _READ_FLAGS, dir_fd=self._object)
            before = self._file_check(self._reader, "payload")
            if before != tuple(state) or before[6] != self._intent.size:
                raise ArtifactUnavailable("Prepared artifact identity changed")
            allocation = _encode(
                {
                    "format": 1,
                    "intent_sha256": hashlib.sha256(self._encoded_intent).hexdigest(),
                    "device": before[0],
                    "inode": before[1],
                }
            )
            if not hmac.compare_digest(self._read_marker("allocation.json"), allocation):
                raise ArtifactUnavailable("Artifact allocation differs")
            digest = hashlib.sha256()
            offset = 0
            while offset < self._intent.size:
                self._check()
                chunk = os.pread(self._reader, min(_CHUNK, self._intent.size - offset), offset)
                if not chunk:
                    raise ArtifactUnavailable("Prepared artifact was truncated")
                digest.update(chunk)
                offset += len(chunk)
            if (
                os.pread(self._reader, 1, offset)
                or not hmac.compare_digest(digest.hexdigest(), self._intent.payload_sha256)
                or self._file_check(self._reader, "payload") != before
            ):
                raise ArtifactUnavailable("Prepared artifact bytes changed")
            # A successful recovery cannot rely on a marker left after failed fsync.
            os.fsync(self._reader)
            for name in ("intent.json", "allocation.json", "prepared.json"):
                fd = os.open(name, _READ_FLAGS, dir_fd=self._object)
                try:
                    self._file_check(fd, name)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(self._object)
            os.fsync(self._links[-1][0])
            self._check()
            self._prepared = PreparedArtifact(self._intent, before)
            return self._prepared

    def read(self, offset: int, size: int) -> bytes:
        """Read under the retained lifetime lock; never return a raw descriptor."""
        with self._mutex:
            self._check()
            self._require_not_retired()
            if self._prepared is None or self._reader < 0:
                raise ArtifactUnavailable("Artifact must be fully verified before delivery")
            if (
                type(offset) is not int
                or type(size) is not int
                or offset < 0
                or not 1 <= size <= _CHUNK
                or offset > self._intent.size
            ):
                raise ArtifactUnavailable("Invalid artifact read bounds")
            expected = self._prepared.file_state
            if self._file_check(self._reader, "payload") != expected:
                raise ArtifactUnavailable("Artifact changed before delivery")
            size = min(size, self._intent.size - offset)
            data = os.pread(self._reader, size, offset)
            if len(data) != size or self._file_check(self._reader, "payload") != expected:
                raise ArtifactUnavailable("Artifact changed during delivery")
            return data

    def _cleanup_binding(self, decision: ArtifactCleanupDecision) -> bytes:
        self._check()
        if (
            type(decision) is not ArtifactCleanupDecision
            or decision.intent != self._intent
            or not self._exclusive
            or self._writer >= 0
        ):
            raise ArtifactUnavailable("Cleanup requires its exact exclusive operation lifetime")
        encoded = decision.encoded()
        if not hmac.compare_digest(self._read_marker("intent.json"), self._encoded_intent):
            raise ArtifactUnavailable("Artifact intent changed before retirement")
        self._prepared = None
        return encoded

    def _retired(self, decision_bytes: bytes) -> tuple[bytes, tuple[int, ...] | None]:
        raw = self._read_marker("retired.json")
        try:
            value = json.loads(raw)
            state = value["file_state"]
            if state is not None and (
                type(state) is not list
                or len(state) != 9
                or any(type(item) is not int or item < 0 for item in state)
            ):
                raise ValueError
            expected = _encode(
                {
                    "format": 1,
                    "cleanup_sha256": hashlib.sha256(decision_bytes).hexdigest(),
                    "file_state": state,
                }
            )
            if not hmac.compare_digest(raw, expected):
                raise ValueError
        except (ValueError, TypeError, KeyError) as exc:
            raise ArtifactUnavailable("Retirement belongs to another object or decision") from exc
        return raw, tuple(state) if state is not None else None

    def _sync_exact_marker(self, name: str, expected: bytes) -> None:
        if not hmac.compare_digest(self._read_marker(name), expected):
            raise ArtifactUnavailable("Artifact recovery marker changed")
        fd = os.open(name, _READ_FLAGS, dir_fd=self._object)
        try:
            before = self._file_check(fd, name)
            os.fsync(fd)
            if self._file_check(fd, name) != before:
                raise ArtifactUnavailable("Artifact recovery marker changed during synchronization")
        finally:
            os.close(fd)
        os.fsync(self._object)
        os.fsync(self._links[-1][0])
        self._check()

    def retire(self, decision: ArtifactCleanupDecision) -> str:
        """Durably fence delivery before cleanup; preserve the payload in this phase.

        The caller already owns a confirmed SQL decision and absence of any live
        reference under the release coordinator. An unavailable/ambiguous SQL
        response must not be converted to an ArtifactCleanupDecision.
        """
        with self._mutex:
            binding = self._cleanup_binding(decision)
            try:
                raw, _ = self._retired(binding)
            except FileNotFoundError:
                try:
                    os.stat("cleaned.json", dir_fd=self._object, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ArtifactUnavailable("Cleanup history has no retirement record") from None
                state = None
                if decision.kind == "delete":
                    state = self.verify_prepared().file_state
                else:
                    try:
                        fd = os.open("payload", _READ_FLAGS, dir_fd=self._object)
                    except FileNotFoundError:
                        # Intent-only cancellation is safe to record, but a lost
                        # allocated/prepared object needs independent reconciliation.
                        for name in ("allocation.json", "prepared.json"):
                            try:
                                os.stat(name, dir_fd=self._object, follow_symlinks=False)
                            except FileNotFoundError:
                                continue
                            raise ArtifactUnavailable(
                                "Allocated artifact is missing without retirement"
                            ) from None
                    else:
                        try:
                            state = self._file_check(fd, "payload")
                            if state[6] > self._intent.size:
                                raise ArtifactUnavailable(
                                    "Partial artifact exceeds its reservation"
                                )
                            expected = _encode(
                                {
                                    "format": 1,
                                    "intent_sha256": hashlib.sha256(
                                        self._encoded_intent
                                    ).hexdigest(),
                                    "device": state[0],
                                    "inode": state[1],
                                }
                            )
                            if not hmac.compare_digest(
                                self._read_marker("allocation.json"), expected
                            ):
                                raise ArtifactUnavailable("Partial artifact allocation differs")
                            os.fsync(fd)
                            if self._file_check(fd, "payload") != state:
                                raise ArtifactUnavailable(
                                    "Partial artifact changed during retirement"
                                )
                        finally:
                            os.close(fd)
                raw = _encode(
                    {
                        "format": 1,
                        "cleanup_sha256": hashlib.sha256(binding).hexdigest(),
                        "file_state": state,
                    }
                )
                self._create_marker("retired.json", raw)
            self._sync_exact_marker("retired.json", raw)
            self._prepared = None
            return hashlib.sha256(raw).hexdigest()

    def cleanup_retired(self, decision: ArtifactCleanupDecision) -> CleanedArtifact:
        """Remove only the recorded payload; retain lock inode and all history.

        An unlink or fsync error is not rolled back and never recreates a binary.
        A later authorized retry verifies the same retirement. Missing bytes may
        finish bookkeeping; any replacement bytes are preserved and refused.
        """
        with self._mutex:
            binding = self._cleanup_binding(decision)
            raw, state = self._retired(binding)
            self._sync_exact_marker("retired.json", raw)
            expected = _encode({"format": 1, "retirement_sha256": hashlib.sha256(raw).hexdigest()})
            try:
                cleaned = self._read_marker("cleaned.json")
            except FileNotFoundError:
                cleaned = None
            if cleaned is not None and not hmac.compare_digest(cleaned, expected):
                raise ArtifactUnavailable("Cleanup marker differs from retirement")
            try:
                fd = os.open("payload", _READ_FLAGS, dir_fd=self._object)
            except FileNotFoundError:
                fd = -1
            if fd >= 0:
                try:
                    current = self._file_check(fd, "payload")
                    if cleaned is not None or state is None or current != state:
                        raise ArtifactUnavailable("Refusing to remove a replacement artifact")
                    self._check()
                    os.unlink("payload", dir_fd=self._object)
                finally:
                    os.close(fd)
            # Retirees retain metadata forever until a separate reviewed archival
            # protocol can account for every reference and pending operation.
            os.fsync(self._object)
            if cleaned is None:
                self._create_marker("cleaned.json", expected)
            self._sync_exact_marker("cleaned.json", expected)
            self._prepared = None
            return CleanedArtifact(
                self._intent.artifact_id, decision.operation_id, hashlib.sha256(raw).hexdigest()
            )

    def close(self) -> None:
        # A worker already inside a method retains this mutex and all descriptors.
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            error = None
            for fd in (self._writer, self._reader, *reversed(self._fds)):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError as exc:
                        error = exc
            self._writer = self._reader = -1
            self._fds.clear()
            _SLOTS.release()
            if error is not None:
                raise ArtifactUnavailable("Artifact descriptor closure requires review") from error

    def __enter__(self) -> ArtifactLease:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
