# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded command and regular-file I/O for the offline migration operator.

Blocking file operations run in a supervised worker, not the pipe supervisor.
This is not containment of an untrusted Docker administrator or filesystem.
"""
from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import math
import os
import stat
import sys
import time
from pathlib import Path

from qualification.bounded_command import CommandBoundaryError, capture_command

MIB = 1024**2
GIB = 1024**3


@dataclasses.dataclass(frozen=True)
class IOPolicy:
    capture_bytes: int = 4 * MIB
    input_bytes: int = 16 * MIB
    file_bytes: int = 64 * GIB
    workspace_bytes: int = 128 * GIB
    min_free_bytes: int | None = None
    operation_seconds: float = 6 * 3600

    def __post_init__(self):
        for value in (self.capture_bytes, self.input_bytes):
            if type(value) is not int or not 1 <= value <= 64 * MIB:
                raise ValueError("Invalid migration memory bound")
        for value in (self.file_bytes, self.workspace_bytes):
            if type(value) is not int or not 1 <= value <= 4 * 1024**4:
                raise ValueError("Invalid migration file bound")
        if self.min_free_bytes is not None and (type(self.min_free_bytes) is not int or not 1 <= self.min_free_bytes <= 4 * 1024**4):
            raise ValueError("Invalid migration free-space reserve")
        seconds(self.operation_seconds, maximum=7 * 86400)


def seconds(value, *, maximum=86400):
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and 0 < value <= maximum
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("A finite positive migration timeout is required")
    return value


def _identity(fd):
    info = os.fstat(fd)
    return {"dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid,
            "mode": info.st_mode, "nlink": info.st_nlink, "size": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def _directory(path, stack):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("A private owned migration directory is required")
    return fd


def _file(stream, stack, *, output, limit):
    if not isinstance(stream, (io.BufferedIOBase, io.RawIOBase)) or not isinstance(stream.name, (str, bytes, os.PathLike)):
        raise ValueError("A named binary regular file is required")
    fd = os.dup(stream.fileno())
    stack.callback(os.close, fd)
    state = _identity(fd)
    position = os.lseek(fd, 0, os.SEEK_CUR)
    path = Path(os.fsdecode(stream.name)).absolute()
    parent = _directory(path.parent, stack)
    named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISREG(state["mode"]) or state["uid"] != os.geteuid()
            or state["nlink"] != 1 or state["mode"] & 0o022
            or (named.st_dev, named.st_ino) != (state["dev"], state["ino"])
            or stat.S_ISLNK(named.st_mode) or stream.tell() != position
            or not 0 <= position <= state["size"] <= limit
            or output and (state["size"] or position or not stream.writable())
            or not output and not stream.readable()):
        raise ValueError("Unsafe, buffered or over-budget migration file")
    return {"fd": fd, "parent": parent, "name": path.name, "identity": state, "position": position}


def operate(kind, *, deadline, policy, argv=None, data=None, stdin=None, stdout=None, workspace=None):
    """Use only explicitly inherited pinned descriptors; never reopen a file name.

    File-descriptor acquisition/stat and process acquisition are normal OS calls,
    not hard realtime operations. Trusted exclusive ownership is still required.
    """
    if not isinstance(policy, IOPolicy):
        raise ValueError("A validated migration I/O policy is required")
    if kind not in {"command", "hash", "read", "receipt"}:
        raise ValueError("Unsupported migration I/O operation")
    if data is not None and (type(data) is not bytes or len(data) > policy.input_bytes):
        raise CommandBoundaryError("Migration input exceeds its memory bound")
    if data is not None and stdin is not None:
        raise CommandBoundaryError("Migration byte input and file input are exclusive")
    if kind == "command" and (not isinstance(argv, (list, tuple)) or not argv or any(type(v) is not str or not v or "\x00" in v for v in argv)):
        raise ValueError("Invalid migration command")
    with contextlib.ExitStack() as stack:
        request = {"kind": kind, "policy": dataclasses.asdict(policy), "argv": argv,
                   "input_size": len(data) if data else 0, "stdin": None, "stdout": None, "workspace": None}
        if stdin is not None:
            request["stdin"] = _file(stdin, stack, output=False,
                                      limit=policy.input_bytes if kind == "read" else policy.file_bytes)
        if stdout is not None:
            request["stdout"] = _file(stdout, stack, output=True, limit=policy.file_bytes)
        if workspace is not None:
            request["workspace"] = _directory(workspace, stack)
        fds = set()
        for name in ("stdin", "stdout"):
            if request[name]:
                fds.update((request[name]["fd"], request[name]["parent"]))
        if request["workspace"] is not None:
            fds.add(request["workspace"])
        header = json.dumps(request, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(header) > 65536:
            raise CommandBoundaryError("Migration command metadata exceeds its bound")
        result = capture_command(
            [sys.executable, "-I", "-B", str(Path(__file__).with_name("migration_io_worker.py"))],
            deadline=deadline, max_output_bytes=policy.input_bytes if kind == "read" else policy.capture_bytes,
            max_input_bytes=65536 + policy.input_bytes, input_data=header + (data or b""),
            pass_fds=tuple(sorted(fds)),
        )
        if result.returncode:
            raise CommandBoundaryError("Migration I/O failed; target is NOT qualified")
        if time.monotonic() >= deadline:
            raise CommandBoundaryError("Migration I/O deadline exceeded")
        return result.stdout
