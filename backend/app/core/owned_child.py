# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Linux child launcher with parent-death binding, without a preexec callback.

An ordinary same-credential exec preserves the binding. Privileged binaries are
refused because set-ID or file-capability execution can clear that binding.
This protects an owned child on parent-thread exit, not process descendants.
"""

from __future__ import annotations

import ctypes
import errno
import os
import shutil
import signal
import stat
import sys
from collections.abc import Sequence


class OwnedChildError(RuntimeError):
    """A fixed launch refusal that never contains command arguments or secrets."""


def owned_child_command(command: Sequence[str]) -> list[str]:
    if sys.platform != "linux" or not command:
        raise OwnedChildError("Owned media children require Linux process support")
    # Run the stdlib-only file directly: importing app.core would load settings
    # and emit unrelated configuration warnings into a media subprocess.
    return [sys.executable, "-B", os.path.abspath(__file__), str(os.getpid()), *command]


def _execute(parent: int, command: list[str]) -> None:
    if sys.platform != "linux" or parent < 1 or not command:
        raise OwnedChildError("Invalid owned-child launch")
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        raise OwnedChildError("Owned-child parent is unavailable")
    executable = shutil.which(command[0])
    if executable is None:
        raise OwnedChildError("Owned-child executable is unavailable")
    fd = os.open(executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise OwnedChildError("Privileged child executables are not supported")
        try:
            os.getxattr(fd, "security.capability")
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise OwnedChildError("Child executable capabilities cannot be verified") from None
        else:
            raise OwnedChildError("Privileged child executables are not supported")
        # Execute the same inode that was checked; argv is never passed through a shell.
        os.execve(fd, [executable, *command[1:]], dict(os.environ))
    finally:
        os.close(fd)


def main() -> int:
    try:
        if len(sys.argv) < 3:
            raise OwnedChildError("Invalid owned-child launch")
        _execute(int(sys.argv[1]), sys.argv[2:])
    except (OwnedChildError, OSError, ValueError, AttributeError):
        print("Unable to start owned media child", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
