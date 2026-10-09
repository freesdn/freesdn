# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded POSIX subprocess capture for local qualification commands.

The caller must separately reconcile daemon-side resources after interruption:
killing a Docker CLI process does not undo work accepted by the Docker daemon.
"""
from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path


class CommandBoundaryError(RuntimeError):
    """Safe diagnostic: deliberately omit command arguments and captured data."""


_cancellation: ContextVar[Callable[[], bool] | None] = ContextVar("command_cancellation", default=None)


@contextmanager
def command_cancellation(requested: Callable[[], bool]):
    """Cooperate with a caller's interruption request without asynchronous raises.

    The caller owns signal handling and must permit its bounded reconciliation
    phase. Nested scopes restore their previous context, including on failure.
    """
    if not callable(requested):
        raise ValueError("A cancellation predicate is required")
    token = _cancellation.set(requested)
    try:
        yield
    finally:
        _cancellation.reset(token)


def _check_cancellation() -> None:
    requested = _cancellation.get()
    if requested is not None and requested():
        raise CommandBoundaryError("Command interrupted; owned work requires reconciliation")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _positive_bytes(value: int) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError("A positive integer byte bound is required")


def _finite_deadline(value: float) -> None:
    if type(value) not in (int, float):
        raise ValueError("A finite monotonic deadline is required")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError("A finite monotonic deadline is required")


def _waitable_exit(child: subprocess.Popen[bytes]):
    # Do not reap: the waitable leader reserves its PID through group cleanup.
    # Callers must not install a SIGCHLD handler or independently reap this child.
    return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def _stop_group(child: subprocess.Popen[bytes]) -> None:
    # start_new_session binds this group ID to our own child. Descendants that
    # escape that group require a containing namespace/cgroup, not a wider kill.
    try:
        _waitable_exit(child)
    except ChildProcessError:
        raise CommandBoundaryError("Owned child wait ownership was lost") from None
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    until = time.monotonic() + 1
    while _waitable_exit(child) is None and time.monotonic() < until:
        time.sleep(0.01)
    # A parent may exit while an ordinary descendant still owns a pipe.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=1)
    except subprocess.TimeoutExpired:
        raise CommandBoundaryError("Owned command did not terminate") from None


def capture_command(
    argv: Sequence[str],
    *,
    deadline: float,
    max_output_bytes: int,
    max_input_bytes: int,
    input_data: bytes | None = None,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
) -> CommandResult:
    """Run without a shell; no unbounded communicate(), output file or wait.

    Deadline covers pipe I/O and child completion; cleanup allows two additional
    seconds. OS process creation itself is not preemptible here. Byte bounds are
    caller policy and must also bound streamed dumps separately at integration.
    Only children that stay in the owned process group are covered by teardown.
    """
    if os.name != "posix" or not hasattr(os, "WNOWAIT"):
        raise CommandBoundaryError("POSIX command containment is required")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise CommandBoundaryError("Exclusive child wait ownership is required")
    _check_cancellation()
    _finite_deadline(deadline)
    _positive_bytes(max_output_bytes)
    _positive_bytes(max_input_bytes)
    if type(pass_fds) is not tuple or any(type(fd) is not int or fd < 3 for fd in pass_fds) or len(set(pass_fds)) != len(pass_fds):
        raise ValueError("Only distinct explicitly owned file descriptors may be inherited")
    if not isinstance(argv, (list, tuple)) or not argv or not argv[0] or any(
        type(part) is not str or "\0" in part for part in argv
    ):
        raise ValueError("A nonempty argument vector is required")
    if input_data is not None and type(input_data) is not bytes:
        raise ValueError("Input must be bytes or absent")
    if input_data is not None and len(input_data) > max_input_bytes:
        raise CommandBoundaryError("Command input exceeds its byte bound")
    if time.monotonic() >= deadline:
        raise CommandBoundaryError("Command deadline expired before dispatch")

    child: subprocess.Popen[bytes] | None = None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    sent = 0
    try:
        # Validate before Popen opens its pipes/devnull: a closed number can be
        # reused there and otherwise silently inherited as a different file.
        # Callers retain ownership and must keep these FDs open until return;
        # this is not protection against concurrent caller-side close/reuse.
        for fd in pass_fds:
            os.fstat(fd)
        _check_cancellation()
        child = subprocess.Popen(
            list(argv), stdin=subprocess.PIPE if input_data else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env,
            start_new_session=True, close_fds=True, bufsize=0,
            pass_fds=pass_fds,
        )
        with selectors.DefaultSelector() as selector:
            for name in ("stdout", "stderr"):
                stream = getattr(child, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            if child.stdin is not None:
                os.set_blocking(child.stdin.fileno(), False)
                selector.register(child.stdin, selectors.EVENT_WRITE, "stdin")
            while selector.get_map() or _waitable_exit(child) is None:
                _check_cancellation()
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise CommandBoundaryError("Command deadline exceeded")
                for key, _ in selector.select(min(remaining_time, 0.05)):
                    if key.data == "stdin":
                        try:
                            sent += os.write(key.fd, input_data[sent:sent + 65536])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            sent = len(input_data)
                        if sent == len(input_data):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    try:
                        chunk = os.read(key.fd, min(65536, max_output_bytes - total + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    total += len(chunk)
                    if total > max_output_bytes:
                        raise CommandBoundaryError("Command output exceeds its byte bound")
                    output[key.data].extend(chunk)
        if time.monotonic() > deadline:
            raise CommandBoundaryError("Command deadline exceeded")
        _check_cancellation()
        observed = _waitable_exit(child)
        if observed is None:
            raise CommandBoundaryError("Command exit was not observed")
        returncode = observed.si_status if observed.si_code == os.CLD_EXITED else -observed.si_status
        return CommandResult(returncode, bytes(output["stdout"]), bytes(output["stderr"]))
    except CommandBoundaryError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        # OS failures can include argv/environment/path secrets in exception text.
        raise CommandBoundaryError("Command execution failed") from None
    finally:
        if child is not None:
            try:
                _stop_group(child)
            finally:
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()
