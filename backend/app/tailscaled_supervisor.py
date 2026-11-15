# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - capless tailscaled supervisor
=======================================

Runs ``tailscaled`` (userspace networking) for the api container, independent
of any request worker, and restarts it when it exits.

Not used by the shipped compose any more: there tailscaled runs in its own
``tailscale`` runtime container (``TAILSCALE_RUNTIME=container``), which this
refuses to duplicate. It remains for a single-container deployment of the
backend image (``FREESDN_VPN_AUTOSTART``, or the image run on its own).

Why this exists (2026-11 soak): ``start_daemon()`` used to spawn tailscaled
with ``asyncio.create_subprocess_exec(stdout=PIPE, stderr=PIPE)`` inside
whichever gunicorn worker handled the click, and never read the pipes. So
tailscaled's stdout/stderr were pipes to that one worker:

* when gunicorn recycled the worker (``--max-requests``), the read ends closed
  and tailscaled's next log line hit a broken pipe;
* while the worker lived, nobody drained the pipes, so after ~200 KiB of logs
  tailscaled would block on a log write;
* asyncio closes (and kills) a still-running child when its transport is torn
  down;
* nothing started it again after an api container restart, although its node
  identity persists in the ``tailscale_state`` volume.

This process owns tailscaled instead: stdin from /dev/null, stdout and stderr
appended to ``/var/lib/tailscale/tailscaled.log`` (size-capped here), its own
session, restarted with backoff on exit. One supervisor per state directory
(an ``flock`` on the run volume), so the entrypoint and a UI click cannot start
two daemons on one state file.

Standard library only, and importable without app settings: the entrypoint runs
it before the app exists.

Exit codes are only ever 0 or 1. Without an init process gunicorn's master is
PID 1 and reaps orphans, and it HALTS the server when any child it reaps exits
with 3 or 4 (its worker-boot / app-load codes). docker-compose.yml gives the api
``init: true`` as well.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import os
import shutil
import signal
import subprocess
import sys
import time

STATE_DIR = os.environ.get("TS_STATE_DIR", "/var/lib/tailscale")
RUN_DIR = os.environ.get("TS_RUN_DIR", "/var/run/tailscale")
STATE_FILE = os.path.join(STATE_DIR, "tailscaled.state")
SOCKET = os.path.join(RUN_DIR, "tailscaled.sock")
LOG_FILE = os.path.join(STATE_DIR, "tailscaled.log")
#: Present once an operator has started Tailscale here; survives restarts.
AUTOSTART_MARKER = os.path.join(STATE_DIR, "freesdn-autostart")
LOCK_FILE = os.path.join(RUN_DIR, "freesdn-supervisor.lock")

LOG_MAX_BYTES = 5 * 1024 * 1024
BACKOFF_MAX = 60.0
#: A run this long counts as healthy and resets the backoff.
HEALTHY_RUN = 300.0
POLL = 2.0


_TRUTHY = ("1", "true", "yes", "on")


def tailscaled_argv() -> list[str]:
    argv = [
        os.environ.get("TAILSCALED_BIN", "tailscaled"),
        f"--state={STATE_FILE}",
        f"--socket={SOCKET}",
        "--tun=userspace-networking",
        # netstack SOCKS5. app/core/http_client.py:overlay_socks_proxy() expects
        # exactly this endpoint when VPN_MODE=userspace.
        "--socks5-server=127.0.0.1:1055",
    ]
    # Same setting as the tailscale runtime container: no log uploads to
    # Tailscale Inc. only when the operator asks for it.
    if os.environ.get("TAILSCALE_NO_LOGS_NO_SUPPORT", "").strip().lower() in _TRUTHY:
        argv.append("--no-logs-no-support")
    return argv


def _say(message: str) -> None:
    """Best effort: our own stderr may be gone too, and that must not kill us."""
    with contextlib.suppress(Exception):
        sys.stderr.write(f"[tailscaled-supervisor] {message}\n")
        sys.stderr.flush()


def sidecar_mode() -> bool:
    """The privileged vpn sidecar owns tailscaled; never start a second one."""
    mode = os.environ.get("VPN_MODE", "off").strip().lower()
    return (
        mode == "sidecar"
        or os.environ.get("FREESDN_OPENVPN_SIDECAR", "").strip().lower() in _TRUTHY
        or os.environ.get("FREESDN_WIREGUARD_SIDECAR", "").strip().lower() in _TRUTHY
    )


def runtime_container() -> bool:
    """The `tailscale` runtime container owns tailscaled (the shipped compose)."""
    return os.environ.get("TAILSCALE_RUNTIME", "").strip().lower() == "container"


def enrolled() -> bool:
    """Has Tailscale been started here before (state or marker on the volume)?"""
    try:
        if os.path.getsize(STATE_FILE) > 0:
            return True
    except OSError:
        pass
    return os.path.exists(AUTOSTART_MARKER)


def preflight() -> str | None:
    """Why this container cannot run tailscaled, or None."""
    if sidecar_mode():
        return "VPN sidecar mode: the vpn container runs tailscaled"
    if runtime_container():
        return "the tailscale runtime container runs tailscaled"
    if shutil.which(tailscaled_argv()[0]) is None:
        return "tailscaled binary not found"
    for d in (STATE_DIR, RUN_DIR):
        if not os.access(d, os.W_OK):
            return f"{d} is not writable"
    return None


def _acquire_lock() -> int | None:
    fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    return fd


def _rotate_log() -> None:
    """Copy-truncate: tailscaled holds the file O_APPEND, so it keeps writing."""
    try:
        if os.path.getsize(LOG_FILE) <= LOG_MAX_BYTES:
            return
        shutil.copyfile(LOG_FILE, LOG_FILE + ".1")
        os.truncate(LOG_FILE, 0)
    except OSError:
        pass


class Supervisor:
    def __init__(self) -> None:
        self.child: subprocess.Popen[bytes] | None = None
        self.stopping = False

    def _on_term(self, _signum: int, _frame: object) -> None:
        self.stopping = True
        if self.child is not None and self.child.poll() is None:
            with contextlib.suppress(Exception):
                self.child.send_signal(signal.SIGTERM)

    def start_child(self) -> subprocess.Popen[bytes]:
        log = open(LOG_FILE, "ab", buffering=0)  # noqa: SIM115 - handed to the child
        try:
            return subprocess.Popen(
                tailscaled_argv(),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                start_new_session=True,
                close_fds=True,
                # tailscaled's log policy writes to $HOME/.cache; the image has no
                # home directory and the rootfs is read-only.
                env={**os.environ, "HOME": "/tmp"},
            )
        finally:
            log.close()

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self._on_term)
        signal.signal(signal.SIGINT, self._on_term)
        backoff = 1.0
        while not self.stopping:
            started = time.monotonic()
            try:
                self.child = self.start_child()
            except OSError as exc:
                _say(f"cannot start tailscaled: {exc}")
                return 1
            _say(f"tailscaled started (pid {self.child.pid}), log {LOG_FILE}")
            rc = None
            while rc is None:
                try:
                    rc = self.child.wait(timeout=POLL)
                except subprocess.TimeoutExpired:
                    _rotate_log()
            if self.stopping:
                break
            ran = time.monotonic() - started
            backoff = 1.0 if ran >= HEALTHY_RUN else min(BACKOFF_MAX, backoff * 2)
            _say(f"tailscaled exited rc={rc} after {ran:.0f}s; restarting in {backoff:.0f}s")
            deadline = time.monotonic() + backoff
            while not self.stopping and time.monotonic() < deadline:
                time.sleep(0.2)
        if self.child is not None and self.child.poll() is None:
            try:
                self.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.child.kill()
        _say("stopped")
        return 0


def _detach() -> bool:
    """Double-fork. True in the grandchild; the caller returns at once."""
    if os.fork() > 0:
        return False
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    with contextlib.suppress(OSError):
        fd = os.open(os.devnull, os.O_RDONLY)
        os.dup2(fd, 0)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tailscaled_supervisor")
    parser.add_argument("--detach", action="store_true", help="return at once; run detached")
    parser.add_argument(
        "--if-enrolled",
        action="store_true",
        help="do nothing unless Tailscale was started here before",
    )
    args = parser.parse_args(argv)

    reason = preflight()
    if reason:
        _say(f"not supervising: {reason}")
        return 0
    if args.if_enrolled and not enrolled():
        return 0
    with contextlib.suppress(OSError):
        open(AUTOSTART_MARKER, "a").close()  # noqa: SIM115
    if args.detach and not _detach():
        return 0
    lock = _acquire_lock()
    if lock is None:
        _say("another supervisor already runs tailscaled here")
        if args.detach:
            os._exit(0)
        return 0
    rc = Supervisor().run()
    if args.detach:
        os._exit(0 if rc == 0 else 1)
    return rc


if __name__ == "__main__":
    sys.exit(main())
