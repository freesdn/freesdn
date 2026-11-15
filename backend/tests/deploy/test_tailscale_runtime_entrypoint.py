# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Tailscale runtime container's entrypoint, including the upgrade path.

Drives the real ``backend/tailscale-runtime/entrypoint.sh`` (and its
healthcheck) under ``/bin/sh`` against private stand-ins for the two volumes and
for the ``tailscaled`` / ``tailscale`` binaries.

The upgrade is the part that matters most. Up to 26.12 tailscaled ran inside the
api container on the same ``tailscale_state`` / ``tailscale_run`` volumes, with
``--state=/var/lib/tailscale/tailscaled.state`` and uid 1001:

* 26.11 (``start_daemon()`` spawned it) left a state file and no marker;
* the 26.12 development builds (``app/tailscaled_supervisor.py``) also left
  ``freesdn-autostart``, their own ``tailscaled.log`` files and a lock file in
  the run volume.

An enrolled node in either layout must come up in the new container, from the
same state file, without anyone clicking Connect again, and without the state
being rewritten by anything but tailscaled. And while the older api container
still runs its own tailscaled during ``docker compose up -d``, the new one must
wait instead of fighting it for the socket.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]
ENTRYPOINT = BACKEND / "tailscale-runtime" / "entrypoint.sh"
HEALTHCHECK = BACKEND / "tailscale-runtime" / "healthcheck.sh"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("sh") is None, reason="POSIX shell scripts"
)

FAKE_TAILSCALED = """#!/bin/sh
printf '%s\\n' "$@" > "$CTL/argv.tmp" && mv "$CTL/argv.tmp" "$CTL/argv"
echo $$ > "$CTL/pid"
# A daemon too stuck to act on TERM: only KILL ends it.
if [ -e "$CTL/ignore-term" ]; then trap '' TERM; fi
exec sleep 30
"""

#: Answers like a live daemon while $CTL/answers exists, else like the pinned
#: CLI does for a socket nobody listens on.
FAKE_TAILSCALE = """#!/bin/sh
if [ -e "$CTL/answers" ]; then
    echo '{"Version": "1.104.5", "BackendState": "NeedsLogin"}'
    exit 0
fi
echo "failed to connect to local tailscaled (no tailscaled process found): connect: connection refused" >&2
exit 1
"""


class Box:
    def __init__(self, root: Path) -> None:
        self.state = root / "state"
        self.run = root / "run"
        self.ctl = root / "ctl"
        self.tmp = root / "tmp"
        for d in (self.state, self.run, self.ctl, self.tmp):
            d.mkdir()
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in (("tailscaled", FAKE_TAILSCALED), ("tailscale", FAKE_TAILSCALE)):
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "TS_STATE_DIR": str(self.state),
            "TS_RUN_DIR": str(self.run),
            "TS_PHASE_FILE": str(self.tmp / "phase"),
            "TAILSCALED_BIN": str(bin_dir / "tailscaled"),
            "TAILSCALE_BIN": str(bin_dir / "tailscale"),
            "TS_POLL_SECONDS": "0.1",
            "CTL": str(self.ctl),
        }
        self.log = root / "entrypoint.log"
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self, **extra: str) -> None:
        # Its own process group, so stop() also ends the tailscaled and the
        # watchdog it starts in the background.
        with self.log.open("wb") as log:
            self.proc = subprocess.Popen(
                ["sh", str(ENTRYPOINT)],
                env={**self.env, **extra},
                stdout=log,
                stderr=log,
                start_new_session=True,
            )

    def phase(self) -> str:
        try:
            return (self.tmp / "phase").read_text().strip()
        except OSError:
            return ""

    def argv(self) -> list[str] | None:
        path = self.ctl / "argv"
        return path.read_text().split("\n")[:-1] if path.exists() else None

    def health(self) -> int:
        return subprocess.run(
            ["sh", str(HEALTHCHECK)], env=self.env, capture_output=True, timeout=30
        ).returncode

    def output(self) -> str:
        return self.log.read_text()

    def daemon_pid(self) -> int | None:
        path = self.ctl / "pid"
        return int(path.read_text()) if path.exists() else None

    def stop(self) -> None:
        if self.proc is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.proc.pid, signal.SIGKILL)
            if self.proc.poll() is None:
                self.proc.wait(timeout=10)


def wait_for(pred, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def box(tmp_path):
    b = Box(tmp_path)
    yield b
    b.stop()


def _stale_socket(path: Path) -> None:
    import socket

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(path))
    s.close()


def _assert_started_on_the_volumes(box: Box) -> list[str]:
    assert wait_for(lambda: box.argv() is not None), box.output()
    argv = box.argv()
    assert argv is not None
    assert f"--state={box.state / 'tailscaled.state'}" in argv
    assert f"--socket={box.run / 'tailscaled.sock'}" in argv
    assert "--tun=userspace-networking" in argv
    assert "--socks5-server=:1055" in argv
    assert box.phase() == "running"
    return argv


# ── never used: no daemon, no traffic, healthy ───────────────────────────────


def test_a_fresh_install_stands_by_and_connect_starts_it(box):
    box.start()
    assert wait_for(lambda: box.phase() == "standby"), box.output()
    time.sleep(0.5)
    assert box.argv() is None, "tailscaled started on a volume nobody enrolled"
    assert box.health() == 0, "standing by must not make the container unhealthy"

    (box.run / "freesdn-start-requested").touch()  # what Connect in the UI does

    _assert_started_on_the_volumes(box)
    assert (box.state / "freesdn-autostart").exists(), "the next start would not come back"
    assert not (box.run / "freesdn-start-requested").exists()
    assert "adopted" not in box.output()


def test_standby_stops_promptly_on_sigterm(box):
    box.start()
    assert wait_for(lambda: box.phase() == "standby")
    assert box.proc is not None
    box.proc.send_signal(signal.SIGTERM)
    assert box.proc.wait(timeout=5) == 0


# ── the upgrade: an enrolled node comes back in the new container ────────────


def test_a_node_enrolled_on_26_11_comes_back_unchanged(box):
    """26.11 left only the state file (start_daemon() spawned tailscaled in
    the api, uid 1001, --state on this volume)."""
    state = box.state / "tailscaled.state"
    state.write_text('{"_machinekey": "bWFjaGluZQ==", "_current-profile": "cHJvZmlsZQ=="}')
    state.chmod(0o600)
    before = state.read_bytes()

    box.start()

    _assert_started_on_the_volumes(box)
    assert state.read_bytes() == before, "the node identity was rewritten before tailscaled ran"
    assert (box.state / "freesdn-autostart").exists()
    assert "adopted the Tailscale node state" in box.output()


def test_a_node_enrolled_under_the_api_supervisor_comes_back(box):
    """The 26.12 development builds' layout: marker, own logs, lock, stale socket."""
    (box.state / "tailscaled.state").write_text('{"_machinekey": "bWFjaGluZQ=="}')
    (box.state / "freesdn-autostart").touch()
    (box.state / "tailscaled.log").write_text("supervisor log\n")
    (box.state / "tailscaled.log.1").write_text("older\n")
    (box.run / "freesdn-supervisor.lock").write_text("4242")
    _stale_socket(box.run / "tailscaled.sock")  # it died with the old api container

    box.start()

    _assert_started_on_the_volumes(box)
    assert not (box.run / "freesdn-supervisor.lock").exists()
    assert (box.state / "tailscaled.log").read_text() == "supervisor log\n"


def test_it_waits_while_the_old_api_container_still_runs_tailscaled(box):
    """`docker compose up -d` can start the new container before it recreates
    the api, whose tailscaled still holds the socket. Starting a second daemon
    then would fail to bind the socket and restart-loop."""
    (box.state / "tailscaled.state").write_text('{"_machinekey": "bWFjaGluZQ=="}')
    _stale_socket(box.run / "tailscaled.sock")
    (box.ctl / "answers").touch()  # the old daemon answers

    box.start()

    assert wait_for(lambda: box.phase() == "waiting"), box.output()
    time.sleep(0.5)
    assert box.argv() is None
    assert box.health() == 1
    assert "waiting for it to stop" in box.output()

    (box.ctl / "answers").unlink()  # the old api container is gone

    _assert_started_on_the_volumes(box)


# ── modes and refusals ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "extra", [{"VPN_MODE": "sidecar"}, {"FREESDN_OPENVPN_SIDECAR": "true"}], ids=["mode", "flag"]
)
def test_sidecar_mode_never_starts_a_second_daemon(box, extra):
    (box.state / "tailscaled.state").write_text('{"_machinekey": "bWFjaGluZQ=="}')
    (box.run / "freesdn-start-requested").touch()
    box.start(**extra)
    assert wait_for(lambda: box.phase() == "sidecar"), box.output()
    time.sleep(0.5)
    assert box.argv() is None
    assert box.health() == 0


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads anything")
def test_a_state_file_it_cannot_read_is_reported_not_crash_looped(box):
    """Written as root by the vpn sidecar or the development image (mode 0600)."""
    state = box.state / "tailscaled.state"
    state.write_text('{"_machinekey": "bWFjaGluZQ=="}')
    state.chmod(0o000)
    try:
        box.start()
        assert wait_for(lambda: box.phase() == "blocked"), box.output()
        time.sleep(0.3)
        assert box.argv() is None
        assert box.proc is not None and box.proc.poll() is None, "it exited instead of waiting"
        assert box.health() == 1
        assert "chown" in box.output() and "1001:1001" in box.output()

        state.chmod(0o600)  # the operator ran the printed command
        _assert_started_on_the_volumes(box)
    finally:
        state.chmod(0o600)


@pytest.mark.parametrize(("value", "flag"), [(None, False), ("false", False), ("true", True)])
def test_log_uploads_stay_on_unless_the_operator_turns_them_off(box, value, flag):
    (box.state / "tailscaled.state").write_text("{}")
    if value is None:
        box.start()
    else:
        box.start(TAILSCALE_NO_LOGS_NO_SUPPORT=value)
    argv = _assert_started_on_the_volumes(box)
    assert ("--no-logs-no-support" in argv) is flag
    assert f"log upload to Tailscale {'off' if flag else 'on'}" in box.output()


def test_the_healthcheck_asks_the_running_daemon(box):
    (box.tmp / "phase").write_text("running\n")
    assert box.health() == 1, "a socket nobody answers on was reported healthy"
    (box.ctl / "answers").touch()
    assert box.health() == 0


# ── the watchdog: a tailscaled that runs but no longer answers ───────────────
#
# Docker never restarts a container for being unhealthy, and a hung tailscaled
# does not exit, so before the watchdog it stayed hung (and the container stayed
# "unhealthy") until someone restarted it by hand.

#: Fast settings for the tests; the shipped defaults are 30 s x 4, 10 s, 10 s.
WATCH = {
    "TS_WATCHDOG_INTERVAL": "0.2",
    "TS_WATCHDOG_FAILS": "3",
    "TS_WATCHDOG_TIMEOUT": "2",
    "TS_WATCHDOG_STOP_GRACE": "1",
}


def _alive(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still "exists"; it is not running.
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(") ", 1)[1][0] != "Z"
    except OSError:
        return False


def _container_status(returncode: int) -> int:
    """The exit code Docker reports: 128+N for a main process killed by signal N
    (an exec'd tailscaled), or the shell's own 128+N when it relays one."""
    return 128 - returncode if returncode < 0 else returncode


def _running_watched(box: Box, **extra: str) -> int:
    (box.state / "tailscaled.state").write_text('{"_machinekey": "bWFjaGluZQ=="}')
    (box.ctl / "answers").touch()
    box.start(TS_WATCHDOG_FIRED_FILE=str(box.tmp / "watchdog"), **{**WATCH, **extra})
    _assert_started_on_the_volumes(box)
    assert wait_for(lambda: box.daemon_pid() is not None)
    pid = box.daemon_pid()
    assert pid is not None
    return pid


def test_a_hung_daemon_is_stopped_so_the_restart_policy_brings_it_back(box):
    """Fails on the old code: tailscaled was exec'd and nothing ever asked it."""
    pid = _running_watched(box)
    (box.ctl / "answers").unlink()  # still running, no longer answering

    assert box.proc is not None
    assert box.proc.wait(timeout=15) == 1, box.output()
    assert not _alive(pid), "the hung tailscaled was left running"
    out = box.output()
    assert "3 of 3 in a row" in out
    assert "stopping it so Docker restarts this container" in out


def test_a_daemon_that_ignores_term_is_killed(box):
    (box.ctl / "ignore-term").touch()
    pid = _running_watched(box)
    (box.ctl / "answers").unlink()

    assert box.proc is not None
    assert box.proc.wait(timeout=15) == 1, box.output()
    assert not _alive(pid)
    assert "did not exit on TERM" in box.output()


def test_a_daemon_that_answers_is_left_alone_whatever_its_login_state(box):
    """The fake answers NeedsLogin, as a node waiting for its enrollment does."""
    pid = _running_watched(box)
    time.sleep(2)  # ten checks
    assert box.proc is not None and box.proc.poll() is None, box.output()
    assert _alive(pid)
    assert "did not answer" not in box.output()


def test_only_missed_answers_in_a_row_count(box):
    pid = _running_watched(box)
    for _ in range(4):  # misses one or two checks at a time, then answers again
        (box.ctl / "answers").unlink()
        time.sleep(0.3)
        (box.ctl / "answers").touch()
        time.sleep(0.6)
    assert box.proc is not None and box.proc.poll() is None, box.output()
    assert _alive(pid)
    assert "answers on its LocalAPI again" in box.output()


def test_docker_stop_still_reaches_tailscaled(box):
    pid = _running_watched(box)
    assert box.proc is not None
    box.proc.send_signal(signal.SIGTERM)
    rc = box.proc.wait(timeout=5)
    assert not _alive(pid), "TERM to the container did not reach tailscaled"
    assert _container_status(rc) == 128 + signal.SIGTERM, "the exit status is tailscaled's own"


def test_a_daemon_that_exits_ends_the_container_with_its_status(box):
    pid = _running_watched(box)
    os.kill(pid, signal.SIGKILL)
    assert box.proc is not None
    assert _container_status(box.proc.wait(timeout=5)) == 128 + signal.SIGKILL
    assert "watchdog" not in box.output()


def test_the_watchdog_can_be_turned_off(box):
    """TS_WATCHDOG_FAILS=0: tailscaled replaces the script, as before."""
    pid = _running_watched(box, TS_WATCHDOG_FAILS="0")
    assert box.proc is not None
    assert pid == box.proc.pid, "with the watchdog off tailscaled is exec'd"
    (box.ctl / "answers").unlink()
    time.sleep(1.5)
    assert box.proc.poll() is None
