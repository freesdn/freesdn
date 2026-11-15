# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Capless tailscaled runs under a supervisor, not inside a request worker.

Evidence (2026-11 soak; reproduced in a capless container from the production
image): ``start_daemon()`` spawned tailscaled with
``asyncio.create_subprocess_exec(stdout=PIPE, stderr=PIPE)`` inside whichever
gunicorn worker served the click. When that Python process exits normally -- a
``max_requests`` recycle -- asyncio closes the subprocess transport and KILLS the
still-running child (measured: dead within 1 s, with or without the pipes;
tailscaled itself ignores SIGPIPE, SigIgn 0x1000, and survives a broken pipe).
Nothing restarted it, not even after an api restart with enrolled state on the
volume. These tests drive the real supervisor against a stand-in daemon.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="flock/fork/procfs")

BACKEND = Path(__file__).resolve().parents[2]


@pytest.fixture
def box(tmp_path):
    state, run = tmp_path / "state", tmp_path / "run"
    state.mkdir()
    run.mkdir()
    pids = tmp_path / "pids"
    fake = tmp_path / "tailscaled"
    fake.write_text(f'#!/bin/sh\necho $$ >> "{pids}"\necho "fake tailscaled up"\nexec sleep 300\n')
    fake.chmod(0o755)
    env = {
        **os.environ,
        "TS_STATE_DIR": str(state),
        "TS_RUN_DIR": str(run),
        "TAILSCALED_BIN": str(fake),
        "VPN_MODE": "off",
    }
    env.pop("FREESDN_OPENVPN_SIDECAR", None)
    env.pop("FREESDN_WIREGUARD_SIDECAR", None)
    started: list[int] = []

    def launch(*args: str, **extra: str) -> int:
        rc = subprocess.run(
            [sys.executable, "-m", "app.tailscaled_supervisor", *args],
            cwd=BACKEND,
            env={**env, **extra},
            timeout=30,
        ).returncode
        return rc

    def daemon_pids() -> list[int]:
        if not pids.exists():
            return []
        return [int(p) for p in pids.read_text().split()]

    def alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return "State:\tZ" not in Path(f"/proc/{pid}/status").read_text()
        except OSError:
            return False

    def wait_for(pred, timeout=10.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if pred():
                return True
            time.sleep(0.1)
        return False

    ns = type("Box", (), {})()
    ns.state, ns.run, ns.launch, ns.daemon_pids = state, run, launch, daemon_pids
    ns.alive, ns.wait_for, ns.started = alive, wait_for, started
    yield ns
    # Teardown: stop the supervisor (it stops the daemon), then anything left.
    lock = run / "freesdn-supervisor.lock"
    if lock.exists() and lock.read_text().strip().isdigit():
        sup = int(lock.read_text().strip())
        if alive(sup):
            os.kill(sup, signal.SIGTERM)
            wait_for(lambda: not alive(sup), 15)
    for pid in daemon_pids():
        if alive(pid):
            os.kill(pid, signal.SIGKILL)


def test_the_daemon_outlives_its_launcher_and_logs_to_a_file(box):
    assert box.launch("--detach") == 0  # returns at once
    assert box.wait_for(lambda: box.daemon_pids())
    pid = box.daemon_pids()[0]
    time.sleep(0.5)
    assert box.alive(pid), "the daemon must outlive the process that launched it"
    out = os.readlink(f"/proc/{pid}/fd/1")
    err = os.readlink(f"/proc/{pid}/fd/2")
    assert out == err == str(box.state / "tailscaled.log"), (out, err)  # not a pipe
    assert "fake tailscaled up" in (box.state / "tailscaled.log").read_text()
    assert (box.state / "freesdn-autostart").exists()  # remembered for restarts


def test_a_daemon_that_exits_is_restarted(box):
    assert box.launch("--detach") == 0
    assert box.wait_for(lambda: box.daemon_pids())
    first = box.daemon_pids()[0]
    os.kill(first, signal.SIGKILL)
    assert box.wait_for(lambda: len(box.daemon_pids()) >= 2, 15), "not restarted"
    assert box.alive(box.daemon_pids()[-1])


def test_a_second_launch_does_not_start_a_second_daemon(box):
    assert box.launch("--detach") == 0
    assert box.wait_for(lambda: box.daemon_pids())
    assert box.launch("--detach") == 0
    time.sleep(1.5)
    assert len(box.daemon_pids()) == 1


def test_if_enrolled_does_nothing_on_a_fresh_volume(box):
    assert box.launch("--detach", "--if-enrolled") == 0
    time.sleep(1.5)
    assert box.daemon_pids() == []
    assert not (box.state / "freesdn-autostart").exists()


def test_if_enrolled_brings_an_enrolled_node_back_after_a_restart(box):
    (box.state / "tailscaled.state").write_text('{"_machinekey": "x"}')
    assert box.launch("--detach", "--if-enrolled") == 0
    assert box.wait_for(lambda: box.daemon_pids())


@pytest.mark.parametrize("extra", [{"VPN_MODE": "sidecar"}, {"FREESDN_OPENVPN_SIDECAR": "true"}])
def test_sidecar_mode_is_left_to_the_vpn_container(box, extra):
    (box.state / "tailscaled.state").write_text("{}")
    assert box.launch("--detach", **extra) == 0
    time.sleep(1.5)
    assert box.daemon_pids() == []


async def test_start_daemon_launches_the_supervisor_not_a_worker_child(monkeypatch):
    """Fails on the old start_daemon: it ran create_subprocess_exec("tailscaled",
    stdout=PIPE, stderr=PIPE) in the request worker."""
    import asyncio

    from app.services import vpn_integration

    spawned: list[tuple] = []

    async def no_exec(*argv, **kwargs):
        spawned.append(argv)
        raise AssertionError(f"request worker spawned {argv[0]!r} itself")

    statuses = iter(
        [{"daemon_running": False, "state": "daemon_stopped"}]
        + [{"daemon_running": True, "state": "needs_login"}] * 20
    )

    async def status():
        return next(statuses)

    launched: list[bool] = []
    monkeypatch.setattr(asyncio, "create_subprocess_exec", no_exec)
    monkeypatch.setattr(vpn_integration.os, "access", lambda *_a: True)
    monkeypatch.setattr(
        vpn_integration, "_launch_tailscaled_supervisor", lambda: launched.append(True) or True
    )
    svc = vpn_integration.TailscaleSetupService()
    monkeypatch.setattr(svc, "get_setup_status", status)

    result = await svc.start_daemon()

    assert launched == [True] and spawned == []
    assert result["success"] is True and result["state"] == "needs_login"
