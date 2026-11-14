# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The api and the workers drive tailscaled in its own runtime container.

tailscaled now lives in the ``tailscale`` service of docker-compose.yml, and
the app containers only share its LocalAPI socket (the tailscale_run volume).
Two things follow, and both are pinned here.

**Nothing breaks without it.** Measured against the pinned CLI (1.104.5), a
``tailscale status`` with nothing behind the socket takes about two seconds to
fail, for a missing socket file and a refused connect alike, and the refused
case says "no tailscaled process found ... connection refused", which the old
code did not recognise as "not running" and logged at ERROR. With the runtime
container stopped, that was every status read, in the api and in each worker.
Now a connect to the socket answers first, in milliseconds, at DEBUG.

**Connect keeps working.** ``start_daemon()`` cannot start a process in another
container. It leaves a start request in the shared run volume, which the
runtime container's entrypoint answers, and it waits for the socket to answer.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import sys
import time

import pytest

from app.services import vpn_integration
from app.services.vpn_integration import TailscaleService, TailscaleSetupService

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="unix sockets")

#: What the pinned CLI prints for a socket file nobody listens on (1.104.5).
REFUSED = (
    b"failed to connect to local tailscaled (no tailscaled process found): Failed to "
    b"connect to local Tailscale daemon for /localapi/v0/status; not running? Error: "
    b"dial unix /var/run/tailscale/tailscaled.sock: connect: connection refused"
)


class _FakeCli:
    """Stand-in for asyncio.create_subprocess_exec that records each argv."""

    def __init__(self, rc: int = 1, stdout: bytes = b"", stderr: bytes = REFUSED):
        self.argvs: list[tuple[str, ...]] = []
        self.rc, self.stdout, self.stderr = rc, stdout, stderr

    async def __call__(self, *argv, **_kwargs):
        self.argvs.append(tuple(str(a) for a in argv))
        parent = self

        class _P:
            returncode = parent.rc

            async def communicate(self):
                return parent.stdout, parent.stderr

            def kill(self):
                pass

            async def wait(self):
                return parent.rc

        return _P()

    def ran(self, *words: str) -> bool:
        return any(a[: len(words)] == words for a in self.argvs)


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    """A private stand-in for the tailscale_run volume."""
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setattr(vpn_integration, "TAILSCALE_SOCKET", str(run / "tailscaled.sock"))
    monkeypatch.setattr(
        vpn_integration, "TAILSCALE_START_REQUEST", str(run / "freesdn-start-requested")
    )
    for name in ("VPN_MODE", "FREESDN_OPENVPN_SIDECAR", "FREESDN_WIREGUARD_SIDECAR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TAILSCALE_RUNTIME", "container")
    return run


def _stale_socket(path) -> None:
    """A socket file whose daemon is gone: what a killed tailscaled leaves."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(path))
    s.close()


@contextlib.asynccontextmanager
async def _listening(path):
    """Something that accepts on the LocalAPI socket, like a live tailscaled."""
    server = await asyncio.start_unix_server(lambda _r, w: w.close(), path=str(path))
    try:
        yield server
    finally:
        server.close()
        await server.wait_closed()


def _loud(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


# ── status: not running is quick, quiet and costs no CLI run ─────────────────


@pytest.mark.parametrize("socket_file", ["missing", "stale"])
async def test_status_without_a_daemon_runs_no_cli_and_logs_no_error(
    run_dir, monkeypatch, caplog, socket_file
):
    """Fails on the old code: it ran the CLI (~2 s each) and, for the stale
    socket, logged the refused connect at ERROR."""
    if socket_file == "stale":
        _stale_socket(run_dir / "tailscaled.sock")
    cli = _FakeCli()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", cli)
    caplog.set_level(logging.DEBUG, logger="app.services.vpn_integration")

    started = time.monotonic()
    status = await TailscaleService().get_status(refresh=True)
    elapsed = time.monotonic() - started

    # Not "Stopped": that is tailscaled's own word for a node taken down.
    assert status.backend_state == "NotRunning" and not status.is_connected
    assert cli.argvs == [], f"the CLI was run against a socket nobody answers on: {cli.argvs}"
    assert elapsed < 0.5
    assert _loud(caplog) == []
    assert any("not running" in r.getMessage() for r in caplog.records)


async def test_a_refused_cli_after_the_probe_is_not_an_error(run_dir, monkeypatch, caplog):
    """The daemon can go away between the probe and the CLI; that is DEBUG too."""
    cli = _FakeCli(rc=1, stderr=REFUSED)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", cli)
    caplog.set_level(logging.DEBUG, logger="app.services.vpn_integration")
    async with _listening(run_dir / "tailscaled.sock"):
        status = await TailscaleService().get_status(refresh=True)
    assert cli.ran("tailscale", "status", "--json")
    assert status.backend_state == "NotRunning"
    assert _loud(caplog) == []


async def test_a_live_daemon_is_still_asked(run_dir, monkeypatch):
    cli = _FakeCli(rc=0, stdout=b'{"BackendState": "NeedsLogin", "Self": null, "Peer": null}')
    monkeypatch.setattr(asyncio, "create_subprocess_exec", cli)
    async with _listening(run_dir / "tailscaled.sock"):
        status = await TailscaleService().get_status(refresh=True)
    assert cli.ran("tailscale", "status", "--json")
    assert status.backend_state == "NeedsLogin"


async def test_a_daemon_that_does_not_answer_is_killed_logged_and_remembered(
    run_dir, monkeypatch, caplog
):
    """A hung daemon: a reason in the log, the CLI reaped, and the next calls
    (refresh=True included, as the dashboard asks) do not pay 5 s again."""
    killed: list[bool] = []
    budget: dict[str, float] = {}

    class _Hung:
        returncode = None

        async def communicate(self):
            await asyncio.sleep(3600)

        def kill(self):
            killed.append(True)

        async def wait(self):
            return -9

    calls: list[tuple] = []

    async def fake_exec(*argv, **_kw):
        calls.append(argv)
        return _Hung()

    real_wait_for = asyncio.wait_for

    async def short_wait_for(aw, timeout):
        budget["timeout"] = timeout
        return await real_wait_for(aw, 0.05)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(asyncio, "wait_for", short_wait_for)
    caplog.set_level(logging.DEBUG, logger="app.services.vpn_integration")
    svc = TailscaleService()
    async with _listening(run_dir / "tailscaled.sock"):
        first = await svc.get_status(refresh=True)
        second = await svc.get_status(refresh=True)

    assert first.backend_state == second.backend_state == "Error"
    assert killed == [True], "the timed-out `tailscale` child was never reaped"
    assert len(calls) == 1, "a failed status was re-run immediately"
    assert budget["timeout"] <= 5
    warnings = _loud(caplog)
    assert warnings and all(w.strip() for w in warnings)
    assert any("did not answer" in w for w in warnings)


async def test_a_daemon_that_went_away_is_not_served_from_the_cache(run_dir, monkeypatch):
    cli = _FakeCli(rc=0, stdout=b'{"BackendState": "Running", "Self": {"Online": true}}')
    monkeypatch.setattr(asyncio, "create_subprocess_exec", cli)
    svc = TailscaleService()
    async with _listening(run_dir / "tailscaled.sock"):
        assert (await svc.get_status(refresh=True)).backend_state == "Running"
    assert (await svc.get_status(refresh=True)).backend_state == "NotRunning"
    # ... and a later cached read must not resurrect the old "Running".
    assert (await svc.get_status()).backend_state == "NotRunning"


async def test_ping_without_a_daemon_runs_no_cli(run_dir, monkeypatch):
    cli = _FakeCli()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", cli)
    assert await TailscaleService().ping("100.64.0.2") is None
    assert cli.argvs == []


async def test_setup_status_without_a_daemon_is_quick(run_dir, monkeypatch):
    """The setup page polls this every 5 s; with the runtime container down
    it used to spend ~2 s in `tailscale status` per poll."""
    cli = _FakeCli(rc=0, stdout=b"1.104.5\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", cli)
    _stale_socket(run_dir / "tailscaled.sock")

    status = await TailscaleSetupService().get_setup_status()

    assert status["state"] == "daemon_stopped" and status["daemon_running"] is False
    assert status["installed"] is True and status["version"] == "1.104.5"
    assert not cli.ran("tailscale", "status"), cli.argvs
    assert "not running" in status["message"]


async def test_setup_status_says_when_a_start_request_is_unanswered(run_dir, monkeypatch):
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _FakeCli(rc=0, stdout=b"1.104.5"))
    (run_dir / "freesdn-start-requested").touch()
    status = await TailscaleSetupService().get_setup_status()
    assert status["state"] == "daemon_stopped"
    assert "docker compose ps tailscale" in status["message"]


# ── Connect: a request to the runtime container, never a local daemon ────────


def _no_local_daemon(monkeypatch) -> list[tuple]:
    """Fail the test if the api tried to run tailscaled or its supervisor."""
    spawned: list[tuple] = []

    def no_supervisor():
        spawned.append(("supervisor",))
        return False

    monkeypatch.setattr(vpn_integration, "_launch_tailscaled_supervisor", no_supervisor)
    return spawned


async def test_connect_asks_the_runtime_container_and_waits_for_it(run_dir, monkeypatch):
    """Fails on the old code: it launched app.tailscaled_supervisor inside the api
    (or, without the state volume, refused with the sidecar message)."""
    spawned = _no_local_daemon(monkeypatch)
    cli = _FakeCli(rc=0, stdout=b'{"BackendState": "NeedsLogin", "Self": null}')
    monkeypatch.setattr(asyncio, "create_subprocess_exec", cli)
    request = run_dir / "freesdn-start-requested"
    sock = run_dir / "tailscaled.sock"
    seen_request: list[bool] = []

    async def runtime_container():
        # What backend/tailscale-runtime/entrypoint.sh does, in miniature.
        while not request.exists():
            await asyncio.sleep(0.05)
        seen_request.append(True)
        request.unlink()
        return await asyncio.start_unix_server(lambda _r, w: w.close(), path=str(sock))

    runtime = asyncio.create_task(runtime_container())
    try:
        result = await TailscaleSetupService().start_daemon()
    finally:
        server = await runtime
        server.close()
        await server.wait_closed()

    assert seen_request == [True]
    assert result["success"] is True, result
    assert result["state"] == "needs_login"
    assert spawned == []
    assert not any(a[0] == "tailscaled" for a in cli.argvs)


async def test_connect_with_the_runtime_container_down_says_so_quickly(
    run_dir, monkeypatch, caplog
):
    spawned = _no_local_daemon(monkeypatch)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _FakeCli(rc=0, stdout=b"1.104.5"))
    monkeypatch.setattr(vpn_integration, "TAILSCALE_START_WAIT_SECONDS", 1.0)
    caplog.set_level(logging.DEBUG, logger="app.services.vpn_integration")

    started = time.monotonic()
    result = await TailscaleSetupService().start_daemon()

    assert time.monotonic() - started < 5
    assert result["success"] is False
    assert "docker compose ps tailscale" in result["message"]
    # The request stays, so the container starts Tailscale when it comes up.
    assert (run_dir / "freesdn-start-requested").exists()
    assert spawned == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


async def test_connect_without_the_run_volume_explains_the_mount(run_dir, monkeypatch):
    spawned = _no_local_daemon(monkeypatch)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _FakeCli(rc=0, stdout=b"1.104.5"))
    monkeypatch.setattr(
        vpn_integration, "TAILSCALE_START_REQUEST", str(run_dir / "absent" / "request")
    )
    result = await TailscaleSetupService().start_daemon()
    assert result["success"] is False
    assert "tailscale_run" in result["message"]
    assert spawned == []


async def test_connect_in_sidecar_mode_starts_nothing(run_dir, monkeypatch):
    """The vpn container owns tailscaled there; neither the api nor the runtime
    container may start a second daemon on the same node state."""
    spawned = _no_local_daemon(monkeypatch)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _FakeCli(rc=0, stdout=b"1.104.5"))
    monkeypatch.setenv("VPN_MODE", "sidecar")
    result = await TailscaleSetupService().start_daemon()
    assert result["success"] is False
    assert "vpn" in result["message"]
    assert not (run_dir / "freesdn-start-requested").exists()
    assert spawned == []


async def test_connect_when_already_running_changes_nothing(run_dir, monkeypatch):
    spawned = _no_local_daemon(monkeypatch)
    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        _FakeCli(rc=0, stdout=b'{"BackendState": "Running", "Self": {}, "Peer": {}}'),
    )
    async with _listening(run_dir / "tailscaled.sock"):
        result = await TailscaleSetupService().start_daemon()
    assert result["success"] is True and "already running" in result["message"]
    assert not (run_dir / "freesdn-start-requested").exists()
    assert spawned == []


# ── the in-container supervisor stays out of the runtime container's way ────


def test_the_supervisor_refuses_when_the_runtime_container_owns_tailscaled(monkeypatch, tmp_path):
    from app import tailscaled_supervisor as sup

    for name in ("VPN_MODE", "FREESDN_OPENVPN_SIDECAR", "FREESDN_WIREGUARD_SIDECAR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sup, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sup, "RUN_DIR", str(tmp_path))
    monkeypatch.setattr(sup.shutil, "which", lambda _b: "/usr/local/bin/tailscaled")
    monkeypatch.setenv("TAILSCALE_RUNTIME", "container")
    assert "runtime container" in (sup.preflight() or "")
    monkeypatch.delenv("TAILSCALE_RUNTIME")
    assert sup.preflight() is None


@pytest.mark.parametrize(
    ("value", "flag"), [(None, False), ("false", False), ("true", True), ("1", True)]
)
def test_the_supervisor_honours_the_log_upload_setting(monkeypatch, value, flag):
    from app import tailscaled_supervisor as sup

    if value is None:
        monkeypatch.delenv("TAILSCALE_NO_LOGS_NO_SUPPORT", raising=False)
    else:
        monkeypatch.setenv("TAILSCALE_NO_LOGS_NO_SUPPORT", value)
    assert ("--no-logs-no-support" in sup.tailscaled_argv()) is flag
