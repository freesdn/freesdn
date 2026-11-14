# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Auto-reconnect runs ``tailscale up`` only when it can be a reconnect.

``vpn.auto_reconnect`` (every minute, in a worker) used to run a bare
``tailscale up`` for every Tailscale connection that was not connected:

* with nothing behind tailscaled's socket (its runtime container stopped or
  restarting) the CLI spent about two seconds failing on each retry, and the
  attempt's recorded error was a socket message;
* with the node logged out (NeedsLogin) a bare ``up`` is a fresh login: the
  CLI asks Tailscale for a login URL, blocks for the 30 s timeout, and resets
  the node's preferences to their defaults (Tailscale 1.104.5 up.go).

Both now fail the attempt at once with an operator-readable reason, and no CLI
runs. The backoff and failover state machine is unchanged.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import sys
from types import SimpleNamespace

import pytest

from app.services import vpn_integration, vpn_reconnect
from app.services.vpn_reconnect import VPNReconnectService

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="unix sockets")


class _Cli:
    """asyncio.create_subprocess_exec stand-in: answers `status --json` with
    the given BackendState and records every argv."""

    def __init__(self, backend_state: str = "Stopped"):
        self.argvs: list[tuple[str, ...]] = []
        self.backend_state = backend_state

    async def __call__(self, *argv, **_kw):
        argv = tuple(str(a) for a in argv)
        self.argvs.append(argv)
        out = b""
        if argv[1:3] == ("status", "--json"):
            status = {"BackendState": self.backend_state, "Self": None, "Peer": None}
            out = json.dumps(status).encode()

        class _P:
            returncode = 0

            async def communicate(self):
                return out, b""

            def kill(self):
                pass

            async def wait(self):
                return 0

        return _P()

    def ups(self) -> list[tuple[str, ...]]:
        return [a for a in self.argvs if a[1:2] == ("up",)]


@pytest.fixture
def sock(tmp_path, monkeypatch):
    path = tmp_path / "tailscaled.sock"
    monkeypatch.setattr(vpn_integration, "TAILSCALE_SOCKET", str(path))
    # A fresh manager: no status cached by an earlier test.
    monkeypatch.setattr(vpn_integration, "_vpn_manager", None)
    return path


@pytest.fixture
def cli(monkeypatch):
    fake = _Cli()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
    return fake


def _stale_socket(path) -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(path))
    s.close()


@contextlib.asynccontextmanager
async def _listening(path):
    server = await asyncio.start_unix_server(lambda _r, w: w.close(), path=str(path))
    try:
        yield
    finally:
        server.close()
        await server.wait_closed()


CONN = SimpleNamespace(vpn_type="tailscale", name="tailnet", organization_id=None)
CONFIG = SimpleNamespace(vpn_type="tailscale", wireguard_interface=None, openvpn_config_path=None)


def _svc() -> VPNReconnectService:
    return VPNReconnectService(session=None)  # type: ignore[arg-type]


# ── nothing behind the socket ────────────────────────────────────────────────


@pytest.mark.parametrize("socket_file", ["missing", "stale"])
async def test_reconnect_without_a_daemon_runs_no_cli(sock, cli, socket_file):
    """Fails on the old code: it ran `tailscale up` against nobody."""
    if socket_file == "stale":
        _stale_socket(sock)

    ok, error = await _svc()._attempt_reconnect(CONN)

    assert not ok
    assert error == vpn_reconnect.TAILSCALE_NOT_RUNNING
    assert cli.argvs == [], f"ran {cli.argvs} with no tailscaled behind the socket"


async def test_failover_to_tailscale_without_a_daemon_runs_no_cli(sock, cli):
    ok, error = await _svc()._attempt_reconnect_with_config(CONN, CONFIG)

    assert not ok
    assert error == vpn_reconnect.TAILSCALE_NOT_RUNNING
    assert cli.ups() == []


# ── logged out ───────────────────────────────────────────────────────────────


async def test_a_logged_out_node_is_not_sent_into_a_fresh_login(sock, cli):
    """Fails on the old code: NeedsLogin is "not connected", so it ran a bare up."""
    cli.backend_state = "NeedsLogin"
    async with _listening(sock):
        ok, error = await _svc()._attempt_reconnect(CONN)
        failover_ok, failover_error = await _svc()._attempt_reconnect_with_config(CONN, CONFIG)

    assert not ok and not failover_ok
    assert error == failover_error == vpn_reconnect.TAILSCALE_NEEDS_LOGIN
    assert cli.ups() == []


# ── the cases that should reconnect still do ─────────────────────────────────


async def test_a_disconnected_node_gets_a_bare_up(sock, cli):
    cli.backend_state = "Stopped"  # logged in, `tailscale down`
    async with _listening(sock):
        ok, error = await _svc()._attempt_reconnect(CONN)

    assert ok and error is None
    assert cli.ups() == [("tailscale", "up")], "anything but a bare `up` resets prefs"


async def test_a_connected_node_needs_nothing(sock, cli):
    cli.backend_state = "Running"
    async with _listening(sock):
        ok, error = await _svc()._attempt_reconnect(CONN)
        failover_ok, _ = await _svc()._attempt_reconnect_with_config(CONN, CONFIG)

    assert ok and failover_ok and error is None
    assert cli.ups() == []
