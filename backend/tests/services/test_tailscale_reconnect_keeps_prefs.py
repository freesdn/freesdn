# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reconnect keeps the node's name and every other Tailscale preference.

``TailscaleSetupService.reconnect()`` (the Reconnect button, the connection
list's Connect action and the staged ``overlay.tailscale.reconnect``) ran
``tailscale up --accept-routes --reset``. ``--reset`` sets every preference not
on the command line back to its default. Measured with the pinned 1.104.5
binaries, offline, on a logged-in node after ``tailscale down`` with
``--hostname=my-office``, an advertised route, shields-up and accept-dns off:

* ``tailscale up --accept-routes --reset``: Hostname "", AdvertiseRoutes null,
  ShieldsUp false, CorpDNS true (all defaults; the node takes the container's
  hostname on the tailnet);
* bare ``tailscale up``: all four kept, WantRunning true.

A bare ``up`` is the CLI's own reconnect; any flag (``--timeout`` too) turns
that path off. The NetBird netfilter mode now goes through ``tailscale set``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys

import pytest

from app.services import vpn_integration
from app.services.vpn_integration import TailscaleSetupService

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="unix sockets")


class _Cli:
    def __init__(self, backend_state: str = "Stopped"):
        self.argvs: list[tuple[str, ...]] = []
        self.backend_state = backend_state

    async def __call__(self, *argv, **_kw):
        argv = tuple(str(a) for a in argv)
        self.argvs.append(argv)
        out = b""
        if argv[1:3] == ("status", "--json"):
            out = json.dumps({"BackendState": self.backend_state, "Self": None}).encode()

        class _P:
            returncode = 0

            async def communicate(self):
                return out, b""

            def kill(self):
                pass

            async def wait(self):
                return 0

        return _P()

    def calls(self, verb: str) -> list[tuple[str, ...]]:
        return [a for a in self.argvs if a[1:2] == (verb,)]


@pytest.fixture
def sock(tmp_path, monkeypatch):
    path = tmp_path / "tailscaled.sock"
    monkeypatch.setattr(vpn_integration, "TAILSCALE_SOCKET", str(path))
    monkeypatch.setattr(
        vpn_integration, "TAILSCALE_START_REQUEST", str(tmp_path / "freesdn-start-requested")
    )
    return path


@pytest.fixture
def cli(monkeypatch):
    fake = _Cli()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)

    real_sleep = asyncio.sleep

    async def no_wait(_seconds):
        await real_sleep(0)

    # reconnect waits 2 s for the link to settle before reading the status.
    monkeypatch.setattr(vpn_integration.asyncio, "sleep", no_wait)
    return fake


@contextlib.asynccontextmanager
async def _listening(path):
    server = await asyncio.start_unix_server(lambda _r, w: w.close(), path=str(path))
    try:
        yield
    finally:
        server.close()
        await server.wait_closed()


async def test_reconnect_is_a_bare_up_that_resets_nothing(sock, cli):
    """Fails on the old code: it ran `tailscale up --accept-routes --reset`."""
    async with _listening(sock):
        result = await TailscaleSetupService().reconnect()

    assert result["success"] is True
    assert cli.calls("up") == [("tailscale", "up")]
    assert not any("--reset" in a for argv in cli.argvs for a in argv)
    assert not any(a.startswith("--hostname") for argv in cli.argvs for a in argv), (
        "a bare up keeps the hostname pref; passing one would be guessing it"
    )


@pytest.mark.parametrize("mode", ["off", "nodivert", "on"])
async def test_the_netbird_netfilter_mode_is_set_on_its_own_first(sock, cli, mode):
    async with _listening(sock):
        result = await TailscaleSetupService().reconnect(netfilter_mode=mode)

    assert result["success"] is True
    assert cli.calls("set") == [("tailscale", "set", f"--netfilter-mode={mode}")]
    assert cli.calls("up") == [("tailscale", "up")]
    assert cli.argvs.index(cli.calls("set")[0]) < cli.argvs.index(cli.calls("up")[0])


async def test_an_unknown_netfilter_mode_is_not_passed(sock, cli):
    async with _listening(sock):
        await TailscaleSetupService().reconnect(netfilter_mode="--operator=root")
    assert cli.calls("set") == []


async def test_a_logged_out_node_is_refused_not_logged_in_afresh(sock, cli):
    """A bare `up` on a NeedsLogin node is a new login with default prefs."""
    cli.backend_state = "NeedsLogin"
    async with _listening(sock):
        result = await TailscaleSetupService().reconnect(netfilter_mode="off")

    assert result["success"] is False
    assert result["state"] == "needs_login"
    assert cli.calls("up") == [] and cli.calls("set") == []


async def test_no_daemon_means_no_cli(sock, cli, monkeypatch):
    monkeypatch.setenv("TAILSCALE_RUNTIME", "container")
    for name in ("VPN_MODE", "FREESDN_OPENVPN_SIDECAR", "FREESDN_WIREGUARD_SIDECAR"):
        monkeypatch.delenv(name, raising=False)

    result = await TailscaleSetupService().reconnect()

    assert result["success"] is False
    assert result["state"] == "daemon_stopped"
    assert "not running" in result["message"]
    assert cli.argvs == []
