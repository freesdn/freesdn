# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""``GET /vpn/runtime`` reports tailscaled reachable only when it answers.

``sidecar_reachable`` used to be ``os.path.exists`` on the LocalAPI socket. A
tailscaled that was killed or crashed leaves that socket file on the volume
(the runtime container's healthcheck says so too), so a dead daemon read as
reachable for as long as the file stayed. It is now the same fast connect the
Tailscale status reads make before running the CLI.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import sys
import time

import pytest

from app.api.v1.endpoints import vpn as vpn_api
from app.services import vpn_integration

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="unix sockets")


@pytest.fixture
def sock(tmp_path, monkeypatch):
    path = tmp_path / "tailscaled.sock"
    monkeypatch.setattr(vpn_integration, "TAILSCALE_SOCKET", str(path))
    return path


def _stale_socket(path) -> None:
    """What a killed tailscaled leaves behind: the file, and nobody listening."""
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


async def test_a_socket_file_left_by_a_dead_daemon_is_not_reachable(sock):
    """Fails on the old code: the file exists, so it said reachable."""
    _stale_socket(sock)
    assert sock.exists()

    started = time.monotonic()
    body = await vpn_api.get_vpn_runtime(user=None)

    assert body["sidecar_reachable"] is False
    assert time.monotonic() - started < 1.0, "a refused connect must answer at once"


async def test_a_daemon_that_accepts_is_reachable(sock):
    async with _listening(sock):
        body = await vpn_api.get_vpn_runtime(user=None)
    assert body["sidecar_reachable"] is True


async def test_no_socket_at_all_is_not_reachable(sock):
    body = await vpn_api.get_vpn_runtime(user=None)
    assert body["sidecar_reachable"] is False
    assert set(body) == {"enabled", "mode", "sidecar_reachable", "tun_available"}


async def test_the_probe_failing_does_not_fail_the_endpoint(sock, monkeypatch):
    async def boom() -> bool:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(vpn_api, "_tailscaled_answers", boom)
    body = await vpn_api.get_vpn_runtime(user=None)
    assert body["sidecar_reachable"] is False
