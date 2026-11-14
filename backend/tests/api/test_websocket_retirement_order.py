# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Retiring an organization cuts its live sockets off at once, however they behave.

The sockets were closed one after another, each a send and a close with their
own five-second timeouts, every connection stayed registered (and so kept
receiving broadcasts) until its turn, and the other API processes were told
only after the whole local loop. A few stalled sockets delayed all of it.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from app.api.v1.endpoints import websocket as ws

_ORG = "0b5e3a52-6f43-4f8e-9d6a-3c2f1d7e8a90"
_TIMEOUT = 0.2


class _StalledSocket:
    """A socket whose peer stopped reading: every send and close hangs."""

    def __init__(self, manager: ws.ConnectionManager, cid: str) -> None:
        self.manager = manager
        self.cid = cid
        self.registered_when_used: bool | None = None
        self.touched = False

    async def send_json(self, _message: dict[str, Any]) -> None:
        self.touched = True
        self.registered_when_used = self.cid in self.manager._connections
        await asyncio.Event().wait()

    async def close(self, code: int = 1000) -> None:
        await asyncio.Event().wait()


@pytest.fixture
def stalled(monkeypatch: pytest.MonkeyPatch) -> tuple[ws.ConnectionManager, list[_StalledSocket]]:
    manager = ws.ConnectionManager()
    monkeypatch.setattr(manager, "_BROADCAST_SEND_TIMEOUT_SECONDS", _TIMEOUT)
    sockets = []
    for n in range(5):
        cid = f"member-{n}"
        socket = _StalledSocket(manager, cid)
        manager._connections[cid] = ws.ConnectionInfo(
            websocket=socket, user_id=f"user-{n}", organization_id=_ORG, role="viewer"
        )
        manager._user_connections[f"user-{n}"] = {cid}
        sockets.append(socket)
    return manager, sockets


async def test_stalled_sockets_are_closed_together_not_in_turn(stalled) -> None:
    manager, sockets = stalled
    started = time.monotonic()
    closed = await manager.close_organization_local(_ORG)
    elapsed = time.monotonic() - started

    assert closed == 5
    # One send timeout plus one close timeout in all, not five of each.
    assert elapsed < 4 * _TIMEOUT, f"took {elapsed:.2f}s"
    assert manager._connections == {} and manager._user_connections == {}


async def test_no_retired_socket_stays_registered_while_it_is_closed(stalled) -> None:
    manager, sockets = stalled
    await manager.close_organization_local(_ORG)
    assert all(s.registered_when_used is False for s in sockets), [
        s.registered_when_used for s in sockets
    ]


async def test_other_processes_are_told_before_the_local_sockets_close(
    stalled, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, sockets = stalled
    seen: dict[str, Any] = {}

    class _Bus:
        async def publish_control(self, payload: dict[str, Any]) -> None:
            seen["payload"] = payload
            seen["registered"] = dict(manager._connections)
            seen["touched"] = [s.touched for s in sockets]

    import app.services.websocket_pubsub as pubsub

    monkeypatch.setattr(pubsub, "get_ws_pubsub", lambda: _Bus())
    await manager.close_organization(_ORG)

    assert seen["payload"] == {"kind": "organization_retired", "organization_id": _ORG}
    assert seen["registered"] == {}, "broadcast-eligible while the others were told"
    assert seen["touched"] == [False] * 5, "the others waited on local socket shutdown"
