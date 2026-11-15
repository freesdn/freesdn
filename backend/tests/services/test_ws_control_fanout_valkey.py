# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Closing sockets reaches every API process (real Valkey, two subscribers).

Each API process holds its own realtime sockets and its own edge agent
sockets. Retiring an organization closed none of its members' sockets (they
lasted until the next revalidation, up to five minutes, and a database error
during that revalidation kept them open), and deleting an agent dropped its
socket only on the process that handled the delete.

Two cross-instance buses on the run's Valkey stand for two API processes: the
request lands on A, the socket is held by B, and B runs the real control
handler against its own connection table and agent registry.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from app.api.v1.endpoints import agents as agents_endpoint
from app.api.v1.endpoints import websocket as ws
from app.core.config import settings
from app.services import websocket_pubsub
from app.services.websocket_pubsub import _CONTROL_CHANNEL, WSCrossInstanceBus


class _Socket:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.closed_with: int | None = None

    async def send_json(self, message: dict[str, Any]) -> None:
        self.sent.append(message)

    async def close(self, code: int = 1000) -> None:
        self.closed_with = code


class _Registry:
    def __init__(self) -> None:
        self.live: set[str] = set()

    async def unregister_connection(self, agent_id: str) -> None:
        self.live.discard(agent_id)


def _hold(connections: ws.ConnectionManager, org_id: str, role: str = "operator") -> _Socket:
    sock, cid, uid = _Socket(), uuid4().hex, uuid4().hex
    connections._connections[cid] = ws.ConnectionInfo(
        websocket=sock, user_id=uid, organization_id=org_id, role=role
    )
    connections._user_connections[uid] = {cid}
    return sock


async def _until(predicate: Callable[[], bool], seconds: float = 5.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    while not predicate():
        if loop.time() > deadline:
            return False
        await asyncio.sleep(0.02)
    return True


@pytest.fixture
async def processes(monkeypatch: pytest.MonkeyPatch):
    if not settings.REDIS_URL:
        pytest.skip("needs the run's Valkey")
    from app.core.redis_client import get_async_redis

    a, b = ws.ConnectionManager(), ws.ConnectionManager()
    a_agents, b_agents = _Registry(), _Registry()
    # This test process is A: the request is handled here.
    monkeypatch.setattr(ws, "manager", a)
    monkeypatch.setattr(agents_endpoint, "_agent_registry", a_agents)

    async def b_control(payload: dict[str, Any]) -> None:
        with monkeypatch.context() as m:
            m.setattr(ws, "manager", b)
            m.setattr(agents_endpoint, "_agent_registry", b_agents)
            await ws.handle_ws_control(payload)

    a_echoes: list[dict[str, Any]] = []

    async def a_control(payload: dict[str, Any]) -> None:
        a_echoes.append(payload)

    a_bus = WSCrossInstanceBus(str(settings.REDIS_URL))
    b_bus = WSCrossInstanceBus(str(settings.REDIS_URL))
    await a_bus.connect(on_targeted=AsyncMock(), on_control=a_control)
    await b_bus.connect(on_targeted=AsyncMock(), on_control=b_control)
    monkeypatch.setattr(websocket_pubsub, "_singleton", a_bus)
    probe = get_async_redis()
    try:
        # Both subscriptions are live on the server before anything publishes.
        for _ in range(100):
            (_, count), *_ = await probe.pubsub_numsub(_CONTROL_CHANNEL)
            if count >= 2:
                break
            await asyncio.sleep(0.02)
        assert count >= 2, "the two subscribers never reached Valkey"
        yield SimpleNamespace(a=a, b=b, a_agents=a_agents, b_agents=b_agents, a_echoes=a_echoes)
    finally:
        await a_bus.disconnect()
        await b_bus.disconnect()
        await probe.aclose()


async def test_retiring_an_org_closes_its_members_sockets_on_every_process(processes) -> None:
    from app.core.organization_access import close_retired_organization_sockets

    org, other = str(uuid4()), str(uuid4())
    on_a = _hold(processes.a, org)
    on_b = _hold(processes.b, org)
    admin_on_b = _hold(processes.b, org, role="super_admin")
    bystander_on_b = _hold(processes.b, other)

    await close_retired_organization_sockets(UUID(org))

    assert on_a.closed_with == 1008
    assert await _until(lambda: on_b.closed_with == 1008), "B kept the member's socket open"
    assert on_b.sent and on_b.sent[0]["type"] == "session_revoked"
    assert admin_on_b.closed_with is None, "a super admin's socket was closed"
    assert bystander_on_b.closed_with is None, "another organization's socket was closed"
    assert len(processes.b._connections) == 2
    assert processes.a_echoes == [], "A carried out its own order twice"


async def test_deleting_an_agent_drops_its_socket_on_every_process(
    processes, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent_id = uuid4()
    processes.a_agents.live.add(str(agent_id))
    processes.b_agents.live.add(str(agent_id))

    class _Agents:
        def __init__(self, _session: Any) -> None:
            pass

        async def soft_delete_agent(self, *_args: Any, **_kwargs: Any) -> bool:
            return True

    monkeypatch.setattr(agents_endpoint, "_verify_agent_org", AsyncMock())
    monkeypatch.setattr(agents_endpoint, "_org_id", lambda _user: uuid4())
    monkeypatch.setattr(agents_endpoint, "PersistentAgentService", _Agents)

    await agents_endpoint.delete_agent(
        agent_id, current_user=SimpleNamespace(), session=AsyncMock(), logdb=AsyncMock()
    )

    assert str(agent_id) not in processes.a_agents.live
    assert await _until(lambda: str(agent_id) not in processes.b_agents.live), (
        "the deleted agent's socket on the other process was left open"
    )


async def test_the_recheck_fails_closed_when_the_database_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextlib.asynccontextmanager
    async def _down():
        raise ConnectionRefusedError("database unreachable")
        yield  # pragma: no cover

    monkeypatch.setattr("app.db.async_session_factory", _down)
    info = ws.ConnectionInfo(websocket=None, user_id=str(uuid4()), organization_id=str(uuid4()))

    assert await ws._revalidate_ws_session(info) is False
