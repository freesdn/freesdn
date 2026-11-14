# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Deleting one agent revokes that agent's access, and nobody else's.

``PersistentAgentService.soft_delete_agent`` looked up every WireGuard
``SiteVPNConfiguration`` of the deleted agent's SITE and tombstoned each one:
peer key, endpoint and allowed IPs cleared, ``enabled=False``,
``status="revoked"``. That row is the site's VPN connection, not the agent's:
nothing links a WireGuard config to an agent (the agent model has no WireGuard
key, and ``/vpn/wireguard/provision-agent`` takes no agent id), and a brain-VPN
import stores the brain server's key in the same column. So removing any one
agent switched the whole site's WireGuard link off, for the site's other agents
and for FreeSDN itself.

Meanwhile the deleted agent's own live WebSocket stayed registered, so commands
for the site could still be routed to it until it happened to disconnect.

Real PostgreSQL through the ``db_session`` savepoint fixture; the request goes
through the real ``DELETE /agents/{id}`` endpoint.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import agents as agents_endpoint
from app.core.security import create_access_token, get_password_hash
from app.db.session import get_logdb_session, get_session
from app.main import app
from app.models.agents import RemoteAgent
from app.models.core import Organization, Site, User
from app.models.vpn import SiteVPNConfiguration
from app.services.remote_agent import AgentRegistryService

PEER_KEY = "Q" * 43 + "="


async def _agent(db: AsyncSession, site: Site, name: str) -> RemoteAgent:
    agent = RemoteAgent(
        id=uuid4(),
        agent_key=hashlib.sha256(uuid4().bytes).hexdigest(),
        name=name,
        site_id=site.id,
        organization_id=site.organization_id,
        is_enabled=True,
        is_approved=True,
    )
    db.add(agent)
    await db.flush()
    return agent


class _LiveConnection:
    """Stands in for a registered agent socket; records being stopped."""

    def __init__(self) -> None:
        self.stopped = False
        self.info = MagicMock()

    async def stop(self) -> None:
        self.stopped = True


@pytest.fixture
async def site_world(db_session: AsyncSession) -> AsyncIterator[Any]:
    org = Organization(id=uuid4(), name="Agent delete probe", slug="agent-del-" + uuid4().hex[:10])
    db_session.add(org)
    await db_session.flush()
    site = Site(id=uuid4(), organization_id=org.id, name="Branch", slug="br-" + uuid4().hex[:8])
    db_session.add(site)
    await db_session.flush()
    admin = User(
        id=uuid4(),
        email=f"agent-del-{uuid4().hex[:8]}@example.com",
        username=f"agent-del-{uuid4().hex[:8]}",
        hashed_password=get_password_hash("Agent-Delete-Passw0rd!"),
        role="org_admin",
        is_active=True,
        is_verified=True,
        organization_id=org.id,
    )
    db_session.add(admin)
    leaving = await _agent(db_session, site, "leaving")
    staying = await _agent(db_session, site, "staying")
    wg = SiteVPNConfiguration(
        id=uuid4(),
        site_id=site.id,
        organization_id=org.id,
        vpn_type="wireguard",
        enabled=True,
        wireguard_interface="wg0",
        wireguard_peer_public_key=PEER_KEY,
        wireguard_endpoint="203.0.113.7:51820",
        wireguard_allowed_ips=["10.100.0.2/32", "10.20.0.0/24"],
        status="connected",
    )
    db_session.add(wg)
    await db_session.flush()

    registry = AgentRegistryService(db_session)
    leaving_conn, staying_conn = _LiveConnection(), _LiveConnection()
    registry._connections[str(leaving.id)] = leaving_conn  # type: ignore[assignment]
    registry._connections[str(staying.id)] = staying_conn  # type: ignore[assignment]
    previous_registry = agents_endpoint._agent_registry
    agents_endpoint._agent_registry = registry

    logdb = MagicMock()
    logdb.execute = AsyncMock()
    logdb.commit = AsyncMock()

    async def _session() -> AsyncIterator[AsyncSession]:
        yield db_session

    async def _logdb() -> AsyncIterator[Any]:
        yield logdb

    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_logdb_session] = _logdb
    try:
        yield type(
            "World",
            (),
            {
                "db": db_session,
                "token": create_access_token(str(admin.id), token_version=admin.token_version),
                "leaving": leaving,
                "staying": staying,
                "wg": wg,
                "registry": registry,
                "leaving_conn": leaving_conn,
                "staying_conn": staying_conn,
            },
        )
    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_logdb_session, None)
        agents_endpoint._agent_registry = previous_registry


async def _delete(world: Any, agent: RemoteAgent) -> Any:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.delete(
            f"/api/v1/agents/{agent.id}", headers={"Authorization": f"Bearer {world.token}"}
        )


async def test_deleting_one_agent_leaves_the_sites_wireguard_link_alone(site_world: Any) -> None:
    response = await _delete(site_world, site_world.leaving)
    assert response.status_code == 200, response.text

    db, wg_id = site_world.db, site_world.wg.id
    db.expire_all()
    wg = (
        await db.execute(select(SiteVPNConfiguration).where(SiteVPNConfiguration.id == wg_id))
    ).scalar_one()
    assert (wg.enabled, wg.status) == (True, "connected"), (
        "deleting one agent switched off the site's WireGuard connection"
    )
    assert wg.wireguard_peer_public_key == PEER_KEY
    assert wg.wireguard_endpoint == "203.0.113.7:51820"
    assert wg.wireguard_allowed_ips == ["10.100.0.2/32", "10.20.0.0/24"]


async def test_the_other_agent_at_the_site_keeps_working(site_world: Any) -> None:
    response = await _delete(site_world, site_world.leaving)
    assert response.status_code == 200, response.text

    db, leaving_id, staying_id = site_world.db, site_world.leaving.id, site_world.staying.id
    db.expire_all()
    rows = {
        a.id: a
        for a in (
            await db.execute(
                select(RemoteAgent)
                .where(RemoteAgent.id.in_([leaving_id, staying_id]))
                .execution_options(include_deleted=True)
            )
        ).scalars()
    }
    assert rows[leaving_id].deleted_at is not None
    assert rows[staying_id].deleted_at is None
    assert rows[staying_id].is_enabled is True
    assert site_world.staying_conn.stopped is False
    assert site_world.registry.get_connection(str(staying_id)) is not None


async def test_the_deleted_agents_live_socket_is_dropped(site_world: Any) -> None:
    response = await _delete(site_world, site_world.leaving)
    assert response.status_code == 200, response.text

    assert site_world.leaving_conn.stopped is True, (
        "the deleted agent's live socket is still registered and can still be sent commands"
    )
    assert site_world.registry.get_connection(str(site_world.leaving.id)) is None
