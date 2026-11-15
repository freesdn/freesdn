# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A retired organization's edge agents stop authenticating.

An agent's key belongs to the organization that registered it, the same way a
user's password does. The three agent authenticators (``verify_credentials``
behind the REST endpoints, the agent WebSocket and ``/agents/auth/verify``; the
self-update check; the release download) checked the agent row only, so after
its organization was deleted or deactivated an agent kept heartbeating, kept
reporting syslog and SNMP traps, kept receiving commands and kept downloading
releases.

Real PostgreSQL through the ``db_session`` savepoint fixture.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import RemoteAgent
from app.models.core import Organization, Site
from app.services.remote_agent import PersistentAgentService

RETIREMENTS = pytest.mark.parametrize("how", ["deleted", "deactivated"])


async def _agent(db: AsyncSession) -> tuple[Organization, RemoteAgent, str]:
    org = Organization(id=uuid4(), name="Agent org probe", slug="agent-org-" + uuid4().hex[:10])
    db.add(org)
    await db.flush()
    site = Site(id=uuid4(), organization_id=org.id, name="Edge", slug="e-" + uuid4().hex[:8])
    db.add(site)
    await db.flush()
    key = secrets.token_urlsafe(32)
    agent = RemoteAgent(
        id=uuid4(),
        agent_key=hashlib.sha256(key.encode()).hexdigest(),
        name="edge",
        site_id=site.id,
        organization_id=org.id,
        is_enabled=True,
        is_approved=True,
    )
    db.add(agent)
    await db.flush()
    return org, agent, key


async def _retire(db: AsyncSession, org: Organization, how: str) -> None:
    if how == "deleted":
        org.deleted_at = datetime.now(UTC)
    else:
        org.is_active = False
    await db.flush()


@RETIREMENTS
async def test_the_agent_key_is_refused(db_session: AsyncSession, how: str) -> None:
    """REST agent endpoints, the agent WebSocket and /agents/auth/verify."""
    org, agent, key = await _agent(db_session)
    svc = PersistentAgentService(db_session)
    assert await svc.verify_credentials(agent.id, key) is agent
    await _retire(db_session, org, how)

    assert await svc.verify_credentials(agent.id, key) is None


@RETIREMENTS
async def test_the_update_check_is_refused(db_session: AsyncSession, how: str) -> None:
    from app.api.v1.endpoints.agent_downloads import _authenticate_agent_for_update_check

    org, agent, key = await _agent(db_session)
    assert await _authenticate_agent_for_update_check(db_session, str(agent.id), key) is agent
    await _retire(db_session, org, how)

    with pytest.raises(HTTPException) as refused:
        await _authenticate_agent_for_update_check(db_session, str(agent.id), key)
    assert refused.value.status_code == 401
    assert refused.value.detail == "Agent authentication required"


@RETIREMENTS
async def test_the_release_download_is_refused(db_session: AsyncSession, how: str) -> None:
    from app.api.v1.endpoints.agent_release_upload import _authenticate_release_download

    org, agent, key = await _agent(db_session)
    assert await _authenticate_release_download(db_session, str(agent.id), key) is agent
    await _retire(db_session, org, how)

    with pytest.raises(HTTPException) as refused:
        await _authenticate_release_download(db_session, str(agent.id), key)
    assert refused.value.status_code == 401
    assert refused.value.detail == "Agent authentication required"
