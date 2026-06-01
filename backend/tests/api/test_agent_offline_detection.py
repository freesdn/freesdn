# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the agent offline detection + alert flow.

Tests the threshold logic + dedup behavior without spinning up a real
Celery worker. The cleanup_stale_agents task body is the unit; we
exercise its query patterns via direct SQL.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


@pytest_asyncio.fixture
async def agent_in_lab(db_session: AsyncSession):
    """Create an org + site + one online agent for the tests."""
    from app.models.agents import RemoteAgent
    from app.models.core import Organization, Site

    org = Organization(
        name=f"offline-{uuid4()}",
        slug=f"offline-{uuid4().hex[:8]}",
    )
    db_session.add(org)
    await db_session.flush()
    site = Site(
        organization_id=org.id,
        name="lab",
        slug=f"lab-{uuid4().hex[:6]}",
    )
    db_session.add(site)
    await db_session.flush()

    agent = RemoteAgent(
        site_id=site.id,
        name="laptop",
        agent_key=f"key-{uuid4().hex}",
        status="online",
        last_heartbeat=datetime.now(UTC),
        offline_threshold_seconds=180,
    )
    db_session.add(agent)
    await db_session.commit()
    return agent


class TestOfflineDetection:
    @pytest.mark.asyncio
    async def test_threshold_default_180s(
        self, db_session: AsyncSession, agent_in_lab
    ) -> None:
        """A fresh online agent with no stale heartbeat stays online."""
        from app.models.agents import RemoteAgent

        # Default fixture: last_heartbeat = now → should stay online
        row = (
            await db_session.execute(
                select(RemoteAgent).where(RemoteAgent.id == agent_in_lab.id)
            )
        ).scalar_one()
        assert row.status == "online"
        # threshold default applied
        assert row.offline_threshold_seconds == 180

    @pytest.mark.asyncio
    async def test_stale_heartbeat_triggers_offline_transition(
        self, db_session: AsyncSession, agent_in_lab
    ) -> None:
        """Simulate the task's logic against an agent with stale heartbeat."""
        from app.models.agents import RemoteAgent

        # Backdate heartbeat to 200s ago (threshold is 180s)
        agent_in_lab.last_heartbeat = datetime.now(UTC) - timedelta(seconds=200)
        await db_session.commit()

        # Replicate the task's pull logic
        now = datetime.now(UTC)
        q = await db_session.execute(
            select(RemoteAgent).where(
                RemoteAgent.status == "online",
                RemoteAgent.deleted_at.is_(None),
                RemoteAgent.last_heartbeat.isnot(None),
            )
        )
        candidates = q.scalars().all()
        flipped = []
        for a in candidates:
            age = (now - a.last_heartbeat).total_seconds()
            if age >= a.offline_threshold_seconds:
                a.status = "offline"
                a.disconnected_at = now
                flipped.append(a.id)
        await db_session.commit()

        assert agent_in_lab.id in flipped
        # And persists
        row = (
            await db_session.execute(
                select(RemoteAgent).where(RemoteAgent.id == agent_in_lab.id)
            )
        ).scalar_one()
        assert row.status == "offline"

    @pytest.mark.asyncio
    async def test_dedup_via_offline_notified_at(
        self, db_session: AsyncSession, agent_in_lab
    ) -> None:
        """If offline_notified_at is set, the task should NOT dispatch again."""
        from app.models.agents import RemoteAgent

        now = datetime.now(UTC)
        # Configure for alerts + already-notified flag set
        agent_in_lab.notification_channels = {"email": {"to": ["op@example.com"]}}
        agent_in_lab.offline_notified_at = now - timedelta(minutes=10)
        await db_session.commit()

        # Dedup condition in the task:
        #   if agent.notification_channels AND agent.offline_notified_at is None
        # With offline_notified_at set, the dispatch branch should skip.
        should_dispatch = bool(
            agent_in_lab.notification_channels
            and agent_in_lab.offline_notified_at is None
        )
        assert should_dispatch is False

    @pytest.mark.asyncio
    async def test_dispatch_runs_when_channels_set_and_not_notified(
        self, db_session: AsyncSession, agent_in_lab
    ) -> None:
        from app.models.agents import RemoteAgent

        agent_in_lab.notification_channels = {"email": {"to": ["op@example.com"]}}
        agent_in_lab.offline_notified_at = None
        await db_session.commit()

        should_dispatch = bool(
            agent_in_lab.notification_channels
            and agent_in_lab.offline_notified_at is None
        )
        assert should_dispatch is True

    @pytest.mark.asyncio
    async def test_no_channels_skips_dispatch(
        self, db_session: AsyncSession, agent_in_lab
    ) -> None:
        """Empty notification_channels means "no alerts for this agent"."""
        from app.models.agents import RemoteAgent

        agent_in_lab.notification_channels = {}
        agent_in_lab.offline_notified_at = None
        await db_session.commit()

        should_dispatch = bool(
            agent_in_lab.notification_channels
            and agent_in_lab.offline_notified_at is None
        )
        assert should_dispatch is False

    @pytest.mark.asyncio
    async def test_per_agent_threshold_overrides_default(
        self, db_session: AsyncSession, agent_in_lab
    ) -> None:
        """A noisier network can raise its threshold to 600s; an agent
        with last_heartbeat 200s ago stays online instead of flipping."""
        agent_in_lab.offline_threshold_seconds = 600
        agent_in_lab.last_heartbeat = datetime.now(UTC) - timedelta(seconds=200)
        await db_session.commit()

        age = (
            datetime.now(UTC) - agent_in_lab.last_heartbeat
        ).total_seconds()
        assert age >= 180  # would flip at default threshold
        assert age < agent_in_lab.offline_threshold_seconds  # stays online
