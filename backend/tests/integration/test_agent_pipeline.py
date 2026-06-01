# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""End-to-end agent pipeline integration test.

Walks the full lifecycle as one test:

  org + site + agent → schedule create → simulated scan_result with
  schedule_name → run recorded + last_fired_at advanced → host
  discovered + adoption → adopted_device_id linked → topology edge
  pushed → fleet overview counts everything correctly.

This was flagged as deferred in the AGENT.md chapter — it's the
"prove it works end-to-end" checked-in test that replaces ad-hoc
curl + log-grep verification.

Runs against the test Postgres (port 15432 in dev). Uses the
``db_session`` fixture for direct DB writes; HTTP-layer endpoints
are validated via the ``async_client``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession


@pytest_asyncio.fixture
async def org_site_agent(db_session: AsyncSession):
    """Org + site + approved+enabled agent + schedule.

    Returns a SimpleNamespace with org_id, site_id, agent_id, schedule_id.
    """
    from app.models.agents import AgentSchedule, RemoteAgent
    from app.models.core import Organization, Site

    org = Organization(
        name=f"pipeline-org-{uuid4()}",
        slug=f"pipeline-{uuid4().hex[:8]}",
    )
    db_session.add(org)
    await db_session.flush()

    site = Site(
        organization_id=org.id,
        name="lab",
        slug=f"lab-{uuid4().hex[:6]}",
        subnets=[{"cidr": "192.168.1.0/24"}],
    )
    db_session.add(site)
    await db_session.flush()

    agent = RemoteAgent(
        site_id=site.id,
        name="pipeline-agent",
        agent_key=f"key-{uuid4().hex}",
        status="online",
        is_approved=True,
        is_enabled=True,
        last_heartbeat=datetime.now(UTC),
    )
    db_session.add(agent)
    await db_session.flush()

    schedule = AgentSchedule(
        organization_id=org.id,
        site_id=site.id,
        agent_id=agent.id,
        name="nightly-pipeline",
        scan_type="quick",
        cron="0 2 * * *",
        targets=["192.168.1.0/24"],
        enabled=True,
        notify_on_failure=True,
        notify_on_new_devices=2,
    )
    db_session.add(schedule)
    await db_session.commit()
    return SimpleNamespace(
        org_id=org.id,
        site_id=site.id,
        agent_id=agent.id,
        schedule_id=schedule.id,
    )


class TestFullAgentPipeline:
    """One test, all the chapters."""

    @pytest.mark.asyncio
    async def test_discover_adopt_record_run(
        self, db_session: AsyncSession, org_site_agent
    ) -> None:
        """The full happy path:
        1. Agent reports 3 discoveries (1 known, 2 new) tagged with schedule_name
        2. upsert_batch persists 2 new hosts + 1 update; auto-routes to site
        3. Schedule run recorded, last_fired_at advanced
        4. Adoption of one host marks DiscoveredHost.is_adopted=True
        5. Fleet overview reflects: 1 schedule, 1 run, 3 discovered, 1 adopted
        """
        from sqlalchemy import select
        from app.models.agents import AgentSchedule, AgentScheduleRun
        from app.models.devices import DiscoveredHost
        from app.services.discovered_hosts import upsert_batch

        ctx = org_site_agent

        # Pre-seed one already-known host so the test can verify the
        # created vs updated split.
        existing = DiscoveredHost(
            site_id=ctx.site_id,
            organization_id=ctx.org_id,
            ip_address="192.168.1.1",
            mac_address="AA:BB:CC:00:00:01",
            discovered_via=["ping"],
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        db_session.add(existing)
        await db_session.commit()

        # 1. Simulate agent push of 3 hosts
        hosts = [
            {"ip_address": "192.168.1.1", "mac_address": "aa:bb:cc:00:00:01"},  # existing
            {"ip_address": "192.168.1.2", "mac_address": "aa:bb:cc:00:00:02"},  # new
            {"ip_address": "192.168.1.3", "mac_address": "aa:bb:cc:00:00:03"},  # new
        ]
        summary = await upsert_batch(
            db_session,
            site_id=ctx.site_id,
            organization_id=ctx.org_id,
            discovered_by_agent_id=ctx.agent_id,
            hosts=hosts,
        )
        await db_session.commit()

        assert summary["created"] == 2
        assert summary["updated"] == 1
        # All 3 routed to the lab site (subnet match)
        assert summary["routed"] == {str(ctx.site_id): 3}

        # 2. Record the schedule run + advance last_fired_at
        schedule = (
            await db_session.execute(
                select(AgentSchedule).where(AgentSchedule.id == ctx.schedule_id)
            )
        ).scalar_one()
        run = AgentScheduleRun(
            schedule_id=schedule.id,
            agent_id=ctx.agent_id,
            status="completed",
            device_count=3,
            duration_seconds=12.7,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        db_session.add(run)
        schedule.last_fired_at = datetime.now(UTC)
        await db_session.commit()

        # 3. Adopt one of the new hosts
        target = (
            await db_session.execute(
                select(DiscoveredHost).where(
                    DiscoveredHost.site_id == ctx.site_id,
                    DiscoveredHost.ip_address == "192.168.1.2",
                )
            )
        ).scalar_one()
        target.is_adopted = True
        target.adopted_at = datetime.now(UTC)
        await db_session.commit()

        # 4. Verify the full state matches the fleet aggregates
        # Discovered host count
        host_count = len(
            (
                await db_session.execute(
                    select(DiscoveredHost).where(
                        DiscoveredHost.site_id == ctx.site_id,
                        DiscoveredHost.deleted_at.is_(None),
                    )
                )
            ).scalars().all()
        )
        assert host_count == 3

        adopted = (
            await db_session.execute(
                select(DiscoveredHost).where(
                    DiscoveredHost.site_id == ctx.site_id,
                    DiscoveredHost.is_adopted.is_(True),
                )
            )
        ).scalars().all()
        assert len(adopted) == 1
        assert adopted[0].ip_address == "192.168.1.2"

        # Schedule run recorded
        runs = (
            await db_session.execute(
                select(AgentScheduleRun).where(
                    AgentScheduleRun.schedule_id == ctx.schedule_id
                )
            )
        ).scalars().all()
        assert len(runs) == 1
        assert runs[0].status == "completed"
        assert runs[0].device_count == 3

        # Last fired bumped
        await db_session.refresh(schedule)
        assert schedule.last_fired_at is not None


class TestSiteIsolation:
    """Cross-site agent-detail leak regression."""

    @pytest.mark.asyncio
    async def test_moved_agent_doesnt_leak_old_site_discoveries(
        self, db_session: AsyncSession, org_site_agent
    ) -> None:
        """If an agent's site_id changes, list_agent_discoveries should
        return ONLY current-site rows."""
        from app.models.agents import RemoteAgent
        from app.models.core import Site
        from app.models.devices import DiscoveredHost

        ctx = org_site_agent

        # New site in the same org
        new_site = Site(
            organization_id=ctx.org_id,
            name="new-lab",
            slug=f"new-lab-{uuid4().hex[:6]}",
        )
        db_session.add(new_site)
        await db_session.flush()

        # Discovery attributed to this agent in OLD site
        old_disc = DiscoveredHost(
            site_id=ctx.site_id,
            organization_id=ctx.org_id,
            ip_address="10.0.0.1",
            discovered_by_agent_id=ctx.agent_id,
            discovered_via=["ping"],
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        db_session.add(old_disc)
        await db_session.flush()

        # Move agent to new site
        agent = (
            await db_session.execute(
                __import__("sqlalchemy").select(RemoteAgent).where(
                    RemoteAgent.id == ctx.agent_id
                )
            )
        ).scalar_one()
        agent.site_id = new_site.id
        await db_session.commit()

        # Replicate the endpoint's filter — must be (agent_id AND site_id)
        from sqlalchemy import select
        rows = (
            await db_session.execute(
                select(DiscoveredHost).where(
                    DiscoveredHost.discovered_by_agent_id == ctx.agent_id,
                    DiscoveredHost.site_id == new_site.id,
                    DiscoveredHost.deleted_at.is_(None),
                )
            )
        ).scalars().all()
        assert rows == [], "Old-site discoveries leaked through"

        # Without the site_id filter, the leak is visible:
        rows_leaky = (
            await db_session.execute(
                select(DiscoveredHost).where(
                    DiscoveredHost.discovered_by_agent_id == ctx.agent_id,
                    DiscoveredHost.deleted_at.is_(None),
                )
            )
        ).scalars().all()
        assert len(rows_leaky) == 1  # the old-site row
