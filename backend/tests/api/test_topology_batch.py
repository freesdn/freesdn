# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the batched topology-edge upsert.

upsert_topology_edges_batch must:
- create new edges + report created count
- merge re-observed edges (by identity tuple) + report updated count
- dedup duplicate tuples WITHIN a single batch (no double insert)
all with a single existing-row query (no per-edge N+1).
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


@pytest_asyncio.fixture
async def org_site(db_session: AsyncSession):
    from app.models.core import Organization, Site

    org = Organization(name=f"te-{uuid4()}", slug=f"te-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    site = Site(organization_id=org.id, name="lab", slug=f"lab-{uuid4().hex[:6]}")
    db_session.add(site)
    await db_session.flush()
    return org.id, site.id


def _edge(li, cid, pid, **kw):
    base = {
        "local_interface": li,
        "neighbor_chassis_id": cid,
        "neighbor_port_id": pid,
        "protocol": "lldp",
    }
    base.update(kw)
    return base


class TestBatchUpsert:
    @pytest.mark.asyncio
    async def test_create_then_update(self, db_session: AsyncSession, org_site):
        from app.models.devices import TopologyEdge
        from app.services.agent_topology import upsert_topology_edges_batch

        org_id, site_id = org_site

        # First batch: 2 new edges
        created, updated = await upsert_topology_edges_batch(
            db_session, site_id=site_id, organization_id=org_id,
            edges=[
                _edge("eth0", "AA:BB", "Gi0/1", neighbor_system_name="sw1"),
                _edge("eth1", "CC:DD", "Gi0/2"),
            ],
        )
        await db_session.flush()
        assert (created, updated) == (2, 0)

        # Second batch: one re-observed (eth0) + one new (eth2)
        created, updated = await upsert_topology_edges_batch(
            db_session, site_id=site_id, organization_id=org_id,
            edges=[
                _edge("eth0", "AA:BB", "Gi0/1", neighbor_system_name="sw1-renamed"),
                _edge("eth2", "EE:FF", "Gi0/3"),
            ],
        )
        await db_session.flush()
        assert (created, updated) == (1, 1)

        # Total distinct edges = 3; eth0's system_name was merged
        rows = (await db_session.execute(
            select(TopologyEdge).where(
                TopologyEdge.site_id == site_id,
                TopologyEdge.deleted_at.is_(None),
            )
        )).scalars().all()
        assert len(rows) == 3
        eth0 = next(r for r in rows if r.local_interface == "eth0")
        assert eth0.neighbor_system_name == "sw1-renamed"

    @pytest.mark.asyncio
    async def test_dedup_within_batch(self, db_session: AsyncSession, org_site):
        from app.models.devices import TopologyEdge
        from app.services.agent_topology import upsert_topology_edges_batch

        org_id, site_id = org_site
        # Same identity tuple twice in one batch → one row, not two
        created, updated = await upsert_topology_edges_batch(
            db_session, site_id=site_id, organization_id=org_id,
            edges=[
                _edge("eth0", "AA:BB", "Gi0/1"),
                _edge("eth0", "AA:BB", "Gi0/1", neighbor_system_name="late"),
            ],
        )
        await db_session.flush()
        rows = (await db_session.execute(
            select(TopologyEdge).where(
                TopologyEdge.site_id == site_id,
                TopologyEdge.deleted_at.is_(None),
            )
        )).scalars().all()
        assert len(rows) == 1
        # created counts the first; the second merged onto it
        assert created == 1
