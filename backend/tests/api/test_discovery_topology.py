# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for build_discovery_topology — graph assembly from discovered_hosts.

The chapter's invariants:
- Hosts get a `subnet_id` when their IP matches a Site.subnets CIDR
- Subnet nodes are produced and host_count is correct
- Virtual host→subnet edges are emitted
- Real LLDP edges from topology_edges surface in the response
- include_adopted=False filters adopted rows out
- Empty inputs return empty graph (not 500)
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.discovery import build_discovery_topology


@pytest_asyncio.fixture
async def org_and_site(db_session: AsyncSession):
    """Create an org and a site claiming 192.168.1.0/24."""
    from app.models.core import Organization, Site

    org = Organization(
        name=f"topo-org-{uuid4()}",
        slug=f"topo-org-{uuid4().hex[:8]}",
    )
    db_session.add(org)
    await db_session.flush()

    site = Site(
        organization_id=org.id,
        name="Test Lab",
        slug=f"demo-lab-{uuid4().hex[:6]}",
        subnets=[{"cidr": "192.168.1.0/24", "name": "Test Lab LAN", "vlan_id": 1}],
    )
    db_session.add(site)
    await db_session.flush()
    return org.id, site.id


async def _add_host(
    session: AsyncSession,
    *,
    site_id: UUID,
    organization_id: UUID,
    ip: str,
    mac: str | None = None,
    hostname: str | None = None,
    is_adopted: bool = False,
) -> UUID:
    from app.models.devices import DiscoveredHost

    now = datetime.now(UTC)
    row = DiscoveredHost(
        site_id=site_id,
        organization_id=organization_id,
        ip_address=ip,
        mac_address=mac,
        hostname=hostname,
        discovered_via=["ping"],
        is_adopted=is_adopted,
        first_seen=now,
        last_seen=now,
    )
    session.add(row)
    await session.flush()
    return row.id


async def _add_edge(
    session: AsyncSession,
    *,
    site_id: UUID,
    organization_id: UUID,
    local_interface: str,
    chassis: str,
    port: str,
    system_name: str | None = None,
) -> UUID:
    from app.models.devices import TopologyEdge

    now = datetime.now(UTC)
    row = TopologyEdge(
        site_id=site_id,
        organization_id=organization_id,
        protocol="lldp",
        local_interface=local_interface,
        neighbor_chassis_id=chassis,
        neighbor_port_id=port,
        neighbor_system_name=system_name,
        first_seen=now,
        last_seen=now,
    )
    session.add(row)
    await session.flush()
    return row.id


class TestBuildDiscoveryTopology:
    @pytest.mark.asyncio
    async def test_empty_when_no_data(
        self, db_session: AsyncSession, org_and_site
    ) -> None:
        org_id, site_id = org_and_site
        result = await build_discovery_topology(
            db_session,
            organization_id=org_id,
            site_id=site_id,
        )
        assert result == {"nodes": [], "edges": [], "subnets": []}

    @pytest.mark.asyncio
    async def test_subnet_grouping_and_virtual_edges(
        self, db_session: AsyncSession, org_and_site
    ) -> None:
        org_id, site_id = org_and_site

        # Two hosts in subnet, one outside
        await _add_host(
            db_session,
            site_id=site_id,
            organization_id=org_id,
            ip="192.168.1.150",
            mac="aa:bb:cc:00:00:01",
        )
        await _add_host(
            db_session,
            site_id=site_id,
            organization_id=org_id,
            ip="192.168.1.51",
            mac="aa:bb:cc:00:00:02",
        )
        await _add_host(
            db_session,
            site_id=site_id,
            organization_id=org_id,
            ip="10.0.5.5",
            mac="aa:bb:cc:00:00:03",
        )
        await db_session.flush()

        result = await build_discovery_topology(
            db_session, organization_id=org_id, site_id=site_id
        )

        host_nodes = [n for n in result["nodes"] if n["type"] == "host"]
        subnet_nodes = [n for n in result["nodes"] if n["type"] == "subnet"]

        assert len(host_nodes) == 3
        assert len(subnet_nodes) == 1
        assert subnet_nodes[0]["cidr"] == "192.168.1.0/24"
        assert subnet_nodes[0]["host_count"] == 2

        # 2 in-subnet hosts get subnet_id; 1 outside doesn't
        with_subnet = [n for n in host_nodes if n["subnet_id"]]
        without_subnet = [n for n in host_nodes if not n["subnet_id"]]
        assert len(with_subnet) == 2
        assert len(without_subnet) == 1
        assert without_subnet[0]["ip_address"] == "10.0.5.5"

        # Virtual subnet_member edges: one per in-subnet host
        virt_edges = [e for e in result["edges"] if e["type"] == "subnet_member"]
        assert len(virt_edges) == 2

    @pytest.mark.asyncio
    async def test_lldp_edge_surfaces(
        self, db_session: AsyncSession, org_and_site
    ) -> None:
        org_id, site_id = org_and_site

        await _add_edge(
            db_session,
            site_id=site_id,
            organization_id=org_id,
            local_interface="eth0",
            chassis="aa:bb:cc:dd:ee:ff",
            port="Gi1/0/1",
            system_name="lab-switch",
        )
        await db_session.flush()

        result = await build_discovery_topology(
            db_session, organization_id=org_id, site_id=site_id
        )

        lldp_edges = [e for e in result["edges"] if e["type"] == "lldp"]
        assert len(lldp_edges) == 1
        assert lldp_edges[0]["neighbor_system_name"] == "lab-switch"
        assert lldp_edges[0]["source"] == "agent-iface:eth0"
        assert lldp_edges[0]["target"] == "aa:bb:cc:dd:ee:ff"

    @pytest.mark.asyncio
    async def test_include_adopted_filter(
        self, db_session: AsyncSession, org_and_site
    ) -> None:
        org_id, site_id = org_and_site

        await _add_host(
            db_session,
            site_id=site_id,
            organization_id=org_id,
            ip="192.168.1.150",
            is_adopted=False,
        )
        await _add_host(
            db_session,
            site_id=site_id,
            organization_id=org_id,
            ip="192.168.1.51",
            is_adopted=True,
        )
        await db_session.flush()

        with_adopted = await build_discovery_topology(
            db_session,
            organization_id=org_id,
            site_id=site_id,
            include_adopted=True,
        )
        without_adopted = await build_discovery_topology(
            db_session,
            organization_id=org_id,
            site_id=site_id,
            include_adopted=False,
        )

        assert len([n for n in with_adopted["nodes"] if n["type"] == "host"]) == 2
        assert (
            len([n for n in without_adopted["nodes"] if n["type"] == "host"]) == 1
        )

    @pytest.mark.asyncio
    async def test_org_isolation_unless_superuser(
        self, db_session: AsyncSession, org_and_site
    ) -> None:
        """Foreign org's discovered hosts must not appear unless superuser."""
        from app.models.core import Organization, Site

        org_id, site_id = org_and_site

        # Make a foreign org with its own host
        other_org = Organization(
            name=f"other-{uuid4()}",
            slug=f"other-{uuid4().hex[:8]}",
        )
        db_session.add(other_org)
        await db_session.flush()
        other_site = Site(
            organization_id=other_org.id,
            name="Other",
            slug=f"other-{uuid4().hex[:6]}",
            subnets=[{"cidr": "10.10.10.0/24"}],
        )
        db_session.add(other_site)
        await db_session.flush()
        await _add_host(
            db_session,
            site_id=other_site.id,
            organization_id=other_org.id,
            ip="10.10.10.10",
        )
        await db_session.flush()

        # Non-superuser at org_and_site's org: should NOT see other org's host
        result = await build_discovery_topology(
            db_session,
            organization_id=org_id,
            site_id=None,  # no site filter — exercise org gate
            is_superuser=False,
        )
        host_ips = {n["ip_address"] for n in result["nodes"] if n["type"] == "host"}
        assert "10.10.10.10" not in host_ips

        # Superuser without site filter sees both orgs
        result_super = await build_discovery_topology(
            db_session,
            organization_id=None,
            site_id=None,
            is_superuser=True,
        )
        super_ips = {
            n["ip_address"] for n in result_super["nodes"] if n["type"] == "host"
        }
        assert "10.10.10.10" in super_ips
