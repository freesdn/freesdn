# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the site-subnet auto-routing in upsert_batch.

The chapter's invariant: an agent pushing /discovery/results with
site_id=A should NOT land every host under A. Rows whose IP matches
site B's subnets must go to B; only unrouted IPs use A as the
default bucket.

We exercise ``resolve_site_for_host`` directly + ``upsert_batch`` via
a sqlite-backed test session.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.discovered_hosts import (
    resolve_site_for_host,
    upsert_batch,
)


async def _make_site(
    session: AsyncSession,
    *,
    organization_id: UUID,
    name: str,
    subnets: list[dict],
) -> UUID:
    from app.models.core import Site

    site = Site(
        organization_id=organization_id,
        name=name,
        slug=name.lower().replace(" ", "-"),
        subnets=subnets,
    )
    session.add(site)
    await session.flush()
    return site.id


async def _make_org(session: AsyncSession) -> UUID:
    from app.models.core import Organization

    org = Organization(
        name=f"test-org-{uuid4()}",
        slug=f"test-org-{uuid4().hex[:8]}",
    )
    session.add(org)
    await session.flush()
    return org.id


class TestResolveSiteForHost:
    @pytest.mark.asyncio
    async def test_returns_site_for_matching_cidr(
        self, db_session: AsyncSession
    ) -> None:
        org = await _make_org(db_session)
        site_id = await _make_site(
            db_session,
            organization_id=org,
            name="Test Lab",
            subnets=[{"cidr": "192.168.1.0/24", "name": "Lab"}],
        )
        resolved = await resolve_site_for_host(
            db_session, organization_id=org, ip_address="192.168.1.150"
        )
        assert resolved == site_id

    @pytest.mark.asyncio
    async def test_returns_none_when_no_match(
        self, db_session: AsyncSession
    ) -> None:
        org = await _make_org(db_session)
        await _make_site(
            db_session,
            organization_id=org,
            name="HQ",
            subnets=[{"cidr": "10.0.0.0/24"}],
        )
        resolved = await resolve_site_for_host(
            db_session, organization_id=org, ip_address="192.168.5.5"
        )
        assert resolved is None

    @pytest.mark.asyncio
    async def test_more_specific_prefix_wins(
        self, db_session: AsyncSession
    ) -> None:
        """Site B with /24 should beat site A with /16 for overlapping IPs."""
        org = await _make_org(db_session)
        broad = await _make_site(
            db_session,
            organization_id=org,
            name="HQ",
            subnets=[{"cidr": "192.168.0.0/16"}],
        )
        narrow = await _make_site(
            db_session,
            organization_id=org,
            name="Test Lab",
            subnets=[{"cidr": "192.168.1.0/24"}],
        )
        resolved = await resolve_site_for_host(
            db_session, organization_id=org, ip_address="192.168.1.105"
        )
        assert resolved == narrow
        # Outside the /24 but still inside the /16 → broad wins
        resolved_far = await resolve_site_for_host(
            db_session, organization_id=org, ip_address="192.168.5.5"
        )
        assert resolved_far == broad

    @pytest.mark.asyncio
    async def test_invalid_cidr_skipped(
        self, db_session: AsyncSession
    ) -> None:
        org = await _make_org(db_session)
        site_id = await _make_site(
            db_session,
            organization_id=org,
            name="Mixed",
            subnets=[
                {"cidr": "not-a-cidr"},  # ignored
                {"cidr": "192.168.1.0/24"},
            ],
        )
        resolved = await resolve_site_for_host(
            db_session, organization_id=org, ip_address="192.168.1.105"
        )
        assert resolved == site_id

    @pytest.mark.asyncio
    async def test_invalid_ip_returns_none(
        self, db_session: AsyncSession
    ) -> None:
        org = await _make_org(db_session)
        await _make_site(
            db_session,
            organization_id=org,
            name="x",
            subnets=[{"cidr": "192.168.1.0/24"}],
        )
        resolved = await resolve_site_for_host(
            db_session, organization_id=org, ip_address="not-an-ip"
        )
        assert resolved is None


class TestUpsertBatchAutoRouting:
    @pytest.mark.asyncio
    async def test_routes_hosts_to_matching_site(
        self, db_session: AsyncSession
    ) -> None:
        org = await _make_org(db_session)
        default_site = await _make_site(
            db_session,
            organization_id=org,
            name="Branch",
            subnets=[],  # no subnets → never claims anything
        )
        lab_site = await _make_site(
            db_session,
            organization_id=org,
            name="Test Lab",
            subnets=[{"cidr": "192.168.1.0/24"}],
        )

        hosts = [
            {"ip_address": "192.168.1.150", "mac_address": "aa:bb:cc:dd:ee:01"},
            {"ip_address": "192.168.1.51", "mac_address": "aa:bb:cc:dd:ee:02"},
            {"ip_address": "10.0.5.5", "mac_address": "aa:bb:cc:dd:ee:03"},  # no claim
        ]

        summary = await upsert_batch(
            db_session,
            site_id=default_site,
            organization_id=org,
            discovered_by_agent_id=None,
            hosts=hosts,
        )
        await db_session.commit()

        assert summary["created"] == 3
        assert summary["skipped"] == 0
        routed = summary["routed"]
        assert routed[str(lab_site)] == 2
        assert routed[str(default_site)] == 1

    @pytest.mark.asyncio
    async def test_auto_route_disabled_keeps_request_site(
        self, db_session: AsyncSession
    ) -> None:
        org = await _make_org(db_session)
        default_site = await _make_site(
            db_session,
            organization_id=org,
            name="Branch",
            subnets=[],
        )
        await _make_site(
            db_session,
            organization_id=org,
            name="Test Lab",
            subnets=[{"cidr": "192.168.1.0/24"}],
        )

        summary = await upsert_batch(
            db_session,
            site_id=default_site,
            organization_id=org,
            discovered_by_agent_id=None,
            hosts=[{"ip_address": "192.168.1.150", "mac_address": "aa:bb:cc:dd:ee:01"}],
            auto_route=False,
        )
        await db_session.commit()

        assert summary["routed"] == {str(default_site): 1}
