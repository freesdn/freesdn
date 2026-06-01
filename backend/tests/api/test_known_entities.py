# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the known-entity correlation index.

When an agent discovers an IP on the wire, FreeSDN should recognize it
if it's already known — a controller appliance (MikroTik / UniFi /
Omada host) or a managed/controller-synced device. These tests cover
the index builder + the match helper.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession


@pytest_asyncio.fixture
async def known_fixture(db_session: AsyncSession):
    from app.models.core import Controller, Organization, Site
    from app.models.devices import Device, DeviceStatus

    org = Organization(name=f"ke-{uuid4()}", slug=f"ke-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()

    site = Site(organization_id=org.id, name="lab", slug=f"lab-{uuid4().hex[:6]}")
    db_session.add(site)
    await db_session.flush()

    # A MikroTik controller appliance (host IP, no MAC, not in devices)
    mikrotik = Controller(
        name="MikroTik Gateway", controller_type="mikrotik",
        host="192.168.1.133", port=443, site_id=site.id,
    )
    # A managed device synced from a controller (has IP + MAC)
    ap = Device(
        name="Office AP", device_type="access_point",
        ip_address="192.168.1.40", mac_address="AA:BB:CC:00:11:22",
        site_id=site.id, controller_id=None,
    )
    db_session.add_all([mikrotik, ap])
    await db_session.flush()
    return {"org": org, "site": site, "mikrotik": mikrotik, "ap": ap}


class TestKnownEntityIndex:
    @pytest.mark.asyncio
    async def test_controller_indexed_by_host_ip(
        self, db_session: AsyncSession, known_fixture
    ) -> None:
        from app.services.discovered_hosts import build_known_entity_index

        idx = await build_known_entity_index(
            db_session, organization_id=known_fixture["org"].id,
        )
        assert "192.168.1.133" in idx["by_ip"]
        entry = idx["by_ip"]["192.168.1.133"]
        assert entry["kind"] == "controller"
        assert entry["controller_type"] == "mikrotik"
        assert "mikrotik" in entry["detail"]

    @pytest.mark.asyncio
    async def test_device_indexed_by_ip_and_mac(
        self, db_session: AsyncSession, known_fixture
    ) -> None:
        from app.services.discovered_hosts import build_known_entity_index

        idx = await build_known_entity_index(
            db_session, organization_id=known_fixture["org"].id,
        )
        assert "192.168.1.40" in idx["by_ip"]
        assert "AABBCC001122" in idx["by_mac"]

    @pytest.mark.asyncio
    async def test_match_by_mac_then_ip(
        self, db_session: AsyncSession, known_fixture
    ) -> None:
        from app.services.discovered_hosts import (
            build_known_entity_index,
            match_known_entity,
        )

        idx = await build_known_entity_index(
            db_session, organization_id=known_fixture["org"].id,
        )
        # MAC match (different format) wins
        m = match_known_entity(idx, ip_address="9.9.9.9", mac_address="aa-bb-cc-00-11-22")
        assert m is not None and m["name"] == "Office AP"
        # IP match for the controller (no MAC)
        m2 = match_known_entity(idx, ip_address="192.168.1.133", mac_address=None)
        assert m2 is not None and m2["kind"] == "controller"
        # Genuinely unknown
        assert match_known_entity(idx, ip_address="10.10.10.10", mac_address="FF:FF:FF:FF:FF:FF") is None

    @pytest.mark.asyncio
    async def test_org_scoping(
        self, db_session: AsyncSession, known_fixture
    ) -> None:
        """A different org must not see this org's controllers/devices."""
        from app.services.discovered_hosts import build_known_entity_index

        idx = await build_known_entity_index(
            db_session, organization_id=uuid4(),  # foreign org
        )
        assert idx["by_ip"] == {}
        assert idx["by_mac"] == {}
