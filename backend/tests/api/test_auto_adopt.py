# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the discovery auto-adopt path.

When a site has ``settings.auto_adopt_known_vendors`` set, every
freshly-upserted discovered host whose recommended_driver + MAC +
confidence clear the bar should be promoted directly to a managed
device row. These tests cover the gating rules:

- Setting OFF (default) → no promotion, even for perfectly-shaped rows.
- Setting ON + recommended_driver=None → skipped.
- Setting ON + low confidence → skipped.
- Setting ON + no MAC → skipped (can't dedup).
- Setting ON + already-managed MAC → skipped.
- Setting ON + all conditions met → device row created.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession


@pytest_asyncio.fixture
async def site_with_auto_adopt(db_session: AsyncSession):
    """Org + site with auto_adopt_known_vendors=True."""
    from app.models.core import Organization, Site

    org = Organization(
        name=f"aa-{uuid4()}",
        slug=f"aa-{uuid4().hex[:8]}",
    )
    db_session.add(org)
    await db_session.flush()

    site = Site(
        organization_id=org.id,
        name="auto-adopt-site",
        slug=f"aa-site-{uuid4().hex[:6]}",
        settings={
            "auto_adopt_known_vendors": True,
            "auto_adopt_min_confidence": 0.7,
        },
    )
    db_session.add(site)
    await db_session.flush()
    await db_session.refresh(site)
    return {"org": org, "site": site}


@pytest_asyncio.fixture
async def site_without_auto_adopt(db_session: AsyncSession):
    """Org + site with the toggle OFF (default state)."""
    from app.models.core import Organization, Site

    org = Organization(
        name=f"noaa-{uuid4()}",
        slug=f"noaa-{uuid4().hex[:8]}",
    )
    db_session.add(org)
    await db_session.flush()

    site = Site(
        organization_id=org.id,
        name="no-auto-adopt",
        slug=f"noaa-site-{uuid4().hex[:6]}",
        settings={},
    )
    db_session.add(site)
    await db_session.flush()
    await db_session.refresh(site)
    return {"org": org, "site": site}


def _high_conf_host(**overrides):
    base = {
        "ip_address": "192.168.50.1",
        "mac_address": "AA:BB:CC:DD:EE:01",
        "vendor": "Ubiquiti",
        "recommended_driver": "unifi",
        "vendor_confidence": 0.9,
        "device_type": "access_point",
        "hostname": "ap-floor-3",
    }
    base.update(overrides)
    return base


class TestAutoAdoptGating:
    @pytest.mark.asyncio
    async def test_off_by_default_no_promotion(
        self, db_session: AsyncSession, site_without_auto_adopt
    ) -> None:
        from sqlalchemy import select
        from app.models.devices import Device
        from app.services.discovered_hosts import _maybe_auto_adopt_for_site

        site = site_without_auto_adopt["site"]
        promoted = await _maybe_auto_adopt_for_site(
            db_session,
            site_id=site.id,
            organization_id=site.organization_id,
            hosts=[_high_conf_host()],
        )
        assert promoted == 0

        dev_count = (await db_session.execute(
            select(Device).where(Device.site_id == site.id)
        )).scalars().all()
        assert len(dev_count) == 0

    @pytest.mark.asyncio
    async def test_on_with_high_confidence_promotes(
        self, db_session: AsyncSession, site_with_auto_adopt
    ) -> None:
        from sqlalchemy import select
        from app.models.devices import Device, DeviceStatus
        from app.services.discovered_hosts import _maybe_auto_adopt_for_site

        site = site_with_auto_adopt["site"]
        promoted = await _maybe_auto_adopt_for_site(
            db_session,
            site_id=site.id,
            organization_id=site.organization_id,
            hosts=[_high_conf_host()],
        )
        await db_session.flush()
        assert promoted == 1

        dev_rows = (await db_session.execute(
            select(Device).where(Device.site_id == site.id)
        )).scalars().all()
        assert len(dev_rows) == 1
        d = dev_rows[0]
        assert d.driver_id == "unifi"
        assert d.discovery_method == "auto_adopt"
        assert d.is_adopted is True
        assert d.adopted_by is None  # no human did it
        # Lifecycle fix: standalone agent-adopted devices land ONLINE
        # (the agent just saw them), NOT ADOPTING — which would never
        # resolve without a controller handshake.
        assert d.status == DeviceStatus.ONLINE
        assert d.last_seen is not None
        assert d.controller_id is None

    @pytest.mark.asyncio
    async def test_skipped_when_recommended_driver_missing(
        self, db_session: AsyncSession, site_with_auto_adopt
    ) -> None:
        from app.services.discovered_hosts import _maybe_auto_adopt_for_site

        site = site_with_auto_adopt["site"]
        promoted = await _maybe_auto_adopt_for_site(
            db_session,
            site_id=site.id,
            organization_id=site.organization_id,
            hosts=[_high_conf_host(recommended_driver=None)],
        )
        assert promoted == 0

    @pytest.mark.asyncio
    async def test_skipped_when_driver_is_generic(
        self, db_session: AsyncSession, site_with_auto_adopt
    ) -> None:
        from app.services.discovered_hosts import _maybe_auto_adopt_for_site

        site = site_with_auto_adopt["site"]
        promoted = await _maybe_auto_adopt_for_site(
            db_session,
            site_id=site.id,
            organization_id=site.organization_id,
            hosts=[_high_conf_host(recommended_driver="generic")],
        )
        assert promoted == 0

    @pytest.mark.asyncio
    async def test_skipped_when_confidence_below_threshold(
        self, db_session: AsyncSession, site_with_auto_adopt
    ) -> None:
        from app.services.discovered_hosts import _maybe_auto_adopt_for_site

        site = site_with_auto_adopt["site"]
        promoted = await _maybe_auto_adopt_for_site(
            db_session,
            site_id=site.id,
            organization_id=site.organization_id,
            hosts=[_high_conf_host(vendor_confidence=0.5)],
        )
        assert promoted == 0

    @pytest.mark.asyncio
    async def test_skipped_when_no_mac(
        self, db_session: AsyncSession, site_with_auto_adopt
    ) -> None:
        from app.services.discovered_hosts import _maybe_auto_adopt_for_site

        site = site_with_auto_adopt["site"]
        promoted = await _maybe_auto_adopt_for_site(
            db_session,
            site_id=site.id,
            organization_id=site.organization_id,
            hosts=[_high_conf_host(mac_address=None)],
        )
        assert promoted == 0

    @pytest.mark.asyncio
    async def test_skipped_when_already_managed(
        self, db_session: AsyncSession, site_with_auto_adopt
    ) -> None:
        """A second auto-adopt pass with the same MAC must not create
        a duplicate device row."""
        from app.services.discovered_hosts import _maybe_auto_adopt_for_site

        site = site_with_auto_adopt["site"]
        # First pass — creates the device
        p1 = await _maybe_auto_adopt_for_site(
            db_session,
            site_id=site.id,
            organization_id=site.organization_id,
            hosts=[_high_conf_host()],
        )
        await db_session.flush()
        assert p1 == 1

        # Second pass — same host, should be a no-op
        p2 = await _maybe_auto_adopt_for_site(
            db_session,
            site_id=site.id,
            organization_id=site.organization_id,
            hosts=[_high_conf_host()],
        )
        await db_session.flush()
        assert p2 == 0

    @pytest.mark.asyncio
    async def test_custom_threshold_respected(
        self, db_session: AsyncSession, site_with_auto_adopt
    ) -> None:
        """A site that bumps the min-confidence to 0.9 should not
        accept a 0.75-confidence host even though it'd clear the
        default 0.7."""
        from app.services.discovered_hosts import _maybe_auto_adopt_for_site

        site = site_with_auto_adopt["site"]
        site.settings = {
            "auto_adopt_known_vendors": True,
            "auto_adopt_min_confidence": 0.9,
        }
        await db_session.flush()

        promoted = await _maybe_auto_adopt_for_site(
            db_session,
            site_id=site.id,
            organization_id=site.organization_id,
            hosts=[_high_conf_host(vendor_confidence=0.75)],
        )
        assert promoted == 0


class TestAgentObservationLiveness:
    """Re-observing an adopted standalone host should keep its managed
    Device row ONLINE + bump last_seen — the controller-less liveness
    mechanism that replaces the controller-sync poller."""

    @pytest.mark.asyncio
    async def test_reobservation_revives_offline_standalone_device(
        self, db_session: AsyncSession, site_with_auto_adopt
    ) -> None:
        from datetime import UTC, datetime, timedelta
        from sqlalchemy import select
        from app.models.devices import (
            Device, DeviceStatus, DiscoveredHost,
        )
        from app.services.discovered_hosts import (
            _touch_adopted_device_liveness,
            upsert_discovered_host,
        )

        site = site_with_auto_adopt["site"]

        # An adopted standalone device that's gone stale → OFFLINE.
        stale = datetime.now(UTC) - timedelta(hours=2)
        device = Device(
            name="ap-stale",
            ip_address="192.168.50.9",
            mac_address="AA:BB:CC:DD:EE:09",
            device_type="access_point",
            site_id=site.id,
            driver_id="unifi",
            status=DeviceStatus.OFFLINE,
            last_seen=stale,
            is_adopted=True,
            discovery_method="auto_adopt",
        )
        db_session.add(device)
        await db_session.flush()

        now = datetime.now(UTC)
        await _touch_adopted_device_liveness(db_session, device.id, now)
        await db_session.flush()
        await db_session.refresh(device)

        assert device.status == DeviceStatus.ONLINE
        assert device.last_seen == now

    @pytest.mark.asyncio
    async def test_controller_backed_device_left_untouched(
        self, db_session: AsyncSession, site_with_auto_adopt
    ) -> None:
        """A device with a controller is the controller's responsibility
        — the agent-liveness path must NOT flip its status."""
        from datetime import UTC, datetime
        from uuid import uuid4
        from app.models.devices import Device, DeviceStatus
        from app.models.core import Controller
        from app.services.discovered_hosts import _touch_adopted_device_liveness

        site = site_with_auto_adopt["site"]
        # Real controller row so the FK is satisfied.
        controller = Controller(
            name="test-ctrl",
            controller_type="unifi",
            host="192.168.50.2",
            port=443,
            site_id=site.id,
        )
        db_session.add(controller)
        await db_session.flush()

        device = Device(
            name="ctrl-ap",
            ip_address="192.168.50.10",
            mac_address="AA:BB:CC:DD:EE:10",
            device_type="access_point",
            site_id=site.id,
            controller_id=controller.id,
            status=DeviceStatus.OFFLINE,
            is_adopted=True,
            discovery_method="controller",
        )
        db_session.add(device)
        await db_session.flush()

        before = device.last_seen
        await _touch_adopted_device_liveness(db_session, device.id, datetime.now(UTC))
        await db_session.refresh(device)

        # Unchanged — controller stays the authority.
        assert device.status == DeviceStatus.OFFLINE
        assert device.last_seen == before
