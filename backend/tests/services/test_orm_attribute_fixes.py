# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Queries that named a model attribute the model does not have.

Each built its statement from ``Model.<missing>`` and raised ``AttributeError``
before reaching the database. Found by the class-level arm of
tests/models/test_orm_constructor_kwargs.py; every test here fails on the code
before the fix. All run on real PostgreSQL.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from app.models.core import Organization, Site
from app.models.devices import Device
from app.models.firmware import DeviceFirmwareStatus


async def _site(db_session):
    suffix = uuid4().hex[:8]
    org = Organization(name="Attr Org", slug=f"attr-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="Attr Site", slug=f"attr-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    return org, site


def _device(site, name, device_type, mac, **kw):
    return Device(
        site_id=site.id,
        name=name,
        device_type=device_type,
        mac_address=mac,
        status="online",
        last_seen=datetime.now(UTC),
        **kw,
    )


async def test_devices_health_filters_on_device_type(db_session, monkeypatch):
    """GET /analytics/devices/health?device_type=... built ``Device.type == t``."""
    from app.services.analytics import PersistentAnalyticsService

    org, site = await _site(db_session)
    sw = _device(site, "SW", "switch", "AA:BB:CC:20:00:01")
    ap = _device(site, "AP", "access_point", "AA:BB:CC:20:00:02")
    db_session.add_all([sw, ap])
    await db_session.flush()

    async def _health(_session, _logdb, device_id):
        return {"device_id": device_id}

    monkeypatch.setattr(PersistentAnalyticsService, "get_device_health", _health)

    out = await PersistentAnalyticsService.get_devices_health(
        db_session, None, site_id=site.id, device_type="switch", organization_id=org.id
    )
    assert out == [{"device_id": sw.id}]


async def test_site_comparison_counts_up_to_date_firmware(db_session):
    """GET /analytics/sites/comparison read ``DeviceFirmwareStatus.compliant``.

    The AttributeError was swallowed by the block's ``except``, so every site
    reported no firmware data at all.
    """
    from app.api.v1.endpoints.analytics import get_sites_comparison

    org, site = await _site(db_session)
    current = _device(site, "Current", "switch", "AA:BB:CC:20:00:11")
    stale = _device(site, "Stale", "switch", "AA:BB:CC:20:00:12")
    db_session.add_all([current, stale])
    await db_session.flush()
    db_session.add_all(
        [
            DeviceFirmwareStatus(device_id=current.id, site_id=site.id, is_up_to_date=True),
            DeviceFirmwareStatus(device_id=stale.id, site_id=site.id, is_up_to_date=False),
        ]
    )
    await db_session.flush()

    user = SimpleNamespace(organization_id=org.id, is_site_limited=False)
    out = await get_sites_comparison(session=db_session, user=user)

    row = next(s for s in out["sites"] if s["site_id"] == str(site.id))
    assert row["firmware"] == {"tracked": 2, "compliant": 1, "compliance_pct": 50.0}


async def test_ai_get_vlans_scopes_through_the_site(db_session):
    """The AI ``get_vlans`` tool filtered on ``Network.organization_id``."""
    from app.modules.ai.tools.network import _get_vlans
    from app.modules.network.models import Network

    org, site = await _site(db_session)
    _other_org, other_site = await _site(db_session)
    mine = Network(site_id=site.id, name="Users", vlan_id=10, is_active=True)
    theirs = Network(site_id=other_site.id, name="Theirs", vlan_id=20)
    db_session.add_all([mine, theirs])
    await db_session.flush()

    user = SimpleNamespace(organization_id=org.id, is_site_limited=False)
    out = await _get_vlans(user, db_session)

    assert out.get("error") is None
    assert [(v["name"], v["vlan_id"], v["is_enabled"]) for v in out["vlans"]] == [
        ("Users", 10, True)
    ]


async def test_ai_get_device_health_reads_the_device_columns(db_session):
    """The AI ``get_device_health`` tool read six attributes DeviceHealth lacks."""
    from app.models.enterprise import DeviceHealth
    from app.modules.ai.tools.diagnostics import _get_device_health

    org, site = await _site(db_session)
    dev = _device(
        site,
        "SW",
        "switch",
        "AA:BB:CC:20:00:21",
        cpu_usage_percent=12.5,
        memory_usage_percent=40.0,
        uptime_seconds=3600,
        temperature_celsius=41.0,
    )
    db_session.add(dev)
    await db_session.flush()
    db_session.add(
        DeviceHealth(device_id=dev.id, organization_id=org.id, site_id=site.id, health_score=88)
    )
    await db_session.flush()

    user = SimpleNamespace(
        organization_id=org.id, is_site_limited=False, can_access_site=lambda _sid: True
    )
    out = await _get_device_health(user, db_session, str(dev.id))

    assert out["cpu_percent"] == 12.5
    assert out["memory_percent"] == 40.0
    assert out["uptime_seconds"] == 3600
    assert out["temperature_celsius"] == 41.0
    assert out["status"] == "online"
    assert out["health_score"] == 88


async def test_switch_lldp_neighbors_label_ports_by_name(db_session):
    """GET /switches/{id}/lldp read ``port.port_name``; DevicePort's label is ``name``.

    Every switch with at least one LLDP neighbour answered 500.
    """
    from app.api.v1.endpoints.switches import get_lldp_neighbors
    from app.models.devices import DevicePort

    org, site = await _site(db_session)
    sw = _device(site, "Core", "switch", "AA:BB:CC:20:00:31")
    db_session.add(sw)
    await db_session.flush()
    db_session.add_all(
        [
            DevicePort(
                device_id=sw.id,
                port_number=1,
                name="Uplink",
                connected_mac="AA:BB:CC:20:00:99",
                port_metadata={"lldpNeighborPort": "ge-0/0/1"},
            ),
            DevicePort(device_id=sw.id, port_number=2, connected_mac="AA:BB:CC:20:00:98"),
        ]
    )
    await db_session.flush()

    user = SimpleNamespace(
        organization_id=org.id, is_site_limited=False, can_access_site=lambda _sid: True
    )
    out = await get_lldp_neighbors(str(sw.id), session=db_session, _user=user)

    assert sorted((n["port_index"], n["port_name"]) for n in out) == [
        (1, "Uplink"),
        (2, "Port 2"),
    ]
