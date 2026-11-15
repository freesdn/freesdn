# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""One bad section must not sink a gateway sync. Real PostgreSQL; no device I/O.

Found on the 2026-11 soak VM with the office OPNsense: its DHCP lease API reports
times as ``"2026/11/12 22:18:13"``. The raw string was bound to the timestamp
column, asyncpg refused it, and because every section shares one session the
failed flush left the transaction rolled back, so the whole sync failed and the
firewall rules, NAT, tunnels and interfaces it had just read were discarded.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.core.crypto import encrypt_dict
from app.models.core import Organization, Site
from app.modules.firewall.models import GatewayConnection, GatewaySyncLog
from app.modules.gateway.models import ImportedDHCPLease, ImportedFirewallRule, ImportedInterface
from app.modules.gateway.services import sync_service
from app.modules.gateway.services.sync_service import SyncService

LEASE = {
    "address": "192.0.2.50",
    "mac": "aa:bb:cc:dd:ee:ff",
    "hostname": "desk-1",
    "if": "lan",
    "state": "active",
    "starts": "2026/11/12 22:18:13",
    "ends": "never",
}


def _ok(data):
    return SimpleNamespace(success=True, data=data)


class _Adapter:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def get_firewall_rules(self):
        return _ok({"rules": [{"uuid": "r1", "description": "allow lan", "action": "pass"}]})

    async def get_nat_rules(self):
        return _ok({"rules": []})

    async def get_vpn_status(self):
        return _ok({})

    async def get_interfaces(self):
        return _ok({"interfaces": [{"identifier": "lan", "description": "LAN", "status": "up"}]})

    async def get_dhcp_leases(self):
        return _ok({"leases": [dict(LEASE)]})


async def _gateway(db) -> GatewayConnection:
    org = Organization(name="Gateway sync", slug=uuid4().hex)
    db.add(org)
    await db.flush()
    site = Site(name="office", slug=uuid4().hex, organization_id=org.id)
    db.add(site)
    await db.flush()
    gw = GatewayConnection(
        org_id=org.id,
        site_id=site.id,
        name="opnsense",
        vendor="opnsense",
        host="opnsense.example.test",
        credentials=encrypt_dict({"api_key": "k"}),
        settings={},
    )
    db.add(gw)
    await db.flush()
    return gw


async def _count(db, model, gw) -> int:
    stmt = select(func.count()).select_from(model).where(model.device_id == gw.id)
    return (await db.execute(stmt)).scalar_one()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026/11/12 22:18:13", datetime(2026, 11, 12, 22, 18, 13, tzinfo=UTC)),
        ("2026-11-12 22:18:13", datetime(2026, 11, 12, 22, 18, 13, tzinfo=UTC)),
        ("2026-11-12T22:18:13Z", datetime(2026, 11, 12, 22, 18, 13, tzinfo=UTC)),
        (1794521893, datetime.fromtimestamp(1794521893, UTC)),
        ("1794521893", datetime.fromtimestamp(1794521893, UTC)),
        ("never", None),
        ("", None),
        (None, None),
    ],
)
def test_lease_times_in_the_formats_gateways_send(raw, expected):
    assert SyncService._lease_time(raw) == expected


async def test_an_opnsense_lease_time_is_stored_and_the_sync_succeeds(db_session, monkeypatch):
    gw = await _gateway(db_session)
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: _Adapter())

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert result["status"] == "success"
    lease = (
        await db_session.execute(
            select(ImportedDHCPLease).where(ImportedDHCPLease.device_id == gw.id)
        )
    ).scalar_one()
    assert lease.starts == datetime(2026, 11, 12, 22, 18, 13, tzinfo=UTC)
    assert lease.ends is None
    # The sync records itself. It used to build GatewaySyncLog(error_message=...)
    # with a dict as items_synced, which raised TypeError after all the work.
    log = (
        await db_session.execute(select(GatewaySyncLog).where(GatewaySyncLog.gateway_id == gw.id))
    ).scalar_one()
    assert log.status == "success" and log.error is None
    assert log.items_synced == 3
    assert log.details == {"firewall_rules": 1, "interfaces": 1, "dhcp_leases": 1}


async def test_one_failing_section_no_longer_discards_the_others(db_session, monkeypatch):
    gw = await _gateway(db_session)
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: _Adapter())
    # Put the original defect back: hand the raw string to the timestamp column.
    monkeypatch.setattr(SyncService, "_lease_time", staticmethod(lambda value: value))

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert result["status"] == "success", "a lease section failure must not fail the sync"
    assert await _count(db_session, ImportedFirewallRule, gw) == 1
    assert await _count(db_session, ImportedInterface, gw) == 1
    assert await _count(db_session, ImportedDHCPLease, gw) == 0
