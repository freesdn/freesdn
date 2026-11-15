# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Gateway sync parses vendor values before writing typed columns. Real PostgreSQL.

The imported tables have Integer and Boolean columns, and the three brain
adapters answer in different dialects:

* RouterOS answers every value as a string (``"mtu": "1500"``,
  ``"disabled": "false"``). asyncpg refuses a str for an integer parameter, so
  a MikroTik gateway's interface section rolled back on every sync and its
  Interfaces tab stayed empty.
* The OPNsense adapter normalises interfaces to ``mac_address`` /
  ``ipv4_address`` / ``ipv4_subnet`` / ``vlan_id`` / ``link_type``; the writer
  read only pfSense's raw names (``macaddr`` / ``ipaddr`` / ``subnet`` /
  ``vlan`` / ``type``), so OPNsense interfaces landed with none of them.
* OPNsense's NAT API answers ``{"rows": [...]}`` with ``"enabled": "1"``; the
  writer read ``data["rules"]``, so NAT was never imported.

Each test fails on the previous sync_service.py.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import select

from app.core.crypto import encrypt_dict
from app.models.core import Organization, Site
from app.modules.firewall.models import GatewayConnection
from app.modules.gateway.models import ImportedFirewallRule, ImportedInterface, ImportedNATRule
from app.modules.gateway.services import sync_service
from app.modules.gateway.services.sync_service import SyncService


def _ok(data):
    return SimpleNamespace(success=True, data=data)


class _Adapter:
    def __init__(self, interfaces=None, nat=None, rules=None):
        self._interfaces = interfaces
        self._nat = nat
        self._rules = rules

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def get_firewall_rules(self):
        return _ok(self._rules or {"rules": []})

    async def get_nat_rules(self):
        return _ok(self._nat or {"rules": []})

    async def get_vpn_status(self):
        return _ok({})

    async def get_interfaces(self):
        return _ok(self._interfaces or {"interfaces": []})

    async def get_dhcp_leases(self):
        return _ok({"leases": []})


async def _gateway(db, vendor):
    org = Organization(name="Vendor values", slug=uuid4().hex)
    db.add(org)
    await db.flush()
    site = Site(name="office", slug=uuid4().hex, organization_id=org.id)
    db.add(site)
    await db.flush()
    gw = GatewayConnection(
        org_id=org.id,
        site_id=site.id,
        name=vendor,
        vendor=vendor,
        host=f"{vendor}.example.test",
        credentials=encrypt_dict({"username": "u"}),
        settings={},
    )
    db.add(gw)
    await db.flush()
    return gw


async def _rows(db, model, gw):
    return (await db.execute(select(model).where(model.device_id == gw.id))).scalars().all()


async def test_routeros_string_values_land_as_integers_and_booleans(db_session, monkeypatch):
    gw = await _gateway(db_session, "mikrotik")
    adapter = _Adapter(
        interfaces={
            "interfaces": [
                {
                    ".id": "*1",
                    "name": "ether1",
                    "type": "ether",
                    "mtu": "1500",
                    "mac-address": "AA:BB:CC:00:10:01",
                    "running": "true",
                    "disabled": "false",
                },
                {".id": "*2", "name": "vlan30", "type": "vlan", "mtu": "auto", "disabled": "true"},
            ],
            "addresses": [],
        },
        rules=[{".id": "*A", "action": "accept", "disabled": "true", "packets": "42"}],
    )
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: adapter)

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert result["status"] == "success"
    ifaces = {i.name: i for i in await _rows(db_session, ImportedInterface, gw)}
    assert set(ifaces) == {"ether1", "vlan30"}
    assert ifaces["ether1"].mtu == 1500
    assert ifaces["ether1"].mac_address == "AA:BB:CC:00:10:01"
    assert ifaces["ether1"].is_up is True and ifaces["ether1"].is_enabled is True
    assert ifaces["vlan30"].mtu is None and ifaces["vlan30"].is_enabled is False
    (rule,) = await _rows(db_session, ImportedFirewallRule, gw)
    assert rule.is_enabled is False and rule.hit_count == 42


async def test_opnsense_normalised_interface_fields_are_stored(db_session, monkeypatch):
    gw = await _gateway(db_session, "opnsense")
    adapter = _Adapter(
        interfaces={
            "interfaces": [
                {
                    "name": "LAN",
                    "description": "LAN",
                    "identifier": "lan",
                    "device": "igc1",
                    "status": "up",
                    "enabled": True,
                    "link_type": "vlan",
                    "mtu": 1500,
                    "mac_address": "aa:bb:cc:00:20:01",
                    "ipv4_address": "192.0.2.1",
                    "ipv4_subnet": "24",
                    "vlan_id": 30,
                    "parent_interface": "igc0",
                }
            ]
        }
    )
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: adapter)

    await SyncService(db_session).sync_gateway(gw.id)

    (iface,) = await _rows(db_session, ImportedInterface, gw)
    assert (iface.mac_address, iface.ipv4_address, iface.ipv4_subnet) == (
        "aa:bb:cc:00:20:01",
        "192.0.2.1",
        "24",
    )
    assert (iface.vlan_tag, iface.if_type, iface.parent_interface, iface.is_up) == (
        30,
        "vlan",
        "igc0",
        True,
    )


async def test_opnsense_nat_rows_are_imported(db_session, monkeypatch):
    gw = await _gateway(db_session, "opnsense")
    adapter = _Adapter(
        nat={
            "rows": [
                {"uuid": "n1", "enabled": "1", "description": "outbound"},
                {"uuid": "n2", "enabled": "0", "description": "parked"},
            ],
            "rowCount": 2,
        }
    )
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: adapter)

    await SyncService(db_session).sync_gateway(gw.id)

    nat = {n.external_id: n.is_enabled for n in await _rows(db_session, ImportedNATRule, gw)}
    assert nat == {"n1": True, "n2": False}
