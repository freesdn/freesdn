# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A gateway sync holds no DB transaction while it talks to the device, stops at
the first sign the device is in trouble, and never calls a silent box healthy.

Evidence (2026-11 soak, office OPNsense with a wedged PHP/configd backend): one
``SyncService.sync_gateway`` kept the transaction it opened with its first SELECT
-- and behind PgBouncer a server connection -- for 7+ minutes while every
request timed out; it then sent every remaining section anyway; and because the
adapter returns a failed ``AdapterResult`` instead of raising, it finished with
``sync_status=success`` and ``is_online=True``. Real PostgreSQL, synthetic device.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.core.crypto import encrypt_dict
from app.models.core import Organization, Site
from app.modules.firewall.models import GatewayConnection, GatewaySyncLog
from app.modules.gateway.models import ImportedFirewallRule, ImportedNATRule
from app.modules.gateway.services import sync_service
from app.modules.gateway.services.sync_service import SyncService


def _ok(data):
    return SimpleNamespace(success=True, data=data, error=None)


def _timed_out():
    # What OPNsenseAdapter returns for a request that hit its read timeout.
    return SimpleNamespace(success=False, data=None, error="AdapterConnectionError")


class _Adapter:
    """Records every device call and whether a DB transaction was open for it."""

    def __init__(self, db, *, fail_from: str | None = None, connect_fails: bool = False):
        self.db = db
        self.fail_from = fail_from
        self.connect_fails = connect_fails
        self.calls: list[str] = []
        self.open_tx: list[str] = []
        self._failing = False

    def _note(self, name: str) -> None:
        self.calls.append(name)
        if self.db.in_transaction():
            self.open_tx.append(name)

    async def __aenter__(self):
        self._note("connect")
        if self.connect_fails:
            from app.adapters.exceptions import AdapterConnectionError

            raise AdapterConnectionError("timed out", adapter_id="opnsense")
        return self

    async def __aexit__(self, *_exc):
        return False

    async def _read(self, name, data):
        self._note(name)
        if name == self.fail_from:
            self._failing = True
        return _timed_out() if self._failing else _ok(data)

    async def get_firewall_rules(self):
        return await self._read("rules", {"rules": [{"uuid": "r1", "description": "lan"}]})

    async def get_nat_rules(self):
        return await self._read("nat", {"rules": [{"uuid": "n1", "description": "out"}]})

    async def get_vpn_status(self):
        return await self._read("vpn", {})

    async def get_interfaces(self):
        return await self._read("interfaces", {"interfaces": [{"identifier": "lan"}]})

    async def get_dhcp_leases(self):
        return await self._read("leases", {"leases": []})


async def _gateway(db) -> GatewayConnection:
    org = Organization(name="Gateway io", slug=uuid4().hex)
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
        is_online=True,
    )
    db.add(gw)
    await db.flush()
    return gw


async def _count(db, model, gw) -> int:
    stmt = select(func.count()).select_from(model).where(model.device_id == gw.id)
    return (await db.execute(stmt)).scalar_one()


async def test_no_transaction_is_open_while_the_device_is_read(db_session, monkeypatch):
    """Fails on the old service: every call ran inside the SELECT's transaction."""
    gw = await _gateway(db_session)
    adapter = _Adapter(db_session)
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: adapter)

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert not db_session.in_transaction()  # the write transaction was committed
    assert result["status"] == "success"
    assert adapter.calls == ["connect", "rules", "nat", "vpn", "interfaces", "leases"]
    assert adapter.open_tx == [], f"DB transaction open during device I/O: {adapter.open_tx}"
    assert await _count(db_session, ImportedFirewallRule, gw) == 1


async def test_a_device_that_times_out_is_not_called_healthy_or_asked_again(
    db_session, monkeypatch
):
    """Fails on the old service: all five sections were sent to a box that had
    already timed out, and the sync ended success / is_online=True."""
    gw = await _gateway(db_session)
    adapter = _Adapter(db_session, fail_from="rules")
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: adapter)

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert result["status"] == "failed" and result["device_failure"] is True
    assert adapter.calls == ["connect", "rules"], adapter.calls
    await db_session.refresh(gw)
    assert gw.sync_status == "failed"
    assert "AdapterConnectionError" in (gw.last_sync_error or "")
    assert gw.last_sync_at is None  # not "freshly synced"
    log = (
        await db_session.execute(select(GatewaySyncLog).where(GatewaySyncLog.gateway_id == gw.id))
    ).scalar_one()
    assert log.status == "failed" and log.error


async def test_sections_read_before_the_device_stalled_still_land(db_session, monkeypatch):
    gw = await _gateway(db_session)
    adapter = _Adapter(db_session, fail_from="vpn")
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: adapter)

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert result["status"] == "failed"
    assert adapter.calls == ["connect", "rules", "nat", "vpn"]
    assert await _count(db_session, ImportedFirewallRule, gw) == 1
    assert await _count(db_session, ImportedNATRule, gw) == 1
    log = (
        await db_session.execute(select(GatewaySyncLog).where(GatewaySyncLog.gateway_id == gw.id))
    ).scalar_one()
    assert log.status == "partial"
    assert log.details["firewall_rules"] == 1 and "vpn_tunnels" in log.details["errors"]


async def test_an_unreachable_device_is_marked_offline(db_session, monkeypatch):
    gw = await _gateway(db_session)
    adapter = _Adapter(db_session, connect_fails=True)
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: adapter)

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert result["status"] == "failed"
    assert adapter.calls == ["connect"]
    await db_session.refresh(gw)
    assert gw.is_online is False and gw.sync_status == "failed"
    assert gw.last_sync_error.startswith("connect:")


@pytest.mark.parametrize("error", ["RequiredReadUnavailableError", "OPNsenseAPIError"])
async def test_a_refused_section_is_not_a_device_failure(db_session, monkeypatch, error):
    """A 4xx/plugin-missing read means the box answered: keep going."""
    gw = await _gateway(db_session)
    adapter = _Adapter(db_session)

    async def refused():
        adapter._note("vpn")
        return SimpleNamespace(success=False, data=None, error=error)

    adapter.get_vpn_status = refused
    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: adapter)

    result = await SyncService(db_session).sync_gateway(gw.id)

    assert result["status"] == "success"
    assert adapter.calls[-1] == "leases"


async def test_config_xml_is_downloaded_once_per_refresh_window(db_session, monkeypatch):
    """On a box whose rules live only in config.xml the MVC rule API is always
    empty, and every sync downloaded the whole configuration (every 5 minutes on
    the 2026-11 soak). Now the download happens once per refresh window and the
    imported rules stand in between."""
    gw = await _gateway(db_session)
    flags: list[bool] = []
    fetched: set = set()

    class _LegacyBox(_Adapter):
        async def get_firewall_rules(self, *, legacy_fallback=True):
            self._note("rules")
            flags.append(legacy_fallback)
            if not legacy_fallback:
                return _ok({"rules": [], "count": 0, "legacy_skipped": True})
            return _ok({"rules": [{"uuid": "x1", "description": "legacy"}], "source": "config_xml"})

    monkeypatch.setattr(sync_service, "build_adapter", lambda _gw: _LegacyBox(db_session))
    monkeypatch.setattr(sync_service, "_config_xml_due", lambda gid: gid not in fetched)
    monkeypatch.setattr(sync_service, "_mark_config_xml_fetched", lambda gid: fetched.add(gid))

    for _ in range(3):
        assert (await SyncService(db_session).sync_gateway(gw.id))["status"] == "success"

    assert flags == [True, False, False]
    assert await _count(db_session, ImportedFirewallRule, gw) == 1  # last-known rules kept
