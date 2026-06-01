# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for FirewallBackupContributor (enterprise backup chapter).

Same FakeAsyncSession pattern. Covers redaction (PSK + creds), collect
shape + secret exclusion (GatewayConnection.credentials never
serialized), and restore tenant/FK guards via the shared
``restore_records`` helper.
"""

from __future__ import annotations

from collections import deque
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app.modules.firewall.backup import FirewallBackupContributor, _redact
from app.services.backup_contributors import (
    BackupContributor,
    ContributorPayload,
)


class _Result:
    def __init__(self, rows): self._rows = rows
    def scalars(self): return self
    def all(self): return self._rows


class FakeAsyncSession:
    def __init__(self, *, execute_results=None, store=None):
        self._q = deque(execute_results or [])
        self._store = store or {}
        self.added: list[Any] = []
        self.flush_count = 0

    async def execute(self, _q): return _Result(self._q.popleft() if self._q else [])
    async def get(self, model_cls, pk): return self._store.get((model_cls.__name__, str(pk)))
    def add(self, obj): self.added.append(obj)
    async def flush(self): self.flush_count += 1


class TestRedact:
    def test_drops_psk_and_creds(self) -> None:
        out = _redact({
            "phase1": "aes256",
            "psk": "leak",
            "pre_shared_key": "leak2",
            "nested": {"api_secret": "x", "keepme": 1},
        })
        assert out == {"phase1": "aes256", "nested": {"keepme": 1}}


def test_protocol() -> None:
    c = FirewallBackupContributor()
    assert isinstance(c, BackupContributor)
    assert c.contributor_id == "firewall"
    assert c.depends_on == ("core",)


# ── collect ──────────────────────────────────────────────────────────────


def _dev(site, **kw):
    base = dict(
        id=uuid4(), site_id=site, controller_id=None, name="FW-1",
        description=None, device_type="firewall", ip_address="10.0.0.1",
        port=443, vendor="opnsense", model="DEC740", firmware_version="24.1",
        serial_number="S1", supports_ids=True, supports_vpn=True,
        default_policy="deny", settings={"tz": "UTC"},
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _rule(dev_id, **kw):
    base = dict(
        id=uuid4(), device_id=dev_id, name="Allow HTTP", description=None,
        rule_order=100, source_address="any", source_port=None,
        source_zone="wan", dest_address="10.0.0.0/24", dest_port="80",
        dest_zone="lan", protocol="tcp", action="allow", log_enabled=True,
        is_enabled=True,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _gw(org, **kw):
    base = dict(
        id=uuid4(), org_id=org, site_id=None, device_id=None,
        name="OPN-Conn", description=None, vendor="opnsense",
        host="fw.example.com", port=443, verify_ssl=False,
        sync_enabled=True, sync_interval_seconds=300, capabilities=["rules"],
        settings={"poll": 30},
    )
    base.update(kw)
    return SimpleNamespace(**base)


class TestCollect:
    @pytest.mark.asyncio
    async def test_shape_counts_and_creds_excluded(self) -> None:
        org, site = uuid4(), uuid4()
        dev = _dev(site)
        rule = _rule(dev.id)
        nat = SimpleNamespace(
            id=uuid4(), device_id=dev.id, name="PF-1", description=None,
            nat_type="port_forward", original_address="1.2.3.4",
            original_port="443", translated_address="10.0.0.5",
            translated_port="443", protocol="tcp", interface="wan",
            is_enabled=True,
        )
        vpn = SimpleNamespace(
            id=uuid4(), device_id=dev.id, name="S2S", description=None,
            vpn_type="ipsec", remote_address="2.2.2.2", remote_id="peer",
            local_address="1.1.1.1", local_id="me", local_subnets=["10.0.0.0/24"],
            remote_subnets=["192.168.0.0/24"], auth_type="psk", is_enabled=True,
            settings={"psk": "SHOULD-NOT-EXPORT", "ike": "v2"},
        )
        gw = _gw(org)
        # collect order: devices, rules, nat, vpn, gateway_connections
        session = FakeAsyncSession(execute_results=[
            [dev], [rule], [nat], [vpn], [gw],
        ])

        payload = await FirewallBackupContributor().collect(session, org, {})
        assert payload.counts == {
            "devices": 1, "rules": 1, "nat_rules": 1, "vpn_tunnels": 1,
            "gateway_connections": 1,
        }
        # VPN PSK stripped from settings.
        vpn_out = payload.data["vpn_tunnels"][0]
        assert "psk" not in vpn_out["settings"]
        assert vpn_out["settings"]["ike"] == "v2"
        # GatewayConnection.credentials never serialized.
        gw_out = payload.data["gateway_connections"][0]
        assert "credentials" not in gw_out
        # Non-secret gateway fields ARE carried.
        assert gw_out["host"] == "fw.example.com"
        assert gw_out["vendor"] == "opnsense"

    @pytest.mark.asyncio
    async def test_no_devices_skips_child_queries(self) -> None:
        org = uuid4()
        # devices(empty) → rules/nat/vpn skipped → gateway_connections
        session = FakeAsyncSession(execute_results=[[], []])
        payload = await FirewallBackupContributor().collect(session, org, {})
        assert payload.counts == {
            "devices": 0, "rules": 0, "nat_rules": 0, "vpn_tunnels": 0,
            "gateway_connections": 0,
        }


# ── restore ──────────────────────────────────────────────────────────────


class TestRestore:
    def _payload(self, data): return ContributorPayload(
        schema_version="1.0.0", counts={}, data=data, metadata={},
    )

    @pytest.mark.asyncio
    async def test_cross_tenant_device_rejected(self) -> None:
        org, org_site, foreign = uuid4(), uuid4(), uuid4()
        session = FakeAsyncSession(execute_results=[[org_site]])
        data = {
            "devices": [{"id": str(uuid4()), "site_id": str(foreign),
                         "name": "Evil FW", "ip_address": "9.9.9.9"}],
            "rules": [], "nat_rules": [], "vpn_tunnels": [],
            "gateway_connections": [],
        }
        result = await FirewallBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )
        assert result.skipped["devices"] == 1
        assert result.created["devices"] == 0
        assert any("cross-tenant" in w for w in result.warnings)
        assert session.added == []

    @pytest.mark.asyncio
    async def test_device_rule_inserted_and_orphan_rule_skipped(self) -> None:
        org, site = uuid4(), uuid4()
        good_dev = uuid4()
        missing_dev = uuid4()
        session = FakeAsyncSession(execute_results=[[site]])
        data = {
            "devices": [{"id": str(good_dev), "site_id": str(site),
                         "name": "FW", "ip_address": "10.0.0.1"}],
            "rules": [
                {"id": str(uuid4()), "device_id": str(good_dev),
                 "name": "ok-rule", "action": "allow"},
                {"id": str(uuid4()), "device_id": str(missing_dev),
                 "name": "orphan-rule", "action": "deny"},
            ],
            "nat_rules": [], "vpn_tunnels": [], "gateway_connections": [],
        }
        result = await FirewallBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )
        assert result.created["devices"] == 1
        assert result.created["rules"] == 1   # only the in-device rule
        assert result.skipped["rules"] == 1   # the orphan
        assert any("orphan" in w.lower() for w in result.warnings)

    @pytest.mark.asyncio
    async def test_gateway_cross_org_rejected(self) -> None:
        org, site, foreign_org = uuid4(), uuid4(), uuid4()
        session = FakeAsyncSession(execute_results=[[site]])
        data = {
            "devices": [], "rules": [], "nat_rules": [], "vpn_tunnels": [],
            "gateway_connections": [
                {"id": str(uuid4()), "org_id": str(foreign_org),
                 "name": "Evil GW", "vendor": "opnsense", "host": "x"},
            ],
        }
        result = await FirewallBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )
        assert result.skipped["gateway_connections"] == 1
        assert result.created["gateway_connections"] == 0
        assert any("cross-tenant" in w for w in result.warnings)

    @pytest.mark.asyncio
    async def test_gateway_credentials_never_written(self) -> None:
        """Even if a (malicious / legacy) archive smuggles a credentials
        field, the blocked_fields guard drops it on insert."""
        org, site = uuid4(), uuid4()
        session = FakeAsyncSession(execute_results=[[site]])
        data = {
            "devices": [], "rules": [], "nat_rules": [], "vpn_tunnels": [],
            "gateway_connections": [
                {"id": str(uuid4()), "org_id": str(org), "name": "GW",
                 "vendor": "opnsense", "host": "fw",
                 "credentials": {"api_key": "SMUGGLED"}},
            ],
        }
        await FirewallBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )
        gw = [o for o in session.added
              if type(o).__name__ == "GatewayConnection"]
        assert len(gw) == 1
        # credentials was NOT passed to the constructor (blocked).
        assert not hasattr(gw[0], "credentials") or gw[0].credentials in (None, {})

    @pytest.mark.asyncio
    async def test_dry_run_writes_nothing(self) -> None:
        org, site = uuid4(), uuid4()
        session = FakeAsyncSession(execute_results=[[site]])
        data = {
            "devices": [{"id": str(uuid4()), "site_id": str(site),
                         "name": "FW", "ip_address": "10.0.0.1"}],
            "rules": [], "nat_rules": [], "vpn_tunnels": [],
            "gateway_connections": [],
        }
        result = await FirewallBackupContributor().restore(
            session, org, self._payload(data), dry_run=True, options={},
        )
        assert result.created["devices"] == 1
        assert result.status == "dry_run_ok"
        assert session.added == []
