# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The agent's syslog / SNMP-trap / DHCP listeners reported into nothing
=====================================================================

``freesdn_agent/listeners/syslog.py`` reports wire type ``log``;
``snmp_trap.py`` and ``dhcp_watcher.py`` report ``device_event``.  Both types
parse cleanly into ``AgentReport`` and are then dropped:
``AgentConnection._handle_report`` ends at
``self._report_handlers.get(report.type, [])`` and
``register_connection`` only ever registered SCAN_RESULT, TOPOLOGY_UPDATE,
SCAN_PROGRESS, ACTION_RESULT and ERROR.  An operator who turned on
``enable_snmp_traps`` / ``enable_syslog`` / ``enable_dhcp_watcher`` got a
privileged UDP listener on 162/514, a rising ``reported`` counter on the
agent, and an empty Log Explorer.

These tests drive the real ``AgentConnection._handle_report`` dispatch path so
they fail if either the handler bodies or their registration regress.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from app.api.v1.endpoints import agents as agents_api
from app.services.remote_agent import (
    AgentConnection,
    AgentInfo,
    AgentReport,
    AgentReportType,
)

ORG_ID = uuid4()
SITE_ID = uuid4()
AGENT_ID = uuid4()


# ── Doubles ─────────────────────────────────────────────────────────────────


class _FakeResult:
    def scalar_one_or_none(self) -> Any:
        return None


class _FakeSession:
    def __init__(self, sink: list[Any]) -> None:
        self._sink = sink
        self.commits = 0

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def execute(self, _stmt: Any) -> _FakeResult:
        return _FakeResult()

    def add(self, obj: Any) -> None:
        self._sink.append(obj)

    async def commit(self) -> None:
        self.commits += 1


class _StubResolver:
    """Stands in for the collector's SourceResolver (which needs a DB)."""

    def __init__(self, value: Any = None) -> None:
        self._value = value

    async def resolve(self, _ip: str) -> Any:
        return self._value


@pytest.fixture
def stored(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Rows handed to ``session.add`` by the report handlers."""
    import app.db as db_mod

    sink: list[Any] = []
    monkeypatch.setattr(db_mod, "async_session_factory", lambda: _FakeSession(sink))
    monkeypatch.setattr(agents_api, "_agent_source_resolver", _StubResolver(None))
    return sink


def _connection() -> AgentConnection:
    """A real AgentConnection with the two handlers under test attached.

    ``start()`` is never called, so no socket task exists; ``_handle_report``
    is the exact method the receiver loop calls per frame.
    """
    conn = AgentConnection(
        AgentInfo(agent_id=str(AGENT_ID), site_id=SITE_ID, site_name="HQ"),
        websocket=None,
    )
    conn.add_report_handler(
        AgentReportType.LOG,
        agents_api._make_log_report_handler(ORG_ID),
    )
    conn.add_report_handler(
        AgentReportType.DEVICE_EVENT,
        agents_api._make_device_event_handler(SITE_ID, ORG_ID, AGENT_ID),
    )
    return conn


# ── log reports (syslog) ────────────────────────────────────────────────────


async def test_syslog_report_is_persisted(stored: list[Any]) -> None:
    """The payload shape is ``parse_syslog()``'s, verbatim."""
    await _connection()._handle_report(
        AgentReport(
            type=AgentReportType.LOG,
            payload={
                "source": "syslog",
                "source_ip": "10.4.57.9",
                "facility": "daemon",
                "severity": "info",
                "hostname": "sw-core-1",
                "app_name": "hostapd",
                "proc_id": "912",
                "message": "AP-STA-CONNECTED aa:bb:cc:dd:ee:ff",
                "timestamp": "2026-08-27T01:02:03+00:00",
            },
        )
    )

    (row,) = stored
    assert row.source_type == "syslog"
    assert row.source_ip == "10.4.57.9"
    assert row.organization_id == ORG_ID
    assert row.hostname == "sw-core-1"
    assert row.app_name == "hostapd"
    assert row.message == "AP-STA-CONNECTED aa:bb:cc:dd:ee:ff"
    # The agent spells severity 6 "info"; the collector stores (and
    # /collector/logs filters on) "informational".
    assert row.severity == "informational"
    # Unmapped fields are kept rather than thrown away.
    assert "proc_id" in (row.raw_data or "")


async def test_syslog_report_without_a_source_is_dropped(stored: list[Any]) -> None:
    """``source_ip`` and ``message`` are both NOT NULL columns."""
    await _connection()._handle_report(
        AgentReport(type=AgentReportType.LOG, payload={"message": "orphan"})
    )
    assert stored == []


async def test_a_resolved_device_is_stamped_only_within_the_agents_org(
    stored: list[Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RFC1918 addresses collide across orgs; an agent forwards whatever its
    LAN sends it, so a device from another org must not be attached."""
    device_id = uuid4()
    payload = {"source_ip": "192.168.1.10", "message": "hello"}

    monkeypatch.setattr(agents_api, "_agent_source_resolver", _StubResolver((ORG_ID, device_id)))
    await _connection()._handle_report(AgentReport(type=AgentReportType.LOG, payload=payload))
    assert stored[-1].device_id == device_id

    monkeypatch.setattr(agents_api, "_agent_source_resolver", _StubResolver((uuid4(), device_id)))
    await _connection()._handle_report(AgentReport(type=AgentReportType.LOG, payload=payload))
    assert stored[-1].device_id is None


# ── device_event: SNMP traps ────────────────────────────────────────────────


async def test_snmp_trap_is_persisted_without_the_community(stored: list[Any]) -> None:
    await _connection()._handle_report(
        AgentReport(
            type=AgentReportType.DEVICE_EVENT,
            payload={
                "event_type": "snmp_trap",
                "source_ip": "10.4.57.1",
                "snmp_version": "v2",
                "community_length": 6,
                "variables": {"1.3.6.1.6.3.1.1.4.1.0": "1.3.6.1.6.3.1.1.5.3"},
                "trap_oid": "1.3.6.1.6.3.1.1.5.3",
                "timestamp": "2026-08-27T01:02:03+00:00",
            },
        )
    )

    (row,) = stored
    assert row.source_type == "snmp_trap"
    assert row.trap_type == "1.3.6.1.6.3.1.1.5.3"
    assert row.varbinds == {"1.3.6.1.6.3.1.1.4.1.0": "1.3.6.1.6.3.1.1.5.3"}
    assert row.organization_id == ORG_ID
    # /collector/logs hands this message to any collector.logs.read holder.
    assert "<redacted>" in row.message
    assert "community_length" not in row.message


async def test_snmp_v1_trap_identity_comes_from_the_generic_specific_pair(
    stored: list[Any],
) -> None:
    await _connection()._handle_report(
        AgentReport(
            type=AgentReportType.DEVICE_EVENT,
            payload={
                "event_type": "snmp_trap",
                "source_ip": "10.4.57.1",
                "snmp_version": "v1",
                "enterprise": "1.3.6.1.4.1.9",
                "generic_trap": 6,
                "specific_trap": 1,
                "variables": {},
            },
        )
    )

    (row,) = stored
    assert row.trap_type == "generic:6/specific:1"
    assert row.enterprise_oid == "1.3.6.1.4.1.9"


# ── device_event: DHCP sightings ────────────────────────────────────────────


async def test_dhcp_sighting_lands_in_discovered_hosts(
    monkeypatch: pytest.MonkeyPatch,
    stored: list[Any],
) -> None:
    import app.services.discovered_hosts as dh

    captured: dict[str, Any] = {}

    async def _fake_upsert_batch(_session: Any, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"created": 1, "updated": 0, "skipped": 0, "routed": {}}

    monkeypatch.setattr(dh, "upsert_batch", _fake_upsert_batch)

    await _connection()._handle_report(
        AgentReport(
            type=AgentReportType.DEVICE_EVENT,
            payload={
                "event_type": "dhcp_discovery",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "requested_ip": "10.4.57.201",
                "hostname": "laptop-7",
                "vendor_class": "MSFT 5.0",
                "dhcp_message": "DHCPREQUEST",
            },
        )
    )

    assert captured["site_id"] == SITE_ID
    assert captured["organization_id"] == ORG_ID
    assert captured["discovered_by_agent_id"] == AGENT_ID
    assert captured["hosts"] == [
        {
            "ip_address": "10.4.57.201",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "hostname": "laptop-7",
            "discovered_via": ["dhcp"],
        }
    ]


async def test_dhcp_discover_without_an_address_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
    stored: list[Any],
) -> None:
    """A DHCPDISCOVER before any offer has no address to record, and
    ``upsert_batch`` skips IP-less rows anyway."""
    import app.services.discovered_hosts as dh

    called = False

    async def _fake_upsert_batch(*_a: Any, **_kw: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(dh, "upsert_batch", _fake_upsert_batch)

    await _connection()._handle_report(
        AgentReport(
            type=AgentReportType.DEVICE_EVENT,
            payload={"event_type": "dhcp_discovery", "mac_address": "AA:BB:CC:DD:EE:FF"},
        )
    )

    assert called is False


async def test_an_unknown_device_event_is_named_not_silently_dropped(
    stored: list[Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING"):
        await _connection()._handle_report(
            AgentReport(
                type=AgentReportType.DEVICE_EVENT,
                payload={"event_type": "lldp_neighbour"},
            )
        )

    assert stored == []
    assert "lldp_neighbour" in caplog.text


# ── the registration that was missing ───────────────────────────────────────


def test_the_websocket_endpoint_registers_both_report_types() -> None:
    """The bug was never the handler bodies -- it was that nothing called
    ``add_report_handler`` for these two types, so the dispatch above found an
    empty list. ``register_connection`` is the only place an AgentConnection is
    created (``grep -rn register_connection app/`` -> agents.py:1382 only), so
    the endpoint is where the subscription has to happen.
    """
    import inspect

    src = inspect.getsource(agents_api.agent_websocket)
    assert "AgentReportType.LOG" in src
    assert "AgentReportType.DEVICE_EVENT" in src
    assert "_make_log_report_handler" in src
    assert "_make_device_event_handler" in src


async def test_reports_from_an_org_less_agent_are_dropped_not_stored(
    stored: list[Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``GET /collector/logs`` filters on
    ``CollectorLog.organization_id == caller org``, so a row written with a
    NULL org is a write nothing can read back -- a silent inert success. The
    collector's own receivers drop sources they cannot tenant-tag; so does
    this path."""
    conn = AgentConnection(
        AgentInfo(agent_id=str(AGENT_ID), site_id=SITE_ID, site_name="HQ"),
        websocket=None,
    )
    conn.add_report_handler(
        AgentReportType.LOG,
        agents_api._make_log_report_handler(None),
    )
    conn.add_report_handler(
        AgentReportType.DEVICE_EVENT,
        agents_api._make_device_event_handler(SITE_ID, None, AGENT_ID),
    )

    with caplog.at_level("WARNING"):
        await conn._handle_report(
            AgentReport(
                type=AgentReportType.LOG,
                payload={"source_ip": "10.0.0.1", "message": "hi"},
            )
        )
        await conn._handle_report(
            AgentReport(
                type=AgentReportType.DEVICE_EVENT,
                payload={"event_type": "snmp_trap", "source_ip": "10.0.0.1"},
            )
        )

    assert stored == []
    assert caplog.text.count("no resolvable organization") == 2
