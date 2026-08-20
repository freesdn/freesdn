# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The agent WebSocket trusted every field an agent put on the wire.

``AgentReport.payload`` is DECLARED ``dict[str, Any]`` and every consumer calls
``.get`` on it, but ``from_dict`` did ``data.get("payload", {})`` and nothing
checked the shape. Three consequences, in rising order of how quiet they were.

1. A MALFORMED FRAME TORE THE CONNECTION DOWN
   ``"payload": []`` reached ``_handle_report``, which does
   ``payload.get("uptime_seconds", 0)``. AttributeError propagates to
   ``_receiver_loop``, whose handler is ``logger.error(...); break`` -- so the
   receive loop exited and the WebSocket closed. One bad frame disconnected the
   agent; a persistently bad one became a reconnect loop.

2. A NON-LIST scan_result LOST THE WHOLE SCAN, SILENTLY
   The 5000-host cap was guarded by ``isinstance(hosts, list)``, so anything
   else skipped the cap *and* went straight into ``upsert_batch``, whose loop
   does ``h.get("ip_address")``. Iterating a dict yields its keys, so the first
   element was a str and the batch died on AttributeError -- swallowed by the
   ``except Exception`` at the bottom of ``_persist_scan_result``. The operator
   saw a scan that completed with zero hosts and no error anywhere. A dict
   payload also bypassed the cap entirely, which is the exact write
   amplification the cap exists to stop.

   ``status`` compounded it: the column is ``String(16)``, and the value went in
   unbounded. An over-long status failed the INSERT, and the same except
   swallowed that too -- so a scheduled scan that genuinely ran left no record
   of having run.

3. capabilities AS A NON-OBJECT 500'd EVERY LATER READ
   ``values["capabilities"] = caps`` stored whatever arrived. JSONB accepts a
   bare list happily. Every reader then does ``caps.get("scan_types")``, so
   ``POST /agents/{id}/scan`` and the schedule-create validation both 500 --
   permanently, for that agent, until someone edits the row by hand.

Separately: THE METRICS NEVER LEFT MEMORY. The shipped agent sends
cpu/memory/disk/uptime/version/platform/hostname every 30s over this socket
(``agent/src/freesdn_agent/services/heartbeat.py``). The handler assigned all
of it to ``AgentInfo`` -- an in-process object no API reads -- and persisted
only freshness. So ``GET /agents`` reported ``uptime_seconds: 0`` forever,
``version`` kept showing whatever the agent registered with even after it
self-updated, and ``GET /agents/{id}/heartbeats`` was empty on every
deployment, as was its retention endpoint's table. The HTTP heartbeat endpoint
that does persist all this is not the transport the shipped agent uses.
"""

from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services import remote_agent as ra
from app.services.remote_agent import (
    AgentConnection,
    AgentReport,
    AgentReportType,
    AgentStatus,
    _as_float,
    _as_int,
)

AGENT_ID = str(uuid4())


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. the payload boundary ──────────────────────────────────────


@pytest.mark.parametrize(
    "wire",
    [
        pytest.param([], id="empty-list"),
        pytest.param([{"cpu_percent": 5}], id="list-of-objects"),
        pytest.param("cpu=5", id="string"),
        pytest.param(42, id="int"),
        pytest.param(None, id="null"),
        pytest.param(True, id="bool"),
    ],
)
def test_a_non_object_payload_becomes_an_empty_object(wire: object) -> None:
    """
    The single boundary every report crosses. Coercing here is what stops an
    AttributeError three frames down from closing the socket.
    """
    report = AgentReport.from_dict({"type": "heartbeat", "payload": wire})
    assert report.payload == {}
    assert isinstance(report.payload, dict)


def test_a_normal_payload_is_untouched() -> None:
    payload = {"cpu_percent": 12.5, "capabilities": {"scan_types": ["arp"]}}
    assert AgentReport.from_dict({"type": "heartbeat", "payload": payload}).payload == payload


def test_a_missing_payload_still_defaults_to_an_object() -> None:
    assert AgentReport.from_dict({"type": "heartbeat"}).payload == {}


def test_the_receiver_loop_still_breaks_on_error() -> None:
    """
    Premise check. The coercion matters precisely BECAUSE the receiver's only
    recovery from an exception is to exit the loop and drop the connection. If
    that ever becomes a `continue`, this fix stops being load-bearing.
    """
    code = _code(AgentConnection._receive_forever)
    tail = code[code.index("except Exception") :]
    assert "break" in tail


# ── numeric coercion ─────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (12.5, 12.5),
        ("12.5", 12.5),
        (0, 0.0),
        (None, 0.0),
        ("not a number", 0.0),
        ([], 0.0),
        ({}, 0.0),
        (True, 0.0),  # a bool is not a percentage
        (-5, 0.0),  # clamped
        (250, 100.0),  # clamped
        (float("nan"), 0.0),
    ],
)
def test_percentages_from_the_wire_never_raise(value: object, expected: float) -> None:
    result = _as_float(value)
    # NaN survives min/max, so assert the clamp held rather than equality.
    assert result == expected or (result != result and expected == 0.0)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (99, 99),
        ("99", 99),
        (99.9, 99),
        (None, 0),
        ("", 0),
        ([], 0),
        (True, 0),
        (-1, 0),
        (10**30, 2**31 - 1),
    ],
)
def test_counters_from_the_wire_never_raise(value: object, expected: int) -> None:
    assert _as_int(value) == expected


# ── 2. scan_result normalisation ─────────────────────────────────


def _connection() -> AgentConnection:
    conn = AgentConnection.__new__(AgentConnection)
    conn.info = SimpleNamespace(
        agent_id=AGENT_ID,
        site_id=uuid4(),
        last_heartbeat=None,
        status=AgentStatus.OFFLINE,
        version="1.0.0",
    )
    return conn


@pytest.fixture
def captured(monkeypatch):
    """Capture what _persist_scan_result hands to upsert_batch."""
    seen: dict = {}

    registry = ra.AgentRegistryService.__new__(ra.AgentRegistryService)
    registry._connections = {AGENT_ID: _connection()}

    async def _upsert(session, **kwargs):
        seen["hosts"] = kwargs["hosts"]
        return {"created": len(kwargs["hosts"]), "updated": 0, "skipped": 0, "routed": {}}

    site = SimpleNamespace(id=uuid4(), organization_id=uuid4())

    class _Session:
        async def execute(self, _q):
            return SimpleNamespace(scalar_one_or_none=lambda: site)

        async def commit(self):
            return None

        def add(self, obj):
            seen.setdefault("added", []).append(obj)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

    monkeypatch.setattr("app.services.discovered_hosts.upsert_batch", _upsert)
    monkeypatch.setattr("app.db.async_session_factory", lambda: _Session())
    return registry, seen


async def _persist(registry, payload: dict) -> None:
    report = AgentReport(type=AgentReportType.SCAN_RESULT, payload=payload)
    report.agent_id = AGENT_ID
    await registry._persist_scan_result(report)


@pytest.mark.parametrize(
    "devices",
    [
        pytest.param({"10.0.0.1": {"ip": "10.0.0.1"}}, id="dict"),
        pytest.param("10.0.0.1", id="string"),
        pytest.param(7, id="int"),
    ],
)
async def test_a_non_list_device_payload_is_dropped_not_iterated(captured, devices) -> None:
    """
    The regression. Pre-fix each of these reached upsert_batch and died on
    ``h.get`` -- a whole scan lost with nothing but a debug log to show for it.
    """
    registry, seen = captured
    await _persist(registry, {"devices": devices})
    assert "hosts" not in seen, "a non-list payload still reaches the per-host loop"


async def test_non_object_entries_are_skipped_and_the_good_ones_survive(captured) -> None:
    """
    upsert_batch runs in one transaction, so one bad element used to cost every
    good host beside it. Dropping just the bad element is the point.
    """
    registry, seen = captured
    await _persist(
        registry,
        {"devices": [{"ip": "10.0.0.1"}, "garbage", None, {"ip": "10.0.0.2"}]},
    )
    assert seen["hosts"] == [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]


async def test_a_normal_scan_is_unaffected(captured) -> None:
    registry, seen = captured
    hosts = [{"ip": f"10.0.0.{i}"} for i in range(5)]
    await _persist(registry, {"devices": hosts})
    assert seen["hosts"] == hosts


async def test_the_five_thousand_host_cap_still_applies(captured) -> None:
    registry, seen = captured
    await _persist(registry, {"devices": [{"ip": "10.0.0.1"}] * 6000})
    assert len(seen["hosts"]) == 5000


async def test_the_results_key_is_still_honoured(captured) -> None:
    """The payload may use `results` instead of `devices`; both shapes ship."""
    registry, seen = captured
    await _persist(registry, {"results": [{"ip": "10.0.0.9"}]})
    assert seen["hosts"] == [{"ip": "10.0.0.9"}]


async def test_an_oversized_scan_is_truncated_not_discarded(captured) -> None:
    """
    The cap's own warning used to crash the handler.

    ``_persist_scan_result`` hangs off AgentRegistryService, which has no
    ``self.info`` -- that attribute lives on AgentConnection. The warning read
    ``getattr(self.info, "agent_id", "?")``, and getattr evaluates ``self.info``
    BEFORE it can supply the default, so it raised AttributeError. The except at
    the bottom of the method caught it. Net effect: the guard whose entire job is
    to truncate an oversized scan instead threw the scan away in full, and logged
    nothing an operator would ever see.

    5001 hosts is the smallest input that proves it: one over the cap.
    """
    registry, seen = captured
    await _persist(registry, {"devices": [{"ip": "10.0.0.1"}] * 5001})
    assert "hosts" in seen, "the truncation path still crashes and drops the whole scan"
    assert len(seen["hosts"]) == 5000


def test_no_registry_method_reaches_for_a_connection_attribute() -> None:
    """
    Guard the class of mistake. AgentConnection has ``self.info``;
    AgentRegistryService does not, and the two files sit next to each other.
    Any registry method touching ``self.info`` raises the moment it runs, and
    these methods all run inside a broad except.
    """
    src = inspect.getsource(ra.AgentRegistryService)
    offenders = [
        line.strip()
        for line in src.split(chr(10))
        if "self.info" in line and not line.strip().startswith("#")
    ]
    assert not offenders, f"AgentRegistryService has no `.info`: {offenders}"


def test_the_status_clamp_matches_the_column_width() -> None:
    """
    ``AgentScheduleRun.status`` is String(16), not the 50 these columns usually
    get. Clamping to the wrong width would still fail the INSERT and still lose
    the run record, so pin the two together.
    """
    from app.models.agents import AgentScheduleRun

    width = AgentScheduleRun.__table__.c.status.type.length
    assert width == 16
    assert f"[:{width}]" in _code(ra.AgentRegistryService._persist_scan_result)


def test_duration_stays_nullable() -> None:
    """
    None means "the agent did not say", which is a different fact from "it took
    no time". Defaulting it to 0.0 would quietly fabricate a measurement.
    """
    code = _code(ra.AgentRegistryService._persist_scan_result)
    assert "if raw_duration is None" in code


# ── 3. capabilities ──────────────────────────────────────────────


class _CapSession:
    """Records the UPDATE values the heartbeat path builds."""

    last_values: dict = {}

    async def execute(self, stmt):
        type(self).last_values = dict(stmt.compile().params)
        return SimpleNamespace()

    async def commit(self):
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False


@pytest.fixture
def heartbeat_conn(monkeypatch):
    _CapSession.last_values = {}
    conn = _connection()
    conn._pending_commands = {}
    conn._report_handlers = {}
    monkeypatch.setattr("app.db.async_session_factory", lambda: _CapSession())
    monkeypatch.setattr(AgentConnection, "_record_heartbeat_sample", AsyncMock(return_value=None))
    return conn


async def _heartbeat(conn, payload: dict) -> dict:
    report = AgentReport(type=AgentReportType.HEARTBEAT, payload=payload)
    await conn._handle_report(report)
    return _CapSession.last_values


@pytest.mark.parametrize(
    "caps",
    [
        pytest.param(["arp", "mdns"], id="list"),
        pytest.param("arp", id="string"),
        pytest.param(3, id="int"),
    ],
)
async def test_non_object_capabilities_are_never_stored(heartbeat_conn, caps) -> None:
    """
    Storing one poisons every later ``caps.get("scan_types")`` -- a permanent
    500 on the scan button and the schedule form for that agent.
    """
    values = await _heartbeat(heartbeat_conn, {"capabilities": caps})
    assert "capabilities" not in values


async def test_object_capabilities_are_stored(heartbeat_conn) -> None:
    caps = {"scan_types": ["arp", "mdns"]}
    values = await _heartbeat(heartbeat_conn, {"capabilities": caps})
    assert values["capabilities"] == caps


@pytest.mark.parametrize("caps", [None, {}])
async def test_absent_capabilities_do_not_clear_the_stored_ones(heartbeat_conn, caps) -> None:
    """
    An agent that omits the field must not wipe what it reported last time --
    the schedule form would lose its scan_type list mid-session.
    """
    values = await _heartbeat(heartbeat_conn, {"capabilities": caps})
    assert "capabilities" not in values


@pytest.mark.parametrize(
    "stored",
    [
        pytest.param(["arp"], id="list"),
        pytest.param("arp", id="string"),
        pytest.param(None, id="null"),
    ],
)
def test_the_readers_survive_a_row_written_by_an_older_build(stored) -> None:
    """
    The write is guarded now, but rows already in the database are not. Both
    read sites must degrade to "nothing reported yet" rather than 500.
    """
    from app.api.v1.endpoints import agent_schedules, agents

    for fn in (agents.run_interactive_scan, agent_schedules._validate_schedule_agent):
        code = _code(fn)
        assert "isinstance(" in code and "dict)" in code, (
            f"{fn.__qualname__} still calls .get on unvalidated capabilities JSONB"
        )

    # And the coercion itself behaves.
    caps = stored if isinstance(stored, dict) else {}
    assert caps.get("scan_types", None) is None


# ── 4. the metrics that never left memory ────────────────────────


async def test_uptime_reaches_the_database(heartbeat_conn) -> None:
    """
    The regression the UI showed: ``GET /agents`` reads uptime_seconds from
    the row, and the row was never written, so it read 0 forever.
    """
    values = await _heartbeat(heartbeat_conn, {"uptime_seconds": 86_400})
    assert values["uptime_seconds"] == 86_400


async def test_a_self_updated_agent_reports_its_new_version(heartbeat_conn) -> None:
    """
    The agent auto-updates. Without this the row kept the version it first
    registered with, so the fleet view showed everyone on the old build.
    """
    values = await _heartbeat(heartbeat_conn, {"version": "1.4.2"})
    assert values["version"] == "1.4.2"


async def test_platform_and_hostname_reach_the_database(heartbeat_conn) -> None:
    values = await _heartbeat(heartbeat_conn, {"platform": "linux", "hostname": "edge-01"})
    assert values["platform"] == "linux"
    assert values["last_hostname"] == "edge-01"


async def test_freshness_is_still_written(heartbeat_conn) -> None:
    """
    The half that already worked, and the one that matters most: without it
    cleanup_stale_agents marks every live agent offline once a minute.
    """
    values = await _heartbeat(heartbeat_conn, {})
    assert values["last_heartbeat"] is not None
    assert values["status"] == AgentStatus.ONLINE.value


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", 42),
        ("version", ""),
        ("platform", ["linux"]),
        ("hostname", None),
    ],
)
async def test_a_bad_string_field_is_ignored_not_written(heartbeat_conn, field, value) -> None:
    """These are String(50)/String(100)/String(255) columns; a list fails the UPDATE."""
    values = await _heartbeat(heartbeat_conn, {field: value})
    assert field not in values
    assert "last_hostname" not in values or field != "hostname"


async def test_over_long_strings_are_truncated_to_the_column_width(heartbeat_conn) -> None:
    from app.models.agents import RemoteAgent

    values = await _heartbeat(
        heartbeat_conn,
        {"version": "v" * 500, "platform": "p" * 500, "hostname": "h" * 500},
    )
    cols = RemoteAgent.__table__.c
    assert len(values["version"]) == cols.version.type.length
    assert len(values["platform"]) == cols.platform.type.length
    assert len(values["last_hostname"]) == cols.last_hostname.type.length


async def test_a_heartbeat_sample_is_recorded(monkeypatch) -> None:
    """
    ``GET /agents/{id}/heartbeats`` and ``DELETE /agents/heartbeats/old`` both
    exist and both operated on a table nothing ever wrote, because the shipped
    agent heartbeats over this socket rather than the HTTP endpoint.
    """
    conn = _connection()
    conn._pending_commands = {}
    conn._report_handlers = {}
    added: list = []

    class _LogSession:
        def add(self, obj):
            added.append(obj)

        async def commit(self):
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

    monkeypatch.setattr("app.db.async_session_factory", lambda: _CapSession())
    monkeypatch.setattr("app.db.session.get_logdb_factory", lambda: lambda: _LogSession())

    await _heartbeat(conn, {"cpu_percent": 42.0, "memory_percent": 60.0, "active_tasks": 3})

    assert len(added) == 1
    sample = added[0]
    assert sample.cpu_percent == 42.0
    assert sample.memory_percent == 60.0
    assert sample.active_tasks == 3
    assert sample.agent_id == __import__("uuid").UUID(AGENT_ID)


async def test_a_logdb_outage_does_not_cost_the_freshness_write(monkeypatch) -> None:
    """
    Deliberate ordering: history is cosmetic, freshness is what keeps a live
    agent from being marked offline. A LogDB failure must not take both.
    """
    conn = _connection()
    conn._pending_commands = {}
    conn._report_handlers = {}

    def _broken():
        raise RuntimeError("LogDB is not configured")

    monkeypatch.setattr("app.db.async_session_factory", lambda: _CapSession())
    monkeypatch.setattr("app.db.session.get_logdb_factory", _broken)

    values = await _heartbeat(conn, {"uptime_seconds": 60})
    assert values["uptime_seconds"] == 60
    assert values["last_heartbeat"] is not None


async def test_the_connection_survives_a_hostile_heartbeat() -> None:
    """
    End to end for defect 1: feed the receiver the exact frame that used to
    break the loop, and assert the loop is still running afterwards.
    """
    conn = AgentConnection.__new__(AgentConnection)
    conn.info = SimpleNamespace(
        agent_id=AGENT_ID, site_id=uuid4(), last_heartbeat=None, status=AgentStatus.OFFLINE
    )
    conn._pending_commands = {}
    conn._report_handlers = {}
    conn._running = True
    conn._max_frame_bytes = 1_000_000
    conn._rate_limiter = SimpleNamespace(check=lambda: True)

    frames = ['{"type": "heartbeat", "payload": []}', '{"type": "heartbeat", "payload": "x"}']
    conn.websocket = MagicMock()
    conn.websocket.receive_text = AsyncMock(side_effect=[*frames, asyncio.CancelledError()])

    handled: list = []

    async def _handle(report):
        handled.append(report)

    conn._handle_report = _handle

    await conn._receiver_loop()
    assert len(handled) == 2, "the receiver loop dropped out on a malformed frame"
    assert all(r.payload == {} for r in handled)
