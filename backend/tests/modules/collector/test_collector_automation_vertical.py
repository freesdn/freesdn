# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The collector was a dead end, so no observability signal could automate anything.

``capability_maturity.py`` rates the automation engine EXPERIMENTAL with the note
"no full real-world vertical proven E2E yet", and this is the reason. The chain
has four links and the first one was missing:

    device emits syslog/trap
      -> collector ingests, resolves source IP to a device, stores a row
      -> [MISSING] nothing published
      -> automation rule matches
      -> fabric operation stages a write on another vendor's box

``SyslogReceiver._process`` and ``SNMPTrapReceiver._handle`` both ended at
``db.commit()``. ``collector.*`` appeared in the codebase only as permission
strings -- never as an event name. ``_ALL_KNOWN_EVENTS`` had no collector entry,
and ``alert_rules`` never reads ``CollectorLog``. Meanwhile
``IMPLEMENTED_TRIGGER_TYPES`` is ``{EVENT, MANUAL}``: a rule fires from the bus
or from a button, and nothing else.

So a device could report a failing power supply and the only possible outcome
was a searchable log line.

**Why the link was missing rather than forgotten.** Publishing every syslog
message is not viable -- one chatty firewall emits thousands a second and the
bus fans out to Redis, the WebSocket forwarder and every loaded rule. The bus's
own dedup is per event id and is no defence against volume. So the bridge is
gated twice, by severity and by rate, and both gates are tested here: a bridge
that floods is as unusable as no bridge, and one that silently mutes a device is
worse than either.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from app.modules.collector.services.events import (
    COLLECTOR_EVENT_TYPES,
    SEVERITY_ORDER,
    CollectorEventPublisher,
)

ORG = uuid4()
DEVICE = uuid4()


def _record(**over):
    base = {
        "source_type": "syslog",
        "organization_id": ORG,
        "device_id": DEVICE,
        "source_ip": "192.168.10.1",
        "severity": "error",
        "facility": "local0",
        "hostname": "fw-edge",
        "app_name": "kernel",
        "message": "power supply 2 failed",
    }
    base.update(over)
    return base


@pytest.fixture
def captured(monkeypatch):
    """Capture what reaches the bus without standing one up."""
    seen: list = []

    class _Bus:
        async def publish(self, event):
            seen.append(event)

    import app.core.events as events_mod

    monkeypatch.setattr(events_mod, "event_bus", _Bus(), raising=True)
    return seen


class _FakeRedis:
    """Enough Redis to exercise the cluster-wide cap deterministically.

    INCR-with-TTL is the whole contract here. Sharing one instance between two
    publishers is what a second gunicorn worker looks like from the limiter's
    point of view.
    """

    def __init__(self):
        self.store: dict[str, int] = {}
        self.expiries: dict[str, int] = {}
        self.expire_calls = 0

    async def incr(self, key):
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key, ttl):
        self.expiries[key] = ttl
        self.expire_calls += 1
        return True


class _DeadRedis:
    async def incr(self, key):
        raise ConnectionError("redis is down")

    async def expire(self, key, ttl):
        raise ConnectionError("redis is down")


# ── the severity gate ───────────────────────────────────────────


async def test_a_severe_message_is_published(captured):
    """The whole point: an error-level log must reach the bus."""
    published = await CollectorEventPublisher(redis=_FakeRedis()).publish("syslog", _record())

    assert published is True
    assert len(captured) == 1
    assert captured[0].event_type == "collector.syslog.received"


@pytest.mark.parametrize("severity", ["emergency", "alert", "critical", "error", "warning"])
async def test_everything_at_or_above_the_floor_is_published(captured, severity):
    assert await CollectorEventPublisher(redis=_FakeRedis()).publish("syslog", _record(severity=severity)) is True


@pytest.mark.parametrize("severity", ["notice", "informational", "debug"])
async def test_routine_chatter_is_not(captured, severity):
    """
    The gate that makes this viable at all. These three severities are the bulk
    of real syslog volume, and waking every automation rule for a debug line
    would make the bridge unusable in exactly the deployments that need it.
    """
    pub = CollectorEventPublisher(redis=_FakeRedis())

    assert await pub.publish("syslog", _record(severity=severity)) is False
    assert captured == []
    assert pub.stats()["suppressed_by_severity"] == 1


def test_the_severity_ordering_runs_backwards_and_is_pinned():
    """
    RFC 5424 numbers 0 as the WORST. "At or above warning" therefore means a
    number less than or equal to 4, which is the easiest thing in this file to
    invert, and inverting it would publish only the debug chatter.
    """
    assert SEVERITY_ORDER["emergency"] < SEVERITY_ORDER["error"]
    assert SEVERITY_ORDER["error"] < SEVERITY_ORDER["warning"]
    assert SEVERITY_ORDER["warning"] < SEVERITY_ORDER["debug"]


async def test_an_unreadable_severity_is_published_not_dropped(captured):
    """
    A message whose severity could not be parsed is not evidence that it is
    unimportant. Dropping the malformed ones would preferentially silence the
    devices with the worst syslog implementations, which are not the devices
    you want to hear less from.
    """
    for value in (None, "wat"):
        assert await CollectorEventPublisher(redis=_FakeRedis()).publish("syslog", _record(severity=value)) is True


# ── the rate gate ───────────────────────────────────────────────


async def test_one_flapping_device_cannot_storm_the_engine(captured):
    """
    An interface that flaps re-sends the same message continuously. Without a
    cap, each one fans out to Redis and every loaded rule.
    """
    pub = CollectorEventPublisher(redis=_FakeRedis(), rate_limit=3, rate_window_seconds=60)

    results = [await pub.publish("syslog", _record()) for _ in range(10)]

    assert results[:3] == [True, True, True]
    assert not any(results[3:])
    assert len(captured) == 3
    assert pub.stats()["suppressed_by_rate"] == 7


async def test_throttling_one_message_does_not_mute_the_device(captured):
    """
    The cap is keyed per app and severity as well as per device. A router
    repeating an interface flap must not also suppress a genuinely different
    critical message from the same box -- which a per-device-only key would do,
    and that is the failure that makes an operator distrust the whole feature.
    """
    pub = CollectorEventPublisher(redis=_FakeRedis(), rate_limit=2, rate_window_seconds=60)

    for _ in range(5):
        await pub.publish("syslog", _record(app_name="link", severity="warning"))
    breakthrough = await pub.publish("syslog", _record(app_name="psu", severity="critical"))

    assert breakthrough is True
    assert captured[-1].payload["message"] == "power supply 2 failed"


async def test_two_devices_have_separate_budgets(captured):
    pub = CollectorEventPublisher(redis=_FakeRedis(), rate_limit=1, rate_window_seconds=60)
    other = uuid4()

    assert await pub.publish("syslog", _record()) is True
    assert await pub.publish("syslog", _record()) is False
    assert await pub.publish("syslog", _record(device_id=other)) is True


async def test_the_window_expires(captured):
    pub = CollectorEventPublisher(redis=_FakeRedis(), rate_limit=1, rate_window_seconds=0.05)

    assert await pub.publish("syslog", _record()) is True
    assert await pub.publish("syslog", _record()) is False
    await asyncio.sleep(0.08)
    assert await pub.publish("syslog", _record()) is True


async def test_suppression_is_counted_not_silent(captured):
    """
    A rule that never fires has several possible causes -- nothing arrived, it
    was below the floor, it was throttled, or the source could not be resolved
    to a tenant -- and from outside they all look identical. The counters are
    what makes that diagnosable.

    Asserts the fields it cares about rather than the whole dict: an exact
    comparison here broke the moment two counters were added, which is a
    maintenance trap rather than a real check.
    """
    pub = CollectorEventPublisher(redis=_FakeRedis(), rate_limit=1)
    await pub.publish("syslog", _record(severity="debug"))
    await pub.publish("syslog", _record(organization_id=None))
    await pub.publish("syslog", _record())
    await pub.publish("syslog", _record())

    stats = pub.stats()

    assert stats["published"] == 1
    assert stats["suppressed_by_severity"] == 1
    assert stats["suppressed_no_org"] == 1
    assert stats["suppressed_by_rate"] == 1
    assert stats["severity_floor"] == "warning"
    assert stats["tracked_sources"] >= 1


# ── the payload an operator writes rules against ────────────────


async def test_the_payload_carries_what_a_rule_needs(captured):
    await CollectorEventPublisher(redis=_FakeRedis()).publish("syslog", _record())
    payload = captured[0].payload

    for field in ("device_id", "source_ip", "severity", "severity_number", "hostname", "message"):
        assert field in payload, f"a rule cannot condition on {field}"

    assert payload["device_id"] == str(DEVICE)
    assert payload["severity"] == "error"
    assert payload["severity_number"] == 3


async def test_the_payload_is_json_safe(captured):
    """
    UUIDs are stringified here rather than at the bus. Redis publish
    json-encodes, and a raw UUID raises there -- inside the fan-out, after the
    log row is already committed, where the failure is a warning nobody reads.
    """
    import json

    await CollectorEventPublisher(redis=_FakeRedis()).publish("syslog", _record())

    json.dumps(captured[0].payload)


async def test_the_event_is_org_scoped(captured):
    """
    The bus routes by ``organization_id`` on the Event, not by whatever is in
    the payload. Without it the event lands on the 'system' scope and every
    tenant's rules see another tenant's logs.
    """
    await CollectorEventPublisher(redis=_FakeRedis()).publish("syslog", _record())

    assert captured[0].organization_id == str(ORG)


async def test_a_numeric_comparison_can_express_worse_than(captured):
    """
    ``severity_number`` exists so a rule can say "error or worse" without
    enumerating names. Enumerating is what an operator does when the ordering
    is not exposed, and they get it backwards.
    """
    await CollectorEventPublisher(redis=_FakeRedis()).publish("syslog", _record(severity="critical"))

    assert captured[0].payload["severity_number"] < SEVERITY_ORDER["error"]


# ── the join to the rest of the chain ───────────────────────────


def test_the_events_are_registered_so_rules_can_subscribe(captured):
    """
    An event the collector publishes but nothing can name is still a dead end.
    ``EVENT_CATEGORIES`` is what the integrations UI offers, what the webhook
    validator accepts, and what a plugin manifest is checked against.
    """
    from app.api.v1.endpoints.integrations import _ALL_KNOWN_EVENTS

    for event_type in COLLECTOR_EVENT_TYPES.values():
        assert event_type in _ALL_KNOWN_EVENTS, f"{event_type} cannot be subscribed to"


def test_the_engine_can_actually_be_triggered_by_these():
    """
    The other end of the join. The engine fires on exactly two trigger types,
    and a bus event is one of them -- so publishing is sufficient, and no new
    trigger type is needed.
    """
    from app.services.automation import IMPLEMENTED_TRIGGER_TYPES, TriggerType

    assert TriggerType.EVENT in IMPLEMENTED_TRIGGER_TYPES


async def test_an_automation_condition_matches_the_published_payload(captured):
    """
    The end-to-end property, checked against the real ``Condition`` evaluator
    rather than a hand-rolled dict comparison: a rule written the way an
    operator would write it must match what the collector actually publishes.

    This is the link that did not exist. If the payload key names drift from
    what a condition addresses, everything above still passes and no rule ever
    fires.
    """
    from app.services.automation import Condition, ConditionGroup, ConditionOperator

    await CollectorEventPublisher(redis=_FakeRedis()).publish("syslog", _record(severity="critical"))
    payload = captured[0].payload

    rule = ConditionGroup(
        conditions=[
            Condition(
                field="severity_number",
                operator=ConditionOperator.LESS_EQUAL,
                value=SEVERITY_ORDER["error"],
            ),
            Condition(
                field="message",
                operator=ConditionOperator.CONTAINS,
                value="power supply",
            ),
        ],
        logic="and",
    )

    assert rule.evaluate(payload) is True


async def test_a_condition_that_should_not_match_does_not(captured):
    """Guards the test above from passing because everything matches."""
    from app.services.automation import Condition, ConditionGroup, ConditionOperator

    await CollectorEventPublisher(redis=_FakeRedis()).publish("syslog", _record(severity="warning"))

    rule = ConditionGroup(
        conditions=[
            Condition(
                field="severity_number",
                operator=ConditionOperator.LESS_EQUAL,
                value=SEVERITY_ORDER["error"],
            )
        ],
        logic="and",
    )

    assert rule.evaluate(captured[0].payload) is False


def test_the_fabric_action_the_vertical_ends_in_exists():
    """
    The far end of the chain. ``fabric.operation`` is what lets a rule act on a
    different vendor's box than the one that raised the log, and its writes
    stage through the dual gate rather than being applied.
    """
    from app.services.automation import ActionType

    assert ActionType.FABRIC_OPERATION == "fabric.operation"


# ── the join itself, driven through the receiver ────────────────


class _FakeResolver:
    """Source IP -> (organization, device), the receiver's own contract."""

    def __init__(self, mapping):
        self._mapping = mapping

    async def resolve(self, source_ip):
        return self._mapping.get(source_ip)


class _FakeSession:
    def __init__(self, sink):
        self._sink = sink

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def add(self, row):
        self._sink.append(row)

    async def commit(self):
        return None


async def test_a_real_syslog_packet_reaches_the_bus(captured):
    """
    The join, driven through ``SyslogReceiver._process`` rather than by calling
    the publisher directly.

    Every other test in this file exercises the publisher, and a mutation that
    deleted the bridge call from the receiver entirely survived all of them --
    the component was covered and the wiring was not, which is the one thing
    this work exists to add.

    A real RFC 3164 line: <27> is facility 3, severity 3 (error).
    """
    import ipaddress

    from app.modules.collector.services.syslog import SyslogReceiver

    stored: list = []
    receiver = SyslogReceiver(
        session_factory=lambda: _FakeSession(stored),
        resolver=_FakeResolver({"192.168.10.1": (ORG, DEVICE)}),
        publisher=CollectorEventPublisher(redis=_FakeRedis()),
        allowlist=[ipaddress.ip_network("192.168.10.0/24")],
    )

    await receiver._process("<27>Oct 11 22:14:15 fw-edge kernel: power supply 2 failed", "192.168.10.1")

    assert len(stored) == 1, "the log row is still the product and must be stored"
    assert len(captured) == 1, "the packet was stored but nothing reached the bus"

    event = captured[0]
    assert event.event_type == "collector.syslog.received"
    assert event.organization_id == str(ORG)
    assert event.payload["device_id"] == str(DEVICE)
    assert "power supply" in event.payload["message"]


async def test_a_packet_from_an_unknown_source_publishes_nothing(captured):
    """
    The receiver drops unresolvable sources before storing, to avoid an
    un-tenanted bucket of rows. An event published after that point would be
    the same leak by another route -- an org-less event lands on the 'system'
    scope, where every tenant's rules see it.
    """
    import ipaddress

    from app.modules.collector.services.syslog import SyslogReceiver

    stored: list = []
    receiver = SyslogReceiver(
        session_factory=lambda: _FakeSession(stored),
        resolver=_FakeResolver({}),
        publisher=CollectorEventPublisher(redis=_FakeRedis()),
        allowlist=[ipaddress.ip_network("192.168.10.0/24")],
    )

    await receiver._process("<27>Oct 11 22:14:15 fw-edge kernel: psu failed", "192.168.10.1")

    assert stored == []
    assert captured == []


async def test_a_packet_rejected_by_the_allowlist_publishes_nothing(captured):
    """
    The allowlist is the collector's front door. Anyone can send UDP to it, so
    an event published before that check would let an unauthenticated packet
    trigger automation rules.
    """
    import ipaddress

    from app.modules.collector.services.syslog import SyslogReceiver

    receiver = SyslogReceiver(
        session_factory=lambda: _FakeSession([]),
        resolver=_FakeResolver({"10.0.0.9": (ORG, DEVICE)}),
        publisher=CollectorEventPublisher(redis=_FakeRedis()),
        allowlist=[ipaddress.ip_network("192.168.10.0/24")],
    )

    await receiver._process("<27>Oct 11 22:14:15 rogue kernel: psu failed", "10.0.0.9")

    assert captured == []


async def test_the_log_is_still_stored_when_the_bus_fails(captured, monkeypatch):
    """
    Publishing is best-effort on top of the stored row, never a precondition
    for it. The commit has already happened by the time the bridge runs, and a
    Redis outage must not cost an operator the log line.
    """
    import ipaddress

    import app.core.events as events_mod
    from app.modules.collector.services.syslog import SyslogReceiver

    class _BrokenBus:
        async def publish(self, event):
            raise RuntimeError("redis is down")

    monkeypatch.setattr(events_mod, "event_bus", _BrokenBus(), raising=True)

    stored: list = []
    receiver = SyslogReceiver(
        session_factory=lambda: _FakeSession(stored),
        resolver=_FakeResolver({"192.168.10.1": (ORG, DEVICE)}),
        publisher=CollectorEventPublisher(redis=_FakeRedis()),
        allowlist=[ipaddress.ip_network("192.168.10.0/24")],
    )

    await receiver._process("<27>Oct 11 22:14:15 fw-edge kernel: psu failed", "192.168.10.1")

    assert len(stored) == 1, "a bus failure cost the operator the log row"


async def test_a_receiver_without_a_publisher_still_works(captured):
    """
    ``publisher=None`` must stay a supported configuration: the existing unit
    tests construct receivers that way, and an embedded caller may not want the
    bus at all.
    """
    import ipaddress

    from app.modules.collector.services.syslog import SyslogReceiver

    stored: list = []
    receiver = SyslogReceiver(
        session_factory=lambda: _FakeSession(stored),
        resolver=_FakeResolver({"192.168.10.1": (ORG, DEVICE)}),
        allowlist=[ipaddress.ip_network("192.168.10.0/24")],
    )

    await receiver._process("<27>Oct 11 22:14:15 fw-edge kernel: psu failed", "192.168.10.1")

    assert len(stored) == 1
    assert captured == []


def test_the_manager_actually_supplies_a_publisher():
    """
    Structural, and the reason it is here: the bridge is inert unless the
    manager passes a publisher to both receivers. Wiring one and forgetting the
    other is a silent half-feature -- syslog automates, traps do not.
    """
    import inspect

    from app.modules.collector.services import manager as manager_mod

    src = inspect.getsource(manager_mod)
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))

    assert body.count("publisher=self._publisher") == 2, (
        "both SyslogReceiver and SNMPTrapReceiver must be given the publisher"
    )


def _snmp_v2c_trap(community: bytes = b"public") -> bytes:
    """A minimal, real v2c trap packet, BER-encoded.

    Built the same way ``tests/security/test_convergence_fixes.py`` builds one,
    so this exercises the actual parser rather than a stand-in for it.
    """

    def ber(tag: int, payload: bytes) -> bytes:
        return bytes([tag, len(payload)]) + payload  # short-form length (<128)

    version = ber(0x02, b"\x01")  # v2c
    comm = ber(0x04, community)
    int0 = ber(0x02, b"\x00")
    vbl = ber(0x30, b"")
    pdu = ber(0xA7, int0 + int0 + int0 + vbl)
    return ber(0x30, version + comm + pdu)


async def test_a_real_snmp_trap_reaches_the_bus(captured):
    """
    The trap half of the join. Written after a mutation that deleted the trap
    bridge survived every other test in this file -- syslog was covered, traps
    were not, which is exactly the silent half-feature the manager test guards
    against at the wiring level and this one guards at the behavioural level.
    """
    import ipaddress

    from app.modules.collector.services.snmp_trap import SNMPTrapReceiver

    stored: list = []
    receiver = SNMPTrapReceiver(
        session_factory=lambda: _FakeSession(stored),
        resolver=_FakeResolver({"192.168.10.2": (ORG, DEVICE)}),
        publisher=CollectorEventPublisher(redis=_FakeRedis()),
        allowlist=[ipaddress.ip_network("192.168.10.0/24")],
    )

    await receiver._handle(_snmp_v2c_trap(), "192.168.10.2")

    assert len(stored) == 1, "the trap row is still the product and must be stored"
    assert len(captured) == 1, "the trap was stored but nothing reached the bus"

    event = captured[0]
    assert event.event_type == "collector.trap.received"
    assert event.organization_id == str(ORG)
    assert event.payload["source_type"] == "snmp_trap"


async def test_a_trap_from_an_unknown_source_publishes_nothing(captured):
    import ipaddress

    from app.modules.collector.services.snmp_trap import SNMPTrapReceiver

    receiver = SNMPTrapReceiver(
        session_factory=lambda: _FakeSession([]),
        resolver=_FakeResolver({}),
        publisher=CollectorEventPublisher(redis=_FakeRedis()),
        allowlist=[ipaddress.ip_network("192.168.10.0/24")],
    )

    await receiver._handle(_snmp_v2c_trap(), "192.168.10.2")

    assert captured == []


async def test_a_trap_never_puts_the_community_on_the_bus(captured):
    """
    The community string is a device credential. It is redacted before the row
    is persisted, and the published payload is built from that same parsed
    dict -- but the bus fans out to Redis and to every WebSocket subscriber,
    which is a wider audience than the log table, so it is worth asserting
    rather than assuming.
    """
    import ipaddress

    from app.modules.collector.services.snmp_trap import SNMPTrapReceiver

    receiver = SNMPTrapReceiver(
        session_factory=lambda: _FakeSession([]),
        resolver=_FakeResolver({"192.168.10.2": (ORG, DEVICE)}),
        publisher=CollectorEventPublisher(redis=_FakeRedis()),
        allowlist=[ipaddress.ip_network("192.168.10.0/24")],
    )

    await receiver._handle(_snmp_v2c_trap(community=b"supersecret"), "192.168.10.2")

    assert captured, "nothing published, so this assertion would pass vacuously"
    assert "supersecret" not in str(captured[0].payload)


# ── robustness of the bridge itself ─────────────────────────────


async def test_the_rate_table_cannot_grow_without_bound(captured):
    """
    The table must stay bounded by a REAL fleet as well as a hostile one.

    Churning ``device_id`` is what exercises this now -- an earlier version of
    this test churned ``app_name``, and once that was removed from the key the
    test kept passing while creating a single bucket, so it no longer proved
    anything. Deleting the eviction entirely still left it green.

    A device id is not attacker-controlled (it comes from the source-IP
    resolver), but a large or churning fleet reaches the same ceiling, and
    without a bound the table simply grows for the life of the process.
    """
    pub = CollectorEventPublisher(redis=_FakeRedis(), max_tracked_sources=64, rate_limit=1000)

    for _ in range(5000):
        await pub.publish("syslog", _record(device_id=uuid4()))

    assert len(pub._buckets) <= 64, f"bucket table grew to {len(pub._buckets)}"
    assert pub.stats()["tracked_sources"] <= 64


async def test_a_device_cannot_evict_its_own_budget_to_bypass_the_cap(captured):
    """
    The bypass that made the first version of this wrong.

    ``app_name`` is free text off the wire. While it was part of the rate key,
    a host could exhaust its budget, mint unique app names until its own bucket
    was evicted from the bounded table, and resume flooding with a fresh one --
    so the cap held only against devices that were not trying to beat it.

    The key now contains only values the packet cannot choose: the org and
    device come from the source-IP resolver, and severity is the 3-bit PRI
    field. Churning app names no longer creates a single new bucket.
    """
    pub = CollectorEventPublisher(redis=_FakeRedis(), max_tracked_sources=16, rate_limit=3, rate_window_seconds=300)

    for _ in range(3):
        assert await pub.publish("syslog", _record(app_name="flood")) is True
    assert await pub.publish("syslog", _record(app_name="flood")) is False

    # Exactly what a hostile device would try.
    for i in range(500):
        await pub.publish("syslog", _record(app_name=f"noise-{i}"))

    assert await pub.publish("syslog", _record(app_name="flood")) is False, (
        "the cap was bypassed by churning app_name"
    )
    assert len(pub._buckets) <= 2, (
        f"app_name churn still inflates the table: {len(pub._buckets)} buckets"
    )


async def test_expired_buckets_are_reclaimed(captured):
    """
    Eviction prefers buckets whose window has passed: they carry no budget, so
    dropping them is free and it means a quiet fleet does not push live sources
    out of the table.
    """
    pub = CollectorEventPublisher(redis=_FakeRedis(), max_tracked_sources=8, rate_window_seconds=0.01)

    for _ in range(200):
        await pub.publish("syslog", _record(device_id=uuid4()))
    await asyncio.sleep(0.05)
    for _ in range(200):
        await pub.publish("syslog", _record(device_id=uuid4()))

    assert len(pub._buckets) <= 8


async def test_an_event_with_no_organization_is_refused(captured):
    """
    Fail closed on tenancy at the source.

    Both current consumers already drop an org-less event -- the automation
    engine's org filter and the WebSocket router both fail closed -- so one
    published here is at best dead weight on the 'system' scope. Refusing it
    here means a future consumer that is NOT fail-closed cannot turn this into
    a cross-tenant leak.
    """
    pub = CollectorEventPublisher(redis=_FakeRedis())

    assert await pub.publish("syslog", _record(organization_id=None)) is False
    assert captured == []
    assert pub.stats()["suppressed_no_org"] == 1


async def test_an_unknown_source_type_publishes_nothing(captured):
    assert await CollectorEventPublisher(redis=_FakeRedis()).publish("netflow", _record()) is False
    assert captured == []


def test_the_rate_check_has_no_await_so_it_cannot_interleave():
    """
    ``_passes_rate`` does read-modify-write on the shared bucket table. That is
    safe under asyncio ONLY while nothing yields between the read and the write:
    an await in the middle would let two coroutines both observe an
    under-budget count and both publish, which is a lost-update race that would
    show up as the cap being quietly exceeded under load.
    """
    import ast
    import inspect
    import textwrap

    from app.modules.collector.services import events as mod

    src = textwrap.dedent(inspect.getsource(mod.CollectorEventPublisher._passes_rate))
    tree = ast.parse(src)
    awaits = [n for n in ast.walk(tree) if isinstance(n, (ast.Await, ast.AsyncFor, ast.AsyncWith))]

    assert not awaits, "an await here makes the rate check a lost-update race"


def test_the_collector_prefix_is_subscribable_by_the_right_people():
    """
    Without an entry in SUBSCRIPTION_PERMISSIONS these events fall through to
    the default-deny, which is safe but means the only subscriber who could
    ever see them is a super_admin on the "*" firehose -- the feature invisible
    to exactly the operators it is for.

    Mapped to the permission that ALREADY gates reading these logs over REST,
    so it grants nobody anything they could not already read.
    """
    from app.core.ws_rbac import SUBSCRIPTION_PERMISSIONS, user_can_subscribe

    assert SUBSCRIPTION_PERMISSIONS.get("collector.") == "collector.logs.read"

    class _Principal:
        def __init__(self, perms, su=False):
            self.is_superuser = su
            self._perms = set(perms)

        def has_permission(self, perm):
            return True if self.is_superuser else perm in self._perms

    assert user_can_subscribe(_Principal({"collector.logs.read"}), "collector.*") is True
    assert user_can_subscribe(_Principal({"device:read"}), "collector.*") is False
    assert user_can_subscribe(_Principal(set()), "collector.*") is False
    # The firehose stays super_admin-only; holding the log permission is not it.
    assert user_can_subscribe(_Principal({"collector.logs.read"}), "*") is False


# ── the cap across workers ──────────────────────────────────────


async def test_the_cap_holds_across_workers(captured):
    """
    The defect this closes.

    Both receivers bind with ``reuse_port=True`` so a config reload can rebind
    seamlessly, and the collector module starts inside the API process per
    organization -- so EVERY gunicorn worker binds and the kernel load-balances
    datagrams between them. WEB_CONCURRENCY ships defaulting to 2.

    With a purely in-process counter each worker had its own budget: the cap was
    silently 2x, and a device sending twice the limit passed completely because
    no single worker ever saw more than half of it. Two publishers sharing one
    Redis is exactly that topology.
    """
    shared = _FakeRedis()
    worker_a = CollectorEventPublisher(redis=shared, rate_limit=4, rate_window_seconds=300)
    worker_b = CollectorEventPublisher(redis=shared, rate_limit=4, rate_window_seconds=300)

    # The kernel spreads a flood between them; alternate to model that.
    results = []
    for i in range(12):
        worker = worker_a if i % 2 == 0 else worker_b
        results.append(await worker.publish("syslog", _record()))

    assert sum(results) == 4, (
        f"{sum(results)} messages published against a cap of 4 -- the budget is "
        "still per-worker"
    )
    assert len(captured) == 4


async def test_without_the_shared_counter_the_cap_would_be_per_worker(captured):
    """
    The control for the test above: two workers that do NOT share state each
    spend a full budget, which is the behaviour that shipped. Stated as a test
    so the previous one cannot pass for an unrelated reason.
    """
    worker_a = CollectorEventPublisher(redis=_FakeRedis(), rate_limit=4, rate_window_seconds=300)
    worker_b = CollectorEventPublisher(redis=_FakeRedis(), rate_limit=4, rate_window_seconds=300)

    results = []
    for i in range(12):
        worker = worker_a if i % 2 == 0 else worker_b
        results.append(await worker.publish("syslog", _record()))

    assert sum(results) == 8, "separate stores should give separate budgets"


async def test_the_window_key_carries_a_ttl(captured):
    """
    Without an expiry the counter never resets and the source is muted for the
    life of the Redis instance. The TTL is set only by the first writer, so a
    steady stream cannot keep pushing the expiry out and pin the key for ever.
    """
    shared = _FakeRedis()
    pub = CollectorEventPublisher(redis=shared, rate_limit=5, rate_window_seconds=60)

    for _ in range(3):
        await pub.publish("syslog", _record())

    assert shared.expiries, "no TTL was set; the counter would never reset"
    assert all(ttl >= 60 for ttl in shared.expiries.values())

    # Counting CALLS, not distinct keys. Asserting len(expiries) == 1 looked
    # right and proved nothing: expiries is keyed by key name, so re-setting
    # the TTL on every message still leaves exactly one entry, and a mutation
    # that did precisely that survived.
    assert shared.expire_calls == 1, (
        f"TTL was written {shared.expire_calls} times for 3 messages; that is a "
        "second Redis round trip on every packet in the receive path"
    )


async def test_a_redis_outage_falls_back_to_the_local_cap(captured):
    """
    Fail open to the local bucket, matching the automation engine's idempotency
    lock. For a monitoring platform, publishing a duplicate during an outage is
    safer than going deaf to a device that is reporting a fault -- but the local
    cap still applies, so "fail open" is not "unbounded".
    """
    pub = CollectorEventPublisher(redis=_DeadRedis(), rate_limit=3, rate_window_seconds=300)

    results = [await pub.publish("syslog", _record()) for _ in range(10)]

    assert sum(results) == 3, "the local bucket stopped applying during the outage"
    assert pub.stats()["cap_degraded"] == 3
    assert pub.stats()["published"] == 3


async def test_redis_is_not_consulted_once_the_local_bucket_is_spent(captured):
    """
    The local bucket runs first so Redis is touched at most ``rate_limit`` times
    per window per source, rather than once per packet. This is the receive
    path: a round trip per datagram would be paid by every message the device
    sends, including the ones about to be thrown away.
    """
    shared = _FakeRedis()
    pub = CollectorEventPublisher(redis=shared, rate_limit=2, rate_window_seconds=300)

    for _ in range(50):
        await pub.publish("syslog", _record())

    total_incrs = sum(shared.store.values())
    assert total_incrs == 2, f"Redis was hit {total_incrs} times for 50 packets"
